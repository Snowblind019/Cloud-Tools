"""Cloud Map reachability: can A reach B on this port, and if not, what's blocking it?

It walks the security groups, network ACLs and route tables in a snapshot, from a live
scan or from Terraform, offline. AWS's Reachability Analyzer answers the same question
from inside AWS, but charges per analysis. This one is free and works on a plan before
anything exists. No GTK, no AWS calls.

The checks, in the order a packet meets them:

    the source's security groups, outbound
    the source subnet's network ACL, outbound
    the route: the source subnet's route table (its own, or the VPC's main one),
      longest prefix first, then the peering connection, transit gateway, internet
      gateway or NAT gateway it names
    the destination subnet's network ACL, inbound
    the destination's security groups, inbound
    the port the destination listens on, when the snapshot knows it
    the replies: network ACLs are stateless, so the destination's outbound rules and
      the source's inbound rules are checked again for the ephemeral ports 1024-65535,
      and the route back. Security groups are stateful, so replies need nothing there.

Every check that can't be done says so ("unknown"), and the verdict is "reachable" only
when every check passed. Addresses are worked out as ranges: for a CIDR, a subnet or
"the internet", a rule has to cover the whole range for the check to pass, and partial
coverage says exactly which part gets through.

    endpoints(snap)                      what can be picked as a source or destination
    resolve(snap, text)                  an ID, name, IP, CIDR or "internet" as an Endpoint
    check(snap, src, dst, protocol, port) -> Result
    result_text(result)                  the result as readable text
"""
from __future__ import annotations

import functools
import ipaddress
import re
import textwrap
from dataclasses import dataclass, field

from . import mapmodel as mm

VERDICTS = ("reachable", "blocked", "unknown")
STATUSES = ("ok", "blocked", "unknown", "skipped")
EXIT_CODES = {"reachable": 0, "blocked": 3, "unknown": 4}

# Ports a client picks for its side of a connection. AWS recommends network ACLs allow
# 1024-65535 for replies: that covers Linux (32768-60999), Windows (49152-65535), NAT
# gateways and load balancers (1024-65535).
EPHEMERAL = (1024, 65535)
ALL_PORTS = (0, 65535)
ALL_PROTOCOLS = (0, 255)
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "all": -1}
PROTOCOL_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "-1": "all"}
PICKABLE = ("instance", "lb", "rds", "subnet")

# Where traffic from the internet can't come from: private, shared, loopback, link-local,
# multicast and reserved ranges. The documentation ranges (like 203.0.113.0/24) count as
# public, since examples use them.
NOT_INTERNET_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                   "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
                   "224.0.0.0/4", "240.0.0.0/4")
INTERNET_V6 = "2000::/3"          # global unicast
NOT_INTERNET_V6 = ("fc00::/7", "fe80::/10", "ff00::/8", "::/8")

MIDDLEBOX = ("eni", "instance", "endpoint", "local-gateway", "carrier", "")
ANY_ADDR = (0, 2 ** 128)          # every address, for rules whose addresses aren't known

# More rules than AWS allows on one network interface (security groups) or in one network
# ACL. A snapshot with more is damaged or made up, and would take minutes to work through.
MAX_SG_RULES = 2000
MAX_ACL_RULES = 1000


# Why a security group rule that references the other side's group can't be judged
# between two VPCs (see route_between).
REFS_TGW = ("Through a transit gateway that only works when security group referencing is "
            "turned on for the transit gateway and its attachments, which isn't in the snapshot.")
REFS_REGIONS = ("Across a peering connection that only works when both VPCs are in the same "
                "region, and the regions aren't known.")
REFS_NO_ROUTE = ("Whether that works between two VPCs depends on the way the traffic goes, which "
                 "couldn't be checked.")


class ReachError(ValueError):
    """Bad input: something that can't be found, or a question that can't be asked."""


def _cli_id(value, prefix) -> bool:
    """Whether an ID is safe to put in a suggested AWS CLI command. IDs come from the
    snapshot, which can be someone else's or hand-made, so one with spaces, quotes, or
    shell or shorthand characters ($ ; ' , { } [ ] =) gets no command at all."""
    return re.fullmatch(prefix + r"-[0-9A-Za-z]{1,64}", str(value or "")) is not None


# =================================================================== addresses

def _net(text):
    return ipaddress.ip_network(str(text).strip(), strict=False)


def _iv(net):
    return (int(net.network_address), int(net.broadcast_address))


def _merge(ivs):
    out = []
    for lo, hi in sorted(ivs):
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def _minus(a, b):
    """Intervals in a and not in b."""
    out = []
    b = _merge(b)
    for lo, hi in _merge(a):
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


def _and(a, b):
    out = []
    for lo, hi in _merge(a):
        for blo, bhi in _merge(b):
            x, y = max(lo, blo), min(hi, bhi)
            if x <= y:
                out.append((x, y))
    return _merge(out)


def _overlaps(a, b) -> bool:
    return bool(_and(a, b))


def _cidrs(ivs, version) -> list:
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    out = []
    for lo, hi in _merge(ivs):
        out += [str(n) for n in ipaddress.summarize_address_range(cls(lo), cls(hi))]
    return out


def _ivs_text(ivs, version, limit=3) -> str:
    cidrs = [c[:-3] if c.endswith("/32") and version == 4 else
             (c[:-4] if c.endswith("/128") else c) for c in _cidrs(ivs, version)]
    if len(cidrs) <= limit:
        return ", ".join(cidrs)
    return ", ".join(cidrs[:limit]) + f" and {len(cidrs) - limit} more ranges"


def _internet_ivs(version):
    if version == 4:
        return _minus([(0, 2 ** 32 - 1)], [_iv(_net(c)) for c in NOT_INTERNET_V4])
    return _minus([_iv(_net(INTERNET_V6))], [_iv(_net(c)) for c in NOT_INTERNET_V6])


def _is_private(net) -> bool:
    """Whether every address in it is outside the internet's address space."""
    if net.version == 4:
        return not _overlaps([_iv(net)], _internet_ivs(4))
    return not _overlaps([_iv(net)], _internet_ivs(6))


def _contains(net_text, ip) -> bool:
    try:
        net = _net(net_text)
    except ValueError:
        return False
    return net.version == ip.version and ip in net


def _valid_ip(text):
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


# =================================================================== boxes
# A check looks at three things at once: the other side's address, the protocol and the
# port (or the ICMP type). Rules are boxes in that space, and first-match (network ACLs)
# or union (security groups) is worked out by cutting boxes apart, so ranges and partial
# coverage come out exact.

def _box_and(a, b):
    out = []
    for (alo, ahi), (blo, bhi) in zip(a, b):
        lo, hi = max(alo, blo), min(ahi, bhi)
        if lo > hi:
            return None
        out.append((lo, hi))
    return tuple(out)


def _box_minus(a, b):
    inter = _box_and(a, b)
    if inter is None:
        return [a]
    pieces, rest = [], list(a)
    for d in range(len(a)):
        lo, hi = rest[d]
        ilo, ihi = inter[d]
        if lo < ilo:
            p = list(rest)
            p[d] = (lo, ilo - 1)
            pieces.append(tuple(p))
        if ihi < hi:
            p = list(rest)
            p[d] = (ihi + 1, hi)
            pieces.append(tuple(p))
        rest[d] = (ilo, ihi)
    return pieces


def _region_minus(region, box):
    out, hit = [], False
    for b in region:
        if _box_and(b, box) is None:
            out.append(b)
        else:
            hit = True
            out.extend(_box_minus(b, box))
    return out, hit


def _proto_iv(protocol):
    p = mm.protocol_number(protocol)
    if p == "-1":
        return ALL_PROTOCOLS
    try:
        n = int(p)
    except ValueError:
        return None
    return (n, n)


def _rule_ports(protocol, from_port, to_port):
    """The port (or ICMP type) range a security group rule covers. -1 or nothing means
    all. For ICMP, from is the type and to the code; a rule for one code other than 0
    doesn't cover ping (echo is code 0), so it gets an empty range (None)."""
    p = mm.protocol_number(protocol)
    f, t = mm._int_or_none(from_port), mm._int_or_none(to_port)
    if p in ("6", "17"):
        if f is None or f < 0:
            return ALL_PORTS
        t = f if t is None or t < 0 else t
        return (min(f, t), max(f, t))
    if p in ("1", "58"):
        if f is None or f < 0:
            return ALL_PORTS
        if t is not None and t > 0:
            return None
        return (f, f)
    return ALL_PORTS


# =================================================================== results

@dataclass
class Endpoint:
    """Something to check from or to.

    kind: instance, lb, rds, subnet ("any host in it"), address (an IP inside a VPC
    that no resource on the map has), cidr (a range inside a VPC), internet (the whole
    internet, or a public IP or range), outside (a private address outside every VPC in
    the snapshot, like on-premises over a VPN).
    key is what check() and the command line take for it again."""
    key: str
    kind: str
    title: str
    detail: str = ""
    node_id: str = ""
    vpc: str = ""
    subnets: list = field(default_factory=list)
    security_groups: object = None     # IDs, or None when no security group applies
    addresses: list = field(default_factory=list)
    version: int = 0                   # 4 or 6 when the endpoint fixes it, else 0
    public_ip: str = ""
    ipv6: list = field(default_factory=list)
    ports: list = field(default_factory=list)       # [(port, protocol)] it listens on
    ports_known: bool = False
    sg_recorded: bool = True
    any_internet: bool = False
    notes: list = field(default_factory=list)
    via_public_ip: str = ""            # given as its public IP rather than by name or ID

    @property
    def label(self) -> str:
        return f"{self.title} ({self.detail})" if self.detail else self.title

    @property
    def phrase(self) -> str:
        """The title inside a sentence: "the internet", not "The internet"."""
        return self.title[0].lower() + self.title[1:] if self.kind == "internet" and \
            self.title.startswith("The ") else self.title

    def as_dict(self) -> dict:
        return {"key": self.key, "kind": self.kind, "title": self.title,
                "detail": self.detail, "node_id": self.node_id, "vpc": self.vpc,
                "subnets": list(self.subnets),
                "security_groups": None if self.security_groups is None else list(self.security_groups),
                "addresses": list(self.addresses), "public_ip": self.public_ip,
                "ports": [p for p, _ in self.ports]}


@dataclass
class Hop:
    """One check along the way.

    kind: what was checked (state, address, sg-out, nacl-out, route, nacl, nat-nacl-in,
    nat, nat-route, nat-nacl-out, public-ip, igw, peering, tgw, nacl-in, sg-in, service,
    nacl-back-out, route-back, nat-nacl-back-in, nat-nacl-back-out, nacl-back-in), in
    that order in a result.
    status: ok, blocked, unknown or skipped. leg: "there" for the request, "back" for
    the replies. node_id and edge_id are on the map when set. partial: blocked for only
    part of the range (the reason says which part gets through)."""
    kind: str
    title: str
    status: str
    reason: str
    node_id: str = ""
    edge_id: str = ""
    leg: str = "there"
    partial: bool = False
    fix: str = ""
    side: str = field(default="", repr=False, compare=False)      # whose addresses it narrows
    full: object = field(default=None, repr=False, compare=False)  # what got through, or None

    def key(self):
        return (self.kind, self.leg, self.node_id, self.status, self.reason)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "title": self.title, "status": self.status,
                "reason": self.reason, "node_id": self.node_id, "edge_id": self.edge_id,
                "leg": self.leg, "partial": self.partial, "fix": self.fix}


@dataclass
class Result:
    """verdict: reachable, blocked or unknown. partial: blocked for only part of the
    source or destination (or through only some of a load balancer's subnets).
    path_nodes and path_edges: what to highlight on the map, IDs that are in the
    snapshot."""
    verdict: str
    summary: str
    source: Endpoint
    destination: Endpoint
    protocol: str
    port: object
    hops: list
    notes: list
    path_nodes: list
    path_edges: list
    partial: bool = False

    @property
    def blocked_index(self):
        for i, h in enumerate(self.hops):
            if h.status == "blocked":
                return i
        return None

    @property
    def blocked_hop(self):
        i = self.blocked_index
        return None if i is None else self.hops[i]

    @property
    def traffic(self) -> str:
        return _traffic_text(self.protocol, self.port)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.verdict, 4)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "partial": self.partial, "summary": self.summary,
                "source": self.source.as_dict(), "destination": self.destination.as_dict(),
                "protocol": self.protocol, "port": self.port,
                "hops": [h.as_dict() for h in self.hops], "blocked_at": self.blocked_index,
                "notes": list(self.notes), "path_nodes": list(self.path_nodes),
                "path_edges": list(self.path_edges)}


def _traffic_text(protocol, port) -> str:
    if protocol == "all":
        return "all traffic"
    if protocol in ("icmp", "icmpv6"):
        return "ping (ICMP echo)" if protocol == "icmp" else "ping (ICMPv6 echo)"
    return f"{protocol} {port}"


# =================================================================== endpoints

def _subnet_title(snap, subnet_id) -> str:
    sn = snap.get(subnet_id)
    return mm.title_of(sn) if sn is not None else subnet_id


def _endpoint_for(snap, node) -> Endpoint:
    p, k = node.props, node.kind
    title = mm.title_of(node)
    if k == "instance":
        subnet = p.get("subnet") or node.parent
        ip = str(p.get("private_ip") or "")
        valid = _valid_ip(ip) is not None
        detail = ", ".join(x for x in (ip if valid else "", "in " + _subnet_title(snap, subnet)) if x)
        return Endpoint(node.id, k, title, detail, node.id, p.get("vpc") or snap.vpc_of(node),
                        [subnet] if subnet else [], list(p.get("security_groups") or []),
                        [ip] if valid else [], public_ip=str(p.get("public_ip") or ""),
                        ipv6=list(p.get("ipv6_ips") or []))
    if k == "lb":
        kind = str(p.get("type") or "application")
        detail = ", ".join(x for x in (str(p.get("scheme") or ""), f"{kind} load balancer") if x)
        ep = Endpoint(node.id, k, title, detail, node.id, p.get("vpc") or snap.vpc_of(node), list(p.get("subnets") or []),
                      list(p["security_groups"]) if "security_groups" in p else None,
                      sg_recorded="security_groups" in p)
        if "listeners" in p:
            ep.ports_known = True
            ep.ports = [(int(li.get("port")), str(li.get("protocol") or "")) for li in p["listeners"]
                        if mm._int_or_none(li.get("port")) is not None]
        return ep
    if k == "rds":
        subnet = node.parent if (snap.get(node.parent) is not None and
                                 snap.get(node.parent).kind == "subnet") else ""
        subnets = [subnet] if subnet else list(p.get("subnets") or [])
        engine = str(p.get("engine") or "database")
        detail = f"{engine}" + (f" in {_subnet_title(snap, subnet)}" if subnet else "")
        ep = Endpoint(node.id, k, title, detail, node.id, p.get("vpc") or snap.vpc_of(node),
                      subnets, list(p["security_groups"]) if "security_groups" in p else None,
                      sg_recorded="security_groups" in p)
        port = mm._int_or_none(p.get("port")) or mm.engine_port(engine)
        if port:
            ep.ports, ep.ports_known = [(port, "TCP")], True
        others = [s for s in p.get("subnets") or [] if s != subnet]
        if subnet and others:
            ep.notes.append(f"{title} is in {_subnet_title(snap, subnet)} now. A Multi-AZ standby, or "
                            f"the database after a failover, is in another subnet of its group "
                            f"({', '.join(_subnet_title(snap, s) for s in others)}), which wasn't checked.")
        return ep
    if k == "subnet":
        cidr = str(p.get("cidr") or "")
        detail = ", ".join(x for x in (cidr, "any host in it") if x)
        return Endpoint(node.id, k, title, detail, node.id, snap.vpc_of(node), [node.id],
                        None, [cidr] if cidr else [])
    raise ReachError(f"{node.id} is a {mm.NODE_KINDS.get(k, k)}. Pick an instance, a load "
                     "balancer, a database, a subnet, an IP or a CIDR.")


def _internet(version=4, text="") -> Endpoint:
    if text:
        net = _net(text)
        single = net.prefixlen == net.max_prefixlen
        shown = str(net.network_address) if single else str(net)
        return Endpoint(text, "internet", shown, "an address on the internet" if single else
                        "a range on the internet", version=net.version, addresses=[str(net)])
    key = "internet" if version == 4 else "internet-ipv6"
    return Endpoint(key, "internet", "The internet" if version == 4 else "The internet (IPv6)",
                    "anywhere outside AWS" if version == 4 else "anywhere, over IPv6",
                    version=version, addresses=["0.0.0.0/0" if version == 4 else "::/0"],
                    any_internet=True)


def _damaged(fn):
    """Turn what a hand-made or damaged snapshot can break (a rule number that isn't a
    number, a rule that isn't an object) into a ReachError, so the window and the command
    line show a plain sentence instead of a traceback."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ReachError:
            raise
        except (TypeError, ValueError, AttributeError, KeyError, IndexError) as exc:
            raise ReachError("The snapshot has something in it Cloud Map can't read "
                             f"({type(exc).__name__}: {exc}). Rescan, or read the Terraform "
                             "again.") from None
    return wrapper


@_damaged
def endpoints(snap) -> list:
    """Everything that can be picked as a source or destination: instances, load
    balancers, RDS databases, subnets ("any host in it") and the internet, over IPv4 and
    IPv6. resolve() also takes an IP or a CIDR typed in."""
    order = {k: i for i, k in enumerate(PICKABLE)}
    nodes = sorted((n for n in snap.nodes.values() if n.kind in PICKABLE and not n.props.get("stub")),
                   key=lambda n: (order[n.kind], mm.title_of(n).lower(), n.id))
    out = [_endpoint_for(snap, n) for n in nodes]
    return out + [_internet(4), _internet(6)]


def resolve(snap, text) -> Endpoint:
    """An Endpoint from what a user typed: a node ID, a name, an IP, a CIDR, or
    "internet" (internet-ipv6 for IPv6)."""
    if isinstance(text, Endpoint):
        return text
    t = str(text or "").strip()
    if not t:
        raise ReachError("Give something to check from and to: an ID, a name, an IP, a CIDR "
                         "or internet.")
    low = t.lower()
    if low in ("internet", "the internet", "anywhere", "world", "0.0.0.0/0", "internet-ipv4"):
        return _internet(4)
    if low in ("internet6", "internet-ipv6", "ipv6-internet", "::/0"):
        return _internet(6)
    node = snap.get(t)
    if node is not None:
        return _endpoint_for(snap, node)
    hits = [n for n in snap.nodes.values() if n.kind in PICKABLE and not n.props.get("stub")
            and low in {n.name.lower(), mm.title_of(n).lower()}]
    things = [n for n in hits if n.kind != "subnet"]
    if len(hits) > 1 and len(things) == 1:
        # An instance and a subnet both called "app": the instance is the likely meaning.
        ep = _endpoint_for(snap, things[0])
        others = [n.id for n in hits if n is not things[0]]
        ep.notes.append(f"{t} is also the name of subnet {', '.join(others)}. Give its ID to "
                        "check that instead.")
        return ep
    if len(hits) == 1:
        return _endpoint_for(snap, hits[0])
    if len(hits) > 1:
        names = "; ".join(f"{mm.NODE_KINDS.get(n.kind, n.kind)} {n.id}"
                          for n in sorted(hits, key=lambda n: n.id)[:6])
        raise ReachError(f"{t} matches {len(hits)} things ({names}). Use the ID instead.")
    try:
        net = _net(t)
    except ValueError:
        raise ReachError(f"Couldn't find {t} in the snapshot. Give an instance, load balancer, "
                         "database or subnet by ID or name, an IP, a CIDR, or internet. "
                         "awskit map reach SOURCE --list shows what's there.") from None
    return _address_endpoint(snap, net, t)


def _vpc_nets(vpc, snap, version):
    nets = []
    for c in vpc.props.get("cidrs") or []:
        try:
            n = _net(c)
        except ValueError:
            continue
        if n.version == version:
            nets.append(n)
    if version == 6:
        for sn in snap.of_kind("subnet"):
            if snap.vpc_of(sn) == vpc.id and sn.props.get("ipv6_cidr"):
                try:
                    nets.append(_net(sn.props["ipv6_cidr"]))
                except ValueError:
                    pass
    return nets


def _subnet_net(sn, version):
    text = sn.props.get("cidr") if version == 4 else sn.props.get("ipv6_cidr")
    try:
        return _net(text) if text else None
    except ValueError:
        return None


def _address_endpoint(snap, net, text) -> Endpoint:
    v = net.version
    single = net.prefixlen == net.max_prefixlen
    if single:
        ip = net.network_address
        for inst in snap.of_kind("instance"):
            p = inst.props
            if str(p.get("private_ip") or "") == str(ip) or str(ip) in (p.get("ipv6_ips") or []):
                ep = _endpoint_for(snap, inst)
                ep.version = v
                return ep
        for inst in snap.of_kind("instance"):
            if str(inst.props.get("public_ip") or "") == str(ip):
                ep = _endpoint_for(snap, inst)
                ep.version = v
                ep.via_public_ip = str(ip)
                ep.notes.append(f"{ip} is the public IP of {ep.title}, so that's what was checked.")
                return ep
    subnets = [sn for sn in snap.of_kind("subnet")
               if _subnet_net(sn, v) is not None and _subnet_net(sn, v).overlaps(net)]
    vpcs = [vpc for vpc in snap.of_kind("vpc") if any(n.overlaps(net) for n in _vpc_nets(vpc, snap, v))]
    real = [vpc for vpc in vpcs if not vpc.props.get("stub")]
    shown = str(net.network_address) if single else str(net)
    if len(vpcs) > 1:
        raise ReachError(f"{text} is in more than one VPC ({', '.join(mm.title_of(x) for x in vpcs)}). "
                         "Pick an instance or subnet instead.")
    if vpcs:
        vpc = vpcs[0]
        if not any(n.supernet_of(net) or n == net for n in _vpc_nets(vpc, snap, v)):
            raise ReachError(f"{text} covers part of {mm.title_of(vpc)} and more. Pick a range "
                             "inside the VPC, or one outside it.")
        if real and not subnets:
            raise ReachError(f"{text} is inside {mm.title_of(vpc)}, but not in any subnet the "
                             "snapshot has.")
        ids = [sn.id for sn in sorted(subnets, key=lambda s: s.id)]
        where = (f"in {_subnet_title(snap, ids[0])}" if len(ids) == 1 else
                 f"across {len(ids)} subnets") if ids else f"in {mm.title_of(vpc)}, outside this snapshot"
        ep = Endpoint(text, "address" if single else "cidr", shown,
                      ("an address " if single else "a range ") + where, vpc=vpc.id, subnets=ids,
                      security_groups=None, addresses=[str(net)], version=v)
        if single and real:
            ep.notes.append(f"No resource on the map has {shown}, so its security groups aren't known.")
        return ep
    if net.prefixlen == 0:
        return _internet(v)
    if _is_private(net):
        return Endpoint(text, "outside", shown,
                        "a private address outside the VPCs in this snapshot, like on-premises"
                        if single else "a private range outside the VPCs in this snapshot",
                        version=v, addresses=[str(net)])
    return _internet(v, text)


# =================================================================== the walk

@dataclass
class _Place:
    """Where one side of a pair is: its VPC and subnet (blank outside AWS), and which of
    its addresses. anywhere: the whole internet."""
    vpc: str
    subnet: str
    ivs: list
    text: str
    anywhere: bool = False


class _Walk:
    def __init__(self, snap, src, dst, protocol, port, version):
        self.snap, self.src, self.dst = snap, src, dst
        self.version = version
        self.protocol = protocol
        self.port = port
        if protocol == "all":
            self.p_iv, self.req, self.rep = ALL_PROTOCOLS, ALL_PORTS, ALL_PORTS
        elif protocol in ("icmp", "icmpv6"):
            n = 1 if version == 4 else 58
            self.p_iv = (n, n)
            self.req = (8, 8) if version == 4 else (128, 128)
            self.rep = (0, 0) if version == 4 else (129, 129)
        else:
            n = PROTOCOLS[protocol]
            self.p_iv, self.req, self.rep = (n, n), (port, port), EPHEMERAL
        self.traffic = _traffic_text(protocol, port)
        self.notes = []
        self.nodes = {}
        self.edges = {}
        self.assumed_acl = []
        self.replies_checked = False
        self._acl_cache = {}

    # ---- small helpers
    def note(self, text):
        if text and text not in self.notes:
            self.notes.append(text)

    def use(self, *ids):
        for i in ids:
            if i and self.snap.get(i) is not None:
                self.nodes.setdefault(i, None)

    def use_edge(self, eid):
        if eid and eid in self.snap.edges:
            self.edges.setdefault(eid, None)

    def name(self, node_id) -> str:
        """Its name, or its ID when it has none (never just "Internet gateway")."""
        node = self.snap.get(node_id)
        if node is None:
            return str(node_id)
        t = mm.title_of(node)
        return node.id if t == mm.NODE_KINDS.get(node.kind) else t

    def named(self, node_id) -> str:
        """'web-sg (sg-0abc)' when it has a name, else the ID."""
        t = self.name(node_id)
        return t if t == str(node_id) else f"{t} ({node_id})"

    def reply_text(self) -> str:
        if self.protocol in ("icmp", "icmpv6"):
            return "ping replies"
        if self.protocol == "all":
            return "replies (all traffic)"
        return f"replies ({self.protocol} ports {EPHEMERAL[0]}-{EPHEMERAL[1]})"

    # ---- places
    def places(self, ep):
        v, snap = self.version, self.snap
        if ep.kind in ("internet", "outside"):
            if ep.any_internet:
                return [_Place("", "", _internet_ivs(v), "the internet", True)]
            net = _net(ep.addresses[0])
            return [_Place("", "", [_iv(net)], ep.title)]
        if ep.kind in ("address", "cidr"):
            net = _net(ep.addresses[0])
            if not ep.subnets:
                return [_Place(ep.vpc, "", [_iv(net)], ep.title)]
            out = []
            for s in ep.subnets:
                sn = snap.get(s)
                sub = _subnet_net(sn, v) if sn is not None else None
                ivs = _and([_iv(net)], [_iv(sub)]) if sub is not None else [_iv(net)]
                if ivs:
                    out.append(_Place(ep.vpc, s, ivs, _ivs_text(ivs, v)))
            return out
        if ep.kind == "instance":
            subnet = ep.subnets[0] if ep.subnets else ""
            sn = snap.get(subnet)
            if v == 4:
                ip = _valid_ip(ep.addresses[0]) if ep.addresses else None
                if ip is not None:
                    return [_Place(ep.vpc, subnet, [(int(ip), int(ip))], str(ip))]
                sub = _subnet_net(sn, 4) if sn is not None else None
                if sub is None:
                    return []
                self.note(f"{ep.title}'s private IP isn't known yet, so any address in "
                          f"{_subnet_title(snap, subnet)} ({sub}) was checked.")
                return [_Place(ep.vpc, subnet, [_iv(sub)], str(sub))]
            ips = [i for i in (_valid_ip(x) for x in ep.ipv6) if i is not None and i.version == 6]
            if ips:
                return [_Place(ep.vpc, subnet, [(int(i), int(i))], str(i)) for i in ips[:1]]
            sub = _subnet_net(sn, 6) if sn is not None else None
            if sub is None:
                return []
            # The rest is checked for any address in the subnet, and address_hops() says
            # the instance's own IPv6 address isn't known.
            return [_Place(ep.vpc, subnet, [_iv(sub)], str(sub))]
        out = []
        for s in ep.subnets:
            sn = snap.get(s)
            sub = _subnet_net(sn, v) if sn is not None else None
            if sub is not None:
                out.append(_Place(ep.vpc, s, [_iv(sub)], str(sub)))
        return out

    # ---- running
    def run(self) -> Result:
        src_places, dst_places = self.places(self.src), self.places(self.dst)
        self.use(self.src.node_id)
        for ep in (self.src, self.dst):
            for n in ep.notes:
                self.note(n)
        if not src_places or not dst_places:
            ep = self.src if not src_places else self.dst
            known = [s for s in ep.subnets if self.snap.get(s) is not None]
            if self.version == 6 and known:
                hop = Hop("address", f"{ep.title}'s address", "blocked",
                          f"{ep.title} has no IPv6 address in the snapshot (its subnet has no IPv6 "
                          "range).", ep.node_id)
            else:
                hop = Hop("address", f"{ep.title}'s address", "unknown",
                          f"Where {ep.title} is isn't in the snapshot (no subnet with an address "
                          "range), so nothing could be checked.", ep.node_id)
            self.use(self.dst.node_id)
            return self.finish([[hop]], [hop])
        paths = []
        for sp in src_places:
            for dp in dst_places:
                self.use(sp.subnet, dp.subnet)
                paths.append(self.pair(sp, dp))
        self.use(self.dst.node_id)
        merged, seen = [], set()
        for hops in paths:
            for h in hops:
                if h.key() not in seen:
                    seen.add(h.key())
                    merged.append(h)
        rank = {k: i for i, k in enumerate(HOP_ORDER)}
        first = {h.key(): i for i, h in enumerate(merged)}
        merged.sort(key=lambda h: (1 if h.leg == "back" else 0, rank.get(h.kind, 99),
                                   first[h.key()]))
        return self.finish(paths, merged, src_places, dst_places)

    def state_hops(self) -> list:
        """An instance that's stopped can't send or answer anything."""
        hops = []
        for ep in (self.src, self.dst):
            node = self.snap.get(ep.node_id) if ep.kind == "instance" else None
            state = str(node.props.get("state") or "") if node is not None else ""
            if state in ("stopped", "stopping", "terminated", "shutting-down"):
                hops.append(Hop("state", f"{ep.title} is {state}", "blocked",
                                f"{ep.title} is {state}, so it can't "
                                + ("send anything." if ep is self.src else "answer."), ep.node_id))
        return hops

    def address_hops(self) -> list:
        """Over IPv6, a host needs an IPv6 address of its own: an instance without one in
        the snapshot, and a load balancer or database (whether they're dual-stack isn't
        recorded), can't pass, even though the rest is checked for its subnet's range."""
        hops = []
        if self.version != 6:
            return hops
        for ep in (self.src, self.dst):
            if ep.kind == "instance" and not any(
                    (_valid_ip(x) is not None and _valid_ip(x).version == 6) for x in ep.ipv6):
                hops.append(Hop("address", f"{ep.title}'s IPv6 address", "unknown",
                                f"No IPv6 address is recorded for {ep.title}. A live scan records "
                                "them, so it likely has none; Terraform may not know it until "
                                "apply. The rest was checked for any address in its subnet's IPv6 "
                                "range.", ep.node_id))
            elif ep.kind in ("lb", "rds"):
                hops.append(Hop("address", f"{ep.title}'s IPv6 address", "unknown",
                                f"Whether {ep.title} has IPv6 addresses (dual-stack) isn't in the "
                                "snapshot. The rest was checked for its subnets' IPv6 ranges.",
                                ep.node_id))
        return hops

    def pair(self, sp, dp) -> list:
        return self.state_hops() + self.address_hops() + self._pair(sp, dp)

    def _pair(self, sp, dp) -> list:
        if sp.vpc and dp.vpc:
            if sp.vpc == dp.vpc:
                return self.same_vpc(sp, dp)
            return self.cross_vpc(sp, dp)
        if sp.vpc:
            return self.to_outside(sp, dp)
        return self.from_outside(sp, dp)

    # ---- scenarios
    def same_vpc(self, sp, dp) -> list:
        hops = [self.sg_hop(self.src, sp, self.dst, dp, "egress", True)]
        if sp.subnet and sp.subnet == dp.subnet:
            sname = self.name(sp.subnet)
            hops.append(Hop("route", f"Inside {sname}", "ok",
                            f"Both are in {sname}, so the traffic is delivered inside the subnet "
                            "with no route needed.", sp.subnet))
            hops.append(Hop("nacl", f"Network ACL of {sname}", "skipped",
                            "Traffic inside a subnet doesn't cross its network ACL.", sp.subnet))
        else:
            hops.append(self.nacl_hop(sp.subnet, True, dp, "nacl-out"))
            hops.append(self.local_route_hop(sp, dp, "route"))
            hops.append(self.nacl_hop(dp.subnet, False, sp, "nacl-in"))
        hops.append(self.sg_hop(self.dst, dp, self.src, sp, "ingress", True))
        hops += self.service_hops()
        if not (sp.subnet and sp.subnet == dp.subnet):
            hops.append(self.nacl_hop(dp.subnet, True, sp, "nacl-back-out", reply=True,
                                      client=self.src.kind))
            back = self.local_route_hop(dp, sp, "route-back", quiet=True)
            if back is not None:
                hops.append(back)
            hops.append(self.nacl_hop(sp.subnet, False, dp, "nacl-back-in", reply=True,
                                      client=self.src.kind))
        return hops

    def cross_vpc(self, sp, dp) -> list:
        hops = []
        out_hops, refs, via = self.route_between(sp, dp)
        hops.append(self.sg_hop(self.src, sp, self.dst, dp, "egress", refs))
        hops.append(self.nacl_hop(sp.subnet, True, dp, "nacl-out"))
        hops += out_hops
        hops.append(self.nacl_hop(dp.subnet, False, sp, "nacl-in"))
        hops.append(self.sg_hop(self.dst, dp, self.src, sp, "ingress", refs))
        hops += self.service_hops()
        hops.append(self.nacl_hop(dp.subnet, True, sp, "nacl-back-out", reply=True,
                                  client=self.src.kind))
        hops.append(self.route_back_between(sp, dp, via))
        hops.append(self.nacl_hop(sp.subnet, False, dp, "nacl-back-in", reply=True,
                                  client=self.src.kind))
        return hops

    def to_outside(self, sp, dp) -> list:
        hops = [self.sg_hop(self.src, sp, self.dst, dp, "egress", False),
                self.nacl_hop(sp.subnet, True, dp, "nacl-out")]
        route = self.lookup(sp.subnet, dp)
        hops.append(route.hop)
        kind = route.kind
        private = self.dst.kind == "outside"
        if route.hop.status != "ok" or route.route is None:
            pass
        elif kind == "igw":
            if private:
                route.hop.status = "blocked"
                route.hop.reason += (f" {self.dst.title} is a private address, and those can't "
                                     "be reached through the internet.")
            else:
                hops += self.igw_out_hops(sp, route)
        elif kind == "eigw":
            if private or self.version != 6:
                route.hop.status = "blocked"
                route.hop.reason += " An egress-only internet gateway only carries IPv6 to the internet."
            else:
                route.hop.reason += (" It carries IPv6 out to the internet and lets the replies "
                                     "back in, but no connections started from the internet.")
                hops.append(self.public_hop_src(sp))
        elif kind == "nat":
            hops += self.nat_hops(sp, dp, route)
        elif kind == "tgw":
            route.hop.status = "unknown"
            route.hop.reason += (" Transit gateway route tables aren't in the snapshot, so where "
                                 "it goes from there wasn't checked (an egress or inspection VPC, "
                                 "a VPN, or nowhere).")
        elif kind == "vgw":
            route.hop.status = "unknown"
            route.hop.reason += (" That's a VPN or Direct Connect, and what's on the other side "
                                 "isn't in the snapshot.")
        elif kind == "peering" and not self.dst.any_internet and \
                self._peer_is_stub(route.target, sp.vpc):
            # The other VPC wasn't scanned, so only some of its address ranges are known
            # (a peering lists the main one): this address may well be one of its own.
            route.hop.status = "unknown"
            route.hop.reason += (f" The VPC on the other side isn't fully in the snapshot, so "
                                 f"whether {self.dst.title} is one of its addresses isn't known.")
        elif kind == "peering":
            route.hop.status = "blocked"
            route.hop.reason += (" A peering connection only reaches the other VPC's own "
                                 "addresses, never the internet or networks beyond it.")
        elif kind == "local":
            route.hop.status = "blocked"
            route.hop.reason += " The local route only covers the VPC itself."
        else:
            route.hop.status = "unknown"
            route.hop.reason += _beyond(kind)
        hops.append(self.nacl_hop(sp.subnet, False, dp, "nacl-back-in", reply=True,
                                  client=self.src.kind))
        return hops

    def _peer_is_stub(self, pcx, vpc_id) -> bool:
        """Whether the VPC on the other side of a peering connection is missing, or only
        known from the peering (not scanned or in the Terraform itself)."""
        edge = next((e for e in self.snap.edges.values() if e.kind == "peering" and
                     e.props.get("pcx") == pcx), None)
        if edge is None:
            return True
        other = self.snap.get(edge.dst if edge.src == vpc_id else edge.src)
        return other is None or bool(other.props.get("stub"))

    def from_outside(self, sp, dp) -> list:
        hops = []
        internet = self.src.kind == "internet"
        if internet:
            hops.append(self.public_hop_dst(dp))
            hops.append(self.igw_hop(dp.vpc))
        hops.append(self.nacl_hop(dp.subnet, False, sp, "nacl-in"))
        hops.append(self.sg_hop(self.dst, dp, self.src, sp, "ingress", False))
        hops += self.service_hops()
        hops.append(self.nacl_hop(dp.subnet, True, sp, "nacl-back-out", reply=True))
        hops.append(self.route_back_outside(dp, sp))
        if self.dst.kind == "lb":
            self.note("This checks the way in to the load balancer. Whether it can reach its "
                      "targets is a separate check, from the load balancer to each target.")
        return hops

    # ---- security groups
    def sg_hop(self, host, place, remote, rplace, direction, refs) -> Hop:
        egress = direction == "egress"
        kind = "sg-out" if egress else "sg-in"
        word = "outbound" if egress else "inbound"
        side = "dst" if egress else "src"
        tofrom = "to" if egress else "from"
        sgs = host.security_groups
        if host.kind in ("subnet", "cidr"):
            what = "a subnet" if host.kind == "subnet" else "a range of addresses"
            return Hop(kind, f"Security groups of {host.title}, {word}", "skipped",
                       f"{host.title} is {what}, standing for any host in it, so security groups "
                       f"on its side weren't checked.", host.node_id)
        if host.kind in ("internet", "outside"):
            return Hop(kind, f"Security groups, {word}", "skipped", "Not in AWS.")
        if host.kind == "address":
            return Hop(kind, f"Security groups of {host.title}, {word}", "unknown",
                       f"No resource on the map has {host.title}, so its security groups aren't "
                       "known.")
        if not host.sg_recorded:
            return Hop(kind, f"Security groups of {host.title}, {word}", "unknown",
                       "Security groups of load balancers and databases aren't in this snapshot "
                       "(made before they were recorded); rescan to check them.", host.node_id)
        if not sgs:
            node = self.snap.get(host.node_id)
            if host.kind == "lb" and node is not None and \
                    str(node.props.get("type", "")).lower() == "network":
                return Hop(kind, f"Security groups of {host.title}, {word}", "ok",
                           f"{host.title} is a Network Load Balancer with no security groups, so "
                           "it doesn't filter traffic itself.", host.node_id, side=side,
                           full=list(rplace.ivs))
            return Hop(kind, f"Security groups of {host.title}, {word}", "unknown",
                       f"No security groups are recorded for {host.title}.", host.node_id)
        names = [self.name(g) for g in sgs]
        title = (f"Security group {names[0]}, {word}" if len(sgs) == 1 else
                 f"Security groups {mm.join_names(names, 3)}, {word}")
        self.use(*sgs)
        missing = [g for g in sgs if self.snap.get(g) is None or
                   not isinstance(self.snap.get(g).props.get(direction), list)]
        if missing:
            return Hop(kind, title, "unknown",
                       f"Security group {', '.join(missing)} isn't in the snapshot, so its rules "
                       "weren't checked.", missing[0])
        count = sum(len(r.get("cidrs") or []) + len(r.get("groups") or []) +
                    len(r.get("prefix_lists") or []) + 1
                    for g in sgs for r in self.snap.get(g).props.get(direction))
        if count > MAX_SG_RULES:
            raise ReachError(f"{title} has {count} rules, more than AWS allows on one network "
                             "interface, so the snapshot looks damaged.")
        ports = self.req
        query = [(iv, self.p_iv, ports) for iv in _merge(rplace.ivs)]
        remote_sgs = self._membership(remote)
        allowed, maybe, group_only, no_refs = [], [], [], []
        for sg_id in sgs:
            sg = self.snap.get(sg_id)
            for idx, r in enumerate(sg.props.get(direction) or [], 1):
                piv = _proto_iv(r.get("protocol"))
                if piv is None:
                    continue
                rports = _rule_ports(r.get("protocol"), r.get("from"), r.get("to"))
                if rports is None or _box_and((piv, rports), (self.p_iv, ports)) is None:
                    continue
                info = (sg_id, idx, r)
                for c in r.get("cidrs") or []:
                    try:
                        net = _net(c)
                    except ValueError:
                        continue
                    if net.version == self.version:
                        allowed.append(((_iv(net), piv, rports), info, c))
                for g in r.get("groups") or []:
                    if isinstance(remote_sgs, list):
                        if g in remote_sgs:
                            if refs is True:
                                for iv in rplace.ivs:
                                    allowed.append(((iv, piv, rports), info, g))
                            elif isinstance(refs, str):
                                maybe.append(((ANY_ADDR, piv, rports), info,
                                              f"security group {self.name(g)}", "ref"))
                            else:
                                no_refs.append((info, g))
                    elif remote_sgs == "any":
                        group_only.append((info, g))
                    elif remote_sgs == "unknown":
                        maybe.append(((ANY_ADDR, piv, rports), info,
                                      f"security group {self.name(g)}", "member"))
                for pl in r.get("prefix_lists") or []:
                    maybe.append(((ANY_ADDR, piv, rports), info, f"prefix list {pl}", "pl"))
                if not r.get("cidrs") and not r.get("groups") and not r.get("prefix_lists"):
                    maybe.append(((ANY_ADDR, piv, rports), info, "", "none"))
        remaining = list(query)
        used = []
        for box, info, src_text in allowed:
            remaining, hit = _region_minus(remaining, box)
            if hit and info not in [u[0] for u in used]:
                used.append((info, src_text))
        all_ivs = _merge(rplace.ivs)
        left_ivs = _merge([b[0] for b in remaining])
        full = _minus(all_ivs, left_ivs)
        for g_info in used:
            sg_id, _, r = g_info[0]
            for g in r.get("groups") or []:
                if isinstance(remote_sgs, list) and g in remote_sgs:
                    self.use_edge(mm.edge_id("sg-reference", g, sg_id) if not egress
                                  else mm.edge_id("sg-reference", sg_id, g))
        node_id = (used[0][0][0] if used else sgs[0])
        if not remaining:
            return Hop(kind, title, "ok", self._sg_ok_text(used, egress, rplace, remote),
                       node_id, side=side, full=all_ivs)
        hit_maybe = [m for m in maybe if any(_box_and(b, m[0]) for b in remaining)]
        if hit_maybe:
            box, (sg_id, idx, r), what, why = hit_maybe[0]
            rule = self._rule_text(r, egress)
            if why == "pl":
                reason = (f"Security group {self.name(sg_id)} allows {rule} (rule {idx}), but the "
                          f"prefix list's addresses aren't in the snapshot, so whether "
                          f"{rplace.text} is in {what.split()[-1]} can't be told.")
            elif why == "ref":
                reason = (f"Security group {self.name(sg_id)} allows {rule} (rule {idx}), which "
                          f"{remote.title} has. {refs}")
            elif why == "member":
                reason = (f"Security group {self.name(sg_id)} allows {rule} (rule {idx}). Whether "
                          f"the host at {rplace.text} is in that group isn't known.")
            else:
                reason = (f"Security group {self.name(sg_id)} has a rule for "
                          f"{mm.port_text(PROTOCOL_NAMES.get(mm.protocol_number(r.get('protocol')), r.get('protocol')), r.get('from'), r.get('to'))} "
                          f"(rule {idx}) with no source recorded: a prefix list, which "
                          "snapshots before reachability didn't record (rescan to check it), or "
                          "an address Terraform only knows after apply.")
            return Hop(kind, title, "unknown", reason, sg_id, side=side, full=None)
        if not used:
            if group_only:
                (sg_id, idx, r), g = group_only[0]
                return Hop(kind, title, "blocked",
                           f"Security group {self.name(sg_id)} allows {self.traffic} only "
                           f"{tofrom} hosts in security group {self.named(g)} (rule {idx}), not "
                           f"{tofrom} any host in {remote.title}.", sg_id, partial=True,
                           side=side, full=None, fix=self._sg_fix(host, sgs[0], egress, remote, rplace))
            reason = (f"No {word} rule in {('security group ' + names[0]) if len(sgs) == 1 else 'its security groups'} "
                      f"allows {self.traffic} {tofrom} {rplace.text}.")
            if no_refs:
                (sg_id, idx, r), g = no_refs[0]
                reason += (f" Rule {idx} of {self.name(sg_id)} allows security group "
                           f"{self.name(g)}, which {remote.title} has, but security group "
                           "references don't work across a peering between regions.")
            listing = self._rules_listing(sgs, direction, egress)
            if listing:
                reason += f" Its {word} rules allow: {listing}."
            return Hop(kind, title, "blocked", reason, sgs[0], side=side, full=[],
                       fix=self._sg_fix(host, sgs[0], egress, remote, rplace))
        part = _ivs_text(full, self.version) if full else ""
        if not full:
            # Rules allow some of the traffic (other protocols or ports) but not all of it.
            return Hop(kind, title, "blocked",
                       f"{self._sg_ok_text(used, egress, rplace, remote, True)} That's only "
                       f"part of {self.traffic}.", node_id, partial=True, side=side, full=[],
                       fix=self._sg_fix(host, sgs[0], egress, remote, rplace))
        return Hop(kind, title, "blocked",
                   f"{self._sg_ok_text(used, egress, rplace, remote, True)} So only {part} of "
                   f"{rplace.text} is allowed; the rest ({_ivs_text(left_ivs, self.version)}) "
                   "isn't.", node_id, partial=True, side=side, full=full,
                   fix=self._sg_fix(host, sgs[0], egress, remote, rplace))

    def _membership(self, ep):
        """Which security groups the other side is in: a list, or "any" (a subnet or a
        range, so some hosts maybe), "unknown" (one host nothing on the map has), or
        "none" (outside AWS)."""
        if ep.kind in ("internet", "outside"):
            return "none"
        if ep.kind in ("subnet", "cidr"):
            return "any"
        if ep.kind == "address":
            return "unknown"
        if ep.security_groups is None:
            return "unknown"
        return list(ep.security_groups)

    def _rule_text(self, r, egress) -> str:
        proto = PROTOCOL_NAMES.get(mm.protocol_number(r.get("protocol")), str(r.get("protocol")))
        what = mm.port_text(proto, r.get("from"), r.get("to"))
        srcs = list(r.get("cidrs") or []) + [self.name(g) for g in r.get("groups") or []] + \
            list(r.get("prefix_lists") or [])
        return f"{what} {'to' if egress else 'from'} {', '.join(srcs) or 'nothing recorded'}"

    def _sg_ok_text(self, used, egress, rplace, remote, partly=False) -> str:
        parts = []
        by_sg = {}
        for (sg_id, idx, r), _ in used:
            by_sg.setdefault(sg_id, []).append((idx, r))
        for sg_id, rules in by_sg.items():
            texts = "; ".join(f"{self._rule_text(r, egress)} (rule {idx})" for idx, r in rules[:3])
            parts.append(f"Security group {self.name(sg_id)} allows {texts}")
        text = ". ".join(parts) + "."
        if partly:
            return text
        groups = [src for _, src in used if str(src).startswith("sg-") or
                  (self.snap.get(src) is not None and self.snap.get(src).kind == "sg")]
        if groups:
            text += f" {remote.title} is in {self.name(groups[0])}."
        elif not any(src == rplace.text for _, src in used):
            text += f" That covers {rplace.text}."
        return text

    def _rules_listing(self, sgs, direction, egress) -> str:
        items = []
        for sg_id in sgs:
            for r in (self.snap.get(sg_id).props.get(direction) or []):
                items.append(self._rule_text(r, egress))
        if not items:
            return ""
        return "; ".join(items[:4]) + (f"; and {len(items) - 4} more" if len(items) > 4 else "")

    def _sg_fix(self, host, sg_id, egress, remote, rplace) -> str:
        """The AWS CLI command that would allow it. Read-only tool: shown, never run."""
        if not _cli_id(sg_id, "sg"):
            return ""
        if self.protocol == "all":
            perm = "IpProtocol=-1"
        elif self.protocol in ("icmp", "icmpv6"):
            perm = f"IpProtocol={'icmp' if self.version == 4 else 'icmpv6'},FromPort=-1,ToPort=-1"
        else:
            perm = f"IpProtocol={self.protocol},FromPort={self.port},ToPort={self.port}"
        others = self._membership(remote)
        same = isinstance(others, list) and others and _cli_id(others[0], "sg") and \
            self.snap.vpc_of(self.snap.get(sg_id)) == self.snap.vpc_of(self.snap.get(others[0]))
        if same:
            perm += f",UserIdGroupPairs=[{{GroupId={others[0]}}}]"
        else:
            cidrs = _cidrs(rplace.ivs, self.version) if not (remote.any_internet) else \
                ["0.0.0.0/0" if self.version == 4 else "::/0"]
            if len(cidrs) > 3:
                return ""
            key = "IpRanges" if self.version == 4 else "Ipv6Ranges"
            field_ = "CidrIp" if self.version == 4 else "CidrIpv6"
            perm += f",{key}=[" + ",".join(f"{{{field_}={c}}}" for c in cidrs) + "]"
        verb = "egress" if egress else "ingress"
        return f"aws ec2 authorize-security-group-{verb} --group-id {sg_id} --ip-permissions '{perm}'"

    # ---- network ACLs
    def nacl_for(self, subnet_id):
        if subnet_id in self._acl_cache:
            return self._acl_cache[subnet_id]
        found = None
        acls = [n for n in self.snap.of_kind("nacl") if subnet_id in (n.props.get("subnets") or [])]
        explicit = [n for n in acls if not n.props.get("default")] or acls
        if explicit:
            found = explicit[0]
        else:
            vpc = self.snap.vpc_of(self.snap.get(subnet_id))
            defaults = [n for n in self.snap.of_kind("nacl") if n.props.get("default") and
                        (n.props.get("vpc") == vpc or n.parent == vpc)]
            found = defaults[0] if defaults else None
        self._acl_cache[subnet_id] = found
        return found

    def nacl_hop(self, subnet_id, egress, rplace, kind, reply=False, client="") -> Hop:
        leg = "back" if reply else "there"
        word = "outbound" if egress else "inbound"
        if reply:
            word = "replies out" if egress else "replies in"
        # Whose addresses the rules match: the source's for traffic coming in to the
        # destination or the NAT gateway, and for replies going back to it.
        side = "src" if kind in ("nacl-in", "nacl-back-out", "nat-nacl-in", "nat-nacl-back-out") \
            else "dst"
        if reply:
            self.replies_checked = True
        sn = self.snap.get(subnet_id) if subnet_id else None
        if sn is None:
            return Hop(kind, f"Network ACL, {word}", "unknown",
                       "That side isn't in this snapshot (like a VPC on the other side of a "
                       "peering), so its network ACL wasn't checked.", leg=leg)
        sname = mm.title_of(sn)
        where = " (the NAT gateway's subnet)" if kind.startswith("nat-") else ""
        acl = self.nacl_for(subnet_id)
        if acl is None:
            if self.snap.source == "terraform":
                if sname not in self.assumed_acl:
                    self.assumed_acl.append(sname)
                return Hop(kind, f"Network ACL of {sname}{where}, {word}", "ok",
                           f"No network ACL for {sname} is in the Terraform input, so the VPC's "
                           "default network ACL was assumed, which allows all traffic.",
                           subnet_id, leg=leg, side=side, full=list(rplace.ivs))
            return Hop(kind, f"Network ACL of {sname}{where}, {word}", "unknown",
                       f"The network ACL for {sname} isn't in the snapshot. The scan may not "
                       "have been allowed to read network ACLs (ec2:DescribeNetworkAcls).",
                       subnet_id, leg=leg)
        self.use(acl.id)
        aname = self.name(acl.id)
        title = f"Network ACL {aname} of {sname}{where}, {word}"
        if not isinstance(acl.props.get("entries"), list):
            again = " (or read the Terraform again)" if acl.source == "terraform" else ""
            return Hop(kind, title, "unknown",
                       f"Network ACL rules aren't in this snapshot (made before they were "
                       f"recorded); rescan{again} to check them.", acl.id, leg=leg)
        if len(acl.props["entries"]) > MAX_ACL_RULES:
            raise ReachError(f"Network ACL {aname} has {len(acl.props['entries'])} rules, more "
                             "than AWS allows, so the snapshot looks damaged.")
        if acl.props.get("rules_unknown"):
            return Hop(kind, title, "unknown",
                       f"Some of network ACL {aname}'s rules aren't known until Terraform "
                       "applies, so it wasn't checked.", acl.id, leg=leg)
        ports = self.rep if reply else self.req
        decided, unsure = _nacl_eval(acl.props["entries"], egress, self.version, rplace.ivs,
                                     self.p_iv, ports)
        if unsure is not None:
            return Hop(kind, title, "unknown",
                       f"Rule {unsure.get('rule')} of network ACL {aname} has no address "
                       "recorded (Terraform may not know it until apply), so whether it "
                       f"matches {self.reply_text() if reply else self.traffic} "
                       f"{'to' if egress else 'from'} {rplace.text} can't be told.",
                       acl.id, leg=leg)
        allowed = [(b, e) for b, a, e in decided if a == "allow"]
        denied = [(b, e) for b, a, e in decided if a != "allow"]
        all_ivs = _merge(rplace.ivs)
        some = _merge([b[0] for b, _ in allowed])
        full = _minus(all_ivs, [b[0] for b, _ in denied])
        tofrom = "to" if egress else "from"
        what = self.reply_text() if reply else self.traffic
        direction = "out" if egress else "in"
        if not denied:
            rules = _rule_list([e for _, e in allowed])
            if reply:
                reason = (f"Network ACL {aname} lets {what} {direction} {tofrom} {rplace.text} "
                          f"at {rules}.")
            else:
                reason = f"Network ACL {aname} allows {what} {direction} {tofrom} {rplace.text} at {rules}."
            return Hop(kind, title, "ok", reason, acl.id, leg=leg, side=side, full=all_ivs)
        deny_rules = _rule_list([e for _, e in denied])
        default_only = all(e is None or _is_default_rule(e) for _, e in denied)
        if not allowed:
            if default_only:
                reason = (f"Network ACL {aname} has no rule that allows {what} {direction} "
                          f"{tofrom} {rplace.text}, so the default rule (*) denies it.")
            else:
                reason = (f"Network ACL {aname} denies {what} {direction} {tofrom} "
                          f"{rplace.text} at {deny_rules}.")
            if reply:
                reason += " Network ACLs are stateless, so replies need a rule of their own."
            return Hop(kind, title, "blocked", reason, acl.id, leg=leg, side=side, full=[],
                       fix=self._nacl_fix(acl, egress, rplace, reply, denied))
        # Some of it is allowed and some isn't.
        if reply and self.protocol in ("tcp", "udp") and some == all_ivs:
            ok_ports = _ports_text(_merge([b[2] for b, _ in allowed]))
            no_ports = _ports_text(_merge([b[2] for b, _ in denied]))
            reason = (f"Network ACL {aname} only lets replies {direction} {tofrom} {rplace.text} "
                      f"on ports {ok_ports} ({_rule_list([e for _, e in allowed])}). Replies to "
                      f"ports {no_ports} are dropped ({deny_rules}).")
            if client in ("nat", "lb"):
                who = "A NAT gateway" if client == "nat" else "A load balancer"
                reason += f" {who} uses ports 1024-65535, so some connections fail."
                return Hop(kind, title, "blocked", reason, acl.id, leg=leg, partial=True,
                           side=side, full=all_ivs,
                           fix=self._nacl_fix(acl, egress, rplace, reply, denied))
            reason += (" That depends on the client's ephemeral ports: Linux uses 32768-60999, "
                       "Windows 49152-65535, NAT gateways and load balancers 1024-65535.")
            return Hop(kind, title, "unknown", reason, acl.id, leg=leg, side=side, full=None)
        if not full:
            reason = (f"Network ACL {aname} allows only part of {what} {direction} {tofrom} "
                      f"{rplace.text} ({_rule_list([e for _, e in allowed])}); the rest is "
                      f"denied at {deny_rules}.")
            return Hop(kind, title, "blocked", reason, acl.id, leg=leg, partial=True, side=side,
                       full=[], fix=self._nacl_fix(acl, egress, rplace, reply, denied))
        reason = (f"Network ACL {aname} allows {what} {direction} {tofrom} only part of "
                  f"{rplace.text}: {_ivs_text(full, self.version)} "
                  f"({_rule_list([e for _, e in allowed])}). The rest "
                  f"({_ivs_text(_minus(all_ivs, full), self.version)}) is denied at {deny_rules}.")
        return Hop(kind, title, "blocked", reason, acl.id, leg=leg, partial=True, side=side,
                   full=full, fix=self._nacl_fix(acl, egress, rplace, reply, denied))

    def _nacl_fix(self, acl, egress, rplace, reply, denied) -> str:
        if not _cli_id(acl.id, "acl"):
            return ""
        cidrs = _cidrs(rplace.ivs, self.version)
        if rplace.anywhere:
            cidrs = ["0.0.0.0/0" if self.version == 4 else "::/0"]
        if len(cidrs) != 1:
            return ""
        used = {int(e.get("rule", 0)) for e in acl.props.get("entries") or []
                if bool(e.get("egress")) == egress}
        first_deny = min([int(e["rule"]) for _, e in denied if e is not None and
                          not _is_default_rule(e)] or [mm.NACL_DEFAULT_RULE])
        number = None
        for n in list(range(100, first_deny, 10)) + list(range(first_deny - 1, 0, -1)):
            if n < first_deny and n not in used:
                number = n
                break
        if number is None:
            return ""
        if self.protocol == "all":
            proto = "--protocol -1"
        elif self.protocol in ("icmp", "icmpv6"):
            num = "1" if self.version == 4 else "58"
            proto = f"--protocol {num} --icmp-type-code Type=-1,Code=-1"
        else:
            lo, hi = (EPHEMERAL if reply else (self.port, self.port))
            proto = f"--protocol {self.protocol} --port-range From={lo},To={hi}"
        block = f"--cidr-block {cidrs[0]}" if self.version == 4 else f"--ipv6-cidr-block {cidrs[0]}"
        return (f"aws ec2 create-network-acl-entry --network-acl-id {acl.id} "
                f"{'--egress' if egress else '--ingress'} --rule-number {number} {proto} "
                f"{block} --rule-action allow")

    # ---- routes
    def route_table(self, subnet_id):
        sn = self.snap.get(subnet_id)
        rt_id = sn.props.get("route_table") if sn is not None else ""
        return self.snap.get(rt_id) if rt_id else None

    def routes_of(self, rt, vpc_id) -> list:
        routes = []
        if rt is not None:
            routes += [dict(r) for r in rt.props.get("routes") or []]
            routes += [dict(r, blackhole=True) for r in rt.props.get("blackholes") or []]
        vpc = self.snap.get(vpc_id)
        have = {r.get("dest") for r in routes}
        local = list(vpc.props.get("cidrs") or []) if vpc is not None else []
        for sn in self.snap.of_kind("subnet"):
            if self.snap.vpc_of(sn) == vpc_id and sn.props.get("ipv6_cidr"):
                local.append(sn.props["ipv6_cidr"])
        for c in local:
            if c and c not in have:
                routes.append({"dest": c, "target": "local"})   # every table has it
        return routes

    def lookup(self, subnet_id, rplace, kind="route", leg="there"):
        """The route a subnet's table picks for the other side's addresses: longest
        prefix first, blackholes included."""
        return _Route(self, subnet_id, rplace, kind, leg)

    def local_route_hop(self, sp, dp, kind, quiet=False):
        leg = "back" if kind == "route-back" else "there"
        r = self.lookup(sp.subnet, dp, kind, leg)
        if r.hop.status == "ok" and r.kind == "local":
            return None if quiet else r.hop
        if r.hop.status != "ok":
            return r.hop
        if r.kind in MIDDLEBOX:
            r.hop.status = "unknown"
            r.hop.reason += (" That's more specific than the local route, so the traffic goes "
                             "through it first (like a firewall appliance), and what it does "
                             "isn't checked.")
        else:
            r.hop.status = "blocked"
            r.hop.reason += " Traffic inside a VPC should take the local route."
        return r.hop

    def route_between(self, sp, dp):
        """Source subnet to another VPC: the route, then the peering or transit gateway.
        Returns (hops, whether security group references work, (kind, target)). That's
        True, False (a peering between regions), or why it can't be told."""
        r = self.lookup(sp.subnet, dp)
        hops = [r.hop]
        if r.hop.status != "ok" or r.route is None:
            return hops, REFS_NO_ROUTE, (r.kind, r.target)
        kind, target = r.kind, r.target
        dvpc = self.name(dp.vpc)
        if kind == "local":
            r.hop.status = "blocked"
            r.hop.reason += (f" {dp.text} is inside this VPC's own range (the VPCs overlap), so "
                             f"the traffic never leaves {self.name(sp.vpc)}.")
            return hops, REFS_NO_ROUTE, (kind, target)
        if kind == "peering":
            hop, refs = self.peering_hop(target, sp.vpc, dp.vpc)
            hops.append(hop)
            return hops, refs, (kind, target)
        if kind == "tgw":
            hops.append(self.tgw_hop(target, sp.vpc, dp.vpc))
            return hops, REFS_TGW, (kind, target)
        if kind in ("igw", "nat", "eigw"):
            r.hop.status = "blocked"
            r.hop.reason += (f" Private addresses in another VPC ({dvpc}) aren't reachable that "
                             "way. It needs a route through a peering connection or a transit "
                             "gateway.")
        else:
            r.hop.status = "unknown"
            r.hop.reason += _beyond(kind)
        return hops, REFS_NO_ROUTE, (kind, target)

    def peering_hop(self, pcx, svpc, dvpc):
        edge = next((e for e in self.snap.edges.values() if e.kind == "peering" and
                     e.props.get("pcx") == pcx), None)
        title = f"Peering connection {pcx}"
        if edge is None:
            return Hop("peering", title, "unknown",
                       f"Peering connection {pcx} isn't in the snapshot, so where it goes isn't "
                       "known.", ""), REFS_NO_ROUTE
        self.use_edge(edge.id)
        other = edge.dst if edge.src == svpc else (edge.src if edge.dst == svpc else "")
        if not other:
            return Hop("peering", title, "blocked",
                       f"{pcx} doesn't connect to {self.name(svpc)}.", "", edge.id), REFS_NO_ROUTE
        if other != dvpc:
            return Hop("peering", title, "blocked",
                       f"{pcx} connects {self.name(svpc)} to {self.name(other)}, not to "
                       f"{self.name(dvpc)}. Peering isn't transitive: each pair of VPCs needs "
                       "its own.", "", edge.id), REFS_NO_ROUTE
        status = str(edge.props.get("status") or "")
        if status and status not in ("active",):
            return Hop("peering", title, "blocked",
                       f"{pcx} isn't active ({status}).", "", edge.id), REFS_NO_ROUTE
        a, b = self.snap.get(svpc), self.snap.get(dvpc)
        ra, rb = (a.region if a else ""), (b.region if b else "")
        known = ra and rb and mm.UNKNOWN_REGION not in (ra, rb)
        refs = True if known and ra == rb else (False if known else REFS_REGIONS)
        where = f", across regions ({ra} and {rb})" if refs is False else ""
        if refs is False:
            self.note("Security group rules that reference a group in the other VPC don't work "
                      "across a peering between regions. Only CIDR rules count there.")
        return Hop("peering", title, "ok",
                   f"{pcx} connects {self.name(svpc)} and {self.name(dvpc)}{where}.", "",
                   edge.id), refs

    def tgw_hop(self, tgw, svpc, dvpc) -> Hop:
        atts = [n for n in self.snap.of_kind("tgw-attachment") if n.props.get("tgw") == tgw]
        title = f"Transit gateway {self.name(tgw)}"
        self.use(tgw)
        for n in atts:
            if n.props.get("vpc") in (svpc, dvpc) or n.parent in (svpc, dvpc):
                self.use(n.id)
                self.use_edge(mm.edge_id("tgw-attachment", n.id, tgw))
        mine = [n for n in atts if dvpc in (n.props.get("vpc"), n.parent)]
        self.note("Transit gateway route tables aren't in the snapshot. Neither are the network "
                  "ACLs on the transit gateway's attachment subnets, which apply to traffic "
                  "going in and out of it.")
        if atts and not mine:
            # Attached to another transit gateway, it can still be reached through a
            # peering between the two, which the snapshot doesn't record.
            elsewhere = [n for n in self.snap.of_kind("tgw-attachment")
                         if dvpc in (n.props.get("vpc"), n.parent) and n.props.get("tgw") != tgw]
            if elsewhere:
                return Hop("tgw", title, "unknown",
                           f"{self.name(dvpc)} is attached to transit gateway "
                           f"{self.name(elsewhere[0].props.get('tgw'))}, not {self.name(tgw)}. "
                           "Whether the two are peered isn't in the snapshot.", tgw)
            return Hop("tgw", title, "blocked",
                       f"{self.name(dvpc)} has no attachment to {self.name(tgw)}.", tgw)
        return Hop("tgw", title, "unknown",
                   f"Transit gateway route tables aren't in the snapshot, so whether "
                   f"{self.name(tgw)} sends the traffic on to {self.name(dvpc)}'s attachment "
                   "wasn't checked.", tgw)

    def route_back_between(self, sp, dp, via) -> Hop:
        kind, target = via
        r = self.lookup(dp.subnet, sp, "route-back", "back")
        want = (f"peering connection {target}" if kind == "peering" else
                f"transit gateway {self.name(target)}") if kind in ("peering", "tgw") else ""
        if r.hop.status == "blocked" and r.route is None and want:
            r.hop.reason += f" Replies need a route back through {want}."
            return r.hop
        if r.hop.status != "ok" or r.route is None:
            return r.hop
        if want and r.kind == kind and r.target == target:
            r.hop.reason += " That's the way the traffic came, so replies get back."
            return r.hop
        if want and r.kind == "peering":
            # Another way back than the way there still works when that peering connection
            # joins the two VPCs: security groups track connections on each host, not by path.
            edge = next((e for e in self.snap.edges.values() if e.kind == "peering" and
                         e.props.get("pcx") == r.target), None)
            if edge is not None and {edge.src, edge.dst} == {sp.vpc, dp.vpc} and \
                    str(edge.props.get("status") or "active") == "active":
                self.use_edge(edge.id)
                r.hop.reason += (f" That isn't the way the traffic came, but {r.target} joins the "
                                 "two VPCs, so replies get back.")
                return r.hop
            if edge is None:
                r.hop.status = "unknown"
                r.hop.reason += f" {r.target} isn't in the snapshot, so where it goes isn't known."
                return r.hop
        if want and (r.kind in ("tgw", "vgw") or r.kind in MIDDLEBOX):
            r.hop.status = "unknown"
            r.hop.reason += (" That isn't the way the traffic came, which can still work."
                             + _beyond(r.kind))
            return r.hop
        if want:
            r.hop.status = "blocked"
            r.hop.reason += (f" Replies need to go back through {want}, so add a route for "
                             f"{sp.text} there.")
            return r.hop
        r.hop.status = "unknown"
        return r.hop

    def route_back_outside(self, dp, sp) -> Hop:
        r = self.lookup(dp.subnet, sp, "route-back", "back")
        if r.hop.status != "ok" or r.route is None:
            return r.hop
        internet = self.src.kind == "internet"
        if internet:
            if r.kind == "igw":
                gw = self.snap.get(r.target)
                if gw is not None and (gw.props.get("vpc") or gw.parent) not in ("", dp.vpc):
                    r.hop.status = "blocked"
                    r.hop.reason += f" But {r.target} isn't attached to this VPC."
                else:
                    r.hop.reason += " Replies go back out the way they came."
                return r.hop
            r.hop.status = "blocked"
            if r.kind == "nat":
                r.hop.reason += (" Replies leave through the NAT gateway with its address, not "
                                 f"the one the client connected to, so the connection fails. "
                                 f"{self.name(dp.subnet)} is a private subnet: use a public subnet, "
                                 "or put a load balancer in front.")
            elif r.kind == "eigw":
                r.hop.status = "unknown"
                r.hop.reason += (" An egress-only internet gateway is for connections started "
                                 "from inside, so connections from the internet don't work "
                                 "through it.")
            elif r.kind in MIDDLEBOX or r.kind in ("tgw", "vgw"):
                r.hop.status = "unknown"
                r.hop.reason += _beyond(r.kind)
            else:
                r.hop.reason += " That doesn't lead back to the internet."
            return r.hop
        if r.kind == "igw":
            r.hop.status = "blocked"
            r.hop.reason += f" {self.src.title} is a private address, so it isn't on the internet."
        else:
            r.hop.status = "unknown"
            r.hop.reason += _beyond(r.kind)
        return r.hop

    # ---- gateways and public addresses
    def igw_hop(self, vpc_id) -> Hop:
        igws = [n for n in self.snap.of_kind("igw")
                if (n.props.get("vpc") or n.parent) == vpc_id]
        if not igws:
            return Hop("igw", "Internet gateway", "blocked",
                       f"{self.name(vpc_id)} has no internet gateway, so nothing on the internet "
                       "can reach into it.", vpc_id)
        self.use(igws[0].id)
        return Hop("igw", f"Internet gateway {self.name(igws[0].id)}", "ok",
                   f"{self.name(vpc_id)} has internet gateway {self.named(igws[0].id)}.",
                   igws[0].id)

    def igw_out_hops(self, sp, route) -> list:
        hops = []
        gw = self.snap.get(route.target)
        if gw is not None and (gw.props.get("vpc") or gw.parent) not in ("", sp.vpc):
            hops.append(Hop("igw", f"Internet gateway {route.target}", "blocked",
                            f"{route.target} isn't attached to {self.name(sp.vpc)}.", route.target))
        hops.append(self.public_hop_src(sp))
        return hops

    def public_hop_src(self, sp) -> Hop:
        ep = self.src
        title = f"Public address of {ep.title}"
        if self.version == 6:
            return Hop("public-ip", title, "ok",
                       f"{ep.title} uses its IPv6 address ({sp.text}), which works on the "
                       "internet as it is.", ep.node_id)
        if ep.kind == "instance":
            ip = ep.public_ip
            if ip and _valid_ip(ip) is not None:
                return Hop("public-ip", title, "ok", f"{ep.title} has public IP {ip}.", ep.node_id)
            if ip:
                return Hop("public-ip", title, "ok",
                           f"{ep.title} gets a public IP when it's created.", ep.node_id)
            return Hop("public-ip", title, "blocked",
                       f"{ep.title} has no public IP. Without one, the internet gateway can't carry "
                       "its traffic: give it a public or Elastic IP, or route through a NAT "
                       "gateway.", ep.node_id)
        if ep.kind == "subnet":
            sn = self.snap.get(sp.subnet)
            if sn is not None and sn.props.get("map_public_ip"):
                return Hop("public-ip", title, "ok",
                           f"Hosts launched in {ep.title} get a public IP by default.", ep.node_id)
            return Hop("public-ip", title, "unknown",
                       f"Only hosts in {ep.title} with a public or Elastic IP can use the internet "
                       "gateway, and the subnet doesn't give one at launch.", ep.node_id)
        return Hop("public-ip", title, "unknown",
                   f"Whether {ep.title} has a public IP isn't known.", ep.node_id)

    def public_hop_dst(self, dp) -> Hop:
        ep = self.dst
        title = f"Public address of {ep.title}"
        node = self.snap.get(ep.node_id)
        p = node.props if node is not None else {}
        if self.version == 6:
            # IPv6 addresses work on the internet as they are, but AWS blocks internet
            # gateway traffic to an internal load balancer and to a database that isn't
            # publicly accessible.
            if ep.kind == "lb" and str(p.get("scheme") or "") == "internal":
                return Hop("public-ip", title, "blocked",
                           f"{ep.title} is an internal load balancer. AWS blocks traffic from the "
                           "internet gateway to its IPv6 addresses.", ep.node_id)
            if ep.kind == "rds" and not p.get("public"):
                return Hop("public-ip", title, "blocked",
                           f"{ep.title} isn't publicly accessible, so its IPv6 address can only be "
                           "reached from inside the VPC.", ep.node_id)
            if ep.kind in ("instance", "lb", "rds") or ep.kind == "subnet":
                return Hop("public-ip", title, "ok",
                           f"{ep.title} has an IPv6 address ({dp.text}), which the internet can "
                           "reach as it is.", ep.node_id)
            return Hop("public-ip", title, "unknown",
                       f"Whether {ep.title} is a host with that IPv6 address isn't known.")
        if ep.kind == "instance":
            ip = ep.public_ip
            if ip and _valid_ip(ip) is not None:
                return Hop("public-ip", title, "ok", f"{ep.title} has public IP {ip}.", ep.node_id)
            if ip:
                return Hop("public-ip", title, "ok", f"{ep.title} gets a public IP when it's "
                           "created.", ep.node_id)
            return Hop("public-ip", title, "blocked",
                       f"{ep.title} has no public IP address, so nothing on the internet can reach "
                       "it. Put it behind a load balancer, or give it a public or Elastic IP in a "
                       "public subnet.", ep.node_id)
        if ep.kind == "lb":
            scheme = str(p.get("scheme") or "")
            if scheme == "internet-facing":
                return Hop("public-ip", title, "ok", f"{ep.title} is internet-facing.", ep.node_id)
            if scheme == "internal":
                return Hop("public-ip", title, "blocked",
                           f"{ep.title} is an internal load balancer, with private addresses only.",
                           ep.node_id)
            return Hop("public-ip", title, "unknown",
                       f"Whether {ep.title} is internet-facing isn't known.", ep.node_id)
        if ep.kind == "rds":
            if p.get("public"):
                return Hop("public-ip", title, "ok",
                           f"{ep.title} is publicly accessible. It also has to be in a public "
                           "subnet, which the route back checks.", ep.node_id)
            return Hop("public-ip", title, "blocked",
                       f"{ep.title} isn't publicly accessible, so it only has a private address.",
                       ep.node_id)
        if ep.kind == "subnet":
            sn = self.snap.get(dp.subnet)
            if sn is not None and sn.props.get("map_public_ip"):
                return Hop("public-ip", title, "ok",
                           f"Hosts launched in {ep.title} get a public IP by default.", ep.node_id)
            return Hop("public-ip", title, "unknown",
                       f"Only hosts in {ep.title} with a public or Elastic IP can be reached from "
                       "the internet, and the subnet doesn't give one at launch.", ep.node_id)
        return Hop("public-ip", title, "unknown",
                   f"Whether {ep.title} has a public IP isn't known.")

    def nat_hops(self, sp, dp, route) -> list:
        hops = []
        nat = self.snap.get(route.target)
        title = f"NAT gateway {self.name(route.target)}"
        if nat is None:
            route.hop.status = "unknown"
            route.hop.reason += f" {route.target} isn't in the snapshot."
            return hops
        self.use(nat.id)
        p = nat.props
        state = str(p.get("state") or "")
        nat_subnet = p.get("subnet") or nat.parent
        to_internet = self.dst.kind == "internet"
        if state and state not in ("available",):
            hops.append(Hop("nat", title, "blocked", f"{self.named(nat.id)} is {state}.", nat.id))
            return hops
        if self.version == 6:
            hops.append(Hop("nat", title, "unknown",
                            "A NAT gateway only translates IPv6 to IPv4 (NAT64, with DNS64 turned "
                            "on), which isn't checked.", nat.id))
            return hops
        if to_internet and str(p.get("connectivity") or "public") == "private":
            hops.append(Hop("nat", title, "blocked",
                            f"{self.named(nat.id)} is a private NAT gateway, which can't reach the "
                            "internet.", nat.id))
            return hops
        self.use(nat_subnet)
        if nat_subnet and nat_subnet != sp.subnet:
            hops.append(self.nacl_hop(nat_subnet, False, sp, "nat-nacl-in"))
        ip = str(p.get("public_ip") or "")
        hops.append(Hop("nat", title, "ok",
                        f"{self.named(nat.id)} in {self.name(nat_subnet)} sends it on"
                        + (f" from {ip}" if ip and to_internet else "") + ".", nat.id))
        r = self.lookup(nat_subnet, dp, "nat-route")
        r.hop.title = f"Route table for the NAT gateway's subnet {self.name(nat_subnet)}"
        hops.append(r.hop)
        if r.hop.status == "ok" and r.route is not None:
            if to_internet:
                if r.kind == "igw":
                    r.hop.reason += " The NAT gateway reaches the internet that way."
                elif r.kind == "nat":
                    r.hop.status = "blocked"
                    r.hop.reason += (" A NAT gateway can't send through another NAT gateway. Its "
                                     "subnet needs a route to an internet gateway.")
                elif r.kind in ("local", "peering", "eigw"):
                    r.hop.status = "blocked"
                    r.hop.reason += (" The NAT gateway's subnet needs a route to an internet "
                                     "gateway for that.")
                else:
                    r.hop.status = "unknown"
                    r.hop.reason += _beyond(r.kind)
            elif r.kind in ("igw", "eigw"):
                r.hop.status = "blocked"
                r.hop.reason += f" {self.dst.title} is a private address, not on the internet."
            else:
                # A transit gateway, a VPN, a peering connection, an appliance: nothing on
                # the other side is in this check, so it can't pass.
                r.hop.status = "unknown"
                r.hop.reason += _beyond(r.kind)
        elif r.route is None and r.hop.status == "blocked":
            r.hop.reason += (" The NAT gateway's subnet needs a route to an internet gateway: "
                             "it's probably in a private subnet.")
        hops.append(self.nacl_hop(nat_subnet, True, dp, "nat-nacl-out"))
        hops.append(self.nacl_hop(nat_subnet, False, dp, "nat-nacl-back-in", reply=True,
                                  client="nat"))
        if nat_subnet and nat_subnet != sp.subnet:
            hops.append(self.nacl_hop(nat_subnet, True, sp, "nat-nacl-back-out", reply=True,
                                      client=self.src.kind))
        return hops

    # ---- what the destination listens on
    def service_hops(self) -> list:
        d = self.dst
        if d.kind == "instance":
            self.note(f"Not checked: whether something on {d.title} listens on {self.traffic}, "
                      "and any firewall inside it.")
            return []
        if d.kind not in ("rds", "lb"):
            return []
        title = f"What {d.title} listens on"
        if d.kind == "lb" and self.protocol in ("icmp", "icmpv6"):
            return [Hop("service", title, "blocked",
                        f"Load balancers don't answer ping. {d.title} only answers on its "
                        "listeners.", d.node_id)]
        if not d.ports_known:
            if d.kind == "lb":
                self.note(f"{d.title}'s listeners aren't in the snapshot, so whether it listens on "
                          f"{self.traffic} wasn't checked.")
            return []
        if self.protocol == "all":
            return []
        if d.kind == "rds":
            port = d.ports[0][0]
            if self.protocol == "tcp" and self.port == port:
                return [Hop("service", title, "ok", f"{d.title} listens on tcp {port}.", d.node_id)]
            if self.protocol == "tcp":
                return [Hop("service", title, "blocked",
                            f"{d.title} listens on tcp {port}, not {self.port}.", d.node_id)]
            return [Hop("service", title, "blocked",
                        f"A database only answers on its port, tcp {port}.", d.node_id)]
        listening = []
        for port, proto in d.ports:
            proto = proto.upper()
            carries = {"HTTP": "tcp", "HTTPS": "tcp", "TCP": "tcp", "TLS": "tcp", "UDP": "udp",
                       "TCP_UDP": "both", "GENEVE": "udp"}.get(proto, "tcp")
            if port == self.port and carries in (self.protocol, "both"):
                listening.append(f"{port} ({proto})" if proto else str(port))
        if listening:
            return [Hop("service", title, "ok",
                        f"{d.title} has a listener on {self.protocol} {listening[0]}.", d.node_id)]
        have = ", ".join(f"{p} ({pr})" if pr else str(p) for p, pr in d.ports) or "none"
        return [Hop("service", title, "blocked",
                    f"{d.title} has no listener on {self.traffic}. Its listeners: {have}.",
                    d.node_id)]

    # ---- the verdict
    def finish(self, paths, hops, src_places=(), dst_places=()) -> Result:
        n = max(len(dst_places), 1)
        states = [_path_state(path, src_places[i // n] if src_places else None,
                              dst_places[i % n] if dst_places else None)
                  for i, path in enumerate(paths)]
        kinds = [st[0] for st in states]
        partial = False
        if all(k == "reachable" for k in kinds):
            verdict = "reachable"
        elif all(k == "blocked" for k in kinds):
            verdict = "blocked"
        elif any(k in ("blocked", "partial") for k in kinds):
            verdict, partial = "blocked", True
        else:
            verdict = "unknown"
        if self.assumed_acl:
            self.note("No network ACL for " + mm.join_names(self.assumed_acl, 4) + " is in the "
                      "Terraform input, so the VPC's default network ACL was assumed. It allows "
                      "all traffic unless it was changed outside this Terraform.")
        if self.replies_checked and self.protocol in ("tcp", "udp"):
            self.note("Network ACLs are stateless, so replies were checked on ports 1024-65535, "
                      "the ephemeral range AWS recommends they allow. It covers Linux "
                      "(32768-60999), Windows (49152-65535), NAT gateways and load balancers.")
        if self.protocol in ("icmp", "icmpv6"):
            self.note("ICMP is checked as ping: an echo request there and an echo reply back.")
        if any(h.kind.startswith("sg") and h.status != "skipped" for h in hops):
            self.note("Security groups are stateful, so replies don't need a rule there.")
        summary = self.summary(verdict, partial, hops, states, src_places, dst_places)
        nodes = [nid for nid in self.nodes if self.snap.get(nid) is not None]
        for h in hops:
            if h.node_id and self.snap.get(h.node_id) is not None and h.node_id not in nodes:
                nodes.append(h.node_id)
            if h.edge_id:
                self.use_edge(h.edge_id)
        if self.dst.node_id in nodes:
            nodes.remove(self.dst.node_id)
            nodes.append(self.dst.node_id)
        return Result(verdict, summary, self.src, self.dst, self.protocol,
                      None if self.protocol in ("all", "icmp", "icmpv6") else self.port,
                      hops, list(self.notes), nodes, list(self.edges), partial)

    def summary(self, verdict, partial, hops, states, src_places, dst_places) -> str:
        s, d, t = self.src.title, self.dst.phrase, self.traffic
        blocked = next((h for h in hops if h.status == "blocked"), None)
        unknown = next((h for h in hops if h.status == "unknown"), None)
        if verdict == "reachable":
            text = f"{s} can reach {d} on {t}, as far as Cloud Map can tell."
            skipped = [h for h in hops if h.status == "skipped" and h.kind.startswith("sg")
                       and h.reason != "Not in AWS."]
            if skipped:
                text += " That's at the network level. " + skipped[0].reason
            return text
        if verdict == "blocked":
            why = blocked.reason if blocked is not None else ""
            if not partial:
                return f"{s} can't reach {d} on {t}. {why}".strip()
            kinds = {st[0] for st in states}
            if len(states) > 1 and kinds & {"reachable", "unknown"}:
                return (f"{s} can reach {d} on {t} through only some of the subnets "
                        f"involved. {why}").strip()
            got_src = _merge([iv for st in states if st[0] == "partial" for iv in st[1]])
            got_dst = _merge([iv for st in states if st[0] == "partial" for iv in st[2]])
            all_src = _merge([iv for pl in src_places for iv in pl.ivs])
            all_dst = _merge([iv for pl in dst_places for iv in pl.ivs])
            if got_src and got_src != all_src:
                lead = (f"Only part of {self.src.phrase} can reach {d} on {t}: "
                        f"{_ivs_text(got_src, self.version)}.")
            elif got_dst and got_dst != all_dst:
                lead = (f"{s} can reach only part of {d} on {t}: "
                        f"{_ivs_text(got_dst, self.version)}.")
            else:
                lead = f"{s} can reach {d} on {t} only partly."
            return f"{lead} {why}".strip()
        text = f"Can't tell whether {self.src.phrase} can reach {d} on {t}."
        if unknown is not None:
            text += " " + unknown.reason
        if all(h.status in ("ok", "skipped") for h in hops if h is not unknown):
            text += " Everything else on the way allows it."
        return text


HOP_ORDER = ("state", "address", "sg-out", "nacl-out", "route", "nacl", "nat-nacl-in", "nat",
             "nat-route", "nat-nacl-out", "public-ip", "igw", "peering", "tgw", "nacl-in", "sg-in",
             "service",
             "nacl-back-out", "route-back", "nat-nacl-back-in", "nat-nacl-back-out", "nacl-back-in")


def _path_state(hops, sp, dp):
    """(state, surviving source addresses, surviving destination addresses) for one
    source and destination pair. state: reachable, partial, blocked or unknown."""
    src = _merge(sp.ivs) if sp is not None else []
    dst = _merge(dp.ivs) if dp is not None else []
    full_block = any(h.status == "blocked" and not h.partial for h in hops)
    for h in hops:
        if h.full is None or h.status not in ("ok", "blocked"):
            continue
        if h.side == "src":
            src = _and(src, h.full)
        elif h.side == "dst":
            dst = _and(dst, h.full)
    if full_block or (sp is not None and not src) or (dp is not None and not dst):
        return ("blocked", src, dst)
    if any(h.status == "blocked" for h in hops):
        return ("partial", src, dst)
    if any(h.status == "unknown" for h in hops):
        return ("unknown", src, dst)
    return ("reachable", src, dst)


def _is_default_rule(entry) -> bool:
    return entry is None or (int(entry.get("rule", 0)) >= mm.NACL_DEFAULT_RULE
                             and entry.get("action") != "allow")


def _rule_list(entries) -> str:
    nums, default = [], False
    for e in entries:
        if _is_default_rule(e):
            default = True
        elif int(e["rule"]) not in nums:
            nums.append(int(e["rule"]))
    parts = []
    if nums:
        nums.sort()
        parts.append(("rule " if len(nums) == 1 else "rules ") + mm.join_names([str(n) for n in nums], 4))
    if default:
        parts.append("the default rule (*)")
    return " and ".join(parts)


def _ports_text(ivs) -> str:
    return ", ".join(f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in ivs)


def _entry_box(e, version):
    """The box a network ACL rule covers, or None when it can't match. A rule with no
    address at all (one Terraform doesn't know until apply) covers every address, and
    _nacl_eval stops there."""
    cidr = e.get("cidr") if version == 4 else e.get("ipv6_cidr")
    if not e.get("cidr") and not e.get("ipv6_cidr"):
        iv = ANY_ADDR
    elif not cidr:
        return None
    else:
        try:
            net = _net(cidr)
        except ValueError:
            return None
        if net.version != version:
            return None
        iv = _iv(net)
    piv = _proto_iv(e.get("protocol"))
    if piv is None:
        return None
    p = mm.protocol_number(e.get("protocol"))
    if p in ("6", "17"):
        ports = _rule_ports(p, e.get("from"), e.get("to"))
    elif p in ("1", "58"):
        t = mm._int_or_none(e.get("icmp_type"))
        code = mm._int_or_none(e.get("icmp_code"))
        if t is not None and t >= 0 and code is not None and code > 0:
            return None                       # one code other than 0: never ping
        ports = ALL_PORTS if t is None or t < 0 else (t, t)
    else:
        ports = ALL_PORTS
    return (iv, piv, ports)


def _nacl_eval(entries, egress, version, remote_ivs, p_iv, ports):
    """First match wins, lowest rule number first, and anything left over hits the
    catch-all deny. Returns ([(box, action, entry or None)] covering the whole query,
    None), or (what was decided so far, the rule) when a rule whose address isn't known
    could match what's left."""
    region = [(iv, p_iv, ports) for iv in _merge(remote_ivs)]
    decided = []
    rules = sorted((e for e in entries if bool(e.get("egress")) == egress),
                   key=lambda e: int(e.get("rule", 0)))
    for e in rules:
        box = _entry_box(e, version)
        if box is None:
            continue
        if not e.get("cidr") and not e.get("ipv6_cidr"):
            if any(_box_and(b, box) is not None for b in region):
                return decided, e
            continue
        nxt = []
        for b in region:
            inter = _box_and(b, box)
            if inter is None:
                nxt.append(b)
                continue
            decided.append((inter, e.get("action", "deny"), e))
            nxt.extend(_box_minus(b, box))
        region = nxt
        if not region:
            break
    for b in region:
        decided.append((b, "deny", None))
    return decided, None


class _Route:
    """The route one subnet's table picks for a range of addresses, as a hop."""

    def __init__(self, walk, subnet_id, rplace, kind="route", leg="there"):
        self.route, self.kind, self.target = None, "", ""
        snap = walk.snap
        sn = snap.get(subnet_id) if subnet_id else None
        if sn is None:
            self.hop = Hop(kind, "Route table", "unknown",
                           "That side isn't in this snapshot, so its route table wasn't checked.",
                           leg=leg)
            return
        sname = mm.title_of(sn)
        vpc_id = snap.vpc_of(sn)
        rt = walk.route_table(subnet_id)
        rt_name = walk.name(rt.id) if rt is not None else ""
        title = (f"Route table {rt_name} for {sname}" if rt is not None else f"Routes for {sname}")
        if kind == "route-back":
            title += ", replies"
        if rt is not None:
            walk.use(rt.id)
        routes = walk.routes_of(rt, vpc_id)
        best, split, lists = _longest(
            routes, rplace.ivs, walk.version, any_internet=rplace.anywhere,
            kind_of=lambda t: "local" if t == "local" else mm._target_kind(snap, t))
        who = f"Route table {rt_name}" if rt is not None else f"{sname}'s routes"
        if best is not None:
            self.route = best
            self.target = str(best.get("target") or "")
            self.kind = "local" if self.target == "local" else mm._target_kind(snap, self.target)
        if split:
            self.hop = Hop(kind, title, "unknown",
                           f"Parts of {rplace.text} take different routes in {who} ("
                           + "; ".join(f"{r['dest']} to {r['target']}" for r in split[:3])
                           + "), so they can't be checked as one.", rt.id if rt else subnet_id,
                           leg=leg)
            return
        if best is None:
            if rt is None and snap.source == "terraform":
                self.hop = Hop(kind, title, "unknown",
                               f"{sname} has no route table in the Terraform input. It uses its "
                               "VPC's main route table, which isn't in this input either.",
                               subnet_id, leg=leg)
                return
            if rt is None:
                self.hop = Hop(kind, title, "unknown",
                               f"The route table for {sname} isn't in the snapshot.", subnet_id,
                               leg=leg)
                return
            self.hop = Hop(kind, title, "blocked",
                           f"{who} has no route for {rplace.text}"
                           + (" (no 0.0.0.0/0 or ::/0 route)." if rplace.anywhere else "."),
                           rt.id, leg=leg)
            return
        target_text = _target_text(walk, self.kind, self.target)
        edge_id = ""
        tid = mm._route_target(snap, self.target, vpc_id) if self.kind != "local" else ""
        if tid:
            edge_id = mm.edge_id("route", subnet_id, tid)
            walk.use_edge(edge_id)
            walk.use(tid)
        if self.kind == "tgw":
            walk.use(self.target)
        if best.get("blackhole"):
            self.hop = Hop(kind, title, "blocked",
                           f"{who} sends {best['dest']} to {self.target or 'a target'} that's gone "
                           "(a blackhole route), so the traffic is dropped.",
                           rt.id if rt else subnet_id, edge_id, leg)
            return
        reason = f"{who} sends {best['dest']} to {target_text}."
        status = "ok"
        if lists and self.kind != "local":
            custom = [r for r in lists if mm._target_kind(snap, r.get("target")) != "endpoint"]
            if custom and not rplace.anywhere:
                status = "unknown"
                reason += (f" It also has a route to prefix list {custom[0]['dest']}, whose "
                           f"addresses aren't in the snapshot. If it holds {rplace.text}, that "
                           "route may win instead.")
            elif custom:
                walk.note(f"{who} also has a route to prefix list {custom[0]['dest']}, whose "
                          "addresses aren't in the snapshot. Traffic to any of them takes that "
                          "route instead.")
            elif rplace.anywhere and kind == "route" and any(
                    mm._target_kind(snap, r.get("target")) == "endpoint" for r in lists):
                walk.note("Traffic to S3 or DynamoDB addresses takes the gateway endpoint's route "
                          "instead of the default route.")
        self.hop = Hop(kind, title, status, reason, rt.id if rt else subnet_id, edge_id, leg)


def _target_text(walk, kind, target) -> str:
    named = walk.named(target)
    return {"local": "local, inside the VPC",
            "igw": f"internet gateway {named}", "eigw": f"egress-only internet gateway {named}",
            "nat": f"NAT gateway {named}", "tgw": f"transit gateway {named}",
            "peering": f"peering connection {target}", "vgw": f"virtual private gateway {named}",
            "endpoint": f"VPC endpoint {named}", "eni": f"network interface {target}",
            "instance": f"instance {named}"}.get(kind, named)


def _beyond(kind) -> str:
    """Why a route target ends the walk."""
    return {"tgw": " Transit gateway route tables aren't in the snapshot, so where it goes from "
                   "there wasn't checked.",
            "vgw": " That's a VPN or Direct Connect, and what's on the other side isn't in the "
                   "snapshot.",
            "endpoint": " That's a VPC endpoint in the path (like a Gateway Load Balancer or "
                        "Network Firewall endpoint), and what it does isn't checked.",
            "eni": " That's a network interface, like a firewall or NAT instance, and what it "
                   "does isn't checked.",
            "instance": " That's an instance, like a firewall or NAT instance, and what it does "
                        "isn't checked.",
            "peering": " That's a peering connection, and what's on the other side of it isn't "
                       "checked."}.get(kind, " Where it goes from there isn't followed.")


# Route targets that lead to another network (this VPC, a peered one, a transit gateway
# or a VPN). Their addresses aren't "the internet", even when they're public, like a
# VPC's IPv6 range.
OTHER_NETWORKS = ("local", "peering", "tgw", "vgw")


def _longest(routes, ivs, version, any_internet=False, kind_of=None):
    """(best route, routes that take part of the range instead, prefix-list routes).
    kind_of(target) is the target's kind, for the internet."""
    cands, lists = [], []
    for r in routes:
        d = str(r.get("dest", ""))
        if d.startswith("pl-"):
            lists.append(r)
            continue
        try:
            net = _net(d)
        except ValueError:
            continue
        if net.version == version:
            cands.append((net, r))
    ivs = _merge(ivs)
    if any_internet:
        # The default route, unless a more specific route sends part of the internet's
        # addresses somewhere else on the way out (like 0.0.0.0/1 to a firewall, or a
        # blackhole). Routes to other networks are those networks' own addresses.
        kind_of = kind_of or mm.target_type
        default = [r for n, r in cands if n.prefixlen == 0]
        split = [r for n, r in cands if n.prefixlen > 0 and _overlaps(ivs, [_iv(n)]) and
                 (r.get("blackhole") or kind_of(str(r.get("target") or "")) not in OTHER_NETWORKS)]
        return (default[0] if default else None), split, lists
    lo, hi = ivs[0][0], ivs[-1][1]
    containing = [(n, r) for n, r in cands
                  if int(n.network_address) <= lo and hi <= int(n.broadcast_address)]
    best = max(containing, key=lambda x: x[0].prefixlen) if containing else None
    plen = best[0].prefixlen if best else -1
    split = [r for n, r in cands if n.prefixlen > plen and _overlaps(ivs, [_iv(n)])]
    return (best[1] if best else None), split, lists


# =================================================================== the entry point

def default_port(ep):
    """The port worth checking first for a destination, or None: a database's port, or a
    load balancer's listener (443 when it has one)."""
    tcp = [p for p, proto in ep.ports if str(proto).upper() not in ("UDP", "GENEVE")]
    if not tcp:
        return None
    return 443 if 443 in tcp else tcp[0]


def _protocol(protocol) -> str:
    p = str(protocol if protocol is not None else "tcp").strip().lower()
    names = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "-1": "all", "icmp6": "icmpv6",
             "any": "all"}
    p = names.get(p, p)
    if p not in PROTOCOLS:
        raise ReachError(f"Protocol has to be tcp, udp, icmp or all, not {protocol}.")
    return p


@_damaged
def check(snap, src, dst, protocol="tcp", port=443) -> Result:
    """Can src reach dst? src and dst are Endpoints (from endpoints() or resolve()), or
    anything resolve() takes. protocol: tcp, udp, icmp (ping) or all. port: the
    destination port for tcp and udp."""
    s, d = resolve(snap, src), resolve(snap, dst)
    proto = _protocol(protocol)
    if proto in ("tcp", "udp"):
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ReachError(f"The port has to be a number, not {port}.") from None
        if not 0 <= port <= 65535:
            raise ReachError(f"The port has to be between 0 and 65535, not {port}.")
    if s.kind in ("internet", "outside") and d.kind in ("internet", "outside"):
        raise ReachError("Both sides are outside AWS. Pick something on the map for one of them.")
    if s.node_id and s.node_id == d.node_id:
        raise ReachError(f"{s.title} is both the source and the destination. Pick two different "
                         "things.")
    if d.via_public_ip and s.kind != "internet":
        # From inside AWS (or a VPN), traffic to a public IP leaves through an internet or
        # NAT gateway and comes back in from a public address, so the destination's
        # security groups see that address, never the source's groups. That's two checks.
        raise ReachError(f"{d.via_public_ip} is the public IP of {d.title}. From {s.title}, traffic "
                         "to it goes out to the internet (through an internet or NAT gateway) and "
                         "comes back in from a public address, which one check doesn't follow. "
                         f"Check {s.title} to internet and internet to {d.title}, or use "
                         f"{d.title}'s private address.")
    if not s.vpc and not d.vpc:
        raise ReachError("Neither side is in a VPC in this snapshot.")
    versions = {e.version for e in (s, d) if e.version}
    if len(versions) > 1:
        raise ReachError("One side is IPv4 and the other IPv6. Pick two of the same kind.")
    version = versions.pop() if versions else 4
    if proto == "icmp" and version == 6:
        proto = "icmpv6"
    elif proto == "icmpv6" and version == 4:
        proto = "icmp"
    return _Walk(snap, s, d, proto, port if proto in ("tcp", "udp") else None, version).run()


# =================================================================== text

def result_text(result, colorize=None, width=100) -> str:
    """The result as readable text, for the terminal and the page's details panel.
    colorize(text, word) can color it, where word is a status or a verdict. A hop blocked
    for only part of the range shows "partly" where the status goes."""
    paint = colorize or (lambda text, word: text)
    head = {"reachable": "Reachable", "blocked": "Partly blocked" if result.partial else "Blocked",
            "unknown": "Unknown"}[result.verdict]
    lines = []
    for label, ep in (("From", result.source), ("To", result.destination)):
        lines.append(f"{label:<5} {ep.label}")
    lines.append(f"{'Over':<5} {result.traffic}")
    lines.append("")
    wrap = textwrap.TextWrapper(width=width, subsequent_indent=" " * (len(head) + 2),
                                break_long_words=False, break_on_hyphens=False)
    lines += wrap.wrap(paint(head, result.verdict) + "  " + result.summary)
    for leg, heading in (("there", "On the way there"), ("back", "Replies")):
        items = [h for h in result.hops if h.leg == leg]
        if not items:
            continue
        lines += ["", heading]
        for h in items:
            word = "partly" if h.partial and h.status == "blocked" else h.status
            lines.append(f"  {paint(f'{word:<9}', h.status)} {h.title}")
            body = textwrap.TextWrapper(width=width, initial_indent=" " * 12,
                                        subsequent_indent=" " * 12, break_long_words=False,
                                        break_on_hyphens=False)
            lines += body.wrap(h.reason)
            if h.fix:
                lines += body.wrap("To allow it: " + h.fix)
    if result.notes:
        lines += ["", "Notes"]
        note = textwrap.TextWrapper(width=width, initial_indent="  - ", subsequent_indent="    ",
                                    break_long_words=False, break_on_hyphens=False)
        for n in result.notes:
            lines += note.wrap(n)
    return "\n".join(lines)
