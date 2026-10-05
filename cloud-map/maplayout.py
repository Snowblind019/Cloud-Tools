"""Cloud Map's layout. Turns a snapshot into positioned boxes and edges.

Two steps. build_view() picks what a map type shows, applies the filters, collapses
long lists into "+N more" boxes, and works out titles, captions, tooltips and data
attributes. layout() then sizes and places everything: nesting, rows of equal width,
AZs as columns with subnets lined up across them, gateways on VPC borders, outside
principals above what they connect to, and edges that run straight when they can.

Nothing here knows about colors or draw.io. mapdrawio.py turns a Layout into a .drawio
file, and the viewer page will draw the same Layout, so both match.

Everything is snapped to a 10 px grid and sorted, so the same snapshot always gives the
same layout.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field

from . import mapmodel as mm
from .mapthemes import CAPTION_SIZE, CARD_TITLE_SIZE, CONTAINER_TITLE_SIZE, category_of

GRID = 10
PAD = 20
GAP = 20
CARD_W = 260
HEADER_CAPTION_W = 230
CARD_MIN_H = 60
CHIP_W, CHIP_H = 180, 40
ICON = 32
CHIP_ICON = 24
CONTAINER_ICON = 24
MAX_ITEMS = 12
EXTERNAL_GAP = 60
MAX_LOG_EDGES = 8

MAP_TYPES = ("access", "network", "combined")
SHOW_CHOICES = ("routes", "sgs", "endpoints", "trust")
DEFAULT_SHOW = {"access": {"trust"}, "network": {"routes", "endpoints"},
                "combined": {"trust", "routes", "endpoints"}}

# Layers, bottom to top. A cell nested in a container belongs to the container's layer
# in draw.io, so anything on a detail layer is an edge or a free-floating shape.
LAYERS = (("base", "Base"), ("routes", "Routes"), ("sgs", "Security groups"),
          ("endpoints", "Endpoints"), ("trust", "Trust paths"), ("flags", "Flags"),
          ("legend", "Legend"))

ACCESS_KINDS = {"org", "ou", "account", "external", "identity-center", "permission-set",
                "role", "oidc-provider", "saml-provider", "trail", "bucket", "cost",
                "sso-roles", "user", "group", "github", "idp", "ext-account", "public"}
NETWORK_KINDS = {"account", "region", "vpc", "az", "subnet", "igw", "eigw", "nat", "tgw",
                 "tgw-attachment", "endpoint", "sg", "nacl", "instance", "lb", "rds", "vgw",
                 "cgw"}
CHIP_KINDS = ("igw", "eigw", "vgw", "tgw-attachment")
DETAIL_KINDS = {"endpoint": "endpoints", "sg": "sgs", "nacl": "sgs"}

EDGE_LAYER = {"trust": "trust", "break-glass": "trust", "oidc": "trust", "saml": "trust",
              "sso": "trust", "sso-assignment": "trust", "route": "routes",
              "sg-reference": "sgs", "log-delivery": "base", "peering": "base",
              "tgw-attachment": "base", "vpn": "base"}

# Legend text for each line style, in the order the legend lists them.
LEGEND_TEXT = (
    ("sso", "Access through IAM Identity Center"),
    ("saml", "Access through a SAML identity provider"),
    ("oidc", "GitHub and other OIDC access"),
    ("trust", "Role trust from another account"),
    ("break-glass", "Break-glass access from the management account"),
    ("log-delivery", "CloudTrail logs"),
    ("route", "Route, labeled with its destination"),
    ("peering", "VPC peering"),
    ("tgw-attachment", "Transit gateway attachment"),
    ("vpn", "Site-to-Site VPN"),
    ("sg-reference", "Security group allows traffic from another group"),
)

PLURAL = {"instance": "instances", "role": "roles", "bucket": "buckets",
          "permission-set": "permission sets", "sg": "security groups",
          "endpoint": "endpoints", "user": "users", "group": "groups", "rds": "databases",
          "lb": "load balancers", "nacl": "network ACLs", "nat": "NAT gateways",
          "ext-account": "outside accounts", "trail": "trails", "oidc-provider": "OIDC providers",
          "saml-provider": "SAML providers", "tgw": "transit gateways",
          "cgw": "customer gateways", "idp": "identity providers"}

# Order of cards inside a container. Lower comes first.
ORDER = {"identity-center": 0, "oidc-provider": 10, "saml-provider": 11, "role": 20,
         "sso-roles": 30, "trail": 40, "bucket": 50, "cost": 60,
         "lb": 0, "instance": 10, "rds": 20, "nat": 90,
         "tgw": 0, "cgw": 10, "igw": 0, "eigw": 1, "vgw": 2, "tgw-attachment": 3,
         "user": 0, "group": 1, "public": 5, "github": 6, "idp": 4, "ext-account": 7,
         "endpoint": 0, "sg": 0, "nacl": 10}


class LayoutError(ValueError):
    pass


@dataclass
class Options:
    map_type: str = "access"
    show: set = None
    accounts: list = field(default_factory=list)
    regions: list = field(default_factory=list)
    vpcs: list = field(default_factory=list)
    service_linked: bool = False
    default_vpcs: bool = False
    labels: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.map_type not in MAP_TYPES:
            raise LayoutError(f"Map type has to be one of {', '.join(MAP_TYPES)}.")
        if self.show is None:
            self.show = set(DEFAULT_SHOW[self.map_type])
        self.show = set(self.show)
        unknown = self.show - set(SHOW_CHOICES)
        if unknown:
            raise LayoutError(f"Unknown --show value: {', '.join(sorted(unknown))}. Use "
                              f"{', '.join(SHOW_CHOICES)} or all.")


# =================================================================== text sizing

_NARROW = set("iljtfI.,:;'!|`()[]{} -")
_WIDE = set("mwMW@%")


def text_width(text, size, bold=False) -> float:
    """A generous estimate of how wide text renders in Helvetica, so wrapped lines fit."""
    w = 0.0
    for ch in str(text):
        if ch in _NARROW:
            w += 0.32
        elif ch in _WIDE:
            w += 0.88
        elif ch.isupper():
            w += 0.69
        elif ch.isdigit():
            w += 0.57
        else:
            w += 0.54
    return w * size * (1.07 if bold else 1.0)


def wrap(text, size, width, bold=False, max_lines=4) -> list:
    """Greedy word wrap. Long words like ARNs are broken by character."""
    text = " ".join(str(text or "").split())
    if not text:
        return []
    # No more than max_lines of the narrowest letters can show, and the rest is cut off
    # anyway, so very long names (from a hand-made snapshot) don't take ages to wrap.
    most = int((max_lines + 1) * (width / max(0.32 * size, 0.1) + 2))
    text = text[:max(most, 8)]
    lines, cur = [], ""
    for word in text.split(" "):
        trial = f"{cur} {word}" if cur else word
        if text_width(trial, size, bold) <= width:
            cur = trial
            continue
        if cur:
            lines.append(cur)
            cur = ""
        if text_width(word, size, bold) > width:
            # Break long names like bucket names and ARNs after - _ . / : first.
            pieces = re.findall(r"[^-_./:]+[-_./:]*|[-_./:]+", word)
            part = ""
            for piece in pieces:
                if text_width(part + piece, size, bold) <= width:
                    part += piece
                    continue
                if part:
                    lines.append(part)
                part = piece
                while text_width(part, size, bold) > width and len(part) > 1:
                    cut = len(part)
                    while cut > 1 and text_width(part[:cut], size, bold) > width:
                        cut -= 1
                    lines.append(part[:cut])
                    part = part[cut:]
            word = part
        cur = word
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and text_width(last + "…", size, bold) > width:
            last = last[:-1]
        lines[-1] = last.rstrip() + "…"
    return lines


def snap_up(v) -> int:
    return int(math.ceil(v / GRID) * GRID)


def snap_down(v) -> int:
    return int(math.floor(v / GRID) * GRID)


# =================================================================== the view

@dataclass
class VNode:
    id: str
    kind: str
    title: str
    caption: str
    parent: str
    category: str
    tooltip: list
    attrs: dict
    flags: list
    order: tuple
    props: dict = field(default_factory=dict)
    count: int = 0


@dataclass
class VEdge:
    id: str
    src: str
    dst: str
    kind: str
    layer: str
    label: str = ""
    tooltip: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    attrs: dict = field(default_factory=dict)


@dataclass
class View:
    nodes: dict
    edges: list
    map_type: str
    show: set
    notes: list
    source_lines: list


def _matches(node, wanted) -> bool:
    if not wanted:
        return True
    keys = {node.id.lower(), node.name.lower(), mm.title_of(node).lower()}
    return any(str(w).lower() in keys for w in wanted)


def _attr_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        if all(isinstance(v, (str, int, float)) for v in value):
            return ", ".join(str(v) for v in value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


RESERVED_ATTRS = {"id", "label", "tooltip", "placeholders", "link", "linkTarget", "tags"}


def _attrs(node) -> dict:
    """Data attributes for draw.io's Edit Data: everything the snapshot knows."""
    out = {"aws_id": node.id, "kind": node.kind, "name": node.name,
           "account": node.account, "region": node.region, "source": node.source,
           "awskit": "1"}
    cidr = node.props.get("cidr") or ", ".join(node.props.get("cidrs", []) or [])
    if cidr:
        out["cidr"] = cidr
    if node.flags:
        out["flags"] = "; ".join(f"{f['severity']}: {f['reason']}" for f in node.flags)
    for k in sorted(node.props):
        if k in ("cidr", "cidrs", "title"):
            continue
        key = k if k not in RESERVED_ATTRS and k not in out else f"prop_{k}"
        text = _attr_text(node.props[k])
        if text:
            out[key] = text
    if node.tags:
        out["tags"] = "; ".join(f"{k}={v}" for k, v in sorted(node.tags.items()))
    return {k: v for k, v in out.items() if v != ""}


TOOLTIP_PROPS = (("arn", "ARN"), ("cidr", "CIDR"), ("az", "Zone"), ("state", "State"),
                 ("type", "Type"), ("scheme", "Scheme"), ("engine", "Engine"),
                 ("private_ip", "Private IP"), ("public_ip", "Public IP"),
                 ("service", "Service"), ("route_table", "Route table"),
                 ("email", "Email"), ("path", "Path"), ("description", "Description"),
                 ("session_duration", "Session"), ("bucket", "Bucket"),
                 ("instance_profile", "Instance profile"), ("asn", "ASN"), ("ip", "IP"))


def _tooltip(snap, node) -> list:
    lines = [("", mm.NODE_KINDS.get(node.kind, node.kind))]
    if node.id != node.props.get("arn"):
        lines.append(("ID", node.id))
    if node.account and node.kind not in ("account",):
        lines.append(("Account", node.account))
    if node.region and node.kind not in ("region",):
        lines.append(("Region", node.region))
    for key, label in TOOLTIP_PROPS:
        v = node.props.get(key)
        if v not in (None, "", [], {}):
            lines.append((label, _attr_text(v)))
    p = node.props
    if node.kind == "role":
        if p.get("trusted_by"):
            lines.append(("Trusted by", ", ".join(p["trusted_by"])))
        if p.get("policies"):
            lines.append(("Policies", ", ".join(str(x).rsplit("/", 1)[-1] for x in p["policies"])))
    if node.kind in ("org", "ou", "account") and p.get("scps"):
        org = mm.org_node(snap)
        summaries = org.props.get("scp_summaries", {}) if org is not None else {}
        for name in p["scps"]:
            lines.append(("SCP " + name, summaries.get(name, "attached")))
    if node.kind == "sg":
        for r in p.get("ingress", [])[:8]:
            src = ", ".join(r.get("cidrs", []) + r.get("groups", [])) or "nothing"
            lines.append(("In", f"{mm.port_text(r.get('protocol'), r.get('from'), r.get('to'))} from {src}"))
    if node.kind == "permission-set" and p.get("accounts"):
        lines.append(("Accounts", ", ".join(p["accounts"])))
    if node.kind == "cost" and p.get("budgets"):
        lines.append(("Budgets", ", ".join(p["budgets"])))
    if node.kind == "github" and p.get("scopes"):
        lines.append(("Allowed", "; ".join(p["scopes"])))
    for k, v in sorted(node.tags.items()):
        if k in ("Name",):
            continue
        lines.append((f"Tag {k}", str(v)))
    for f in node.flags:
        lines.append((f"Problem ({f['severity']})", f["reason"]))
    return lines


def _caption(node, labels) -> tuple:
    """(title, caption) with the labels file first, then a Description tag, then the
    automatic caption."""
    label = labels.get(node.id)
    title = mm.title_of(node)
    caption = node.tags.get("Description") or node.caption
    if isinstance(label, str):
        caption = label
    elif isinstance(label, dict):
        caption = label.get("caption", caption)
        title = label.get("title", title)
    return title, caption


def _role_order(node) -> int:
    p = node.props
    if p.get("break_glass"):
        return 80
    classes = set(p.get("trust_classes", []))
    if "oidc-github" in classes or "oidc" in classes:
        return 20
    if classes & {"outside", "public"}:
        return 21
    if "saml" in classes:
        return 22
    if "org" in classes:
        return 23
    return 25


def _order(node) -> tuple:
    p = node.props
    if node.kind == "role":
        first = _role_order(node)
    elif node.kind == "bucket":
        first = 50 if p.get("trails") else 51
    elif node.kind == "account":
        first = 0 if p.get("management") else (9 if p.get("stub") else 1)
    elif node.kind == "subnet":
        first = 0 if p.get("public") else 1
    elif node.kind == "ou":
        first = 5
    elif node.kind == "org":
        first = 0
    else:
        first = ORDER.get(node.kind, 50)
    return (first, mm.title_of(node).lower(), node.id)


def build_view(snap, opts: Options) -> View:
    mt = opts.map_type
    kinds = {"access": ACCESS_KINDS, "network": NETWORK_KINDS,
             "combined": ACCESS_KINDS | NETWORK_KINDS}[mt]
    notes = []
    keep = {}
    for node in snap.nodes.values():
        p = node.props
        if node.kind not in kinds:
            continue
        if node.kind == "org" and p.get("partial"):
            continue
        if p.get("collapsed") or p.get("hidden"):
            continue
        if p.get("service_linked") and not opts.service_linked:
            continue
        if node.kind in DETAIL_KINDS and DETAIL_KINDS[node.kind] not in opts.show:
            continue
        if node.kind == "nacl" and p.get("default"):
            continue
        keep[node.id] = node

    def parent_in_view(node):
        """The nearest ancestor that's in the view, skipping ones this map type leaves out."""
        cur = node
        seen = set()
        while cur.parent and cur.parent not in seen:
            seen.add(cur.parent)
            if cur.parent in keep:
                return cur.parent
            nxt = snap.get(cur.parent)
            if nxt is None:
                return ""
            cur = nxt
        return ""

    parents = {nid: parent_in_view(n) for nid, n in keep.items()}

    # ---- filters
    def under(nid, pred):
        cur = nid
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            if pred(cur):
                return True
            cur = parents.get(cur, "")
        return False

    if opts.accounts:
        wanted = {n.id for n in keep.values() if n.kind == "account" and _matches(n, opts.accounts)}
        if not wanted:
            raise LayoutError("None of the accounts in --accounts are in this snapshot.")
        drop = set()
        for nid, n in keep.items():
            if n.kind in ("org", "ou", "external") or n.parent == mm.EXTERNAL:
                continue
            if not under(nid, lambda x: x in wanted):
                drop.add(nid)
        for nid in drop:
            keep.pop(nid)
    if opts.regions:
        drop = {nid for nid, n in keep.items() if n.kind == "region" and not _matches(
            n, opts.regions) and n.region not in opts.regions}
        for nid in list(keep):
            if under(nid, lambda x: x in drop):
                keep.pop(nid, None)
    if opts.vpcs:
        wanted = {n.id for n in keep.values() if n.kind == "vpc" and _matches(n, opts.vpcs)}
        if not wanted:
            raise LayoutError("None of the VPCs in --vpcs are in this snapshot.")
        for nid, n in list(keep.items()):
            if n.kind == "vpc" and nid not in wanted:
                for other in list(keep):
                    if under(other, lambda x: x == nid):
                        keep.pop(other, None)
            elif n.kind in ("tgw", "cgw") or (n.kind in ("igw", "eigw", "vgw") and not n.props.get("vpc")):
                keep.pop(nid, None)

    # ---- empty default VPCs
    if not opts.default_vpcs:
        busy = {"instance", "nat", "lb", "rds", "endpoint", "tgw-attachment", "vgw"}
        peered = {e.src for e in snap.edges.values() if e.kind == "peering"} | \
                 {e.dst for e in snap.edges.values() if e.kind == "peering"}
        hidden = 0
        for vpc in [n for n in keep.values() if n.kind == "vpc" and n.props.get("default")]:
            inside = [x for x in snap.nodes.values() if x.kind in busy and
                      snap.vpc_of(x) == vpc.id]
            if inside or vpc.id in peered:
                continue
            hidden += 1
            for other in list(keep):
                if other == vpc.id or snap.vpc_of(snap.get(other)) == vpc.id:
                    keep.pop(other, None)
        if hidden:
            notes.append(f"Left out {mm.plural(hidden, 'empty default VPC')}. Export with "
                         "--default-vpcs to include them.")

    parents = {nid: parent_in_view(n) for nid, n in keep.items()}

    # ---- empty containers go, from the inside out
    changed = True
    while changed:
        changed = False
        has_child = set(parents.values())
        for nid, n in list(keep.items()):
            empty = nid not in has_child
            if not empty:
                continue
            if n.kind in ("region", "az", "external") or (
                    n.kind == "account" and mt == "network") or (
                    n.kind == "account" and n.props.get("stub") and mt != "access"):
                keep.pop(nid)
                parents.pop(nid, None)
                changed = True

    # ---- edges
    edges = []
    idc = [n for n in keep.values() if n.kind == "identity-center"]
    idc_id = idc[0].id if idc else ""
    bundle = {}
    for e in sorted(snap.edges.values(), key=lambda e: e.id):
        layer = EDGE_LAYER.get(e.kind, "base")
        if layer in ("trust", "routes", "sgs") and \
                {"trust": "trust", "routes": "routes", "sgs": "sgs"}[layer] not in opts.show:
            continue
        if e.src not in keep or e.dst not in keep:
            continue
        if e.kind == "sso-assignment" and idc_id:
            bundle.setdefault(e.dst, set()).update(filter(None, e.label.split(", ")))
            edges.append(VEdge(f"sso:{e.src}->{idc_id}", e.src, idc_id, "sso", "trust",
                               tooltip=[("", "Signs in through IAM Identity Center")],
                               flags=list(e.flags)))
            continue
        kind = "sso" if e.kind == "sso-assignment" else e.kind
        tip = [("", _edge_text(snap, e))]
        for k in ("principal", "route_table", "pcx", "vpn", "status"):
            if e.props.get(k):
                tip.append((k.replace("_", " ").capitalize(), str(e.props[k])))
        for scope in e.props.get("scopes", []):
            tip.append(("Allowed", scope))
        for f in e.flags:
            tip.append((f"Problem ({f['severity']})", f["reason"]))
        # Route destinations read well on the line. Ports between security groups don't
        # fit in the gap between cards, so they stay in the tooltip.
        label = e.label if kind in ("route", "sso") else ""
        if kind == "sg-reference" and e.label:
            tip.append(("Ports", e.label))
        edges.append(VEdge(e.id, e.src, e.dst, kind, layer, label, tip, list(e.flags),
                           {"awskit": "1", "kind": kind, "aws_src": e.src, "aws_dst": e.dst}))
    for account, sets in sorted(bundle.items()):
        names = ", ".join(sorted(sets))
        edges.append(VEdge(f"sso:{idc_id}->{account}", idc_id, account, "sso", "trust", "",
                           [("", "Identity Center access"), ("Permission sets", names)]))
    # Org trails: one line per member account gets busy, so past a few the caption says it.
    per_trail = {}
    for e in edges:
        if e.kind == "log-delivery" and keep.get(e.dst) is not None and keep[e.dst].kind == "trail":
            per_trail.setdefault(e.dst, []).append(e)
    for trail, lst in per_trail.items():
        if len(lst) > MAX_LOG_EDGES:
            ids = {e.id for e in lst}
            edges = [e for e in edges if e.id not in ids]
    # Same edge twice (after bundling) becomes one.
    seen = {}
    for e in edges:
        if e.id in seen:
            seen[e.id].flags += [f for f in e.flags if f not in seen[e.id].flags]
        else:
            seen[e.id] = e
    edges = [seen[k] for k in sorted(seen)]
    for e in edges:
        e.attrs.setdefault("awskit", "1")
        e.attrs.setdefault("kind", e.kind)
        if e.flags:
            e.attrs["flags"] = "; ".join(f"{f['severity']}: {f['reason']}" for f in e.flags)

    # ---- view nodes
    vnodes = {}
    for nid, n in keep.items():
        title, caption = _caption(n, opts.labels)
        vnodes[nid] = VNode(nid, n.kind, title, caption, parents.get(nid, ""),
                            category_of(n.kind, n.props), _tooltip(snap, n), _attrs(n),
                            list(n.flags), _order(n), dict(n.props))

    _collapse(vnodes, edges)
    lines = source_lines(snap)
    return View(vnodes, edges, mt, set(opts.show), notes, lines)


def _edge_text(snap, e) -> str:
    src, dst = snap.get(e.src), snap.get(e.dst)
    s = mm.title_of(src) if src is not None else e.src
    d = mm.title_of(dst) if dst is not None else e.dst
    text = {"trust": f"{d} trusts {s}", "break-glass": f"{s} can assume {d} (break-glass)",
            "oidc": f"{s} to {d} through OIDC", "saml": f"{s} to {d} through SAML",
            "log-delivery": f"CloudTrail logs from {s} to {d}",
            "route": f"{s} routes {e.label} to {d}", "peering": f"{s} peers with {d}",
            "tgw-attachment": f"{s} attaches to {d}", "vpn": f"VPN from {s} to {d}",
            "sg-reference": f"{d} allows {e.label} from {s}",
            "sso-assignment": f"{s} can reach {d}"}.get(e.kind, f"{s} to {d}")
    return text


def _collapse(vnodes, edges):
    """More than MAX_ITEMS cards of one kind in a container become MAX_ITEMS plus one
    '+N more' box that lists the rest in its tooltip."""
    groups = {}
    containers = {v.parent for v in vnodes.values()}
    for v in vnodes.values():
        if v.id in containers or v.kind in mm.CONTAINER_KINDS or v.kind in CHIP_KINDS:
            continue
        groups.setdefault((v.parent, v.kind), []).append(v)
    redirect = {}
    for (parent, kind), items in sorted(groups.items()):
        if len(items) <= MAX_ITEMS:
            continue
        items.sort(key=lambda v: v.order)
        extra = items[MAX_ITEMS:]
        mid = f"more:{parent}:{kind}"
        noun = PLURAL.get(kind, mm.NODE_KINDS.get(kind, kind).lower() + "s")
        flags = []
        bad = [v for v in extra if v.flags]
        if bad:
            sev = min((mm.worst(v.flags) for v in bad), key=lambda s: mm.SEV_RANK.get(s, 9))
            flags = [{"severity": sev,
                      "reason": f"{mm.plural(len(bad), 'of these has', 'of these have')} problems: "
                                + ", ".join(v.title for v in bad[:6])}]
        tooltip = [("", f"{len(extra)} more {noun}")] + [("", v.title) for v in extra]
        vnodes[mid] = VNode(mid, kind, f"+{len(extra)} more {noun}",
                            "Hover for the full list", parent, extra[0].category, tooltip,
                            {"awskit": "1", "kind": "more", "collapsed_kind": kind,
                             "items": ", ".join(v.attrs.get("aws_id", v.id) for v in extra)},
                            flags, (999, "", mid), {"more": True}, len(extra))
        for v in extra:
            redirect[v.id] = mid
            vnodes.pop(v.id)
    if redirect:
        for e in edges:
            e.src = redirect.get(e.src, e.src)
            e.dst = redirect.get(e.dst, e.dst)
        seen = {}
        for e in edges:
            key = (e.src, e.dst, e.kind)
            if key in seen:
                seen[key].flags += [f for f in e.flags if f not in seen[key].flags]
                e.kind = ""
            else:
                seen[key] = e
                e.id = mm.edge_id(e.kind, e.src, e.dst) if (e.src in redirect.values() or
                                                           e.dst in redirect.values()) else e.id
        edges[:] = [e for e in edges if e.kind]


def source_lines(snap) -> list:
    """The footnote: where this came from, when, what it covered, and anything skipped."""
    lines = []
    scope = snap.scope or {}
    if snap.source == "terraform":
        inputs = ", ".join(scope.get("inputs", [])) or "Terraform"
        kind = " and ".join(scope.get("kind", [])) or "state"
        lines.append(f"Source: Terraform {kind} ({inputs})")
        if snap.scanned_at:
            lines.append(f"Plan made {snap.scanned_at}")
    else:
        profiles = ", ".join(p or "default" for p in scope.get("profiles", [])) or "default"
        lines.append(f"Source: live scan of profile{'s' if len(scope.get('profiles', [])) > 1 else ''} {profiles}")
        if snap.scanned_at:
            lines.append(f"Scanned {snap.scanned_at}")
        if scope.get("regions"):
            regs = scope["regions"]
            lines.append("Regions: " + (", ".join(regs) if len(regs) <= 6 else
                                        f"{len(regs)} enabled regions"))
    return lines


# =================================================================== placed output

@dataclass
class Box:
    id: str
    kind: str
    role: str            # container, card, chip, detail, more
    layer: str
    parent: str          # cell parent: the containing box, or "" for top level and detail
    x: int               # relative to parent
    y: int
    w: int
    h: int
    ax: int = 0          # absolute
    ay: int = 0
    title_lines: list = field(default_factory=list)
    caption_lines: list = field(default_factory=list)
    text: tuple = (0, 0, 0)   # text left, top, width (relative)
    icon: tuple = None        # left, top, size (relative)
    category: str = ""
    tooltip: list = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    flags: list = field(default_factory=list)
    props: dict = field(default_factory=dict)
    hints: dict = field(default_factory=dict)


@dataclass
class Link:
    id: str
    src: str
    dst: str
    kind: str
    layer: str
    label: str = ""
    tooltip: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    exit: tuple = None
    entry: tuple = None
    points: list = field(default_factory=list)
    hints: dict = field(default_factory=dict)


@dataclass
class Text:
    id: str
    layer: str
    x: int
    y: int
    w: int
    h: int
    lines: list
    style: str = "footnote"   # footnote, strip, legend


@dataclass
class LegendEntry:
    id: str
    style: str
    label: str
    x: int
    y: int


@dataclass
class Layout:
    boxes: list
    links: list
    texts: list
    legend: list
    width: int
    height: int
    map_type: str
    layers: list
    extra: list = field(default_factory=list)    # cells drawn by hand, from layout memory
    meta: dict = field(default_factory=dict)     # how it was made, for the .drawio root

    def box(self, box_id):
        for b in self.boxes:
            if b.id == box_id:
                return b
        return None


# =================================================================== layout tree

class LBox:
    def __init__(self, v, role):
        self.v = v
        self.role = role
        self.bands = []
        self.chips = []
        self.parent = None
        self.w = self.h = 0
        self.x = self.y = 0
        self.header = 0
        self.title_lines = []
        self.caption_lines = []
        self.text = (0, 0, 0)
        self.icon = None
        self.fixed_h = None
        self.strip_titles = []

    @property
    def id(self):
        return self.v.id if self.v is not None else ""


class Band:
    def __init__(self, items, mode="row", cols=1, layer=None, title=""):
        self.items = items
        self.mode = mode
        self.cols = max(1, cols)
        self.layer = layer
        self.title = title
        self.w = self.h = 0
        self.item_w = 0
        self.row_h = []
        self.packed = False


GROUP_SHAPES = ("region", "vpc", "subnet")


def _measure_card(lb):
    v = lb.v
    text_x = 12 + ICON + 12
    text_w = CARD_W - text_x - 12
    lb.title_lines = wrap(v.title, CARD_TITLE_SIZE, text_w, bold=True, max_lines=2)
    lb.caption_lines = wrap(v.caption, CAPTION_SIZE, text_w, max_lines=3)
    text_h = 16 * len(lb.title_lines) + (2 + 14 * len(lb.caption_lines) if lb.caption_lines else 0)
    lb.w = CARD_W
    lb.h = max(CARD_MIN_H, snap_up(text_h + 24))
    lb.text = (text_x, 0, text_w)
    lb.icon = (12, 0, ICON)


def _measure_chip(lb):
    v = lb.v
    text_x = 8 + CHIP_ICON + 8
    text_w = CHIP_W - text_x - 8
    lb.title_lines = wrap(v.title, CAPTION_SIZE + 1, text_w, bold=True, max_lines=1)
    lb.caption_lines = []
    lb.w, lb.h = CHIP_W, CHIP_H
    lb.text = (text_x, 0, text_w)
    lb.icon = (8, (CHIP_H - CHIP_ICON) // 2, CHIP_ICON)


def _header(lb, width):
    v = lb.v
    if v.kind == "external":
        lb.title_lines, lb.caption_lines, lb.header = [], [], 0
        lb.text, lb.icon = (0, 0, 0), None
        return
    if v.kind in GROUP_SHAPES:
        text_x, icon = 34, None          # the AWS group shape draws its own corner icon
    elif v.kind == "az":
        text_x, icon = 12, None
    else:
        text_x, icon = 14 + CONTAINER_ICON + 10, (14, 14, CONTAINER_ICON)
    text_w = max(width - text_x - 14, 120)
    lb.title_lines = wrap(v.title, CONTAINER_TITLE_SIZE, text_w, bold=True, max_lines=2)
    # Short caption lines leave room for lines coming down into the container.
    lb.caption_lines = wrap(v.caption, CAPTION_SIZE, min(text_w, HEADER_CAPTION_W), max_lines=4)
    top = 6 if v.kind in GROUP_SHAPES else 12
    text_h = 18 * len(lb.title_lines) + (2 + 14 * len(lb.caption_lines) if lb.caption_lines else 0)
    lb.header = snap_up(top + text_h + 12)
    if v.kind == "vpc" and lb.chips:
        lb.header = max(lb.header, 60)
    lb.text = (text_x, top, text_w)
    lb.icon = icon


def _band_size(band):
    items = band.items
    if not items:
        band.w = band.h = 0
        return
    title_h = 30 if band.title else 0
    if band.mode == "col":
        band.item_w = max(i.w for i in items)
        band.w = band.item_w
        band.h = sum(i.h for i in items) + GAP * (len(items) - 1) + title_h
        return
    cols = min(band.cols, len(items))
    band.item_w = max(i.w for i in items)
    rows = [items[k:k + cols] for k in range(0, len(items), cols)]
    band.row_h = [max(i.h for i in row) for row in rows]
    widths = [i.w for i in items]
    # Containers in a row share one width, like D1, unless one is far bigger than the
    # others. Then each keeps its own size instead of leaving a big empty box.
    band.packed = (band.mode == "row" and any(i.role == "container" for i in items) and
                   min(widths) > 0 and max(widths) / min(widths) > 1.6)
    if band.packed:
        band.w = max(sum(i.w for i in row) + GAP * (len(row) - 1) for row in rows)
    else:
        band.w = cols * band.item_w + (cols - 1) * GAP
    band.h = sum(band.row_h) + GAP * (len(rows) - 1) + title_h


def measure(lb):
    if lb.role == "card":
        _measure_card(lb)
        return
    if lb.role == "chip":
        _measure_chip(lb)
        return
    if lb.role == "spacer":
        lb.w, lb.h = 0, lb.fixed_h or 0
        return
    for band in lb.bands:
        for item in band.items:
            measure(item)
    for chip in lb.chips:
        measure(chip)
    if lb.v is not None and lb.v.kind == "vpc":
        _align_az_tiers(lb)
    for band in lb.bands:
        _band_size(band)
    pad = 0 if lb.role == "root" or (lb.v is not None and lb.v.kind == "external") else PAD
    bands = [b for b in lb.bands if b.items]
    inner_w = max([b.w for b in bands] or [0])
    chips_w = len(lb.chips) * (CHIP_W + GAP)
    if lb.role == "root":
        lb.header = 0
    else:
        title_w = text_width(lb.v.title, CONTAINER_TITLE_SIZE, True) + 60
        natural = max(inner_w + 2 * pad, 240, snap_up(title_w + chips_w + (40 if chips_w else 0)))
        _header(lb, natural)
    inner_h = sum(b.h for b in bands) + GAP * max(0, len(bands) - 1)
    min_w = 0 if lb.role == "root" else 240
    title_need = 0
    if lb.role != "root":
        title_need = snap_up(text_width(lb.v.title, CONTAINER_TITLE_SIZE, True) + lb.text[0] + 30)
    lb.w = snap_up(max(inner_w + 2 * pad, min_w, title_need + (chips_w + 20 if chips_w else 0)))
    lb.h = snap_up(lb.header + inner_h + (pad if bands else (0 if lb.role == "root" else 10)))


def _align_az_tiers(vpc):
    """Subnets line up across AZ columns: public rows on top, private below, and each row
    as tall as its tallest subnet."""
    az_band = next((b for b in vpc.bands if b.mode == "azs"), None)
    if az_band is None:
        return
    pub, priv = [], []
    for az in az_band.items:
        subs = [i for i in az.bands[0].items if i.role != "spacer"] if az.bands else []
        pub.append([s for s in subs if s.v.props.get("public")])
        priv.append([s for s in subs if not s.v.props.get("public")])
    tiers = []
    for group in (pub, priv):
        depth = max([len(g) for g in group] or [0])
        for i in range(depth):
            tiers.append([g[i] if i < len(g) else None for g in group])
    heights = [max([s.h for s in tier if s is not None] or [0]) for tier in tiers]
    for col, az in enumerate(az_band.items):
        slots = []
        for tier, h in zip(tiers, heights):
            s = tier[col]
            if s is None:
                sp = LBox(None, "spacer")
                sp.fixed_h = h
                sp.w, sp.h = 0, h
                slots.append(sp)
            else:
                s.fixed_h = h
                s.h = h
                slots.append(s)
        az.bands = [Band(slots, "col")]
        _band_size(az.bands[0])
        title_w = text_width(az.v.title, CONTAINER_TITLE_SIZE, True) + 40
        _header(az, max(az.bands[0].w + 2 * PAD, title_w))
        az.w = snap_up(max(az.bands[0].w + 2 * PAD, 240))
        az.h = snap_up(az.header + az.bands[0].h + PAD)
    az_band.mode = "row"
    az_band.cols = len(az_band.items)


def arrange(lb, w, h):
    lb.w, lb.h = w, max(h, lb.h)
    if lb.role in ("card", "chip", "spacer"):
        if lb.icon is not None:
            ix, _, size = lb.icon
            lb.icon = (ix, (lb.h - size) // 2, size)
        if lb.role == "card":
            text_h = 16 * len(lb.title_lines) + (2 + 14 * len(lb.caption_lines) if lb.caption_lines else 0)
            lb.text = (lb.text[0], max(4, int((lb.h - text_h) / 2) - 1), lb.text[2])
        elif lb.role == "chip":
            lb.text = (lb.text[0], max(2, (lb.h - 16) // 2), lb.text[2])
        return
    pad = 0 if lb.role == "root" or (lb.v is not None and lb.v.kind == "external") else PAD
    inner_w = lb.w - 2 * pad
    y = lb.header
    lb.strip_titles = []
    for band in lb.bands:
        if not band.items:
            continue
        if band.title:
            lb.strip_titles.append((band.layer, band.title, pad, y, inner_w))
            y += 30
        if band.mode == "col":
            for item in band.items:
                ih = item.fixed_h if item.fixed_h is not None else item.h
                arrange(item, inner_w if item.role != "card" or True else item.w, ih)
                item.x, item.y = pad, y
                y += item.h + GAP
            y -= GAP
        else:
            cols = min(band.cols, len(band.items))
            if all(i.role in ("card", "chip") for i in band.items) and band.cols > 1:
                # A lone card in a three-wide row keeps its own width instead of
                # stretching across the whole container.
                per = snap_down((inner_w - (band.cols - 1) * GAP) / band.cols)
                item_w = max(band.item_w, per)
            else:
                item_w = max(band.item_w, snap_down((inner_w - (cols - 1) * GAP) / cols))
            if band.layer is not None or band.mode == "fixed":
                item_w = band.item_w
            rows = [band.items[k:k + cols] for k in range(0, len(band.items), cols)]
            for r, row in enumerate(rows):
                row_h = band.row_h[r] if r < len(band.row_h) else max(i.h for i in row)
                x = pad
                for c, item in enumerate(row):
                    if band.packed:
                        arrange(item, item.w, item.h)
                        item.x = x
                        x += item.w + GAP
                    else:
                        arrange(item, item_w, row_h)
                        item.x = pad + c * (item_w + GAP)
                    item.y = y
                y += row_h + GAP
            y -= GAP
        y += GAP
    for i, chip in enumerate(lb.chips):
        arrange(chip, CHIP_W, CHIP_H)
        chip.x = lb.w - PAD - (i + 1) * CHIP_W - i * GAP
        chip.y = -CHIP_H // 2


# =================================================================== building the tree

def _tree(view):
    children = {}
    for v in view.nodes.values():
        children.setdefault(v.parent, []).append(v)
    for lst in children.values():
        lst.sort(key=lambda v: v.order)
    containers = {v.id for v in view.nodes.values()
                  if v.kind in mm.CONTAINER_KINDS or v.id in children}

    def make(v):
        if v.id not in containers:
            return LBox(v, "card")
        lb = LBox(v, "container")
        kids = children.get(v.id, [])
        if v.kind == "org":
            lb.bands = [Band([make(k) for k in kids], "row", 4)]
        elif v.kind == "ou":
            lb.bands = [Band([make(k) for k in kids], "row", 3)]
        elif v.kind == "external":
            lb.bands = [Band([make(k) for k in kids], "fixed", max(1, len(kids)))]
        elif v.kind == "account":
            idc = [make(k) for k in kids if k.kind == "identity-center"]
            regions = [make(k) for k in kids if k.kind == "region"]
            cards = [make(k) for k in kids if k.kind not in ("identity-center", "region")]
            n = len(cards)
            cols = 1 if n <= 6 else (2 if n <= 14 else 3)
            lb.bands = [Band(idc, "col"), Band(cards, "row", cols), Band(regions, "col")]
        elif v.kind == "identity-center":
            n = len(kids)
            lb.bands = [Band([make(k) for k in kids], "row", 1 if n <= 4 else 2)]
        elif v.kind == "region":
            top = [make(k) for k in kids if k.kind != "vpc"]
            vpcs = [make(k) for k in kids if k.kind == "vpc"]
            lb.bands = [Band(top, "row", 4), Band(vpcs, "row", 2)]
        elif v.kind == "vpc":
            chips = [LBox(k, "chip") for k in kids if k.kind in CHIP_KINDS]
            lbs = [make(k) for k in kids if k.kind == "lb"]
            azs = [make(k) for k in kids if k.kind == "az"]
            loose = [make(k) for k in kids if k.kind not in CHIP_KINDS and k.kind not in
                     ("lb", "az", "endpoint", "sg", "nacl")]
            eps = [LBox(k, "card") for k in kids if k.kind == "endpoint"]
            sgs = [LBox(k, "card") for k in kids if k.kind in ("sg", "nacl")]
            lb.chips = chips
            lb.bands = [Band(lbs + loose, "row", 3), Band(azs, "azs", max(1, len(azs))),
                        Band(eps, "row", 3, layer="endpoints", title="VPC endpoints"),
                        Band(sgs, "row", 3, layer="sgs", title="Security groups and network ACLs")]
        elif v.kind == "az":
            lb.bands = [Band([make(k) for k in kids], "col")]
        elif v.kind == "subnet":
            n = len(kids)
            lb.bands = [Band([make(k) for k in kids], "row", 1 if n <= 3 else 2)]
        else:
            lb.bands = [Band([make(k) for k in kids], "row", 2)]
        for band in lb.bands:
            for item in band.items:
                item.parent = lb
        for chip in lb.chips:
            chip.parent = lb
        return lb

    roots = children.get("", [])
    external = [make(v) for v in roots if v.kind == "external"]
    main = [make(v) for v in roots if v.kind != "external"]
    for lb in main:
        if lb.role == "card":     # a loose card at the top level gets no container
            pass
    return external[0] if external else None, main


# =================================================================== routing

class Rect:
    __slots__ = ("x", "y", "w", "h", "id")

    def __init__(self, x, y, w, h, rid=""):
        self.x, self.y, self.w, self.h, self.id = x, y, w, h, rid

    @property
    def r(self):
        return self.x + self.w

    @property
    def b(self):
        return self.y + self.h

    @property
    def cx(self):
        return self.x + self.w / 2

    @property
    def cy(self):
        return self.y + self.h / 2

    def contains(self, o):
        return self.x <= o.x and self.y <= o.y and self.r >= o.r and self.b >= o.b


def _hits(seg, rect, margin=3):
    (x1, y1), (x2, y2) = seg
    lo_x, hi_x = min(x1, x2), max(x1, x2)
    lo_y, hi_y = min(y1, y2), max(y1, y2)
    return not (hi_x <= rect.x - margin or lo_x >= rect.r + margin or
                hi_y <= rect.y - margin or lo_y >= rect.b + margin)


def _clear(path, obstacles):
    for a, b in zip(path, path[1:]):
        for o in obstacles:
            if _hits((a, b), o):
                return False
    return True


def _steps(lo, hi, prefer, limit=60):
    """Grid positions between lo and hi (keeping 10 px from the ends), nearest to prefer
    first."""
    lo, hi = snap_up(lo + 10), snap_down(hi - 10)
    if lo > hi:
        return []
    cands = list(range(lo, hi + 1, GRID))
    cands.sort(key=lambda c: (abs(c - prefer), c))
    return cands[:limit]


def _rel(rect, x, y):
    return (round((x - rect.x) / rect.w, 4) if rect.w else 0.5,
            round((y - rect.y) / rect.h, 4) if rect.h else 0.5)


def route(s, t, obstacles, prefer="v", s_container=False, t_container=False):
    """Exit point, entry point (both relative to their box) and bend points for an
    orthogonal edge from s to t. Straight when nothing's in the way, then a Z, then a
    bracket around the side. None means leave it to draw.io."""
    if s.contains(t) or t.contains(s):
        return None

    def vertical_straight():
        ox0, ox1 = max(s.x, t.x), min(s.r, t.r)
        if ox1 - ox0 < 20:
            return None
        down = t.y >= s.b
        if not down and s.y < t.b:
            return None
        prefer_x = (ox0 + ox1) / 2
        for x in _steps(ox0, ox1, prefer_x):
            ys, yt = (s.b, t.y) if down else (s.y, t.b)
            if _clear([(x, ys), (x, yt)], obstacles):
                return (_rel(s, x, ys), _rel(t, x, yt), [])
        return None

    def horizontal_straight():
        oy0, oy1 = max(s.y, t.y), min(s.b, t.b)
        if oy1 - oy0 < 20:
            return None
        right = t.x >= s.r
        if not right and s.x < t.r:
            return None
        if t_container:
            prefer_y = min(max(t.y + 30, oy0 + 10), oy1 - 10)
        elif s_container:
            prefer_y = t.cy
        else:
            prefer_y = (oy0 + oy1) / 2
        for y in _steps(oy0, oy1, prefer_y):
            xs, xt = (s.r, t.x) if right else (s.x, t.r)
            if _clear([(xs, y), (xt, y)], obstacles):
                return (_rel(s, xs, y), _rel(t, xt, y), [])
        return None

    def vertical_z():
        if t.y >= s.b:
            down = True
        elif t.b <= s.y:
            down = False
        else:
            return None
        ys, yt = (s.b, t.y) if down else (s.y, t.b)
        mids = [yt - 10, ys + 10, snap_up((ys + yt) / 2)] if down else [yt + 10, ys - 10,
                                                                        snap_up((ys + yt) / 2)]
        for xm in mids:
            for x1 in _steps(s.x, s.r, t.cx if t.cx < s.r and t.cx > s.x else s.cx, 12):
                for x2 in _steps(t.x, t.r, t.cx, 12):
                    path = [(x1, ys), (x1, xm), (x2, xm), (x2, yt)]
                    if _clear(path, obstacles):
                        return (_rel(s, x1, ys), _rel(t, x2, yt), [(x1, xm), (x2, xm)])
        return None

    def horizontal_z():
        if t.x >= s.r:
            right = True
        elif t.r <= s.x:
            right = False
        else:
            return None
        xs, xt = (s.r, t.x) if right else (s.x, t.r)
        mids = [xs + 10, xt - 10, snap_up((xs + xt) / 2)] if right else [xs - 10, xt + 10,
                                                                         snap_up((xs + xt) / 2)]
        for xm in mids:
            for y1 in _steps(s.y, s.b, s.cy, 12):
                for y2 in _steps(t.y, t.b, t.cy if not t_container else t.y + 30, 12):
                    path = [(xs, y1), (xm, y1), (xm, y2), (xt, y2)]
                    if _clear(path, obstacles):
                        return (_rel(s, xs, y1), _rel(t, xt, y2), [(xm, y1), (xm, y2)])
        return None

    def bracket(side):
        if side == "right":
            xm = max(s.r, t.r) + 10
            xs, xt = s.r, t.r
        else:
            xm = min(s.x, t.x) - 10
            xs, xt = s.x, t.x
        path = [(xs, s.cy), (xm, s.cy), (xm, t.cy), (xt, t.cy)]
        if _clear(path, obstacles):
            return (_rel(s, xs, s.cy), _rel(t, xt, t.cy), [(xm, s.cy), (xm, t.cy)])
        return None

    order = ([vertical_straight, horizontal_straight, vertical_z, horizontal_z]
             if prefer == "v" else
             [horizontal_straight, vertical_straight, horizontal_z, vertical_z])
    order += [lambda: bracket("right"), lambda: bracket("left")]
    for fn in order:
        got = fn()
        if got:
            return got
    return None


PREFER_VERTICAL = {"route", "tgw-attachment"}


def _route_links(layout_boxes, view, links):
    by_id = {b.id: b for b in layout_boxes}
    rects = {b.id: Rect(b.ax, b.ay, b.w, b.h, b.id) for b in layout_boxes}
    leaf = [b for b in layout_boxes if b.role in ("card", "chip", "detail", "more")]
    headers = []
    for b in layout_boxes:
        if b.role == "container" and b.title_lines:
            tw = max(text_width(t, CONTAINER_TITLE_SIZE, True) for t in b.title_lines)
            if b.caption_lines:
                tw = max(tw, max(text_width(c, CAPTION_SIZE) for c in b.caption_lines))
            headers.append((b, Rect(b.ax + b.text[0] - 4, b.ay + b.text[1],
                                    min(tw + 8, b.w - b.text[0]), b.text[1] +
                                    18 * len(b.title_lines) + 14 * len(b.caption_lines))))

    def family(box_id):
        out = {box_id}
        cur = by_id.get(box_id)
        while cur is not None and cur.parent:
            out.add(cur.parent)
            cur = by_id.get(cur.parent)
        return out

    for link in links:
        s, t = rects.get(link.src), rects.get(link.dst)
        if s is None or t is None:
            continue
        skip = family(link.src) | family(link.dst)
        obstacles = [rects[b.id] for b in leaf if b.id not in skip]
        # Container titles block lines even when the line is going into that container.
        obstacles += [r for b, r in headers if b.id not in (link.src, link.dst)]
        external = by_id[link.src].parent == mm.EXTERNAL or by_id[link.dst].parent == mm.EXTERNAL
        prefer = "v" if (link.kind in PREFER_VERTICAL or external) else "h"
        got = route(s, t, obstacles, prefer, by_id[link.src].role == "container",
                    by_id[link.dst].role == "container")
        if got:
            link.exit, link.entry, pts = got
            link.points = [(int(x), int(y)) for x, y in pts]


# =================================================================== layout

def layout(view: View) -> Layout:
    external, roots = _tree(view)
    root = LBox(None, "root")
    cols = 2 if view.map_type == "network" else 4
    root.bands = [Band(roots, "row", cols)]
    measure(root)
    arrange(root, root.w, root.h)

    ext_h = 0
    if external is not None:
        measure(external)
        ext_h = external.h
    top = ext_h + EXTERNAL_GAP if external is not None and ext_h else 0
    boxes = []

    def emit(lb, parent_id, ox, oy, abs_parent):
        """ox, oy: absolute position of the parent's origin."""
        if lb.role == "spacer":
            return
        v = lb.v
        ax, ay = ox + lb.x, oy + lb.y
        detail_layer = None
        if lb.parent is not None:
            for band in lb.parent.bands:
                if lb in band.items and band.layer:
                    detail_layer = band.layer
        role = lb.role
        if detail_layer:
            role = "detail"
        elif v is not None and v.props.get("more"):
            role = "more"
        layer = detail_layer or "base"
        parent_cell = "" if (detail_layer or parent_id is None) else parent_id
        rel_x, rel_y = (ax, ay) if not parent_cell else (lb.x, lb.y)
        if v is not None:
            box = Box(v.id, v.kind, role, layer, parent_cell, rel_x, rel_y, lb.w, lb.h, ax, ay,
                      list(lb.title_lines), list(lb.caption_lines), lb.text, lb.icon,
                      v.category, v.tooltip, v.attrs, v.flags, v.props)
            if v.kind == "subnet":
                box.hints["public"] = bool(v.props.get("public"))
            if detail_layer and lb.parent is not None and lb.parent.v is not None:
                # Detail cards float on their own layer, but they belong to their VPC.
                box.hints["container"] = lb.parent.v.id
            boxes.append(box)
            for layer_name, title, sx, sy, sw in lb.strip_titles:
                texts.append(Text(f"strip:{v.id}:{layer_name}", layer_name, ax + sx, ay + sy,
                                  sw, 24, [title], "strip"))
        for band in lb.bands:
            for item in band.items:
                emit(item, v.id if v is not None else None, ax, ay, abs_parent)
        for chip in lb.chips:
            emit(chip, v.id, ax, ay, abs_parent)

    texts = []
    emit(root, None, 0, top, None)
    content_w = root.w
    if external is not None:
        _place_external(external, boxes, view, content_w)
        emit(external, None, 0, 0, None)
        content_w = max(content_w, external.w)

    links = [Link(e.id, e.src, e.dst, e.kind, e.layer, e.label, e.tooltip, e.flags, e.attrs)
             for e in view.edges]
    ids = {b.id for b in boxes}
    links = [lk for lk in links if lk.src in ids and lk.dst in ids]
    _route_links(boxes, view, links)

    bottom = max([b.ay + b.h for b in boxes] or [0])
    right = max([b.ax + b.w for b in boxes] + [content_w])
    legend, y = _legend(links, boxes, bottom + 40)
    lines = list(view.source_lines)
    lines += view.notes
    lines += [w for w in view_warnings(view)]
    if len(lines) > 12:
        extra = len(lines) - 11
        lines = lines[:11] + [f"and {extra} more notes, listed in the snapshot's warnings"]
    foot_h = 16 * len(lines) + 8
    texts.append(Text("footnote", "legend", 0, y, max(right, 600), foot_h, lines, "footnote"))
    height = y + foot_h
    # Only layers with something on them, so a network map has no empty Trust paths.
    used = {b.layer for b in boxes} | {lk.layer for lk in links} | {t.layer for t in texts}
    flagged = any(b.flags for b in boxes) or any(lk.flags for lk in links)
    layers = [name for name, _ in LAYERS
              if name in ("base", "legend") or (name == "flags" and flagged) or
              (name not in ("base", "legend", "flags") and name in used)]
    return Layout(boxes, links, texts, legend, snap_up(max(right, 600)), snap_up(height),
                  view.map_type, layers)


def view_warnings(view):
    return getattr(view, "warnings", [])


def _place_external(external, boxes, view, content_w):
    """Each outside principal sits above the thing it connects to, like You above IAM
    Identity Center and GitHub above the OIDC provider in D1."""
    by_id = {b.id: b for b in boxes}
    items = external.bands[0].items if external.bands else []
    targets = {}
    for e in view.edges:
        for a, b in ((e.src, e.dst), (e.dst, e.src)):
            if a in [i.id for i in items] and b in by_id:
                targets.setdefault(a, []).append(by_id[b])
    desired = []
    for item in items:
        tb = targets.get(item.id, [])
        cx = (sum(b.ax + b.w / 2 for b in tb) / len(tb)) if tb else 0
        desired.append((cx, item.v.order, item))
    desired.sort(key=lambda d: (d[0], d[1]))
    x = 0
    for cx, _, item in desired:
        arrange(item, item.w, item.h)
        want = snap_down(cx - item.w / 2) if cx else x
        item.x = max(want, x)
        item.y = 0
        x = item.x + item.w + GAP
    external.x = external.y = 0
    external.w = max(content_w, x - GAP if items else 0)
    external.h = max([i.h for i in items] or [0])
    external.header = 0


def _legend(links, boxes, y):
    used = []
    styles = {lk.kind for lk in links}
    for key, text in LEGEND_TEXT:
        if key in styles:
            used.append((key, text))
    if any(b.flags for b in boxes) or any(lk.flags for lk in links):
        used.append(("flag", "Security problem, hover the red badge for why"))
    entries = []
    col_w = 380
    for i, (key, text) in enumerate(used):
        col, row = i % 2, i // 2
        entries.append(LegendEntry(f"legend:{key}", key, text, col * col_w, y + row * 30))
    rows = (len(used) + 1) // 2
    return entries, y + rows * 30 + (20 if used else 0)


# Data attributes left out of a redacted export: policy documents carry condition values
# (an sts:ExternalId, for one) that PII Redact has no rule for.
REDACTED_DROP = {"trust_policy", "prop_trust_policy"}


def _source_without_names(line: str) -> str:
    """The footnote's source line without profile or file names."""
    if line.startswith("Source: live scan"):
        return "Source: live scan"
    if line.startswith("Source: Terraform"):
        return re.sub(r"\s*\(.*\)\s*$", "", line)
    return line


def redact_view(view: View, text_fn, id_fn, hide=()) -> View:
    """Run every title, caption, tooltip, label and data attribute through text_fn, and
    swap every ID for id_fn(ID). Done before layout, so boxes are sized for the redacted
    text. hide: profile and file names to take out of the footnote, notes and warnings."""
    def t(x):
        if x is None or x == "":
            return x
        return text_fn(str(x))

    def keyed(key, value):
        """Redact "key: "value"" so PII Redact's setting-name rules (bucket, account,
        email, owner and so on) apply to the whole value, then take the key back off."""
        if value is None or value == "":
            return value
        value = str(value)
        if not key:
            return t(value)
        if key == "tags":            # "k=v; k2=v2": each tag on its own, by its own key
            pairs = [part.partition("=") for part in value.split("; ")]
            return "; ".join(f"{t(k)}={keyed(k, v)}" if eq else t(k) for k, eq, v in pairs)
        prefix = f'{key}: "'
        out = text_fn(prefix + value.replace("\\", "\\\\").replace('"', '\\"') + '"')
        if out.startswith(prefix) and out.endswith('"'):
            return out[len(prefix):-1].replace('\\"', '"').replace("\\\\", "\\")
        return t(value) if out == t(f"{key}: {value}") else "[Redacted]"

    def attrs(items):
        return {k: (keyed(k, val) if k not in ("awskit", "kind") else val)
                for k, val in items if k not in REDACTED_DROP}

    names = sorted({str(h) for h in hide if h}, key=len, reverse=True)

    def scrub(line):
        line = _source_without_names(str(line))
        for name in names:
            line = re.sub(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", "[redacted]", line)
        return t(line)

    def tip(lines):
        return [(t(label) if label else label, keyed(label, value)) for label, value in lines]

    def flags(fl):
        return [{"severity": f["severity"], "reason": t(f["reason"])} for f in fl]

    nodes = {}
    for v in view.nodes.values():
        new = VNode(id_fn(v.id), v.kind, t(v.title), t(v.caption),
                    id_fn(v.parent) if v.parent else "", v.category, tip(v.tooltip),
                    attrs(v.attrs.items()), flags(v.flags), v.order, v.props, v.count)
        nodes[new.id] = new
    edges = [VEdge(id_fn(e.id), id_fn(e.src), id_fn(e.dst), e.kind, e.layer, t(e.label),
                   tip(e.tooltip), flags(e.flags), attrs(e.attrs.items()))
             for e in view.edges]
    out = View(nodes, edges, view.map_type, set(view.show), [scrub(n) for n in view.notes],
               [scrub(n) for n in view.source_lines])
    out.warnings = [scrub(w) for w in getattr(view, "warnings", [])]
    return out


def make(snap, opts: Options) -> Layout:
    view = build_view(snap, opts)
    view.warnings = list(snap.warnings)
    return layout(view)
