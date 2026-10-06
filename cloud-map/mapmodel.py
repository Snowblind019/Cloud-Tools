"""Cloud Map's model: one set of nodes and edges that every map is drawn from.

Both inputs build into this. mapscan.py reads a live AWS environment and maptf.py reads
Terraform, and both hand their raw facts to the add_* helpers here. finish() then works
out everything that depends on more than one resource: which accounts are inside the
org, who each role trusts, which subnets are public, route edges, security flags and
captions. Doing that in one place means a role trusted by GitHub gets the same caption
and the same flags whichever way it was read.

The model saves as JSON (a snapshot, <name>.cloudmap.json), so one scan can be exported
many ways without scanning again. Everything is sorted when it's written, so the same
input always gives a byte-identical file.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import iampolicy
from .common import SEVERITY_ORDER, open_port_risk

FORMAT_NAME = "awskit-cloudmap"
FORMAT_VERSION = 1
SUFFIX = ".cloudmap.json"

EXTERNAL = "external"
UNKNOWN_ACCOUNT = "unknown-account"
UNKNOWN_REGION = "unknown-region"

CONTAINER_KINDS = ("org", "ou", "account", "region", "vpc", "az", "subnet", "external",
                   "identity-center")

# Every node kind, with the name used when a node has no name of its own.
NODE_KINDS = {
    "org": "Organization", "ou": "Organizational unit", "account": "Account",
    "region": "Region", "vpc": "VPC", "az": "Availability Zone", "subnet": "Subnet",
    "external": "Outside the organization", "identity-center": "IAM Identity Center",
    "permission-set": "Permission set", "role": "IAM role", "oidc-provider": "OIDC provider",
    "saml-provider": "SAML provider", "trail": "CloudTrail trail", "bucket": "S3 bucket",
    "cost": "Cost guardrails", "sso-roles": "Identity Center roles",
    "user": "Identity Center user", "group": "Identity Center group",
    "github": "GitHub Actions", "idp": "Identity provider",
    "ext-account": "Outside AWS account", "public": "Anyone",
    "igw": "Internet gateway", "eigw": "Egress-only internet gateway", "nat": "NAT gateway",
    "route-table": "Route table", "tgw": "Transit gateway",
    "tgw-attachment": "Transit gateway attachment", "endpoint": "VPC endpoint",
    "sg": "Security group", "nacl": "Network ACL", "instance": "EC2 instance",
    "lb": "Load balancer", "rds": "RDS database", "vgw": "Virtual private gateway",
    "cgw": "Customer gateway",
}

EDGE_KINDS = ("trust", "break-glass", "sso-assignment", "oidc", "saml", "log-delivery",
              "route", "peering", "tgw-attachment", "sg-reference", "vpn")

WORLD = ("0.0.0.0/0", "::/0")
# Kinds that show their ID when they have no Name tag, since "Subnet" alone says nothing.
ID_TITLES = ("vpc", "subnet", "instance", "nacl", "rds", "tgw-attachment", "route-table")
BREAK_GLASS_ROLES = ("OrganizationAccountAccessRole",)
READ_ONLY_POLICIES = ("ReadOnlyAccess", "ViewOnlyAccess", "SecurityAudit")
ADMIN_POLICIES = ("AdministratorAccess",)
SEV_RANK = dict(SEVERITY_ORDER)


# =================================================================== small helpers

def edge_id(kind, src, dst) -> str:
    return f"{kind}:{src}->{dst}"


def account_of_arn(arn) -> str:
    m = re.match(r"arn:aws[\w-]*:[^:]*:[^:]*:(\d{12}):", str(arn or ""))
    return m.group(1) if m else ""


def region_of_arn(arn) -> str:
    m = re.match(r"arn:aws[\w-]*:[^:]*:([a-z0-9-]+):", str(arn or ""))
    return m.group(1) if m else ""


def region_of_az(az) -> str:
    az = str(az or "")
    m = re.fullmatch(r"([a-z]{2}(?:-gov)?-[a-z]+-\d)[a-z]", az)
    return m.group(1) if m else ""


def clean(value):
    """Make a value safe and stable for JSON: datetimes become text, sets become sorted
    lists, and dict keys become strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(clean(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def target_type(target) -> str:
    """igw, nat, tgw and so on, from a route target's ID."""
    t = str(target or "")
    for prefix, kind in (("igw-", "igw"), ("eigw-", "eigw"), ("nat-", "nat"), ("vgw-", "vgw"),
                         ("vpce-", "endpoint"), ("tgw-", "tgw"), ("pcx-", "peering"),
                         ("eni-", "eni"), ("i-", "instance"), ("cagw-", "carrier"),
                         ("lgw-", "local-gateway")):
        if t.startswith(prefix):
            return kind
    return "local" if t == "local" else ""


def _dest_key(dest):
    d = str(dest)
    return (0 if d in WORLD else 1, d)


def port_text(protocol, from_port, to_port) -> str:
    proto = str(protocol if protocol is not None else "-1").lower()
    if proto in ("-1", "all"):
        return "all traffic"
    if from_port in (None, -1, "") and to_port in (None, -1, ""):
        return proto
    if from_port == to_port or to_port in (None, ""):
        return f"{proto} {from_port}"
    return f"{proto} {from_port}-{to_port}"


def join_names(names, limit=3) -> str:
    names = [n for n in names if n]
    if len(names) <= limit:
        return ", ".join(names)
    return ", ".join(names[:limit]) + f" and {len(names) - limit} more"


def plural(n, word, many=None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


# =================================================================== model

@dataclass
class Node:
    id: str
    kind: str
    name: str = ""
    caption: str = ""
    parent: str = ""
    account: str = ""
    region: str = ""
    props: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    flags: list = field(default_factory=list)
    source: str = "aws"

    def flag(self, severity: str, reason: str):
        item = {"severity": severity, "reason": reason}
        if item not in self.flags:
            self.flags.append(item)

    @property
    def title(self) -> str:
        return title_of(self)

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "name": self.name, "caption": self.caption,
                "parent": self.parent, "account": self.account, "region": self.region,
                "props": clean(self.props), "tags": clean(self.tags),
                "flags": sorted_flags(self.flags), "source": self.source}


@dataclass
class Edge:
    id: str
    src: str
    dst: str
    kind: str
    label: str = ""
    flags: list = field(default_factory=list)
    props: dict = field(default_factory=dict)

    def flag(self, severity: str, reason: str):
        item = {"severity": severity, "reason": reason}
        if item not in self.flags:
            self.flags.append(item)

    def as_dict(self) -> dict:
        return {"id": self.id, "src": self.src, "dst": self.dst, "kind": self.kind,
                "label": self.label, "flags": sorted_flags(self.flags),
                "props": clean(self.props)}


def sorted_flags(flags) -> list:
    out = []
    for f in sorted(flags, key=lambda f: (SEV_RANK.get(f.get("severity"), 9), f.get("reason", ""))):
        if f not in out:
            out.append(dict(f))
    return out


def worst(flags) -> str:
    if not flags:
        return ""
    return min((f.get("severity", "info") for f in flags), key=lambda s: SEV_RANK.get(s, 9))


def title_of(node) -> str:
    if node.props.get("title"):
        return str(node.props["title"])
    if node.name:
        return node.name
    if node.kind == "account":
        return f"Account {node.id}"
    if node.kind in ID_TITLES:
        return node.id
    return NODE_KINDS.get(node.kind, node.kind)


class SnapshotError(ValueError):
    pass


def _text(value) -> str:
    """A snapshot field as text: a number or nothing becomes a string, anything else is
    refused, so a hand-made snapshot can't break the layout later on."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)
    raise TypeError(f"expected text, got {type(value).__name__}")


def _flags(value) -> list:
    out = []
    for f in list(value or []):
        if not isinstance(f, dict):
            raise TypeError("a flag isn't an object")
        out.append({"severity": _text(f.get("severity")) or "info", "reason": _text(f.get("reason"))})
    return out


class Snapshot:
    """Nodes and edges, plus where they came from. Save it with save(), read it back with
    Snapshot.load()."""

    def __init__(self, source="aws", scanned_at="", scope=None, warnings=None):
        self.source = source
        self.scanned_at = scanned_at
        self.scope = dict(scope or {})
        self.warnings = list(warnings or [])
        self.meta = {}
        self.nodes: dict = {}
        self.edges: dict = {}
        self._listed = {}            # (node ID, list name) -> keys already in that list

    # ---- building
    def add(self, node: Node) -> Node:
        """Add a node, or fill in the blanks of the one already there with this ID."""
        old = self.nodes.get(node.id)
        if old is None:
            self.nodes[node.id] = node
            return node
        if old.props.get("stub") and not node.props.get("stub"):
            node.parent = node.parent or old.parent
            node.flags = old.flags + [f for f in node.flags if f not in old.flags]
            self.nodes[node.id] = node
            return node
        for attr in ("name", "caption", "parent", "account", "region"):
            if not getattr(old, attr) and getattr(node, attr):
                setattr(old, attr, getattr(node, attr))
        for k, v in node.props.items():
            if k == "stub":
                continue
            if old.props.get(k) in (None, "", [], {}) and v not in (None, "", [], {}):
                old.props[k] = v
        for k, v in node.tags.items():
            old.tags.setdefault(k, v)
        for f in node.flags:
            old.flag(f["severity"], f["reason"])
        return old

    def connect(self, src, dst, kind, label="", props=None, eid=None) -> Edge:
        eid = eid or edge_id(kind, src, dst)
        edge = self.edges.get(eid)
        if edge is None:
            edge = Edge(eid, src, dst, kind, label, [], dict(props or {}))
            self.edges[eid] = edge
        else:
            if label and not edge.label:
                edge.label = label
            for k, v in (props or {}).items():
                edge.props.setdefault(k, v)
        return edge

    def warn(self, text: str):
        if text and text not in self.warnings:
            self.warnings.append(text)

    def get(self, node_id):
        return self.nodes.get(node_id)

    def of_kind(self, *kinds) -> list:
        return sorted((n for n in self.nodes.values() if n.kind in kinds), key=lambda n: n.id)

    def children(self, parent_id) -> list:
        return sorted((n for n in self.nodes.values() if n.parent == parent_id),
                      key=lambda n: n.id)

    def ancestors(self, node_id) -> list:
        out, seen = [], set()
        node = self.nodes.get(node_id)
        while node is not None and node.parent and node.parent not in seen:
            seen.add(node.parent)
            node = self.nodes.get(node.parent)
            if node is not None:
                out.append(node)
        return out

    def vpc_of(self, node) -> str:
        if node is None:
            return ""
        if node.kind == "vpc":
            return node.id
        for a in self.ancestors(node.id):
            if a.kind == "vpc":
                return a.id
        return str(node.props.get("vpc", ""))

    def account_node(self, node) -> Node | None:
        for a in [node] + self.ancestors(node.id):
            if a.kind == "account":
                return a
        return None

    # ---- saving
    def as_dict(self) -> dict:
        return {
            "format": FORMAT_NAME,
            "format_version": FORMAT_VERSION,
            "source": self.source,
            "scanned_at": self.scanned_at,
            "scope": clean(self.scope),
            "warnings": sorted(set(self.warnings)),
            "meta": clean(self.meta),
            "nodes": [self.nodes[k].as_dict() for k in sorted(self.nodes)],
            "edges": [self.edges[k].as_dict() for k in sorted(self.edges)],
        }

    def dumps(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def save(self, path) -> Path:
        from .common import write_atomic
        path = Path(path)
        write_atomic(path, self.dumps())
        return path

    @classmethod
    def from_dict(cls, data) -> "Snapshot":
        if not isinstance(data, dict) or data.get("format") != FORMAT_NAME:
            raise SnapshotError("That isn't a Cloud Map snapshot. Make one with awskit map "
                                "scan or awskit map tf.")
        version = data.get("format_version", 0)
        if not isinstance(version, int) or version > FORMAT_VERSION:
            raise SnapshotError(f"This snapshot is format version {version}, which is newer "
                                f"than this AWS Kit understands ({FORMAT_VERSION}). Update AWS Kit.")
        snap = cls(data.get("source", "aws"), data.get("scanned_at", ""), data.get("scope"),
                   data.get("warnings"))
        try:
            snap.meta = dict(data.get("meta") or {})
            for n in data.get("nodes", []):
                props = dict(n.get("props") or {})
                if "category" in props and not isinstance(props["category"], str):
                    props["category"] = str(props["category"])
                node = Node(_text(n["id"]), _text(n["kind"]), _text(n.get("name")),
                            _text(n.get("caption")), _text(n.get("parent")),
                            _text(n.get("account")), _text(n.get("region")), props,
                            {_text(k): _text(v) for k, v in dict(n.get("tags") or {}).items()},
                            _flags(n.get("flags")), _text(n.get("source")) or "aws")
                snap.nodes[node.id] = node
            for e in data.get("edges", []):
                edge = Edge(_text(e["id"]), _text(e["src"]), _text(e["dst"]), _text(e["kind"]),
                            _text(e.get("label")), _flags(e.get("flags")),
                            dict(e.get("props") or {}))
                snap.edges[edge.id] = edge
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SnapshotError(f"The snapshot is damaged: {type(exc).__name__} {exc}") from exc
        return snap

    @classmethod
    def load(cls, path) -> "Snapshot":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise SnapshotError(f"Couldn't read {path}: {exc.strerror or exc}") from exc
        except ValueError as exc:
            raise SnapshotError(f"{Path(path).name} isn't valid JSON: {exc}") from exc
        return cls.from_dict(data)


def merge(snaps) -> "Snapshot":
    """One snapshot from several, before finish(). Nodes with the same ID fill in each
    other's blanks, so two Terraform stacks that share a VPC draw it once."""
    snaps = list(snaps)
    out = Snapshot(snaps[0].source if snaps else "aws")
    for snap in snaps:
        for node_id in sorted(snap.nodes):
            out.add(snap.nodes[node_id])
        for edge_id_ in sorted(snap.edges):
            e = snap.edges[edge_id_]
            merged = out.connect(e.src, e.dst, e.kind, e.label, e.props, eid=e.id)
            for f in e.flags:
                merged.flag(f["severity"], f["reason"])
            if e.kind == "sso-assignment":
                merged.props["permission_sets"] = sorted(set(merged.props.get("permission_sets", []))
                                                         | set(e.props.get("permission_sets", [])))
        for w in snap.warnings:
            out.warn(w)
        out.meta.update(snap.meta)
    return out


# =================================================================== containers

def ensure_account(snap, account_id, name="", source="aws", **props) -> Node:
    account_id = account_id or UNKNOWN_ACCOUNT
    if account_id == UNKNOWN_ACCOUNT:
        name = name or "Unknown account"
        props.setdefault("title", "Unknown account")
    return snap.add(Node(account_id, "account", name, account=account_id, props=props,
                         source=source))


def ensure_region(snap, account, region, source="aws", stub_account=False) -> str:
    """The region node under its account. stub_account: the account is only known from
    something that points at it (a peered VPC, a shared transit gateway), so it isn't
    counted as one of yours."""
    account = account or UNKNOWN_ACCOUNT
    region = region or UNKNOWN_REGION
    if not stub_account:
        ensure_account(snap, account, source=source)
    elif snap.get(account) is None:
        ensure_account(snap, account, source=source, stub=True)
    rid = f"{account}/{region}"
    snap.add(Node(rid, "region", region if region != UNKNOWN_REGION else "Unknown region",
                  parent=account, account=account, region=region, source=source))
    return rid


def ensure_az(snap, vpc_id, az, account="", region="", source="aws") -> str:
    vpc = snap.get(vpc_id)
    if vpc is not None:
        account, region = vpc.account or account, vpc.region or region
    aid = f"{vpc_id}/{az or 'unknown-az'}"
    snap.add(Node(aid, "az", az or "Unknown zone", parent=vpc_id, account=account,
                  region=region or region_of_az(az), source=source))
    return aid


def ensure_external(snap) -> str:
    snap.add(Node(EXTERNAL, "external", NODE_KINDS["external"], source="model"))
    return EXTERNAL


def external_node(snap, node_id, kind, name, source="aws", **props) -> Node:
    ensure_external(snap)
    return snap.add(Node(node_id, kind, name, parent=EXTERNAL, props=props, source=source))


# =================================================================== access builders

def add_org(snap, org_id, arn="", master_account="", root_id="", root_scps=(), accounts=(),
            scp_summaries=None, partial=False, source="aws") -> Node:
    """accounts: [{id, name, email, status}] for accounts that may not have their own entry."""
    node = snap.add(Node(org_id, "org", "Organization", source=source, props={
        "arn": arn, "master_account": master_account, "root_id": root_id,
        "scps": sorted(set(root_scps)), "accounts": [dict(a) for a in accounts],
        "scp_summaries": dict(scp_summaries or {}), "partial": bool(partial)}))
    if not partial:
        node.props["partial"] = False
    return node


def add_ou(snap, ou_id, name, parent_id, arn="", scps=(), tags=None, source="aws") -> Node:
    return snap.add(Node(ou_id, "ou", name, source=source, tags=dict(tags or {}),
                         props={"arn": arn, "org_parent": parent_id, "scps": sorted(set(scps))}))


def add_org_account(snap, account_id, name, parent_id="", arn="", email="", status="",
                    scps=(), tags=None, source="aws") -> Node:
    node = ensure_account(snap, account_id, name, source=source)
    node.tags.update(tags or {})
    for k, v in (("arn", arn), ("email", email), ("status", status), ("org_parent", parent_id)):
        if v:
            node.props[k] = v
    node.props["in_org"] = True
    if scps:
        node.props["scps"] = sorted(set(node.props.get("scps", [])) | set(scps))
    if name:
        node.name = name
    return node


def add_identity_center(snap, instance_arn, account, identity_store="", source="aws") -> Node:
    return snap.add(Node(instance_arn, "identity-center", "IAM Identity Center", account=account,
                         source=source, props={"identity_store": identity_store}))


def add_permission_set(snap, arn, name, instance_arn, description="", policies=(),
                       session="", accounts=(), source="aws") -> Node:
    return snap.add(Node(arn, "permission-set", name, parent=instance_arn, source=source, props={
        "description": description, "policies": sorted(set(policies)),
        "session_duration": session, "accounts": sorted(set(accounts))}))


def add_principal(snap, kind, principal_id, name, source="aws") -> Node:
    return external_node(snap, principal_id, kind, name or f"{kind} {principal_id}", source)


def add_assignment(snap, principal_id, account_id, permission_set_arn) -> Edge:
    edge = snap.connect(principal_id, account_id or UNKNOWN_ACCOUNT, "sso-assignment")
    sets = set(edge.props.get("permission_sets", []))
    sets.add(permission_set_arn)
    edge.props["permission_sets"] = sorted(sets)
    return edge


def add_role(snap, arn, name, path="/", trust=None, description="", policies=(), tags=None,
             source="aws") -> Node:
    account = account_of_arn(arn)
    ensure_account(snap, account, source=source)
    if isinstance(trust, str):
        try:
            trust, _ = iampolicy.load_policy(trust)
        except iampolicy.PolicyError:
            trust = None
    return snap.add(Node(arn, "role", name, parent=account or UNKNOWN_ACCOUNT,
                         account=account, source=source, tags=dict(tags or {}), props={
                             "arn": arn, "path": path or "/", "trust_policy": trust or {},
                             "description": description, "policies": sorted(set(policies))}))


def add_oidc_provider(snap, arn, url, audiences=(), source="aws") -> Node:
    account = account_of_arn(arn)
    ensure_account(snap, account, source=source)
    host = re.sub(r"^https://", "", str(url or arn.split("oidc-provider/", 1)[-1]))
    return snap.add(Node(arn, "oidc-provider", host, parent=account or UNKNOWN_ACCOUNT,
                         account=account, source=source,
                         props={"arn": arn, "url": host, "audiences": sorted(set(audiences))}))


def add_saml_provider(snap, arn, source="aws") -> Node:
    account = account_of_arn(arn)
    ensure_account(snap, account, source=source)
    name = arn.split("saml-provider/", 1)[-1]
    return snap.add(Node(arn, "saml-provider", name, parent=account or UNKNOWN_ACCOUNT,
                         account=account, source=source, props={"arn": arn}))


def add_trail(snap, arn, name, bucket="", home_region="", multi_region=False, org_trail=False,
              validation=False, source="aws") -> Node:
    account = account_of_arn(arn)
    ensure_account(snap, account, source=source)
    return snap.add(Node(arn, "trail", name, parent=account or UNKNOWN_ACCOUNT, account=account,
                         region=home_region or region_of_arn(arn), source=source, props={
                             "arn": arn, "bucket": bucket, "multi_region": bool(multi_region),
                             "org_trail": bool(org_trail), "log_validation": bool(validation)}))


def add_bucket(snap, name, account, tags=None, source="aws", **props) -> Node:
    ensure_account(snap, account, source=source)
    arn = f"arn:aws:s3:::{name}"
    return snap.add(Node(arn, "bucket", name, parent=account or UNKNOWN_ACCOUNT,
                         account=account or "", source=source, tags=dict(tags or {}),
                         props=dict(props, arn=arn)))


def add_cost(snap, account, budgets=(), anomaly_monitors=0, source="aws") -> Node:
    ensure_account(snap, account, source=source)
    node = snap.add(Node(f"{account or UNKNOWN_ACCOUNT}/cost", "cost", "Cost guardrails",
                         parent=account or UNKNOWN_ACCOUNT, account=account, source=source,
                         props={"budgets": [], "anomaly_monitors": 0}))
    node.props["budgets"] = sorted(set(node.props.get("budgets", [])) | set(budgets))
    node.props["anomaly_monitors"] = int(node.props.get("anomaly_monitors", 0)) + int(anomaly_monitors)
    return node


# =================================================================== network builders

def add_vpc(snap, vpc_id, account, region, cidrs=(), name="", is_default=False, tags=None,
            source="aws", stub=False) -> Node:
    rid = ensure_region(snap, account, region, source, stub_account=stub)
    props = {"cidrs": sorted(set(c for c in cidrs if c)), "default": bool(is_default)}
    if stub:
        props["stub"] = True
    return snap.add(Node(vpc_id, "vpc", name, parent=rid, account=account or UNKNOWN_ACCOUNT,
                         region=region or UNKNOWN_REGION, tags=dict(tags or {}), props=props,
                         source=source))


def add_subnet(snap, subnet_id, vpc_id, az, cidr="", name="", ipv6="", map_public=None,
               account="", region="", tags=None, source="aws") -> Node:
    vpc = snap.get(vpc_id)
    account = (vpc.account if vpc else "") or account
    region = (vpc.region if vpc else "") or region or region_of_az(az)
    parent = ensure_az(snap, vpc_id, az, account, region, source)
    props = {"cidr": cidr, "ipv6_cidr": ipv6, "vpc": vpc_id, "az": az}
    if map_public is not None:
        props["map_public_ip"] = bool(map_public)
    return snap.add(Node(subnet_id, "subnet", name, parent=parent, account=account,
                         region=region, tags=dict(tags or {}), props=props, source=source))


def _in_vpc(snap, vpc_id):
    vpc = snap.get(vpc_id)
    return (vpc.account, vpc.region) if vpc else ("", "")


def add_gateway(snap, kind, gateway_id, vpc_id="", account="", region="", name="", tags=None,
                source="aws", **props) -> Node:
    """Internet, egress-only and virtual private gateways sit on their VPC's border. One
    that isn't attached goes in its region."""
    a, r = _in_vpc(snap, vpc_id)
    account, region = a or account, r or region
    parent = vpc_id if vpc_id else ensure_region(snap, account, region, source)
    return snap.add(Node(gateway_id, kind, name, parent=parent, account=account, region=region,
                         tags=dict(tags or {}), props=dict(props, vpc=vpc_id), source=source))


def add_nat(snap, nat_id, subnet_id, vpc_id="", connectivity="public", public_ip="",
            state="", name="", tags=None, source="aws") -> Node:
    a, r = _in_vpc(snap, vpc_id)
    return snap.add(Node(nat_id, "nat", name, parent=subnet_id, account=a, region=r,
                         tags=dict(tags or {}), source=source, props={
                             "vpc": vpc_id, "subnet": subnet_id, "connectivity": connectivity,
                             "public_ip": public_ip, "state": state}))


def add_route_table(snap, rt_id, vpc_id, routes=(), subnets=(), main=False, name="",
                    tags=None, source="aws", blackholes=()) -> Node:
    """blackholes: routes whose target is gone ({dest, target}). They still win the
    longest-prefix match and drop the traffic, so reachability needs them, but they
    aren't drawn. Only kept when there are some, so older snapshots stay the same."""
    a, r = _in_vpc(snap, vpc_id)
    node = snap.add(Node(rt_id, "route-table", name, parent=vpc_id, account=a, region=r,
                         tags=dict(tags or {}), source=source,
                         props={"vpc": vpc_id, "routes": [], "subnets": [], "main": bool(main)}))
    for route in routes:
        add_route(snap, rt_id, route.get("dest", ""), route.get("target", ""))
    for s in subnets:
        associate_subnet(snap, rt_id, s)
    if main:
        node.props["main"] = True
    holes = [{"dest": str(b.get("dest", "")), "target": str(b.get("target", ""))}
             for b in blackholes or () if b.get("dest")]
    if holes:
        known = node.props.setdefault("blackholes", [])
        for h in holes:
            if h not in known:
                known.append(h)
        known.sort(key=lambda x: (_dest_key(x["dest"]), x["target"]))
    return node


def add_route(snap, rt_id, dest, target):
    node = snap.get(rt_id)
    if node is None:
        node = snap.add(Node(rt_id, "route-table", props={"routes": [], "subnets": [],
                                                           "main": False}))
    route = {"dest": str(dest or ""), "target": str(target or "")}
    routes = node.props.setdefault("routes", [])
    if route["dest"] and _first_time(snap, rt_id, "routes", routes, route):
        routes.append(route)                 # sorted once, in finish()


def associate_subnet(snap, rt_id, subnet_id):
    node = snap.get(rt_id)
    if node is None:
        node = snap.add(Node(rt_id, "route-table", props={"routes": [], "subnets": [],
                                                           "main": False}))
    subnets = node.props.setdefault("subnets", [])
    if subnet_id and subnet_id not in subnets:
        subnets.append(subnet_id)
        subnets.sort()


def set_main_route_table(snap, vpc_id, rt_id):
    node = snap.get(rt_id)
    if node is None:
        node = add_route_table(snap, rt_id, vpc_id)
    node.props["main"] = True
    if not node.parent:
        node.parent = vpc_id


def add_tgw(snap, tgw_id, account, region, asn="", name="", owner="", tags=None,
            source="aws", stub_account=False) -> Node:
    rid = ensure_region(snap, account, region, source, stub_account=stub_account)
    return snap.add(Node(tgw_id, "tgw", name, parent=rid, account=account, region=region,
                         tags=dict(tags or {}), source=source,
                         props={"asn": str(asn or ""), "owner": owner or account}))


def add_tgw_attachment(snap, attachment_id, tgw_id, vpc_id, subnets=(), state="", name="",
                       tags=None, source="aws") -> Node:
    a, r = _in_vpc(snap, vpc_id)
    node = snap.add(Node(attachment_id, "tgw-attachment", name, parent=vpc_id, account=a,
                         region=r, tags=dict(tags or {}), source=source, props={
                             "tgw": tgw_id, "vpc": vpc_id, "subnets": sorted(set(subnets)),
                             "state": state}))
    if tgw_id:
        snap.connect(attachment_id, tgw_id, "tgw-attachment")
    return node


def add_peering(snap, pcx_id, requester_vpc, accepter_vpc, status="", requester=None,
                accepter=None, name="") -> Edge:
    """requester and accepter: {account, region, cidr} for the side that may be outside
    this input, so a stub VPC can stand in for it."""
    for vpc_id, info in ((requester_vpc, requester or {}), (accepter_vpc, accepter or {})):
        if vpc_id and snap.get(vpc_id) is None and info:
            add_vpc(snap, vpc_id, info.get("account", ""), info.get("region", ""),
                    [info.get("cidr", "")], stub=True, source="model")
    return snap.connect(requester_vpc, accepter_vpc, "peering", props={
        "pcx": pcx_id, "status": status, "name": name})


def add_endpoint(snap, vpce_id, vpc_id, service, endpoint_type="Gateway", subnets=(),
                 route_tables=(), name="", tags=None, source="aws") -> Node:
    a, r = _in_vpc(snap, vpc_id)
    return snap.add(Node(vpce_id, "endpoint", name, parent=vpc_id, account=a, region=r,
                         tags=dict(tags or {}), source=source, props={
                             "vpc": vpc_id, "service": service, "type": endpoint_type,
                             "subnets": sorted(set(subnets)),
                             "route_tables": sorted(set(route_tables))}))


def rule(protocol="-1", from_port=None, to_port=None, cidrs=(), groups=(), description="",
         prefix_lists=()):
    """One security group rule, the same shape whichever input it came from. prefix_lists
    (pl-... IDs) are only kept when there are some, so older snapshots stay the same."""
    out = {"protocol": str(protocol if protocol not in (None, "") else "-1"),
           "from": from_port, "to": to_port,
           "cidrs": sorted(set(c for c in cidrs if c)),
           "groups": sorted(set(g for g in groups if g)), "description": description or ""}
    pls = sorted(set(str(p) for p in prefix_lists or () if p))
    if pls:
        out["prefix_lists"] = pls
    return out


def add_security_group(snap, sg_id, vpc_id, name="", description="", ingress=(), egress=(),
                       tags=None, source="aws") -> Node:
    a, r = _in_vpc(snap, vpc_id)
    node = snap.add(Node(sg_id, "sg", name, parent=vpc_id, account=a, region=r,
                         tags=dict(tags or {}), source=source,
                         props={"vpc": vpc_id, "description": description, "ingress": [],
                                "egress": []}))
    for r_ in ingress:
        add_sg_rule(snap, sg_id, "ingress", r_)
    for r_ in egress:
        add_sg_rule(snap, sg_id, "egress", r_)
    return node


def add_sg_rule(snap, sg_id, direction, sg_rule):
    node = snap.get(sg_id)
    if node is None:
        node = snap.add(Node(sg_id, "sg", props={"ingress": [], "egress": [], "stub": True}))
    rules = node.props.setdefault(direction, [])
    if _first_time(snap, sg_id, direction, rules, sg_rule):
        rules.append(sg_rule)                # sorted once, in finish()


def _first_time(snap, node_id, name, items, item) -> bool:
    """Whether item isn't in the list yet. Keeps a set of what's there, so adding
    thousands of rules or routes doesn't compare each one with all the others."""
    seen = getattr(snap, "_listed", None)
    if seen is None:
        seen = snap._listed = {}
    key = (node_id, name)
    if key not in seen or len(seen[key]) != len(items):
        seen[key] = {json.dumps(x, sort_keys=True) for x in items}
    text = json.dumps(item, sort_keys=True)
    if text in seen[key]:
        return False
    seen[key].add(text)
    return True


def _sort_lists(snap):
    """Rules and routes in a fixed order, so the same account gives the same snapshot."""
    for node in snap.nodes.values():
        if node.kind == "sg":
            for direction in ("ingress", "egress"):
                if isinstance(node.props.get(direction), list):
                    node.props[direction].sort(key=lambda x: json.dumps(x, sort_keys=True))
        elif node.kind == "route-table" and isinstance(node.props.get("routes"), list):
            node.props["routes"].sort(key=lambda x: (_dest_key(x["dest"]), x["target"]))
        elif node.kind == "nacl" and isinstance(node.props.get("entries"), list):
            node.props["entries"].sort(key=_entry_key)


# Protocol names as AWS numbers them, the way network ACL entries store them.
PROTOCOL_NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "icmp6": "58",
                    "all": "-1", "-1": "-1"}
# The rule number AWS gives the catch-all deny at the end of every network ACL ("*").
NACL_DEFAULT_RULE = 32767


def protocol_number(protocol) -> str:
    """'6' for tcp, '-1' for all traffic, and so on. Numbers stay numbers."""
    p = str(protocol if protocol not in (None, "") else "-1").strip().lower()
    if p in PROTOCOL_NUMBERS:
        return PROTOCOL_NUMBERS[p]
    try:
        n = int(p)
    except ValueError:
        return p
    return "-1" if n < 0 else str(n)


def _int_or_none(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def nacl_entry(rule_number, egress, action, protocol="-1", cidr="", ipv6_cidr="",
               from_port=None, to_port=None, icmp_type=None, icmp_code=None) -> dict:
    """One network ACL rule, the same shape whichever input it came from. Ports are only
    kept for tcp and udp, and the ICMP type and code for ICMP."""
    proto = protocol_number(protocol)
    out = {"rule": int(rule_number), "egress": bool(egress),
           "action": "allow" if str(action).strip().lower() == "allow" else "deny",
           "protocol": proto, "cidr": str(cidr or ""), "ipv6_cidr": str(ipv6_cidr or ""),
           "from": None, "to": None}
    if proto in ("6", "17"):
        out["from"], out["to"] = _int_or_none(from_port), _int_or_none(to_port)
    elif proto in ("1", "58"):
        if _int_or_none(icmp_type) is not None:
            out["icmp_type"] = _int_or_none(icmp_type)
        if _int_or_none(icmp_code) is not None:
            out["icmp_code"] = _int_or_none(icmp_code)
    return out


def default_nacl_entries() -> list:
    """The catch-all deny AWS puts last in every network ACL, in both directions. A live
    scan lists it, Terraform doesn't, so the Terraform input adds it."""
    return [nacl_entry(NACL_DEFAULT_RULE, egress, "deny", "-1", "0.0.0.0/0")
            for egress in (False, True)]


def _entry_key(entry):
    return (bool(entry.get("egress")), int(entry.get("rule", 0)),
            json.dumps(entry, sort_keys=True))


def add_nacl(snap, acl_id, vpc_id, subnets=(), is_default=False, name="", tags=None,
             source="aws", entries=None) -> Node:
    """entries: the rules (nacl_entry), when the input has them. A snapshot made before
    rules were recorded has no "entries" at all, which reachability treats as unknown."""
    a, r = _in_vpc(snap, vpc_id)
    props = {"vpc": vpc_id, "subnets": sorted(set(subnets)), "default": bool(is_default)}
    if entries is not None:
        props["entries"] = []
    node = snap.add(Node(acl_id, "nacl", name, parent=vpc_id, account=a, region=r,
                         tags=dict(tags or {}), source=source, props=props))
    for e in entries or ():
        add_nacl_entry(snap, acl_id, e)
    return node


def add_nacl_entry(snap, acl_id, entry):
    """Add one rule. Rule numbers are unique per direction, so a rule Terraform lists both
    inline and as its own aws_network_acl_rule is kept once."""
    node = snap.get(acl_id)
    if node is None or node.kind != "nacl":
        return                  # a rule for an ACL that isn't in this input
    entries = node.props.setdefault("entries", [])
    key = (bool(entry.get("egress")), int(entry.get("rule", 0)))
    if any((bool(e.get("egress")), int(e.get("rule", 0))) == key for e in entries):
        return
    entries.append(entry)
    entries.sort(key=_entry_key)


def add_instance(snap, instance_id, subnet_id, vpc_id="", name="", instance_type="", state="",
                 private_ip="", public_ip="", security_groups=(), imds_tokens="",
                 imds_endpoint="", profile="", tags=None, source="aws", **extra) -> Node:
    a, r = _in_vpc(snap, vpc_id)
    return snap.add(Node(instance_id, "instance", name, parent=subnet_id, account=a, region=r,
                         tags=dict(tags or {}), source=source, props=dict(extra, **{
                             "vpc": vpc_id, "subnet": subnet_id, "type": instance_type,
                             "state": state, "private_ip": private_ip, "public_ip": public_ip,
                             "security_groups": sorted(set(security_groups)),
                             "imds_tokens": imds_tokens, "imds_endpoint": imds_endpoint,
                             "instance_profile": profile})))


def add_lb(snap, arn, name, vpc_id, subnets=(), azs=(), scheme="", lb_type="application",
           tags=None, source="aws", security_groups=None, listeners=None) -> Node:
    """security_groups: a list when the input says (a Network Load Balancer can have
    none). listeners: [{port, protocol}] when they were read. Left out when unknown, so
    older snapshots stay the same and reachability can tell "none" from "not read"."""
    a, r = _in_vpc(snap, vpc_id)
    props = {"arn": arn, "vpc": vpc_id, "subnets": sorted(set(subnets)),
             "azs": sorted(set(azs)), "scheme": scheme, "type": lb_type}
    if security_groups is not None:
        props["security_groups"] = sorted(set(g for g in security_groups if g))
    if listeners is not None:
        props["listeners"] = []
    node = snap.add(Node(arn, "lb", name, parent=vpc_id, account=a or account_of_arn(arn),
                         region=r or region_of_arn(arn), tags=dict(tags or {}), source=source,
                         props=props))
    for li in listeners or ():
        add_listener(snap, arn, li.get("port"), li.get("protocol", ""))
    return node


def add_listener(snap, lb_id, port, protocol=""):
    node = snap.get(lb_id)
    port = _int_or_none(port)
    if node is None or port is None:
        return
    items = node.props.setdefault("listeners", [])
    item = {"port": port, "protocol": str(protocol or "").upper()}
    if item not in items:
        items.append(item)
        items.sort(key=lambda x: (x["port"], x["protocol"]))


# The port each RDS engine listens on unless it's set.
ENGINE_PORTS = (("aurora-postgresql", 5432), ("postgres", 5432), ("aurora-mysql", 3306),
                ("aurora", 3306), ("mysql", 3306), ("mariadb", 3306), ("oracle", 1521),
                ("sqlserver", 1433), ("db2", 50000))


def engine_port(engine):
    e = str(engine or "").lower()
    for prefix, port in ENGINE_PORTS:
        if e.startswith(prefix):
            return port
    return None


def add_rds(snap, arn, identifier, vpc_id, subnets=(), az="", engine="", version="",
            instance_class="", public=False, tags=None, source="aws", security_groups=None,
            port=None) -> Node:
    """Placed in the subnet from its subnet group that's in its zone. security_groups and
    port are left out when the input doesn't have them; the port falls back to the
    engine's default."""
    a, r = _in_vpc(snap, vpc_id)
    parent = ""
    for s in sorted(subnets):
        sn = snap.get(s)
        if sn is not None and (not az or sn.props.get("az") == az):
            parent = s
            break
    if not parent and subnets:
        parent = sorted(subnets)[0]
    props = {"arn": arn, "vpc": vpc_id, "subnets": sorted(set(subnets)), "az": az,
             "engine": engine, "version": version, "class": instance_class,
             "public": bool(public)}
    if security_groups is not None:
        props["security_groups"] = sorted(set(g for g in security_groups if g))
    port = _int_or_none(port) or engine_port(engine)
    if port:
        props["port"] = port
    return snap.add(Node(arn, "rds", identifier, parent=parent or vpc_id,
                         account=a or account_of_arn(arn), region=r or region_of_arn(arn),
                         tags=dict(tags or {}), source=source, props=props))


def add_cgw(snap, cgw_id, account, region, ip="", asn="", name="", tags=None,
            source="aws") -> Node:
    rid = ensure_region(snap, account, region, source)
    return snap.add(Node(cgw_id, "cgw", name, parent=rid, account=account, region=region,
                         tags=dict(tags or {}), source=source,
                         props={"ip": ip, "asn": str(asn or "")}))


def add_vpn(snap, vpn_id, cgw_id, gateway_id, state="", name="") -> Edge:
    return snap.connect(cgw_id, gateway_id, "vpn", props={"vpn": vpn_id, "state": state,
                                                          "name": name})


# =================================================================== trust parsing

ASSUME_ACTIONS = ("sts:assumerole", "sts:assumerolewithsaml", "sts:assumerolewithwebidentity")


def _allows_assume(stmt) -> bool:
    """Whether a statement's Action (or NotAction) covers assuming the role, wildcards
    like sts:Assume* and sts:*Role included."""
    if "NotAction" in stmt:
        nots = [str(a).lower() for a in iampolicy.as_list(stmt.get("NotAction"))]
        return any(not any(fnmatch.fnmatchcase(t, n) for n in nots) for t in ASSUME_ACTIONS)
    actions = [str(a).lower() for a in iampolicy.as_list(stmt.get("Action"))]
    if not actions:
        return True
    return any(fnmatch.fnmatchcase(t, a) for a in actions for t in ASSUME_ACTIONS)


def trust_principals(doc) -> list:
    """Who a trust policy lets assume the role, one entry per principal."""
    out = []
    if not isinstance(doc, dict):
        return out
    for stmt in iampolicy.statements(doc):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        if not _allows_assume(stmt):
            continue
        conds = iampolicy.condition_keys(stmt)
        if "NotPrincipal" in stmt:
            out.append({"type": "public", "value": "*", "stmt": stmt, "conds": conds,
                        "not_principal": True})
            continue
        for kind, values in sorted(iampolicy.principal_parts(stmt.get("Principal")).items()):
            for v in values:
                if kind == "AWS" and v == "*":
                    out.append({"type": "public", "value": "*", "stmt": stmt, "conds": conds})
                elif kind == "AWS":
                    out.append({"type": "aws", "value": v, "account": iampolicy.account_of(v),
                                "stmt": stmt, "conds": conds})
                elif kind == "Service":
                    out.append({"type": "service", "value": v, "stmt": stmt, "conds": conds})
                elif kind == "Federated":
                    out.append({"type": "federated", "value": v, "stmt": stmt, "conds": conds})
    return out


def github_scopes(subs) -> list:
    """Readable versions of GitHub OIDC sub patterns, like 'Snowblind019/aws-platform,
    main only'."""
    out = []
    for s in subs:
        s = str(s)
        if s in ("*", "repo:*") or s.startswith("*"):
            out.append("any repo")
            continue
        m = re.match(r"repo:([^:]+)(?::(.*))?$", s)
        if not m:
            out.append(s)
            continue
        repo, rest = m.group(1), m.group(2) or "*"
        if repo.endswith("/*"):
            out.append(f"any repo in {repo[:-2]}")
            continue
        if rest == "*":
            scope = "any branch"
        elif rest.startswith("ref:refs/heads/"):
            branch = rest[len("ref:refs/heads/"):]
            scope = "any branch" if branch in ("*", "**") else (
                f"{branch} only" if "*" not in branch else f"branches {branch}")
        elif rest.startswith("ref:refs/tags/"):
            tag = rest[len("ref:refs/tags/"):]
            scope = "any tag" if tag in ("*", "**") else f"tag {tag}"
        elif rest.startswith("environment:"):
            scope = f"{rest.split(':', 1)[1]} environment"
        elif rest == "pull_request":
            scope = "pull requests"
        else:
            scope = rest
        out.append(f"{repo}, {scope}")
    return sorted(set(out))


def _any_branch(subs) -> list:
    loose = []
    for s in subs:
        m = re.match(r"repo:([^:/]+/[^:*]+):(.*)$", str(s))
        if m and m.group(2) in ("*", "ref:refs/heads/*", "ref:refs/heads/**", "ref:*"):
            loose.append(m.group(1))
    return sorted(set(loose))


TRUST_FINDINGS = {
    "Open to everyone", "Public principal with a weak condition", "Allow with NotPrincipal",
    "GitHub OIDC trust without a repo check", "GitHub OIDC repo check is loose",
    "GitHub OIDC trust without an audience check", "Federated trust without conditions",
    "Web identity trust with no Federated principal",
}


# =================================================================== finish

def finish(snap, known_accounts=()) -> Snapshot:
    """Work out everything that depends on more than one resource. Run once, after all
    the add_* calls."""
    _sort_lists(snap)
    _place_org(snap)
    _place_identity_center(snap)
    _fix_orphans(snap)
    _trusts(snap, set(known_accounts or ()))
    _trails(snap)
    _routes(snap)
    _security_groups(snap)
    _instances(snap)
    _assignments(snap)
    _captions(snap)
    snap.warnings = sorted(set(snap.warnings))
    for node in snap.nodes.values():
        node.flags = sorted_flags(node.flags)
    for edge in snap.edges.values():
        edge.flags = sorted_flags(edge.flags)
    return snap


def org_node(snap):
    orgs = [o for o in snap.of_kind("org") if not o.props.get("partial")]
    return orgs[0] if orgs else None


def _place_org(snap):
    orgs = snap.of_kind("org")
    full = [o for o in orgs if not o.props.get("partial")]
    snap.meta["org"] = "full" if full else ("partial" if orgs else "none")
    if not full:
        if orgs:
            master = orgs[0].props.get("master_account")
            if master:
                snap.meta["management_account"] = master
            snap.warn("Organizations data isn't available from this account. Scan with the "
                      "management account or a delegated admin to see the org.")
        return
    org = full[0]
    roots = {o.props.get("root_id") for o in orgs if o.props.get("root_id")}
    master = org.props.get("master_account", "")
    for info in org.props.get("accounts", []):
        acct = ensure_account(snap, info.get("id"), info.get("name", ""), source=org.source)
        acct.props["in_org"] = True
        if not acct.props.get("org_parent"):
            acct.props["org_parent"] = org.props.get("root_id", "")
        for k in ("email", "status"):
            if info.get(k) and not acct.props.get(k):
                acct.props[k] = info[k]
    if master:
        acct = ensure_account(snap, master, source=org.source)
        acct.props["management"] = True
        acct.props["in_org"] = True
        acct.props.setdefault("org_parent", org.props.get("root_id", ""))
        snap.meta["management_account"] = master
    for node in snap.of_kind("ou", "account"):
        if node.kind == "account" and not node.props.get("in_org") and "org_parent" not in node.props:
            continue
        parent = node.props.get("org_parent", "")
        node.props["in_org"] = True
        if not parent or parent in roots or snap.get(parent) is None or parent == node.id:
            node.parent = org.id
        else:
            node.parent = parent


def _place_identity_center(snap):
    master = snap.meta.get("management_account", "")
    org = org_node(snap)
    for idc in snap.of_kind("identity-center"):
        home = master if (org is not None and master) else (idc.account or UNKNOWN_ACCOUNT)
        ensure_account(snap, home, source=idc.source)
        idc.parent = home
        idc.account = home


def _fix_orphans(snap):
    for node in list(snap.nodes.values()):
        if not node.parent or snap.get(node.parent) is not None:
            continue
        missing = node.parent
        if missing.startswith("vpc-") and "/" not in missing:
            add_vpc(snap, missing, node.account, node.region, stub=True, source="model")
        elif missing.startswith("subnet-"):
            node.parent = node.props.get("vpc") or ""
            if node.parent and snap.get(node.parent) is None:
                add_vpc(snap, node.parent, node.account, node.region, stub=True, source="model")
        elif node.kind in ("permission-set",):
            continue
        else:
            node.parent = ""
        if not node.parent and node.kind not in ("org", "external", "account", "ou"):
            if node.kind in ("vpc", "tgw", "cgw"):
                node.parent = ensure_region(snap, node.account, node.region)
            elif node.kind in CONTAINER_KINDS:
                pass
            else:
                node.parent = ensure_account(snap, node.account).id
    for vpc in snap.of_kind("vpc"):
        if vpc.props.get("stub") and not vpc.name:
            vpc.name = vpc.id


def _inside_org(snap, known):
    """(set of account IDs inside the org, whether that set comes from org data)."""
    if org_node(snap) is not None:
        return {n.id for n in snap.of_kind("account") if n.props.get("in_org")}, True
    mine = {n.id for n in snap.of_kind("account") if n.id != UNKNOWN_ACCOUNT
            and not n.props.get("stub")}
    if snap.meta.get("management_account"):
        mine.add(snap.meta["management_account"])
    return mine | set(known), False


def _trusts(snap, known):
    inside, from_org = _inside_org(snap, known)
    idc_names = {}
    for ps in snap.of_kind("permission-set"):
        idc_names.setdefault(ps.name, ps)
    for sp in snap.of_kind("saml-provider"):
        if sp.name.startswith("AWSSSO_"):
            sp.props["hidden"] = "identity-center"
    sso_roles = {}

    for role in snap.of_kind("role"):
        name, acct = role.name, role.account
        if role.props.get("path", "/").startswith("/aws-service-role/"):
            role.props["service_linked"] = True
        if name.startswith("AWSReservedSSO_"):
            role.props["collapsed"] = "identity-center"
            m = re.match(r"AWSReservedSSO_(.+)_[0-9a-f]{16}$", name)
            ps_name = m.group(1) if m else name[len("AWSReservedSSO_"):]
            ps = idc_names.get(ps_name)
            if ps is not None:
                accounts = set(ps.props.get("accounts", [])) | {acct}
                ps.props["accounts"] = sorted(a for a in accounts if a)
            else:
                sso_roles.setdefault(acct, set()).add(ps_name)
            continue
        if name in BREAK_GLASS_ROLES:
            role.props["break_glass"] = True
            role.props["title"] = "Break-glass role"
        doc = role.props.get("trust_policy") or {}
        for f in iampolicy.analyze(doc, "trust") if doc else []:
            if f.title in TRUST_FINDINGS and f.severity in ("critical", "high", "medium", "low"):
                role.flag(f.severity, f"{f.title}. {f.detail}".strip())
        trusted_by, classes = [], set()
        for p in trust_principals(doc):
            _trust_edge(snap, role, p, inside, from_org, trusted_by, classes)
        role.props["trusted_by"] = trusted_by
        role.props["trust_classes"] = sorted(classes)
        if "oidc-github" in classes:
            role.props["category"] = "ci"
    for acct, names in sorted(sso_roles.items()):
        ensure_account(snap, acct)
        snap.add(Node(f"{acct or UNKNOWN_ACCOUNT}/identity-center-roles", "sso-roles",
                      "Identity Center roles", parent=acct or UNKNOWN_ACCOUNT, account=acct,
                      props={"permission_sets": sorted(names)}, source="model"))


def _trust_edge(snap, role, p, inside, from_org, trusted_by, classes):
    acct = role.account
    conds = p["conds"]
    kind = "break-glass" if role.props.get("break_glass") else "trust"
    if p["type"] == "public":
        src = external_node(snap, "public:*", "public", "Anyone", source="model").id
        edge = snap.connect(src, role.id, kind, props={"class": "public"})
        if not conds:
            edge.flag("critical", "Principal * lets any AWS account assume this role")
        else:
            edge.flag("high", "Principal * with a condition. Check it really narrows who "
                              "can assume this role")
        trusted_by.append("anyone (Principal *)")
        classes.add("public")
    elif p["type"] == "service":
        classes.add("service")
        trusted_by.append(p["value"])
    elif p["type"] == "aws":
        other = p["account"]
        principal = p["value"]
        if other and other == acct:
            classes.add("same-account")
            trusted_by.append("this account")
            return
        if other in inside:
            classes.add("org")
            src_node = snap.get(principal) if snap.get(principal) is not None else None
            src = src_node.id if src_node is not None else ensure_account(snap, other).id
            snap.connect(src, role.id, kind, props={"class": "org", "principal": principal})
            other_node = snap.get(other)
            trusted_by.append(title_of(other_node) if other_node is not None else other)
            return
        classes.add("outside")
        if snap.get(other) is not None and snap.get(other).kind == "account":
            src = other
        else:
            src = external_node(snap, other or principal, "ext-account",
                                f"Account {other}" if other else principal,
                                source="model").id
        edge = snap.connect(src, role.id, kind, props={"class": "outside",
                                                       "principal": principal})
        where = "outside the organization" if from_org else "not one of your known accounts"
        sev = "medium" if "sts:externalid" in conds else "high"
        reason = f"Trusted by account {other or principal}, which is {where}"
        edge.flag(sev, reason)
        role.flag(sev, reason)
        trusted_by.append(f"account {other or principal} ({where})")
    elif p["type"] == "federated":
        _federated_edge(snap, role, p, trusted_by, classes)


def _federated_edge(snap, role, p, trusted_by, classes):
    value, stmt = p["value"], p["stmt"]
    kind = "break-glass" if role.props.get("break_glass") else "trust"
    if ":oidc-provider/" in value:
        host = value.split(":oidc-provider/", 1)[1]
        provider = snap.get(value) or add_oidc_provider(snap, value, host, source="model")
        github = "token.actions.githubusercontent.com" in host
        edge = snap.connect(provider.id, role.id, "oidc", props={"class": "oidc"})
        ext_kind = "github" if github else "idp"
        ext = external_node(snap, f"oidc:{host}", ext_kind,
                            "GitHub Actions" if github else host, source="model")
        snap.connect(ext.id, provider.id, "oidc", props={"class": "oidc"})
        if github:
            subs = iampolicy.condition_values(stmt, "token.actions.githubusercontent.com:sub")
            scopes = github_scopes(subs) if subs else ["any repo"]
            edge.props["scopes"] = scopes
            for repo in _any_branch(subs):
                reason = f"GitHub OIDC trust allows any branch of {repo}"
                edge.flag("medium", reason)
                role.flag("medium", reason)
            if not subs:
                edge.flag("critical", "GitHub OIDC trust without a repo check")
            if not iampolicy.condition_values(stmt, "token.actions.githubusercontent.com:aud"):
                edge.flag("low", "GitHub OIDC trust without an audience check")
            for f in role.flags:
                if "GitHub OIDC repo check is loose" in f["reason"]:
                    edge.flag(f["severity"], f["reason"])
            prev = set(ext.props.get("scopes", []))
            ext.props["scopes"] = sorted(prev | set(scopes))
            trusted_by.append("GitHub, " + "; ".join(scopes))
            classes.add("oidc-github")
        else:
            trusted_by.append(host)
            classes.add("oidc")
            if not p["conds"]:
                edge.flag("medium", f"{host} can assume this role with no conditions")
    elif ":saml-provider/" in value:
        name = value.split(":saml-provider/", 1)[1]
        if name.startswith("AWSSSO_"):
            classes.add("identity-center")
            trusted_by.append("IAM Identity Center")
            return
        provider = snap.get(value) or add_saml_provider(snap, value, source="model")
        snap.connect(provider.id, role.id, "saml", props={"class": "saml"})
        ext = external_node(snap, f"saml:{name}", "idp", name, source="model", protocol="SAML")
        snap.connect(ext.id, provider.id, "saml", props={"class": "saml"})
        trusted_by.append(f"SAML provider {name}")
        classes.add("saml")
    else:
        ext = external_node(snap, f"oidc:{value}", "idp", value, source="model")
        edge = snap.connect(ext.id, role.id, kind, props={"class": "oidc"})
        if not p["conds"]:
            edge.flag("medium", f"{value} can assume this role with no conditions")
        trusted_by.append(value)
        classes.add("oidc")


def _trails(snap):
    org = org_node(snap)
    members = [a for a in snap.of_kind("account") if a.props.get("in_org")]
    for trail in snap.of_kind("trail"):
        bucket = trail.props.get("bucket")
        if bucket:
            bid = f"arn:aws:s3:::{bucket}"
            b = snap.get(bid)
            if b is None:
                b = add_bucket(snap, bucket, trail.account, source="model", owner_assumed=True)
            names = set(b.props.get("trails", []))
            names.add(trail.name)
            b.props["trails"] = sorted(names)
            snap.connect(trail.id, bid, "log-delivery")
        if trail.props.get("org_trail") and org is not None:
            for acct in members:
                if acct.id != trail.account:
                    snap.connect(acct.id, trail.id, "log-delivery")


def _target_kind(snap, target) -> str:
    """target_type, or for a target known only by its Terraform address (from a plan,
    before it has an AWS ID), the kind of node it is."""
    kind = target_type(target)
    if kind:
        return kind
    node = snap.get(target)
    if node is not None and node.kind in ("igw", "eigw", "nat", "vgw", "endpoint", "tgw",
                                          "instance"):
        return node.kind
    return ""


def _route_target(snap, target, vpc_id):
    kind = _target_kind(snap, target)
    if kind in ("igw", "eigw", "nat", "vgw", "endpoint", "instance", "eni"):
        return target if snap.get(target) is not None else ""
    if kind == "tgw":
        for att in snap.of_kind("tgw-attachment"):
            if att.props.get("tgw") == target and att.parent == vpc_id:
                return att.id
        return target if snap.get(target) is not None else ""
    if kind == "peering":
        for e in snap.edges.values():
            if e.kind == "peering" and e.props.get("pcx") == target:
                return e.dst if e.src == vpc_id else e.src
    return ""


def _routes(snap):
    # Gateway endpoints add a prefix-list route to their route tables. A live scan sees
    # that route, but Terraform only lists it on the endpoint.
    for ep in snap.of_kind("endpoint"):
        if ep.props.get("type") != "Gateway":
            continue
        for rt_id in ep.props.get("route_tables", []):
            rt = snap.get(rt_id)
            if rt is not None and not any(r["target"] == ep.id for r in rt.props.get("routes", [])):
                add_route(snap, rt_id, "pl-" + _service_short(ep.props.get("service")), ep.id)
    tables = snap.of_kind("route-table")
    main = {}
    assoc = {}
    for rt in tables:
        if rt.props.get("main"):
            main.setdefault(rt.parent or rt.props.get("vpc"), rt)
        for s in rt.props.get("subnets", []):
            assoc.setdefault(s, rt)
    for subnet in snap.of_kind("subnet"):
        vpc_id = snap.vpc_of(subnet)
        rt = assoc.get(subnet.id) or main.get(vpc_id)
        if rt is None:
            if subnet.props.get("map_public_ip"):
                subnet.props["public"] = True
            continue
        subnet.props["route_table"] = rt.id
        routes = rt.props.get("routes", [])
        subnet.props["public"] = any(r["dest"] in WORLD and _target_kind(snap, r["target"]) == "igw"
                                     for r in routes)
        targets = {}
        for r in routes:
            tid = _route_target(snap, r["target"], vpc_id)
            if tid and tid != subnet.id:
                targets.setdefault(tid, set()).add(r["dest"])
        for tid, dests in sorted(targets.items()):
            if snap.get(tid).kind == "endpoint":
                short = _service_short(snap.get(tid).props.get("service"))
                dests = {f"{short.upper() if len(short) <= 4 else short} prefix list"
                         if str(d).startswith("pl-") else d for d in dests}
            label = ", ".join(sorted(dests, key=_dest_key))
            snap.connect(subnet.id, tid, "route", label=label, props={"route_table": rt.id})


def _service_short(service) -> str:
    service = str(service or "")
    return service.rsplit(".", 1)[-1] if service else "endpoint"


def _security_groups(snap):
    for sg in snap.of_kind("sg"):
        open_labels = []
        for r in sg.props.get("ingress", []):
            world = [c for c in r.get("cidrs", []) if c in WORLD]
            if world:
                sev, label = open_port_risk(r.get("protocol"), r.get("from"), r.get("to"))
                open_labels.append(label)
                if sev in ("critical", "high", "medium"):
                    sg.flag(sev, f"Open to the internet: {label} from {', '.join(world)}")
            for g in r.get("groups", []):
                if g != sg.id and snap.get(g) is not None:
                    edge = snap.connect(g, sg.id, "sg-reference")
                    ports = set(filter(None, edge.label.split(", ")))
                    ports.add(port_text(r.get("protocol"), r.get("from"), r.get("to")))
                    edge.label = ", ".join(sorted(ports))
        sg.props["open_to_internet"] = sorted(set(open_labels))


def _instances(snap):
    for inst in snap.of_kind("instance"):
        public = bool(inst.props.get("public_ip"))
        tokens = str(inst.props.get("imds_tokens") or "")
        if tokens == "optional" and inst.props.get("imds_endpoint") != "disabled":
            inst.flag("high" if public else "medium",
                      "IMDSv1 allowed: instance metadata answers without a token" +
                      (", and the instance has a public IP" if public else ""))
        if public:
            bad = [g for g in inst.props.get("security_groups", [])
                   if snap.get(g) is not None and snap.get(g).flags]
            if bad:
                inst.flag("high", "Public IP and a security group open to the internet (" +
                          ", ".join(bad) + ")")


def _assignments(snap):
    for edge in snap.edges.values():
        if edge.kind != "sso-assignment":
            continue
        names = []
        for arn in edge.props.get("permission_sets", []):
            ps = snap.get(arn)
            names.append(ps.name if ps is not None else arn.rsplit("/", 1)[-1])
            if ps is not None:
                accounts = set(ps.props.get("accounts", []))
                accounts.add(edge.dst)
                ps.props["accounts"] = sorted(accounts)
        edge.label = ", ".join(sorted(set(names)))
        if snap.get(edge.dst) is None:
            ensure_account(snap, edge.dst)


# =================================================================== captions

def _policy_note(policies) -> str:
    names = {str(p).rsplit("/", 1)[-1] for p in policies}
    if names & set(ADMIN_POLICIES):
        return "admin access"
    if names & set(READ_ONLY_POLICIES):
        return "read-only"
    if "PowerUserAccess" in names:
        return "power user"
    return ""


def _scp_text(scps) -> str:
    named = [s for s in scps if s != "FullAWSAccess"]
    return ("SCPs: " + ", ".join(named)) if named else ""


def _captions(snap):
    used_by = {}
    for e in snap.edges.values():
        if e.kind in ("oidc", "saml") and snap.get(e.dst) is not None and snap.get(e.dst).kind == "role":
            used_by.setdefault(e.src, set()).add(e.dst)
    assignments = {}
    for e in snap.edges.values():
        if e.kind == "sso-assignment":
            assignments.setdefault(e.src, set()).add(e.dst)
    attachments = {}
    for att in snap.of_kind("tgw-attachment"):
        attachments.setdefault(att.props.get("tgw"), []).append(att.id)

    for node in snap.nodes.values():
        if node.caption:
            continue
        p, k = node.props, node.kind
        cap = ""
        if k == "org":
            scps = p.get("scps", [])
            others = [s for s in scps if s != "FullAWSAccess"]
            if "FullAWSAccess" in scps and not others:
                cap = "FullAWSAccess on root"
            elif scps:
                cap = join_names(scps) + " on root"
        elif k == "ou":
            cap = _scp_text(p.get("scps", []))
        elif k == "account":
            if p.get("management"):
                cap = "Management account, SCPs don't apply here"
            elif p.get("stub"):
                cap = "Not in this input"
            else:
                cap = _scp_text(p.get("scps", []))
        elif k == "identity-center":
            sets = [n for n in snap.children(node.id) if n.kind == "permission-set"]
            n_assign = sum(1 for e in snap.edges.values() if e.kind == "sso-assignment")
            cap = plural(len(sets), "permission set")
            if n_assign:
                cap += ", " + plural(n_assign, "assignment")
        elif k == "permission-set":
            pols = [str(x).rsplit("/", 1)[-1] for x in p.get("policies", [])]
            parts = [join_names(pols, 2)] if pols else []
            if p.get("accounts"):
                parts.append(plural(len(p["accounts"]), "account"))
            cap = ", ".join(parts)
        elif k in ("user", "group"):
            n = len(assignments.get(node.id, ()))
            cap = f"Identity Center {k}" + (f", {plural(n, 'account')}" if n else "")
        elif k == "github":
            scopes = p.get("scopes", [])
            cap = scopes[0] if len(scopes) == 1 else (plural(len(scopes), "repo rule") if scopes else "")
        elif k == "idp":
            cap = p.get("protocol", "OIDC") + " identity provider"
        elif k == "ext-account":
            cap = "Outside AWS account"
        elif k == "public":
            cap = "Principal * in a trust policy"
        elif k == "role":
            if p.get("break_glass"):
                parts = [node.name]
            else:
                parts = []
                trusted = p.get("trusted_by", [])
                if trusted:
                    parts.append("trusted by " + join_names(trusted, 2))
            note = _policy_note(p.get("policies", []))
            if note:
                parts.append(note)
            cap = ", ".join(parts)
        elif k == "oidc-provider":
            n = len(used_by.get(node.id, ()))
            github = "githubusercontent" in node.name
            if github:
                p["title"] = "GitHub OIDC provider"
            parts = [] if github else ["OIDC provider"]
            if p.get("audiences"):
                parts.append("audience " + ", ".join(p["audiences"]))
            parts.append(f"used by {plural(n, 'role')}")
            cap = ", ".join(parts)
        elif k == "saml-provider":
            n = len(used_by.get(node.id, ()))
            cap = f"SAML provider, used by {plural(n, 'role')}"
        elif k == "sso-roles":
            cap = join_names(p.get("permission_sets", []))
        elif k == "trail":
            if p.get("org_trail"):
                cap = "Org trail, all accounts"
            elif p.get("multi_region"):
                cap = "Multi-region trail"
            else:
                cap = f"Single-region trail, {node.region}" if node.region else "Single-region trail"
        elif k == "bucket":
            if p.get("trails"):
                cap = "CloudTrail logs" + (", owner not checked" if p.get("owner_assumed") else "")
            else:
                cap = "S3 bucket"
        elif k == "cost":
            budgets = len(p.get("budgets", []))
            monitors = int(p.get("anomaly_monitors", 0))
            parts = [plural(budgets, "budget")] if budgets else []
            if monitors:
                parts.append("anomaly alerts")
            cap = ", ".join(parts) if parts else "No budgets or anomaly alerts"
        elif k == "vpc":
            cap = ", ".join(p.get("cidrs", []))
            if p.get("default"):
                cap = (cap + ", default VPC") if cap else "Default VPC"
            if p.get("stub"):
                cap = (cap + ", not in this input") if cap else "Not in this input"
        elif k == "subnet":
            parts = [p.get("cidr", "")]
            if p.get("public") is True:
                parts.append("public")
            elif p.get("public") is False:
                parts.append("private")
            parts.append(p.get("az", ""))
            cap = ", ".join(x for x in parts if x)
        elif k in ("igw", "eigw", "vgw"):
            cap = node.id if node.name else ""
        elif k == "nat":
            cap = ", ".join(x for x in ((p.get("connectivity") or "public") + " NAT",
                                        p.get("public_ip", "")) if x)
        elif k == "tgw":
            parts = []
            if p.get("asn"):
                parts.append(f"ASN {p['asn']}")
            parts.append(plural(len(attachments.get(node.id, [])), "attachment"))
            if p.get("owner") and node.account and p["owner"] != node.account:
                parts.append(f"shared from {p['owner']}")
            cap = ", ".join(parts)
        elif k == "tgw-attachment":
            tgw = snap.get(p.get("tgw"))
            cap = f"to {title_of(tgw) if tgw is not None else p.get('tgw', '')}"
        elif k == "endpoint":
            short = _service_short(p.get("service"))
            if not node.name:
                p["title"] = short.upper() if len(short) <= 4 else short
            etype = p.get("type", "Gateway")
            cap = f"{etype} endpoint"
            if etype == "Interface" and p.get("subnets"):
                cap += f", {plural(len(p['subnets']), 'subnet')}"
        elif k == "sg":
            if p.get("open_to_internet"):
                cap = join_names(p["open_to_internet"], 2) + " open to the internet"
            else:
                cap = plural(len(p.get("ingress", [])), "inbound rule")
        elif k == "nacl":
            cap = plural(len(p.get("subnets", [])), "subnet")
        elif k == "instance":
            cap = ", ".join(x for x in (p.get("type", ""), p.get("state", ""),
                                        p.get("private_ip", "")) if x)
        elif k == "lb":
            kind = str(p.get("type", "application")).capitalize()
            cap = ", ".join(x for x in (kind, p.get("scheme", "")) if x)
        elif k == "rds":
            cap = ", ".join(x for x in (" ".join(x for x in (p.get("engine", ""),
                                                             p.get("version", "")) if x),
                                        p.get("class", ""),
                                        "public" if p.get("public") else "") if x)
        elif k == "cgw":
            cap = ", ".join(x for x in (p.get("ip", ""), f"ASN {p['asn']}" if p.get("asn") else "") if x)
        elif k == "route-table":
            cap = plural(len(p.get("routes", [])), "route")
        node.caption = cap
