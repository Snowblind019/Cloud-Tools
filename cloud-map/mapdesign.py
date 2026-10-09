"""Cloud Map's designer: draw a network in draw.io with the AWS Kit Designer library, and
get Terraform for it. One way: the design is the source of truth, and the Terraform goes
into a folder the designer owns. No GTK.

A design is a .drawio file. Every library shape is a UserObject with awskit_type and the
settings it needs (edited with draw.io's Edit Data). Containment is the structure: a
subnet drawn inside a VPC belongs to it, a NAT gateway inside a public subnet lives in
that subnet. An arrow from one security group to another allows traffic from the first.
Route tables aren't drawn: they follow from the subnet types (see network()).

    read()      the design file, as shapes and arrows
    check()     problems, as errors and warnings, before anything is written
    network()   the Terraform inputs for each VPC, with the route tables worked out
    build()     the module and its example, into <design>-tf/
    layout()    the design as a Layout, so the viewer page can draw it with its problems
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .common import open_port_risk

DESIGN_SUFFIX = ".drawio"
MARKER = ".awskit-designer"
GENERATOR = "AWS Kit Cloud Map designer"
DEFAULT_REGION = "us-east-1"
SHAPE_TYPES = ("vpc", "subnet", "igw", "nat", "sg", "endpoint")
EDGE_TYPES = ("sg-rule",)
CONTAINERS = ("vpc", "subnet")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,47}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
GATEWAY_SERVICES = ("s3", "dynamodb")
WORLD = ("0.0.0.0/0", "::/0")

# The Availability Zone letters in each region, from AWS's list of zones (2026). Letters
# map to physical zones per account in the oldest regions, so this checks the letter
# exists, not which zone you get.
REGION_AZS = {
    "us-east-1": "abcdef", "us-east-2": "abc", "us-west-1": "abc", "us-west-2": "abcd",
    "ca-central-1": "abd", "ca-west-1": "abc", "mx-central-1": "abc", "af-south-1": "abc",
    "ap-east-1": "abc", "ap-east-2": "abc", "ap-northeast-1": "abcd", "ap-northeast-2": "abcd",
    "ap-northeast-3": "abc", "ap-south-1": "abc", "ap-south-2": "abc", "ap-southeast-1": "abc",
    "ap-southeast-2": "abc", "ap-southeast-3": "abc", "ap-southeast-4": "abc",
    "ap-southeast-5": "abc", "ap-southeast-6": "abc", "ap-southeast-7": "abc",
    "eu-central-1": "abc", "eu-central-2": "abc", "eu-north-1": "abc", "eu-south-1": "abc",
    "eu-south-2": "abc", "eu-west-1": "abc", "eu-west-2": "abcd", "eu-west-3": "abc",
    "il-central-1": "abc", "me-central-1": "abc", "me-south-1": "abc", "sa-east-1": "abc",
    "us-gov-east-1": "abc", "us-gov-west-1": "abc",
}

# Each shape's settings, with the defaults the library gives it. Edit Data shows these.
SETTINGS = {
    "vpc": (("name", "main"), ("cidr", "10.0.0.0/16"), ("dns_hostnames", "true")),
    "subnet": (("name", "public-a"), ("cidr", "10.0.1.0/24"), ("az", "a"), ("type", "public")),
    "igw": (("name", "igw"),),
    "nat": (("name", "nat-a"), ("mode", "per-az")),
    "sg": (("name", "web"), ("description", "Web servers"), ("ingress", "tcp 443 0.0.0.0/0"),
           ("egress", "all 0.0.0.0/0")),
    "endpoint": (("name", "s3"), ("kind", "gateway"), ("service", "s3"),
                 ("route_tables", "private"), ("security_groups", "")),
    "sg-rule": (("protocol", "tcp"), ("ports", "443"), ("description", "")),
}

TYPE_TITLES = {"vpc": "VPC", "subnet": "Subnet", "igw": "Internet gateway",
               "nat": "NAT gateway", "sg": "Security group", "endpoint": "VPC endpoint",
               "sg-rule": "Security group arrow"}


class DesignError(ValueError):
    pass


class BuildError(Exception):
    pass


@dataclass
class Shape:
    id: str
    type: str
    attrs: dict
    parent: str                      # the draw.io cell parent
    rect: tuple                      # absolute x, y, w, h on the page
    label: str = ""
    container: str = ""              # the design container it's in (a VPC or subnet)
    vpc: str = ""                    # the VPC it belongs to
    edge: bool = False
    source: str = ""
    target: str = ""
    points: list = field(default_factory=list)

    def get(self, key, default=""):
        v = self.attrs.get(key)
        return default if v is None else str(v).strip()

    @property
    def name(self) -> str:
        return self.get("name")

    def title(self, lower=False) -> str:
        what = TYPE_TITLES.get(self.type, self.type)
        if lower and what != "VPC":
            what = what[0].lower() + what[1:]
        if self.type == "endpoint":
            return f'{what} "{self.get("service") or self.name}"'
        return f'{what} "{self.name}"' if self.name else what


@dataclass
class Design:
    path: Path
    name: str
    region: str
    theme: str
    shapes: dict                     # id -> Shape, library shapes and arrows
    others: list                     # raw XML of everything else (notes, plain shapes)
    meta: dict
    sha256: str
    loose_edges: list = field(default_factory=list)   # plain arrows, for SG rules

    def of_type(self, kind) -> list:
        return sorted((s for s in self.shapes.values() if s.type == kind),
                      key=lambda s: (s.name, s.id))

    def in_vpc(self, vpc_id, kind) -> list:
        return [s for s in self.of_type(kind) if s.vpc == vpc_id]


@dataclass
class Problem:
    severity: str                    # error or warning
    message: str
    shape: str = ""                  # the shape it's about, if one

    def as_dict(self) -> dict:
        return {"severity": self.severity, "message": self.message, "shape": self.shape}


# =================================================================== reading

def _cells(text):
    from .maplayoutmem import _diagram_xml
    diagram, model = _diagram_xml(text)
    root = model.find("root")
    if root is None:
        raise DesignError("The design's page is empty.")
    out = []
    for el in root:
        if el.tag == "mxCell":
            cell = el
        elif el.tag in ("UserObject", "object"):
            cell = el.find("mxCell")
            if cell is None:
                continue
        else:
            continue
        out.append((el, cell))
    return diagram, out


def _geo(cell):
    g = cell.find("mxGeometry")
    if g is None:
        return None, [], None, None

    def num(v, d=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return d
    rect = (num(g.get("x")), num(g.get("y")), num(g.get("width"), 0), num(g.get("height"), 0))
    pts, src, dst = [], None, None
    arr = g.find("Array")
    if arr is not None:
        pts = [(num(p.get("x")), num(p.get("y"))) for p in arr.findall("mxPoint")]
    for p in g.findall("mxPoint"):
        if p.get("as") == "sourcePoint":
            src = (num(p.get("x")), num(p.get("y")))
        elif p.get("as") == "targetPoint":
            dst = (num(p.get("x")), num(p.get("y")))
    return rect, pts, src, dst


def label_text(value) -> str:
    text = re.sub(r"(?i)<br\s*/?>|</div>|</p>", " ", str(value or ""))
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def read(path, text=None) -> Design:
    path = Path(path)
    if text is None:
        from .maplayoutmem import MAX_DIAGRAM
        try:
            if path.stat().st_size > MAX_DIAGRAM:
                raise DesignError(f"{path.name} is too big to be a design.")
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DesignError(f"Couldn't read {path.name}: {exc}") from exc
    try:
        diagram, cells = _cells(text)
    except (ET.ParseError, ValueError) as exc:
        raise DesignError(f"{path.name} isn't a draw.io file: {exc}") from exc
    meta = {}
    shapes, others, loose = {}, [], []
    by_id = {}
    for el, cell in cells:
        cid = el.get("id") or ""
        if cid == "0":
            meta = {k: v for k, v in el.attrib.items() if k.startswith("awskit_")}
            continue
        by_id[cid] = (el, cell)
    layers = {cid for cid, (el, cell) in by_id.items() if cell.get("parent") == "0"}
    # absolute positions, following parents up to the layer
    absolute = {}

    def pos(cid, depth=0):
        if cid in absolute:
            return absolute[cid]
        if cid not in by_id or cid in layers or depth > 64:
            return (0.0, 0.0)
        el, cell = by_id[cid]
        rect, _, _, _ = _geo(cell)
        if rect is None or cell.get("vertex") != "1":
            return (0.0, 0.0)
        px, py = pos(cell.get("parent", ""), depth + 1)
        absolute[cid] = (px + rect[0], py + rect[1])
        return absolute[cid]

    for cid, (el, cell) in by_id.items():
        if cid in layers:
            continue
        kind = el.get("awskit_type", "") if el is not cell else ""
        rect, pts, src, dst = _geo(cell)
        parent = cell.get("parent", "")
        if el.get("awskit_part"):
            continue                              # an icon inside a library shape
        if cell.get("edge") == "1":
            ox, oy = pos(parent)
            shape = Shape(cid, kind or "", dict(el.attrib) if el is not cell else {}, parent,
                          (0, 0, 0, 0), el.get("label", "") if el is not cell else cell.get("value", ""),
                          edge=True, source=cell.get("source", ""), target=cell.get("target", ""),
                          points=[(ox + x, oy + y) for x, y in pts])
            if src:
                shape.attrs["_src"] = (ox + src[0], oy + src[1])
            if dst:
                shape.attrs["_dst"] = (ox + dst[0], oy + dst[1])
            if kind in EDGE_TYPES:
                shapes[cid] = shape
            else:
                loose.append(shape)
                others.append(ET.tostring(el, encoding="unicode"))
            continue
        if cell.get("vertex") != "1" or rect is None:
            continue
        ax, ay = pos(cid)
        if kind in SHAPE_TYPES or kind:
            shapes[cid] = Shape(cid, kind, dict(el.attrib), parent, (ax, ay, rect[2], rect[3]),
                                el.get("label", ""))
        else:
            others.append(ET.tostring(el, encoding="unicode"))
    design = Design(path, plain(meta.get("awskit_name", "")) or plain(_stem(path)),
                    meta.get("awskit_region", ""),
                    meta.get("awskit_theme", "dark"), shapes, others, meta,
                    hashlib.sha256(text.encode("utf-8")).hexdigest(), loose)
    _place(design)
    return design


def plain(text, limit=120) -> str:
    """Text from the design file (its name, the file name) for a comment or the README:
    one line, no control characters, so it can't start a new line of Terraform."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(text or ""))
    return " ".join(s.split())[:limit]


def _md(text) -> str:
    """plain() text that Markdown and HTML show as it is."""
    return re.sub(r"([\\`*_\[\]<>|#!&{}()~])", r"\\\1", plain(text))


def _code(text) -> str:
    """plain() text as Markdown inline code, which shows HTML and links as plain text."""
    return "`" + plain(text).replace("`", "'") + "`"


def _stem(path) -> str:
    name = Path(path).name
    return name[: -len(DESIGN_SUFFIX)] if name.endswith(DESIGN_SUFFIX) else Path(path).stem


def _inside(inner, outer, slack=0.0) -> bool:
    x, y, w, h = inner
    cx, cy = x + w / 2, y + h / 2
    ox, oy, ow, oh = outer
    return ox - slack <= cx <= ox + ow + slack and oy - slack <= cy <= oy + oh + slack


def _place(design):
    """Which container each shape is in: its draw.io parent when that's a VPC or subnet,
    otherwise the smallest one it sits inside (gateways can sit on a VPC's border)."""
    shapes = design.shapes
    containers = [s for s in shapes.values() if s.type in CONTAINERS and not s.edge]
    for s in shapes.values():
        if s.edge:
            continue
        p = shapes.get(s.parent)
        if p is not None and p.type in CONTAINERS:
            s.container = p.id
            continue
        slack = min(s.rect[2], s.rect[3]) / 2 if s.type == "igw" else 0
        best = None
        for c in containers:
            if c.id == s.id or not _inside(s.rect, c.rect, slack):
                continue
            if s.type in CONTAINERS and c.rect[2] * c.rect[3] <= s.rect[2] * s.rect[3]:
                continue
            if best is None or c.rect[2] * c.rect[3] < best.rect[2] * best.rect[3]:
                best = c
        s.container = best.id if best else ""
    for s in shapes.values():
        if s.edge:
            continue
        cur, seen = s, set()
        while cur is not None and cur.id not in seen:
            seen.add(cur.id)
            if cur.type == "vpc" and cur is not s:
                s.vpc = cur.id
                break
            cur = shapes.get(cur.container)
        if s.type == "vpc":
            s.vpc = s.id


# =================================================================== the settings

@dataclass
class Rule:
    protocol: str                    # tcp, udp, icmp or -1
    from_port: object = None
    to_port: object = None
    cidr: str = ""
    group: str = ""                  # the other security group's shape id, for arrows
    description: str = ""

    def ports_text(self) -> str:
        from .mapmodel import port_text
        return port_text(self.protocol, self.from_port, self.to_port)


PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "all": "-1", "-1": "-1",
             "any": "-1"}


def parse_ports(protocol, text):
    """(protocol, from, to) from a protocol and a ports text like 443, 8000-8080 or all.
    Raises ValueError with a message that says what's wrong."""
    proto = PROTOCOLS.get(str(protocol or "").strip().lower())
    if proto is None:
        raise ValueError(f"protocol {protocol or '(none)'} isn't one of tcp, udp, icmp or all")
    text = str(text or "").strip().lower()
    if proto == "-1":
        if text not in ("", "all", "-", "*"):
            raise ValueError("all traffic doesn't take ports")
        return proto, None, None
    if proto == "icmp":
        if text in ("", "all", "-", "*"):
            return proto, -1, -1
        m = re.fullmatch(r"(\d{1,3})(?:-(\d{1,3}))?", text)
        if not m:
            raise ValueError(f"ICMP takes a type and code like 8 or 8-0, not {text}")
        icmp_type, code = int(m.group(1)), int(m.group(2) or -1)
        if icmp_type > 255 or code > 255:
            raise ValueError(f"ICMP type and code go up to 255, not {text}")
        return proto, icmp_type, code
    if text in ("all", "*"):
        return proto, 0, 65535
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", text)
    if not m:
        raise ValueError(f"ports {text or '(none)'} should be a port like 443 or a range like 8000-8080")
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535) or lo > hi:
        raise ValueError(f"ports {text} have to be between 0 and 65535, low to high")
    return proto, lo, hi


def parse_rules(text) -> list:
    """Rules written as PROTOCOL PORTS CIDR, one per line or separated by semicolons, with
    an optional # description. all and icmp can leave out the ports: all 0.0.0.0/0."""
    out = []
    for raw in re.split(r"[;\n]", str(text or "")):
        raw = raw.strip()
        if not raw:
            continue
        desc = ""
        if "#" in raw:
            raw, desc = raw.split("#", 1)
            raw, desc = raw.strip(), desc.strip()
        parts = raw.split()
        if len(parts) == 2 and PROTOCOLS.get(parts[0].lower()) in ("-1", "icmp"):
            parts = [parts[0], "all", parts[1]]
        if len(parts) != 3:
            raise ValueError(f"\"{raw}\" should be PROTOCOL PORTS CIDR, like tcp 443 0.0.0.0/0")
        proto, lo, hi = parse_ports(parts[0], parts[1])
        try:
            net = ipaddress.ip_network(parts[2], strict=True)
        except ValueError:
            raise ValueError(f"{parts[2]} isn't a CIDR block, like 10.0.0.0/16") from None
        out.append(Rule(proto, lo, hi, str(net), "", desc))
    return out


# The characters AWS takes in a security group's description and a rule's description. Any
# other character (an apostrophe, an accented letter, a dash like –) passes terraform
# validate and plan, then fails at apply.
AWS_TEXT_CHARS = r"A-Za-z0-9 ._\-:/()#,@\[\]+=&;{}!$*"
AWS_TEXT_MAX = 255


def _aws_text_problem(text) -> str:
    """Why AWS would refuse text as a description, or "" when it's fine."""
    text = str(text or "")
    bad = sorted(set(re.sub(f"[{AWS_TEXT_CHARS}]", "", text)))
    if bad:
        shown = " ".join(ch if ch.isprintable() else f"U+{ord(ch):04X}" for ch in bad)
        return (f"AWS doesn't allow {shown} in it. Use letters, numbers, spaces and "
                "._-:/()#,@[]+=&;{}!$*")
    if len(text) > AWS_TEXT_MAX:
        return f"it's {len(text)} characters long, and AWS allows up to {AWS_TEXT_MAX}"
    return ""


def _aws_text(text) -> str:
    """text with the characters AWS refuses in a description left out."""
    return " ".join(re.sub(f"[^{AWS_TEXT_CHARS}]", "", str(text or "")).split())[:AWS_TEXT_MAX]


def _bool(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _az_letter(value, region):
    """The zone letter from a or us-west-2a. Raises ValueError."""
    v = str(value or "").strip().lower()
    if re.fullmatch(r"[a-z]", v):
        return v
    m = re.fullmatch(r"([a-z]{2}(?:-gov)?-[a-z]+-\d)([a-z])", v)
    if m:
        if region and m.group(1) != region:
            raise ValueError(f"zone {value} isn't in the design's region {region}")
        return m.group(2)
    raise ValueError(f"zone {value} should be a letter like a, or a zone like {region or 'us-west-2'}a")


# =================================================================== checking

def check(design, region=None) -> list:
    """Every problem, errors first. Nothing is written while there are errors."""
    problems, _ = analyze(design, region)
    return problems


def errors(problems) -> list:
    return [p for p in problems if p.severity == "error"]


def _net(text, what):
    try:
        net = ipaddress.ip_network(str(text or "").strip(), strict=True)
    except ValueError as exc:
        if "has host bits set" in str(exc):
            raise ValueError(f"{text} has host bits set. The network is "
                             f"{ipaddress.ip_network(str(text).strip(), strict=False)}") from None
        raise ValueError(f"{str(text or '').strip() or 'an empty value'} isn't a valid CIDR "
                         "block, like 10.0.0.0/16") from None
    if net.version != 4:
        raise ValueError(f"{text} has to be IPv4")
    if not 16 <= net.prefixlen <= 28:
        raise ValueError(f"{text} has to be between /16 and /28, the sizes AWS allows")
    return net


def _rule_key(sg, rule, direction, other="") -> str:
    ports = {"-1": "all", "icmp": "icmp"}.get(rule.protocol) if rule.protocol in ("-1", "icmp") \
        and rule.from_port in (None, -1) else None
    if ports is None:
        ports = f"{rule.protocol}-{rule.from_port}" + (
            f"-{rule.to_port}" if rule.to_port not in (None, rule.from_port, -1) else "")
    word = "from" if direction == "ingress" else "to"
    return f"{sg}-{ports}-{word}-{other or rule.cidr}"


def analyze(design, region=None):
    """(problems, {vpc name: Terraform inputs}). The inputs are only complete when there
    are no errors."""
    P = []

    def err(shape, msg):
        P.append(Problem("error", msg, shape.id if shape is not None else ""))

    def warn(shape, msg):
        P.append(Problem("warning", msg, shape.id if shape is not None else ""))

    region = (region or design.region or "").strip()
    zones = None
    if not region:
        err(None, "The design has no region. Give it one with --region, or set awskit_region "
                  "on the page (Edit Data on an empty spot of the diagram).")
    elif not REGION_RE.match(region):
        err(None, f"{region} isn't an AWS region name like us-west-2.")
    else:
        zones = REGION_AZS.get(region)
        if zones is None:
            warn(None, f"AWS Kit doesn't know the zones in {region}, so zone letters aren't checked.")

    shapes = design.shapes
    vpcs = design.of_type("vpc")
    if not vpcs:
        err(None, "There's no VPC in the design. Drag one in from the AWS Kit Designer library.")

    # ---- names
    for s in sorted(shapes.values(), key=lambda s: (s.type, s.name, s.id)):
        if s.edge:
            continue
        if s.type not in SHAPE_TYPES:
            warn(s, f"A shape with awskit_type {s.type!r} isn't one the designer builds, so it's left out.")
            continue
        if not s.name:
            err(s, f"{s.title()} has no name. Select it and press Ctrl+M (Edit Data) to set one.")
        elif not NAME_RE.match(s.name):
            err(s, f"{s.title()}: the name can only have letters, numbers, - and _, start with "
                   "a letter, and be up to 48 long, since it's used as a Terraform key.")
    seen = {}
    for s in shapes.values():
        if s.edge or s.type not in SHAPE_TYPES or not s.name:
            continue
        key = (s.type, s.name) if s.type == "vpc" else (s.type, s.vpc, s.name)
        if key in seen:
            err(s, f"Two {TYPE_TITLES[s.type].lower()}s are called \"{s.name}\""
                   + (" in the same VPC" if s.type != "vpc" else "") + ". Names have to be unique.")
        seen[key] = s

    out = {}
    for vpc in vpcs:
        m = {"vpc": {}, "internet_gateway": None, "subnets": {}, "nat_gateways": {},
             "route_tables": {}, "gateway_endpoints": {}, "interface_endpoints": {},
             "security_groups": {}, "ingress_rules": {}, "egress_rules": {}}
        out[vpc.name or vpc.id] = m
        try:
            vnet = _net(vpc.get("cidr"), "The CIDR")
        except ValueError as exc:
            err(vpc, f"{vpc.title()}: {exc}.")
            vnet = None
        dns = vpc.get("dns_hostnames", "true").lower()
        if dns not in ("true", "false", "1", "0", "yes", "no", "on", "off"):
            err(vpc, f"{vpc.title()}: dns_hostnames has to be true or false.")
        outer = shapes.get(vpc.container)
        if outer is not None:
            err(vpc, f"{vpc.title()} is drawn inside {outer.title(True)}. VPCs can't be nested.")
        m["vpc"] = {"name": vpc.name, "cidr": str(vnet) if vnet is not None else vpc.get("cidr"),
                    "enable_dns_hostnames": _bool(dns)}
        if vpc.get("dns_hostnames", "") == "":
            m["vpc"]["enable_dns_hostnames"] = True

        # ---- subnets
        subnets = design.in_vpc(vpc.id, "subnet")
        nets = []
        for sub in subnets:
            parent = shapes.get(sub.container)
            if parent is not None and parent.type == "subnet":
                err(sub, f"{sub.title()} is drawn inside {parent.title(True)}. Subnets go straight in a VPC.")
            info = {"cidr": sub.get("cidr"), "az": "", "public": False, "route_table": ""}
            try:
                net = _net(sub.get("cidr"), "The CIDR")
                info["cidr"] = str(net)
                if vnet is not None and not net.subnet_of(vnet):
                    err(sub, f"{sub.title()}: {net} isn't inside its VPC's {vnet}.")
                for other, onet in nets:
                    if net.overlaps(onet):
                        err(sub, f"{sub.title()}: {net} overlaps {other.title(True)} ({onet}).")
                nets.append((sub, net))
            except ValueError as exc:
                err(sub, f"{sub.title()}: {exc}.")
            az = sub.get("az")
            if not az:
                err(sub, f"{sub.title()} has no availability zone. Set az to a letter like a.")
            else:
                try:
                    letter = _az_letter(az, region if zones is not None or REGION_RE.match(region or "") else "")
                    info["az"] = letter
                    if zones is not None and letter not in zones:
                        err(sub, f"{sub.title()}: {region} has no zone {region}{letter}. It has "
                                 + ", ".join(f"{region}{z}" for z in zones) + ".")
                except ValueError as exc:
                    err(sub, f"{sub.title()}: {exc}.")
            kind = sub.get("type", "").lower()
            if kind not in ("public", "private"):
                err(sub, f"{sub.title()}: type has to be public or private.")
            info["public"] = kind == "public"
            m["subnets"][sub.name] = info
        for s in shapes.values():
            if s.type == "subnet" and not s.edge and not s.vpc:
                if not any(p.shape == s.id and "inside a VPC" in p.message for p in P):
                    err(s, f"{s.title()} isn't inside a VPC. Draw it inside one.")
        if not subnets:
            warn(vpc, f"{vpc.title()} has no subnets.")
        elif not any(not i["public"] for i in m["subnets"].values()):
            warn(vpc, f"{vpc.title()} has no private subnets, so there's nowhere to put things "
                      "that shouldn't be reachable from the internet.")

        # ---- internet gateway
        igws = design.in_vpc(vpc.id, "igw")
        if len(igws) > 1:
            for g in igws[1:]:
                err(g, f"{vpc.title()} has more than one internet gateway. A VPC can only have one.")
        if igws:
            m["internet_gateway"] = igws[0].name
        if any(i["public"] for i in m["subnets"].values()) and not igws:
            for sub in subnets:
                if sub.get("type").lower() == "public":
                    err(sub, f"{sub.title()} is public, but {vpc.title()} has no internet "
                             "gateway. Put one on the VPC's border.")

        # ---- NAT gateways
        nats = design.in_vpc(vpc.id, "nat")
        by_az, singles = {}, []
        for n in nats:
            sub = shapes.get(n.container)
            mode = n.get("mode", "per-az").lower()
            if mode not in ("per-az", "single"):
                err(n, f"{n.title()}: mode has to be per-az or single.")
            if sub is None or sub.type != "subnet":
                err(n, f"{n.title()} has to sit in a public subnet.")
                continue
            if sub.get("type").lower() != "public":
                err(n, f"{n.title()} sits in {sub.title(True)}, which is private. NAT gateways go "
                       "in public subnets.")
                continue
            m["nat_gateways"][n.name] = {"subnet": sub.name}
            az = m["subnets"].get(sub.name, {}).get("az", "")
            by_az.setdefault(az, []).append(n)
            if mode == "single":
                singles.append(n)
        if len(singles) > 1:
            for n in singles[1:]:
                err(n, f"{vpc.title()} has more than one NAT gateway set to single. Only one "
                       "can be shared by every zone.")
        shared = {}
        for sub in subnets:
            info = m["subnets"].get(sub.name)
            if info is None or info["public"]:
                if info is not None and info["public"] and igws:
                    info["route_table"] = "public"
                continue
            nat = (by_az.get(info["az"]) or [None])[0] or (singles[0] if singles else None)
            zone_ok = bool(info["az"]) and (zones is None or info["az"] in zones)
            if nat is None:
                if nats and zone_ok:
                    err(sub, f"{sub.title()} is in zone {info['az']}, which has no NAT gateway "
                             "to route through. Draw one in a public subnet in that zone, or "
                             "set a NAT gateway's mode to single to share it.")
                info["route_table"] = "private"
                m["route_tables"].setdefault("private", {})
                continue
            nat_az = m["subnets"].get(m["nat_gateways"].get(nat.name, {}).get("subnet", ""), {}).get("az", "")
            if nat.get("mode", "per-az").lower() == "single":
                table = "private"
            else:
                table = f"private-{nat_az}" if nat_az else "private"
            info["route_table"] = table
            m["route_tables"][table] = {"nat_gateway": nat.name}
            if nat_az != info["az"]:
                shared.setdefault(nat.id, set()).update({nat_az, info["az"]})
        for nid, azs in shared.items():
            n = shapes[nid]
            warn(n, f"{n.title()} is shared by private subnets in zones {', '.join(sorted(azs))}. "
                    "It's cheaper, but not highly available: if its zone goes down, the others "
                    "lose their internet route too.")
        if any(i["public"] for i in m["subnets"].values()) and igws:
            m["route_tables"]["public"] = {"internet_gateway": True}

        # ---- security groups
        sgs = design.in_vpc(vpc.id, "sg")
        for g in sgs:
            why = _aws_text_problem(g.get("description"))
            if why:
                err(g, f"{g.title()}: the description won't work, {why}.")
            m["security_groups"][g.name] = {"description": g.get("description") or
                                            _aws_text(f"{g.name}, from the {design.name} design")}
            for direction in ("ingress", "egress"):
                try:
                    rules = parse_rules(g.get(direction))
                except ValueError as exc:
                    err(g, f"{g.title()}, {direction}: {exc}.")
                    continue
                for rule in rules:
                    why = _aws_text_problem(rule.description)
                    if why:
                        err(g, f"{g.title()}, {direction}: the description of {rule.ports_text()} "
                               f"{rule.cidr} won't work, {why}.")
                    key = _rule_key(g.name, rule, direction)
                    target = m["ingress_rules" if direction == "ingress" else "egress_rules"]
                    new = _rule_dict(g.name, rule)
                    if key in target and target[key] != new:
                        err(g, f"{g.title()}: two {direction} rules would both be named {key}. "
                               "Rename a security group so the names differ.")
                    elif key in target:
                        warn(g, f"{g.title()} lists the {direction} rule "
                                f"{rule.ports_text()} {rule.cidr} twice.")
                    target[key] = new
                    if direction == "ingress" and rule.cidr in WORLD:
                        sev, what = open_port_risk(rule.protocol, rule.from_port, rule.to_port)
                        if sev in ("critical", "high"):
                            warn(g, f"{g.title()} allows {rule.ports_text()} from {rule.cidr}, the "
                                    f"whole internet ({what}).")
        for s in shapes.values():
            if s.type in ("sg", "nat", "igw", "endpoint") and not s.edge and not s.vpc:
                if not any(p.shape == s.id for p in P if "inside a VPC" in p.message or
                           "public subnet" in p.message):
                    err(s, f"{s.title()} isn't inside a VPC. Draw it inside one"
                           + (" (on its border is fine)." if s.type == "igw" else "."))

        # ---- VPC endpoints
        for ep in design.in_vpc(vpc.id, "endpoint"):
            kind = ep.get("kind", "gateway").lower()
            service = ep.get("service").lower()
            key = ep.name or service
            if kind == "gateway":
                if service not in GATEWAY_SERVICES:
                    err(ep, f"{ep.title()}: gateway endpoints are only for s3 and dynamodb. "
                            "Set kind to interface for other services.")
                    continue
                which = ep.get("route_tables", "private").lower() or "private"
                if which not in ("private", "public", "all"):
                    err(ep, f"{ep.title()}: route_tables has to be private, public or all.")
                    continue
                tables = sorted(t for t in m["route_tables"]
                                if which == "all" or (which == "public") == (t == "public"))
                if not tables:
                    err(ep, f"{ep.title()} goes in the {which} route tables, but {vpc.title()} "
                            "has none. Add a subnet of that type, or change route_tables.")
                    continue
                m["gateway_endpoints"][key] = {"service": service, "route_tables": tables}
            elif kind == "interface":
                if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", service or ""):
                    err(ep, f"{ep.title()}: service should be a short name like ssm or ecr.api.")
                    continue
                parent = shapes.get(ep.container)
                if parent is not None and parent.type == "subnet":
                    subs = [parent.name]
                else:
                    first = {}
                    for sub in sorted(subnets, key=lambda s: s.name):
                        info = m["subnets"].get(sub.name)
                        if info and not info["public"]:
                            first.setdefault(info["az"], sub.name)
                    subs = [first[a] for a in sorted(first)]
                if not subs:
                    err(ep, f"{ep.title()} needs a subnet: draw it in one, or add private subnets "
                            f"to {vpc.title()}.")
                    continue
                groups = [g.strip() for g in ep.get("security_groups").split(",") if g.strip()]
                missing = [g for g in groups if g not in m["security_groups"]]
                if missing:
                    err(ep, f"{ep.title()}: there's no security group called "
                            + ", ".join(repr(g) for g in missing) + " in its VPC.")
                    continue
                m["interface_endpoints"][key] = {"service": service, "subnets": subs,
                                                 "security_groups": groups}
            else:
                err(ep, f"{ep.title()}: kind has to be gateway or interface.")

    # ---- arrows between security groups
    vpc_name = {v.id: v.name or v.id for v in vpcs}
    arrows = [s for s in shapes.values() if s.edge and s.type == "sg-rule"]
    arrows += [s for s in design.loose_edges
               if getattr(shapes.get(s.source), "type", "") == "sg" and
               getattr(shapes.get(s.target), "type", "") == "sg"]
    for a in arrows:
        src, dst = shapes.get(a.source), shapes.get(a.target)
        if src is None or dst is None:
            err(a, "A security group arrow has to connect two security groups. This one "
                   "isn't attached at both ends.")
            continue
        if src.type != "sg" or dst.type != "sg":
            err(a, f"The security group arrow from {src.title(True)} to {dst.title(True)} has to "
                   "connect two security groups.")
            continue
        if src.vpc != dst.vpc:
            err(a, f"The arrow from {src.title(True)} to {dst.title(True)} crosses VPCs. Security "
                   "group arrows have to stay in one VPC.")
            continue
        proto, ports = a.get("protocol"), a.get("ports")
        if not a.type:
            text = label_text(a.label).split()
            if len(text) >= 1:
                proto, ports = text[0], (text[1] if len(text) > 1 else "")
        if not proto:
            err(a, f"The arrow from {src.title(True)} to {dst.title(True)} needs a protocol and ports. "
                   "Select it and press Ctrl+M (Edit Data), or label it like tcp 443.")
            continue
        try:
            p, lo, hi = parse_ports(proto, ports)
        except ValueError as exc:
            err(a, f"The arrow from {src.title(True)} to {dst.title(True)}: {exc}.")
            continue
        why = _aws_text_problem(a.get("description"))
        if why:
            err(a, f"The arrow from {src.title(True)} to {dst.title(True)}: the description "
                   f"won't work, {why}.")
            continue
        m = out.get(vpc_name.get(dst.vpc, ""))
        if m is None:
            continue
        rule = Rule(p, lo, hi, "", src.name, a.get("description"))
        key, new = _rule_key(dst.name, rule, "ingress", src.name), _rule_dict(dst.name, rule)
        if key in m["ingress_rules"] and m["ingress_rules"][key] != new:
            err(a, f"The arrow from {src.title(True)} to {dst.title(True)} would get the rule name "
                   f"{key}, which another rule already has. Rename a security group so the names differ.")
            continue
        m["ingress_rules"][key] = new

    for m in out.values():
        for k in ("subnets", "nat_gateways", "route_tables", "gateway_endpoints",
                  "interface_endpoints", "security_groups", "ingress_rules", "egress_rules"):
            m[k] = dict(sorted(m[k].items()))
    order = {"error": 0, "warning": 1}
    P.sort(key=lambda p: order.get(p.severity, 2))
    return P, out


def _rule_dict(sg, rule) -> dict:
    out = {"security_group": sg, "protocol": rule.protocol}
    if rule.from_port is not None:
        out["from_port"] = rule.from_port
        out["to_port"] = rule.to_port if rule.to_port is not None else rule.from_port
    if rule.cidr:
        out["cidr_ipv6" if ":" in rule.cidr else "cidr_ipv4"] = rule.cidr
    if rule.group:
        out["referenced_security_group"] = rule.group
    if rule.description:
        out["description"] = rule.description
    return out


def network(design, region=None) -> dict:
    """The Terraform inputs for each VPC. Raises DesignError when the design has errors."""
    problems, out = analyze(design, region)
    bad = errors(problems)
    if bad:
        raise DesignError("The design has problems:\n" + "\n".join(f"- {p.message}" for p in bad))
    return out


# =================================================================== HCL

_BARE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


_HCL_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def hcl_string(text) -> str:
    """A quoted HCL string. Only escapes HCL knows are used (it has no \\b or \\f), and
    ${ and %{ are doubled so nothing in a name or description is read as a template."""
    out = []
    for ch in str(text):
        if ch in _HCL_ESCAPES:
            out.append(_HCL_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F or ch in "\u2028\u2029":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return ('"' + "".join(out) + '"').replace("${", "$${").replace("%{", "%%{")


def hcl_key(key) -> str:
    return key if _BARE.match(str(key)) else hcl_string(key)


def hcl_value(v, indent=0) -> str:
    """A value as HCL, formatted the way terraform fmt leaves it."""
    pad = " " * indent
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return hcl_string(v)
    if isinstance(v, (list, tuple)):
        if all(not isinstance(x, (dict, list, tuple)) for x in v):
            return "[" + ", ".join(hcl_value(x) for x in v) + "]"
        inner = ",\n".join(" " * (indent + 2) + hcl_value(x, indent + 2) for x in v)
        return "[\n" + inner + ",\n" + pad + "]"
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{\n" + hcl_body(list(v.items()), indent + 2) + "\n" + pad + "}"
    raise TypeError(f"Can't write {type(v).__name__} as HCL")


def hcl_body(entries, indent) -> str:
    """key = value lines. Runs of one-line values get their = lined up, like fmt does."""
    pad = " " * indent
    rendered = [(hcl_key(k), hcl_value(v, indent)) for k, v in entries]
    out, run = [], []

    def flush():
        width = max((len(k) for k, _ in run), default=0)
        out.extend(f"{pad}{k.ljust(width)} = {v}" for k, v in run)
        run.clear()
    for k, v in rendered:
        if "\n" in v:
            flush()
            out.append(f"{pad}{k} = {v}")
        else:
            run.append((k, v))
    flush()
    return "\n".join(out)


# =================================================================== Terraform files

def _header(design_name, comment="#") -> str:
    design_name = plain(design_name)
    return (f"{comment} Generated by AWS Kit Cloud Map from the design {design_name}.\n"
            f"{comment} Edits here are overwritten the next time the design is built. "
            "Change the design instead.\n")


TF_VERSIONS = '''terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}
'''

TF_VARIABLES = '''variable "name_prefix" {
  description = "Goes in front of every Name tag and security group name."
  type        = string
}

variable "tags" {
  description = "Tags for every resource, on top of its Name tag."
  type        = map(string)
  default     = {}
}

variable "vpc" {
  description = "The VPC: its name, CIDR block, and whether instances get DNS hostnames."
  type = object({
    name                 = string
    cidr                 = string
    enable_dns_hostnames = optional(bool, true)
  })
}

variable "internet_gateway" {
  description = "The internet gateway's name, or null for none."
  type        = string
  default     = null
}

variable "subnets" {
  description = "Subnets by name. az is the zone letter, like a. route_table is a key of route_tables."
  type = map(object({
    cidr        = string
    az          = string
    public      = bool
    route_table = string
  }))
  default = {}
}

variable "nat_gateways" {
  description = "NAT gateways by name, each in a public subnet, with an Elastic IP."
  type = map(object({
    subnet = string
  }))
  default = {}
}

variable "route_tables" {
  description = "Route tables by name. Public ones route 0.0.0.0/0 to the internet gateway, private ones to a NAT gateway."
  type = map(object({
    internet_gateway = optional(bool, false)
    nat_gateway      = optional(string)
  }))
  default = {}
}

variable "gateway_endpoints" {
  description = "Gateway endpoints (s3, dynamodb) by name, and the route tables they're added to."
  type = map(object({
    service      = string
    route_tables = list(string)
  }))
  default = {}
}

variable "interface_endpoints" {
  description = "Interface endpoints by name, with their subnets and security groups."
  type = map(object({
    service         = string
    subnets         = list(string)
    security_groups = optional(list(string), [])
  }))
  default = {}
}

variable "security_groups" {
  description = "Security groups by name."
  type = map(object({
    description = string
  }))
  default = {}
}

variable "ingress_rules" {
  description = "Inbound rules by name. Each allows a CIDR block or another of these security groups."
  type = map(object({
    security_group            = string
    protocol                  = string
    from_port                 = optional(number)
    to_port                   = optional(number)
    cidr_ipv4                 = optional(string)
    cidr_ipv6                 = optional(string)
    referenced_security_group = optional(string)
    description               = optional(string)
  }))
  default = {}
}

variable "egress_rules" {
  description = "Outbound rules by name, the same way as ingress_rules."
  type = map(object({
    security_group            = string
    protocol                  = string
    from_port                 = optional(number)
    to_port                   = optional(number)
    cidr_ipv4                 = optional(string)
    cidr_ipv6                 = optional(string)
    referenced_security_group = optional(string)
    description               = optional(string)
  }))
  default = {}
}
'''

TF_MAIN = '''data "aws_region" "current" {}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc.cidr
  enable_dns_support   = true
  enable_dns_hostnames = var.vpc.enable_dns_hostnames

  tags = merge(var.tags, { Name = "${var.name_prefix}-${var.vpc.name}" })
}

resource "aws_internet_gateway" "this" {
  for_each = var.internet_gateway == null ? {} : { (var.internet_gateway) = true }

  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_subnet" "this" {
  for_each = var.subnets

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value.cidr
  availability_zone = "${data.aws_region.current.region}${each.value.az}"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-${each.key}"
    Tier = each.value.public ? "public" : "private"
  })
}

resource "aws_eip" "nat" {
  for_each = var.nat_gateways

  domain = "vpc"

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  for_each = var.nat_gateways

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.this[each.value.subnet].id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "this" {
  for_each = var.route_tables

  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_route" "internet" {
  for_each = { for name, table in var.route_tables : name => table if table.internet_gateway }

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[var.internet_gateway].id
}

resource "aws_route" "nat" {
  for_each = { for name, table in var.route_tables : name => table if table.nat_gateway != null }

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.value.nat_gateway].id
}

resource "aws_route_table_association" "this" {
  for_each = var.subnets

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.this[each.value.route_table].id
}

resource "aws_vpc_endpoint" "gateway" {
  for_each = var.gateway_endpoints

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.${each.value.service}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for name in each.value.route_tables : aws_route_table.this[name].id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each = var.interface_endpoints

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value.service}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for name in each.value.subnets : aws_subnet.this[name].id]
  security_group_ids  = [for name in each.value.security_groups : aws_security_group.this[name].id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}
'''

TF_SECURITY = '''resource "aws_security_group" "this" {
  for_each = var.security_groups

  name        = "${var.name_prefix}-${each.key}"
  description = each.value.description
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = var.ingress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  description                  = each.value.description
  ip_protocol                  = each.value.protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  referenced_security_group_id = each.value.referenced_security_group == null ? null : aws_security_group.this[each.value.referenced_security_group].id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = var.egress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  description                  = each.value.description
  ip_protocol                  = each.value.protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  referenced_security_group_id = each.value.referenced_security_group == null ? null : aws_security_group.this[each.value.referenced_security_group].id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}
'''

TF_OUTPUTS = '''output "vpc_id" {
  description = "The VPC's ID."
  value       = aws_vpc.this.id
}

output "subnet_ids" {
  description = "Subnet IDs by name."
  value       = { for name, subnet in aws_subnet.this : name => subnet.id }
}

output "route_table_ids" {
  description = "Route table IDs by name."
  value       = { for name, table in aws_route_table.this : name => table.id }
}

output "internet_gateway_id" {
  description = "The internet gateway's ID, or null."
  value       = one([for gateway in aws_internet_gateway.this : gateway.id])
}

output "nat_gateway_ids" {
  description = "NAT gateway IDs by name."
  value       = { for name, nat in aws_nat_gateway.this : name => nat.id }
}

output "security_group_ids" {
  description = "Security group IDs by name."
  value       = { for name, group in aws_security_group.this : name => group.id }
}

output "endpoint_ids" {
  description = "VPC endpoint IDs by name."
  value = merge(
    { for name, endpoint in aws_vpc_endpoint.gateway : name => endpoint.id },
    { for name, endpoint in aws_vpc_endpoint.interface : name => endpoint.id },
  )
}
'''


def name_prefix_of(name) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", str(name).lower()).strip("-")
    if not slug or not slug[0].isalpha():
        slug = "design-" + slug if slug else "design"
    if slug.startswith("sg-"):
        slug = "net-" + slug
    return slug[:32].rstrip("-")


def _module_args(m) -> list:
    """A VPC's inputs, leaving out what's empty so the example stays short."""
    order = ("vpc", "internet_gateway", "subnets", "nat_gateways", "route_tables",
             "gateway_endpoints", "interface_endpoints", "security_groups", "ingress_rules",
             "egress_rules")
    return [(k, m[k]) for k in order if m.get(k) not in (None, {}, [])]


def files(design, region=None) -> dict:
    """{relative path: text} for everything build() writes."""
    nets = network(design, region)
    region = (region or design.region).strip()
    dname = design.path.name
    head = _header(dname)
    out = {
        "versions.tf": head + "\n" + TF_VERSIONS,
        "variables.tf": head + "\n" + TF_VARIABLES,
        "main.tf": head + "\n" + TF_MAIN,
        "security.tf": head + "\n" + TF_SECURITY,
        "outputs.tf": head + "\n" + TF_OUTPUTS,
    }
    blocks = []
    outputs = []
    for vpc_name, m in nets.items():
        args = [("source", "../.."), None, ("name_prefix", "var.name_prefix"), ("tags", "var.tags"),
                None] + _module_args(m)
        lines, run = [], []
        for item in args:
            if item is None:
                if run:
                    lines.append(hcl_body(run, 2))
                    run = []
                continue
            run.append(item)
        if run:
            lines.append(hcl_body(run, 2))
        body = "\n\n".join(lines)
        body = body.replace('name_prefix = "var.name_prefix"', "name_prefix = var.name_prefix")
        body = body.replace('tags        = "var.tags"', "tags        = var.tags")
        blocks.append(f'module {hcl_string(vpc_name)} {{\n{body}\n}}\n')
        outputs.append(f'output {hcl_string(vpc_name)} {{\n'
                       f'  description = "The {vpc_name} VPC\'s IDs."\n'
                       f'  value = {{\n'
                       f'    vpc_id             = module.{vpc_name}.vpc_id\n'
                       f'    subnet_ids         = module.{vpc_name}.subnet_ids\n'
                       f'    security_group_ids = module.{vpc_name}.security_group_ids\n'
                       f'  }}\n}}\n')
    out["examples/basic/main.tf"] = (head + "\n" + TF_VERSIONS + "\n" +
                                     'provider "aws" {\n  region = var.region\n}\n\n' +
                                     "\n".join(blocks))
    out["examples/basic/variables.tf"] = head + "\n" + (
        'variable "region" {\n'
        '  description = "The region to build in. The design was drawn for the one in terraform.tfvars."\n'
        '  type        = string\n}\n\n'
        'variable "name_prefix" {\n'
        '  description = "Goes in front of every Name tag and security group name."\n'
        '  type        = string\n'
        f'  default     = {hcl_string(name_prefix_of(design.name))}\n}}\n\n'
        'variable "tags" {\n'
        '  description = "Tags for every resource."\n'
        '  type        = map(string)\n'
        '  default = {\n'
        f'    Design    = {hcl_string(dname)}\n'
        '    ManagedBy = "terraform"\n'
        '  }\n}\n')
    out["examples/basic/terraform.tfvars"] = head + "\n" + f"region = {hcl_string(region)}\n"
    out["examples/basic/outputs.tf"] = head + "\n" + "\n".join(outputs)
    out["README.md"] = readme(design, nets, region)
    return out


def readme(design, nets, region) -> str:
    dname = design.path.name
    rows = []
    for vpc_name, m in nets.items():
        subs = m["subnets"]
        pub = sorted(k for k, v in subs.items() if v["public"])
        priv = sorted(k for k, v in subs.items() if not v["public"])
        rows.append(f"| `{vpc_name}` | {m['vpc']['cidr']} | {', '.join(pub) or '-'} | "
                    f"{', '.join(priv) or '-'} | {', '.join(sorted(m['nat_gateways'])) or '-'} | "
                    f"{', '.join(sorted(m['security_groups'])) or '-'} | "
                    f"{', '.join(sorted(list(m['gateway_endpoints']) + list(m['interface_endpoints']))) or '-'} |")
    comment = re.sub(r"-{2,}", "-", _header(dname, "").strip())
    return (f"<!-- {comment} -->\n\n"
            f"# {_md(design.name)}\n\n"
            f"Terraform for the network in the design {_code(dname)}, drawn for {region}. Generated by "
            "AWS Kit's Cloud Map designer. It's a starting point: read it, plan it, and change "
            "the design (not these files) when you want something different, then build again.\n\n"
            "| VPC | CIDR | Public subnets | Private subnets | NAT gateways | Security groups | Endpoints |\n"
            "|---|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
            "## What's here\n\n"
            "| File | What it is |\n|---|---|\n"
            "| `main.tf` | The VPC, subnets, internet and NAT gateways, route tables, routes and endpoints |\n"
            "| `security.tf` | Security groups, and a rule resource for each rule |\n"
            "| `variables.tf` | The module's inputs. Everything is a map keyed by name, so adding a subnet doesn't move the others |\n"
            "| `outputs.tf` | IDs by name |\n"
            "| `versions.tf` | Terraform 1.6 or OpenTofu 1.6 and newer, AWS provider 6 and newer |\n"
            "| `examples/basic/` | A root module that calls this one once per VPC, with the design's settings |\n\n"
            "Route tables aren't drawn in the design. Public subnets share one that routes "
            "0.0.0.0/0 to the internet gateway. Private subnets route to the NAT gateway in "
            "their zone, or to the one set to single, and gateway endpoints are added to the "
            "route tables they name.\n\n"
            "## Using it\n\n"
            "```bash\ncd examples/basic\nterraform init\nterraform plan\n```\n\n"
            "The region is in `examples/basic/terraform.tfvars`. Nothing in the module names an "
            "account or a region. AWS Kit never runs apply. After you apply it, scan it with "
            "Cloud Map (`awskit map tf examples/basic`) to see what's really there.\n\n"
            f"`.awskit-designer` marks this folder as the designer's. Building {_code(dname)} again "
            "rewrites the files listed in it, removes the ones the design no longer makes if "
            "they're unchanged, and leaves anything else here alone, like `.terraform/` and "
            "state files.\n")


# =================================================================== building

@dataclass
class BuildResult:
    folder: Path
    files: list
    removed: list
    problems: list
    formatted: str = ""              # what fmt said, or why it didn't run
    checks: list = field(default_factory=list)   # (command, ok, output) from init and validate


def default_folder(design) -> Path:
    return design.path.with_name(f"{_stem(design.path)}-tf")


def read_marker(folder) -> dict:
    try:
        data = json.loads((Path(folder) / MARKER).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data.get("generator") == GENERATOR else {}
    except (OSError, ValueError):
        return {}


def check_folder(folder) -> dict:
    """The folder's marker when the designer may write there: it's missing, empty, or
    has the marker. Raises BuildError for anything else."""
    folder = Path(folder)
    if folder.is_symlink():
        raise BuildError(f"{folder} is a link. Build into a real folder.")
    if not folder.exists():
        return {}
    if not folder.is_dir():
        raise BuildError(f"{folder} is a file, not a folder.")
    marker = folder / MARKER
    if marker.exists():
        got = read_marker(folder)
        if not got:
            raise BuildError(f"{marker} isn't one the designer wrote, so {folder} is left alone.")
        return got
    if any(folder.iterdir()):
        raise BuildError(f"{folder} isn't empty and wasn't made by the designer, so nothing was "
                         "written. Pick an empty folder, or a new one.")
    return {}


def _inside_folder(folder: Path, rel: str) -> Path:
    from pathlib import PurePosixPath, PureWindowsPath
    if not isinstance(rel, str) or not rel or "\0" in rel or ":" in rel:
        raise BuildError(f"{rel!r} isn't a path inside the folder.")
    parts = PurePosixPath(rel.replace("\\", "/")).parts
    if (rel.startswith(("/", "\\")) or PureWindowsPath(rel).drive or PureWindowsPath(rel).anchor
            or any(p in ("", ".", "..") for p in parts)):
        raise BuildError(f"{rel} isn't a path inside the folder.")
    path = folder.joinpath(*parts)
    real = folder.resolve()
    cur = path
    for _ in parts:                  # path itself and each folder above it, up to folder
        if cur.is_symlink():
            raise BuildError(f"{cur} is a link, so the designer won't write through it.")
        cur = cur.parent
    if real not in path.resolve().parents:
        raise BuildError(f"{rel} would land outside {folder}.")
    return path


def _sha256_file(path: Path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _marker_files(marker) -> dict:
    """{relative path: sha256} the designer wrote last time. Markers from before the
    hashes were kept list names only; those files are rewritten but never deleted."""
    files = marker.get("files") if isinstance(marker, dict) else None
    if isinstance(files, dict):
        return {k: v for k, v in files.items() if isinstance(k, str) and isinstance(v, str)}
    if isinstance(files, list):
        return {k: "" for k in files if isinstance(k, str)}
    return {}


# What terraform init and validate in examples/basic read: the .tf files there and in the
# module above, and the providers already downloaded into .terraform.
_TF_CODE = ("*.tf", "*.tf.json")


def foreign_files(folder, written) -> list:
    """Files Terraform would load when checking the output that the designer didn't write
    just now: other .tf files, or providers someone else downloaded into .terraform."""
    folder = Path(folder)
    written = set(written)
    out = []
    for sub in ("", "examples/basic"):
        base = folder / sub if sub else folder
        for pattern in _TF_CODE:
            for f in sorted(base.glob(pattern)):
                rel = f"{sub}/{f.name}" if sub else f.name
                if rel not in written:
                    out.append(rel)
    for name in (".terraform", ".terraform.lock.hcl"):
        if (folder / "examples" / "basic" / name).exists():
            out.append(f"examples/basic/{name}")
    return out


def build(design, folder=None, region=None, fmt=True, validate=False, log=None) -> BuildResult:
    """Write the Terraform into folder (default <design>-tf next to the design). Only
    into an empty folder or one with the designer's marker. Never runs apply."""
    problems = check(design, region)
    bad = errors(problems)
    if bad:
        raise DesignError("The design has problems, so nothing was written:\n" +
                          "\n".join(f"- {p.message}" for p in bad))
    from .common import write_atomic
    folder = Path(folder) if folder else default_folder(design)
    old = check_folder(folder)
    content = files(design, region)
    folder.mkdir(parents=True, exist_ok=True)
    # Every path is checked before anything is written.
    targets = {rel: _inside_folder(folder, rel) for rel in sorted(content)}
    _inside_folder(folder, MARKER)
    written = []
    for rel, path in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        _inside_folder(folder, rel)          # nothing turned into a link meanwhile
        # A new random temporary name each time, then a rename over path: a file or link
        # planted in the folder can't send the write anywhere else.
        write_atomic(path, content[rel].encode("utf-8"))
        written.append(rel)
    removed = []
    for rel, digest in _marker_files(old).items():
        if rel in content or not digest:
            continue
        try:
            path = _inside_folder(folder, rel)
        except BuildError:
            continue
        # Only a file the designer wrote, unchanged since: anything else is the user's.
        if path.is_file() and not path.is_symlink() and _sha256_file(path) == digest:
            path.unlink()
            removed.append(rel)
    result = BuildResult(folder, written, removed, problems)
    if fmt:
        result.formatted = run_fmt(folder, written)
    hashes = {rel: _sha256_file(targets[rel]) or "" for rel in written}
    marker = {"generator": GENERATOR, "design": plain(design.path.name), "sha256": design.sha256,
              "region": (region or design.region).strip(), "files": hashes}
    write_atomic(_inside_folder(folder, MARKER), json.dumps(marker, indent=2) + "\n")
    if validate:
        foreign = foreign_files(folder, written)
        if foreign:
            result.checks = [("validate", None, SKIPPED_VALIDATE + ", ".join(foreign) + ".")]
        else:
            result.checks = validate_folder(folder, log=log)
    return result


SKIPPED_VALIDATE = ("init and validate didn't run, because Terraform would also load files "
                    "the designer didn't write, and start the providers they name. Run them "
                    "yourself if you trust those files, or build into a new folder. The files: ")


def run_fmt(folder, written=None) -> str:
    """terraform fmt on the files the designer wrote (all of them when written is None),
    and nothing else in the folder."""
    from . import tfplan
    tf = tfplan.terraform_bin()
    if not tf:
        return "terraform and tofu aren't installed, so fmt didn't run (the files are already laid out the way it would)"
    folder = Path(folder).resolve()
    if written is None:
        written = sorted(_marker_files(read_marker(folder)))
    changed = []
    for rel in written:
        if not rel.endswith((".tf", ".tfvars")):
            continue
        r = tfplan._run([tf, "fmt", "-no-color", rel], cwd=str(folder), timeout=120)
        if r.returncode != 0:
            return f"{Path(tf).name} fmt: " + (r.stderr or r.stdout).strip()
        changed += [x for x in r.stdout.split() if x]
    return f"{Path(tf).name} fmt" + (f" tidied {len(changed)} file(s)" if changed else ": nothing to change")


def validate_folder(folder, log=None) -> list:
    """init -backend=false and validate in examples/basic. [(command, ok, output)]."""
    from . import tfplan
    tf = tfplan.terraform_bin()
    if not tf:
        return [("validate", None, "terraform and tofu aren't installed, so the output wasn't "
                                   "validated. Install either one to have it checked.")]
    example = Path(folder).resolve() / "examples" / "basic"
    out = []
    name = Path(tf).name
    for cmd in (["init", "-backend=false", "-input=false", "-no-color"], ["validate", "-no-color"]):
        if log:
            log(f"Running {name} {' '.join(cmd)}")
        try:
            r = tfplan._run([tf] + cmd, cwd=str(example), timeout=600)
            ok = r.returncode == 0
            text = tfplan._tail((r.stdout or "") + "\n" + (r.stderr or ""), 30)
        except tfplan.PlanError as exc:
            ok, text = False, str(exc)
        out.append((f"{name} {cmd[0]}", ok, text))
        if not ok:
            break
    return out


# =================================================================== shapes, the library and new designs

# Library shape sizes and labels. Labels use draw.io placeholders, so they follow the
# settings as they're edited.
SHAPE_SIZES = {"vpc": (760, 440), "subnet": (320, 200), "igw": (180, 40), "nat": (260, 60),
               "sg": (260, 60), "endpoint": (260, 60)}
LABELS = {
    "vpc": ("%name%", "%cidr%"),
    "subnet": ("%name%", "%cidr%, %type%, zone %az%"),
    "igw": ("%name%", ""),
    "nat": ("%name%", "NAT gateway, %mode%"),
    "sg": ("%name%", "%description%"),
    "endpoint": ("%name%", "%kind% endpoint for %service%"),
}


def _box_for(kind, w, h, settings):
    from . import maplayout as ml
    from .mapthemes import category_of
    props = {"public": str(settings.get("type", "")).lower() == "public"} if kind == "subnet" else {}
    if kind in CONTAINERS:
        role, text, icon = "container", (34, 6, max(w - 48, 60)), None
    elif kind == "igw":
        role, text, icon = "chip", (40, 0, max(w - 48, 40)), (8, (h - 24) / 2, 24)
    else:
        role, text, icon = "card", (56, 0, max(w - 68, 40)), (12, (h - 32) / 2, 32)
    return ml.Box("", kind, role, "base", "", 0, 0, w, h, 0, 0, [], [], text, icon,
                  category_of(kind), [], {}, [], props)


def shape_cells(kind, cid, x, y, w=None, h=None, settings=None, parent="1",
                theme_name="dark") -> list:
    """The draw.io cells for one designer shape: a UserObject with awskit_type and its
    settings, styled like the maps, plus the icon inside cards and gateways."""
    from .mapdrawio import (CAPTION_SIZE, Writer, _style, _user_object, _vertex, join_style,
                            shape_for)
    from .mapthemes import card_colors, container_colors
    dw, dh = SHAPE_SIZES[kind]
    w, h = w or dw, h or dh
    attrs = {k: v for k, v in SETTINGS[kind]}
    attrs.update({k: str(v) for k, v in (settings or {}).items()})
    box = _box_for(kind, w, h, attrs)
    writer = Writer(None, theme_name)
    style = writer.box_style(box)
    th = writer.th
    if box.role == "container":
        colors = container_colors(th, kind, box.props)
        caption_color = colors["caption"]
    else:
        colors = card_colors(th, box.category)
        caption_color = colors["caption"]
        style.update(writer.text_style(box, style.get("fontSize", 13), style.get("fontColor"),
                                       valign="middle"))
    title, caption = LABELS[kind]
    label = f"<b>{title}</b>"
    if caption:
        label += (f"<br><span style=\"font-size:{CAPTION_SIZE}px;color:{caption_color};"
                  f"font-weight:normal\">{caption}</span>")
    data = dict(attrs)
    data["awskit_type"] = kind
    cells = [_user_object(cid, label, "", data, _vertex(join_style(style), parent, x, y, w, h))]
    if box.icon:
        ix, iy, size = box.icon
        icon_style = _style(shape="mxgraph.aws4.resourceIcon",
                            resIcon=f"mxgraph.aws4.{shape_for(box)}",
                            fillColor=colors["icon_fill"] if box.role != "container" else "none",
                            strokeColor=colors.get("glyph", caption_color), gradientColor="none",
                            html=1, movable=0, resizable=0, rotatable=0, deletable=0, editable=0,
                            connectable=0, aspect="fixed")
        cells.append(_user_object(f"{cid}-icon", "", "", {"awskit_part": "icon"},
                                  _vertex(icon_style, cid, ix, iy, size, size)))
    return cells


def arrow_cell(cid, source, target, settings=None, parent="1", theme_name="dark",
               points=None, src_point=None, dst_point=None) -> str:
    from .mapdrawio import _num, _style, _user_object
    from .mapthemes import theme
    th = theme(theme_name)
    line = th["edges"]["sg-reference"]
    attrs = {k: v for k, v in SETTINGS["sg-rule"]}
    attrs.update({k: str(v) for k, v in (settings or {}).items()})
    attrs["awskit_type"] = "sg-rule"
    style = _style(edgeStyle="orthogonalEdgeStyle", rounded=1, arcSize=16, html=1,
                   strokeColor=line["color"], strokeWidth=line["width"], endArrow="block",
                   endFill=1, endSize=6, fontSize=10, fontColor=line["color"],
                   labelBackgroundColor=th["page"])
    ends = "".join(f" {k}=\"{v}\"" for k, v in (("source", source), ("target", target)) if v)
    geo = '<mxGeometry relative="1" as="geometry">'
    if src_point:
        geo += f'<mxPoint x="{_num(src_point[0])}" y="{_num(src_point[1])}" as="sourcePoint"/>'
    if dst_point:
        geo += f'<mxPoint x="{_num(dst_point[0])}" y="{_num(dst_point[1])}" as="targetPoint"/>'
    if points:
        geo += "<Array as=\"points\">" + "".join(
            f'<mxPoint x="{_num(x)}" y="{_num(y)}"/>' for x, y in points) + "</Array>"
    geo += "</mxGeometry>"
    cell = (f"<mxCell style=\"{style}\" edge=\"1\" parent=\"{parent}\"{ends}>{geo}</mxCell>")
    return _user_object(cid, "%protocol% %ports%", "", attrs, cell)


def note_cell(cid, text, x, y, w, h, theme_name="dark", parent="1") -> str:
    from .mapdrawio import _plain_vertex, _style
    from .mapthemes import theme
    th = theme(theme_name)
    style = _style(text=None, html=1, whiteSpace="wrap", align="left", verticalAlign="top",
                   fontSize=12, fontColor=th["dim"], spacing=4)
    style = "text;" + style
    return _plain_vertex(cid, text, style, parent, x, y, w, h)


def design_xml(name, region, theme_name="dark", cells=(), width=1000, height=700) -> str:
    """A whole design file around the given cells (which use layer "1")."""
    from .mapdrawio import _attr_name
    from xml.sax.saxutils import quoteattr
    from .mapthemes import theme
    th = theme(theme_name)
    meta = {"awskit_design": "1", "awskit_name": name, "awskit_region": region,
            "awskit_theme": theme_name}
    root = "<UserObject label=\"\"" + "".join(
        f" {_attr_name(k)}={quoteattr(v)}" for k, v in sorted(meta.items())) + " id=\"0\"><mxCell/></UserObject>"
    return ("<mxfile host=\"AWS Kit\" compressed=\"false\">\n"
            f"<diagram id=\"awskit-design\" name={quoteattr(name)}>"
            f"<mxGraphModel dx=\"0\" dy=\"0\" grid=\"1\" gridSize=\"10\" guides=\"1\" tooltips=\"1\" "
            f"connect=\"1\" arrows=\"1\" fold=\"1\" page=\"1\" pageScale=\"1\" pageWidth=\"{width}\" "
            f"pageHeight=\"{height}\" math=\"0\" shadow=\"0\" background=\"{th['page']}\" "
            f"adaptiveColors=\"none\"><root>{root}\n<mxCell id=\"1\" value=\"Design\" parent=\"0\"/>\n"
            + "\n".join(cells) + "\n</root></mxGraphModel></diagram></mxfile>\n")


TEMPLATE_NOTE = ("Drag shapes in from the AWS Kit Designer library on the left. Draw subnets "
                 "inside the VPC, a NAT gateway inside a public subnet, and arrows between "
                 "security groups. Select a shape and press Ctrl+M (Edit Data) to change its "
                 "settings. With nothing selected, Ctrl+M sets the design's region.")


def template(name, region, theme_name="dark") -> str:
    """A new design: a VPC with an internet gateway, a public and a private subnet."""
    cells = [note_cell("note", TEMPLATE_NOTE, 40, 20, 760, 50, theme_name)]
    cells += shape_cells("vpc", "vpc", 40, 90, 760, 300, {"name": "main", "cidr": "10.0.0.0/16"},
                         theme_name=theme_name)
    cells += shape_cells("igw", "igw", 560, -20, settings={"name": "igw"}, parent="vpc",
                         theme_name=theme_name)
    cells += shape_cells("subnet", "public-a", 20, 60, 340, 200,
                         {"name": "public-a", "cidr": "10.0.1.0/24", "az": "a", "type": "public"},
                         parent="vpc", theme_name=theme_name)
    cells += shape_cells("subnet", "private-a", 400, 60, 340, 200,
                         {"name": "private-a", "cidr": "10.0.11.0/24", "az": "a", "type": "private"},
                         parent="vpc", theme_name=theme_name)
    return design_xml(name, region, theme_name, cells, 860, 440)


def new_design(path, name=None, region=None, theme_name="dark", overwrite=False) -> Path:
    path = Path(path)
    if path.suffix != DESIGN_SUFFIX:
        path = path.with_name(path.name + DESIGN_SUFFIX)
    if path.exists() and not overwrite:
        raise DesignError(f"{path} already exists.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(template(name or _stem(path), region or DEFAULT_REGION, theme_name),
                    encoding="utf-8")
    return path


LIBRARY_ITEMS = (
    ("vpc", "VPC", {}),
    ("subnet", "Public subnet", {"name": "public-a", "type": "public", "cidr": "10.0.1.0/24"}),
    ("subnet", "Private subnet", {"name": "private-a", "type": "private", "cidr": "10.0.11.0/24"}),
    ("igw", "Internet gateway", {}),
    ("nat", "NAT gateway", {}),
    ("sg", "Security group", {}),
    ("endpoint", "Gateway endpoint (S3)", {}),
    ("endpoint", "Interface endpoint", {"name": "ssm", "kind": "interface", "service": "ssm",
                                         "route_tables": ""}),
)


def library_xml(theme_name="dark") -> str:
    """The AWS Kit Designer shape library, in draw.io's library format."""
    items = []
    for kind, title, settings in LIBRARY_ITEMS:
        w, h = SHAPE_SIZES[kind]
        if kind == "subnet":
            w, h = 320, 160
        if kind == "vpc":
            w, h = 400, 240
        cells = shape_cells(kind, "2", 0, 0, w, h, settings, theme_name=theme_name)
        xml = ("<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/>"
               + "".join(cells) + "</root></mxGraphModel>")
        items.append({"xml": xml, "w": w, "h": h, "title": title})
    edge = arrow_cell("2", "", "", theme_name=theme_name, src_point=(0, 40), dst_point=(160, 40))
    items.append({"xml": "<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/>"
                         + edge + "</root></mxGraphModel>",
                  "w": 160, "h": 80, "title": "Security group arrow"})
    return ("<mxlibrary title=\"AWS Kit Designer\">" + html.escape(json.dumps(items, indent=1), quote=False)
            + "</mxlibrary>\n")


LIBRARY_DIR = Path(__file__).resolve().parent / "designer"


def library_path(theme_name="dark") -> Path:
    return LIBRARY_DIR / f"awskit-designer{'' if theme_name == 'dark' else '-light'}.xml"


# =================================================================== showing a design

SEVERITY_FLAG = {"error": "high", "warning": "medium"}


def layout(design, problems=None, region=None):
    """The design as a Layout, drawn where it's drawn in draw.io, with each problem as a
    red flag on its shape. The viewer page, SVG and PNG draw it like a map."""
    from . import maplayout as ml
    from .mapdrawio import MARGIN
    from .mapthemes import CAPTION_SIZE, CARD_TITLE_SIZE, CONTAINER_TITLE_SIZE
    if problems is None:
        problems = check(design, region)
    shapes = [s for s in design.shapes.values() if not s.edge and s.type in SHAPE_TYPES]
    rects = [s.rect for s in shapes]
    extra_geo = []
    for raw in design.others:
        try:
            el = ET.fromstring(raw)
        except ET.ParseError:
            continue
        cell = el if el.tag == "mxCell" else el.find("mxCell")
        if cell is not None and cell.get("vertex") == "1" and cell.get("parent") not in design.shapes:
            g = _geo(cell)[0]
            if g:
                extra_geo.append(g)
    allr = rects + extra_geo
    ox = min([r[0] for r in allr] or [0])
    oy = min([r[1] for r in allr] or [0])
    by_shape = {}
    for p in problems:
        if p.shape:
            by_shape.setdefault(p.shape, []).append(
                {"severity": SEVERITY_FLAG.get(p.severity, "medium"), "reason": p.message})
    boxes = []
    order = sorted(shapes, key=lambda s: (0 if s.type == "vpc" else 1 if s.type == "subnet" else 2,
                                          s.rect[1], s.rect[0]))
    placed = {}
    for s in order:
        x, y, w, h = s.rect
        ax, ay = x - ox, y - oy
        kind = s.type
        box = _box_for(kind, w, h, s.attrs)
        title, caption = _texts(s)
        if box.role == "container":
            box.title_lines = ml.wrap(title, CONTAINER_TITLE_SIZE, box.text[2], bold=True, max_lines=2)
            box.caption_lines = ml.wrap(caption, CAPTION_SIZE, box.text[2], max_lines=3)
        elif box.role == "chip":
            box.title_lines = ml.wrap(title, CAPTION_SIZE + 1, box.text[2], bold=True, max_lines=1)
            box.text = (box.text[0], max(2, (h - 16) / 2), box.text[2])
        else:
            box.title_lines = ml.wrap(title, CARD_TITLE_SIZE, box.text[2], bold=True, max_lines=2)
            box.caption_lines = ml.wrap(caption, CAPTION_SIZE, box.text[2], max_lines=3)
            th = 16 * len(box.title_lines) + (2 + 14 * len(box.caption_lines) if box.caption_lines else 0)
            box.text = (box.text[0], max(4, (h - th) / 2 - 1), box.text[2])
        parent = placed.get(s.container)
        box.id = s.id
        box.parent = parent.id if parent is not None else ""
        box.ax, box.ay = ax, ay
        box.x, box.y = (ax - parent.ax, ay - parent.ay) if parent is not None else (ax, ay)
        box.tooltip = [("", TYPE_TITLES.get(kind, kind))] + [
            (k.replace("_", " ").capitalize(), s.get(k)) for k, _ in SETTINGS.get(kind, ()) if s.get(k)]
        box.attrs = {"awskit_type": kind, **{k: s.get(k) for k, _ in SETTINGS.get(kind, ())}}
        box.flags = by_shape.get(s.id, [])
        boxes.append(box)
        placed[s.id] = box
    links = []
    for a in [s for s in design.shapes.values() if s.edge] + list(design.loose_edges):
        if a.source not in placed or a.target not in placed:
            continue
        if a.type != "sg-rule" and not (design.shapes[a.source].type == "sg" and
                                        design.shapes[a.target].type == "sg"):
            continue
        label = f"{a.get('protocol')} {a.get('ports')}".strip() if a.type else label_text(a.label)
        link = ml.Link(a.id, a.source, a.target, "sg-reference", "base", label,
                       [("", "Security group arrow"), ("From", design.shapes[a.source].name),
                        ("To", design.shapes[a.target].name), ("Allows", label)],
                       by_shape.get(a.id, []))
        links.append(link)
    extra = []
    shift_x, shift_y = MARGIN - ox, MARGIN - oy
    for raw in design.others:
        try:
            el = ET.fromstring(raw)
        except ET.ParseError:
            continue
        cell = el if el.tag == "mxCell" else el.find("mxCell")
        if cell is None:
            continue
        if cell.get("parent") not in placed:
            cell.set("parent", "awskit-layer-base")
            g = cell.find("mxGeometry")
            if g is not None:
                if cell.get("vertex") == "1":
                    for k, d in (("x", shift_x), ("y", shift_y)):
                        g.set(k, str(float(g.get(k, 0) or 0) + d))
                for p in g.iter("mxPoint"):
                    p.set("x", str(float(p.get("x", 0) or 0) + shift_x))
                    p.set("y", str(float(p.get("y", 0) or 0) + shift_y))
        extra.append(ET.tostring(el, encoding="unicode"))
    width = max([b.ax + b.w for b in boxes] + [r[0] - ox + r[2] for r in extra_geo] + [400])
    height = max([b.ay + b.h for b in boxes] + [r[1] - oy + r[3] for r in extra_geo] + [200])
    n_err = len(errors(problems))
    n_warn = len(problems) - n_err
    foot = [f"Design: {design.path.name}, {(region or design.region) or 'no region'}. "
            + (f"{n_err} error{'s' if n_err != 1 else ''}, " if n_err else "No errors, ")
            + (f"{n_warn} warning{'s' if n_warn != 1 else ''}." if n_warn else "no warnings.")]
    texts = [ml.Text("footnote", "legend", 0, ml.snap_up(height + 30), ml.snap_up(width), 20, foot,
                     "footnote")]
    lay = ml.Layout(boxes, links, texts, [], ml.snap_up(width), ml.snap_up(height + 60),
                    "design", ["base", "flags", "legend"])
    lay.extra = extra
    lay.meta = {"awskit_design": "1"}
    return lay


def _texts(s) -> tuple:
    if s.type == "vpc":
        return s.name, s.get("cidr")
    if s.type == "subnet":
        return s.name, f"{s.get('cidr')}, {s.get('type')}, zone {s.get('az')}"
    if s.type == "igw":
        return s.name, ""
    if s.type == "nat":
        return s.name, f"NAT gateway, {s.get('mode', 'per-az')}"
    if s.type == "sg":
        try:
            rules = parse_rules(s.get("ingress"))
            caption = "in: " + "; ".join(f"{r.ports_text()} from {r.cidr}" for r in rules) \
                if rules else (s.get("description") or "no inbound rules")
        except ValueError:
            caption = s.get("description")
        return s.name, caption
    if s.type == "endpoint":
        return s.name, f"{s.get('kind', 'gateway')} endpoint for {s.get('service')}"
    return s.name, ""


def summary(problems) -> str:
    n_err = len(errors(problems))
    n_warn = len(problems) - n_err
    if not problems:
        return "No problems."
    parts = []
    if n_err:
        parts.append(f"{n_err} error{'s' if n_err != 1 else ''}")
    if n_warn:
        parts.append(f"{n_warn} warning{'s' if n_warn != 1 else ''}")
    return ", ".join(parts) + "."
