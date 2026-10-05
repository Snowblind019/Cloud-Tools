"""Cloud Map's draw.io writer. Turns a Layout into a .drawio file.

The XML is written uncompressed and in a fixed order, so the same snapshot gives a
byte-identical file that diffs cleanly in git. Every node is a UserObject whose cell ID
is the node's ID, with a tooltip, its data as attributes (Edit Data in draw.io shows
them), and awskit="1" so cells AWS Kit made can be told apart from ones drawn by hand.

Icons are draw.io's built-in AWS shapes. Every name in SHAPES and GROUP_ICONS was checked
against the aws4 stencil set in draw.io's own source, and the tests check them again
against tests/drawio-aws4-shapes.txt so nothing renders as a blank box.
"""
from __future__ import annotations

import hashlib
import re
from xml.sax.saxutils import escape, quoteattr

from . import maplayout as ml
from .mapthemes import (CAPTION_SIZE, CARD_TITLE_SIZE, CONTAINER_TITLE_SIZE, EDGE_LABEL_SIZE,
                        FONT, card_colors, container_colors, theme)

MARGIN = 40

# Node kind -> aws4 stencil drawn inside mxgraph.aws4.resourceIcon. One table for all of
# them. Checked against draw.io 31.7.0's aws4.xml.
SHAPES = {
    "org": "organizations",
    "ou": "organizations_organizational_unit",
    "account": "organizations_account",
    "account-management": "organizations_management_account",
    "identity-center": "single_sign_on",
    "permission-set": "permissions",
    "role": "role",
    "oidc-provider": "identity_and_access_management",
    "saml-provider": "saml_token",
    "trail": "cloudtrail",
    "bucket": "bucket",
    "cost": "budgets",
    "sso-roles": "role",
    "user": "user",
    "group": "users",
    "github": "git_repository",
    "idp": "temporary_security_credential",
    "idp-saml": "saml_token",
    "ext-account": "organizations_account",
    "public": "internet",
    "igw": "internet_gateway",
    "eigw": "internet_gateway",
    "nat": "nat_gateway",
    "tgw": "transit_gateway",
    "tgw-attachment": "transit_gateway_attachment",
    "endpoint": "endpoints",
    "sg": "security_group",
    "nacl": "network_access_control_list",
    "instance": "ec2",
    "lb": "application_load_balancer",
    "lb-network": "network_load_balancer",
    "lb-gateway": "gateway_load_balancer",
    "lb-classic": "classic_load_balancer",
    "rds": "rds_instance",
    "vgw": "vpn_gateway",
    "cgw": "customer_gateway",
    "route-table": "route_table",
}

# Containers drawn with draw.io's AWS group shape, which puts the icon in the corner.
GROUP_ICONS = {"region": "group_region", "vpc": "group_vpc2", "subnet": "group_security_group"}

# The shapes (not stencils) these use, registered in draw.io's shapes code.
BASE_SHAPES = ("mxgraph.aws4.resourceIcon", "mxgraph.aws4.group")

LAYER_IDS = {name: f"awskit-layer-{name}" for name, _ in ml.LAYERS}


def shape_for(box) -> str:
    kind, props = box.kind, box.props
    if kind == "account" and props.get("management"):
        return SHAPES["account-management"]
    if kind == "idp" and props.get("protocol") == "SAML":
        return SHAPES["idp-saml"]
    if kind == "lb":
        t = str(props.get("type", "application")).lower()
        return SHAPES.get(f"lb-{t}", SHAPES["lb"])
    return SHAPES.get(kind, "")


def all_shape_names() -> list:
    """Every draw.io shape name the writer can emit, for the shape check in the tests."""
    names = {f"mxgraph.aws4.{v}" for v in SHAPES.values()}
    names |= {f"mxgraph.aws4.{v}" for v in GROUP_ICONS.values()}
    return sorted(names)


# Style keys that come from where things are, not how they look. Layout memory keeps
# these as positions and routes, never as style changes.
LAYOUT_STYLE_KEYS = {"spacing", "spacingLeft", "spacingTop", "spacingRight", "spacingBottom",
                     "exitX", "exitY", "exitDx", "exitDy", "exitPerimeter", "entryX", "entryY",
                     "entryDx", "entryDy", "entryPerimeter"}

# Cells AWS Kit writes without awskit="1": the root, layers, legend and footnote.
GENERATED_PREFIXES = ("awskit-layer-", "legend:", "strip:", "footnote")


# =================================================================== XML helpers

def _parts(**parts) -> dict:
    """Style parts as an ordered dict of text values, leaving out the None ones."""
    out = {}
    for k, v in parts.items():
        if v is None:
            continue
        key = k.rstrip("_")
        if isinstance(v, bool):
            v = 1 if v else 0
        if isinstance(v, float):
            v = _num(v)
        out[key] = str(v)
    return out


def join_style(parts: dict) -> str:
    return "".join(f"{k}={v};" for k, v in parts.items())


def _style(**parts) -> str:
    return join_style(_parts(**parts))


def parse_style(text) -> dict:
    """A draw.io style string as an ordered dict. A bare name like "ellipse" becomes
    {"shape": "ellipse"} the way draw.io reads it."""
    out = {}
    for part in str(text or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        else:
            out.setdefault("shape", part)
    return out


def merged(base: dict, overrides) -> dict:
    out = dict(base)
    for k, v in (overrides or {}).items():
        out[k] = str(v)
    return out


def short_hash(text) -> str:
    """Eight hex digits of SHA-1, used to tell whether draw.io changed a label or style."""
    return hashlib.sha1(str(text).encode("utf-8")).hexdigest()[:8]


def geo_text(x, y, w, h) -> str:
    return ",".join(_num(float(v)) for v in (x, y, w, h))


def points_text(points) -> str:
    return " ".join(f"{_num(float(x))},{_num(float(y))}" for x, y in points)


def _num(v) -> str:
    if isinstance(v, float):
        if v == int(v):
            return str(int(v))
        return repr(round(v, 4))
    return str(int(v))


def _attr_name(name) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))
    if not re.match(r"[A-Za-z_]", name):
        name = "a_" + name
    return name


def _html(text) -> str:
    return escape(str(text), {'"': "&quot;"})


def _lines(lines) -> str:
    return "<br>".join(_html(x) for x in lines)


def tooltip_html(lines) -> str:
    out = []
    for i, (label, value) in enumerate(lines):
        if not label:
            out.append(f"<b>{_html(value)}</b>" if i == 0 else _html(value))
        else:
            out.append(f"<b>{_html(label)}:</b> {_html(value)}")
    return "<br>".join(out)


def _user_object(cell_id, label, tooltip, attrs, cell_xml) -> str:
    parts = [f"<UserObject label={quoteattr(label)}"]
    if tooltip:
        parts.append(f" tooltip={quoteattr(tooltip)}")
    parts.append(' placeholders="1"')
    for k in sorted(attrs):
        name = _attr_name(k)
        if name in ("label", "tooltip", "placeholders", "id"):
            name = "data_" + name
        parts.append(f" {name}={quoteattr(str(attrs[k]))}")
    parts.append(f" id={quoteattr(cell_id)}>")
    return "".join(parts) + cell_xml + "</UserObject>"


def _vertex(style, parent, x, y, w, h) -> str:
    return (f"<mxCell style={quoteattr(style)} vertex=\"1\" parent={quoteattr(parent)}>"
            f"<mxGeometry x=\"{_num(x)}\" y=\"{_num(y)}\" width=\"{_num(w)}\" "
            f"height=\"{_num(h)}\" as=\"geometry\"/></mxCell>")


def _plain_vertex(cell_id, value, style, parent, x, y, w, h) -> str:
    return (f"<mxCell id={quoteattr(cell_id)} value={quoteattr(value)} style={quoteattr(style)} "
            f"vertex=\"1\" parent={quoteattr(parent)}><mxGeometry x=\"{_num(x)}\" "
            f"y=\"{_num(y)}\" width=\"{_num(w)}\" height=\"{_num(h)}\" as=\"geometry\"/></mxCell>")


# =================================================================== writer

class Writer:
    def __init__(self, layout, theme_name="dark", meta=None):
        self.lay = layout
        self.th = theme(theme_name)
        self.theme_name = theme_name
        self.meta = dict(meta or {})
        self.cells = []

    def parent_of(self, box) -> str:
        return box.parent or LAYER_IDS[box.layer]

    def pos(self, box):
        if box.parent:
            return box.x, box.y
        return box.x + MARGIN, box.y + MARGIN

    # ---- labels
    def label(self, box, title_size, title_color, caption_color) -> str:
        title = _lines(box.title_lines)
        out = f"<b>{title}</b>" if title else ""
        if box.caption_lines:
            out += (f"<br><span style=\"font-size:{CAPTION_SIZE}px;color:{caption_color};"
                    f"font-weight:normal\">{_lines(box.caption_lines)}</span>")
        return out

    def text_style(self, box, size, color, valign="top"):
        tx, ty, tw = box.text
        return dict(whiteSpace="wrap", html=1, fontFamily=FONT, fontSize=size, fontColor=color,
                    align="left", verticalAlign=valign, spacing=0, spacingLeft=tx,
                    spacingTop=ty, spacingRight=max(0, box.w - tx - tw), spacingBottom=0)

    # ---- boxes
    def box(self, box):
        x, y = self.pos(box)
        parent = self.parent_of(box)
        tip = tooltip_html(box.tooltip)
        attrs = dict(box.attrs)
        if box.role in ("container",):
            self.container(box, x, y, parent, tip, attrs)
        else:
            self.card(box, x, y, parent, tip, attrs)

    def box_label(self, box) -> str:
        if box.role == "container":
            c = container_colors(self.th, box.kind, box.props)
            return self.label(box, CONTAINER_TITLE_SIZE, c["title"], c["caption"])
        colors = card_colors(self.th, box.category)
        size = CAPTION_SIZE + 1 if box.role == "chip" else CARD_TITLE_SIZE
        return self.label(box, size, colors["title"], colors["caption"])

    def box_style(self, box) -> dict:
        """The style AWS Kit gives a box, before any changes made in draw.io."""
        if box.role == "container":
            c = container_colors(self.th, box.kind, box.props)
            base = self.text_style(box, CONTAINER_TITLE_SIZE, c["title"])
            common = dict(container=1, collapsible=0, recursiveResize=0, pointerEvents=0)
            if box.kind in ml.GROUP_SHAPES:
                return _parts(shape="mxgraph.aws4.group",
                              grIcon=f"mxgraph.aws4.{GROUP_ICONS[box.kind]}",
                              grIconSize=24, grStroke=1, strokeColor=c["stroke"],
                              fillColor=c["fill"], dashed=bool(c["dashed"]),
                              strokeWidth=c["width"], **base, **common)
            arc = 20 if box.kind == "org" else 12
            return _parts(rounded=1, arcSize=arc, absoluteArcSize=1, fillColor=c["fill"],
                          strokeColor=c["stroke"], dashed=bool(c["dashed"]),
                          dashPattern="6 4" if c["dashed"] else None,
                          strokeWidth=c["width"], **base, **common)
        colors = card_colors(self.th, box.category)
        size = CAPTION_SIZE + 1 if box.role == "chip" else CARD_TITLE_SIZE
        base = self.text_style(box, size, colors["title"])
        # A card holds its icon, so it's a draw.io container, but nothing should be dropped
        # into it: dropTarget=0 keeps a dragged card in its subnet.
        return _parts(rounded=1, arcSize=10 if box.role != "chip" else 8, absoluteArcSize=1,
                      fillColor=colors["fill"], strokeColor=colors["stroke"],
                      dashed=box.role == "more", dashPattern="4 3" if box.role == "more" else None,
                      container=1 if box.icon else None, collapsible=0,
                      dropTarget=0 if box.icon else None, **base)

    def memory_attrs(self, box, x, y, label, style) -> dict:
        """What layout memory reads back: the geometry, label and style as written, so a
        change made in draw.io can be told apart from one in AWS."""
        out = {"awskit_geo": geo_text(x, y, box.w, box.h), "awskit_lh": short_hash(label),
               "awskit_sh": short_hash(style)}
        if box.hints.get("pinned"):
            out["awskit_pin"] = "1"
        if box.hints.get("container"):
            out["awskit_in"] = box.hints["container"]
        return out

    def container(self, box, x, y, parent, tip, attrs):
        c = container_colors(self.th, box.kind, box.props)
        label = self.box_label(box)
        style = join_style(merged(self.box_style(box), box.hints.get("style")))
        attrs.update(self.memory_attrs(box, x, y, label, style))
        self.cells.append(_user_object(box.id, label, tip, attrs,
                                       _vertex(style, parent, x, y, box.w, box.h)))
        if box.icon and box.kind not in ml.GROUP_SHAPES:
            # Containers get just the glyph, in their caption color, so they stay quiet.
            self.icon(box, box.icon, None, c["caption"], tip)

    def card(self, box, x, y, parent, tip, attrs):
        colors = card_colors(self.th, box.category)
        label = self.box_label(box)
        style = join_style(merged(self.box_style(box), box.hints.get("style")))
        attrs.update(self.memory_attrs(box, x, y, label, style))
        self.cells.append(_user_object(box.id, label, tip, attrs,
                                       _vertex(style, parent, x, y, box.w, box.h)))
        if box.icon:
            self.icon(box, box.icon, colors["icon_fill"], colors["glyph"], tip)

    def icon(self, box, icon, fill, glyph, tip):
        name = shape_for(box) or "generic"
        ix, iy, size = icon
        style = _style(shape="mxgraph.aws4.resourceIcon", resIcon=f"mxgraph.aws4.{name}",
                       fillColor=fill or "none", strokeColor=glyph, gradientColor="none",
                       html=1, movable=0, resizable=0, rotatable=0, deletable=0, editable=0,
                       connectable=0, aspect="fixed")
        self.cells.append(_user_object(f"{box.id}#icon", "", tip,
                                       {"awskit": "1", "role": "icon", "aws_id": box.attrs.get("aws_id", box.id)},
                                       _vertex(style, box.id, ix, iy, size, size)))

    # ---- edges
    def edge_style(self, link, color_key, color=None, width=None, dashed=None, label=True):
        return join_style(self.edge_parts(link, color_key, color, width, dashed, label))

    def edge_parts(self, link, color_key, color=None, width=None, dashed=None, label=True):
        line = self.th["edges"].get(color_key) or self.th["edges"]["trust"]
        both = link.kind in ("peering", "vpn", "tgw-attachment")
        parts = dict(edgeStyle="orthogonalEdgeStyle", rounded=1, arcSize=16, html=1,
                     orthogonalLoop=1, jettySize="auto",
                     strokeColor=color or line["color"], strokeWidth=width or line["width"],
                     dashed=bool(line["dashed"] if dashed is None else dashed),
                     dashPattern="6 4" if (line["dashed"] if dashed is None else dashed) else None,
                     endArrow="block", endFill=1, endSize=6,
                     startArrow="block" if both else "none", startFill=1 if both else None,
                     startSize=6 if both else None,
                     fontFamily=FONT, fontSize=EDGE_LABEL_SIZE, fontColor=line["color"] if label else None,
                     labelBackgroundColor=self.th["label_background"] if label else None)
        if link.exit:
            parts.update(exitX=link.exit[0], exitY=link.exit[1], exitDx=0, exitDy=0,
                         exitPerimeter=0)
        if link.entry:
            parts.update(entryX=link.entry[0], entryY=link.entry[1], entryDx=0, entryDy=0,
                         entryPerimeter=0)
        return _parts(**parts)

    def edge_xml(self, cell_id, link, style, layer, label, tip, attrs):
        pts = ""
        if link.points:
            pts = "<Array as=\"points\">" + "".join(
                f"<mxPoint x=\"{_num(x + MARGIN)}\" y=\"{_num(y + MARGIN)}\"/>" for x, y in link.points
            ) + "</Array>"
        cell = (f"<mxCell style={quoteattr(style)} edge=\"1\" parent={quoteattr(LAYER_IDS[layer])} "
                f"source={quoteattr(link.src)} target={quoteattr(link.dst)}>"
                f"<mxGeometry relative=\"1\" as=\"geometry\">{pts}</mxGeometry></mxCell>")
        return _user_object(cell_id, label, tip, attrs, cell)

    def edge(self, link):
        style = join_style(merged(self.edge_parts(link, link.kind), link.hints.get("style")))
        attrs = dict(link.attrs)
        attrs["awskit_pts"] = points_text((x + MARGIN, y + MARGIN) for x, y in link.points)
        attrs["awskit_sh"] = short_hash(style)
        if link.hints.get("pinned"):
            attrs["awskit_pin"] = "1"
        self.cells.append(self.edge_xml(link.id, link, style, link.layer, _html(link.label),
                                        tooltip_html(link.tooltip), attrs))

    # ---- flags
    def flags(self):
        fl = self.th["flagged"]
        for box in self.lay.boxes:
            if not box.flags:
                continue
            ax, ay = box.ax + MARGIN, box.ay + MARGIN
            reasons = [("", "Security problem")] + [(f["severity"].capitalize(), f["reason"])
                                                    for f in box.flags]
            tip = tooltip_html(reasons)
            outline = _style(rounded=1, arcSize=12, absoluteArcSize=1, fillColor="none",
                             strokeColor=fl["stroke"], strokeWidth=2.5, pointerEvents=0,
                             movable=0, resizable=0, editable=0, connectable=0)
            self.cells.append(_user_object(f"{box.id}#flag", "", "", {
                "awskit": "1", "role": "flag-outline", "aws_id": box.attrs.get("aws_id", box.id)},
                _vertex(outline, LAYER_IDS["flags"], ax - 4, ay - 4, box.w + 8, box.h + 8)))
            badge = _style(shape="ellipse", fillColor=fl["fill"], strokeColor="none",
                           fontColor=fl["text"], fontStyle=1, fontSize=12, fontFamily=FONT,
                           align="center", verticalAlign="middle", html=1, resizable=0,
                           editable=0, connectable=0)
            self.cells.append(_user_object(f"{box.id}#badge", "!", tip, {
                "awskit": "1", "role": "flag-badge", "aws_id": box.attrs.get("aws_id", box.id),
                "flags": box.attrs.get("flags", "")},
                _vertex(badge, LAYER_IDS["flags"], ax + box.w - 12, ay - 8, 20, 20)))
        for link in self.lay.links:
            if not link.flags:
                continue
            style = self.edge_style(link, "flag", label=False)
            reasons = [("", "Security problem")] + [(f["severity"].capitalize(), f["reason"])
                                                    for f in link.flags]
            self.cells.append(self.edge_xml(f"{link.id}#flag", link, style, "flags", "",
                                            tooltip_html(reasons),
                                            {"awskit": "1", "role": "flag-edge",
                                             "flags": link.attrs.get("flags", "")}))

    # ---- legend and notes
    def legend(self):
        th = self.th
        for entry in self.lay.legend:
            x, y = entry.x + MARGIN, entry.y + MARGIN
            if entry.style == "flag":
                sample = _style(rounded=1, arcSize=6, absoluteArcSize=1, fillColor="none",
                                strokeColor=th["flagged"]["stroke"], strokeWidth=2.5)
                self.cells.append(_plain_vertex(f"{entry.id}:sample", "", sample,
                                                LAYER_IDS["legend"], x, y + 2, 40, 16))
            else:
                line = th["edges"].get(entry.style) or th["edges"]["trust"]
                both = entry.style in ("peering", "vpn", "tgw-attachment")
                style = _style(html=1, strokeColor=line["color"], strokeWidth=line["width"],
                               dashed=bool(line["dashed"]),
                               dashPattern="6 4" if line["dashed"] else None,
                               endArrow="block", endFill=1, endSize=5,
                               startArrow="block" if both else "none",
                               startFill=1 if both else None, startSize=5 if both else None)
                self.cells.append(
                    f"<mxCell id={quoteattr(entry.id + ':sample')} style={quoteattr(style)} "
                    f"edge=\"1\" parent=\"{LAYER_IDS['legend']}\"><mxGeometry relative=\"1\" "
                    f"as=\"geometry\"><mxPoint x=\"{x}\" y=\"{y + 10}\" as=\"sourcePoint\"/>"
                    f"<mxPoint x=\"{x + 40}\" y=\"{y + 10}\" as=\"targetPoint\"/></mxGeometry></mxCell>")
            text = _style(fillColor="none", strokeColor="none", html=1, align="left", verticalAlign="middle",
                          whiteSpace="nowrap", fontFamily=FONT, fontSize=12,
                          fontColor=th["legend_text"], spacing=0)
            self.cells.append(_plain_vertex(f"{entry.id}:text", _html(entry.label), text,
                                            LAYER_IDS["legend"], x + 52, y, 320, 20))

    def texts(self):
        th = self.th
        for t in self.lay.texts:
            if t.style == "strip":
                style = _style(fillColor="none", strokeColor="none", html=1, align="left", verticalAlign="middle",
                               whiteSpace="nowrap", fontFamily=FONT, fontSize=11, fontStyle=1,
                               fontColor=th["dim"], spacing=0, spacingLeft=2)
            else:
                style = _style(fillColor="none", strokeColor="none", html=1, align="left", verticalAlign="top",
                               whiteSpace="wrap", fontFamily=FONT, fontSize=11,
                               fontColor=th["footnote"], spacing=0)
            self.cells.append(_plain_vertex(t.id, _lines(t.lines), style, LAYER_IDS[t.layer],
                                            t.x + MARGIN, t.y + MARGIN, t.w, t.h))

    # ---- whole file
    def write(self, diagram_name="") -> str:
        lay = self.lay
        for box in lay.boxes:
            if box.layer != "base" and box.layer not in lay.layers:
                continue
            self.box(box)
        for link in lay.links:
            if link.layer in lay.layers:
                self.edge(link)
        if "flags" in lay.layers:
            self.flags()
        self.legend()
        self.texts()
        self.extras()
        layers = "".join(
            f"<mxCell id=\"{LAYER_IDS[name]}\" value={quoteattr(title)} parent=\"0\"/>"
            for name, title in ml.LAYERS if name in lay.layers)
        name = diagram_name or {"access": "Access map", "network": "Network map",
                                "combined": "Combined map"}[lay.map_type]
        w, h = lay.width + 2 * MARGIN, lay.height + 2 * MARGIN
        head = (f"<mxfile host=\"awskit\" compressed=\"false\">"
                f"<diagram id=\"awskit-{lay.map_type}\" name={quoteattr(name)}>"
                f"<mxGraphModel dx=\"0\" dy=\"0\" grid=\"1\" gridSize=\"10\" guides=\"1\" "
                f"tooltips=\"1\" connect=\"1\" arrows=\"1\" fold=\"1\" page=\"1\" "
                f"pageScale=\"1\" pageWidth=\"{w}\" pageHeight=\"{h}\" math=\"0\" "
                f"shadow=\"0\" background=\"{self.th['page']}\" adaptiveColors=\"none\">"
                f"<root>{self.root_cell()}")
        body = "\n".join([layers] + self.cells)
        return head + "\n" + body + "\n</root></mxGraphModel></diagram></mxfile>\n"


    # ---- what layout memory needs
    def root_cell(self) -> str:
        """The diagram's root, carrying how it was drawn (map type, theme, filters), so
        layout memory can read a saved file back. draw.io keeps these as the page's data."""
        meta = {k: v for k, v in self.meta.items() if v not in (None, "")}
        if not meta:
            return "<mxCell id=\"0\"/>"
        attrs = "".join(f" {_attr_name(k)}={quoteattr(str(v))}" for k, v in sorted(meta.items()))
        return f"<UserObject label=\"\"{attrs} id=\"0\"><mxCell/></UserObject>"

    def extras(self):
        """Cells drawn by hand in draw.io, carried over from the layout memory. A cell
        whose container isn't on this map goes on the base layer, and a line whose end
        isn't on it is left out."""
        extra = getattr(self.lay, "extra", None) or []
        if not extra:
            return
        import xml.etree.ElementTree as ET
        present = {b.id for b in self.lay.boxes} | {LAYER_IDS[n] for n in self.lay.layers}
        cells = []
        for raw in extra:
            try:
                el = ET.fromstring(raw)
            except ET.ParseError:
                continue
            cell = el if el.tag == "mxCell" else el.find("mxCell")
            cid = el.get("id")
            if cell is None or not cid or cid in present:
                continue
            cells.append((el, cell, cid))
        present |= {cid for _, _, cid in cells}
        for el, cell, cid in cells:
            if cell.get("parent") not in present:
                cell.set("parent", LAYER_IDS["base"])
            if cell.get("edge") == "1" and any(
                    cell.get(end) and cell.get(end) not in present for end in ("source", "target")):
                continue
            self.cells.append(ET.tostring(el, encoding="unicode"))


def write(layout, theme_name="dark", diagram_name="", meta=None) -> str:
    return Writer(layout, theme_name, meta).write(diagram_name)
