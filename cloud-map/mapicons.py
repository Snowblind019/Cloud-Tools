"""AWS icons for Cloud Map's viewer and its SVG and PNG exports. No GTK.

The .drawio export names draw.io's built-in AWS shapes, and draw.io draws them. For the
viewer to look the same, it draws the very same shapes: draw.io's aws4 stencil set, read
from the draw.io web app the installers download (it isn't in this repo, see the README
for why). A stencil is a list of vector drawing steps (move, line, curve, arc, fill),
so cairo draws it directly, sharp at any zoom, and no SVG library is needed.

draw.io up to 31.x ships the set as stencils/aws4.xml. Newer versions pack every stencil
set into js/stencils.min.js in a compact binary form, which decode_compact() reads. Both
give the same shapes, checked by the tests. The parsed shapes are cached as JSON next to
the draw.io files, so later starts don't parse 5 MB of XML again.

When the draw.io files aren't there, draw_glyph() draws a simple stand-in: the icon
square with a short name in it, like VPC or EC2.
"""
from __future__ import annotations

import base64
import json
import math
import re
import struct
import threading
import xml.etree.ElementTree as ET
import zlib
from functools import lru_cache
from pathlib import Path

from .common import drawio_dir, drawio_installed

PREFIX = "mxgraph.aws4."
CACHE_NAME = "awskit-aws4-icons.json"
CACHE_FORMAT = 1

# Short names for the stand-in glyphs, by Cloud Map node kind or draw.io shape name.
ABBREV = {
    "org": "ORG", "ou": "OU", "account": "ACCT", "identity-center": "SSO",
    "permission-set": "PS", "role": "ROLE", "oidc-provider": "OIDC", "saml-provider": "SAML",
    "trail": "CT", "bucket": "S3", "cost": "$", "sso-roles": "SSO", "user": "USER",
    "group": "GRP", "github": "GH", "idp": "IDP", "ext-account": "EXT", "public": "*",
    "igw": "IGW", "eigw": "EIGW", "nat": "NAT", "tgw": "TGW", "tgw-attachment": "TGW",
    "endpoint": "VPCE", "sg": "SG", "nacl": "ACL", "instance": "EC2", "lb": "ELB",
    "rds": "RDS", "vgw": "VGW", "cgw": "CGW", "route-table": "RT", "region": "RGN",
    "vpc": "VPC", "subnet": "SN", "az": "AZ",
}


# =================================================================== reading stencils

class Stencil:
    __slots__ = ("w", "h", "aspect", "strokewidth", "bg", "fg")

    def __init__(self, w, h, aspect, strokewidth, bg, fg):
        self.w, self.h, self.aspect, self.strokewidth = w, h, aspect, strokewidth
        self.bg, self.fg = bg, fg

    def as_list(self):
        return [self.w, self.h, self.aspect, self.strokewidth, self.bg, self.fg]


def key_of(name) -> str:
    """The registry name draw.io uses: lower case, spaces as underscores."""
    name = str(name or "").strip()
    if name.startswith(PREFIX):
        name = name[len(PREFIX):]
    return name.lower().replace(" ", "_")


def _num(el, attr, default=0.0) -> float:
    try:
        return float(el.get(attr, default))
    except (TypeError, ValueError):
        return float(default)


PATH_STEPS = {
    "move": lambda e: ["M", _num(e, "x"), _num(e, "y")],
    "line": lambda e: ["L", _num(e, "x"), _num(e, "y")],
    "quad": lambda e: ["Q", _num(e, "x1"), _num(e, "y1"), _num(e, "x2"), _num(e, "y2")],
    "curve": lambda e: ["C", _num(e, "x1"), _num(e, "y1"), _num(e, "x2"), _num(e, "y2"),
                        _num(e, "x3"), _num(e, "y3")],
    "arc": lambda e: ["A", _num(e, "rx"), _num(e, "ry"), _num(e, "x-axis-rotation"),
                      _num(e, "large-arc-flag"), _num(e, "sweep-flag"), _num(e, "x"),
                      _num(e, "y")],
    "close": lambda e: ["Z"],
}


def _compile_steps(parent) -> list:
    """A stencil's background or foreground as a flat list of drawing steps."""
    out = []
    if parent is None:
        return out
    for el in parent:
        tag = el.tag
        if tag == "path":
            steps = [PATH_STEPS[c.tag](c) for c in el if c.tag in PATH_STEPS]
            out.append(["path", steps])
        elif tag == "rect":
            out.append(["rect", _num(el, "x"), _num(el, "y"), _num(el, "w"), _num(el, "h")])
        elif tag == "roundrect":
            out.append(["roundrect", _num(el, "x"), _num(el, "y"), _num(el, "w"),
                        _num(el, "h"), _num(el, "arcsize")])
        elif tag == "ellipse":
            out.append(["ellipse", _num(el, "x"), _num(el, "y"), _num(el, "w"), _num(el, "h")])
        elif tag in ("fill", "stroke", "fillstroke", "save", "restore"):
            out.append([tag])
        elif tag in ("fillcolor", "strokecolor"):
            out.append([tag, el.get("color", "none")])
        elif tag in ("alpha", "fillalpha", "strokealpha"):
            out.append(["alpha", _num(el, "alpha", 1)])
        elif tag == "strokewidth":
            out.append(["strokewidth", _num(el, "width", 1), el.get("fixed") == "1"])
        elif tag == "dashed":
            out.append(["dashed", el.get("dashed") == "1"])
        elif tag == "dashpattern":
            out.append(["dashpattern", el.get("pattern", "3 3")])
        elif tag == "linejoin":
            out.append(["linejoin", el.get("join", "miter")])
        elif tag == "linecap":
            out.append(["linecap", el.get("cap", "flat")])
        elif tag == "miterlimit":
            out.append(["miterlimit", _num(el, "limit", 10)])
        # text, image and include-shape aren't used by the AWS shapes.
    return out


def compile_shapes(root) -> dict:
    """{registry name: Stencil} from a <shapes> element."""
    out = {}
    for shape in root.iter("shape"):
        name = key_of(shape.get("name"))
        if not name:
            continue
        out[name] = Stencil(_num(shape, "w", 100) or 100, _num(shape, "h", 100) or 100,
                            shape.get("aspect", "variable"), shape.get("strokewidth", "1"),
                            _compile_steps(shape.find("background")),
                            _compile_steps(shape.find("foreground")))
    return out


# ---- draw.io 32's packed stencils

_DRAW = {"move", "line", "quad", "curve", "arc", "rect", "roundrect", "ellipse", "text",
         "image", "include-shape"}
_XS = {"x", "x1", "x2", "x3"}
_YS = {"y", "y1", "y2", "y3"}


def _fmt(n) -> str:
    v = n / 1000
    return str(int(v)) if v == int(v) else repr(v)


def decode_compact(text: str):
    """One stencil file from js/stencils.min.js, back to an XML element. A port of the
    decode() function at the end of that file: base64, raw deflate, then five streams
    (element and attribute codes, x deltas, y deltas, other numbers, strings)."""
    data = zlib.decompress(base64.b64decode(text), -15)
    lengths = struct.unpack(">5I", data[:20])
    streams, offset = [], 20
    for n in lengths:
        streams.append(data[offset:offset + n])
        offset += n
    ops, strings = streams[0], streams[4].decode("utf-8").split("\0")
    pos = [0, 0, 0, 0]
    si = 0
    names, attr_names = [], []
    root = ET.Element("root")
    stack = [root]
    px = py = 0
    per = {}

    def read(k):
        buf, n, m = streams[k], 0, 1
        while True:
            c = buf[pos[k]]
            pos[k] += 1
            n += (c & 127) * m
            m *= 128
            if not c & 128:
                break
        return -(n + 1) // 2 if n % 2 else n // 2

    while pos[0] < len(ops):
        op = ops[pos[0]]
        pos[0] += 1
        if op == 255:
            stack.pop()
            continue
        if (op >> 1) == len(names):
            names.append(strings[si])
            si += 1
        name = names[op >> 1]
        node = ET.SubElement(stack[-1], name)
        count = ops[pos[0]]
        pos[0] += 1
        coords = name in _DRAW
        if name == "shape":
            px = py = 0
            per = {}
        for _ in range(count):
            aid = ops[pos[0]]
            pos[0] += 1
            if aid == len(attr_names):
                attr_names.append(strings[si])
                si += 1
            attr = attr_names[aid]
            kind = ops[pos[0]]
            pos[0] += 1
            if kind == 0:
                node.set(attr, strings[si])
                si += 1
            elif coords and attr in _XS:
                px += read(1)
                node.set(attr, _fmt(px))
            elif coords and attr in _YS:
                py += read(2)
                node.set(attr, _fmt(py))
            else:
                key = name + " " + attr
                per[key] = per.get(key, 0) + read(3)
                node.set(attr, _fmt(per[key]))
        if not op & 1:
            stack.append(node)
    return root[0] if len(root) else root


def _packed_aws4(folder: Path):
    path = folder / "js" / "stencils.min.js"
    text = path.read_text(encoding="utf-8")
    m = re.search(r"\[\s*['\"]aws4\.xml['\"]\s*\]\s*=\s*['\"]([A-Za-z0-9+/=]+)['\"]", text)
    if not m:
        raise ValueError(f"No aws4 stencils in {path}")
    return decode_compact(m.group(1)), path


def read_stencil_source(folder: Path):
    """(<shapes> element, the file it came from) from a draw.io web app folder."""
    plain = folder / "stencils" / "aws4.xml"
    if plain.is_file():
        return ET.parse(plain).getroot(), plain
    return _packed_aws4(folder)


class IconSet:
    """draw.io's AWS stencils, loaded once. Thread safe, so the viewer can load it in the
    background while the first frame draws stand-ins."""

    def __init__(self, folder=None):
        self.folder = Path(folder) if folder else drawio_dir()
        self.shapes = {}
        self.error = ""
        self.loaded = False
        self.version = ""
        self._lock = threading.Lock()

    def load(self) -> "IconSet":
        with self._lock:
            if self.loaded:
                return self
            self.loaded = True
            self.version = drawio_installed(self.folder)
            if not self.version:
                self.error = (f"draw.io isn't downloaded to {self.folder}, so simple stand-in "
                              "icons are used. Run the installer again to get the AWS icons.")
                return self
            try:
                self.shapes = self._from_cache() or self._parse()
            except (OSError, ValueError, ET.ParseError, zlib.error, struct.error,
                    IndexError) as exc:
                self.error = f"Couldn't read draw.io's AWS icons: {exc}"
                self.shapes = {}
        return self

    def _cache_key(self, source: Path) -> str:
        st = source.stat()
        return f"{CACHE_FORMAT}:{self.version}:{source.name}:{st.st_size}:{int(st.st_mtime)}"

    def _source(self) -> Path:
        plain = self.folder / "stencils" / "aws4.xml"
        return plain if plain.is_file() else self.folder / "js" / "stencils.min.js"

    def _from_cache(self):
        try:
            data = json.loads((self.folder / CACHE_NAME).read_text(encoding="utf-8"))
            if data.get("key") != self._cache_key(self._source()):
                return None
            return {k: Stencil(*v) for k, v in data["shapes"].items()}
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _parse(self) -> dict:
        root, source = read_stencil_source(self.folder)
        shapes = compile_shapes(root)
        if not shapes:
            raise ValueError("the AWS stencil set is empty")
        try:
            from .common import write_atomic
            write_atomic(self.folder / CACHE_NAME,
                         json.dumps({"key": self._cache_key(source),
                                     "shapes": {k: s.as_list() for k, s in shapes.items()}},
                                    separators=(",", ":")))
        except OSError:
            pass  # a read-only folder just means parsing again next time
        return shapes

    def get(self, name):
        if not self.loaded:
            self.load()
        return self.shapes.get(key_of(name))

    def __contains__(self, name):
        return self.get(name) is not None


_default = None
_default_lock = threading.Lock()


def default_icons() -> IconSet:
    """The icon set from the installed draw.io, shared by everything in this process."""
    global _default
    with _default_lock:
        if _default is None or _default.folder != drawio_dir():
            _default = IconSet()
        return _default


# =================================================================== drawing

@lru_cache(maxsize=512)
def _rgb(color):
    """'#RRGGBB' (or 'none') to an (r, g, b) tuple, or None."""
    if not color or color == "none":
        return None
    c = str(color).lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    try:
        return tuple(int(c[i:i + 2], 16) / 255 for i in (0, 2, 4))
    except ValueError:
        return None


def arc_to_curves(x0, y0, rx, ry, angle, large, sweep, x, y) -> list:
    """An SVG elliptical arc as cubic Bezier segments [(x1, y1, x2, y2, x3, y3), ...],
    the same conversion draw.io makes (the W3C endpoint to center steps)."""
    if rx == 0 or ry == 0 or (x0 == x and y0 == y):
        return [(x0, y0, x, y, x, y)]
    rx, ry = abs(rx), abs(ry)
    phi = math.radians(angle % 360)
    cos_p, sin_p = math.cos(phi), math.sin(phi)
    dx, dy = (x0 - x) / 2, (y0 - y) / 2
    x1p = cos_p * dx + sin_p * dy
    y1p = -sin_p * dx + cos_p * dy
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:
        s = math.sqrt(lam)
        rx, ry = rx * s, ry * s
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    coef = math.sqrt(max(0.0, num / den)) if den else 0.0
    if bool(large) == bool(sweep):
        coef = -coef
    cxp, cyp = coef * rx * y1p / ry, -coef * ry * x1p / rx
    cx = cos_p * cxp - sin_p * cyp + (x0 + x) / 2
    cy = sin_p * cxp + cos_p * cyp + (y0 + y) / 2

    def ang(ux, uy, vx, vy):
        a = math.atan2(ux * vy - uy * vx, ux * vx + uy * vy)
        return a

    t1 = ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dt = ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not sweep and dt > 0:
        dt -= 2 * math.pi
    elif sweep and dt < 0:
        dt += 2 * math.pi
    segs = max(1, int(math.ceil(abs(dt) / (math.pi / 2) - 1e-9)))
    delta = dt / segs
    k = 4 / 3 * math.tan(delta / 4)
    out = []
    t = t1
    for _ in range(segs):
        c1, s1 = math.cos(t), math.sin(t)
        c2, s2 = math.cos(t + delta), math.sin(t + delta)
        p1 = (c1 - k * s1, s1 + k * c1)
        p2 = (c2 + k * s2, s2 - k * c2)
        p3 = (c2, s2)
        pts = []
        for px_, py_ in (p1, p2, p3):
            ex, ey = px_ * rx, py_ * ry
            pts += [cos_p * ex - sin_p * ey + cx, sin_p * ex + cos_p * ey + cy]
        out.append(tuple(pts))
        t += delta
    return out


class _State:
    __slots__ = ("fill", "stroke", "width", "alpha", "dashed", "dash", "join", "cap", "miter")

    def __init__(self, fill, stroke, width):
        self.fill, self.stroke, self.width = fill, stroke, width
        self.alpha = 1.0
        self.dashed = False
        self.dash = "3 3"
        self.join, self.cap, self.miter = "miter", "flat", 10.0

    def copy(self):
        s = _State(self.fill, self.stroke, self.width)
        for k in ("alpha", "dashed", "dash", "join", "cap", "miter"):
            setattr(s, k, getattr(self, k))
        return s


def draw_stencil(cr, stencil, x, y, w, h, fill="#000000", stroke=None, stroke_width=1.0):
    """Draw a stencil into the box x, y, w, h the way mxStencil.drawShape does: fixed
    aspect shapes are scaled evenly and centered, 'fill' and 'stroke' colors in the
    stencil mean the colors given here."""
    import cairo
    sx, sy = w / stencil.w, h / stencil.h
    x0, y0 = x, y
    if stencil.aspect == "fixed":
        sx = sy = min(sx, sy)
        x0 += (w - stencil.w * sx) / 2
        y0 += (h - stencil.h * sy) / 2
    min_scale = min(sx, sy)
    if stencil.strokewidth == "inherit":
        sw = stroke_width
    else:
        try:
            sw = float(stencil.strokewidth) * min_scale
        except ValueError:
            sw = min_scale
    base = {"fill": fill, "stroke": stroke}
    state = _State(fill, stroke, sw)
    stack = []
    cr.save()
    cr.new_path()

    def color(value):
        if value in base:
            return base[value]
        return value if _rgb(value) or value == "none" else base["fill"]

    def paint(do_fill, do_stroke):
        if do_fill and _rgb(state.fill):
            r, g, b = _rgb(state.fill)
            cr.set_source_rgba(r, g, b, state.alpha)
            cr.fill_preserve()
        if do_stroke and _rgb(state.stroke) and state.width > 0:
            r, g, b = _rgb(state.stroke)
            cr.set_source_rgba(r, g, b, state.alpha)
            cr.set_line_width(state.width)
            cr.set_line_join({"round": cairo.LINE_JOIN_ROUND, "bevel": cairo.LINE_JOIN_BEVEL}.get(
                state.join, cairo.LINE_JOIN_MITER))
            cr.set_line_cap({"round": cairo.LINE_CAP_ROUND, "square": cairo.LINE_CAP_SQUARE}.get(
                state.cap, cairo.LINE_CAP_BUTT))
            cr.set_miter_limit(state.miter)
            if state.dashed:
                try:
                    pat = [float(v) * state.width for v in state.dash.split() if v]
                except ValueError:
                    pat = [3 * state.width, 3 * state.width]
                cr.set_dash(pat if any(pat) else [])
            else:
                cr.set_dash([])
            cr.stroke_preserve()
        cr.new_path()

    def X(v):
        return x0 + v * sx

    def Y(v):
        return y0 + v * sy

    for steps in (stencil.bg, stencil.fg):
        for step in steps:
            op = step[0]
            if op == "path":
                cr.new_path()
                for s in step[1]:
                    k = s[0]
                    if k == "M":
                        cr.move_to(X(s[1]), Y(s[2]))
                    elif k == "L":
                        cr.line_to(X(s[1]), Y(s[2]))
                    elif k == "C":
                        cr.curve_to(X(s[1]), Y(s[2]), X(s[3]), Y(s[4]), X(s[5]), Y(s[6]))
                    elif k == "Q":
                        cx0, cy0 = cr.get_current_point() if cr.has_current_point() else (X(s[1]), Y(s[2]))
                        qx, qy, ex, ey = X(s[1]), Y(s[2]), X(s[3]), Y(s[4])
                        cr.curve_to(cx0 + 2 / 3 * (qx - cx0), cy0 + 2 / 3 * (qy - cy0),
                                    ex + 2 / 3 * (qx - ex), ey + 2 / 3 * (qy - ey), ex, ey)
                    elif k == "A":
                        if cr.has_current_point():
                            cx0, cy0 = cr.get_current_point()
                        else:
                            cx0, cy0 = X(s[6]), Y(s[7])
                            cr.move_to(cx0, cy0)
                        for c in arc_to_curves(cx0, cy0, s[1] * sx, s[2] * sy, s[3], s[4], s[5],
                                               X(s[6]), Y(s[7])):
                            cr.curve_to(*c)
                    elif k == "Z":
                        cr.close_path()
            elif op == "rect":
                cr.new_path()
                cr.rectangle(X(step[1]), Y(step[2]), step[3] * sx, step[4] * sy)
            elif op == "roundrect":
                cr.new_path()
                rw, rh = step[3] * sx, step[4] * sy
                factor = (step[5] or 15) / 100
                rounded_rect(cr, X(step[1]), Y(step[2]), rw, rh, min(rw * factor, rh * factor))
            elif op == "ellipse":
                cr.new_path()
                ew, eh = step[3] * sx, step[4] * sy
                if ew > 0 and eh > 0:
                    cr.save()
                    cr.translate(X(step[1]) + ew / 2, Y(step[2]) + eh / 2)
                    cr.scale(ew / 2, eh / 2)
                    cr.arc(0, 0, 1, 0, 2 * math.pi)
                    cr.restore()
            elif op == "fill":
                paint(True, False)
            elif op == "stroke":
                paint(False, True)
            elif op == "fillstroke":
                paint(True, True)
            elif op == "fillcolor":
                state.fill = color(step[1])
            elif op == "strokecolor":
                state.stroke = color(step[1])
            elif op == "alpha":
                state.alpha = max(0.0, min(1.0, float(step[1])))
            elif op == "strokewidth":
                state.width = step[1] * (1 if step[2] else min_scale)
            elif op == "dashed":
                state.dashed = step[1]
            elif op == "dashpattern":
                # draw.io scales the pattern here, then again by the line width.
                try:
                    state.dash = " ".join(str(float(v) * min_scale) for v in step[1].split() if v)
                except ValueError:
                    pass
            elif op == "linejoin":
                state.join = step[1]
            elif op == "linecap":
                state.cap = step[1]
            elif op == "miterlimit":
                state.miter = step[1]
            elif op == "save":
                stack.append(state.copy())
            elif op == "restore" and stack:
                state = stack.pop()
    cr.new_path()
    cr.restore()


def rounded_rect(cr, x, y, w, h, r):
    r = max(0.0, min(r, w / 2, h / 2))
    if r <= 0:
        cr.rectangle(x, y, w, h)
        return
    cr.new_sub_path()
    cr.arc(x + w - r, y + r, r, -math.pi / 2, 0)
    cr.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
    cr.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
    cr.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
    cr.close_path()


def abbreviation(name) -> str:
    """The stand-in glyph's text for a node kind or a draw.io shape name."""
    if name in ABBREV:
        return ABBREV[name]
    key = key_of(name)
    for word, short in (("vpc", "VPC"), ("region", "RGN"), ("security_group", "SN"),
                        ("internet_gateway", "IGW"), ("nat", "NAT"), ("endpoint", "VPCE"),
                        ("role", "ROLE"), ("bucket", "S3"), ("ec2", "EC2"), ("rds", "RDS")):
        if word in key:
            return short
    return (key[:3] or "?").upper()


def draw_glyph(cr, name, x, y, w, h, color):
    """A stand-in when the AWS icons aren't available: a short name, centered."""
    import cairo
    text = abbreviation(name)
    rgb = _rgb(color) or (0.5, 0.5, 0.5)
    cr.save()
    size = min(w, h)
    cr.set_source_rgb(*rgb)
    cr.set_line_width(max(size * 0.05, 0.5))
    rounded_rect(cr, x + size * 0.08, y + size * 0.08, w - size * 0.16, h - size * 0.16, size * 0.12)
    cr.stroke()
    cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
    fs = size * (0.36 if len(text) <= 3 else 0.27)
    cr.set_font_size(max(fs, 1))
    ext = cr.text_extents(text)
    cr.move_to(x + (w - ext.x_advance) / 2, y + h / 2 + ext.height / 2)
    cr.show_text(text)
    cr.new_path()
    cr.restore()
