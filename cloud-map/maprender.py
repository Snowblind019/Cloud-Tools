"""Draws a laid-out Cloud Map onto any cairo context. No GTK.

The viewer page, the SVG export and the PNG export all draw through Scene.render(), so
all three look the same. The drawing follows the .drawio export cell by cell: the same
Layout, the same theme table, the same AWS icons (see mapicons.py), the same rounded
corners, arrowheads, dashes and red flags, drawn in draw.io's layer order. Positions are
in draw.io page units, with the export's 40 px margin, so a point on the viewer's canvas
is the same point in the .drawio file.

Large maps stay smooth because render() only draws what's inside the visible area,
skips text that would be too small to read, and reuses icons it already drew at the
same size.
"""
from __future__ import annotations

import math
from collections import OrderedDict

from . import mapicons
from . import maplayout as ml
from .mapdrawio import GROUP_ICONS, MARGIN, shape_for
from .mapthemes import (CAPTION_SIZE, CARD_TITLE_SIZE, CONTAINER_TITLE_SIZE, EDGE_LABEL_SIZE,
                        card_colors, container_colors, theme)

FONT = "Helvetica, Arial, Liberation Sans, Nimbus Sans, DejaVu Sans, sans-serif"
TOY_FONT = "Arial" if __import__("os").name == "nt" else "Sans"
SELECT_COLOR = "#3584E4"
BOTH_WAYS = ("peering", "vpn", "tgw-attachment")
EDGE_RADIUS = 8          # arcSize=16 on edges
ARROW_SIZE = 6           # endSize=6
LEGEND_ARROW = 5
MIN_TEXT_PX = 2.5        # below this many pixels tall, text isn't drawn
MIN_ICON_PX = 5


def rgb(color):
    return mapicons._rgb(color)


def set_color(cr, color, alpha=1.0):
    c = rgb(color)
    if c is None:
        return False
    cr.set_source_rgba(c[0], c[1], c[2], alpha)
    return True


# =================================================================== text

class Text:
    """Draws single lines of text, through Pango when it's there (always with GTK, on
    Linux and in the Windows GTK bundle) and cairo's own text otherwise. Lines come
    already wrapped by the layout, so nothing here wraps."""

    def __init__(self):
        self.pango = None
        try:
            import gi
            gi.require_version("Pango", "1.0")
            gi.require_version("PangoCairo", "1.0")
            from gi.repository import Pango, PangoCairo
            self.pango = (Pango, PangoCairo)
        except (ImportError, ValueError):
            self.pango = None
        self.fonts = {}
        self.layouts = OrderedDict()

    def _font(self, size, bold):
        key = (size, bold)
        if key not in self.fonts:
            Pango = self.pango[0]
            desc = Pango.FontDescription.from_string(FONT)
            desc.set_weight(Pango.Weight.BOLD if bold else Pango.Weight.NORMAL)
            desc.set_absolute_size(size * Pango.SCALE)
            self.fonts[key] = desc
        return self.fonts[key]

    def _layout(self, cr, text, size, bold):
        Pango, PangoCairo = self.pango
        key = (text, size, bold)
        layout = self.layouts.get(key)
        if layout is None:
            layout = PangoCairo.create_layout(cr)
            try:
                import cairo
                fo = cairo.FontOptions()
                fo.set_hint_metrics(cairo.HINT_METRICS_OFF)
                fo.set_hint_style(cairo.HINT_STYLE_NONE)
                PangoCairo.context_set_font_options(layout.get_context(), fo)
            except (TypeError, AttributeError, ValueError):
                pass
            layout.set_font_description(self._font(size, bold))
            layout.set_text(text, -1)
            self.layouts[key] = layout
            if len(self.layouts) > 4000:
                self.layouts.popitem(last=False)
        else:
            self.layouts.move_to_end(key)
            PangoCairo.update_layout(cr, layout)
        return layout

    def width(self, cr, text, size, bold=False) -> float:
        if self.pango:
            ink, logical = self._layout(cr, text, size, bold).get_extents()
            return logical.width / self.pango[0].SCALE
        self._toy(cr, size, bold)
        return cr.text_extents(text).x_advance

    def _toy(self, cr, size, bold):
        import cairo
        cr.select_font_face(TOY_FONT, cairo.FONT_SLANT_NORMAL,
                            cairo.FONT_WEIGHT_BOLD if bold else cairo.FONT_WEIGHT_NORMAL)
        cr.set_font_size(size)

    def draw(self, cr, x, baseline, text, size, color, bold=False, align="left"):
        """One line with its baseline at y. align left, center or right of x."""
        if not text or not set_color(cr, color):
            return
        if self.pango:
            Pango, PangoCairo = self.pango
            layout = self._layout(cr, text, size, bold)
            if align != "left":
                _, logical = layout.get_extents()
                w = logical.width / Pango.SCALE
                x -= w / 2 if align == "center" else w
            cr.move_to(x, baseline - layout.get_baseline() / Pango.SCALE)
            PangoCairo.show_layout(cr, layout)
            cr.new_path()
            return
        self._toy(cr, size, bold)
        if align != "left":
            w = cr.text_extents(text).x_advance
            x -= w / 2 if align == "center" else w
        cr.move_to(x, baseline)
        cr.show_text(text)
        cr.new_path()


def baseline_in(line_top, step, size) -> float:
    """Baseline of a line of `size` text in a line box `step` tall, like an HTML label."""
    return line_top + (step + 0.7 * size) / 2


# =================================================================== geometry

def _side_point(rect, toward):
    """Where the line from rect's center toward a point leaves the rect."""
    x, y, w, h = rect
    cx, cy = x + w / 2, y + h / 2
    dx, dy = toward[0] - cx, toward[1] - cy
    if dx == 0 and dy == 0:
        return cx, cy
    tx = (w / 2) / abs(dx) if dx else math.inf
    ty = (h / 2) / abs(dy) if dy else math.inf
    t = min(tx, ty)
    return cx + dx * t, cy + dy * t


def fallback_route(s, t):
    """An orthogonal route when the layout left one to draw.io: straight down, across or
    up when the boxes overlap on one axis, otherwise a Z through the middle."""
    sx, sy, sw, sh = s
    tx, ty, tw, th = t
    if sx <= tx and sx + sw >= tx + tw and sy <= ty and sy + sh >= ty + th or \
            tx <= sx and tx + tw >= sx + sw and ty <= sy and ty + th >= sy + sh:
        # one is inside the other: a short line from the inner box's top
        inner, outer = (t, s) if sw * sh > tw * th else (s, t)
        ix, iy, iw, ih = inner
        a, b = (ix + iw / 2, iy), (ix + iw / 2, outer[1])
        return [a, b] if inner is s else [b, a]
    ox0, ox1 = max(sx, tx), min(sx + sw, tx + tw)
    oy0, oy1 = max(sy, ty), min(sy + sh, ty + th)
    if ox1 - ox0 >= 10:
        x = (ox0 + ox1) / 2
        return [(x, sy + sh), (x, ty)] if ty >= sy + sh else [(x, sy), (x, ty + th)]
    if oy1 - oy0 >= 10:
        y = (oy0 + oy1) / 2
        return [(sx + sw, y), (tx, y)] if tx >= sx + sw else [(sx, y), (tx + tw, y)]
    scx, scy, tcx, tcy = sx + sw / 2, sy + sh / 2, tx + tw / 2, ty + th / 2
    if ty >= sy + sh or ty + th <= sy:
        down = ty >= sy + sh
        y0, y1 = (sy + sh, ty) if down else (sy, ty + th)
        mid = (y0 + y1) / 2
        return [(scx, y0), (scx, mid), (tcx, mid), (tcx, y1)]
    right = tx >= sx + sw
    x0, x1 = (sx + sw, tx) if right else (sx, tx + tw)
    mid = (x0 + x1) / 2
    return [(x0, scy), (mid, scy), (mid, tcy), (x1, tcy)]


def path_length(pts) -> float:
    return sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(pts, pts[1:]))


def point_at(pts, frac):
    """The point frac of the way along a polyline, and its direction."""
    total = path_length(pts)
    if total == 0:
        return pts[0], (1, 0)
    want = total * frac
    for a, b in zip(pts, pts[1:]):
        seg = math.hypot(b[0] - a[0], b[1] - a[1])
        if seg and want <= seg:
            f = want / seg
            return (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f), \
                   ((b[0] - a[0]) / seg, (b[1] - a[1]) / seg)
        want -= seg
    a, b = pts[-2], pts[-1]
    seg = math.hypot(b[0] - a[0], b[1] - a[1]) or 1
    return b, ((b[0] - a[0]) / seg, (b[1] - a[1]) / seg)


def dist_to_path(pts, x, y) -> float:
    best = math.inf
    for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
        dx, dy = x2 - x1, y2 - y1
        seg = dx * dx + dy * dy
        t = 0 if seg == 0 else max(0, min(1, ((x - x1) * dx + (y - y1) * dy) / seg))
        px, py = x1 + t * dx, y1 + t * dy
        best = min(best, math.hypot(x - px, y - py))
    return best


def _intersects(a, b) -> bool:
    return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])


def _bbox(pts, pad=0):
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return (min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad)


# =================================================================== draw.io styles

def style_color(value, dark=True, default=None):
    """A color from a draw.io style: #RRGGBB, none, default, or light-dark(a, b)."""
    if value is None:
        return default
    v = str(value).strip()
    if v.startswith("light-dark(") and v.endswith(")"):
        parts = [p.strip() for p in v[len("light-dark("):-1].split(",")]
        if len(parts) == 2:
            v = parts[1] if dark else parts[0]
    if v in ("", "default", "inherit"):
        return default
    if v == "none":
        return "none"
    return v if rgb(v) is not None else default


# Numbers from a style or a hand-drawn cell are kept finite and within this, so an edited
# file can't put cairo into an error state (which would spoil the whole picture).
NUM_LIMIT = 200_000.0


def _num(value, default):
    try:
        v = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(v):
        return default
    return min(max(v, -NUM_LIMIT), NUM_LIMIT)


def _dash(cr, pattern):
    """cairo refuses a dash pattern with a negative entry or nothing but zeros."""
    if pattern and all(v >= 0 for v in pattern) and sum(pattern) > 0:
        cr.set_dash(pattern)
    else:
        cr.set_dash([])


def restyled(colors: dict, style, dark=True) -> dict:
    """Theme colors with the style changes made in draw.io on top (kept by layout
    memory): fill, line and text color, line width and dashes."""
    if not style:
        return colors
    out = dict(colors)
    out["fill"] = style_color(style.get("fillColor"), dark, out.get("fill"))
    out["stroke"] = style_color(style.get("strokeColor"), dark, out.get("stroke"))
    out["title"] = style_color(style.get("fontColor"), dark, out.get("title"))
    if "strokeWidth" in style:
        out["width"] = max(0.0, _num(style["strokeWidth"], out.get("width", 1)))
    if "dashed" in style:
        out["dashed"] = str(style["dashed"]) == "1"
    return out


def restyled_line(line: dict, style, dark=True) -> dict:
    out = dict(line)
    out["font"] = line.get("font") or line["color"]          # the label keeps its color
    out["color"] = style_color(style.get("strokeColor"), dark, out["color"])
    if out["color"] == "none":
        out["color"] = line["color"]
    if "fontColor" in style:
        out["font"] = style_color(style.get("fontColor"), dark, out["font"])
    if "strokeWidth" in style:
        out["width"] = max(0.0, _num(style["strokeWidth"], out["width"]))
    if "dashed" in style:
        out["dashed"] = str(style["dashed"]) == "1"
    return out


# =================================================================== hand-drawn cells

class Extra:
    """A cell drawn by hand in draw.io (a note, text, a shape or a line), which layout
    memory carries into every new export. Drawn here so the viewer matches the file."""
    __slots__ = ("id", "edge", "rect", "style", "text", "layer", "points", "source",
                 "target", "src_pt", "dst_pt", "parent")

    def __init__(self, cid):
        self.id = cid
        self.edge = False
        self.rect = None
        self.style = {}
        self.text = ""
        self.layer = "base"
        self.points = []
        self.source = self.target = None
        self.src_pt = self.dst_pt = None
        self.parent = ""


def label_lines(value) -> list:
    """A draw.io label (often HTML) as plain lines."""
    import html as _html
    import re
    text = re.sub(r"(?i)<br\s*/?>|</div>|</p>|</li>", "\n", str(value or ""))
    text = _html.unescape(re.sub(r"<[^>]+>", "", text))
    lines = [" ".join(line.split()) for line in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    while lines and not lines[0]:
        lines.pop(0)
    return lines


def read_extras(lay, rects) -> list:
    """Extra cells from layout memory, with positions in page units. rects are the
    boxes' page rectangles, for cells drawn inside a container."""
    import xml.etree.ElementTree as ET
    from .mapdrawio import LAYER_IDS, parse_style
    layer_of = {v: k for k, v in LAYER_IDS.items()}
    box_layer = {b.id: b.layer for b in lay.boxes}
    items = {}
    for raw in getattr(lay, "extra", None) or []:
        try:
            el = ET.fromstring(raw)
        except ET.ParseError:
            continue
        cell = el if el.tag == "mxCell" else el.find("mxCell")
        cid = el.get("id")
        if cell is None or not cid or (cell.get("vertex") != "1" and cell.get("edge") != "1"):
            continue
        x = Extra(cid)
        x.edge = cell.get("edge") == "1"
        x.style = parse_style(cell.get("style", ""))
        x.text = el.get("label", "") if el is not cell else cell.get("value", "")
        x.parent = cell.get("parent", "")
        x.source, x.target = cell.get("source"), cell.get("target")
        geo = cell.find("mxGeometry")
        if geo is not None:
            if not x.edge:
                x.rect = tuple(_num(geo.get(k), d) for k, d in
                               (("x", 0), ("y", 0), ("width", 80), ("height", 40)))
            for pt in geo.findall("mxPoint"):
                p = (_num(pt.get("x"), 0), _num(pt.get("y"), 0))
                if pt.get("as") == "sourcePoint":
                    x.src_pt = p
                elif pt.get("as") == "targetPoint":
                    x.dst_pt = p
            arr = geo.find("Array")
            if arr is not None:
                x.points = [(_num(p.get("x"), 0), _num(p.get("y"), 0)) for p in arr.findall("mxPoint")]
        items[cid] = x

    # Page positions: a cell inside a container or a group is relative to it.
    origin = {}

    def origin_of(pid, depth=0):
        if pid in layer_of or not pid or depth > 32:
            return (0.0, 0.0)
        if pid in rects:
            return rects[pid][:2]
        if pid in origin:
            return origin[pid]
        p = items.get(pid)
        if p is None or p.rect is None:
            return (0.0, 0.0)
        ox, oy = origin_of(p.parent, depth + 1)
        origin[pid] = (ox + p.rect[0], oy + p.rect[1])
        return origin[pid]

    def layer(pid, depth=0):
        if pid in layer_of:
            return layer_of[pid]
        if pid in box_layer:
            return box_layer[pid]
        p = items.get(pid)
        return layer(p.parent, depth + 1) if p is not None and depth < 32 else "base"
    out = []
    for x in items.values():
        ox, oy = origin_of(x.parent)
        x.layer = layer(x.parent)
        if x.rect is not None:
            x.rect = (ox + x.rect[0], oy + x.rect[1], x.rect[2], x.rect[3])
        x.points = [(ox + px, oy + py) for px, py in x.points]
        if x.src_pt:
            x.src_pt = (ox + x.src_pt[0], oy + x.src_pt[1])
        if x.dst_pt:
            x.dst_pt = (ox + x.dst_pt[0], oy + x.dst_pt[1])
        out.append(x)
    for x in out:
        if x.edge:
            ends = {}
            for end, pt in (("source", x.src_pt), ("target", x.dst_pt)):
                ref = getattr(x, end)
                r = rects.get(ref) if ref else None
                if r is None and ref in items and items[ref].rect is not None:
                    r = items[ref].rect
                ends[end] = (r, pt)
            x.rect = None
            x.src_pt, x.dst_pt = _edge_ends(ends["source"], ends["target"], x.points)
    return [x for x in out if x.rect is not None or (x.edge and x.src_pt and x.dst_pt)]


def _edge_ends(src, dst, points):
    """Where a hand-drawn line starts and ends: on the box it's connected to, toward its
    first or last waypoint, or at its own loose end."""
    (sr, sp), (tr, tp) = src, dst

    def center(r):
        return (r[0] + r[2] / 2, r[1] + r[3] / 2)
    s_ref = sp if sr is None else center(sr)
    t_ref = tp if tr is None else center(tr)
    if s_ref is None or t_ref is None:
        return None, None
    a = _side_point(sr, points[0] if points else t_ref) if sr is not None else sp
    b = _side_point(tr, points[-1] if points else s_ref) if tr is not None else tp
    return a, b


# =================================================================== the scene

class Scene:
    """A Layout ready to draw and to hit test. Everything is in page units (layout
    coordinates plus the export margin)."""

    def __init__(self, layout, theme_name="dark", icons=None, problems=None):
        self.lay = layout
        self.theme_name = theme_name
        self.th = theme(theme_name)
        self.dark = theme_name == "dark"
        self.icons = icons if icons is not None else mapicons.default_icons()
        self.text = Text()
        self.width = layout.width + 2 * MARGIN
        self.height = layout.height + 2 * MARGIN
        self.boxes = {b.id: b for b in layout.boxes}
        self.links = {lk.id: lk for lk in layout.links}
        self.rects = {b.id: (b.ax + MARGIN, b.ay + MARGIN, b.w, b.h) for b in layout.boxes}
        self.depth = {}
        for b in layout.boxes:
            d, cur, seen = 0, b, set()
            while cur is not None and cur.parent and cur.parent not in seen:
                seen.add(cur.parent)
                cur = self.boxes.get(cur.parent)
                d += 1
            self.depth[b.id] = d
        self.paths = {lk.id: self._path(lk) for lk in layout.links}
        self.icon_cache = OrderedDict()
        # Extra red marks, for designs: box id -> list of problem texts.
        self.problems = dict(problems or {})
        self.extras = read_extras(layout, self.rects)
        self.order = self._order()

    # ---- geometry
    def _path(self, link):
        s, t = self.rects.get(link.src), self.rects.get(link.dst)
        if s is None or t is None:
            return []
        if link.exit is not None and link.entry is not None:
            a = (s[0] + link.exit[0] * s[2], s[1] + link.exit[1] * s[3])
            b = (t[0] + link.entry[0] * t[2], t[1] + link.entry[1] * t[3])
            pts = [a] + [(x + MARGIN, y + MARGIN) for x, y in link.points] + [b]
        else:
            pts = fallback_route(s, t)
        out = [pts[0]]
        for p in pts[1:]:
            if abs(p[0] - out[-1][0]) > 0.01 or abs(p[1] - out[-1][1]) > 0.01:
                out.append(p)
        return out if len(out) > 1 else [pts[0], pts[-1]]

    def _order(self):
        """(kind, object, bbox) in drawing order: each draw.io layer in turn, its shapes,
        then its lines, then its text."""
        items = []
        layers = [name for name, _ in ml.LAYERS]
        for layer in layers:
            for b in self.lay.boxes:
                if b.layer == layer:
                    x, y, w, h = self.rects[b.id]
                    pad = 30 if b.role in ("container",) else 4
                    items.append(("box", b, (x - 4, y - pad, x + w + 4, y + h + 4)))
            for lk in self.lay.links:
                if lk.layer == layer and self.paths.get(lk.id):
                    items.append(("link", lk, _bbox(self.paths[lk.id], 40)))
            if layer == "flags":
                for b in self.lay.boxes:
                    if b.flags or b.id in self.problems:
                        x, y, w, h = self.rects[b.id]
                        items.append(("flag", b, (x - 10, y - 10, x + w + 10, y + h + 10)))
                for lk in self.lay.links:
                    if lk.flags and self.paths.get(lk.id):
                        items.append(("flag-link", lk, _bbox(self.paths[lk.id], 10)))
            for x in self.extras:
                if x.layer == layer:
                    pts = [x.src_pt, x.dst_pt] + x.points if x.edge else \
                        [(x.rect[0], x.rect[1] - 2), (x.rect[0] + x.rect[2], x.rect[1] + x.rect[3] * 2)]
                    items.append(("extra", x, _bbox(pts, 30)))
            if layer == "legend":
                for e in self.lay.legend:
                    x, y = e.x + MARGIN, e.y + MARGIN
                    items.append(("legend", e, (x, y, x + 380, y + 20)))
            for t in self.lay.texts:
                if t.layer == layer:
                    x, y = t.x + MARGIN, t.y + MARGIN
                    items.append(("text", t, (x, y, x + t.w, y + t.h)))
        return items

    # ---- hit testing
    def hit(self, x, y, tolerance=4.0):
        """What's under a page point: ("badge", box id), ("link", link id), ("box", box id)
        or None. Red badges come first, then lines, then the innermost box."""
        for b in self.lay.boxes:
            if b.flags or b.id in self.problems:
                bx, by, bw, bh = self.rects[b.id]
                if math.hypot(x - (bx + bw - 2), y - (by + 2)) <= 10 + tolerance / 2:
                    return ("badge", b.id)
        best, best_d = None, tolerance
        for lk in self.lay.links:
            pts = self.paths.get(lk.id)
            if not pts:
                continue
            d = dist_to_path(pts, x, y)
            if d <= best_d:
                best, best_d = lk.id, d
        if best is not None:
            return ("link", best)
        found = None
        for b in self.lay.boxes:
            bx, by, bw, bh = self.rects[b.id]
            if bx <= x <= bx + bw and by <= y <= by + bh:
                if b.layer != "base":
                    return ("box", b.id)          # detail cards float above everything
                if found is None or self.depth[b.id] >= self.depth[found]:
                    found = b.id
        return ("box", found) if found else None

    def box_at(self, x, y):
        got = self.hit(x, y, 0)
        return got[1] if got and got[0] in ("box", "badge") else None

    # ---- drawing
    def render(self, cr, view=None, scale=1.0, vector=False, background=True):
        """Draw onto cr in page units. view is the visible page rect (x0, y0, x1, y1), or
        None for everything. scale is device pixels per page unit, which decides how small
        text can get before it's skipped. vector=True draws icons as paths every time,
        for SVG and PNG files."""
        self.scale = max(scale, 1e-6)
        self.vector = vector
        if background:
            set_color(cr, self.th["page"])
            if view is None:
                cr.rectangle(0, 0, self.width, self.height)
            else:
                cr.rectangle(view[0], view[1], view[2] - view[0], view[3] - view[1])
            cr.fill()
        for kind, obj, bbox in self.order:
            if view is not None and not _intersects(bbox, view):
                continue
            if kind == "box":
                self.draw_box(cr, obj)
            elif kind == "link":
                self.draw_link(cr, obj)
            elif kind == "flag":
                self.draw_flag(cr, obj)
            elif kind == "flag-link":
                self.draw_link(cr, obj, flag=True)
            elif kind == "legend":
                self.draw_legend(cr, obj)
            elif kind == "text":
                self.draw_text_block(cr, obj)
            elif kind == "extra":
                self.draw_extra(cr, obj)

    def _text_ok(self, size):
        return size * self.scale >= MIN_TEXT_PX

    def lines(self, cr, x, top, title_lines, caption_lines, title_size, title_color,
              caption_color, title_step, caption_step=16, gap=0):
        y = top
        if self._text_ok(title_size):
            for line in title_lines:
                self.text.draw(cr, x, baseline_in(y, title_step, title_size), line, title_size,
                               title_color, bold=True)
                y += title_step
        else:
            y += title_step * len(title_lines)
        y += gap
        if caption_lines and self._text_ok(CAPTION_SIZE):
            for line in caption_lines:
                self.text.draw(cr, x, baseline_in(y, caption_step, CAPTION_SIZE), line,
                               CAPTION_SIZE, caption_color)
                y += caption_step

    def draw_box(self, cr, box):
        if box.role == "container":
            self.draw_container(cr, box)
        else:
            self.draw_card(cr, box)

    def draw_container(self, cr, box):
        c = restyled(container_colors(self.th, box.kind, box.props), box.hints.get("style"),
                     self.dark)
        x, y, w, h = self.rects[box.id]
        width = c["width"]
        if box.kind in ml.GROUP_SHAPES:
            cr.rectangle(x, y, w, h)
            pattern = [3 * width, 3 * width] if c["dashed"] else []
        else:
            arc = 20 if box.kind == "org" else 12
            mapicons.rounded_rect(cr, x, y, w, h, arc / 2)
            pattern = [6 * width, 4 * width] if c["dashed"] else []
        if set_color(cr, c["fill"]):
            cr.fill_preserve()
        if set_color(cr, c["stroke"]):
            cr.set_line_width(width)
            _dash(cr, pattern)
            cr.stroke_preserve()
            cr.set_dash([])
        cr.new_path()
        if box.kind in ml.GROUP_SHAPES:
            self.icon(cr, GROUP_ICONS[box.kind], box.kind, x, y, 24, None, c["stroke"],
                      group=True)
        elif box.icon:
            ix, iy, size = box.icon
            self.icon(cr, shape_for(box) or "generic", box.kind, x + ix, y + iy, size, None,
                      c["caption"])
        tx, ty, _ = box.text
        self.lines(cr, x + tx, y + ty, box.title_lines, box.caption_lines,
                   CONTAINER_TITLE_SIZE, c["title"], c["caption"], 18, 16)

    def draw_card(self, cr, box):
        colors = restyled(dict(card_colors(self.th, box.category), width=1,
                               dashed=box.role == "more"), box.hints.get("style"), self.dark)
        x, y, w, h = self.rects[box.id]
        chip = box.role == "chip"
        mapicons.rounded_rect(cr, x, y, w, h, 4 if chip else 5)
        if set_color(cr, colors["fill"]):
            cr.fill_preserve()
        if set_color(cr, colors["stroke"]):
            sw = colors["width"]
            cr.set_line_width(sw)
            _dash(cr, [4 * sw, 3 * sw] if colors["dashed"] else [])
            cr.stroke_preserve()
            cr.set_dash([])
        cr.new_path()
        if box.icon:
            ix, iy, size = box.icon
            self.icon(cr, shape_for(box) or "generic", box.kind, x + ix, y + iy, size,
                      colors["icon_fill"], colors["glyph"])
        tx, ty, _ = box.text
        size = CAPTION_SIZE + 1 if chip else CARD_TITLE_SIZE
        self.lines(cr, x + tx, y + ty, box.title_lines, box.caption_lines, size,
                   colors["title"], colors["caption"], 16, 16)

    def icon(self, cr, shape, kind, x, y, size, fill, glyph, group=False):
        """draw.io's resourceIcon (a square in fill, the stencil in glyph, 10% in from the
        edges) or, for group=True, its group corner icon (the stencil fills the square)."""
        px = size * self.scale
        if px < MIN_ICON_PX:
            if fill and set_color(cr, fill):
                cr.rectangle(x, y, size, size)
                cr.fill()
            return
        if not self.vector and px <= 256:
            key = (shape, kind, fill, glyph, group, int(round(px)))
            surf = self.icon_cache.get(key)
            if surf is None:
                surf = self._icon_surface(shape, kind, fill, glyph, group, int(round(px)))
                self.icon_cache[key] = surf
                if len(self.icon_cache) > 800:
                    self.icon_cache.popitem(last=False)
            else:
                self.icon_cache.move_to_end(key)
            cr.save()
            cr.translate(x, y)
            n = int(round(px))
            cr.scale(size / n, size / n)
            cr.set_source_surface(surf, 0, 0)
            cr.paint()
            cr.restore()
            return
        self._icon_vector(cr, shape, kind, x, y, size, fill, glyph, group)

    def _icon_surface(self, shape, kind, fill, glyph, group, px):
        import cairo
        surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, max(px, 1), max(px, 1))
        c2 = cairo.Context(surf)
        self._icon_vector(c2, shape, kind, 0, 0, px, fill, glyph, group)
        surf.flush()
        return surf

    def _icon_vector(self, cr, shape, kind, x, y, size, fill, glyph, group):
        stencil = self.icons.get(shape) if self.icons is not None else None
        if not group and fill and set_color(cr, fill):
            cr.rectangle(x, y, size, size)
            cr.fill()
        if stencil is not None:
            if group:
                mapicons.draw_stencil(cr, stencil, x, y, size, size, fill=glyph)
            else:
                mapicons.draw_stencil(cr, stencil, x + size * 0.1, y + size * 0.1,
                                      size * 0.8, size * 0.8, fill=glyph)
            return
        if group and set_color(cr, glyph):
            cr.rectangle(x, y, size, size)
            cr.fill()
            mapicons.draw_glyph(cr, kind, x, y, size, size, self.th["page"])
            return
        mapicons.draw_glyph(cr, kind, x, y, size, size, glyph)

    # ---- lines
    def _rounded_path(self, cr, pts, radius=EDGE_RADIUS):
        cr.move_to(*pts[0])
        for i in range(1, len(pts) - 1):
            p0, p1, p2 = pts[i - 1], pts[i], pts[i + 1]
            d1 = math.hypot(p1[0] - p0[0], p1[1] - p0[1])
            d2 = math.hypot(p2[0] - p1[0], p2[1] - p1[1])
            r = min(radius, d1 / 2, d2 / 2)
            if r <= 0.5:
                cr.line_to(*p1)
                continue
            a = (p1[0] - (p1[0] - p0[0]) / d1 * r, p1[1] - (p1[1] - p0[1]) / d1 * r)
            b = (p1[0] + (p2[0] - p1[0]) / d2 * r, p1[1] + (p2[1] - p1[1]) / d2 * r)
            cr.line_to(*a)
            cr.curve_to(a[0] + (p1[0] - a[0]) * 0.55, a[1] + (p1[1] - a[1]) * 0.55,
                        b[0] + (p1[0] - b[0]) * 0.55, b[1] + (p1[1] - b[1]) * 0.55, b[0], b[1])
        cr.line_to(*pts[-1])

    def _arrow(self, cr, tip, direction, size, sw, color):
        """draw.io's block arrow: returns how far the line has to stop short of the tip."""
        ux, uy = direction
        off = sw * 1.118
        px, py = tip[0] - ux * off, tip[1] - uy * off
        L = size + sw
        ax, ay = ux * L, uy * L
        cr.move_to(px, py)
        cr.line_to(px - ax - ay / 2, py - ay + ax / 2)
        cr.line_to(px + ay / 2 - ax, py - ay - ax / 2)
        cr.close_path()
        set_color(cr, color)
        cr.fill_preserve()
        cr.set_line_width(sw)
        cr.set_dash([])
        cr.stroke()
        return L + off

    @staticmethod
    def _shorten(pts, at_end, amount):
        pts = list(pts)
        if at_end:
            a, b = pts[-2], pts[-1]
        else:
            a, b = pts[1], pts[0]
        d = math.hypot(b[0] - a[0], b[1] - a[1])
        if d <= 0:
            return pts
        f = max(0.0, (d - amount) / d)
        new = (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f)
        if at_end:
            pts[-1] = new
        else:
            pts[0] = new
        return pts

    def line_style(self, kind):
        edges = self.th["edges"]
        return edges.get(kind) or edges["trust"]

    def draw_link(self, cr, link, flag=False, color=None, width=None, label=True):
        pts = self.paths.get(link.id)
        if not pts or len(pts) < 2:
            return
        style = self.line_style("flag" if flag else link.kind)
        if not flag and link.hints.get("style"):
            style = restyled_line(style, link.hints["style"], self.dark)
        color = color or style["color"]
        sw = width or style["width"]
        both = link.kind in BOTH_WAYS
        line = list(pts)

        def direction(a, b):
            d = math.hypot(b[0] - a[0], b[1] - a[1]) or 1
            return ((b[0] - a[0]) / d, (b[1] - a[1]) / d)
        end_dir = direction(pts[-2], pts[-1])
        start_dir = direction(pts[1], pts[0])
        cr.save()
        cut = self._arrow(cr, pts[-1], end_dir, ARROW_SIZE, sw, color)
        line = self._shorten(line, True, cut)
        if both:
            cut = self._arrow(cr, pts[0], start_dir, ARROW_SIZE, sw, color)
            line = self._shorten(line, False, cut)
        self._rounded_path(cr, line)
        set_color(cr, color)
        cr.set_line_width(sw)
        _dash(cr, [6 * sw, 4 * sw] if style["dashed"] else [])
        cr.stroke()
        cr.restore()
        if label and link.label and not flag and self._text_ok(EDGE_LABEL_SIZE):
            (lx, ly), _ = point_at(pts, 0.5)
            w = self.text.width(cr, link.label, EDGE_LABEL_SIZE)
            if set_color(cr, self.th["label_background"]):
                cr.rectangle(lx - w / 2 - 1, ly - 7, w + 2, 14)
                cr.fill()
            self.text.draw(cr, lx, ly + 3.5, link.label, EDGE_LABEL_SIZE,
                           style.get("font") or style["color"], align="center")

    # ---- flags, legend, text
    def draw_flag(self, cr, box):
        fl = self.th["flagged"]
        x, y, w, h = self.rects[box.id]
        mapicons.rounded_rect(cr, x - 4, y - 4, w + 8, h + 8, 6)
        set_color(cr, fl["stroke"])
        cr.set_line_width(2.5)
        cr.set_dash([])
        cr.stroke()
        cr.arc(x + w - 2, y + 2, 10, 0, 2 * math.pi)
        set_color(cr, fl["fill"])
        cr.fill()
        if self._text_ok(12):
            self.text.draw(cr, x + w - 2, y + 2 + 4.3, "!", 12, fl["text"], bold=True,
                           align="center")

    def draw_legend(self, cr, entry):
        th = self.th
        x, y = entry.x + MARGIN, entry.y + MARGIN
        if entry.style == "flag":
            mapicons.rounded_rect(cr, x, y + 2, 40, 16, 3)
            set_color(cr, th["flagged"]["stroke"])
            cr.set_line_width(2.5)
            cr.stroke()
        else:
            style = self.line_style(entry.style)
            sw = style["width"]
            pts = [(x, y + 10), (x + 40, y + 10)]
            cut = self._arrow(cr, pts[1], (1, 0), LEGEND_ARROW, sw, style["color"])
            pts[1] = (pts[1][0] - cut, pts[1][1])
            if entry.style in BOTH_WAYS:
                cut = self._arrow(cr, pts[0], (-1, 0), LEGEND_ARROW, sw, style["color"])
                pts[0] = (pts[0][0] + cut, pts[0][1])
            cr.move_to(*pts[0])
            cr.line_to(*pts[1])
            set_color(cr, style["color"])
            cr.set_line_width(sw)
            _dash(cr, [6 * sw, 4 * sw] if style["dashed"] else [])
            cr.stroke()
            cr.set_dash([])
        if self._text_ok(12):
            self.text.draw(cr, x + 52, baseline_in(y, 20, 12), entry.label, 12,
                           th["legend_text"])

    def draw_text_block(self, cr, t):
        x, y = t.x + MARGIN, t.y + MARGIN
        if t.style == "strip":
            if self._text_ok(11):
                self.text.draw(cr, x + 2, baseline_in(y, t.h, 11), t.lines[0] if t.lines else "",
                               11, self.th["dim"], bold=True)
            return
        if not self._text_ok(11):
            return
        for i, line in enumerate(t.lines):
            self.text.draw(cr, x, baseline_in(y + 14 * i, 14, 11), line, 11, self.th["footnote"])

    # ---- cells drawn by hand in draw.io
    # draw.io's own defaults (black on white): the file says adaptiveColors="none", so
    # draw.io doesn't swap colors for the dark page either. Shapes drawn in AWS Kit's
    # editor get the theme's colors written into their style (see mapeditor.py).
    EXTRA_FILL, EXTRA_STROKE, EXTRA_FONT = "#FFFFFF", "#000000", "#000000"

    def draw_extra(self, cr, x):
        st = x.style
        dark = self.dark
        alpha = _num(st.get("opacity"), 100) / 100
        if alpha < 1:
            cr.push_group()
        if x.edge:
            self._extra_edge(cr, x, st, dark)
        else:
            self._extra_vertex(cr, x, st, dark)
        if alpha < 1:
            cr.pop_group_to_source()
            cr.paint_with_alpha(max(alpha, 0))

    def _extra_vertex(self, cr, x, st, dark):
        rx, ry, w, h = x.rect
        shape = st.get("shape", "")
        text_only = shape == "text"
        fill = style_color(st.get("fillColor"), dark, "none" if text_only else self.EXTRA_FILL)
        stroke = style_color(st.get("strokeColor"), dark, "none" if text_only else self.EXTRA_STROKE)
        sw = max(0.0, _num(st.get("strokeWidth"), 1))
        dashed = st.get("dashed") == "1"
        label_rect = (rx, ry, w, h)
        if shape.startswith("mxgraph.aws4."):
            self._extra_aws(cr, x, st, dark, shape)
            if st.get("verticalLabelPosition") == "bottom":
                label_rect = (rx - w / 2, ry + h, w * 2, 0)
        else:
            if shape == "ellipse":
                cr.save()
                cr.translate(rx + w / 2, ry + h / 2)
                cr.scale(max(w / 2, 0.01), max(h / 2, 0.01))
                cr.arc(0, 0, 1, 0, 2 * math.pi)
                cr.restore()
            elif shape == "rhombus":
                cr.move_to(rx + w / 2, ry)
                cr.line_to(rx + w, ry + h / 2)
                cr.line_to(rx + w / 2, ry + h)
                cr.line_to(rx, ry + h / 2)
                cr.close_path()
            elif st.get("rounded") == "1":
                arc = _num(st.get("arcSize"), 15)
                r = arc / 2 if st.get("absoluteArcSize") == "1" else min(w, h) * arc / 100
                mapicons.rounded_rect(cr, rx, ry, w, h, max(0.0, min(r, w / 2, h / 2)))
            else:
                cr.rectangle(rx, ry, w, h)
            if fill != "none" and set_color(cr, fill):
                cr.fill_preserve()
            if stroke != "none" and set_color(cr, stroke):
                cr.set_line_width(sw)
                _dash(cr, [3 * sw, 3 * sw] if dashed else [])
                cr.stroke_preserve()
                cr.set_dash([])
            cr.new_path()
        self._extra_label(cr, x.text, label_rect, st, dark)

    def _extra_aws(self, cr, x, st, dark, shape):
        rx, ry, w, h = x.rect
        fill = style_color(st.get("fillColor"), dark, "#ED7100")
        glyph = style_color(st.get("strokeColor"), dark, "#FFFFFF")
        if shape == "mxgraph.aws4.resourceIcon":
            icon = str(st.get("resIcon", ""))
            size = min(w, h)
            self.icon(cr, icon, icon, rx + (w - size) / 2, ry + (h - size) / 2, size,
                      None if fill == "none" else fill, glyph)
            return
        stencil = self.icons.get(shape) if self.icons is not None else None
        if stencil is not None:
            mapicons.draw_stencil(cr, stencil, rx, ry, w, h, fill=None if fill == "none" else fill,
                                  stroke=glyph if glyph != "none" else None)
        else:
            mapicons.rounded_rect(cr, rx, ry, w, h, 3)
            if set_color(cr, fill if fill != "none" else "#5F5E5A"):
                cr.fill()

    def _wrap(self, cr, line, size, bold, width):
        words = line.split(" ")
        out, cur = [], ""
        for word in words:
            test = f"{cur} {word}" if cur else word
            if cur and self.text.width(cr, test, size, bold) > width:
                out.append(cur)
                cur = word
            else:
                cur = test
        out.append(cur)
        return out

    def _extra_label(self, cr, value, rect, st, dark):
        lines = label_lines(value)
        size = _num(st.get("fontSize"), 12)
        if not lines or not self._text_ok(size):
            return
        color = style_color(st.get("fontColor"), dark, self.EXTRA_FONT)
        if color == "none":
            return
        bold = int(_num(st.get("fontStyle"), 0)) & 1 == 1
        rx, ry, w, h = rect
        spacing = _num(st.get("spacing"), 2)
        inner = max(w - 2 * spacing, 1)
        if st.get("whiteSpace") == "wrap" and w > 0:
            wrapped = []
            for line in lines:
                wrapped += self._wrap(cr, line, size, bold, inner)
            lines = wrapped
        step = size * 1.2
        total = step * len(lines)
        valign = st.get("verticalAlign", "middle" if h else "top")
        top = ry + spacing if valign == "top" else \
            (ry + h - spacing - total if valign == "bottom" else ry + (h - total) / 2)
        align = st.get("align", "center")
        ax = rx + spacing if align == "left" else (rx + w - spacing if align == "right" else rx + w / 2)
        for i, line in enumerate(lines):
            self.text.draw(cr, ax, baseline_in(top + i * step, step, size), line, size, color,
                           bold=bold, align=align if align in ("left", "right") else "center")

    def _extra_edge(self, cr, x, st, dark):
        pts = [x.src_pt] + list(x.points) + [x.dst_pt]
        if not x.points and st.get("edgeStyle") in ("orthogonalEdgeStyle", "elbowEdgeStyle"):
            (ax, ay), (bx, by) = pts[0], pts[-1]
            if abs(ax - bx) > 1 and abs(ay - by) > 1:
                if abs(bx - ax) >= abs(by - ay):
                    mid = (ax + bx) / 2
                    pts = [pts[0], (mid, ay), (mid, by), pts[-1]]
                else:
                    mid = (ay + by) / 2
                    pts = [pts[0], (ax, mid), (bx, mid), pts[-1]]
        if len(pts) < 2:
            return
        color = style_color(st.get("strokeColor"), dark, self.EXTRA_STROKE)
        if color == "none":
            return
        sw = _num(st.get("strokeWidth"), 1)

        def direction(a, b):
            d = math.hypot(b[0] - a[0], b[1] - a[1]) or 1
            return ((b[0] - a[0]) / d, (b[1] - a[1]) / d)
        line = list(pts)
        cr.save()
        if st.get("endArrow", "classic") != "none":
            cut = self._arrow(cr, pts[-1], direction(pts[-2], pts[-1]),
                              _num(st.get("endSize"), 6), sw, color)
            line = self._shorten(line, True, cut)
        if st.get("startArrow", "none") != "none":
            cut = self._arrow(cr, pts[0], direction(pts[1], pts[0]),
                              _num(st.get("startSize"), 6), sw, color)
            line = self._shorten(line, False, cut)
        if st.get("rounded") == "1":
            self._rounded_path(cr, line, 10)
        else:
            cr.move_to(*line[0])
            for p in line[1:]:
                cr.line_to(*p)
        set_color(cr, color)
        cr.set_line_width(sw)
        _dash(cr, [3 * sw, 3 * sw] if st.get("dashed") == "1" else [])
        cr.stroke()
        cr.restore()
        if x.text:
            (lx, ly), _ = point_at(pts, 0.5)
            size = _num(st.get("fontSize"), 11)
            lines = label_lines(x.text)
            font = style_color(st.get("fontColor"), dark, self.EXTRA_FONT)
            bg = style_color(st.get("labelBackgroundColor"), dark, self.th["page"])
            if lines and self._text_ok(size) and font != "none":
                step = size * 1.2
                top = ly - step * len(lines) / 2
                wmax = max(self.text.width(cr, ln, size) for ln in lines)
                if bg != "none" and set_color(cr, bg):
                    cr.rectangle(lx - wmax / 2 - 2, top, wmax + 4, step * len(lines))
                    cr.fill()
                for i, ln in enumerate(lines):
                    self.text.draw(cr, lx, baseline_in(top + i * step, step, size), ln, size,
                                   font, align="center")

    # ---- the viewer's highlights, drawn on top in screen-sized strokes
    def draw_selection(self, cr, box_id=None, link_id=None, hover_id=None, px=1.0):
        """px: page units per screen pixel, so outlines stay the same width at any zoom."""
        self.scale = 1 / px if px else 1.0
        if hover_id and hover_id in self.rects and hover_id != box_id:
            x, y, w, h = self.rects[hover_id]
            mapicons.rounded_rect(cr, x - 2 * px, y - 2 * px, w + 4 * px, h + 4 * px, 6)
            set_color(cr, SELECT_COLOR, 0.45)
            cr.set_line_width(2 * px)
            cr.stroke()
        if link_id and link_id in self.links:
            link = self.links[link_id]
            self.draw_link(cr, link, color=SELECT_COLOR, width=max(3 * px, 2.5), label=False)
            for end in (link.src, link.dst):
                if end in self.rects:
                    x, y, w, h = self.rects[end]
                    mapicons.rounded_rect(cr, x - 3 * px, y - 3 * px, w + 6 * px, h + 6 * px, 6)
                    set_color(cr, SELECT_COLOR)
                    cr.set_line_width(2.5 * px)
                    cr.stroke()
        if box_id and box_id in self.rects:
            x, y, w, h = self.rects[box_id]
            mapicons.rounded_rect(cr, x - 3 * px, y - 3 * px, w + 6 * px, h + 6 * px, 7)
            set_color(cr, SELECT_COLOR)
            cr.set_line_width(3 * px)
            cr.stroke()


# =================================================================== the viewer's view

class Viewport:
    """Pan and zoom for the viewer: which page point sits at the screen's top left, and
    how many screen pixels one page unit takes. Kept here, without GTK, so hit testing at
    any zoom can be tested on its own."""

    def __init__(self, zoom=1.0, ox=0.0, oy=0.0, zoom_min=0.04, zoom_max=8.0):
        self.zoom, self.ox, self.oy = zoom, ox, oy
        self.zoom_min, self.zoom_max = zoom_min, zoom_max

    def to_page(self, x, y):
        return self.ox + x / self.zoom, self.oy + y / self.zoom

    def to_screen(self, px, py):
        return (px - self.ox) * self.zoom, (py - self.oy) * self.zoom

    def visible(self, width, height):
        return (self.ox, self.oy, self.ox + width / self.zoom, self.oy + height / self.zoom)

    def zoom_at(self, zoom, anchor):
        """Zoom, keeping the page point under anchor (screen coordinates) where it is."""
        zoom = min(max(zoom, self.zoom_min), self.zoom_max)
        px, py = self.to_page(*anchor)
        self.zoom = zoom
        self.ox = px - anchor[0] / zoom
        self.oy = py - anchor[1] / zoom

    def center_on(self, px, py, width, height):
        self.ox = px - width / 2 / self.zoom
        self.oy = py - height / 2 / self.zoom

    def fit(self, scene_w, scene_h, width, height, margin=0.98):
        # A map smaller than the window is shown at 100% instead of blown up.
        zoom = min(width / scene_w * margin, height / scene_h * margin, 1.0)
        self.zoom = min(max(zoom, self.zoom_min), self.zoom_max)
        self.center_on(scene_w / 2, scene_h / 2, width, height)


# =================================================================== files

# cairo's image surfaces stop at 32767 pixels a side; past about 100 megapixels a PNG
# takes gigabytes of memory to draw.
MAX_SIDE = 32000
MAX_PIXELS = 100_000_000


def png_scale(scene, scale) -> float:
    """scale, made smaller when the map would be too big a picture at it."""
    w, h = max(scene.width, 1), max(scene.height, 1)
    fit = min(MAX_SIDE / w, MAX_SIDE / h, math.sqrt(MAX_PIXELS / (w * h)))
    if fit < 0.25:
        raise ValueError("The map is too big for a PNG. Export it as SVG or .drawio instead, "
                         "or show less of it.")
    return min(scale, fit)


def _surface_size(scene, scale):
    return max(1, int(math.ceil(scene.width * scale))), max(1, int(math.ceil(scene.height * scale)))


def render_png(layout, theme_name="dark", scale=2.0, icons=None, problems=None) -> bytes:
    """The whole map as PNG bytes, at scale times the draw.io page size."""
    import io

    import cairo
    scene = Scene(layout, theme_name, icons, problems)
    scale = png_scale(scene, scale)
    w, h = _surface_size(scene, scale)
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, h)
    cr = cairo.Context(surf)
    cr.scale(scale, scale)
    scene.render(cr, scale=scale, vector=True)
    surf.flush()
    buf = io.BytesIO()
    surf.write_to_png(buf)
    return buf.getvalue()


def render_svg(layout, theme_name="dark", icons=None, problems=None) -> bytes:
    """The whole map as SVG. Text is drawn as glyph outlines, so the file looks the same
    everywhere and carries no text of its own beyond what's drawn."""
    import io

    import cairo
    scene = Scene(layout, theme_name, icons, problems)
    buf = io.BytesIO()
    surf = cairo.SVGSurface(buf, scene.width, scene.height)
    try:
        surf.set_document_unit(cairo.SVGUnit.PX)
    except AttributeError:
        pass
    try:
        surf.restrict_to_version(cairo.SVGVersion.VERSION_1_2)
    except AttributeError:
        pass
    cr = cairo.Context(surf)
    scene.render(cr, scale=4.0, vector=True)
    surf.finish()
    return buf.getvalue()


def render_image(layout, theme_name="dark", width=None, height=None, icons=None):
    """A cairo ImageSurface of the whole map, scaled to fit width x height. For tests and
    thumbnails."""
    import cairo
    scene = Scene(layout, theme_name, icons)
    scale = 1.0
    if width and height:
        scale = min(width / scene.width, height / scene.height)
    w, h = _surface_size(scene, scale)
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, h)
    cr = cairo.Context(surf)
    cr.scale(scale, scale)
    scene.render(cr, scale=scale)
    surf.flush()
    return surf
