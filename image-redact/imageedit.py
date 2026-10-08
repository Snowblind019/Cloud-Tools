"""The Image Redact editor without the window: shapes, selection, dragging, undo, style,
and where the file goes. image_page.py (GTK, for Linux) and image_tk.py (tkinter, for
Windows) both drive this, so the two behave the same.

Everything here is in image pixels. The windows turn mouse positions into image pixels
before calling in, and draw with paint().
"""
from __future__ import annotations

import copy
import math
import os
from dataclasses import dataclass

from . import imageredact as ir

PAD = 24
HANDLE = 5
ZOOMS = [0.1, 0.17, 0.25, 0.33, 0.5, 0.67, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0]
LINE_KINDS = ("rect", "oval", "line", "arrow", "pen")
CORNER_KINDS = ("cover", "rect")

# (id, name, shortcut key, tooltip)
TOOLS = [
    ("select", "Select", "v", "Select, move and resize (V). Delete removes, arrow keys nudge."),
    ("cover", "Cover", "c", "Cover with a solid box (C). Same as what text detection draws."),
    ("rect", "Box", "r", "Box outline, or filled with Fill on (R)"),
    ("oval", "Oval", "o", "Oval (O)"),
    ("line", "Line", "l", "Line (L). Hold Shift for straight angles."),
    ("arrow", "Arrow", "a", "Arrow (A). Hold Shift for straight angles."),
    ("pen", "Pen", "p", "Draw freehand (P)"),
    ("text", "Text", "t", "Text (T). Click where it goes, type, then press Enter."),
]

SHORTCUTS_HELP = ("V C R O L A P T pick tools. Ctrl+S saves, Ctrl+C copies, F2 renames, Ctrl+M "
                  "moves. The wheel zooms, Shift+wheel scrolls, middle-drag pans.")

# Shown when Save or Copy is tried while text detection is still running.
BUSY = ("Text detection is still running. Save and Copy work again once it's done, so "
        "nothing goes out before it's covered.")


@dataclass
class Outcome:
    """What a file action did. kind is 'done', 'ask' (dest exists, confirm replacing it),
    'error', or 'nothing'."""
    kind: str
    message: str = ""
    dest: str = ""


def fit_zoom(size, w, h):
    iw, ih = size
    if w <= 2 * PAD or h <= 2 * PAD:
        return None
    return min((w - 2 * PAD) / iw, (h - 2 * PAD) / ih, 1.0)


def step_zoom(zoom, direction):
    if direction > 0:
        return next((z for z in ZOOMS if z > zoom * 1.01), ZOOMS[-1])
    return next((z for z in reversed(ZOOMS) if z < zoom * 0.99), ZOOMS[0])


def clamp_zoom(zoom):
    return min(max(zoom, ZOOMS[0]), ZOOMS[-1])


class Editor:
    def __init__(self):
        self.cfg = ir.load_config()
        self.png = None            # the image as opened, never changed
        self.surface = None
        self.source_path = None
        self.shapes = []
        self.undo_stack, self.redo_stack = [], []
        self.selected = None
        self.passes = None         # OCR results, kept so settings changes don't re-read
        self.ocr_warning = ""      # set when only part of the text check ran
        self.generation = 0
        self._finding = None       # the generation text detection is running for
        self.saved_path = None
        self.name = ""
        self.folder = ir.pictures_folder()
        self.unsaved = False       # changes made by hand since the last save or copy
        self.tool = "cover"
        self.drag = None
        self.draft = None

    # ================================================================== image
    @property
    def size(self):
        return (self.surface.get_width(), self.surface.get_height()) if self.surface else (1, 1)

    def load(self, png, path):
        """Start over with a new image. Raises ir.ImageError if it can't be read."""
        surface = ir.surface_from_png(png)
        self.generation += 1
        self.png, self.surface, self.source_path = png, surface, path
        self.shapes, self.undo_stack, self.redo_stack = [], [], []
        self.selected, self.passes, self.saved_path, self.unsaved = None, None, None, False
        self.ocr_warning, self._finding = "", None
        self.drag = self.draft = None
        self.name = ir.default_name(path)
        if path:
            self.folder = os.path.dirname(os.path.abspath(path))
        else:
            recent = [f for f in self.cfg["recent_folders"] if os.path.isdir(f)]
            self.folder = recent[0] if recent else ir.pictures_folder()
        return surface

    def describe(self):
        w, h = self.size
        where = os.path.basename(self.source_path) if self.source_path else "Pasted image"
        return f"{where}, {w}x{h}. Cover anything that shouldn't be shared."

    # ================================================================== undo
    def checkpoint(self):
        self.undo_stack.append(copy.deepcopy(self.shapes))
        del self.undo_stack[:-100]
        self.redo_stack.clear()

    def undo(self) -> bool:
        if not self.undo_stack:
            return False
        self.redo_stack.append(copy.deepcopy(self.shapes))
        self.shapes = self.undo_stack.pop()
        self.selected = None
        self.unsaved = True
        return True

    def redo(self) -> bool:
        if not self.redo_stack:
            return False
        self.undo_stack.append(copy.deepcopy(self.shapes))
        self.shapes = self.redo_stack.pop()
        self.selected = None
        self.unsaved = True
        return True

    def delete_selected(self) -> bool:
        if self.selected is None or self.selected not in self.shapes:
            return False
        self.checkpoint()
        self.shapes = [s for s in self.shapes if s is not self.selected]
        self.selected = None
        self.unsaved = True
        return True

    # ================================================================== detection
    @property
    def finding(self) -> bool:
        """True while text detection runs for the image that's open. Save and Copy wait
        for it, so the image never goes out before the boxes are on it."""
        return self._finding is not None and self._finding == self.generation

    def start_finding(self) -> int:
        """Text detection is starting. Returns the generation to hand to found() or
        find_failed() when it's done."""
        self._finding = self.generation
        return self.generation

    def found(self, gen, passes, warning=""):
        """Text detection finished. Returns the status message, or None when another
        image was opened since it started."""
        if gen != self.generation:
            return None
        self._finding = None
        self.passes, self.ocr_warning = passes, warning
        return self.apply_passes()

    def find_failed(self, gen, exc):
        """Text detection failed. If only part of it did, the boxes from the part that
        worked still go on, with a warning. Returns the status message, or None when
        another image was opened since it started."""
        if gen != self.generation:
            return None
        if isinstance(exc, ir.PartialOcrError):
            return self.found(gen, exc.passes, str(exc))
        self._finding = None
        return (str(exc).strip().splitlines() or ["Text detection failed."])[0]

    def apply_passes(self) -> str:
        """Turn the OCR results into boxes with the current PII Redact settings. Replaces
        the boxes detection drew before, but not ones you changed or drew yourself."""
        boxes = ir.find_boxes(self.passes, ir.redaction_options(), self.size)
        color, radius = self.cfg["box_color"], self.cfg["corners"]
        new = [ir.cover_shape(b, color, auto=True, radius=radius) for b in boxes]
        old = [s for s in self.shapes if s.get("auto")]
        if old or new:
            self.checkpoint()
            # Detected boxes go underneath, so arrows and text you add stay on top.
            self.shapes = new + [s for s in self.shapes if not s.get("auto")]
            if self.selected is not None and self.selected.get("auto"):
                self.selected = None
        msg = ir.summary([b[4] for b in boxes])
        if self.ocr_warning:
            # Find PII reads the text again in this case, so say so.
            return (f"{self.ocr_warning} {msg}. Some text may not be covered, so check it "
                    "carefully, or click Find PII to try again.")
        if boxes:
            return msg + ". Check it over and cover anything it missed."
        return msg + ". Check it over and cover anything that shouldn't be shared."

    # ================================================================== hit testing
    def handles(self, shape):
        if shape["kind"] in ("line", "arrow"):
            return [(shape["x1"], shape["y1"]), (shape["x2"], shape["y2"])]
        if shape["kind"] in ("cover", "rect", "oval"):
            x1, y1, x2, y2 = ir.rect_of(shape)
            return [(x1, y1), (x2, y1), (x2, y2), (x1, y2)]
        return []

    def handle_at(self, ix, iy, tol):
        if self.selected is None:
            return None
        for i, (hx, hy) in enumerate(self.handles(self.selected)):
            if abs(hx - ix) <= tol and abs(hy - iy) <= tol:
                return i
        return None

    def shape_at(self, ix, iy, tol):
        for shape in reversed(self.shapes):
            if ir.hit(shape, ix, iy, tol):
                return shape
        return None

    def hover_text(self, ix, iy, tol):
        shape = self.shape_at(ix, iy, tol)
        if shape is not None and shape.get("auto"):
            return "Found by text detection: " + ir.label_name(shape.get("label", ""))
        return None

    # ================================================================== dragging
    def drag_begin(self, ix, iy, zoom):
        """Mouse button down. zoom is the view's zoom, for screen-sized tolerances."""
        if self.surface is None:
            return
        self.drag = {"start": (ix, iy), "moved": False, "mode": None}
        tool = self.tool
        if tool == "select":
            handle = self.handle_at(ix, iy, (HANDLE + 3) / zoom)
            if handle is not None:
                if self.selected["kind"] in ("cover", "rect", "oval"):
                    x1, y1, x2, y2 = ir.rect_of(self.selected)
                    self.selected.update(x1=x1, y1=y1, x2=x2, y2=y2)
                self.drag.update(mode="resize", handle=handle, before=copy.deepcopy(self.shapes),
                                 orig=copy.deepcopy(self.selected))
                return
            shape = self.shape_at(ix, iy, 5 / zoom)
            self.selected = shape
            if shape is not None:
                self.drag.update(mode="move", before=copy.deepcopy(self.shapes),
                                 orig=copy.deepcopy(shape))
            return
        if tool == "text":
            self.drag["mode"] = "text"
            return
        cfg = self.cfg
        color = cfg["box_color"] if tool == "cover" else cfg["draw_color"]
        if tool == "pen":
            self.draft = {"kind": "pen", "points": [[ix, iy]], "color": list(color),
                          "width": cfg["width"], "fill": False}
        else:
            self.draft = {"kind": tool, "x1": ix, "y1": iy, "x2": ix, "y2": iy,
                          "color": list(color),
                          "width": 0 if tool == "cover" else cfg["width"],
                          "fill": tool == "cover" or (tool in ("rect", "oval") and cfg["fill"])}
            if tool in CORNER_KINDS:
                self.draft["radius"] = cfg["corners"]
        self.drag["mode"] = "create"

    def drag_update(self, ix, iy, shift, zoom):
        d = self.drag
        if not d or not d.get("mode"):
            return False
        sx, sy = d["start"]
        if math.hypot(ix - sx, iy - sy) * zoom > 2:
            d["moved"] = True
        mode = d["mode"]
        if mode == "create" and self.draft is not None:
            if self.draft["kind"] == "pen":
                last = self.draft["points"][-1]
                if math.hypot(ix - last[0], iy - last[1]) * zoom >= 2:
                    self.draft["points"].append([ix, iy])
            else:
                if shift:
                    ix, iy = constrain(self.draft["kind"], sx, sy, ix, iy)
                self.draft["x2"], self.draft["y2"] = ix, iy
        elif mode == "move" and self.selected is not None:
            o = d["orig"]
            for k in ("x1", "y1", "x2", "y2", "x", "y", "points"):
                if k in o:
                    self.selected[k] = copy.deepcopy(o[k])
            ir.translate(self.selected, ix - sx, iy - sy)
        elif mode == "resize" and self.selected is not None:
            o, h, sel = d["orig"], d["handle"], self.selected
            if sel["kind"] in ("line", "arrow"):
                if shift:
                    ax, ay = (o["x2"], o["y2"]) if h == 0 else (o["x1"], o["y1"])
                    ix, iy = constrain(sel["kind"], ax, ay, ix, iy)
                sel["x1" if h == 0 else "x2"] = ix
                sel["y1" if h == 0 else "y2"] = iy
            else:
                sel["x1"] = ix if h in (0, 3) else o["x1"]
                sel["x2"] = ix if h in (1, 2) else o["x2"]
                sel["y1"] = iy if h in (0, 1) else o["y1"]
                sel["y2"] = iy if h in (2, 3) else o["y2"]
        else:
            return False
        return True

    def drag_end(self, zoom):
        """Mouse button up. Returns a text request for the window to show an entry for:
        ('new', (x, y)) or ('edit', shape), or None."""
        d, self.drag = self.drag, None
        if not d or not d.get("mode"):
            return None
        mode = d["mode"]
        if mode == "text":
            if d["moved"]:
                return None
            hit = self.shape_at(*d["start"], 5 / zoom)
            if hit is not None and hit["kind"] == "text":
                return ("edit", hit)
            return ("new", d["start"])
        if mode == "create":
            draft, self.draft = self.draft, None
            if draft is None:
                return None
            if draft["kind"] == "pen":
                keep = len(draft["points"]) >= 2 or not d["moved"]
            else:
                x1, y1, x2, y2 = ir.rect_of(draft)
                keep = max(x2 - x1, y2 - y1) * zoom >= 4
            if keep:
                self.checkpoint()
                self.shapes.append(draft)
                self.unsaved = True
            return None
        if d["moved"] and self.selected is not None:
            self.undo_stack.append(d["before"])
            del self.undo_stack[:-100]
            self.redo_stack.clear()
            self.selected.pop("auto", None)
            self.unsaved = True
        return None

    def text_at_double_click(self, ix, iy, zoom):
        shape = self.shape_at(ix, iy, 5 / zoom)
        return ("edit", shape) if shape is not None and shape["kind"] == "text" else None

    def nudge(self, dx, dy) -> bool:
        if self.selected is None:
            return False
        self.checkpoint()
        ir.translate(self.selected, dx, dy)
        self.selected.pop("auto", None)
        self.unsaved = True
        return True

    def escape(self):
        self.drag = self.draft = self.selected = None

    def commit_text(self, request, text):
        if request is None:
            return False
        kind, value = request
        if kind == "edit":
            shape = value
            if text.strip() and text != shape["text"]:
                self.checkpoint()
                shape["text"] = text
                self.unsaved = True
                return True
            if not text.strip():
                self.selected = shape
                return self.delete_selected()
            return False
        if not text.strip():
            return False
        ix, iy = value
        self.checkpoint()
        self.shapes.append({"kind": "text", "x": ix, "y": iy, "text": text,
                            "size": self.cfg["text_size"], "color": list(self.cfg["draw_color"]),
                            "width": 0, "fill": False})
        self.unsaved = True
        return True

    # ================================================================== tools and style
    def set_tool(self, tool):
        self.tool = tool
        if tool != "select":
            self.selected = None

    def style_kind(self):
        return self.selected["kind"] if self.selected else self.tool

    def style(self) -> dict:
        """What the style controls should show, and which of them to show."""
        kind, sel, cfg = self.style_kind(), self.selected, self.cfg
        if sel:
            color = sel["color"]
        else:
            color = cfg["box_color"] if kind == "cover" else cfg["draw_color"]
        return {
            "kind": kind,
            "color": list(color),
            "fill": bool(sel.get("fill")) if sel else cfg["fill"],
            "width": sel.get("width", cfg["width"]) if sel and kind in LINE_KINDS else cfg["width"],
            "size": sel["size"] if sel and kind == "text" else cfg["text_size"],
            "corners": sel.get("radius", 0) if sel and kind in CORNER_KINDS else cfg["corners"],
            "show_color": kind != "select",
            "show_fill": kind in ("rect", "oval"),
            "show_width": kind in LINE_KINDS,
            "show_size": kind == "text",
            "show_corners": kind in CORNER_KINDS,
        }

    def set_style(self, color=None, fill=None, width=None, size=None, corners=None) -> bool:
        """Change one style setting. With a shape selected, it changes that shape. Otherwise
        it changes the tool's setting, and for Cover, the boxes detection drew follow along
        until you change one of them yourself. Returns True if any shape changed."""
        kind, sel = self.style_kind(), self.selected
        if sel is not None:
            self.checkpoint()
            if color is not None:
                sel["color"] = list(color)
            if fill is not None and kind in ("rect", "oval"):
                sel["fill"] = bool(fill)
            if width is not None and kind in LINE_KINDS:
                sel["width"] = float(width)
            if size is not None and kind == "text":
                sel["size"] = float(size)
            if corners is not None and kind in CORNER_KINDS:
                sel["radius"] = float(corners)
            sel.pop("auto", None)
            self.unsaved = True
            return True
        cfg = self.cfg
        if color is not None:
            if kind == "cover":
                cfg["box_color"] = list(color)
            elif kind != "select":
                cfg["draw_color"] = list(color)
        if fill is not None and kind in ("rect", "oval"):
            cfg["fill"] = bool(fill)
        if width is not None:
            cfg["width"] = int(width)
        if size is not None:
            cfg["text_size"] = int(size)
        if corners is not None and kind in CORNER_KINDS:
            cfg["corners"] = int(corners)
        changed = False
        if kind == "cover" and (color is not None or corners is not None):
            autos = [s for s in self.shapes if s.get("auto")]
            if autos:
                self.checkpoint()
                for s in autos:
                    if color is not None:
                        s["color"] = list(color)
                    if corners is not None:
                        s["radius"] = float(corners)
                changed = True
        self.save_cfg()
        return changed

    def save_cfg(self):
        cfg = ir.load_config()
        for key in ("find_on_open", "box_color", "draw_color", "width", "fill", "text_size",
                    "corners", "recent_folders"):
            cfg[key] = self.cfg[key]
        ir.save_config(cfg)

    def remember(self, folder):
        ir.remember_folder(self.cfg, folder)
        self.save_cfg()

    # ================================================================== files
    def target(self):
        return os.path.join(self.folder, self.name)

    def folder_choices(self):
        seen, out = set(), []
        folders = [self.folder] + list(self.cfg["recent_folders"])
        if self.source_path:
            folders.append(os.path.dirname(self.source_path))
        folders.append(ir.pictures_folder())
        for f in folders:
            f = os.path.abspath(f)
            if f not in seen and os.path.isdir(f):
                seen.add(f)
                out.append(f)
        return out

    def rename(self, typed) -> Outcome:
        """The name box changed. Before saving it's where Save writes, after it renames."""
        try:
            name = ir.clean_name(typed, ir.file_type(self.name))
        except ValueError as exc:
            return Outcome("error", str(exc))
        if name == self.name:
            return Outcome("nothing")
        if not self.saved_path:
            self.name = name
            return Outcome("done", f"Will save as {ir.short_path(self.target())}")
        return self._plan_relocate(os.path.join(os.path.dirname(self.saved_path), name),
                                   "Renamed to")

    def move_to(self, folder) -> Outcome:
        """A folder was picked. Before saving it's where Save writes, after it moves."""
        folder = os.path.abspath(folder)
        if not self.saved_path:
            self.folder = folder
            return Outcome("done", f"Will save as {ir.short_path(self.target())}")
        if folder == os.path.dirname(self.saved_path):
            return Outcome("nothing")
        return self._plan_relocate(os.path.join(folder, os.path.basename(self.saved_path)),
                                   "Moved to")

    def _plan_relocate(self, dest, verb) -> Outcome:
        src = self.saved_path
        if not os.path.exists(src):
            # Moved or deleted outside the app, so the next save just writes a new file.
            self.saved_path = None
            self.folder, self.name = os.path.dirname(dest), os.path.basename(dest)
            return Outcome("done", f"The saved file is gone. Will save as {ir.short_path(dest)}")
        if os.path.exists(dest) and os.path.abspath(dest) != os.path.abspath(src):
            return Outcome("ask", verb, dest)
        return self.relocate(dest, verb)

    def relocate(self, dest, verb="Moved to") -> Outcome:
        try:
            ir.relocate(self.saved_path, dest)
        except (OSError, ir.ImageError) as exc:
            return Outcome("error", f"Couldn't move the file: {exc}")
        self.saved_path = dest
        self.folder, self.name = os.path.dirname(dest), os.path.basename(dest)
        self.remember(self.folder)
        return Outcome("done", f"{verb} {ir.short_path(dest)}")

    def plan_save(self) -> Outcome:
        path = self.target()
        if os.path.exists(path) and path != self.saved_path:
            return Outcome("ask", "Save", path)
        return Outcome("done", dest=path)

    def write(self, path) -> Outcome:
        if self.finding:
            return Outcome("error", BUSY)
        try:
            ir.write_atomic(path, ir.encode(self.png, self.shapes, ir.file_type(path)))
        except (OSError, ir.ImageError) as exc:
            return Outcome("error", f"Couldn't save: {exc}")
        self.saved_path = path
        self.unsaved = False
        self.remember(os.path.dirname(path))
        return Outcome("done", f"Saved to {ir.short_path(path)}", path)

    def copy_png(self) -> bytes:
        """The finished image to put on the clipboard. Call copied() once it's there."""
        if self.finding:
            raise ir.ImageError(BUSY)
        return ir.encode(self.png, self.shapes, ".png")

    def copied(self):
        """The image made it onto the clipboard, so closing doesn't need to ask."""
        self.unsaved = False


def constrain(kind, sx, sy, x, y):
    """Shift held: squares and circles, or lines at 45 degree steps."""
    dx, dy = x - sx, y - sy
    if kind in ("cover", "rect", "oval"):
        side = max(abs(dx), abs(dy))
        return sx + math.copysign(side, dx or 1), sy + math.copysign(side, dy or 1)
    angle = round(math.atan2(dy, dx) / (math.pi / 4)) * (math.pi / 4)
    length = math.hypot(dx, dy)
    return sx + length * math.cos(angle), sy + length * math.sin(angle)


# =================================================================== drawing

def offsets(size, zoom, w, h):
    """Where the image's top left corner goes in a view w by h, centered when it fits."""
    iw, ih = size
    return max(PAD, (w - iw * zoom) / 2), max(PAD, (h - ih * zoom) / 2)


def paint(cr, ed, ox, oy, zoom, peek=False):
    """Draw the image, its shapes, the shape being drawn and the selection, with the
    image's top left corner at ox, oy in view pixels."""
    import cairo
    if ed.surface is None:
        return
    iw, ih = ed.size
    cr.save()
    cr.set_source_rgba(0, 0, 0, 0.25)
    cr.rectangle(ox + 1, oy + 2, iw * zoom, ih * zoom)
    cr.fill()
    cr.translate(ox, oy)
    cr.scale(zoom, zoom)
    cr.rectangle(0, 0, iw, ih)
    cr.clip()
    cr.set_source_surface(ed.surface, 0, 0)
    cr.get_source().set_filter(cairo.FILTER_GOOD if zoom < 1 else (
        cairo.FILTER_NEAREST if zoom >= 2 else cairo.FILTER_BILINEAR))
    cr.paint()
    ir.draw_shapes(cr, ed.shapes, see_through=peek)
    if peek:
        cr.set_line_width(1.5 / zoom)
        cr.set_dash([4 / zoom, 3 / zoom])
        cr.set_source_rgba(1, 0.75, 0, 0.95)
        for s in ed.shapes:
            if ir.is_cover(s):
                x1, y1, x2, y2 = ir.rect_of(s)
                cr.rectangle(x1, y1, x2 - x1, y2 - y1)
                cr.stroke()
        cr.set_dash([])
    if ed.draft is not None:
        ir.draw_shapes(cr, [ed.draft])
    cr.restore()
    if ed.selected is not None and ed.selected in ed.shapes:
        _paint_selection(cr, ed, ox, oy, zoom)


def _paint_selection(cr, ed, ox, oy, zoom):
    x1, y1, x2, y2 = ir.bbox(ed.selected)
    vx1, vy1 = ox + x1 * zoom, oy + y1 * zoom
    vx2, vy2 = ox + x2 * zoom, oy + y2 * zoom
    cr.save()
    cr.set_line_width(1)
    cr.set_dash([5, 3])
    cr.set_source_rgba(0.2, 0.52, 0.89, 1)
    cr.rectangle(vx1 - 3.5, vy1 - 3.5, vx2 - vx1 + 7, vy2 - vy1 + 7)
    cr.stroke()
    cr.set_dash([])
    for hx, hy in ed.handles(ed.selected):
        vx, vy = ox + hx * zoom, oy + hy * zoom
        cr.rectangle(vx - HANDLE, vy - HANDLE, HANDLE * 2, HANDLE * 2)
        cr.set_source_rgb(1, 1, 1)
        cr.fill_preserve()
        cr.set_source_rgba(0.2, 0.52, 0.89, 1)
        cr.stroke()
    cr.restore()


def draw_icon(cr, kind, w, h, rgba):
    """Small icons drawn with cairo, so toolbars look the same whatever icon theme or
    platform they're on. Drawn on an 18 by 18 grid and scaled to w by h."""
    import cairo
    cr.save()
    cr.set_source_rgba(*rgba)
    cr.set_line_width(1.6)
    cr.set_line_cap(cairo.LINE_CAP_ROUND)
    cr.set_line_join(cairo.LINE_JOIN_ROUND)
    cr.scale(w / 18, h / 18)
    k = kind
    if k == "select":
        for x, y in ((5, 2.5), (5, 15), (8.2, 12), (10.4, 16.4), (12.4, 15.5), (10.3, 11.1),
                     (14.6, 11.1)):
            cr.line_to(x, y)
        cr.close_path()
        cr.fill()
    elif k == "cover":
        cr.rectangle(2.5, 5, 13, 8)
        cr.fill()
    elif k == "rect":
        cr.rectangle(3, 4.5, 12, 9)
        cr.stroke()
    elif k == "oval":
        cr.save()
        cr.translate(9, 9)
        cr.scale(6.5, 4.8)
        cr.arc(0, 0, 1, 0, 2 * math.pi)
        cr.restore()
        cr.stroke()
    elif k == "line":
        cr.move_to(3.5, 14.5)
        cr.line_to(14.5, 3.5)
        cr.stroke()
    elif k == "arrow":
        cr.move_to(3.5, 14.5)
        cr.line_to(12, 6)
        cr.stroke()
        cr.move_to(15, 3)
        cr.line_to(8.5, 4.6)
        cr.line_to(13.4, 9.5)
        cr.close_path()
        cr.fill()
    elif k == "pen":
        cr.move_to(2.5, 12)
        cr.curve_to(5, 4, 8, 4, 9, 9)
        cr.curve_to(10, 14, 13, 14, 15.5, 6)
        cr.stroke()
    elif k == "text":
        cr.set_line_width(2)
        cr.move_to(4, 4)
        cr.line_to(14, 4)
        cr.move_to(9, 4)
        cr.line_to(9, 15)
        cr.stroke()
    elif k == "fill":
        cr.rectangle(3, 4, 12, 10)
        cr.fill()
    elif k == "corners":
        cr.move_to(3, 15)
        cr.line_to(3, 9)
        cr.arc(9, 9, 6, math.pi, 3 * math.pi / 2)
        cr.line_to(15, 3)
        cr.stroke()
    elif k in ("undo", "redo"):
        if k == "redo":
            cr.translate(18, 0)
            cr.scale(-1, 1)
        cr.arc_negative(10, 10.5, 5, -0.2, math.pi * 1.02)
        cr.stroke()
        cr.move_to(5, 4.5)
        cr.line_to(5, 10.5)
        cr.line_to(11, 10.5)
        cr.stroke()
    elif k == "delete":
        cr.move_to(3, 5)
        cr.line_to(15, 5)
        cr.move_to(7, 5)
        cr.line_to(7.5, 3)
        cr.line_to(10.5, 3)
        cr.line_to(11, 5)
        cr.stroke()
        cr.move_to(4.5, 5)
        cr.line_to(5.5, 15.5)
        cr.line_to(12.5, 15.5)
        cr.line_to(13.5, 5)
        cr.stroke()
    elif k in ("zoom-in", "zoom-out"):
        cr.arc(7.5, 7.5, 5, 0, 2 * math.pi)
        cr.stroke()
        cr.set_line_width(2)
        cr.move_to(11.3, 11.3)
        cr.line_to(15.5, 15.5)
        cr.stroke()
        cr.set_line_width(1.5)
        cr.move_to(5, 7.5)
        cr.line_to(10, 7.5)
        if k == "zoom-in":
            cr.move_to(7.5, 5)
            cr.line_to(7.5, 10)
        cr.stroke()
    elif k == "fit":
        for x, y, dx, dy in ((3, 3, 1, 1), (15, 3, -1, 1), (15, 15, -1, -1), (3, 15, 1, -1)):
            cr.move_to(x + 4 * dx, y)
            cr.line_to(x, y)
            cr.line_to(x, y + 4 * dy)
        cr.stroke()
        cr.rectangle(6.5, 6.5, 5, 5)
        cr.fill()
    elif k == "menu":
        for y in (5, 9, 13):
            cr.move_to(3.5, y)
            cr.line_to(14.5, y)
        cr.stroke()
    cr.restore()


def draw_app_icon(cr, size):
    """The Image Redact icon: a screenshot with lines of text, two of them covered."""
    s = size / 64
    cr.save()
    cr.scale(s, s)
    ir.rounded_rect(cr, 4, 6, 56, 52, 9)
    cr.set_source_rgb(0.93, 0.95, 0.97)
    cr.fill_preserve()
    cr.set_line_width(2.5)
    cr.set_source_rgb(0.24, 0.29, 0.36)
    cr.stroke()
    ir.rounded_rect(cr, 4, 6, 56, 11, 9)
    cr.set_source_rgb(0.24, 0.29, 0.36)
    cr.fill()
    cr.rectangle(4, 13, 56, 4)
    cr.fill()
    cr.set_source_rgb(0.55, 0.6, 0.67)
    for y, x2 in ((25, 50), (35, 44), (45, 52)):
        ir.rounded_rect(cr, 11, y, x2 - 11, 4, 2)
        cr.fill()
    cr.set_source_rgb(0.05, 0.05, 0.06)
    ir.rounded_rect(cr, 24, 22, 22, 10, 3)
    cr.fill()
    ir.rounded_rect(cr, 9, 42, 20, 10, 3)
    cr.fill()
    cr.restore()
