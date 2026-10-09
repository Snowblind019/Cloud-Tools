"""Cloud Map page for the AWS Kit window: the map, drawn natively, with pan, zoom,
search, details and export, and Edit, which opens it in draw.io (see map_edit.py).

The canvas draws through maprender.py, the same code as the SVG and PNG exports, from
the same Layout the .drawio writer uses, so all of them show the same map. The page only
handles input and widgets. The same code runs on Linux, Windows and WSL.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

from gi.repository import Gdk, GLib, Gtk, Pango

from . import cloudmap, maplayout, maplayoutmem, mapreach, maprender
from . import mapmodel as mm
from .map_edit import EditController
from .common import error_text, load_config, save_config
from .widgets import (CheckListButton, DetailPane, Page, account_pickers, button, chosen_profiles,
                      clear_box, fill_accounts, flash, hbox, label, margins, on_main, open_file,
                      run_bg, scroll_kind, set_clipboard, sev_badge, show_message, spacer,
                      string_dropdown, vbox)

MAP_TYPES = list(maplayout.MAP_TYPES)
MAP_TYPE_TITLES = ["Access", "Network", "Combined"]
THEMES = ["dark", "light"]
LAYER_TOGGLES = (("routes", "Routes"), ("sgs", "Security groups"), ("endpoints", "Endpoints"),
                 ("trust", "Trust paths"))
ZOOM_MIN, ZOOM_MAX = 0.04, 8.0
ZOOM_STEP = 1.2
TILE = 384                # device pixels per tile side
MAX_TILES = 96


def esc(text) -> str:
    return GLib.markup_escape_text(str(text if text is not None else ""))


def safe_name(text) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", str(text or "")).strip("-") or "map"


def tooltip_markup(lines) -> str:
    out = []
    for i, (lab, value) in enumerate(lines):
        if not lab:
            out.append(f"<b>{esc(value)}</b>" if i == 0 else esc(value))
        else:
            out.append(f"<b>{esc(lab)}:</b> {esc(value)}")
    return "\n".join(out[:24])


# =================================================================== canvas

class MapCanvas(Gtk.DrawingArea):
    """Draws a maprender.Scene with pan and zoom.

    The map is drawn in tiles that are kept and reused, so panning only draws the strip
    that comes into view, and the tiles around the window are drawn ahead while idle.
    Zooming stretches the tiles already drawn for a moment, then redraws them sharp at
    the new zoom once the wheel stops."""

    def __init__(self, on_select=None, on_activate=None):
        super().__init__()
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_focusable(True)
        self.set_has_tooltip(True)
        self.scene = None
        self.vp = maprender.Viewport(zoom_min=ZOOM_MIN, zoom_max=ZOOM_MAX)
        self.selected = None             # box id
        self.selected_link = None
        self.hover = None
        self.path = None                 # reachability: (box ids, link ids, blocked box ids)
        self.on_select = on_select
        self.on_activate = on_activate
        self.pointer = None
        self.tiles = OrderedDict()       # (scene, zoom, scale, tx, ty) -> drawn tile
        self.max_tiles = MAX_TILES       # more on a big screen, see _tile_limit
        self.tile_zoom = None            # the zoom the tiles on screen were drawn at
        self.prefetch_id = 0
        self.sharpen_id = 0
        self.need_fit = False
        self.frame_ms = 0.0
        self.set_draw_func(self._draw)

        drag = Gtk.GestureDrag()
        drag.set_button(0)
        drag.connect("drag-begin", self._drag_begin)
        drag.connect("drag-update", self._drag_update)
        self.add_controller(drag)
        self.drag = drag
        self._drag_from = None
        self._dragged = 0

        click = Gtk.GestureClick()
        click.set_button(1)
        click.connect("released", self._clicked)
        self.add_controller(click)

        scroll = Gtk.EventControllerScroll.new(Gtk.EventControllerScrollFlags.BOTH_AXES)
        scroll.connect("scroll", self._scrolled)
        self.add_controller(scroll)
        pinch = Gtk.GestureZoom()
        pinch.connect("begin", self._pinch_begin)
        pinch.connect("scale-changed", self._pinch_changed)
        self.add_controller(pinch)

        motion = Gtk.EventControllerMotion()
        motion.connect("motion", self._moved)
        motion.connect("leave", self._left)
        self.add_controller(motion)

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._key)
        self.add_controller(keys)
        self.connect("query-tooltip", self._tooltip)

    # ---- coordinates (the math is in maprender.Viewport)
    zoom = property(lambda self: self.vp.zoom)
    ox = property(lambda self: self.vp.ox, lambda self, v: setattr(self.vp, "ox", v))
    oy = property(lambda self: self.vp.oy, lambda self, v: setattr(self.vp, "oy", v))

    def to_page(self, x, y):
        return self.vp.to_page(x, y)

    def to_widget(self, px, py):
        return self.vp.to_screen(px, py)

    def visible(self):
        return self.vp.visible(self.get_width(), self.get_height())

    # ---- scene
    def set_scene(self, scene, keep_view=False):
        old = self.scene
        self.scene = scene
        self.tiles.clear()
        self.tile_zoom = None
        if scene is None:
            self.selected = self.selected_link = self.hover = None
        else:
            if self.selected not in scene.rects:
                self.selected = None
            if self.selected_link not in scene.links:
                self.selected_link = None
            if not keep_view or old is None:
                self.need_fit = True
        self.trigger_tooltip_query()
        self.queue_draw()

    def invalidate(self):
        """Draw everything again, icons too: the ones drawn while draw.io's icons were
        still loading are the simple stand-ins."""
        self.tiles.clear()
        if self.scene is not None:
            self.scene.icon_cache.clear()
        self.queue_draw()

    def fit(self):
        if self.scene is None:
            return
        self.vp.fit(self.scene.width, self.scene.height, max(self.get_width(), 1),
                    max(self.get_height(), 1))
        self._schedule_sharpen()
        self.queue_draw()

    def set_zoom(self, zoom, anchor=None):
        """Zoom, keeping the page point under anchor (widget coordinates) where it is."""
        if anchor is None:
            anchor = (self.get_width() / 2, self.get_height() / 2)
        self.vp.zoom_at(zoom, anchor)
        self._schedule_sharpen()
        self.queue_draw()

    def zoom_by(self, factor, anchor=None):
        self.set_zoom(self.zoom * factor, anchor)

    def center_on(self, px, py):
        self.vp.center_on(px, py, self.get_width(), self.get_height())
        self.queue_draw()

    def show_box(self, box_id, zoom_in=False):
        if self.scene is None or box_id not in self.scene.rects:
            return
        x, y, w, h = self.scene.rects[box_id]
        if zoom_in:
            vw, vh = max(self.get_width(), 1), max(self.get_height(), 1)
            self.set_zoom(min(vw / (w + 60), vh / (h + 60)))
        elif self.zoom < 0.5:
            self.set_zoom(0.8)
        self.center_on(x + w / 2, y + h / 2)

    def select(self, box_id=None, link_id=None, notify=True):
        self.selected, self.selected_link = box_id, link_id
        self.queue_draw()
        if notify and self.on_select:
            self.on_select(box_id, link_id)

    # ---- drawing
    def _schedule_sharpen(self):
        if self.sharpen_id:
            GLib.source_remove(self.sharpen_id)
        self.sharpen_id = GLib.timeout_add(140, self._sharpen)

    def _sharpen(self):
        self.sharpen_id = 0
        if self.tile_zoom != self.zoom:
            self.queue_draw()
        return False

    def _tile_size(self, zoom, sf):
        """Page units across one tile at this zoom."""
        return TILE / (zoom * sf)

    def _render_tile(self, scene, zoom, sf, tx, ty):
        import cairo
        size = self._tile_size(zoom, sf)
        rect = (tx * size, ty * size, (tx + 1) * size, (ty + 1) * size)
        surf = cairo.ImageSurface(cairo.FORMAT_RGB24, TILE, TILE)
        c2 = cairo.Context(surf)
        c2.scale(zoom * sf, zoom * sf)
        c2.translate(-rect[0], -rect[1])
        scene.render(c2, view=rect, scale=zoom * sf)
        surf.flush()
        self.tiles[(id(scene), zoom, sf, tx, ty)] = surf
        while len(self.tiles) > self.max_tiles:
            self.tiles.popitem(last=False)
        return surf

    def _tile_range(self, view, size, ring=0):
        return (int(math.floor(view[0] / size)) - ring, int(math.floor(view[1] / size)) - ring,
                int(math.floor(view[2] / size)) + ring, int(math.floor(view[3] / size)) + ring)

    def _tile_limit(self, size):
        """How many tiles to keep: at least the window and the ring around it that
        _prefetch draws. On a big screen, fewer would make each new tile push out one
        that's still needed, and _prefetch would never stop drawing."""
        x0, y0, x1, y1 = self._tile_range(self.visible(), size, ring=1)
        return max(MAX_TILES, (x1 - x0 + 1) * (y1 - y0 + 1))

    def _prefetch(self):
        """Draws the tiles just outside the window while nothing else is happening, so a
        pan rarely waits for one."""
        self.prefetch_id = 0
        scene = self.scene
        if scene is None or self.tile_zoom != self.zoom or self.sharpen_id:
            return False
        sf = max(self.get_scale_factor(), 1)
        size = self._tile_size(self.zoom, sf)
        self.max_tiles = self._tile_limit(size)
        x0, y0, x1, y1 = self._tile_range(self.visible(), size, ring=1)
        for ty in range(y0, y1 + 1):
            for tx in range(x0, x1 + 1):
                key = (id(scene), self.zoom, sf, tx, ty)
                if key in self.tiles:
                    self.tiles.move_to_end(key)
                    continue
                if tx * size > scene.width or ty * size > scene.height or \
                        (tx + 1) * size < 0 or (ty + 1) * size < 0:
                    continue
                self._render_tile(scene, self.zoom, sf, tx, ty)
                self.prefetch_id = GLib.idle_add(self._prefetch, priority=GLib.PRIORITY_LOW)
                return False
        return False

    def _draw(self, area, cr, width, height):
        import time

        import cairo
        start = time.perf_counter()
        scene = self.scene
        if scene is None:
            return
        if self.need_fit and width > 1 and height > 1:
            # Fitting waits for the first draw, when the canvas knows its size.
            self.need_fit = False
            self.fit()
        maprender.set_color(cr, scene.th["page"])
        cr.paint()
        sf = max(self.get_scale_factor(), 1)
        if self.tile_zoom is None or (self.tile_zoom != self.zoom and not self.sharpen_id):
            # The zoom settled: draw sharp tiles at the new zoom from now on.
            self.tile_zoom = self.zoom
        stretching = self.tile_zoom != self.zoom
        z = self.tile_zoom
        size = self._tile_size(z, sf)
        if not stretching:
            self.max_tiles = self._tile_limit(size)
        x0, y0, x1, y1 = self._tile_range(self.visible(), size)
        k = self.zoom / (z * sf)
        for ty in range(y0, y1 + 1):
            for tx in range(x0, x1 + 1):
                if tx * size > scene.width or ty * size > scene.height or \
                        (tx + 1) * size < 0 or (ty + 1) * size < 0:
                    continue            # outside the page, which is plain background
                key = (id(scene), z, sf, tx, ty)
                surf = self.tiles.get(key)
                if surf is None:
                    if stretching:
                        continue        # filled in sharp once the wheel stops
                    surf = self._render_tile(scene, z, sf, tx, ty)
                else:
                    self.tiles.move_to_end(key)
                cr.save()
                cr.translate((tx * size - self.ox) * self.zoom, (ty * size - self.oy) * self.zoom)
                cr.scale(k, k)
                cr.set_source_surface(surf, 0, 0)
                pattern = cr.get_source()
                pattern.set_extend(cairo.EXTEND_PAD)
                if not stretching and sf == 1:
                    pattern.set_filter(cairo.FILTER_NEAREST)
                cr.rectangle(0, 0, TILE, TILE)
                cr.fill()
                cr.restore()
        if not stretching and not self.prefetch_id:
            self.prefetch_id = GLib.idle_add(self._prefetch, priority=GLib.PRIORITY_LOW)
        if self.path:
            cr.save()
            cr.scale(self.zoom, self.zoom)
            cr.translate(-self.ox, -self.oy)
            scene.draw_path(cr, *self.path, px=1 / self.zoom)
            cr.restore()
        if self.selected or self.selected_link or self.hover:
            cr.save()
            cr.scale(self.zoom, self.zoom)
            cr.translate(-self.ox, -self.oy)
            scene.draw_selection(cr, self.selected, self.selected_link, self.hover,
                                 px=1 / self.zoom)
            cr.restore()
        self.frame_ms = (time.perf_counter() - start) * 1000

    # ---- input
    def _drag_begin(self, gesture, x, y):
        self._drag_from = (self.ox, self.oy)
        self._dragged = 0
        self.grab_focus()

    def _drag_update(self, gesture, dx, dy):
        if self._drag_from is None:
            return
        self.ox = self._drag_from[0] - dx / self.zoom
        self.oy = self._drag_from[1] - dy / self.zoom
        self._dragged = max(self._dragged, abs(dx) + abs(dy))
        if abs(dx) + abs(dy) > 3:
            self.set_cursor(Gdk.Cursor.new_from_name("grabbing", None))
        self.queue_draw()

    def _clicked(self, gesture, n_press, x, y):
        self.set_cursor(None)
        self.grab_focus()
        if self._dragged > 4:
            return                               # that was a pan, not a click
        if self.scene is None:
            return
        hit = self.scene.hit(*self.to_page(x, y), tolerance=5 / self.zoom)
        if n_press == 2 and hit and hit[0] == "box":
            box = self.scene.boxes.get(hit[1])
            if box is not None and box.role == "container":
                self.show_box(box.id, zoom_in=True)
            if self.on_activate:
                self.on_activate(hit[1])
            return
        if hit is None:
            self.select(None, None)
        elif hit[0] == "link":
            self.select(None, hit[1])
        else:
            self.select(hit[1], None)

    def _scrolled(self, controller, dx, dy):
        """The wheel zooms toward the pointer, Shift+wheel moves sideways. A touchpad moves
        the map with two fingers, and zooms with Ctrl held or a pinch."""
        if self.scene is None:
            return False
        state = controller.get_current_event_state()
        ctrl = bool(state & Gdk.ModifierType.CONTROL_MASK)
        kind = scroll_kind(controller)
        if kind == "touchpad" and not ctrl:
            self.ox += dx / self.zoom          # scrolling down shows what's further down
            self.oy += dy / self.zoom
            self.queue_draw()
            return True
        if state & Gdk.ModifierType.SHIFT_MASK and not ctrl:
            self.ox += (dy or dx) * (40 if kind == "wheel" else 1) / self.zoom
            self.queue_draw()
            return True
        anchor = self.pointer or (self.get_width() / 2, self.get_height() / 2)
        if dy:
            # a notch is one step; touchpads and fine wheels report distances instead
            power = -dy if kind == "wheel" else -dy / (60 if kind == "touchpad" else 15)
            self.zoom_by(ZOOM_STEP ** power, anchor)
        return True

    def _pinch_begin(self, gesture, sequence):
        ok, x, y = gesture.get_bounding_box_center()
        self._pinch = (self.zoom, (x, y) if ok else None)

    def _pinch_changed(self, gesture, scale):
        if self.scene is not None and getattr(self, "_pinch", None):
            zoom0, anchor = self._pinch
            self.set_zoom(zoom0 * scale, anchor)

    def _moved(self, controller, x, y):
        self.pointer = (x, y)
        if self.scene is None:
            return
        hover = self.scene.box_at(*self.to_page(x, y))
        if hover != self.hover:
            self.hover = hover
            self.queue_draw()

    def _left(self, controller):
        self.pointer = None
        if self.hover:
            self.hover = None
            self.queue_draw()

    def _key(self, controller, keyval, keycode, state):
        if state & (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.ALT_MASK):
            return False
        name = Gdk.keyval_name(keyval) or ""
        if name in ("plus", "equal", "KP_Add"):
            self.zoom_by(ZOOM_STEP)
        elif name in ("minus", "KP_Subtract", "underscore"):
            self.zoom_by(1 / ZOOM_STEP)
        elif name in ("0", "KP_0"):
            self.set_zoom(1.0)
        elif name in ("f", "F"):
            self.fit()
        elif name == "Escape":
            self.select(None, None)
        elif name in ("Left", "Right", "Up", "Down"):
            step = 60 / self.zoom
            self.ox += {"Left": -step, "Right": step}.get(name, 0)
            self.oy += {"Up": -step, "Down": step}.get(name, 0)
            self.queue_draw()
        else:
            return False
        return True

    def _tooltip(self, widget, x, y, keyboard, tooltip):
        if self.scene is None:
            return False
        hit = self.scene.hit(*self.to_page(x, y), tolerance=5 / self.zoom)
        if hit is None:
            return False
        if hit[0] == "link":
            link = self.scene.links[hit[1]]
            tooltip.set_markup(tooltip_markup(link.tooltip))
            return True
        box = self.scene.boxes.get(hit[1])
        if box is None:
            return False
        lines = list(box.tooltip)
        if hit[0] == "badge":
            lines = [("", "Security problem")] + [(f["severity"].capitalize(), f["reason"])
                                                  for f in box.flags]
            lines += [("Problem", p) for p in self.scene.problems.get(box.id, [])]
        else:
            if not lines:
                lines = [("", " ".join(box.title_lines))]
            lines += [("Problem", p) for p in self.scene.problems.get(box.id, [])]
        tooltip.set_markup(tooltip_markup(lines))
        return True


# =================================================================== page

class MapPage(Page):
    name = "map"
    title = "Cloud Map"

    def __init__(self, win):
        super().__init__(win, "Draws an AWS environment as an access map or a network map, "
                         "from a live scan, Terraform, or a saved snapshot. Drag to pan, scroll "
                         "to zoom, click a box for its details.")
        self.snap = None
        self.snap_path = None
        self.source = {}                 # how the snapshot was made, for Rescan
        self.layout = None
        self.generation = 0
        self.matches = []
        self.match_index = -1
        self._last_query = ""
        self._match_scene = None         # the scene the matches were found in
        self._detail_node = None
        self.cfg = dict(load_config().get("cloud_map") or {})
        self._restoring = False
        self.editing = EditController(self)
        self.mode = "map"              # or "design"
        self.reach_points = []         # mapreach.Endpoint list for the From and To pickers
        self.reach_result = None
        self.design = None
        self.design_path = None
        self.design_out = None         # where Build writes, when not the default
        self.built = None              # the last BuildResult

        # ---- top bar
        bar = self.toolbar()
        self.search = Gtk.SearchEntry(placeholder_text="Find a name, ID, CIDR or tag")
        self.search.set_size_request(280, -1)
        self.search.connect("activate", lambda *_: self.find(next_match=True))
        self.search.connect("search-changed", lambda *_: self.find(next_match=False))
        bar.append(self.search)
        self.flag_btn = Gtk.MenuButton(label="No flags")
        self.flag_btn.set_tooltip_text("Every security problem on this map")
        self.flag_pop = Gtk.Popover()
        self.flag_pop.connect("show", lambda *_: self.fill_flags())
        self.flag_btn.set_popover(self.flag_pop)
        bar.append(self.flag_btn)
        bar.append(spacer())
        bar.append(button("−", lambda: self.canvas.zoom_by(1 / ZOOM_STEP), "Zoom out (-)"))
        self.zoom_label = button("100%", lambda: self.canvas.set_zoom(1.0), "Actual size (0)")
        self.zoom_label.set_size_request(64, -1)
        bar.append(self.zoom_label)
        bar.append(button("+", lambda: self.canvas.zoom_by(ZOOM_STEP), "Zoom in (+)"))
        bar.append(button("Fit", lambda: self.canvas.fit(), "Fit the map in the window (F)"))
        self.edit_btn = button("Edit", lambda: self.editing.start(),
                               "Open the map in draw.io to move things around, recolor them "
                               "and add notes. Your layout is kept for every rescan.")
        bar.append(self.edit_btn)
        self.export_btn = Gtk.MenuButton(label="Export")
        self.export_btn.set_popover(self._export_popover())
        bar.append(self.export_btn)
        self.append(bar)
        self.bar = bar

        # ---- warnings
        self.warn_revealer = Gtk.Revealer()
        warn = hbox(8, "mapwarn")
        margins(warn, 0)
        icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        icon.set_valign(Gtk.Align.START)
        warn.append(icon)
        self.warn_label = label("", wrap=True, selectable=True)
        self.warn_label.set_hexpand(True)
        warn.append(self.warn_label)
        close = Gtk.Button.new_from_icon_name("window-close-symbolic")
        close.add_css_class("flat")
        close.set_valign(Gtk.Align.START)
        close.set_tooltip_text("Hide these notes. They're also in the map's footnote.")
        close.connect("clicked", lambda *_: self.warn_revealer.set_reveal_child(False))
        warn.append(close)
        self.warn_revealer.set_child(warn)
        self.append(self.warn_revealer)
        self.append(self.editing.pull_bar)

        # ---- body: controls | canvas | details
        outer = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        outer.set_vexpand(True)
        self.controls = self._controls()
        outer.set_start_child(self.controls)
        outer.set_resize_start_child(False)
        outer.set_shrink_start_child(False)
        inner = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.center = Gtk.Stack()
        self.center.set_hexpand(True)
        self.canvas = MapCanvas(on_select=self.selected)
        frame = Gtk.Frame()
        frame.set_child(self.canvas)
        self.center.add_named(self._empty_state(), "empty")
        self.center.add_named(frame, "canvas")
        self.center.add_named(self.editing.editor_box, "editor")
        self.center.add_named(self.editing.outside_box, "outside")
        inner.set_start_child(self.center)
        self.details_box = self._details()
        inner.set_end_child(self.details_box)
        inner.set_resize_end_child(False)
        inner.set_shrink_end_child(False)
        inner.set_position(640)
        self.inner = inner
        outer.set_end_child(inner)
        outer.set_position(250)
        self.append(outer)
        self.append(self.status)
        # Closing AWS Kit with changes still in the built-in draw.io asks first.
        win.connect("close-request", self.editing.close_request)
        GLib.timeout_add(300, self._tick)
        GLib.idle_add(self._restore)

    # ---- building the widgets
    def _section(self, text):
        w = label(text, "heading")
        w.set_margin_top(8)
        return w

    def _controls(self):
        box = vbox(6)
        margins(box, 10)
        box.append(self._section("Source"))
        box.append(button("Open snapshot", self.open_snapshot,
                          "A .cloudmap.json file from awskit map scan or awskit map tf"))
        box.append(label("Live scan", "dim-label"))
        account_pickers(self)
        box.append(self.accounts)
        box.append(self.regions)
        self.scan_btn = button("Scan now", self.scan, "Reads access and network data. Read-only.",
                               css="suggested-action")
        box.append(self.scan_btn)
        box.append(label("Terraform", "dim-label"))
        row = hbox(6)
        row.append(button("State or plan", self.open_tf_file,
                          "terraform show -json output, a .tfstate file or a saved plan"))
        row.append(button("Folder", self.open_tf_folder,
                          "Reads the folder's current state, or its plan"))
        box.append(row)
        self.plan_check = Gtk.CheckButton(label="Draw the plan for folders")
        self.plan_check.set_tooltip_text("Runs terraform plan and draws what it would build. "
                                         "Never runs apply.")
        box.append(self.plan_check)
        self.rescan_btn = button("Rescan", self.rescan, "Run the same scan or Terraform read again")
        self.rescan_btn.set_sensitive(False)
        box.append(self.rescan_btn)
        self.source_label = label("Nothing loaded.", "dim-label", wrap=True)
        self.source_label.set_ellipsize(Pango.EllipsizeMode.NONE)
        box.append(self.source_label)

        box.append(self._section("Designer"))
        box.append(label("Draw a network and get Terraform for it.", "dim-label", wrap=True))
        row = hbox(6)
        row.append(button("New design", self.new_design,
                          "Start a design from the template and open it in draw.io"))
        row.append(button("Open design", self.open_design, "Open a design .drawio file"))
        box.append(row)

        box.append(self._section("Map"))
        self.type_dd = string_dropdown(MAP_TYPE_TITLES)
        self.type_dd.connect("notify::selected", lambda *_: self.options_changed(True))
        box.append(self.type_dd)
        self.theme_dd = string_dropdown(["Dark", "Light"])
        self.theme_dd.connect("notify::selected", lambda *_: self.theme_changed())
        box.append(self.theme_dd)

        self.design_box = self._design_controls()
        self.design_box.set_visible(False)
        box.append(self.design_box)
        map_box = vbox(6)
        self.map_only = map_box
        box.append(map_box)
        outer_box, box = box, map_box

        box.append(self._reach_controls())

        box.append(self._section("Layout"))
        self.layout_label = label("Automatic layout.", "dim-label", wrap=True)
        box.append(self.layout_label)
        row = hbox(6)
        self.tidy_btn = button("Tidy up", self.tidy_up,
                               "Put everything you didn't move by hand back where the automatic "
                               "layout wants it. What you moved stays put.")
        row.append(self.tidy_btn)
        self.reset_btn = button("Reset layout", self.reset_layout,
                                "Forget this map's saved layout: positions, style changes and "
                                "shapes you drew. Captions stay.")
        row.append(self.reset_btn)
        box.append(row)
        self.tidy_btn.set_sensitive(False)
        self.reset_btn.set_sensitive(False)

        box.append(self._section("Show"))
        self.layer_checks = {}
        for key, text in LAYER_TOGGLES:
            cb = Gtk.CheckButton(label=text)
            cb.connect("toggled", lambda *_: self.options_changed())
            self.layer_checks[key] = cb
            box.append(cb)
        self.service_linked = Gtk.CheckButton(label="Service-linked roles")
        self.service_linked.connect("toggled", lambda *_: self.options_changed())
        box.append(self.service_linked)
        self.default_vpcs = Gtk.CheckButton(label="Empty default VPCs")
        self.default_vpcs.connect("toggled", lambda *_: self.options_changed())
        box.append(self.default_vpcs)

        box.append(self._section("Only"))
        self.f_accounts = CheckListButton("Accounts", all_label="All", on_change=self.options_changed)
        self.f_regions = CheckListButton("Regions", all_label="All", on_change=self.options_changed)
        self.f_vpcs = CheckListButton("VPCs", all_label="All", on_change=self.options_changed)
        for w in (self.f_accounts, self.f_regions, self.f_vpcs):
            w.set_options([])
            box.append(w)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(outer_box)
        scroller.set_size_request(230, -1)
        return scroller

    def _reach_controls(self):
        box = vbox(6)
        box.append(self._section("Reachability"))
        box.append(label("Can one thing reach another? Walks the security groups, network "
                         "ACLs and routes on this map, offline.", "dim-label", wrap=True))
        self.reach_from = self._reach_picker()
        self.reach_to = self._reach_picker()
        self.reach_to.connect("notify::selected", lambda *_: self._reach_default_port())
        for text, picker in (("From", self.reach_from), ("To", self.reach_to)):
            row = hbox(6)
            lab = label(text, "dim-label")
            lab.set_size_request(38, -1)
            row.append(lab)
            picker.set_hexpand(True)
            row.append(picker)
            box.append(row)
        row = hbox(6)
        self.reach_proto = string_dropdown(["TCP", "UDP", "ICMP", "All"])
        self.reach_proto.connect("notify::selected", lambda *_: self.reach_port.set_sensitive(
            self.reach_proto.get_selected() < 2))
        row.append(self.reach_proto)
        self.reach_port = Gtk.Entry(text="443", placeholder_text="Port")
        self.reach_port.set_width_chars(6)
        self.reach_port.set_hexpand(True)
        self.reach_port.connect("activate", lambda *_: self.check_reach())
        row.append(self.reach_port)
        box.append(row)
        row = hbox(6)
        self.reach_btn = button("Check", self.check_reach,
                                "Checks the path both ways: security groups, network ACLs "
                                "(and their replies), routes and gateways", css="suggested-action")
        self.reach_btn.set_hexpand(True)
        row.append(self.reach_btn)
        self.reach_clear = button("Clear", self.clear_reach, "Take the path off the map")
        self.reach_clear.set_sensitive(False)
        row.append(self.reach_clear)
        box.append(row)
        self.reach_box = box
        box.set_sensitive(False)
        return box

    def _reach_picker(self):
        """A searchable dropdown whose button shortens long names, so the controls column
        keeps its width. The open list shows them in full."""
        dd = Gtk.DropDown.new_from_strings([])
        dd.set_enable_search(True)
        dd.set_expression(Gtk.PropertyExpression.new(Gtk.StringObject, None, "string"))

        def setup(factory, item, short):
            lab = Gtk.Label(xalign=0)
            if short:
                lab.set_ellipsize(Pango.EllipsizeMode.END)
                lab.set_width_chars(8)
                lab.set_max_width_chars(14)
            item.set_child(lab)

        def bind(factory, item):
            item.get_child().set_text(item.get_item().get_string())
        for short, setter in ((True, dd.set_factory), (False, dd.set_list_factory)):
            f = Gtk.SignalListItemFactory()
            f.connect("setup", setup, short)
            f.connect("bind", bind)
            setter(f)

        def tip(*_):
            obj = dd.get_selected_item()
            dd.set_tooltip_text(obj.get_string() if obj is not None else None)
        dd.connect("notify::selected", tip)
        return dd

    def fill_reach(self):
        """The From and To lists, from what's on the current map."""
        points = []
        if self.snap is not None:
            try:
                points = mapreach.endpoints(self.snap)
            except Exception:  # noqa: BLE001 - an odd snapshot just means nothing to pick
                points = []
        old_from, old_to = self._reach_key(self.reach_from), self._reach_key(self.reach_to)
        self.reach_points = points
        labels = [p.label for p in points]
        for dd, old, default in ((self.reach_from, old_from, 0),
                                 (self.reach_to, old_to, 1 if len(points) > 1 else 0)):
            dd.set_model(Gtk.StringList.new(labels))
            keys = [p.key for p in points]
            dd.set_selected(keys.index(old) if old in keys else (default if points else
                                                               Gtk.INVALID_LIST_POSITION))
        has_network = any(p.kind in ("instance", "lb", "rds", "subnet") for p in points)
        self.reach_box.set_sensitive(has_network)
        self.clear_reach()

    def _reach_key(self, dd):
        i = dd.get_selected()
        if 0 <= i < len(self.reach_points):
            return self.reach_points[i].key
        return None

    def _reach_point(self, dd):
        i = dd.get_selected()
        return self.reach_points[i] if 0 <= i < len(self.reach_points) else None

    def _reach_default_port(self):
        dst = self._reach_point(self.reach_to)
        if dst is None:
            return
        try:
            port = mapreach.default_port(dst)
        except Exception:  # noqa: BLE001
            port = None
        if port:
            self.reach_port.set_text(str(port))

    def reach_from_here(self, which):
        """From here / To here in the details panel, for the selected box."""
        node = self._detail_node
        if node is None:
            return
        keys = [p.node_id for p in self.reach_points]
        if node.id not in keys:
            return
        (self.reach_from if which == "from" else self.reach_to).set_selected(keys.index(node.id))

    def check_reach(self):
        if self.snap is None:
            return
        src, dst = self._reach_point(self.reach_from), self._reach_point(self.reach_to)
        if src is None or dst is None:
            self.status.idle("Pick where from and where to.")
            return
        protocol = ("tcp", "udp", "icmp", "all")[self.reach_proto.get_selected()]
        port = None
        if protocol in ("tcp", "udp"):
            text = self.reach_port.get_text().strip()
            if not text.isdecimal() or not 0 <= int(text) <= 65535:
                show_message(self.win, "That isn't a port", "Type a port number from 0 to 65535.")
                self.reach_port.grab_focus()
                return
            port = int(text)
        try:
            result = mapreach.check(self.snap, src, dst, protocol=protocol, port=port)
        except mapreach.ReachError as exc:
            show_message(self.win, "Can't check that", str(exc))
            return
        self.show_reach(result)

    def show_reach(self, result, move=True):
        self.reach_result = result
        scene = self.canvas.scene
        boxes, bad = [], []
        if scene is not None:
            by_aws = {b.attrs.get("aws_id", b.id): b.id for b in scene.lay.boxes}
            for node_id in result.path_nodes:
                bid = by_aws.get(node_id, node_id)
                if bid in scene.rects and bid not in boxes:
                    boxes.append(bid)
            hop = result.blocked_hop
            if hop is not None:
                for node_id in self._blocked_boxes(result, hop):
                    bid = by_aws.get(node_id, node_id)
                    if bid in scene.rects and bid not in bad:
                        bad.append(bid)
                        break
            links = [eid for eid in result.path_edges if eid in scene.links]
        else:
            links = []
        self.canvas.path = (boxes, links, bad)
        self.canvas.select(None, None, notify=False)
        self.canvas.queue_draw()
        self.reach_clear.set_sensitive(True)
        clear_box(self.d_flags)
        title = {"reachable": "Reachable", "blocked": "Partly blocked" if result.partial else
                 "Blocked", "unknown": "Can't tell"}.get(result.verdict, result.verdict)
        self.d_title.set_text(title)
        for css in ("ok-text", "bad-text", "warn-text"):
            self.d_title.remove_css_class(css)
        self.d_title.add_css_class({"reachable": "ok-text", "blocked": "bad-text"}.get(
            result.verdict, "warn-text"))
        self.d_kind.set_text(f"Reachability, {result.traffic}")
        self.d_kind.set_tooltip_text(None)
        self.d_caption.set_text(result.summary)
        self._reach_text(result)
        self.copy_id.set_visible(False)
        self.copy_arn.set_visible(False)
        self.reach_here.set_visible(False)
        self._detail_node = None
        if move and bad:
            self.canvas.show_box(bad[0])
        if move:
            self.status.idle(f"{title}: {result.summary}")

    def _blocked_boxes(self, result, hop):
        """Where to put the red outline, best first. Security groups and network ACLs are
        often not drawn, so fall back to the host or subnet they guard."""
        out = [hop.node_id] if hop.node_id else []
        node = self.snap.get(hop.node_id) if (self.snap and hop.node_id) else None
        kind = node.kind if node is not None else ""
        if kind == "sg" or hop.kind.startswith("sg"):
            ends = [result.destination, result.source] if hop.kind == "sg-in" else \
                [result.source, result.destination]
            for ep in ends:
                if ep.node_id and (not hop.node_id or hop.node_id in (ep.security_groups or [])):
                    out.append(ep.node_id)
        elif kind == "nacl":
            guarded = set(node.props.get("subnets") or [])
            out += [n for n in result.path_nodes if n in guarded]
        return out

    def _reach_text(self, result):
        """The hops in the details panel: a colored status word and title per hop, with the
        reason indented under it. Copy gives the same text as awskit map reach."""
        self.detail.set_text(" ")
        self.detail.text = mapreach.result_text(result)
        buf = self.detail.view.get_buffer()
        buf.set_text("")
        table = buf.get_tag_table()

        def tag(name, **props):
            t = table.lookup(name)
            if t is None:
                t = Gtk.TextTag(name=name, **props)
                table.add(t)
            return t
        bold = tag("reach-bold", weight=700)
        head = tag("reach-head", weight=700, pixels_above_lines=8)
        body = tag("reach-body", left_margin=26, pixels_below_lines=4)
        colors = {"ok": tag("reach-ok", foreground="#26a269", weight=700),
                  "blocked": tag("reach-blocked", foreground="#e01b24", weight=700),
                  "unknown": tag("reach-unknown", foreground="#e66100", weight=700),
                  "skipped": tag("reach-skipped", foreground="#77767b", weight=700)}

        def put(text, *tags):
            buf.insert_with_tags(buf.get_end_iter(), text, *tags)
        for name, ep in (("From", result.source), ("To", result.destination)):
            put(f"{name}  ", bold)
            put(ep.label + "\n")
        put("Over  ", bold)
        put(result.traffic + "\n")
        for leg, heading in (("there", "On the way there"), ("back", "Replies")):
            hops = [h for h in result.hops if h.leg == leg]
            if not hops:
                continue
            put("\n" + heading + "\n", head)
            for h in hops:
                word = "PARTLY" if h.partial and h.status == "blocked" else h.status.upper()
                put(f"{word}  ", colors.get(h.status, bold))
                put(h.title + "\n", bold)
                put(h.reason + "\n", body)
                if h.fix:
                    put("To allow it: " + h.fix + "\n", body)
        if result.notes:
            put("\nNotes\n", head)
            for n in result.notes:
                put("- " + n + "\n", body)

    def clear_reach(self):
        self.reach_result = None
        if getattr(self, "canvas", None) is not None and self.canvas.path:
            self.canvas.path = None
            self.canvas.queue_draw()
            self.clear_details()
        if getattr(self, "reach_clear", None) is not None:
            self.reach_clear.set_sensitive(False)

    def _design_controls(self):
        box = vbox(6)
        box.append(self._section("Design"))
        self.design_label = label("", "dim-label", wrap=True)
        box.append(self.design_label)
        self.build_btn = button("Build Terraform", self.build_design,
                                "Check the design and write a Terraform module and an example "
                                "for it. Never runs apply.", css="suggested-action")
        box.append(self.build_btn)
        row = hbox(6)
        self.plan_btn = button("Plan", self.plan_design,
                               "Run Plan Check on the built example, with the profile picked in "
                               "the header")
        self.folder_btn = button("Open folder", self.open_design_folder,
                                 "Open the folder the Terraform was written to")
        row.append(self.plan_btn)
        row.append(self.folder_btn)
        box.append(row)
        self.out_label = label("", "dim-label", wrap=True)
        box.append(self.out_label)
        self.out_btn = button("Change folder", self.choose_design_folder,
                              "Build somewhere else: an empty folder, or one the designer made")
        self.out_btn.add_css_class("flat")
        box.append(self.out_btn)
        return box

    def _empty_state(self):
        box = vbox(12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        box.append(label("No map loaded yet", "headline", xalign=0.5))
        box.append(label("Open a saved snapshot, scan the accounts picked on the left, or read "
                         "a Terraform state, plan or folder.", "dim-label", xalign=0.5, wrap=True))
        row = hbox(8)
        row.set_halign(Gtk.Align.CENTER)
        row.append(button("Open snapshot", self.open_snapshot))
        row.append(button("Scan now", self.scan, css="suggested-action"))
        row.append(button("Read Terraform", self.open_tf_folder))
        box.append(row)
        margins(box, 30)
        return box

    def _details(self):
        box = vbox(4)
        box.set_size_request(320, -1)
        head = vbox(2)
        margins(head, 10)
        head.set_margin_bottom(0)
        self.d_title = label("Nothing selected", "headline", wrap=True, selectable=True)
        self.d_kind = label("Click a box or a line on the map.", "dim-label")
        self.d_kind.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        self.d_caption = label("", wrap=True, selectable=True)
        # Long ARNs and captions wrap inside the panel instead of widening it.
        for w in (self.d_title, self.d_kind, self.d_caption):
            w.set_max_width_chars(34)
        head.append(self.d_title)
        head.append(self.d_kind)
        head.append(self.d_caption)
        self.d_flags = vbox(4)
        head.append(self.d_flags)
        # In a scroller, so long captions and flag reasons wrap inside the panel instead
        # of asking the paned for more height than it has.
        head_scroll = Gtk.ScrolledWindow()
        head_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        head_scroll.set_propagate_natural_height(True)
        head_scroll.set_max_content_height(300)
        head_scroll.set_child(head)
        box.append(head_scroll)
        self.detail = DetailPane("Properties, tags and the raw JSON show here.", "Details")
        copy_row = hbox(6)
        self.copy_id = button("Copy ID", lambda: self.copy_field("id"))
        self.copy_arn = button("Copy ARN", lambda: self.copy_field("arn"))
        for b in (self.copy_id, self.copy_arn):
            b.add_css_class("flat")
            copy_row.append(b)
        head.append(copy_row)
        self.reach_here = hbox(6)
        for text, which in (("Reach from here", "from"), ("Reach to here", "to")):
            b = button(text, lambda w=which: self.reach_from_here(w),
                       "Use this as the start or the end of a reachability check")
            b.add_css_class("flat")
            self.reach_here.append(b)
        self.reach_here.set_visible(False)
        head.append(self.reach_here)
        self.copy_id.set_visible(False)
        self.copy_arn.set_visible(False)
        self.detail.set_vexpand(True)
        box.append(self.detail)
        return box

    def _export_popover(self):
        pop = Gtk.Popover()
        box = vbox(6)
        margins(box, 10)
        box.append(label("Export what's on screen", "heading"))
        self.redact_check = Gtk.CheckButton(label="Redact")
        self.redact_check.set_tooltip_text("Runs every label, tooltip and data attribute through "
                                           "PII Redact, and hashes the cell IDs in .drawio files")
        box.append(self.redact_check)
        for fmt, text, tip in (("drawio", ".drawio", "Opens in draw.io, with layers and data"),
                               ("svg", "SVG", "A picture that scales, for docs and slides"),
                               ("png", "PNG", "A picture at twice the size, for chat and tickets")):
            b = button(text, lambda f=fmt: (pop.popdown(), self.export(f)), tip)
            box.append(b)
        pop.set_child(box)
        return pop

    # ---- settings
    def _restore(self):
        cfg = self.cfg
        self._restoring = True
        try:
            mt = cfg.get("map_type", "access")
            self.type_dd.set_selected(MAP_TYPES.index(mt) if mt in MAP_TYPES else 0)
            th = cfg.get("theme", "dark")
            self.theme_dd.set_selected(THEMES.index(th) if th in THEMES else 0)
            self._set_layer_defaults(cfg.get("show"))
            self.service_linked.set_active(bool(cfg.get("service_linked")))
            self.default_vpcs.set_active(bool(cfg.get("default_vpcs")))
            self.plan_check.set_active(bool(cfg.get("plan")))
        finally:
            self._restoring = False
        last = cfg.get("snapshot")
        design = cfg.get("design")
        if cfg.get("mode") == "design" and design and Path(design).is_file():
            self.load_design(design, quiet=True)
        elif last and Path(last).is_file():
            self.source = dict(cfg.get("source") or {"kind": "file"})
            self.load_snapshot(last, quiet=True)
        else:
            self.center.set_visible_child_name("empty")
        return False

    def _set_layer_defaults(self, show=None):
        mt = self.map_type()
        wanted = set(show) if show is not None else maplayout.DEFAULT_SHOW[mt]
        for key, cb in self.layer_checks.items():
            cb.set_active(key in wanted)

    def remember(self):
        if self._restoring:
            return
        self.cfg.update({
            "snapshot": str(self.snap_path or ""), "source": self.source,
            "map_type": self.map_type(), "theme": self.theme_name(),
            "show": sorted(self.show()), "service_linked": self.service_linked.get_active(),
            "default_vpcs": self.default_vpcs.get_active(), "plan": self.plan_check.get_active(),
            "accounts": self.f_accounts.selected(), "regions": self.f_regions.selected(),
            "vpcs": self.f_vpcs.selected(), "mode": self.mode,
            "design": str(self.design_path or self.cfg.get("design") or "")})
        cfg = load_config()
        cfg["cloud_map"] = self.cfg
        save_config(cfg)

    def map_type(self):
        return MAP_TYPES[self.type_dd.get_selected()] if self.type_dd.get_selected() < 3 else "access"

    def theme_name(self):
        return THEMES[self.theme_dd.get_selected()] if self.theme_dd.get_selected() < 2 else "dark"

    def show(self):
        return {k for k, cb in self.layer_checks.items() if cb.get_active()}

    # ---- the account pickers in the left panel (shared helpers expect these names)
    def profile_changed(self, profile):
        fill_accounts(self, reset=True)

    def profiles_changed(self):
        fill_accounts(self)

    # ---- sources
    def open_snapshot(self):
        open_file(self.win, lambda p: self.load_snapshot(p, source={"kind": "file"}),
                  "Open a Cloud Map snapshot")

    def load_snapshot(self, path, quiet=False, source=None):
        """source says how the file was made, for Rescan. None keeps the current one."""
        self.status.busy(f"Reading {Path(path).name}...", progress=False)
        # Only the last file asked for counts, so a slow read (the last snapshot, opened
        # at startup) can't replace one opened after it.
        self._load_seq = getattr(self, "_load_seq", 0) + 1
        seq = self._load_seq

        def done(snap):
            if seq != self._load_seq:
                return
            if source is not None or not self.source:
                self.source = dict(source or {"kind": "file"})
            self.source["snapshot"] = str(path)
            self.set_snapshot(snap, path)

        def failed(exc):
            if seq != self._load_seq:
                return
            self.status.idle("")
            if quiet:
                self.center.set_visible_child_name("empty")
                self.status.idle(f"Couldn't open the last snapshot: {exc}")
                return
            show_message(self.win, "Couldn't open that snapshot", str(exc))
        run_bg(lambda: mm.Snapshot.load(path), done, failed)

    def scan(self):
        profiles = chosen_profiles(self)
        regions = self.regions.selected() or None
        name = "+".join(safe_name(p or "default") for p in profiles)
        self.run_scan({"kind": "scan", "profiles": profiles, "regions": regions or [],
                       "name": name})

    def run_scan(self, source):
        cancel = self.new_cancel()
        self.scan_btn.set_sensitive(False)
        self.rescan_btn.set_sensitive(False)
        self.status.busy("Starting the scan...", cancel)
        progress = on_main(self.status.progress)
        out = cloudmap.MAP_DIR / "scans" / f"{source['name']}{mm.SUFFIX}"

        def work():
            snap = cloudmap.scan(source["profiles"], source.get("regions") or None,
                                 progress=progress, cancel=cancel)
            if not snap.nodes:
                raise RuntimeError("\n".join(snap.warnings) or "The scan found nothing.")
            out.parent.mkdir(parents=True, exist_ok=True)
            snap.save(out)
            return snap

        def done(snap):
            self.scan_btn.set_sensitive(True)
            self.source = dict(source, snapshot=str(out))
            self.set_snapshot(snap, out)

        def failed(exc):
            self.scan_btn.set_sensitive(True)
            self.rescan_btn.set_sensitive(bool(self.snap))
            self.status.idle("")
            show_message(self.win, "The scan didn't work", error_text(exc))
        run_bg(work, done, failed)

    def open_tf_file(self):
        open_file(self.win, lambda p: self.read_tf(p, False), "Terraform state or plan")

    def open_tf_folder(self):
        open_file(self.win, lambda p: self.read_tf(p, self.plan_check.get_active()),
                  "Terraform folder", folder=True)

    def read_tf(self, path, plan=False):
        self.run_tf({"kind": "terraform", "path": str(path), "plan": bool(plan and
                                                                       os.path.isdir(path)),
                     "name": safe_name(cloudmap.stem_of(path))})

    def run_tf(self, source):
        self.rescan_btn.set_sensitive(False)
        what = "Running terraform plan" if source.get("plan") else "Reading Terraform"
        self.status.busy(f"{what} in {Path(source['path']).name}...", progress=False)
        log = on_main(self.status.text.set_text)
        out = cloudmap.MAP_DIR / "terraform" / f"{source['name']}{mm.SUFFIX}"

        def work():
            snap = cloudmap.read_terraform([source["path"]], plan=source.get("plan", False),
                                           log=log)
            out.parent.mkdir(parents=True, exist_ok=True)
            snap.save(out)
            return snap

        def done(snap):
            self.source = dict(source, snapshot=str(out))
            self.set_snapshot(snap, out)

        def failed(exc):
            self.rescan_btn.set_sensitive(bool(self.snap))
            self.status.idle("")
            show_message(self.win, "Couldn't read that Terraform", str(exc))
        run_bg(work, done, failed)

    def rescan(self):
        if self.mode == "design" and self.design_path:
            self.load_design(self.design_path)
            return
        kind = (self.source or {}).get("kind")
        if kind == "scan":
            self.run_scan(self.source)
        elif kind == "terraform":
            self.run_tf(self.source)
        elif self.snap_path:
            self.load_snapshot(self.snap_path)

    # ---- the snapshot
    def set_snapshot(self, snap, path):
        self.snap = snap
        self.snap_path = Path(path) if path else None
        self.set_mode("map")
        self.editing.snapshot_changed()
        self.rescan_btn.set_sensitive(True)
        kind = (self.source or {}).get("kind")
        what = {"scan": "Live scan", "terraform": "Terraform"}.get(kind, "Snapshot")
        lines = [f"{what}: {self.snap_path.name if self.snap_path else 'not saved'}"]
        if snap.scanned_at:
            lines.append(("Scanned " if snap.source == "aws" else "Made ") + snap.scanned_at)
        self.source_label.set_text("\n".join(lines))
        self.source_label.set_tooltip_text(str(self.snap_path or ""))
        self._fill_filters()
        self.fill_reach()
        warnings = list(snap.warnings)
        self.warn_label.set_text("\n".join(warnings[:8]) + (
            f"\nand {len(warnings) - 8} more, in the footnote" if len(warnings) > 8 else ""))
        self.warn_revealer.set_reveal_child(bool(warnings))
        self.relayout(fit=True)

    def _fill_filters(self):
        snap, cfg = self.snap, self.cfg
        same = str(self.snap_path or "") == cfg.get("snapshot")
        accounts = [(n.id, mm.title_of(n) + (f" ({n.id})" if n.name and n.id != n.name else ""))
                    for n in snap.of_kind("account")]
        regions = sorted({n.region for n in snap.of_kind("region") if n.region})
        vpcs = [(n.id, mm.title_of(n) + (f" ({n.id})" if n.name else ""))
                for n in snap.of_kind("vpc") if not n.props.get("stub")]
        for widget, opts, key in ((self.f_accounts, accounts, "accounts"),
                                  (self.f_regions, [(r, r) for r in regions], "regions"),
                                  (self.f_vpcs, vpcs, "vpcs")):
            keep = [v for v in (cfg.get(key) or []) if v in dict(opts)] if same else []
            widget.on_change = None
            widget.set_options(opts, keep)
            widget.on_change = self.options_changed
            widget.set_sensitive(bool(opts))

    def options_changed(self, map_type_changed=False):
        if self._restoring or self.mode == "design":
            return
        if map_type_changed:
            self._restoring = True
            try:
                self._set_layer_defaults()
            finally:
                self._restoring = False
            self.editing.snapshot_changed()
        self.remember()
        if self.snap is not None:
            self.relayout()

    def theme_changed(self):
        if self._restoring:
            return
        self.remember()
        if self.layout is not None:
            self.show_layout(self.layout, keep_view=True)

    def relayout(self, fit=False, note=""):
        if self.mode == "design":
            if self.design_path:
                self.load_design(self.design_path, note=note, fit=fit)
            return
        if self.snap is None:
            return
        self.generation += 1
        gen = self.generation
        snap, snap_path = self.snap, self.snap_path
        args = self.layout_args()
        self.status.busy("Laying out the map...", progress=False)

        def work():
            labels = cloudmap.load_labels()
            memory = cloudmap.memory_for(snap_path)
            return cloudmap.make_layout(snap, labels=labels, memory=memory,
                                        snapshot_name=snap_path.name if snap_path else "",
                                        **args), memory

        def done(result):
            if gen != self.generation:
                return
            lay, memory = result
            self.show_layout(lay, keep_view=not fit, note=note)
            self.update_layout_label(memory)
            self.remember()

        def failed(exc):
            if gen != self.generation:
                return
            self.status.idle(str(exc))
            if isinstance(exc, (maplayout.LayoutError, ValueError)):
                self.canvas.set_scene(None)
                self.layout = None
                self.update_flags()
        run_bg(work, done, failed)

    def show_layout(self, lay, keep_view=True, note=""):
        self.layout = lay
        scene = maprender.Scene(lay, self.theme_name())
        self.canvas.set_scene(scene, keep_view=keep_view)
        if self.center.get_visible_child_name() in ("empty", "canvas", None):
            self.center.set_visible_child_name("canvas")
        self.update_flags()
        cards = sum(1 for b in lay.boxes if b.role != "container")
        self.status.idle((note + "  " if note else "") +
                         f"{mm.plural(cards, 'resource')}, {mm.plural(len(lay.links), 'line')}. "
                         f"Drew at {datetime.now():%H:%M}.")
        if self.canvas.selected or self.canvas.selected_link:
            self.selected(self.canvas.selected, self.canvas.selected_link)
        elif self.reach_result is not None:
            self.show_reach(self.reach_result, move=False)    # the new layout's boxes
        else:
            self.clear_details()
        icons = scene.icons
        if icons is not None and not icons.loaded:
            # Reading draw.io's icons takes a moment the first time, so do it off the
            # main thread and redraw when they're in.
            def load():
                icons.load()
                return icons
            run_bg(load, lambda _: self.canvas.invalidate())

    # ---- the designer
    def set_mode(self, mode):
        self.mode = mode
        design = mode == "design"
        if design:
            self.clear_reach()
        self.design_box.set_visible(design)
        self.map_only.set_visible(not design)
        self.type_dd.set_sensitive(not design)
        if not design:
            self.design = None

    def new_design(self):
        from . import mapdesign
        from .cloudmap import _default_region
        dialog = Gtk.FileDialog(title="Save the new design", initial_name="network.drawio")

        def chosen(dlg, result):
            try:
                path = dlg.save_finish(result).get_path()
            except GLib.Error:
                return
            try:
                path = mapdesign.new_design(path, region=_default_region(),
                                            theme_name=self.theme_name(), overwrite=True)
            except (mapdesign.DesignError, OSError) as exc:
                show_message(self.win, "Couldn't make the design", str(exc))
                return
            self.load_design(path, edit=True)
        dialog.save(self.win, None, chosen)

    def open_design(self):
        open_file(self.win, lambda p: self.load_design(p), "Open a design")

    def load_design(self, path, quiet=False, edit=False, note="", fit=None):
        """Read a design and show it, with its problems marked in red."""
        from . import mapdesign
        path = Path(path)
        first = self.mode != "design" or self.design_path != path
        self.generation += 1
        gen = self.generation
        self.status.busy(f"Reading {path.name}...", progress=False)

        def work():
            design = mapdesign.read(path)
            problems = mapdesign.check(design)
            return design, problems, mapdesign.layout(design, problems)

        def done(result):
            if gen != self.generation:
                return
            design, problems, lay = result
            if first:
                self.design_out = None
                self.built = None
            self.set_design(design, problems, lay, fit=first if fit is None else fit, note=note)
            if edit:
                self.editing.start()

        def failed(exc):
            self.status.idle("")
            if not quiet:
                show_message(self.win, "Couldn't open that design", str(exc))
            elif self.layout is None:
                self.center.set_visible_child_name("empty")
        run_bg(work, done, failed)

    def set_design(self, design, problems, lay, fit=True, note=""):
        from . import mapdesign
        changed = self.design_path != design.path
        self.design = design
        self.design_path = design.path
        self.design_problems = problems
        self.snap = None
        self.set_mode("design")
        self.design = design
        if changed:
            self.editing.snapshot_changed()
        self.rescan_btn.set_sensitive(True)
        self.source_label.set_text(f"Design: {design.path.name}")
        self.source_label.set_tooltip_text(str(design.path))
        self.design_label.set_text(f"{design.name}, for {design.region or 'no region yet'}. "
                                   f"{mapdesign.summary(problems)}"
                                   + (" Problems are marked in red, and the flag button lists "
                                      "them." if problems else ""))
        general = [p.message for p in problems if not p.shape]
        self.warn_label.set_text("\n".join(general))
        self.warn_revealer.set_reveal_child(bool(general))
        has_errors = bool(mapdesign.errors(problems))
        self.build_btn.set_sensitive(not has_errors)
        self.build_btn.set_tooltip_text("Fix the errors first: they're marked in red." if has_errors
                                        else "Check the design and write a Terraform module and "
                                             "an example for it. Never runs apply.")
        self.update_design_output()
        self.show_layout(lay, keep_view=not fit, note=note)
        self.remember()

    def design_folder(self) -> Path:
        from . import mapdesign
        return Path(self.design_out) if self.design_out else mapdesign.default_folder(self.design)

    def update_design_output(self):
        if self.design is None:
            return
        folder = self.design_folder()
        built = self.built is not None and self.built.folder == folder
        self.out_label.set_text(f"Writes to {folder}" + (", built." if built else "."))
        self.out_label.set_tooltip_text(str(folder))
        valid = built and all(ok for _, ok, _ in self.built.checks if ok is not None) and \
            any(ok for _, ok, _ in self.built.checks)
        self.plan_btn.set_sensitive(bool(valid))
        self.folder_btn.set_sensitive(folder.is_dir())

    def choose_design_folder(self):
        def chosen(path):
            self.design_out = path
            self.update_design_output()
        open_file(self.win, chosen, "Build the Terraform into", folder=True)

    def build_design(self):
        from . import mapdesign
        if self.design is None:
            return
        design, folder = self.design, self.design_folder()
        self.build_btn.set_sensitive(False)
        self.status.busy(f"Building {folder.name}...", progress=False)
        log = on_main(self.status.text.set_text)

        def work():
            fresh = mapdesign.read(design.path)
            return mapdesign.build(fresh, folder, validate=False, log=log)

        def built(result):
            """Checks the output with init and validate. When the folder holds files the
            designer didn't write, Terraform would load them too, so that's asked first."""
            from .widgets import confirm_terraform, trust_terraform_folder
            example = result.folder / "examples" / "basic"
            foreign = mapdesign.foreign_files(result.folder, result.files)

            def check():
                trust_terraform_folder(example)
                self.build_btn.set_sensitive(False)
                self.status.busy("Checking the Terraform...", progress=False)

                def validated(checks):
                    result.checks = checks
                    done(result)
                run_bg(lambda: mapdesign.validate_folder(result.folder, log=log), validated, failed)
            if not foreign:
                check()
                return
            result.checks = [("validate", None, mapdesign.SKIPPED_VALIDATE + ", ".join(foreign) + ".")]
            done(result)
            confirm_terraform(self.win, example, check, what="terraform init and validate",
                              detail="It has files the designer didn't write, which Terraform "
                                     "would load: " + ", ".join(foreign[:6]) +
                                     (" and more" if len(foreign) > 6 else "") + ".")

        def done(result):
            self.build_btn.set_sensitive(True)
            self.built = result
            lines = [f"Wrote {len(result.files)} files to {result.folder}:"]
            lines += [f"  {f}" for f in result.files]
            lines += [f"  removed {f}" for f in result.removed]
            if result.formatted:
                lines += ["", result.formatted]
            for cmd, ok, text in result.checks:
                if ok:
                    lines += ["", f"{cmd}: passed"]
                else:
                    lines += ["", f"{cmd}: " + ("didn't run" if ok is None else "failed"), text]
            warnings = [p.message for p in result.problems]
            if warnings:
                lines += ["", "Warnings:"] + [f"  {w}" for w in warnings]
            lines += ["", "AWS Kit never runs apply. Plan runs Plan Check on examples/basic."]
            self.clear_details()
            self.d_title.set_text("Built Terraform")
            ok = all(c[1] for c in result.checks if c[1] is not None)
            self.d_kind.set_text("Validated" if result.checks and ok and result.checks[0][1] is not None
                                 else "Written" if ok else "Written, but validate failed")
            self.detail.set_text("\n".join(lines))
            self.update_design_output()
            self.status.idle(f"Built {result.folder.name}: {len(result.files)} files.")

        def failed(exc):
            self.build_btn.set_sensitive(True)
            self.status.idle("")
            show_message(self.win, "Couldn't build the Terraform", str(exc))
        run_bg(work, built, failed)

    def open_design_folder(self):
        folder = self.design_folder()
        try:
            from gi.repository import Gio
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(str(folder)).get_uri(), None)
        except GLib.Error as exc:
            self.status.idle(f"Couldn't open the folder: {exc.message}")

    def plan_design(self):
        """Plan Check on the built example, with the profile picked in AWS Kit."""
        if self.built is None:
            return
        example = self.built.folder / "examples" / "basic"

        profile = self.win.profile

        def creds():
            import botocore.session
            session = botocore.session.Session(profile=profile) if profile else botocore.session.get_session()
            return profile, session.get_credentials() is not None

        def done(result):
            profile, ok = result
            if not ok:
                show_message(self.win, "Plan needs AWS credentials",
                             "Pick a profile in the header (or sign in on the Profiles page), "
                             "then press Plan again. Planning only reads from AWS.")
                return
            page = self.win.pages.get("plan")
            if page is None:
                return
            self.win.show_page("plan")
            page.set_folder(str(example))
            page.run_plan()          # asks first, unless this session's build checked it

        def failed(exc):
            show_message(self.win, "Plan needs AWS credentials", str(exc))
        run_bg(creds, done, failed)

    def layout_args(self) -> dict:
        return dict(map_type=self.map_type(), show=self.show(),
                    accounts=self.f_accounts.selected(), regions=self.f_regions.selected(),
                    vpcs=self.f_vpcs.selected(), service_linked=self.service_linked.get_active(),
                    default_vpcs=self.default_vpcs.get_active())

    # ---- layout memory
    def set_editing(self, on):
        """While draw.io is open inside the page it gets the room, and the map's options
        wait."""
        self.bar.set_sensitive(not on)
        self.controls.set_visible(not on)
        self.details_box.set_visible(not on)
        if on:
            self._warn_shown = self.warn_revealer.get_reveal_child()
            self.warn_revealer.set_reveal_child(False)
        elif getattr(self, "_warn_shown", False):
            self.warn_revealer.set_reveal_child(True)
            self._warn_shown = False

    def after_layout_saved(self, text):
        self.relayout(note=text)

    def update_layout_label(self, memory=None):
        got = maplayoutmem.summary_of(memory, self.map_type())
        if not got["boxes"] and not got["extra"] and not got["styles"]:
            self.layout_label.set_text("Automatic layout. Edit it in draw.io and it's kept "
                                       "for every rescan.")
        else:
            parts = [f"{got['pinned']} moved by hand"]
            if got["styles"]:
                parts.append(mm.plural(got["styles"], "style change"))
            if got["extra"]:
                parts.append(mm.plural(got["extra"], "shape of your own", "shapes of your own"))
            self.layout_label.set_text("Your saved layout: " + ", ".join(parts) + ".")
        self.tidy_btn.set_sensitive(bool(got["boxes"] - got["pinned"]))
        self.reset_btn.set_sensitive(bool(got["boxes"] or got["extra"] or got["styles"] or
                                          got["edges"]))

    def tidy_up(self):
        if not self.snap_path:
            return
        side = maplayoutmem.sidecar_path(self.snap_path)
        memory = maplayoutmem.load(side)
        n = maplayoutmem.tidy(memory, self.map_type())
        maplayoutmem.save(memory, side)
        self.relayout(note=f"Tidied up: {mm.plural(n, 'box', 'boxes')} back to the automatic "
                           "layout. What you moved by hand stays put.")

    def reset_layout(self):
        if not self.snap_path:
            return
        map_type = self.map_type()
        dlg = Gtk.AlertDialog(message=f"Reset the {map_type} map's layout?",
                              detail="Positions, style changes and shapes you drew for this map "
                                     "are forgotten, and it's drawn fresh. Captions you changed "
                                     "stay, in labels.json.")
        dlg.set_buttons(["Cancel", "Reset layout"])
        dlg.set_cancel_button(0)
        dlg.set_default_button(0)

        def chosen(d, res):
            try:
                if d.choose_finish(res) != 1:
                    return
            except GLib.Error:
                return
            maplayoutmem.reset_file(maplayoutmem.sidecar_path(self.snap_path), map_type)
            self.relayout(note=f"The {map_type} map's layout is reset.")
        dlg.choose(self.win, None, chosen)

    def _tick(self):
        self.zoom_label.set_label(f"{round(self.canvas.zoom * 100)}%")
        return True

    # ---- details
    def clear_details(self):
        for css in ("ok-text", "bad-text", "warn-text"):
            self.d_title.remove_css_class(css)
        self.reach_here.set_visible(False)
        self.d_title.set_text("Nothing selected")
        self.d_kind.set_text("Click a box or a line on the map.")
        self.d_caption.set_text("")
        clear_box(self.d_flags)
        self.detail.set_text("")
        self.copy_id.set_visible(False)
        self.copy_arn.set_visible(False)
        self._detail_node = None

    def selected(self, box_id, link_id):
        for css in ("ok-text", "bad-text", "warn-text"):
            self.d_title.remove_css_class(css)
        self.reach_here.set_visible(False)
        if box_id is None and link_id is None:
            self.clear_details()
            return
        scene = self.canvas.scene
        if scene is None:
            return
        clear_box(self.d_flags)
        if link_id:
            self.show_link(scene.links.get(link_id))
        else:
            self.show_box(scene.boxes.get(box_id))

    def _flag_rows(self, flags):
        for f in flags:
            row = hbox(6)
            row.append(sev_badge(f.get("severity", "info")))
            reason = label(f.get("reason", ""), wrap=True, selectable=True)
            reason.set_max_width_chars(30)
            row.append(reason)
            self.d_flags.append(row)

    def show_box(self, box):
        if box is None:
            self.clear_details()
            return
        node = self.snap.get(box.attrs.get("aws_id", box.id)) if self.snap else None
        self._detail_node = node
        self.d_title.set_text(" ".join(box.title_lines) or box.id)
        kind = mm.NODE_KINDS.get(box.kind, box.kind)
        self.d_kind.set_text(kind + ("" if node is None else f"  ·  {node.id}"))
        self.d_kind.set_tooltip_text(node.id if node is not None else None)
        self.d_caption.set_text(" ".join(box.caption_lines))
        self._flag_rows(box.flags)
        lines = []
        if node is None:
            for lab, value in box.tooltip:
                lines.append(f"{lab}: {value}" if lab else str(value))
        else:
            lines += [f"Name: {node.name}" if node.name else "", f"Kind: {kind}",
                      f"ID: {node.id}", f"Account: {node.account}" if node.account else "",
                      f"Region: {node.region}" if node.region else "",
                      f"Source: {node.source}"]
            lines = [x for x in lines if x]
            if node.props:
                lines += ["", "Properties"]
                for k in sorted(node.props):
                    v = node.props[k]
                    if v in (None, "", [], {}) or k == "trust_policy":
                        continue
                    lines.append(f"  {k}: {maplayout._attr_text(v)}")
            if node.tags:
                lines += ["", "Tags"] + [f"  {k} = {v}" for k, v in sorted(node.tags.items())]
            lines += ["", "Raw JSON", json.dumps(node.as_dict(), indent=2, ensure_ascii=False)]
        self.detail.set_text("\n".join(lines))
        self.copy_id.set_visible(node is not None)
        self.copy_arn.set_visible(bool(node is not None and node.props.get("arn")))
        self.reach_here.set_visible(node is not None and self.reach_box.get_sensitive() and
                                    any(p.node_id == node.id for p in self.reach_points))

    def show_link(self, link):
        if link is None:
            self.clear_details()
            return
        self._detail_node = None
        first = link.tooltip[0][1] if link.tooltip else link.kind
        self.d_title.set_text(first)
        self.d_kind.set_text({"sso": "Identity Center access"}.get(
            link.kind, link.kind.replace("-", " ").capitalize()) + " line")
        self.d_caption.set_text(link.label)
        self._flag_rows(link.flags)
        lines = [f"{lab}: {v}" if lab else str(v) for lab, v in link.tooltip]
        edge = self.snap.edges.get(link.id) if self.snap else None
        if edge is not None:
            lines += ["", "Raw JSON", json.dumps(edge.as_dict(), indent=2, ensure_ascii=False)]
        self.detail.set_text("\n".join(lines))
        self.copy_id.set_visible(False)
        self.copy_arn.set_visible(False)

    def copy_field(self, which):
        node = getattr(self, "_detail_node", None)
        if node is None:
            return
        value = node.id if which == "id" else node.props.get("arn", "")
        if value:
            set_clipboard(self, value)
            flash(self.copy_id if which == "id" else self.copy_arn, "Copied")

    # ---- search and flags
    def find(self, next_match=True):
        text = self.search.get_text().strip().lower()
        scene = self.canvas.scene
        if not text or scene is None:
            self.matches, self.match_index = [], -1
            return
        # A new layout (another map type, filter or snapshot) has other boxes, so the
        # matches are looked up again.
        if not next_match or not self.matches or self._last_query != text or \
                self._match_scene is not scene:
            self._last_query = text
            self._match_scene = scene
            self.matches = []
            for b in scene.lay.boxes:
                hay = [b.id, " ".join(b.title_lines), " ".join(b.caption_lines)]
                hay += [str(v) for k, v in b.attrs.items() if k in (
                    "aws_id", "name", "cidr", "tags", "arn", "private_ip", "public_ip")]
                if any(text in h.lower() for h in hay):
                    self.matches.append(b.id)
            self.matches.sort(key=lambda bid: (scene.boxes[bid].role == "container",
                                               scene.depth.get(bid, 0) * -1))
            self.match_index = -1
            if not next_match:
                if self.matches:
                    self.status.idle(f"{mm.plural(len(self.matches), 'match', 'matches')}. "
                                     "Press Enter to go to the next one.")
                else:
                    self.status.idle(f"Nothing on this map matches {text}.")
                return
        if not self.matches:
            self.status.idle(f"Nothing on this map matches {text}.")
            return
        self.match_index = (self.match_index + 1) % len(self.matches)
        box_id = self.matches[self.match_index]
        self.canvas.select(box_id)
        self.canvas.show_box(box_id)
        self.status.idle(f"Match {self.match_index + 1} of {len(self.matches)}.")

    def flagged(self):
        if self.layout is None:
            return []
        out = []
        for b in self.layout.boxes:
            for f in b.flags:
                out.append(("box", b.id, " ".join(b.title_lines), f))
        for lk in self.layout.links:
            for f in lk.flags:
                out.append(("link", lk.id, lk.tooltip[0][1] if lk.tooltip else lk.kind, f))
        out.sort(key=lambda x: (mm.SEV_RANK.get(x[3].get("severity"), 9), x[2]))
        return out

    def update_flags(self):
        items = self.flagged()
        things = len({(k, i) for k, i, _, _ in items})
        self.flag_btn.set_label(f"{things} flagged" if things else "No flags")
        if things:
            self.flag_btn.add_css_class("destructive-action")
        else:
            self.flag_btn.remove_css_class("destructive-action")

    def fill_flags(self):
        box = vbox(4)
        margins(box, 8)
        items = self.flagged()
        if not items:
            box.append(label("Nothing on this map is flagged.", "dim-label"))
        for kind, oid, title, f in items:
            b = Gtk.Button()
            b.add_css_class("flat")
            row = hbox(6)
            row.append(sev_badge(f.get("severity", "info")))
            text = vbox(0)
            text.append(label(title, "heading"))
            reason = label(f.get("reason", ""), "dim-label", wrap=True)
            reason.set_max_width_chars(60)
            text.append(reason)
            row.append(text)
            b.set_child(row)
            b.connect("clicked", lambda _b, k=kind, i=oid: self.jump_to(k, i))
            box.append(b)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_propagate_natural_height(True)
        scroller.set_propagate_natural_width(True)
        scroller.set_max_content_height(460)
        scroller.set_child(box)
        self.flag_pop.set_child(scroller)

    def jump_to(self, kind, oid):
        self.flag_pop.popdown()
        if kind == "box":
            self.canvas.select(oid)
            self.canvas.show_box(oid)
        else:
            self.canvas.select(None, oid)
            pts = self.canvas.scene.paths.get(oid) if self.canvas.scene else None
            if pts:
                (x, y), _ = maprender.point_at(pts, 0.5)
                if self.canvas.zoom < 0.5:
                    self.canvas.set_zoom(0.8)
                self.canvas.center_on(x, y)

    # ---- export
    def export(self, fmt):
        if self.layout is None or (self.snap is None and self.mode != "design"):
            show_message(self.win, "Nothing to export yet", "Load a map first.")
            return
        redact = self.redact_check.get_active() and self.mode != "design"
        if self.mode == "design" and self.design_path:
            name = f"{Path(self.design_path).stem}.{fmt}"
            if fmt == "drawio":
                show_message(self.win, "The design is already a .drawio file",
                             f"It's {self.design_path}. Export SVG or PNG for a picture of it.")
                return
        else:
            # A redacted export's name doesn't carry the snapshot's (a profile name, say).
            stem = cloudmap.stem_of(self.snap_path) if self.snap_path and not redact else "cloud-map"
            name = f"{stem}-{self.map_type()}{'-redacted' if redact else ''}.{fmt}"
        dialog = Gtk.FileDialog(title="Export the map", initial_name=name)

        def chosen(dlg, result):
            try:
                gfile = dlg.save_finish(result)
            except GLib.Error:
                return
            self.write_export(gfile.get_path(), fmt, redact)
        dialog.save(self.win, None, chosen)

    def write_export(self, path, fmt, redact, on_done=None):
        snap, snap_path = self.snap, self.snap_path
        args = self.layout_args()
        theme_name = self.theme_name()
        lay = self.layout
        self.status.busy(f"Writing {Path(path).name}...", progress=False)

        def work():
            use = lay
            if redact and snap is not None:
                # The saved layout is applied by ID: the sidecar itself never goes along.
                use = cloudmap.make_layout(snap, redacted=True, labels=cloudmap.load_labels(),
                                           memory=cloudmap.memory_for(snap_path), **args)
            return cloudmap.write_file(path, cloudmap.render(use, fmt, theme_name))

        def done(p):
            self.status.idle(f"Wrote {p}" + (", redacted" if redact else ""))
            if on_done:
                on_done(p)

        def failed(exc):
            self.status.idle("")
            show_message(self.win, "Couldn't export the map", str(exc))
        run_bg(work, done, failed)
