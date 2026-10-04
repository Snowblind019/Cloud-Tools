"""Image Redact in the window: the editor, its page in AWS Kit, and its own small window."""
from __future__ import annotations

import copy
import math
import os

import cairo
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from . import imageredact as ir
from .common import ClipboardError, is_wsl, read_clipboard_image, write_clipboard_image
from .widgets import Page, button, hbox, label, margins, run_bg, show_message, vbox

PAD = 24
ZOOMS = [0.1, 0.17, 0.25, 0.33, 0.5, 0.67, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0]
HANDLE = 5

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


def fg_color(widget):
    try:
        return widget.get_color()
    except AttributeError:  # GTK before 4.10
        return widget.get_style_context().get_color()


def rgba(values):
    c = Gdk.RGBA()
    c.red, c.green, c.blue, c.alpha = values
    return c


def from_rgba(c):
    return [round(c.red, 4), round(c.green, 4), round(c.blue, 4), round(c.alpha, 4)]


class ToolIcon(Gtk.DrawingArea):
    """Small drawn icons, so the toolbar looks the same whatever icon theme is installed."""

    def __init__(self, kind, size=18):
        super().__init__()
        self.kind = kind
        self.set_content_width(size)
        self.set_content_height(size)
        self.set_draw_func(self._draw)

    def _draw(self, area, cr, w, h):
        c = fg_color(self)
        cr.set_source_rgba(c.red, c.green, c.blue, c.alpha)
        cr.set_line_width(1.6)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        cr.set_line_join(cairo.LINE_JOIN_ROUND)
        cr.scale(w / 18, h / 18)
        k = self.kind
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


class ImageEditor(Gtk.Box):
    """Open or paste a screenshot, cover what text detection finds, fix it up by hand,
    then save, rename, move or copy the result."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.cfg = ir.load_config()
        self.png = None            # the image as opened, never changed
        self.surface = None
        self.source_path = None
        self.shapes = []
        self.undo_stack, self.redo_stack = [], []
        self.selected = None
        self.passes = None         # OCR results, kept so settings changes don't re-read
        self.generation = 0
        self.saved_path = None
        self.name = ""
        self.folder = ir.pictures_folder()
        self.unsaved = False       # changes made by hand since the last save or copy
        self.zoom, self.fit = 1.0, True
        self.ox = self.oy = PAD
        self.drag = None
        self.draft = None
        self.text_target = None
        self._loading_style = False
        self._scroll_target = None
        self._cfg_save_id = 0
        self._settings_win = None
        self.tool = "cover"
        self.ocr_ok, self.ocr_msg = ir.ocr_status()

        self.append(self._build_toolbar())
        self.append(self._build_canvas())
        self.append(self._build_file_bar())
        self._build_text_popover()
        self._install_shortcuts()
        self.set_tool("cover")
        self._update_state()
        self.set_status("Paste a screenshot (Ctrl+V), drop an image here, or click Open."
                        if self.ocr_ok else self.ocr_msg.splitlines()[0] +
                        " You can still cover things by hand.")

    # ================================================================== layout
    def _build_toolbar(self):
        bar = hbox(6)
        open_btn = button("Open", self.open_dialog, tooltip="Open an image (Ctrl+O)")
        paste_btn = button("Paste", self.paste, tooltip="Paste a screenshot (Ctrl+V)")
        self.find_btn = button("Find PII", self.find_pii,
                               tooltip="Read the text and cover account IDs, keys, emails and "
                                       "the rest, using your PII Redact settings (Ctrl+F)")
        self.peek_btn = Gtk.ToggleButton(label="See through")
        self.peek_btn.set_tooltip_text("Show what's under the solid boxes, to check they cover "
                                       "the right thing. Saved and copied images are always solid.")
        self.peek_btn.connect("toggled", lambda *_: self.area.queue_draw())
        for w in (open_btn, paste_btn, Gtk.Separator(orientation=Gtk.Orientation.VERTICAL),
                  self.find_btn, self.peek_btn,
                  Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)):
            bar.append(w)

        tools = hbox(0, css="linked")
        self.tool_buttons = {}
        group = None
        for tid, name, key, tip in TOOLS:
            b = Gtk.ToggleButton()
            b.set_child(ToolIcon(tid))
            b.set_tooltip_text(tip)
            if group:
                b.set_group(group)
            group = group or b
            b.connect("toggled", self._tool_toggled, tid)
            self.tool_buttons[tid] = b
            tools.append(b)
        bar.append(tools)

        try:
            self.color_btn = Gtk.ColorDialogButton(dialog=Gtk.ColorDialog(with_alpha=False))
            self.color_btn.connect("notify::rgba", self._style_changed)
        except AttributeError:  # GTK before 4.10
            self.color_btn = Gtk.ColorButton()
            self.color_btn.connect("color-set", self._style_changed)
        self.color_btn.set_tooltip_text("Color")
        self.fill_btn = Gtk.ToggleButton()
        fill_box = hbox(4)
        fill_box.append(ToolIcon("fill", 14))
        fill_box.append(Gtk.Label(label="Fill"))
        self.fill_btn.set_child(fill_box)
        self.fill_btn.set_tooltip_text("Fill boxes and ovals instead of outlining them")
        self.fill_btn.connect("toggled", self._style_changed)
        self.width_spin = Gtk.SpinButton.new_with_range(1, 40, 1)
        self.width_spin.set_tooltip_text("Line width")
        self.width_spin.connect("value-changed", self._style_changed)
        self.width_label = label("Width", "dim-label")
        self.size_spin = Gtk.SpinButton.new_with_range(8, 200, 2)
        self.size_spin.set_tooltip_text("Text size")
        self.size_spin.connect("value-changed", self._style_changed)
        self.size_label = label("Size", "dim-label")
        for w in (self.color_btn, self.fill_btn, self.width_label, self.width_spin,
                  self.size_label, self.size_spin):
            w.set_valign(Gtk.Align.CENTER)
            bar.append(w)

        bar.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        self.undo_btn = self._icon_button("undo", "Undo (Ctrl+Z)", self.undo)
        self.redo_btn = self._icon_button("redo", "Redo (Ctrl+Shift+Z)", self.redo)
        self.delete_btn = self._icon_button("delete", "Delete the selected shape "
                                            "(Delete)", self.delete_selected)
        for w in (self.undo_btn, self.redo_btn, self.delete_btn):
            bar.append(w)

        menu = Gtk.MenuButton(icon_name="open-menu-symbolic")
        menu.set_tooltip_text("Options")
        menu.set_hexpand(True)
        menu.set_halign(Gtk.Align.END)
        pop = Gtk.Popover()
        box = vbox(6)
        margins(box, 10)
        self.auto_check = Gtk.CheckButton(label="Find PII when an image opens")
        self.auto_check.set_active(self.cfg["find_on_open"])
        self.auto_check.connect("toggled", self._auto_toggled)
        box.append(self.auto_check)
        settings = Gtk.Button(label="Choose what gets covered")
        settings.set_tooltip_text("Opens the PII Redact settings. Image Redact uses the same "
                                  "categories and word lists.")
        settings.connect("clicked", lambda *_: (pop.popdown(), self.open_settings()))
        box.append(settings)
        tip = label("Shortcuts: V C R O L A P T pick tools. Ctrl+S saves, Ctrl+C copies, F2 "
                    "renames, Ctrl+M moves. Ctrl+scroll zooms, middle-drag pans.",
                    "dim-label", wrap=True)
        tip.set_max_width_chars(42)
        box.append(tip)
        pop.set_child(box)
        menu.set_popover(pop)
        bar.append(menu)
        return bar

    def _icon_button(self, icon, tooltip, callback):
        b = Gtk.Button()
        b.set_child(ToolIcon(icon, 16))
        b.set_tooltip_text(tooltip)
        b.connect("clicked", lambda *_: callback())
        return b

    def _build_canvas(self):
        self.area = Gtk.DrawingArea()
        self.area.set_focusable(True)
        self.area.set_hexpand(True)
        self.area.set_vexpand(True)
        self.area.set_draw_func(self._draw)
        self.area.connect("resize", self._resized)

        drag = Gtk.GestureDrag(button=Gdk.BUTTON_PRIMARY)
        drag.connect("drag-begin", self._drag_begin)
        drag.connect("drag-update", self._drag_update)
        drag.connect("drag-end", self._drag_end)
        self.area.add_controller(drag)
        click = Gtk.GestureClick(button=Gdk.BUTTON_PRIMARY)
        click.connect("pressed", self._pressed)
        self.area.add_controller(click)
        pan = Gtk.GestureDrag(button=Gdk.BUTTON_MIDDLE)
        pan.connect("drag-begin", self._pan_begin)
        pan.connect("drag-update", self._pan_update)
        self.area.add_controller(pan)
        motion = Gtk.EventControllerMotion()
        motion.connect("motion", self._motion)
        self.area.add_controller(motion)
        scroll = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        scroll.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        scroll.connect("scroll", self._scrolled)
        self.area.add_controller(scroll)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._key_pressed)
        self.area.add_controller(keys)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.set_gtypes([Gdk.FileList, Gio.File, Gdk.Texture])
        drop.connect("drop", self._dropped)
        self.area.add_controller(drop)

        self.scroller = Gtk.ScrolledWindow()
        self.scroller.set_child(self.area)
        self.scroller.set_vexpand(True)
        self.scroller.get_hadjustment().connect("changed", self._adjustment_changed)
        self.scroller.get_vadjustment().connect("changed", self._adjustment_changed)
        frame = Gtk.Frame()
        frame.set_child(self.scroller)
        return frame

    def _build_file_bar(self):
        bar = hbox(6)
        bar.append(label("Name"))
        self.name_entry = Gtk.Entry()
        self.name_entry.set_width_chars(26)
        self.name_entry.set_tooltip_text("Press Enter to rename. Once it's saved, this renames "
                                         "the file itself (F2).")
        self.name_entry.connect("activate", lambda *_: self.apply_name())
        focus = Gtk.EventControllerFocus()
        focus.connect("leave", lambda *_: self.apply_name(quiet=True))
        self.name_entry.add_controller(focus)
        bar.append(self.name_entry)
        bar.append(label("in"))
        self.folder_btn = Gtk.MenuButton()
        self.folder_pop = Gtk.Popover()
        self.folder_pop.connect("show", lambda *_: self._fill_folder_menu())
        self.folder_btn.set_popover(self.folder_pop)
        bar.append(self.folder_btn)

        self.spinner = Gtk.Spinner()
        bar.append(self.spinner)
        self.status = label("")
        self.status.set_hexpand(True)
        self.status.set_ellipsize(Pango.EllipsizeMode.END)
        bar.append(self.status)

        zoom = hbox(0, css="linked")
        zoom.append(self._icon_button("zoom-out", "Zoom out (Ctrl+-)",
                                      lambda: self.step_zoom(-1)))
        self.zoom_label = Gtk.Button(label="100%")
        self.zoom_label.set_tooltip_text("Actual size")
        self.zoom_label.connect("clicked", lambda *_: self.set_zoom(1.0))
        zoom.append(self.zoom_label)
        zoom.append(self._icon_button("zoom-in", "Zoom in (Ctrl++)",
                                      lambda: self.step_zoom(1)))
        zoom.append(self._icon_button("fit", "Fit in the window (Ctrl+0)",
                                      self.zoom_fit))
        bar.append(zoom)
        self.copy_btn = button("Copy", self.copy, tooltip="Copy the finished image (Ctrl+C)")
        self.save_btn = button("Save", self.save, tooltip="Save the finished image (Ctrl+S)",
                               css="suggested-action")
        bar.append(self.copy_btn)
        bar.append(self.save_btn)
        self._update_folder_button()
        return bar

    def _build_text_popover(self):
        self.text_pop = Gtk.Popover()
        self.text_pop.set_parent(self.area)
        self.text_pop.set_autohide(True)
        box = vbox(4)
        margins(box, 6)
        self.text_entry = Gtk.Entry()
        self.text_entry.set_width_chars(28)
        self.text_entry.connect("activate", lambda *_: self._commit_text())
        box.append(self.text_entry)
        box.append(label("Enter to place it, Esc to cancel", "dim-label"))
        self.text_pop.set_child(box)
        self.text_pop.connect("closed", lambda *_: self.area.grab_focus())

    def _install_shortcuts(self):
        keys = Gtk.ShortcutController()
        pairs = [("<Control>o", self.open_dialog), ("<Control>v", self.paste),
                 ("<Control>s", self.save), ("<Control>c", self.copy),
                 ("<Control>f", self.find_pii), ("<Control>z", self.undo),
                 ("<Control><Shift>z", self.redo), ("<Control>y", self.redo),
                 ("<Control>0", self.zoom_fit), ("<Control>equal", lambda: self.step_zoom(1)),
                 ("<Control>plus", lambda: self.step_zoom(1)),
                 ("<Control>KP_Add", lambda: self.step_zoom(1)),
                 ("<Control>minus", lambda: self.step_zoom(-1)),
                 ("<Control>KP_Subtract", lambda: self.step_zoom(-1)),
                 ("F2", self.focus_name), ("<Control>m", self.folder_btn.popup)]
        for tid, _, key, _ in TOOLS:
            pairs.append((key, lambda t=tid: self.set_tool(t)))
        for trigger, callback in pairs:
            keys.add_shortcut(Gtk.Shortcut(
                trigger=Gtk.ShortcutTrigger.parse_string(trigger),
                action=Gtk.CallbackAction.new(lambda *_a, cb=callback: (cb(), True)[1])))
        self.add_controller(keys)

    # ================================================================== status
    def set_status(self, text, busy=False):
        self.status.set_text(text)
        self.status.set_tooltip_text(text)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def _update_state(self):
        have = self.surface is not None
        for w in (self.save_btn, self.copy_btn, self.name_entry, self.folder_btn):
            w.set_sensitive(have)
        self.find_btn.set_sensitive(have and self.ocr_ok)
        if not self.ocr_ok:
            self.find_btn.set_tooltip_text(self.ocr_msg)
        self.undo_btn.set_sensitive(bool(self.undo_stack))
        self.redo_btn.set_sensitive(bool(self.redo_stack))
        self.delete_btn.set_sensitive(self.selected is not None)
        self.zoom_label.set_label(f"{round(self.zoom * 100)}%")

    # ================================================================== loading
    def confirm_discard(self, then, action="Discard"):
        if not self.unsaved:
            then()
            return
        dlg = Gtk.AlertDialog(message="Discard your changes to this image?",
                              detail="They haven't been saved or copied.")
        dlg.set_buttons(["Cancel", action])
        dlg.set_cancel_button(0)
        dlg.set_default_button(0)

        def done(d, result):
            try:
                if d.choose_finish(result) == 1:
                    then()
            except GLib.Error:
                pass
        dlg.choose(self.get_root(), None, done)

    def open_dialog(self):
        def pick():
            dialog = Gtk.FileDialog(title="Open an image")
            filt = Gtk.FileFilter()
            filt.set_name("Images")
            filt.add_pixbuf_formats()
            filters = Gio.ListStore.new(Gtk.FileFilter)
            filters.append(filt)
            dialog.set_filters(filters)
            start = self.source_path and os.path.dirname(self.source_path)
            if not start:
                shots = os.path.join(ir.pictures_folder(), "Screenshots")
                start = shots if os.path.isdir(shots) else ir.pictures_folder()
            if os.path.isdir(start):
                dialog.set_initial_folder(Gio.File.new_for_path(start))

            def done(dlg, result):
                try:
                    path = dlg.open_finish(result).get_path()
                except GLib.Error:
                    return
                self.open_path(path, confirmed=True)
            dialog.open(self.get_root(), None, done)
        self.confirm_discard(pick)

    def open_path(self, path, confirmed=False):
        def go():
            self.set_status(f"Opening {os.path.basename(path)}...", busy=True)
            run_bg(lambda: ir.load_image_bytes(path), lambda png: self.load_png(png, path),
                   lambda exc: self.set_status(str(exc)))
        if confirmed:
            go()
        else:
            self.confirm_discard(go)

    def paste(self):
        def go():
            self.set_status("Reading the clipboard...", busy=True)
            if is_wsl():
                # The Windows clipboard, where Snipping Tool and Win+Shift+S put screenshots.
                run_bg(read_clipboard_image, self._pasted_bytes, self._paste_failed)
            else:
                self.get_clipboard().read_texture_async(None, self._pasted_texture)
        self.confirm_discard(go)

    def _pasted_texture(self, clipboard, result):
        try:
            texture = clipboard.read_texture_finish(result)
        except GLib.Error:
            texture = None
        if texture is not None:
            self.load_png(texture.save_to_png_bytes().get_data(), None)
        else:
            run_bg(read_clipboard_image, self._pasted_bytes, self._paste_failed)

    def _pasted_bytes(self, png):
        if png:
            self.load_png(png, None)
        else:
            self.set_status("The clipboard doesn't have an image in it.")

    def _paste_failed(self, exc):
        self.set_status(str(exc) if isinstance(exc, ClipboardError)
                        else "Couldn't read an image from the clipboard.")

    def _dropped(self, target, value, x, y):
        if isinstance(value, Gdk.Texture):
            png = value.save_to_png_bytes().get_data()
            self.confirm_discard(lambda: self.load_png(png, None))
            return True
        files = value.get_files() if isinstance(value, Gdk.FileList) else [value]
        for f in files:
            path = f.get_path()
            if path and os.path.splitext(path)[1].lower() in ir.OPEN_TYPES:
                self.open_path(path)
                return True
        self.set_status("Drop a PNG, JPEG or other image file.")
        return False

    def load_png(self, png, path):
        try:
            surface = ir.surface_from_png(png)
        except ir.ImageError as exc:
            self.set_status(str(exc))
            return
        self.generation += 1
        self.png, self.surface, self.source_path = png, surface, path
        self.shapes, self.undo_stack, self.redo_stack = [], [], []
        self.selected, self.passes, self.saved_path, self.unsaved = None, None, None, False
        self.name = ir.default_name(path)
        if path:
            self.folder = os.path.dirname(os.path.abspath(path))
        else:
            recent = [f for f in self.cfg["recent_folders"] if os.path.isdir(f)]
            self.folder = recent[0] if recent else ir.pictures_folder()
        self.name_entry.set_text(self.name)
        self._update_folder_button()
        self.zoom_fit()
        self._update_state()
        self.area.grab_focus()
        w, h = surface.get_width(), surface.get_height()
        where = os.path.basename(path) if path else "Pasted image"
        if self.ocr_ok and self.cfg["find_on_open"]:
            self.find_pii()
        else:
            self.set_status(f"{where}, {w}x{h}. Cover anything that shouldn't be shared.")

    # ================================================================== detection
    def find_pii(self):
        if self.png is None or not self.ocr_ok:
            return
        if self.passes is not None:
            self._apply_boxes()
            return
        gen = self.generation
        png, lang = self.png, self.cfg["language"]
        self.find_btn.set_sensitive(False)
        self.set_status("Reading the text in the image...", busy=True)

        def done(passes):
            if gen != self.generation:
                return
            self.passes = passes
            self.find_btn.set_sensitive(True)
            self._apply_boxes()

        def failed(exc):
            if gen != self.generation:
                return
            self.find_btn.set_sensitive(True)
            self.set_status(str(exc).splitlines()[0])
        run_bg(lambda: ir.read_text(png, lang), done, failed)

    def _apply_boxes(self):
        size = (self.surface.get_width(), self.surface.get_height())
        boxes = ir.find_boxes(self.passes, ir.redaction_options(), size)
        new = [ir.cover_shape(b, self.cfg["box_color"], auto=True) for b in boxes]
        old_auto = [s for s in self.shapes if s.get("auto")]
        if old_auto or new:
            self._checkpoint()
            self.shapes = [s for s in self.shapes if not s.get("auto")] + new
            if self.selected is not None and self.selected.get("auto"):
                self.selected = None
        self.area.queue_draw()
        self._update_state()
        msg = ir.summary([b[4] for b in boxes])
        tail = (" Check it over and cover anything it missed." if boxes else
                ". Check it over and cover anything that shouldn't be shared.")
        self.set_status(msg + ("." if boxes else "") + tail)

    def _auto_toggled(self, check):
        self.cfg["find_on_open"] = check.get_active()
        self._save_cfg()

    def open_settings(self):
        from .redact_page import RedactSettingsWindow
        if self._settings_win is None:
            root = self.get_root()
            app = root.get_application() if hasattr(root, "get_application") else None
            self._settings_win = RedactSettingsWindow(application=app, parent=root,
                                                      on_saved=self._redact_settings_saved)
            self._settings_win.connect("close-request", self._settings_closed)
        self._settings_win.present()

    def _settings_closed(self, *_):
        self._settings_win = None
        return False

    def _redact_settings_saved(self):
        # The text was already read, so finding again with new settings is instant.
        if self.passes is not None:
            self._apply_boxes()

    # ================================================================== tools and style
    def set_tool(self, tid):
        self.tool_buttons[tid].set_active(True)

    def _tool_toggled(self, btn, tid):
        if not btn.get_active():
            return
        self.tool = tid
        if tid != "select":
            self.selected = None
        self.area.set_cursor_from_name("default" if tid == "select" else "crosshair")
        self._sync_style_controls()
        self.area.queue_draw()
        self._update_state()

    def _style_kind(self):
        return self.selected["kind"] if self.selected else self.tool

    def _sync_style_controls(self):
        kind = self._style_kind()
        self._loading_style = True
        if self.selected:
            color = self.selected["color"]
        else:
            color = self.cfg["box_color"] if kind == "cover" else self.cfg["draw_color"]
        self.color_btn.set_rgba(rgba(color))
        sel = self.selected
        self.fill_btn.set_active(bool(sel.get("fill")) if sel else self.cfg["fill"])
        self.width_spin.set_value(sel.get("width", self.cfg["width"]) if sel and kind != "cover"
                                  else self.cfg["width"])
        self.size_spin.set_value(sel["size"] if sel and kind == "text" else self.cfg["text_size"])
        self.fill_btn.set_visible(kind in ("rect", "oval"))
        line_like = kind in ("rect", "oval", "line", "arrow", "pen")
        self.width_spin.set_visible(line_like)
        self.width_label.set_visible(line_like)
        self.size_spin.set_visible(kind == "text")
        self.size_label.set_visible(kind == "text")
        self.color_btn.set_visible(kind != "select")
        self._loading_style = False

    def _style_changed(self, *_):
        if self._loading_style:
            return
        color = from_rgba(self.color_btn.get_rgba())
        kind = self._style_kind()
        if self.selected:
            self._checkpoint()
            sel = self.selected
            sel["color"] = color
            if kind in ("rect", "oval"):
                sel["fill"] = self.fill_btn.get_active()
            if kind in ("rect", "oval", "line", "arrow", "pen"):
                sel["width"] = self.width_spin.get_value()
            if kind == "text":
                sel["size"] = self.size_spin.get_value()
            sel.pop("auto", None)
            self._changed()
        else:
            if kind == "cover":
                self.cfg["box_color"] = color
            elif kind != "select":
                self.cfg["draw_color"] = color
            if kind in ("rect", "oval"):
                self.cfg["fill"] = self.fill_btn.get_active()
            self.cfg["width"] = int(self.width_spin.get_value())
            self.cfg["text_size"] = int(self.size_spin.get_value())
            self._save_cfg()

    def _save_cfg(self):
        if self._cfg_save_id:
            GLib.source_remove(self._cfg_save_id)

        def go():
            self._cfg_save_id = 0
            cfg = ir.load_config()
            for key in ("find_on_open", "box_color", "draw_color", "width", "fill", "text_size",
                        "recent_folders"):
                cfg[key] = self.cfg[key]
            ir.save_config(cfg)
            return GLib.SOURCE_REMOVE
        self._cfg_save_id = GLib.timeout_add(400, go)

    # ================================================================== undo
    def _checkpoint(self):
        self.undo_stack.append(copy.deepcopy(self.shapes))
        del self.undo_stack[:-100]
        self.redo_stack.clear()

    def _changed(self):
        self.unsaved = True
        self.area.queue_draw()
        self._update_state()

    def undo(self):
        if self.undo_stack:
            self.redo_stack.append(copy.deepcopy(self.shapes))
            self.shapes = self.undo_stack.pop()
            self.selected = None
            self._changed()

    def redo(self):
        if self.redo_stack:
            self.undo_stack.append(copy.deepcopy(self.shapes))
            self.shapes = self.redo_stack.pop()
            self.selected = None
            self._changed()

    def delete_selected(self):
        if self.selected is not None and self.selected in self.shapes:
            self._checkpoint()
            self.shapes = [s for s in self.shapes if s is not self.selected]
            self.selected = None
            self._sync_style_controls()
            self._changed()

    # ================================================================== zoom
    def _image_size(self):
        return (self.surface.get_width(), self.surface.get_height()) if self.surface else (1, 1)

    def zoom_fit(self):
        self.fit = True
        self.area.set_content_width(1)
        self.area.set_content_height(1)
        self._fit_zoom(self.area.get_width(), self.area.get_height())

    def _fit_zoom(self, w, h):
        iw, ih = self._image_size()
        if w > 2 * PAD and h > 2 * PAD:
            self.zoom = min((w - 2 * PAD) / iw, (h - 2 * PAD) / ih, 1.0)
        self.area.queue_draw()
        self._update_state()

    def _resized(self, area, w, h):
        if self.fit:
            self._fit_zoom(w, h)

    def set_zoom(self, zoom, anchor=None):
        if self.surface is None:
            return
        zoom = min(max(zoom, ZOOMS[0]), ZOOMS[-1])
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        if anchor is None:
            anchor = (hadj.get_page_size() / 2, vadj.get_page_size() / 2)
        vx, vy = anchor
        ix, iy = self.to_image(hadj.get_value() + vx, vadj.get_value() + vy)
        self.fit = False
        self.zoom = zoom
        iw, ih = self._image_size()
        cw, ch = int(iw * zoom + 2 * PAD), int(ih * zoom + 2 * PAD)
        self.area.set_content_width(cw)
        self.area.set_content_height(ch)
        # Keep the same spot under the pointer once the new size is laid out.
        ox = max(PAD, (max(cw, hadj.get_page_size()) - iw * zoom) / 2)
        oy = max(PAD, (max(ch, vadj.get_page_size()) - ih * zoom) / 2)
        self._scroll_target = (ox + ix * zoom - vx, oy + iy * zoom - vy)
        self._adjustment_changed()
        self.area.queue_draw()
        self._update_state()

    def _adjustment_changed(self, *_):
        if self._scroll_target is None:
            return
        tx, ty = self._scroll_target
        for adj, value in ((self.scroller.get_hadjustment(), tx),
                           (self.scroller.get_vadjustment(), ty)):
            adj.set_value(min(max(value, 0), max(adj.get_upper() - adj.get_page_size(), 0)))

    def step_zoom(self, direction, anchor=None):
        if direction > 0:
            nxt = next((z for z in ZOOMS if z > self.zoom * 1.01), ZOOMS[-1])
        else:
            nxt = next((z for z in reversed(ZOOMS) if z < self.zoom * 0.99), ZOOMS[0])
        self.set_zoom(nxt, anchor)

    def _scrolled(self, ctrl, dx, dy):
        state = ctrl.get_current_event_state()
        if not state & Gdk.ModifierType.CONTROL_MASK or self.surface is None:
            return False
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        px, py = getattr(self, "_pointer", (hadj.get_page_size() / 2, vadj.get_page_size() / 2))
        anchor = (px - hadj.get_value(), py - vadj.get_value())
        self.step_zoom(-1 if dy > 0 else 1, anchor)
        return True

    def _pan_begin(self, gesture, x, y):
        self._pan_start = (self.scroller.get_hadjustment().get_value(),
                           self.scroller.get_vadjustment().get_value())
        self._scroll_target = None

    def _pan_update(self, gesture, dx, dy):
        hx, vy = self._pan_start
        self.scroller.get_hadjustment().set_value(hx - dx)
        self.scroller.get_vadjustment().set_value(vy - dy)

    # ================================================================== coordinates
    def to_image(self, x, y):
        return (x - self.ox) / self.zoom, (y - self.oy) / self.zoom

    def to_view(self, x, y):
        return self.ox + x * self.zoom, self.oy + y * self.zoom

    def _handles(self, shape):
        if shape["kind"] in ("line", "arrow"):
            return [(shape["x1"], shape["y1"]), (shape["x2"], shape["y2"])]
        if shape["kind"] in ("cover", "rect", "oval"):
            x1, y1, x2, y2 = ir.rect_of(shape)
            return [(x1, y1), (x2, y1), (x2, y2), (x1, y2)]
        return []

    def _handle_at(self, x, y):
        if self.selected is None:
            return None
        for i, (hx, hy) in enumerate(self._handles(self.selected)):
            vx, vy = self.to_view(hx, hy)
            if abs(vx - x) <= HANDLE + 3 and abs(vy - y) <= HANDLE + 3:
                return i
        return None

    def _shape_at(self, ix, iy):
        tol = 5 / self.zoom
        for shape in reversed(self.shapes):
            if ir.hit(shape, ix, iy, tol):
                return shape
        return None

    # ================================================================== mouse
    def _pressed(self, gesture, n, x, y):
        self.area.grab_focus()
        if n == 2 and self.surface is not None:
            shape = self._shape_at(*self.to_image(x, y))
            if shape and shape["kind"] == "text":
                self._edit_text(shape)

    def _drag_begin(self, gesture, x, y):
        self.area.grab_focus()
        if self.surface is None:
            return
        ix, iy = self.to_image(x, y)
        self.drag = {"start": (ix, iy), "view": (x, y), "moved": False}
        tool = self.tool
        if tool == "select":
            handle = self._handle_at(x, y)
            if handle is not None:
                self.drag.update(mode="resize", handle=handle,
                                 before=copy.deepcopy(self.shapes),
                                 orig=copy.deepcopy(self.selected))
                if self.selected["kind"] in ("cover", "rect", "oval"):
                    x1, y1, x2, y2 = ir.rect_of(self.selected)
                    self.selected.update(x1=x1, y1=y1, x2=x2, y2=y2)
                    self.drag["orig"] = copy.deepcopy(self.selected)
                return
            shape = self._shape_at(ix, iy)
            self.selected = shape
            self._sync_style_controls()
            if shape is not None:
                self.drag.update(mode="move", before=copy.deepcopy(self.shapes),
                                 orig=copy.deepcopy(shape))
            else:
                self.drag["mode"] = None
            self.area.queue_draw()
            self._update_state()
            return
        if tool == "text":
            self.drag["mode"] = "text"
            return
        color = self.cfg["box_color"] if tool == "cover" else self.cfg["draw_color"]
        if tool == "pen":
            self.draft = {"kind": "pen", "points": [[ix, iy]], "color": list(color),
                          "width": self.cfg["width"], "fill": False}
        else:
            self.draft = {"kind": tool, "x1": ix, "y1": iy, "x2": ix, "y2": iy,
                          "color": list(color), "width": 0 if tool == "cover" else
                          self.cfg["width"], "fill": tool == "cover" or (
                              tool in ("rect", "oval") and self.cfg["fill"])}
        self.drag["mode"] = "create"

    def _drag_update(self, gesture, dx, dy):
        d = self.drag
        if not d or not d.get("mode"):
            return
        if abs(dx) > 2 or abs(dy) > 2:
            d["moved"] = True
        sx, sy = d["start"]
        ix, iy = sx + dx / self.zoom, sy + dy / self.zoom
        shift = gesture.get_current_event_state() & Gdk.ModifierType.SHIFT_MASK
        mode = d["mode"]
        if mode == "create" and self.draft is not None:
            if self.draft["kind"] == "pen":
                last = self.draft["points"][-1]
                if math.hypot(ix - last[0], iy - last[1]) * self.zoom >= 2:
                    self.draft["points"].append([ix, iy])
            else:
                if shift:
                    ix, iy = self._constrain(self.draft["kind"], sx, sy, ix, iy)
                self.draft["x2"], self.draft["y2"] = ix, iy
        elif mode == "move" and self.selected is not None:
            o = d["orig"]
            for k in ("x1", "y1", "x2", "y2", "x", "y", "points"):
                if k in o:
                    self.selected[k] = copy.deepcopy(o[k])
            ir.translate(self.selected, dx / self.zoom, dy / self.zoom)
        elif mode == "resize" and self.selected is not None:
            o, h, sel = d["orig"], d["handle"], self.selected
            if sel["kind"] in ("line", "arrow"):
                if shift:
                    ax, ay = (o["x2"], o["y2"]) if h == 0 else (o["x1"], o["y1"])
                    ix, iy = self._constrain(sel["kind"], ax, ay, ix, iy)
                sel["x1" if h == 0 else "x2"] = ix
                sel["y1" if h == 0 else "y2"] = iy
            else:
                sel["x1"] = ix if h in (0, 3) else o["x1"]
                sel["x2"] = ix if h in (1, 2) else o["x2"]
                sel["y1"] = iy if h in (0, 1) else o["y1"]
                sel["y2"] = iy if h in (2, 3) else o["y2"]
        self.area.queue_draw()

    @staticmethod
    def _constrain(kind, sx, sy, x, y):
        dx, dy = x - sx, y - sy
        if kind in ("cover", "rect", "oval"):
            side = max(abs(dx), abs(dy))
            return sx + math.copysign(side, dx or 1), sy + math.copysign(side, dy or 1)
        angle = round(math.atan2(dy, dx) / (math.pi / 4)) * (math.pi / 4)
        length = math.hypot(dx, dy)
        return sx + length * math.cos(angle), sy + length * math.sin(angle)

    def _drag_end(self, gesture, dx, dy):
        d, self.drag = self.drag, None
        if not d or not d.get("mode"):
            return
        mode = d["mode"]
        if mode == "text":
            if not d["moved"]:
                hit = self._shape_at(*d["start"])
                if hit is not None and hit["kind"] == "text":
                    self._edit_text(hit)
                else:
                    self._new_text(*d["start"])
            return
        if mode == "create":
            draft, self.draft = self.draft, None
            if draft is None:
                return
            if draft["kind"] == "pen":
                keep = len(draft["points"]) >= 2 or not d["moved"]
            else:
                x1, y1, x2, y2 = ir.rect_of(draft)
                keep = max(x2 - x1, y2 - y1) * self.zoom >= 4
            if keep:
                self._checkpoint()
                self.shapes.append(draft)
                self._changed()
            self.area.queue_draw()
            return
        if d["moved"] and self.selected is not None:
            self.undo_stack.append(d["before"])
            del self.undo_stack[:-100]
            self.redo_stack.clear()
            self.selected.pop("auto", None)
            self._changed()

    def _motion(self, ctrl, x, y):
        self._pointer = (x, y)
        if self.surface is None or self.drag:
            return
        if self.tool == "select":
            if self._handle_at(x, y) is not None:
                self.area.set_cursor_from_name("crosshair")
                return
            shape = self._shape_at(*self.to_image(x, y))
            self.area.set_cursor_from_name("move" if shape else "default")
            if shape is not None and shape.get("auto"):
                self.status.set_text("Found by text detection: " + ir.label_name(
                    shape.get("label", "")))

    def _key_pressed(self, ctrl, keyval, keycode, state):
        if keyval in (Gdk.KEY_Delete, Gdk.KEY_BackSpace, Gdk.KEY_KP_Delete):
            self.delete_selected()
            return True
        if keyval == Gdk.KEY_Escape:
            self.drag, self.draft, self.selected = None, None, None
            self._sync_style_controls()
            self.area.queue_draw()
            self._update_state()
            return True
        moves = {Gdk.KEY_Left: (-1, 0), Gdk.KEY_Right: (1, 0), Gdk.KEY_Up: (0, -1),
                 Gdk.KEY_Down: (0, 1)}
        if keyval in moves and self.selected is not None:
            step = 10 if state & Gdk.ModifierType.SHIFT_MASK else 1
            self._checkpoint()
            ir.translate(self.selected, moves[keyval][0] * step, moves[keyval][1] * step)
            self.selected.pop("auto", None)
            self._changed()
            return True
        return False

    # ================================================================== text
    def _new_text(self, ix, iy):
        self.text_target = (ix, iy, None)
        self.text_entry.set_text("")
        self._show_text_popover(ix, iy)

    def _edit_text(self, shape):
        self.text_target = (shape["x"], shape["y"], shape)
        self.text_entry.set_text(shape["text"])
        self._show_text_popover(shape["x"], shape["y"])

    def _show_text_popover(self, ix, iy):
        vx, vy = self.to_view(ix, iy)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(vx), int(vy), 1, 1
        self.text_pop.set_pointing_to(rect)
        self.text_pop.popup()
        self.text_entry.grab_focus()

    def _commit_text(self):
        text = self.text_entry.get_text()
        target, self.text_target = self.text_target, None
        self.text_pop.popdown()
        if target is None:
            return
        ix, iy, shape = target
        if shape is not None:
            if text.strip() and text != shape["text"]:
                self._checkpoint()
                shape["text"] = text
                self._changed()
            elif not text.strip():
                self.selected = shape
                self.delete_selected()
            return
        if text.strip():
            self._checkpoint()
            self.shapes.append({"kind": "text", "x": ix, "y": iy, "text": text,
                                "size": self.cfg["text_size"],
                                "color": list(self.cfg["draw_color"]), "width": 0,
                                "fill": False})
            self._changed()

    # ================================================================== drawing
    def _draw(self, area, cr, w, h):
        fg = fg_color(area)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.05)
        cr.paint()
        if self.surface is None:
            self._draw_empty(cr, w, h, fg)
            return
        iw, ih = self._image_size()
        z = self.zoom
        self.ox = max(PAD, (w - iw * z) / 2)
        self.oy = max(PAD, (h - ih * z) / 2)
        cr.set_source_rgba(0, 0, 0, 0.25)
        cr.rectangle(self.ox + 1, self.oy + 2, iw * z, ih * z)
        cr.fill()
        cr.save()
        cr.translate(self.ox, self.oy)
        cr.scale(z, z)
        cr.rectangle(0, 0, iw, ih)
        cr.clip()
        cr.set_source_surface(self.surface, 0, 0)
        cr.get_source().set_filter(cairo.FILTER_GOOD if z < 1 else (
            cairo.FILTER_NEAREST if z >= 2 else cairo.FILTER_BILINEAR))
        cr.paint()
        see = self.peek_btn.get_active()
        ir.draw_shapes(cr, self.shapes, see_through=see)
        if see:
            cr.set_line_width(1.5 / z)
            cr.set_dash([4 / z, 3 / z])
            for s in self.shapes:
                if ir.is_cover(s):
                    x1, y1, x2, y2 = ir.rect_of(s)
                    cr.set_source_rgba(1, 0.75, 0, 0.95)
                    cr.rectangle(x1, y1, x2 - x1, y2 - y1)
                    cr.stroke()
            cr.set_dash([])
        if self.draft is not None:
            ir.draw_shapes(cr, [self.draft])
        cr.restore()
        if self.selected is not None and self.selected in self.shapes:
            self._draw_selection(cr)

    def _draw_selection(self, cr):
        x1, y1, x2, y2 = ir.bbox(self.selected)
        vx1, vy1 = self.to_view(x1, y1)
        vx2, vy2 = self.to_view(x2, y2)
        cr.set_line_width(1)
        cr.set_dash([5, 3])
        cr.set_source_rgba(0.2, 0.52, 0.89, 1)
        cr.rectangle(vx1 - 3.5, vy1 - 3.5, vx2 - vx1 + 7, vy2 - vy1 + 7)
        cr.stroke()
        cr.set_dash([])
        for hx, hy in self._handles(self.selected):
            vx, vy = self.to_view(hx, hy)
            cr.rectangle(vx - HANDLE, vy - HANDLE, HANDLE * 2, HANDLE * 2)
            cr.set_source_rgb(1, 1, 1)
            cr.fill_preserve()
            cr.set_source_rgba(0.2, 0.52, 0.89, 1)
            cr.stroke()

    def _draw_empty(self, cr, w, h, fg):
        import gi
        gi.require_version("PangoCairo", "1.0")
        from gi.repository import PangoCairo
        layout = self.area.create_pango_layout(None)
        layout.set_alignment(Pango.Alignment.CENTER)
        layout.set_width(int(min(w - 40, 560) * Pango.SCALE))
        layout.set_wrap(Pango.WrapMode.WORD)
        layout.set_markup(
            "<span size='large' weight='bold'>Paste a screenshot with Ctrl+V, drop an image "
            "here, or click Open</span>\n\n"
            "Account IDs, keys, ARNs, emails and other identifying text get covered with "
            "solid boxes. Then draw over anything it missed and save or copy it.", -1)
        _, logical = layout.get_pixel_extents()
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.6)
        cr.move_to((w - logical.width) / 2 - logical.x, (h - logical.height) / 2)
        PangoCairo.show_layout(cr, layout)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.18)
        cr.set_line_width(2)
        cr.set_dash([8, 6])
        cr.rectangle(PAD, PAD, w - 2 * PAD, h - 2 * PAD)
        cr.stroke()

    # ================================================================== files
    def _target(self):
        return os.path.join(self.folder, self.name)

    def _update_folder_button(self):
        name = os.path.basename(self.folder.rstrip(os.sep)) or self.folder
        if os.path.abspath(self.folder) == os.path.expanduser("~"):
            name = "Home"
        self.folder_btn.set_label(name)
        self.folder_btn.set_tooltip_text(f"{ir.short_path(self.folder)}\nPick where it saves. "
                                         "Once saved, picking a folder moves the file (Ctrl+M).")

    def _fill_folder_menu(self):
        box = vbox(2)
        margins(box, 8)
        heading = "Move to" if self.saved_path else "Save in"
        box.append(label(heading, "heading"))
        seen = set()
        folders = [self.folder] + list(self.cfg["recent_folders"])
        if self.source_path:
            folders.append(os.path.dirname(self.source_path))
        folders.append(ir.pictures_folder())
        for f in folders:
            f = os.path.abspath(f)
            if f in seen or not os.path.isdir(f):
                continue
            seen.add(f)
            b = Gtk.ToggleButton(label=ir.short_path(f))
            b.set_active(f == os.path.abspath(self.folder))
            b.add_css_class("flat")
            b.get_child().set_xalign(0)
            b.connect("clicked", lambda _b, path=f: (self.folder_pop.popdown(),
                                                     self.set_folder(path)))
            box.append(b)
        box.append(Gtk.Separator())
        choose = Gtk.Button(label="Choose another folder")
        choose.add_css_class("flat")
        choose.connect("clicked", lambda *_: (self.folder_pop.popdown(), self.choose_folder()))
        box.append(choose)
        show = Gtk.Button(label="Open this folder")
        show.add_css_class("flat")
        show.connect("clicked", lambda *_: (self.folder_pop.popdown(), self.show_folder()))
        box.append(show)
        self.folder_pop.set_child(box)

    def choose_folder(self):
        dialog = Gtk.FileDialog(title="Move to folder" if self.saved_path else "Save in folder")
        if os.path.isdir(self.folder):
            dialog.set_initial_folder(Gio.File.new_for_path(self.folder))

        def done(dlg, result):
            try:
                path = dlg.select_folder_finish(result).get_path()
            except GLib.Error:
                return
            if path:
                self.set_folder(path)
        dialog.select_folder(self.get_root(), None, done)

    def show_folder(self):
        folder = os.path.dirname(self.saved_path) if self.saved_path else self.folder
        try:
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(folder).get_uri(), None)
        except GLib.Error as exc:
            self.set_status(f"Couldn't open the folder: {exc.message}")

    def focus_name(self):
        if self.surface is None:
            return
        self.name_entry.grab_focus()
        stem = os.path.splitext(self.name_entry.get_text())[0]
        self.name_entry.select_region(0, len(stem))

    def _ask_replace(self, path, then):
        dlg = Gtk.AlertDialog(message=f"Replace {os.path.basename(path)}?",
                              detail=f"There's already a file with that name in "
                                     f"{ir.short_path(os.path.dirname(path))}.")
        dlg.set_buttons(["Cancel", "Replace"])
        dlg.set_cancel_button(0)
        dlg.set_default_button(0)

        def done(d, result):
            try:
                if d.choose_finish(result) == 1:
                    then()
            except GLib.Error:
                pass
        dlg.choose(self.get_root(), None, done)

    def apply_name(self, quiet=False):
        if self.surface is None:
            return
        typed = self.name_entry.get_text()
        try:
            name = ir.clean_name(typed, ir.file_type(self.name))
        except ValueError as exc:
            self.name_entry.set_text(self.name)
            if not quiet:
                self.set_status(str(exc))
            return
        if name == self.name:
            if typed != name:
                self.name_entry.set_text(name)
            return
        if not self.saved_path:
            self.name = name
            self.name_entry.set_text(name)
            if not quiet:
                self.set_status(f"Will save as {ir.short_path(self._target())}")
            return
        self._relocate(os.path.join(os.path.dirname(self.saved_path), name), "Renamed to")

    def set_folder(self, folder):
        folder = os.path.abspath(folder)
        if not self.saved_path:
            self.folder = folder
            self._update_folder_button()
            self.set_status(f"Will save as {ir.short_path(self._target())}")
            return
        if folder == os.path.dirname(self.saved_path):
            return
        self._relocate(os.path.join(folder, os.path.basename(self.saved_path)), "Moved to")

    def _relocate(self, dest, verb):
        src = self.saved_path

        def go():
            try:
                ir.relocate(src, dest)
            except (OSError, ir.ImageError) as exc:
                self.name_entry.set_text(self.name)
                show_message(self.get_root(), "Couldn't move the file", str(exc))
                return
            self.saved_path = dest
            self.folder, self.name = os.path.dirname(dest), os.path.basename(dest)
            self.name_entry.set_text(self.name)
            self._update_folder_button()
            self._remember(self.folder)
            self.set_status(f"{verb} {ir.short_path(dest)}")

        if os.path.exists(dest) and os.path.abspath(dest) != os.path.abspath(src):
            self.name_entry.set_text(self.name)
            self._ask_replace(dest, go)
        elif not os.path.exists(src):
            # Moved or deleted outside the app, so the next save just writes a new file.
            self.saved_path = None
            self.folder, self.name = os.path.dirname(dest), os.path.basename(dest)
            self.name_entry.set_text(self.name)
            self._update_folder_button()
            self.set_status(f"The saved file is gone. Will save as {ir.short_path(dest)}")
        else:
            go()

    def _remember(self, folder):
        ir.remember_folder(self.cfg, folder)
        self._save_cfg()

    def save(self):
        if self.surface is None:
            return
        self.apply_name(quiet=True)
        path = self._target()
        if os.path.exists(path) and path != self.saved_path:
            self._ask_replace(path, lambda: self._write(path))
        else:
            self._write(path)

    def _write(self, path):
        try:
            data = ir.encode(self.png, self.shapes, ir.file_type(path))
            ir.write_atomic(path, data)
        except (OSError, ir.ImageError) as exc:
            show_message(self.get_root(), "Couldn't save", str(exc))
            return
        self.saved_path = path
        self.unsaved = False
        self._remember(os.path.dirname(path))
        self.set_status(f"Saved to {ir.short_path(path)}")

    def copy(self):
        if self.surface is None:
            return
        try:
            png = ir.encode(self.png, self.shapes, ".png")
        except ir.ImageError as exc:
            self.set_status(str(exc))
            return
        set_clipboard_image(self, png)
        self.unsaved = False
        self.set_status("Copied the finished image. It's ready to paste.")


def set_clipboard_image(widget, png):
    """Like set_clipboard for text: on WSL it goes to the Windows clipboard, and outside
    GNOME wl-copy or xclip keep it around after the window closes."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
    if is_wsl() or "GNOME" not in desktop:
        try:
            write_clipboard_image(png)
            return
        except ClipboardError:
            pass
    texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(png))
    widget.get_clipboard().set_texture(texture)


class ImagePage(Page):
    name = "image"
    title = "Image Redact"

    def __init__(self, win):
        super().__init__(win, "Paste or open a screenshot. Account IDs, keys, emails and other "
                         "identifying text get covered with solid boxes, using your PII Redact "
                         "settings. Draw over anything it missed, then save or copy. Nothing "
                         "leaves your machine.")
        self.editor = ImageEditor()
        margins(self.editor, 10)
        self.editor.set_margin_top(4)
        self.editor.set_vexpand(True)
        self.append(self.editor)
        # Focus the canvas when the page shows, so Ctrl+V pastes right away.
        self.connect("map", lambda *_: self.editor.area.grab_focus())
        win.connect("close-request", self._close_request)
        self._closing = False

    def _close_request(self, win):
        if self._closing or not self.editor.unsaved:
            return False

        def close():
            self._closing = True
            win.close()
        self.editor.confirm_discard(close, action="Close without saving")
        return True


class ImageWindow(Gtk.ApplicationWindow):
    """Image Redact on its own, for a keybind, the launcher entry or Open With."""

    def __init__(self, app, path=None, paste=False):
        super().__init__(application=app, title="Image Redact")
        self.set_default_size(1180, 800)
        self.editor = ImageEditor()
        margins(self.editor, 10)
        self.set_child(self.editor)
        self._closing = False
        self.connect("close-request", self._close_request)
        self.editor.area.grab_focus()
        if path:
            self.editor.open_path(path, confirmed=True)
        elif paste:
            GLib.idle_add(lambda: (self.editor.paste(), False)[1])

    def _close_request(self, *_):
        if self._closing or not self.editor.unsaved:
            return False

        def close():
            self._closing = True
            self.close()
        self.editor.confirm_discard(close, action="Close without saving")
        return True
