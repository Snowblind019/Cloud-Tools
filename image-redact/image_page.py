"""Image Redact in the window on Linux: the GTK editor, its page in AWS Kit, and its own
small window. The editing itself lives in imageedit.py, shared with the Windows window."""
from __future__ import annotations

import os

from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from . import imageedit as ie
from . import imageredact as ir
from .common import ClipboardError, is_wsl, read_clipboard_image, write_clipboard_image
from .widgets import (Page, button, hbox, label, margins, run_bg, scroll_kind,
                      show_message, vbox)

PAD = ie.PAD


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
        ie.draw_icon(cr, self.kind, w, h, (c.red, c.green, c.blue, c.alpha))


class ImageEditor(Gtk.Box):
    """Open or paste a screenshot, cover what text detection finds, fix it up by hand,
    then save, rename, move or copy the result."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.ed = ie.Editor()
        self.zoom, self.fit = 1.0, True
        self.ox = self.oy = PAD
        self.text_request = None
        self._double_text = None
        self._loading_style = False
        self._zoom_anchor = None        # (image x, image y, view x, view y) to keep in place
        self._wheel = [0.0, 0.0, 0]     # notches so far, last direction, time of last one
        self._pinch = None
        self._pointer_view = None
        self._settings_win = None
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

    @property
    def unsaved(self):
        return self.ed.unsaved

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
        for tid, _name, _key, tip in ie.TOOLS:
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
            self.color_btn.connect("notify::rgba", self._color_changed)
        except AttributeError:  # GTK before 4.10
            self.color_btn = Gtk.ColorButton()
            self.color_btn.connect("color-set", self._color_changed)
        self.color_btn.set_tooltip_text("Color")
        self.fill_btn = Gtk.ToggleButton()
        fill_box = hbox(4)
        fill_box.append(ToolIcon("fill", 14))
        fill_box.append(Gtk.Label(label="Fill"))
        self.fill_btn.set_child(fill_box)
        self.fill_btn.set_tooltip_text("Fill boxes and ovals instead of outlining them")
        self.fill_btn.connect("toggled", self._fill_changed)
        self.width_spin = self._spin(1, 40, 1, "Line width", "width")
        self.width_label = label("Width", "dim-label")
        self.size_spin = self._spin(8, 200, 2, "Text size", "size")
        self.size_label = label("Size", "dim-label")
        self.corners_spin = self._spin(0, 60, 1, "Round the corners of Cover and Box shapes. "
                                       "Rounded covers grow a little so the corners still "
                                       "cover everything.", "corners")
        self.corners_label = label("Corners", "dim-label")
        for w in (self.color_btn, self.fill_btn, self.width_label, self.width_spin,
                  self.size_label, self.size_spin, self.corners_label, self.corners_spin):
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
        self.auto_check.set_active(self.ed.cfg["find_on_open"])
        self.auto_check.connect("toggled", self._auto_toggled)
        box.append(self.auto_check)
        settings = Gtk.Button(label="Choose what gets covered")
        settings.set_tooltip_text("Opens the PII Redact settings. Image Redact uses the same "
                                  "categories and word lists.")
        settings.connect("clicked", lambda *_: (pop.popdown(), self.open_settings()))
        box.append(settings)
        tip = label("Shortcuts: " + ie.SHORTCUTS_HELP, "dim-label", wrap=True)
        tip.set_max_width_chars(42)
        box.append(tip)
        pop.set_child(box)
        menu.set_popover(pop)
        bar.append(menu)
        return bar

    def _spin(self, low, high, step, tooltip, key):
        spin = Gtk.SpinButton.new_with_range(low, high, step)
        spin.set_tooltip_text(tooltip)
        spin.connect("value-changed", self._spin_changed, key)
        return spin

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
        pinch = Gtk.GestureZoom()
        pinch.connect("begin", self._pinch_begin)
        pinch.connect("scale-changed", self._pinch_changed)
        self.area.add_controller(pinch)
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
        # Where the pointer is in the visible part, which stays put while the image moves
        # under it as it zooms.
        where = Gtk.EventControllerMotion()
        where.connect("enter", self._pointer_moved)
        where.connect("motion", self._pointer_moved)
        self.scroller.add_controller(where)
        frame = Gtk.Frame()
        frame.set_child(self.scroller)
        # The wheel is handled on the frame around the scroller, before anything inside it
        # sees the event. Once a smooth scroll starts (a high resolution wheel never ends
        # one), the scroller takes every scroll for itself first, which is why zooming
        # worked only some of the time when this sat on the image.
        wheel = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.BOTH_AXES)
        wheel.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        wheel.connect("scroll", self._scrolled)
        frame.add_controller(wheel)
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
        zoom.append(self._icon_button("fit", "Fit in the window (Ctrl+0)", self.zoom_fit))
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
        for tid, _, key, _ in ie.TOOLS:
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
        have = self.ed.surface is not None
        # Nothing goes out while text detection is still deciding what to cover.
        ready = have and not self.ed.finding
        for w in (self.save_btn, self.copy_btn):
            w.set_sensitive(ready)
        for w in (self.name_entry, self.folder_btn):
            w.set_sensitive(have)
        self.find_btn.set_sensitive(ready and self.ocr_ok)
        if not self.ocr_ok:
            self.find_btn.set_tooltip_text(self.ocr_msg)
        self.undo_btn.set_sensitive(bool(self.ed.undo_stack))
        self.redo_btn.set_sensitive(bool(self.ed.redo_stack))
        self.delete_btn.set_sensitive(self.ed.selected is not None)
        self.zoom_label.set_label(f"{round(self.zoom * 100)}%")

    def _refresh(self):
        self.area.queue_draw()
        self._update_state()

    # ================================================================== loading
    def confirm_discard(self, then, action="Discard"):
        if not self.ed.unsaved:
            then()
            return
        self._ask("Discard your changes to this image?", "They haven't been saved or copied.",
                  action, then)

    def _ask(self, message, detail, action, then):
        dlg = Gtk.AlertDialog(message=message, detail=detail)
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
            start = self.ed.source_path and os.path.dirname(self.ed.source_path)
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

    def _latest(self):
        """Wraps one open or paste's callbacks. Starting another open or paste makes the
        older one's result count for nothing, so a slow open that finishes after a paste
        can't replace the pasted image without asking."""
        self._load_seq = getattr(self, "_load_seq", 0) + 1
        seq = self._load_seq

        def wrap(fn):
            def call(*args):
                if seq == self._load_seq:
                    return fn(*args)
                return None
            return call
        return wrap

    def open_path(self, path, confirmed=False):
        def go():
            latest = self._latest()
            self.set_status(f"Opening {os.path.basename(path)}...", busy=True)
            run_bg(lambda: ir.load_image_bytes(path),
                   latest(lambda png: self.load_png(png, path)),
                   latest(lambda exc: self.set_status(str(exc))))
        if confirmed:
            go()
        else:
            self.confirm_discard(go)

    def paste(self):
        def go():
            latest = self._latest()
            self.set_status("Reading the clipboard...", busy=True)
            if is_wsl():
                # The Windows clipboard, where Snipping Tool and Win+Shift+S put screenshots.
                run_bg(read_clipboard_image, latest(self._pasted_bytes),
                       latest(self._paste_failed))
            else:
                self.get_clipboard().read_texture_async(
                    None, lambda clip, result: self._pasted_texture(clip, result, latest))
        self.confirm_discard(go)

    def _pasted_texture(self, clipboard, result, latest=None):
        latest = latest or (lambda fn: fn)
        try:
            texture = clipboard.read_texture_finish(result)
        except GLib.Error:
            texture = None
        if texture is not None:
            latest(self.load_png)(texture.save_to_png_bytes().get_data(), None)
        else:
            run_bg(read_clipboard_image, latest(self._pasted_bytes), latest(self._paste_failed))

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
            self.confirm_discard(lambda: (self._latest(), self.load_png(png, None)))
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
            self.ed.load(png, path)
        except ir.ImageError as exc:
            self.set_status(str(exc))
            return
        self.name_entry.set_text(self.ed.name)
        self._update_folder_button()
        self._sync_style_controls()
        self.zoom_fit()
        self._update_state()
        self.area.grab_focus()
        if self.ocr_ok and self.ed.cfg["find_on_open"]:
            self.find_pii()
        else:
            self.set_status(self.ed.describe())

    # ================================================================== detection
    def find_pii(self):
        ed = self.ed
        if ed.png is None or not self.ocr_ok or ed.finding:
            return
        if ed.passes is not None and not ed.ocr_warning:
            self._apply_boxes()
            return
        png, lang = ed.png, ed.cfg["language"]
        gen = ed.start_finding()
        self._update_state()
        self.set_status("Reading the text in the image...", busy=True)

        def finished(apply):
            selected = ed.selected
            msg = apply()
            if msg is not None:
                if ed.selected is not selected:
                    # A detected box that was selected is gone, so its controls go too.
                    self._sync_style_controls()
                self._refresh()
                self.set_status(msg)
        run_bg(lambda: ir.read_text(png, lang),
               lambda passes: finished(lambda: ed.found(gen, passes)),
               lambda exc: finished(lambda: ed.find_failed(gen, exc)))

    def _apply_boxes(self):
        selected = self.ed.selected
        msg = self.ed.apply_passes()
        if self.ed.selected is not selected:
            self._sync_style_controls()
        self._refresh()
        self.set_status(msg)

    def _auto_toggled(self, check):
        self.ed.cfg["find_on_open"] = check.get_active()
        self.ed.save_cfg()

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
        # The text was already read, so finding again with new settings is instant. While
        # it's being read again, the new settings apply when that's done.
        if self.ed.passes is not None and not self.ed.finding:
            self._apply_boxes()

    # ================================================================== tools and style
    def set_tool(self, tid):
        self.tool_buttons[tid].set_active(True)

    def _tool_toggled(self, btn, tid):
        if not btn.get_active():
            return
        self.ed.set_tool(tid)
        self.area.set_cursor_from_name("default" if tid == "select" else "crosshair")
        self._sync_style_controls()
        self._refresh()

    def _sync_style_controls(self):
        st = self.ed.style()
        self._loading_style = True
        self.color_btn.set_rgba(rgba(st["color"]))
        self.fill_btn.set_active(st["fill"])
        self.width_spin.set_value(st["width"])
        self.size_spin.set_value(st["size"])
        self.corners_spin.set_value(st["corners"])
        self.color_btn.set_visible(st["show_color"])
        self.fill_btn.set_visible(st["show_fill"])
        for w in (self.width_spin, self.width_label):
            w.set_visible(st["show_width"])
        for w in (self.size_spin, self.size_label):
            w.set_visible(st["show_size"])
        for w in (self.corners_spin, self.corners_label):
            w.set_visible(st["show_corners"])
        self._loading_style = False

    def _apply_style(self, **change):
        if self._loading_style:
            return
        if self.ed.set_style(**change):
            self._refresh()

    def _color_changed(self, *_):
        self._apply_style(color=from_rgba(self.color_btn.get_rgba()))

    def _fill_changed(self, btn):
        self._apply_style(fill=btn.get_active())

    def _spin_changed(self, spin, key):
        self._apply_style(**{key: spin.get_value()})

    # ================================================================== undo
    def undo(self):
        if self.ed.undo():
            self._sync_style_controls()
            self._refresh()

    def redo(self):
        if self.ed.redo():
            self._sync_style_controls()
            self._refresh()

    def delete_selected(self):
        if self.ed.delete_selected():
            self._sync_style_controls()
            self._refresh()

    # ================================================================== zoom
    def zoom_fit(self):
        self.fit = True
        self._zoom_anchor = None
        self.area.set_content_width(1)
        self.area.set_content_height(1)
        self._fit_zoom(self.area.get_width(), self.area.get_height())

    def _fit_zoom(self, w, h):
        z = ie.fit_zoom(self.ed.size, w, h)
        if z:
            self.zoom = z
        self._refresh()

    def _resized(self, area, w, h):
        if self.fit:
            self._fit_zoom(w, h)

    def _content_size(self):
        """The canvas size at the current zoom (1x1 in fit mode, where it fills the view)."""
        if self.fit:
            return 1, 1
        iw, ih = self.ed.size
        return int(iw * self.zoom + 2 * PAD), int(ih * self.zoom + 2 * PAD)

    def _layout(self):
        """Where the image sits on the canvas at the current zoom, and where the view is
        scrolled to, including a zoom that isn't laid out yet. So several wheel notches in a
        row each start from where the one before is going, not from the last drawn frame."""
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        cw, ch = self._content_size()
        ox, oy = ie.offsets(self.ed.size, self.zoom, max(cw, hadj.get_page_size()),
                            max(ch, vadj.get_page_size()))
        if self._zoom_anchor is not None:
            ix, iy, vx, vy = self._zoom_anchor
            sx, sy = ox + ix * self.zoom - vx, oy + iy * self.zoom - vy
        else:
            sx, sy = hadj.get_value(), vadj.get_value()
        return sx, sy, ox, oy

    def set_zoom(self, zoom, anchor=None):
        """Zoom to zoom, keeping the image point under anchor (a point in the visible part,
        the middle by default) where it is."""
        if self.ed.surface is None:
            return
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        if anchor is None:
            anchor = (hadj.get_page_size() / 2, vadj.get_page_size() / 2)
        vx, vy = anchor
        sx, sy, ox, oy = self._layout()
        ix, iy = (sx + vx - ox) / self.zoom, (sy + vy - oy) / self.zoom
        self.fit = False
        self.zoom = ie.clamp_zoom(zoom)
        cw, ch = self._content_size()
        self.area.set_content_width(cw)
        self.area.set_content_height(ch)
        self._zoom_anchor = (ix, iy, vx, vy)
        self._adjustment_changed()
        self._refresh()

    def _adjustment_changed(self, *_):
        """Scroll so the zoom anchor stays under the pointer. Runs again as the new size is
        laid out, and lets go once the canvas has its new size."""
        if self._zoom_anchor is None:
            return
        ix, iy, vx, vy = self._zoom_anchor
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        cw, ch = self._content_size()
        sizes = (max(cw, hadj.get_page_size()), max(ch, vadj.get_page_size()))
        ox, oy = ie.offsets(self.ed.size, self.zoom, *sizes)
        done = True
        for adj, value, size in ((hadj, ox + ix * self.zoom - vx, sizes[0]),
                                 (vadj, oy + iy * self.zoom - vy, sizes[1])):
            adj.set_value(min(max(value, 0), max(adj.get_upper() - adj.get_page_size(), 0)))
            if abs(adj.get_upper() - size) > 0.5:
                done = False
        if done:
            self._zoom_anchor = None

    def step_zoom(self, direction, anchor=None):
        self.set_zoom(ie.step_zoom(self.zoom, direction), anchor)

    def _pointer_moved(self, ctrl, x, y):
        self._pointer_view = (x, y)

    def _pointer_anchor(self):
        if self._pointer_view is not None:
            return self._pointer_view
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        return hadj.get_page_size() / 2, vadj.get_page_size() / 2

    def _scrolled(self, ctrl, dx, dy):
        """The wheel scrolls up and down, Shift+wheel left and right, and Ctrl+wheel zooms
        toward the pointer. A touchpad scrolls both ways, and zooms with Ctrl held or a
        pinch."""
        if self.ed.surface is None or not self._over_image():
            return False
        state = ctrl.get_current_event_state()
        ctrl_held = bool(state & Gdk.ModifierType.CONTROL_MASK)
        shift = bool(state & Gdk.ModifierType.SHIFT_MASK)
        kind = scroll_kind(ctrl)
        if not ctrl_held:
            if kind == "touchpad":
                return False                # the scroller pans, with its own momentum
            if shift:
                # Some systems already turn Shift+wheel into a sideways scroll, so take
                # whichever way it came.
                self._scroll_view(dy or dx, 0, kind)
            else:
                self._scroll_view(dx, dy, kind)
            return True
        if not dy:
            return True                     # a sideways tilt with Ctrl held does nothing
        anchor = self._pointer_anchor()
        if kind == "wheel":
            steps = self._wheel_steps(dy)
            for _ in range(abs(steps)):
                self.step_zoom(-1 if steps > 0 else 1, anchor)
        else:
            # Touchpad with Ctrl, or a fine-grained wheel that reports distances: smooth.
            self.set_zoom(self.zoom * 2 ** (-dy / (150 if kind == "touchpad" else 60)), anchor)
        return True

    def _over_image(self):
        """False over the scrollbars, where the wheel should still just scroll."""
        if self._pointer_view is None:
            return True
        hit = self.scroller.pick(*self._pointer_view, Gtk.PickFlags.DEFAULT)
        return hit is None or hit is self.area or hit is self.scroller or \
            hit.is_ancestor(self.area)

    def _wheel_steps(self, dy):
        """Whole notches from wheel deltas. A high resolution wheel sends parts of a notch,
        so they add up until a whole one is there. A pause or a change of direction starts
        again."""
        total, last_dir, last_time = self._wheel
        now = GLib.get_monotonic_time()
        direction = 1 if dy > 0 else -1
        if direction != last_dir or now - last_time > 400000:
            total = 0.0
        total += dy
        steps = int(total + (0.02 if total > 0 else -0.02))
        total -= steps
        self._wheel = [total, direction, now]
        return steps

    def _scroll_view(self, dx, dy, kind):
        hadj, vadj = self.scroller.get_hadjustment(), self.scroller.get_vadjustment()
        steps = []
        for adj, delta in ((hadj, dx), (vadj, dy)):
            steps.append(delta * adj.get_page_size() ** (2 / 3) if kind == "wheel" else delta)
        if self._zoom_anchor is not None:
            # A zoom that isn't laid out yet: the scrollbars still have the old size, so
            # scrolling them now would lose where the zoom is going. Scroll from there
            # instead, and it gets there once the new size is in.
            sx, sy, _ox, _oy = self._layout()
            cw, ch = self._content_size()
            ix, iy, vx, vy = self._zoom_anchor
            moved = []
            for adj, start, size, step in ((hadj, sx, cw, steps[0]), (vadj, sy, ch, steps[1])):
                page = adj.get_page_size()
                top = max(max(size, page) - page, 0)
                end = min(max(min(max(start, 0), top) + step, 0), top)
                moved.append(end - start)
            self._zoom_anchor = (ix, iy, vx - moved[0], vy - moved[1])
            self._adjustment_changed()
            return
        for adj, step in ((hadj, steps[0]), (vadj, steps[1])):
            if step:
                adj.set_value(min(max(adj.get_value() + step, 0),
                                  max(adj.get_upper() - adj.get_page_size(), 0)))

    def _pinch_begin(self, gesture, sequence):
        ok, x, y = gesture.get_bounding_box_center()
        sx, sy, _ox, _oy = self._layout()
        self._pinch = (self.zoom, (x - sx, y - sy) if ok else None)

    def _pinch_changed(self, gesture, scale):
        if self._pinch is not None and self.ed.surface is not None:
            zoom0, anchor = self._pinch
            self.set_zoom(zoom0 * scale, anchor)

    def _pan_begin(self, gesture, x, y):
        # From where the view is going, in case a zoom isn't laid out yet.
        sx, sy, _ox, _oy = self._layout()
        self._zoom_anchor = None
        self._pan_start = (sx, sy)

    def _pan_update(self, gesture, dx, dy):
        hx, vy = self._pan_start
        self.scroller.get_hadjustment().set_value(hx - dx)
        self.scroller.get_vadjustment().set_value(vy - dy)

    # ================================================================== mouse
    def to_image(self, x, y):
        return (x - self.ox) / self.zoom, (y - self.oy) / self.zoom

    def to_view(self, x, y):
        return self.ox + x * self.zoom, self.oy + y * self.zoom

    def _pressed(self, gesture, n, x, y):
        self.area.grab_focus()
        # A double-click on text edits it. The entry opens when the button comes up, like a
        # click with the Text tool, since the drag that starts on this same press takes the
        # focus back to the image.
        self._double_text = None
        if n == 2 and self.ed.surface is not None:
            self._double_text = self.ed.text_at_double_click(*self.to_image(x, y), self.zoom)

    def _drag_begin(self, gesture, x, y):
        self.area.grab_focus()
        if self.ed.surface is None:
            return
        self._drag_origin = (x, y)
        self.ed.drag_begin(*self.to_image(x, y), self.zoom)
        self._sync_style_controls()
        self._refresh()

    def _drag_update(self, gesture, dx, dy):
        if not self.ed.drag:
            return
        x0, y0 = self._drag_origin
        shift = bool(gesture.get_current_event_state() & Gdk.ModifierType.SHIFT_MASK)
        if self.ed.drag_update(*self.to_image(x0 + dx, y0 + dy), shift, self.zoom):
            self.area.queue_draw()

    def _drag_end(self, gesture, dx, dy):
        request = self.ed.drag_end(self.zoom)
        double, self._double_text = self._double_text, None
        request = request or double
        if request:
            self._show_text_entry(request)
        self._refresh()

    def _motion(self, ctrl, x, y):
        if self.ed.surface is None or self.ed.drag:
            return
        if self.ed.tool == "select":
            ix, iy = self.to_image(x, y)
            if self.ed.handle_at(ix, iy, (ie.HANDLE + 3) / self.zoom) is not None:
                self.area.set_cursor_from_name("crosshair")
                return
            over = self.ed.shape_at(ix, iy, 5 / self.zoom)
            self.area.set_cursor_from_name("move" if over else "default")
            hover = self.ed.hover_text(ix, iy, 5 / self.zoom)
            if hover:
                self.status.set_text(hover)

    def _key_pressed(self, ctrl, keyval, keycode, state):
        if keyval in (Gdk.KEY_Delete, Gdk.KEY_BackSpace, Gdk.KEY_KP_Delete):
            self.delete_selected()
            return True
        if keyval == Gdk.KEY_Escape:
            self.ed.escape()
            self._sync_style_controls()
            self._refresh()
            return True
        moves = {Gdk.KEY_Left: (-1, 0), Gdk.KEY_Right: (1, 0), Gdk.KEY_Up: (0, -1),
                 Gdk.KEY_Down: (0, 1)}
        if keyval in moves and self.ed.selected is not None:
            step = 10 if state & Gdk.ModifierType.SHIFT_MASK else 1
            self.ed.nudge(moves[keyval][0] * step, moves[keyval][1] * step)
            self._refresh()
            return True
        return False

    # ================================================================== text
    def _show_text_entry(self, request):
        self.text_request = request
        kind, value = request
        ix, iy = (value["x"], value["y"]) if kind == "edit" else value
        self.text_entry.set_text(value["text"] if kind == "edit" else "")
        vx, vy = self.to_view(ix, iy)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(vx), int(vy), 1, 1
        self.text_pop.set_pointing_to(rect)
        self.text_pop.popup()
        self.text_entry.grab_focus()

    def _commit_text(self):
        request, self.text_request = self.text_request, None
        self.text_pop.popdown()
        if self.ed.commit_text(request, self.text_entry.get_text()):
            self._refresh()

    # ================================================================== drawing
    def _draw(self, area, cr, w, h):
        fg = fg_color(area)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.05)
        cr.paint()
        if self.ed.surface is None:
            self._draw_empty(cr, w, h, fg)
            return
        self.ox, self.oy = ie.offsets(self.ed.size, self.zoom, w, h)
        ie.paint(cr, self.ed, self.ox, self.oy, self.zoom, peek=self.peek_btn.get_active())

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
    def _update_folder_button(self):
        folder = self.ed.folder
        name = os.path.basename(folder.rstrip(os.sep)) or folder
        if os.path.abspath(folder) == os.path.expanduser("~"):
            name = "Home"
        self.folder_btn.set_label(name)
        self.folder_btn.set_tooltip_text(f"{ir.short_path(folder)}\nPick where it saves. "
                                         "Once saved, picking a folder moves the file (Ctrl+M).")

    def _fill_folder_menu(self):
        box = vbox(2)
        margins(box, 8)
        box.append(label("Move to" if self.ed.saved_path else "Save in", "heading"))
        current = os.path.abspath(self.ed.folder)
        for f in self.ed.folder_choices():
            b = Gtk.ToggleButton(label=ir.short_path(f))
            b.set_active(f == current)
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
        dialog = Gtk.FileDialog(title="Move to folder" if self.ed.saved_path
                                else "Save in folder")
        if os.path.isdir(self.ed.folder):
            dialog.set_initial_folder(Gio.File.new_for_path(self.ed.folder))

        def done(dlg, result):
            try:
                path = dlg.select_folder_finish(result).get_path()
            except GLib.Error:
                return
            if path:
                self.set_folder(path)
        dialog.select_folder(self.get_root(), None, done)

    def show_folder(self):
        folder = os.path.dirname(self.ed.saved_path) if self.ed.saved_path else self.ed.folder
        try:
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(folder).get_uri(), None)
        except GLib.Error as exc:
            self.set_status(f"Couldn't open the folder: {exc.message}")

    def focus_name(self):
        if self.ed.surface is None:
            return
        self.name_entry.grab_focus()
        stem = os.path.splitext(self.name_entry.get_text())[0]
        self.name_entry.select_region(0, len(stem))

    def _show_outcome(self, outcome, quiet=False):
        """Act on what a rename, move or save said back, asking first when it would replace
        a file."""
        if outcome.kind == "ask":
            dest = outcome.dest
            verb = outcome.message

            def go():
                if verb == "Save":
                    self._show_outcome(self.ed.write(dest))
                else:
                    self._show_outcome(self.ed.relocate(dest, verb))
            self._ask(f"Replace {os.path.basename(dest)}?",
                      f"There's already a file with that name in "
                      f"{ir.short_path(os.path.dirname(dest))}.", "Replace", go)
        elif outcome.kind == "error":
            if quiet:
                self.set_status(outcome.message)
            else:
                show_message(self.get_root(), "Something went wrong", outcome.message)
        elif outcome.kind == "done" and outcome.message and not quiet:
            self.set_status(outcome.message)
        self.name_entry.set_text(self.ed.name)
        self._update_folder_button()

    def apply_name(self, quiet=False):
        if self.ed.surface is None:
            return
        self._show_outcome(self.ed.rename(self.name_entry.get_text()), quiet=quiet)

    def set_folder(self, folder):
        self._show_outcome(self.ed.move_to(folder))

    def save(self):
        if self.ed.surface is None:
            return
        if self.ed.finding:
            self.set_status(ie.BUSY, busy=True)
            return
        self.apply_name(quiet=True)
        plan = self.ed.plan_save()
        if plan.kind == "ask":
            self._show_outcome(plan)
        else:
            self._show_outcome(self.ed.write(plan.dest))

    def copy(self):
        if self.ed.surface is None:
            return
        if self.ed.finding:
            self.set_status(ie.BUSY, busy=True)
            return
        try:
            png = self.ed.copy_png()
            set_clipboard_image(self, png)
        except ir.ImageError as exc:
            self.set_status(str(exc))
            return
        except GLib.Error as exc:
            self.set_status(f"Couldn't copy the image: {exc.message}")
            return
        self.ed.copied()
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
