"""Editing a Cloud Map in draw.io, for the Cloud Map page.

Edit writes the map, with its saved layout, to a working .drawio file next to the
snapshot (<name>-<type>.drawio), and opens it in the draw.io editor AWS Kit downloaded:

- Linux: inside the page, with WebKitGTK 6.0. Done saves and goes back to the map.
- Windows, and Linux without WebKitGTK (or WSL when it can't start): the page shows why,
  and an Open in draw.io button that opens the editor in an Edge app window, the default
  browser, or draw.io desktop.

Every save goes through the bridge in mapeditor.py, then layout memory reads the file
back (maplayoutmem.remember) and the map redraws. draw.io desktop saves the file itself,
so the file is watched, and a change made outside AWS Kit can be pulled in.
"""
from __future__ import annotations

import sys
from pathlib import Path

from gi.repository import Gio, GLib, Gtk

from . import cloudmap, mapeditor, maplayoutmem
from . import mapmodel as mm
from .common import is_wsl
from .widgets import button, hbox, label, margins, run_bg, show_message, string_dropdown, vbox

LOAD_TIMEOUT_S = 45         # the embedded editor has this long to load before falling back
DONE_TIMEOUT_S = 12         # Done gives up waiting for draw.io's save after this long

INSTALL_HINT = ("It needs WebKitGTK 6.0, which isn't installed. To edit inside AWS Kit, install "
                "it (Fedora: webkitgtk6.0, Debian and Ubuntu: gir1.2-webkit-6.0, Arch: "
                "webkitgtk-6.0) and restart AWS Kit.")


def why_outside(problem, kind="missing") -> str:
    """What the page says where the editor would be, when it can't be embedded. kind is
    missing (no WebKitGTK), failed (it didn't start) or asked (the Own window button)."""
    if sys.platform == "win32":
        return ("The built-in editor isn't available on Windows, so it opens in its own "
                "window. GTK for Windows doesn't include WebKitGTK, the web view the "
                "editor needs. It's the same offline draw.io either way, and saves come "
                "straight back here.")
    if kind == "asked":
        return ("The editor opens in its own window this time. Press Edit again for the "
                "built-in one. Saves come straight back here.")
    if is_wsl():
        return ("The built-in editor couldn't start here, so it opens in a Windows window "
                f"instead. ({problem}) WSL often has no graphics driver WebKitGTK can use. "
                "Saves come straight back here.")
    if kind == "failed":
        return (f"The built-in editor couldn't start, so it opens in its own window. ({problem}) "
                "Saves come straight back here.")
    return f"The built-in editor isn't available, so it opens in its own window. {INSTALL_HINT}"


class EditController:
    """Owns the editor for one MapPage: the bridge, the web view, the fallback panel and
    the file watcher."""

    def __init__(self, page):
        self.page = page
        self.bridge = None
        self.view = None              # WebKit.WebView, made the first time it's needed
        self.webkit = None            # the WebKit module, once loaded
        self.problem = None           # why WebKit can't be used, once known
        self.path = None              # the working .drawio file
        self.snap = None              # the snapshot it's a map of, and its file
        self.snap_path = None
        self.map_type = None
        self.mode = None              # "embedded", "outside" or None
        self.kind = "map"             # what's being edited: a map, or a design
        self.monitor = None
        self.monitor_path = None
        self.known_hash = None        # what AWS Kit last wrote or read in the working file
        self._check_id = 0
        self._load_timer = 0
        self._done_timer = 0
        self._closing = False         # AWS Kit is closing, already asked about changes
        self.editor_box = self._editor_widgets()
        self.outside_box = self._outside_widgets()
        self.pull_bar = self._pull_widgets()

    # ---- widgets
    def _editor_widgets(self):
        box = vbox(0)
        bar = hbox(8, "mapwarn")
        margins(bar, 0)
        bar.set_margin_start(8)
        bar.set_margin_end(8)
        bar.set_margin_top(4)
        bar.set_margin_bottom(4)
        self.edit_note = label("Editing in draw.io. Move things, recolor them, add notes, then "
                               "press Done. The layout is kept for every rescan.", wrap=True)
        self.edit_note.set_hexpand(True)
        bar.append(self.edit_note)
        self.away_btn = button("Own window", self.own_window,
            "Use the editor in its own window instead, if it doesn't show properly here")
        self.away_btn.add_css_class("flat")
        bar.append(self.away_btn)
        self.cancel_btn = button("Cancel", self.cancel, "Close the editor without saving")
        bar.append(self.cancel_btn)
        self.done_btn = button("Done", self.done, "Save and go back to the map",
                               css="suggested-action")
        bar.append(self.done_btn)
        for b in (self.away_btn, self.cancel_btn, self.done_btn):
            b.set_valign(Gtk.Align.CENTER)
        box.append(bar)
        self.view_holder = Gtk.Box()
        self.view_holder.set_hexpand(True)
        self.view_holder.set_vexpand(True)
        box.append(self.view_holder)
        return box

    def _outside_widgets(self):
        box = vbox(12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        margins(box, 30)
        box.append(label("Edit in draw.io", "headline", xalign=0.5))
        self.outside_msg = label("", "dim-label", xalign=0.5, wrap=True)
        self.outside_msg.set_max_width_chars(70)
        box.append(self.outside_msg)
        row = hbox(8)
        row.set_halign(Gtk.Align.CENTER)
        self.open_btn = button("Open in draw.io", self.open_outside,
                               "Opens the offline draw.io editor AWS Kit downloaded",
                               css="suggested-action")
        row.append(self.open_btn)
        self.targets = []
        self.target_dd = string_dropdown([""])
        self.target_dd.set_tooltip_text("What Open in draw.io uses")
        self.target_dd.connect("notify::selected", lambda *_: self._target_changed())
        row.append(self.target_dd)
        box.append(row)
        self.outside_status = label("", "dim-label", xalign=0.5, wrap=True)
        self.outside_status.set_max_width_chars(70)
        box.append(self.outside_status)
        self.file_label = label("", "dim-label", xalign=0.5, wrap=True, selectable=True)
        self.file_label.set_max_width_chars(70)
        box.append(self.file_label)
        back = button("Back to the map", self.back_to_map)
        back.set_halign(Gtk.Align.CENTER)
        box.append(back)
        return box

    def _pull_widgets(self):
        rev = Gtk.Revealer()
        bar = hbox(8, "mapwarn")
        margins(bar, 0)
        icon = Gtk.Image.new_from_icon_name("document-edit-symbolic")
        bar.append(icon)
        self.pull_label = label("", wrap=True)
        self.pull_label.set_hexpand(True)
        bar.append(self.pull_label)
        self.pull_button = button("Pull in the new layout", self.pull_in,
                                  "Read the file's layout and redraw the map with it")
        bar.append(self.pull_button)
        close = Gtk.Button.new_from_icon_name("window-close-symbolic")
        close.add_css_class("flat")
        close.set_tooltip_text("Ignore this change")
        close.connect("clicked", lambda *_: rev.set_reveal_child(False))
        bar.append(close)
        rev.set_child(bar)
        return rev

    # ---- starting
    def busy(self) -> bool:
        return self.mode == "embedded"

    def start(self):
        page = self.page
        if page.mode == "design":
            self.start_design()
            return
        if page.snap is None or page.layout is None:
            show_message(page.win, "Nothing to edit yet", "Load a map first.")
            return
        if not page.snap_path:
            show_message(page.win, "Save the snapshot first", "The layout is kept next to it.")
            return
        try:
            mapeditor.check_drawio()
        except mapeditor.BridgeError as exc:
            show_message(page.win, "draw.io isn't downloaded", str(exc))
            return
        if self.bridge is not None and self.bridge.running():
            if self.mode == "outside":
                page.center.set_visible_child_name("outside")
                return
            self.stop()
        snap, snap_path = page.snap, page.snap_path
        map_type, theme_name = page.map_type(), page.theme_name()
        args = page.layout_args()
        args.pop("map_type", None)
        page.status.busy("Getting the map ready for draw.io...", progress=False)
        page.edit_btn.set_sensitive(False)

        def work():
            return cloudmap.prepare_edit(snap, snap_path, map_type, theme_name, **args)

        def done(result):
            page.edit_btn.set_sensitive(True)
            path, lay, pulled = result
            self.path, self.map_type, self.kind = path, map_type, "map"
            self.snap, self.snap_path = snap, snap_path
            self.known_hash = maplayoutmem.file_hash(path.read_bytes())
            self.watch(path)
            self.pull_bar.set_reveal_child(False)
            if pulled:
                page.status.idle("Pulled in the layout saved outside AWS Kit first.")
                page.show_layout(lay, keep_view=True)
            else:
                page.status.idle("")
            problem = self.webkit_problem()
            if problem:
                self.show_outside(problem)
            else:
                self.open_embedded(path)

        def failed(exc):
            page.edit_btn.set_sensitive(True)
            page.status.idle("")
            show_message(page.win, "Couldn't get the map ready for draw.io", str(exc))
        run_bg(work, done, failed)

    def start_design(self):
        """The design file itself, with the AWS Kit Designer library in the sidebar."""
        page = self.page
        if page.design_path is None:
            return
        try:
            mapeditor.check_drawio()
        except mapeditor.BridgeError as exc:
            show_message(page.win, "draw.io isn't downloaded", str(exc))
            return
        if self.bridge is not None and self.bridge.running():
            if self.mode == "outside" and self.path == Path(page.design_path):
                page.center.set_visible_child_name("outside")
                return
            self.stop()
        self.path, self.map_type, self.kind = Path(page.design_path), "design", "design"
        try:
            self.known_hash = maplayoutmem.file_hash(self.path.read_bytes())
        except OSError as exc:
            show_message(page.win, "Couldn't read the design", str(exc))
            return
        self.watch(self.path)
        self.pull_bar.set_reveal_child(False)
        problem = self.webkit_problem()
        if problem:
            self.show_outside(problem)
        else:
            self.open_embedded(self.path)

    def webkit_problem(self) -> str:
        if self.problem is None:
            self.problem = mapeditor.webkit_problem()
        return self.problem

    def _new_bridge(self, idle_timeout):
        page = self.page
        if self.kind == "design":
            from . import mapdesign
            theme_name = page.theme_name()
            return mapeditor.Bridge(self.path, title=f"{self.path.stem} design", theme=theme_name,
                                    on_save=self._saved_thread, on_exit=self._exit_thread,
                                    on_event=self._event_thread, idle_timeout=idle_timeout,
                                    library=mapdesign.library_path(theme_name))
        return mapeditor.Bridge(self.path, title=f"{cloudmap.stem_of(page.snap_path)} "
                                f"{self.map_type} map", theme=page.theme_name(),
                                on_save=self._saved_thread, on_exit=self._exit_thread,
                                on_event=self._event_thread, idle_timeout=idle_timeout)

    # ---- the editor inside the page (Linux)
    def _make_view(self):
        if self.view is not None:
            return self.view
        import gi
        gi.require_version("WebKit", "6.0")
        from gi.repository import WebKit
        self.webkit = WebKit
        # Ephemeral: nothing draw.io keeps (drafts, settings) is written to disk.
        view = WebKit.WebView(network_session=WebKit.NetworkSession.new_ephemeral())
        settings = view.get_settings()
        if is_wsl():
            settings.set_hardware_acceleration_policy(WebKit.HardwareAccelerationPolicy.NEVER)
        view.set_hexpand(True)
        view.set_vexpand(True)
        view.connect("decide-policy", self._policy)
        view.connect("create", lambda *_: None)          # no pop-up windows
        view.connect("web-process-terminated", self._view_died)
        view.connect("load-failed", self._view_failed)
        self.view_holder.append(view)
        self.view = view
        return view

    def _allowed(self, uri) -> bool:
        if not uri or uri.startswith(("about:", "data:", "blob:")):
            return True
        return self.bridge is not None and uri.startswith(f"http://127.0.0.1:{self.bridge.port}/")

    def _policy(self, view, decision, kind):
        """Only the bridge: a link to anywhere else (help pages) is ignored."""
        PD = self.webkit.PolicyDecisionType
        if kind in (PD.NAVIGATION_ACTION, PD.NEW_WINDOW_ACTION):
            try:
                uri = decision.get_navigation_action().get_request().get_uri()
            except (AttributeError, TypeError):
                return False
            if not self._allowed(uri):
                decision.ignore()
                return True
        return False

    def open_embedded(self, path):
        page = self.page
        try:
            view = self._make_view()
        except (ImportError, ValueError, GLib.Error) as exc:
            self.problem = f"WebKitGTK couldn't start: {exc}"
            self.show_outside(self.problem, "failed")
            return
        self.bridge = self._new_bridge(idle_timeout=0)
        url = self.bridge.start()
        self.mode = "embedded"
        if self.kind == "design":
            self.edit_note.set_text("Editing the design. Drag shapes in from AWS Kit Designer on "
                                    "the left, set them up with Ctrl+M (Edit Data), then press "
                                    "Done to check it.")
        else:
            self.edit_note.set_text("Editing in draw.io. Move things, recolor them, add notes, "
                                    "then press Done. The layout is kept for every rescan.")
        page.set_editing(True)
        page.center.set_visible_child_name("editor")
        self.done_btn.set_sensitive(True)
        self.cancel_btn.set_sensitive(True)
        view.load_uri(url)
        view.grab_focus()
        self._load_timer = GLib.timeout_add_seconds(LOAD_TIMEOUT_S, self._load_timeout)

    def _load_timeout(self):
        self._load_timer = 0
        if self.mode == "embedded" and self.bridge is not None and not self.bridge.loaded:
            self._fall_back("draw.io didn't finish loading in the built-in view")
        return False

    def _view_died(self, view, reason):
        if self.mode == "embedded":
            self._fall_back(f"the web view stopped ({getattr(reason, 'value_nick', reason)})")

    def _view_failed(self, view, event, uri, error):
        if self.mode == "embedded" and uri and uri.startswith("http://127.0.0.1"):
            self._fall_back(f"the web view couldn't load draw.io ({error.message})")
        return False

    def _fall_back(self, why, kind="failed"):
        """The embedded editor didn't work (or the Own window button): use the editor in
        its own window, for the rest of this session unless it was asked for."""
        for attr in ("_load_timer", "_done_timer"):
            if getattr(self, attr):
                GLib.source_remove(getattr(self, attr))
                setattr(self, attr, 0)
        text = why[:1].upper() + why[1:] + "." if why else ""
        if kind == "failed":
            self.problem = text
        self.stop()
        if self.view is not None:
            self.view.load_uri("about:blank")
        self.show_outside(text, kind)

    def own_window(self):
        """The Own window button. Switching reloads the editor, so changes that weren't
        saved yet would be lost: ask first when there are any."""
        if self.mode != "embedded" or self.view is None:
            self._fall_back("", kind="asked")
            return

        def answered(view, result, *_):
            try:
                value = view.evaluate_javascript_finish(result)
                modified = bool(value.to_boolean()) if value is not None else False
            except GLib.Error:
                modified = False
            if not modified:
                self._fall_back("", kind="asked")
                return
            dlg = Gtk.AlertDialog(message="Switch to its own window?",
                                  detail="Changes you haven't saved in draw.io yet will be lost. "
                                         "Press Save in draw.io first to keep them.")
            dlg.set_buttons(["Keep editing", "Switch anyway"])
            dlg.set_cancel_button(0)
            dlg.set_default_button(0)

            def chosen(d, res):
                try:
                    if d.choose_finish(res) == 1:
                        self._fall_back("", kind="asked")
                except GLib.Error:
                    pass
            dlg.choose(self.page.win, None, chosen)
        self.view.evaluate_javascript("awskitModified()", -1, None, None, None, answered, None)

    def done(self):
        if self.mode != "embedded" or self.view is None:
            return
        self.done_btn.set_sensitive(False)
        self.cancel_btn.set_sensitive(False)
        self.page.status.busy("Saving your layout...", progress=False)

        def started(view, result, *_):
            try:
                value = view.evaluate_javascript_finish(result)
                answer = value.to_string() if value is not None else ""
            except GLib.Error:
                answer = ""
            if answer != "saving":
                self.close_embedded()           # draw.io never loaded: nothing to save
        self.view.evaluate_javascript("awskitSave(true)", -1, None, None, None, started, None)
        self._done_timer = GLib.timeout_add_seconds(DONE_TIMEOUT_S, self._done_timeout)

    def _done_timeout(self):
        self._done_timer = 0
        if self.mode == "embedded":
            self.page.status.idle("draw.io didn't answer, so the editor was closed.")
            self.close_embedded()
        return False

    def cancel(self):
        if self.mode != "embedded" or self.view is None:
            return

        def answered(view, result, *_):
            try:
                value = view.evaluate_javascript_finish(result)
                modified = bool(value.to_boolean()) if value is not None else False
            except GLib.Error:
                modified = False
            if not modified:
                self.close_embedded()
                return
            dlg = Gtk.AlertDialog(message="Throw away your changes?",
                                  detail="Nothing you changed in draw.io since the last save "
                                         "will be kept.")
            dlg.set_buttons(["Keep editing", "Throw away"])
            dlg.set_cancel_button(0)
            dlg.set_default_button(0)

            def chosen(d, res):
                try:
                    if d.choose_finish(res) == 1:
                        self.close_embedded()
                except GLib.Error:
                    pass
            dlg.choose(self.page.win, None, chosen)
        self.view.evaluate_javascript("awskitModified()", -1, None, None, None, answered, None)

    def close_embedded(self):
        for attr in ("_load_timer", "_done_timer"):
            if getattr(self, attr):
                GLib.source_remove(getattr(self, attr))
                setattr(self, attr, 0)
        self.stop()
        if self.view is not None:
            self.view.load_uri("about:blank")
        self.page.set_editing(False)
        self.page.center.set_visible_child_name("canvas" if self.page.layout else "empty")
        self.page.canvas.grab_focus()

    # ---- the editor in its own window (Windows, and the fallback)
    def show_outside(self, problem, kind=None):
        page = self.page
        self.mode = "outside"
        page.set_editing(False)
        if kind is None:
            kind = "missing" if "isn't installed" in problem or "isn't part of" in problem \
                else "failed"
        self.outside_msg.set_text(why_outside(problem, kind))
        self.targets = mapeditor.available_targets()
        titles = [mapeditor.TARGETS[t] for t in self.targets]
        self._filling = True
        try:
            self.target_dd.set_model(Gtk.StringList.new(titles))
            want = mapeditor.choose_target(page.cfg.get("editor", ""), self.targets)
            self.target_dd.set_selected(self.targets.index(want))
        finally:
            self._filling = False
        self.target_dd.set_visible(len(self.targets) > 1)
        self.file_label.set_text(f"Working file: {self.path}")
        self.outside_status.set_text("")
        page.center.set_visible_child_name("outside")

    def _target_changed(self):
        if getattr(self, "_filling", False) or not self.targets:
            return
        i = self.target_dd.get_selected()
        if 0 <= i < len(self.targets):
            self.page.cfg["editor"] = self.targets[i]
            self.page.remember()

    def target(self) -> str:
        i = self.target_dd.get_selected()
        return self.targets[i] if 0 <= i < len(self.targets) else "browser"

    def open_outside(self):
        if self.path is None:
            return
        target = self.target()
        if target == "desktop":
            try:
                mapeditor.open_in_desktop(self.path)
            except (mapeditor.BridgeError, OSError) as exc:
                show_message(self.page.win, "Couldn't open draw.io desktop", str(exc))
                return
            text = (f"Opened {self.path.name} in draw.io desktop. Save it there, and AWS Kit "
                    "offers to pull the new layout in.")
            if self.kind == "design":
                from . import mapdesign
                text = (f"Opened {self.path.name} in draw.io desktop. Add the designer's shapes "
                        f"with File, Open Library: {mapdesign.library_path(self.page.theme_name())}. "
                        "When you save, AWS Kit offers to check the design again.")
            self.outside_status.set_text(text)
            return
        if self.bridge is None or not self.bridge.running():
            self.bridge = self._new_bridge(idle_timeout=mapeditor.OUTSIDE_IDLE_S)
            self.bridge.start()
        try:
            used, _ = mapeditor.open_outside(target, self.bridge.url, self.path)
        except mapeditor.BridgeError as exc:
            show_message(self.page.win, "Couldn't open the editor", str(exc))
            return
        self.outside_status.set_text(
            f"Opened in the {mapeditor.TARGETS[used].lower()}. Each save there comes back "
            "here and redraws the map. Close that window when you're done.")

    def back_to_map(self):
        self.stop()
        self.mode = None
        self.page.center.set_visible_child_name("canvas" if self.page.layout else "empty")

    # ---- what the bridge reports (on its own threads)
    def _saved_thread(self, path):
        try:
            self.known_hash = maplayoutmem.file_hash(Path(path).read_bytes())
        except OSError:
            pass
        GLib.idle_add(self._saved, Path(path))

    def _exit_thread(self, info):
        GLib.idle_add(self._exited, dict(info or {}))

    def _event_thread(self, info):
        GLib.idle_add(self._event, dict(info or {}))

    def _saved(self, path):
        self.read_back(path, "Saved in draw.io")
        return False

    def _event(self, info):
        """A save from draw.io failed (a full disk, a read-only folder). The changes are
        still in the editor, so it stays open."""
        if info.get("event") != "save-failed":
            return False
        why = str(info.get("error") or "unknown error")[:300]
        if self.mode == "embedded":
            if getattr(self, "_done_timer", 0):
                GLib.source_remove(self._done_timer)
                self._done_timer = 0
            self.done_btn.set_sensitive(True)
            self.cancel_btn.set_sensitive(True)
            self.page.status.idle(f"Couldn't save: {why}. Your changes are still in the editor.")
        elif self.mode == "outside":
            self.outside_status.set_text(f"A save from draw.io failed: {why}. Your changes are "
                                         "still in that window, so try saving again there.")
        return False

    def _exited(self, info):
        if self.mode == "embedded":
            self.close_embedded()
        elif self.mode == "outside":
            self.bridge = None
            if info.get("saved"):
                self.back_to_map()           # saved and closed: show the updated map
                return False
            reason = "was closed" if info.get("reason") == "closed" else "finished"
            self.outside_status.set_text(f"The draw.io window {reason}. Open it again to make "
                                         "more changes.")
        return False

    # ---- layout memory
    def read_back(self, path, what):
        page = self.page
        if self.kind == "design":
            self.known_hash = maplayoutmem.file_hash(Path(path).read_bytes())
            page.load_design(path, note=f"{what}.", fit=False)
            return
        # The snapshot the editor was opened for: a scan that finished while draw.io was
        # open may have put another one on the page, and this layout isn't for that one.
        snap, snap_path = self.snap, self.snap_path
        if page.snap is not None and page.snap_path is not None and page.snap_path == snap_path:
            snap = page.snap                 # the same file read again: the newest copy
        if snap is None or not snap_path:
            return
        page.status.busy("Reading your layout back...", progress=False)

        def work():
            return maplayoutmem.remember(path, snap, maplayoutmem.sidecar_path(snap_path))

        def done(got):
            self.known_hash = maplayoutmem.file_hash(Path(path).read_bytes())
            parts = [f"{got['moved']} moved"] if got["moved"] else []
            for key, one, many in (("styles", "style change", "style changes"),
                                   ("captions", "caption", "captions"),
                                   ("extra", "shape of your own", "shapes of your own")):
                if got[key]:
                    parts.append(mm.plural(got[key], one, many))
            page.after_layout_saved(f"{what}. " + (", ".join(parts) + "." if parts else
                                                   "Layout kept."))

        def failed(exc):
            page.status.idle("")
            show_message(page.win, "Saved, but couldn't read the layout back", str(exc))
        run_bg(work, done, failed)

    def pull_in(self):
        self.pull_bar.set_reveal_child(False)
        if self.monitor_path is not None:
            self.read_back(self.monitor_path, "Pulled in the new layout")

    # ---- watching the working file
    def watch(self, path):
        path = Path(path)
        if self.monitor is not None and self.monitor_path == path:
            return
        self.unwatch()
        try:
            gfile = Gio.File.new_for_path(str(path))
            self.monitor = gfile.monitor_file(Gio.FileMonitorFlags.WATCH_MOVES, None)
        except GLib.Error:
            self.monitor = None
            return
        self.monitor_path = path
        self.monitor.connect("changed", self._file_changed)

    def unwatch(self):
        if self.monitor is not None:
            self.monitor.cancel()
        self.monitor = None
        self.monitor_path = None
        self.pull_bar.set_reveal_child(False)

    def _file_changed(self, monitor, gfile, other, event):
        E = Gio.FileMonitorEvent
        if event in (E.DELETED, E.MOVED_OUT, E.PRE_UNMOUNT, E.UNMOUNTED, E.ATTRIBUTE_CHANGED):
            return
        # Saves often arrive as several events. Look once they've settled.
        if self._check_id:
            GLib.source_remove(self._check_id)
        self._check_id = GLib.timeout_add(500, self._check_file)

    def _check_file(self):
        self._check_id = 0
        path = self.monitor_path
        if path is None:
            return False
        try:
            data = path.read_bytes()
        except OSError:
            return False
        if maplayoutmem.file_hash(data) == self.known_hash:
            return False                     # AWS Kit's own write, or a save already read
        if not mapeditor.looks_like_drawio(data[:4000].decode("utf-8", "replace")):
            return False
        self.pull_label.set_text(f"{path.name} was saved outside AWS Kit, by draw.io desktop "
                                 "or another editor.")
        self.pull_button.set_label("Check the design again" if self.kind == "design"
                                   else "Pull in the new layout")
        self.pull_bar.set_reveal_child(True)
        return False

    # ---- ending
    def close_request(self, win):
        """Closing AWS Kit while draw.io has changes that weren't saved: ask first, the
        same as Cancel does."""
        if self._closing or self.mode != "embedded" or self.view is None:
            return False

        def close():
            self._closing = True
            win.close()

        def answered(view, result, *_):
            try:
                value = view.evaluate_javascript_finish(result)
                modified = bool(value.to_boolean()) if value is not None else False
            except GLib.Error:
                modified = False
            if not modified:
                close()
                return
            dlg = Gtk.AlertDialog(message="Close without saving your changes?",
                                  detail="Nothing you changed in draw.io since the last save "
                                         "will be kept. Press Done first to keep it.")
            dlg.set_buttons(["Keep editing", "Close anyway"])
            dlg.set_cancel_button(0)
            dlg.set_default_button(0)

            def chosen(d, res):
                try:
                    if d.choose_finish(res) == 1:
                        close()
                except GLib.Error:
                    pass
            dlg.choose(win, None, chosen)
        self.view.evaluate_javascript("awskitModified()", -1, None, None, None, answered, None)
        return True

    def stop(self):
        if self.bridge is not None:
            self.bridge.closed = True        # no exit callback for a stop asked for here
            self.bridge.stop()
        self.bridge = None
        if self.mode == "embedded":
            self.mode = None

    def snapshot_changed(self):
        """A different snapshot, map type or design: the old working file isn't this one's."""
        if self.mode == "embedded":
            return
        page = self.page
        if self.path is not None:
            if page.mode == "design" and page.design_path is not None and \
                    Path(page.design_path) == self.path:
                return
            if page.mode == "map" and page.snap_path is not None and \
                    cloudmap.work_file(page.snap_path, page.map_type()) == self.path:
                return
        if self.mode == "outside":
            self.back_to_map()
        self.unwatch()
        self.path = None
