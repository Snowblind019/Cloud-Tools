"""PII Redact in the window: the page in AWS Kit, the small paste window, and settings."""
from __future__ import annotations

from gi.repository import Gio, GLib, Gtk, Pango

from . import redact
from .widgets import Page, button, hbox, label, margins, set_clipboard, vbox

HIGHLIGHT = "rgba(230,160,0,0.35)"


def heading(text, top=16):
    w = label(text, "heading")
    w.set_margin_top(top)
    return w


def caption(text):
    return label(text, "dim-label", wrap=True)


# =================================================================== settings

class RedactSettingsWindow(Gtk.Window):
    """Every category checkbox, the output options and the word lists. Saves as you go."""

    def __init__(self, application=None, parent=None, on_saved=None):
        super().__init__(title="PII Redact settings")
        if application is not None:
            self.set_application(application)
        if parent is not None:
            self.set_transient_for(parent)
        self.set_default_size(660, 800)
        self.on_saved = on_saved
        self.cfg = redact.load_config()
        self.checks = {}
        self.sections = {}
        self._save_id = 0
        self._loading = True

        outer = vbox(0)
        self.set_child(outer)
        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.append(scroller)

        body = vbox(6)
        margins(body, 20)
        scroller.set_child(body)
        body.append(caption("Checked items get replaced. Changes save right away and apply to "
                            "the PII Redact page, the paste window, clip mode, the terminal, "
                            "Image Redact, and every Copy redacted button in AWS Kit."))

        for cat in redact.CATEGORIES:
            if cat.section not in self.sections:
                self.sections[cat.section] = []
                body.append(self._section_header(cat.section))
            cb = self._check(cat.title, cat.desc, self.cfg["categories"][cat.id])
            self.checks[cat.id] = cb
            self.sections[cat.section].append(cat.id)
            body.append(cb)

        body.append(heading("Output"))
        self.numbered = self._check(
            "Number the redactions",
            "Writes [Redacted-AccountID-1] instead of [Redacted], so the same value always "
            "gets the same number", self.cfg["numbered"])
        self.copy_on_paste = self._check(
            "Copy automatically when I paste",
            "In the paste window, the redacted text goes straight to the clipboard",
            self.cfg["copy_on_paste"])
        self.copy_in_terminal = self._check(
            "Copy terminal results to the clipboard",
            "Same as adding -c every time", self.cfg["copy_in_terminal"])
        for w in (self.numbered, self.copy_on_paste, self.copy_in_terminal):
            body.append(w)

        ph_row = hbox(8)
        ph_row.set_margin_top(6)
        ph_row.append(Gtk.Label(label="Placeholder word"))
        self.placeholder = Gtk.Entry()
        self.placeholder.set_text(self.cfg["placeholder"])
        self.placeholder.set_width_chars(18)
        self.placeholder.connect("changed", self._changed)
        ph_row.append(self.placeholder)
        self.ph_example = caption("")
        ph_row.append(self.ph_example)
        body.append(ph_row)

        body.append(heading("Always redact"))
        body.append(caption("One per line. Your name, GitHub handle, employer, domains you own, "
                            "project names. Matches whole words in any case."))
        frame, self.always_buf = self._text_area(self.cfg["always_redact"])
        body.append(frame)

        body.append(heading("Never redact"))
        body.append(caption("One per line. Anything matching these stays visible, like AWS's "
                            "documentation account 123456789012 or a bucket name you don't mind "
                            "showing."))
        frame, self.never_buf = self._text_area(self.cfg["never_redact"])
        body.append(frame)

        outer.append(Gtk.Separator())
        bar = hbox(8)
        margins(bar, 10)
        reset = button("Reset to defaults", self._reset,
                       tooltip="Resets the checkboxes and output options. Your word lists stay "
                               "as they are.")
        self.status = caption("Changes save automatically")
        self.status.set_hexpand(True)
        for w in (reset, self.status, button("Close", self.close)):
            bar.append(w)
        outer.append(bar)

        self.connect("close-request", self._flush)
        self._update_example()
        self._loading = False

    def _section_header(self, name):
        row = hbox(4)
        row.set_margin_top(12)
        title = heading(name, top=0)
        title.set_hexpand(True)
        row.append(title)
        for text, value in (("All", True), ("None", False)):
            btn = Gtk.Button(label=text)
            btn.add_css_class("flat")
            btn.set_valign(Gtk.Align.CENTER)
            btn.connect("clicked", self._set_section, name, value)
            row.append(btn)
        return row

    def _check(self, title, desc, active):
        cb = Gtk.CheckButton()
        box = vbox(1)
        box.append(Gtk.Label(label=title, xalign=0))
        if desc:
            box.append(caption(desc))
        cb.set_child(box)
        cb.set_active(active)
        cb.connect("toggled", self._changed)
        return cb

    def _text_area(self, lines):
        view = Gtk.TextView(monospace=True)
        for side in ("left", "right", "top", "bottom"):
            getattr(view, f"set_{side}_margin")(6)
        buf = view.get_buffer()
        buf.set_text("\n".join(lines))
        buf.connect("changed", self._changed)
        sc = Gtk.ScrolledWindow()
        sc.set_min_content_height(100)
        sc.set_child(view)
        frame = Gtk.Frame()
        frame.set_child(sc)
        return frame, buf

    def _set_section(self, _btn, name, value):
        for cid in self.sections[name]:
            self.checks[cid].set_active(value)

    def set_numbered(self, value):
        self._loading = True
        self.numbered.set_active(value)
        self._loading = False

    def _update_example(self):
        word = redact.clean_placeholder(self.placeholder.get_text())
        self.ph_example.set_text(f"Shows up as [{word}]")

    def _changed(self, *_):
        if self._loading:
            return
        self._update_example()
        if self._save_id:
            GLib.source_remove(self._save_id)
        self._save_id = GLib.timeout_add(250, self._save)

    def _save(self):
        self._save_id = 0

        def lines(buf):
            text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            return [line.strip() for line in text.splitlines() if line.strip()]

        cfg = redact.load_config()
        cfg["categories"] = {cid: cb.get_active() for cid, cb in self.checks.items()}
        cfg["numbered"] = self.numbered.get_active()
        cfg["copy_on_paste"] = self.copy_on_paste.get_active()
        cfg["copy_in_terminal"] = self.copy_in_terminal.get_active()
        cfg["placeholder"] = redact.clean_placeholder(self.placeholder.get_text())
        cfg["always_redact"] = lines(self.always_buf)
        cfg["never_redact"] = lines(self.never_buf)
        if redact.save_config(cfg):
            self.status.set_text("Saved")
            if self.on_saved:
                self.on_saved()
        else:
            self.status.set_text(f"Couldn't save to {redact.CONFIG_FILE}")
        return GLib.SOURCE_REMOVE

    def _flush(self, *_):
        if self._save_id:
            GLib.source_remove(self._save_id)
            self._save()
        return False

    def _reset(self):
        self._loading = True
        for cat in redact.CATEGORIES:
            self.checks[cat.id].set_active(cat.default)
        for w in (self.numbered, self.copy_on_paste, self.copy_in_terminal):
            w.set_active(False)
        self.placeholder.set_text("Redacted")
        self._loading = False
        self._changed()


# =================================================================== paste and redact

class RedactView(Gtk.Box):
    """Paste on the left, redacted on the right with every replacement highlighted."""

    def __init__(self, initial_text=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self._pending = 0
        self._copy_after_run = False
        self._settings_win = None

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_vexpand(True)
        paned.set_wide_handle(True)
        paned.set_shrink_start_child(False)
        paned.set_shrink_end_child(False)
        paned.set_position(560)
        self.append(paned)

        in_pane, self.in_view = self._make_pane("Paste here")
        out_pane, self.out_view = self._make_pane("Redacted")
        self.out_view.set_editable(False)
        paned.set_start_child(in_pane)
        paned.set_end_child(out_pane)
        self.in_buf = self.in_view.get_buffer()
        self.out_buf = self.out_view.get_buffer()
        self.tag = self.out_buf.create_tag("redacted", background=HIGHLIGHT, weight=700)

        row = hbox(8)
        self.numbered = Gtk.CheckButton(label="Number them")
        self.numbered.set_tooltip_text(
            "Use [Redacted-AccountID-1] style so the same value keeps the same number")
        self.numbered.set_active(redact.load_config()["numbered"])
        self.status = label("Paste something on the left")
        self.status.set_hexpand(True)
        self.status.set_ellipsize(Pango.EllipsizeMode.END)
        self.copy_btn = button("Copy", self.copy, tooltip="Copy the redacted text (Ctrl+Shift+C)",
                               css="suggested-action")
        for w in (self.numbered, self.status,
                  button("Settings", self.open_settings,
                         tooltip="Choose what gets redacted (Ctrl+,)"),
                  button("Paste", self.paste),
                  button("Clear", lambda: self.in_buf.set_text("")),
                  self.copy_btn):
            row.append(w)
        self.append(row)

        self.in_buf.connect("changed", self.schedule)
        self.in_buf.connect("paste-done", self._mark_pasted)
        self._num_handler = self.numbered.connect("toggled", self._toggle_numbered)

        keys = Gtk.ShortcutController()
        for trigger, callback in (("<Control><Shift>c", self.copy),
                                  ("<Control>comma", self.open_settings)):
            keys.add_shortcut(Gtk.Shortcut(
                trigger=Gtk.ShortcutTrigger.parse_string(trigger),
                action=Gtk.CallbackAction.new(lambda *_a, cb=callback: (cb(), True)[1])))
        self.add_controller(keys)

        # Re-run whenever the settings change, even from another window or the terminal.
        try:
            redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self._monitor = Gio.File.new_for_path(str(redact.CONFIG_FILE)).monitor_file(
                Gio.FileMonitorFlags.NONE, None)
            self._monitor.connect("changed", self.schedule)
        except (OSError, GLib.Error):
            self._monitor = None

        if initial_text:
            self.in_buf.set_text(initial_text)

    def _make_pane(self, title):
        box = vbox(4)
        box.append(label(title, "heading"))
        view = Gtk.TextView(monospace=True)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        for side in ("left", "right", "top", "bottom"):
            getattr(view, f"set_{side}_margin")(8)
        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_hexpand(True)
        scroller.set_child(view)
        frame = Gtk.Frame()
        frame.set_child(scroller)
        box.append(frame)
        return box, view

    def focus_input(self):
        self.in_view.grab_focus()

    def set_text(self, text):
        self.in_buf.set_text(text)

    def schedule(self, *_):
        # A run is already queued and will read the latest text and settings when it fires.
        if not self._pending:
            self._pending = GLib.timeout_add(120, self._run)

    def _run(self):
        self._pending = 0
        cfg = redact.load_config()
        if self.numbered.get_active() != cfg["numbered"]:
            self.numbered.handler_block(self._num_handler)
            self.numbered.set_active(cfg["numbered"])
            self.numbered.handler_unblock(self._num_handler)
        text = self.in_buf.get_text(self.in_buf.get_start_iter(), self.in_buf.get_end_iter(),
                                    False)
        out, counts, ranges = redact.redact(text, redact.options_from(cfg))
        self.out_buf.set_text(out)
        for s, e in ranges:
            self.out_buf.apply_tag(self.tag, self.out_buf.get_iter_at_offset(s),
                                   self.out_buf.get_iter_at_offset(e))
        msg = redact.summarize(counts) if text.strip() else "Paste something on the left"
        if self._copy_after_run and cfg["copy_on_paste"] and out.strip():
            set_clipboard(self, out)
            msg += ". Copied"
        self._copy_after_run = False
        self.status.set_text(msg)
        self.status.set_tooltip_text(msg)
        return GLib.SOURCE_REMOVE

    def _mark_pasted(self, *_):
        self._copy_after_run = True

    def _toggle_numbered(self, btn):
        cfg = redact.load_config()
        cfg["numbered"] = btn.get_active()
        redact.save_config(cfg)
        if self._settings_win is not None:
            self._settings_win.set_numbered(cfg["numbered"])
        self.schedule()

    def open_settings(self):
        if self._settings_win is None:
            root = self.get_root()
            self._settings_win = RedactSettingsWindow(
                application=root.get_application() if hasattr(root, "get_application") else None,
                parent=root, on_saved=self.schedule)
            self._settings_win.connect("close-request", self._settings_closed)
        self._settings_win.present()

    def _settings_closed(self, *_):
        self._settings_win = None
        return False

    def paste(self):
        self.get_clipboard().read_text_async(None, self._paste_done)

    def _paste_done(self, clipboard, result):
        try:
            text = clipboard.read_text_finish(result)
        except GLib.Error:
            text = None
        if text:
            self._copy_after_run = True
            self.in_buf.set_text(text)
        else:
            self.status.set_text("Clipboard has no text in it")

    def copy(self):
        if self._pending:  # make sure the output matches what's pasted right now
            GLib.source_remove(self._pending)
            self._run()
        text = self.out_buf.get_text(self.out_buf.get_start_iter(), self.out_buf.get_end_iter(),
                                     False)
        if not text:
            self.status.set_text("Nothing to copy yet")
            return
        set_clipboard(self, text)
        self.status.set_text(f"Copied {len(text):,} characters")


class RedactPage(Page):
    name = "redact"
    title = "PII Redact"

    def __init__(self, win):
        super().__init__(win, "Paste Terraform, AWS CLI, boto3 or any other output on the left. "
                         "Account IDs, keys, ARNs, emails, public IPs and other identifying info "
                         "come out on the right, ready to share. Nothing leaves your machine.")
        self.view = RedactView()
        margins(self.view, 10)
        self.view.set_margin_top(4)
        self.view.set_vexpand(True)
        self.append(self.view)


class RedactWindow(Gtk.ApplicationWindow):
    """The small paste window, for a keybind or the PII Redact launcher entry."""

    def __init__(self, app, initial_text=None):
        super().__init__(application=app, title="PII Redact")
        self.set_default_size(1150, 740)
        self.view = RedactView(initial_text)
        margins(self.view, 10)
        self.set_child(self.view)
        self.view.focus_input()
