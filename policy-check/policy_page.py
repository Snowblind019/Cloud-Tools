"""Policy Check page for the AWS Kit window."""
from __future__ import annotations

import json
from pathlib import Path

from gi.repository import Gdk, GLib, Gtk

from . import iampolicy
from .common import SEVERITY_ORDER, AwsContext, error_text
from .widgets import (Page, button, clear_box, flash, hbox, label, open_file, run_bg,
                      set_clipboard, sev_badge, show_message, spacer, string_dropdown, vbox)


class PolicyPage(Page):
    name = "policy"
    title = "Policy Check"
    KIND_KEYS = [None] + list(iampolicy.KINDS)

    def __init__(self, win):
        super().__init__(win, "Paste an IAM policy, trust policy, resource policy or SCP. It's "
                         "checked as you type, offline. Tick Also ask AWS to add IAM Access "
                         "Analyzer's own findings, which is free.")
        self.findings = []
        self.kind = "identity"
        self.note = ""
        self.error = ""
        self._timer = 0
        self._gen = 0  # bumped for every check, so a slow older one can't overwrite a newer one

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_vexpand(True)

        left = vbox(0)
        bar = self.toolbar()
        self.kind_dd = string_dropdown(["Work out the type"] +
                                       [iampolicy.KIND_NAMES[k] for k in iampolicy.KINDS])
        self.kind_dd.connect("notify::selected", lambda *_: self.check_local())
        bar.append(self.kind_dd)
        bar.append(button("Open file", lambda: open_file(self.win, self.load_file, "Open policy")))
        bar.append(button("Clear", lambda: self.buffer.set_text("")))
        left.append(bar)
        aws_row = self.toolbar()
        self.arn = Gtk.Entry(placeholder_text="Policy ARN, role ARN, or role/NAME")
        self.arn.set_hexpand(True)
        self.arn.connect("activate", lambda *_: self.fetch())
        aws_row.append(self.arn)
        aws_row.append(button("Load from AWS", self.fetch))
        left.append(aws_row)

        self.editor = Gtk.TextView(monospace=True)
        self.editor.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        for side in ("left", "right", "top", "bottom"):
            getattr(self.editor, f"set_{side}_margin")(8)
        self.buffer = self.editor.get_buffer()
        self.buffer.connect("changed", self.changed)
        sc = Gtk.ScrolledWindow()
        sc.set_child(self.editor)
        sc.set_vexpand(True)
        left.append(sc)
        row = self.toolbar()
        self.aws = Gtk.CheckButton(label="Also ask AWS (Access Analyzer)")
        row.append(self.aws)
        row.append(spacer())
        self.check_btn = button("Check", self.check_full, css="suggested-action",
                                tooltip="Ctrl+Enter")
        row.append(self.check_btn)
        left.append(row)

        right = vbox(0)
        top = self.toolbar()
        self.result = label("Paste a policy on the left.", "headline", wrap=True)
        self.result.set_hexpand(True)
        top.append(self.result)
        self.copy_btn = button("Copy report", self.copy_report)
        top.append(self.copy_btn)
        right.append(top)
        self.list = Gtk.ListBox()
        self.list.set_selection_mode(Gtk.SelectionMode.NONE)
        sc2 = Gtk.ScrolledWindow()
        sc2.set_child(self.list)
        sc2.set_vexpand(True)
        right.append(sc2)

        paned.set_start_child(left)
        paned.set_end_child(right)
        paned.set_position(560)
        self.append(paned)
        self.append(self.status)

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self.key)
        self.editor.add_controller(keys)

    def key(self, ctrl, keyval, code, state):
        if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter) and state & Gdk.ModifierType.CONTROL_MASK:
            self.check_full()
            return True
        return False

    def text(self):
        return self.buffer.get_text(self.buffer.get_start_iter(), self.buffer.get_end_iter(), False)

    def changed(self, *_):
        if self._timer:
            GLib.source_remove(self._timer)
        self._timer = GLib.timeout_add(350, self._debounced)

    def _debounced(self):
        self._timer = 0
        self.check_local()
        return False

    def clear_result(self, message):
        self.findings = []
        self.note = ""
        self.error = message
        self.result.set_text(message)
        clear_box(self.list)

    def check_local(self, then=None):
        """Parse and check in the background, so a huge paste can't freeze the window.
        then(doc, kind, findings) runs after a good check."""
        self._gen += 1
        gen = self._gen
        text = self.text()
        if not text.strip():
            self.clear_result("Paste a policy on the left.")
            return
        choice = self.KIND_KEYS[self.kind_dd.get_selected()]

        def work():
            doc, note = iampolicy.load_policy(text)
            kind = choice or iampolicy.detect_kind(doc)
            return doc, note, kind, iampolicy.analyze(doc, kind)

        def done(result):
            if gen != self._gen:
                return
            doc, self.note, self.kind, findings = result
            self.error = ""
            self.show(findings)
            if then:
                then(doc, self.kind, findings)

        def bad(exc):
            if gen != self._gen:
                return
            if isinstance(exc, iampolicy.PolicyError):
                self.clear_result(str(exc))
            else:
                self.clear_result(f"Couldn't check that: {exc or type(exc).__name__}")
        run_bg(work, done, bad)

    def check_full(self):
        if self._timer:  # check now instead of after the typing pause
            GLib.source_remove(self._timer)
            self._timer = 0
        if not self.aws.get_active():
            self.check_local()
            return
        profile = self.win.profile

        def ask_aws(doc, kind, local):
            gen = self._gen
            self.status.busy("Asking IAM Access Analyzer...", progress=False)

            def done(extra):
                self.status.idle("Access Analyzer finished.")
                if gen == self._gen:  # skip it if the policy changed meanwhile
                    self.show(local + extra)
            run_bg(lambda: iampolicy.validate_with_aws(AwsContext(profile), doc, kind), done,
                   self.failed)
        self.check_local(ask_aws)

    def failed(self, exc):
        self.status.idle("")
        show_message(self.win, "Couldn't reach AWS", error_text(exc, self.win.profile))

    def show(self, findings):
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        self.findings = findings
        clear_box(self.list)
        kind_name = iampolicy.KIND_NAMES.get(self.kind, self.kind)
        if not findings:
            self.result.set_text(f"{kind_name}: no problems found.")
            return
        self.result.set_text(f"{kind_name}: {len(findings)} finding(s), worst is "
                             f"{findings[0].severity}.")
        for f in findings:
            box = vbox(4, "finding-row")
            head = hbox(8)
            head.append(sev_badge(f.severity))
            t = label(f.title, "heading", wrap=True)
            t.set_hexpand(True)
            head.append(t)
            if f.where:
                head.append(label(f.where, "dim-label"))
            box.append(head)
            if f.source != "awskit":
                box.append(label(f"From {f.source}", "dim-label"))
            if f.detail:
                box.append(label(f.detail, wrap=True, selectable=True))
            if f.fix:
                box.append(label("Fix: " + f.fix, "dim-label", wrap=True, selectable=True))
            if f.link:
                link = Gtk.LinkButton(uri=f.link, label="AWS docs")
                link.set_halign(Gtk.Align.START)
                box.append(link)
            self.list.append(box)

    def copy_report(self):
        if self.text().strip() and not self.error:
            set_clipboard(self, iampolicy.report_text(self.findings, self.kind, self.note))
            flash(self.copy_btn, "Copied")

    def load_file(self, path):
        try:
            if Path(path).stat().st_size > iampolicy.MAX_POLICY_TEXT:
                show_message(self.win, "That file is too big",
                             "It's over 1 MB. IAM policies are a few KB at most.")
                return
            # UTF-8 or UTF-16 with a byte order mark too, as Notepad and PowerShell save it
            text = iampolicy.decode_text(Path(path).read_bytes())
            self.buffer.set_text(text.replace("\r\n", "\n").replace("\r", "\n"))
        except (OSError, ValueError) as exc:
            show_message(self.win, "Couldn't open the file", str(exc))

    def fetch(self):
        ref = self.arn.get_text().strip()
        if not ref:
            self.arn.grab_focus()
            return
        profile = self.win.profile
        self.status.busy(f"Loading {ref}...", progress=False)

        def done(result):
            doc, kind, name = result
            self.kind_dd.set_selected(self.KIND_KEYS.index(kind))
            self.buffer.set_text(json.dumps(doc, indent=2))
            self.status.idle(f"Loaded {name}.")
        run_bg(lambda: iampolicy.fetch_policy(AwsContext(profile), ref), done, self.failed)

    def set_text(self, text):
        self.buffer.set_text(text)
