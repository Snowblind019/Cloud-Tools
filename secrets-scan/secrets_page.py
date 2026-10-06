"""Secrets Scan page for the AWS Kit window."""
from __future__ import annotations

import os
from pathlib import Path

from gi.repository import Gtk, Pango

from . import secretscan
from .secretscan import MODES, HookError, ScanError
from .widgets import (DetailPane, Page, ResultTable, ask, button, clear_box, export_rows, hbox,
                      label, on_main, open_file, run_bg, show_message, spacer, string_dropdown)

MODE_KEYS = ["staged", "all", "history", "files"]


class FindingsTable(ResultTable):
    """The Level column says BLOCK or WARN, in the kit's high and low colors."""

    def _bind_cell(self, factory, list_item, key, kind):
        super()._bind_cell(factory, list_item, key, kind)
        if key == "level":
            name = list_item.get_item().data.get("level_name", "")
            lab = list_item.get_child()
            lab.set_text(name.upper())
            lab.set_tooltip_text("Stops a commit" if name == "block"
                                 else "Worth a look, doesn't stop a commit")


def short_path(path: str) -> str:
    home = str(Path.home())
    if path == home or path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


class SecretsPage(Page):
    name = "secrets"
    title = "Secrets Scan"

    COLS = [
        ("level", "Level", {"width": 86, "kind": "severity", "sort_key": "level_rank"}),
        ("file", "File", {"width": 290, "expand": True}),
        ("line", "Line", {"width": 64}),
        ("what", "What", {"width": 220}),
        ("preview", "Preview", {"width": 300, "kind": "mono"}),
        ("commit", "Commit", {"width": 100, "kind": "mono"}),
    ]
    EXPORT_COLS = [("level_name", "Level"), ("file", "File"), ("line", "Line"),
                   ("what", "What"), ("preview", "Preview"), ("commit", "Commit"),
                   ("note", "Note"), ("fix", "How to fix")]

    def __init__(self, win):
        super().__init__(win, "Finds AWS keys, tokens, private keys and passwords before they "
                         "get into a git repo, with PII Redact's patterns. Check what's staged, "
                         "every file, or past commits, and add a commit hook that stops them. "
                         "Runs offline, and never shows a whole secret.")
        self.settings = secretscan.load_settings()
        folder = self.settings.get("folder") or ""
        self.folder = folder if folder and os.path.isdir(folder) else ""
        self.result = None
        self.hook = {}
        self._hook_gen = 0

        row1 = self.toolbar()
        row1.append(button("Folder", self.pick_folder, tooltip="Pick the repo or folder to scan"))
        self.folder_label = label("", "mono")
        self.folder_label.set_ellipsize(Pango.EllipsizeMode.START)
        self.folder_label.set_hexpand(True)
        self.folder_label.set_margin_start(4)
        row1.append(self.folder_label)
        row1.append(label("What to scan", "dim-label"))
        mode = self.settings.get("mode", "staged")
        self.mode = string_dropdown([MODES[k] for k in MODE_KEYS],
                                    MODE_KEYS.index(mode) if mode in MODE_KEYS else 0)
        self.mode.set_tooltip_text("Staged changes: what's about to be committed. All files: "
                                   "every tracked file plus new ones git doesn't ignore. Git "
                                   "history: lines added in recent commits. Folder, not git: "
                                   "plain files.")
        self.mode.connect("notify::selected", lambda *_: self.mode_changed())
        row1.append(self.mode)
        self.depth_box = hbox(4)
        self.depth_box.append(label("Commits", "dim-label"))
        self.depth = Gtk.SpinButton.new_with_range(1, 100000, 50)
        self.depth.set_value(self.settings.get("history_commits", 200))
        self.depth.set_tooltip_text("How many recent commits to read")
        self.depth_box.append(self.depth)
        row1.append(self.depth_box)
        self.scan_btn = button("Scan", self.run, css="suggested-action")
        row1.append(self.scan_btn)
        self.append(row1)

        row2 = self.toolbar()
        self.hook_label = label("Commit hook: pick a folder first", "dim-label")
        row2.append(self.hook_label)
        self.hook_btn = button("Install commit hook", self.toggle_hook,
                               tooltip="A git pre-commit hook that checks staged changes and "
                                       "stops commits with a secret in them")
        row2.append(self.hook_btn)
        self.block_ids = Gtk.CheckButton(label="Also block account IDs")
        self.block_ids.set_active(bool(self.settings.get("block_account_ids")))
        self.block_ids.set_tooltip_text("Treat AWS account IDs as something to fix instead of a "
                                        "warning. Saved, so the commit hook and the terminal "
                                        "do the same.")
        self.block_ids.set_margin_start(10)
        self.block_ids.connect("toggled", lambda *_: self.block_ids_changed())
        row2.append(self.block_ids)
        row2.append(spacer())
        row2.append(button("Export", self.export, tooltip="Save the findings as Markdown, CSV "
                                                          "or JSON, values masked"))
        self.append(row2)

        self.counts_box = hbox(10)
        self.counts_box.set_margin_start(12)
        self.counts_box.set_margin_bottom(6)
        self.append(self.counts_box)

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        self.table = FindingsTable(self.COLS, on_select=self.selected,
                                   placeholder="Pick a repo or folder and press Scan.")
        paned.set_start_child(self.table)
        self.detail = DetailPane("Select a finding to see the lines around it, with every "
                                 "secret hidden, and how to fix it.", title="Finding")
        self.allow_btn = button("Allow this", self.allow_selected,
                                tooltip="Not a secret? Adds its sha256 (never the value) to "
                                        f"{secretscan.ALLOW_FILE} so scans and the commit "
                                        "hook skip it")
        self.allow_btn.set_sensitive(False)
        self.detail.extra.append(self.allow_btn)
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(True)
        paned.set_shrink_end_child(False)
        paned.set_position(330)
        self.append(paned)
        self.append(self.status)

        self.show_folder()
        self.mode_changed(save=False)
        self.show_counts()
        self.refresh_hook()

    # ---- folder and settings
    def save(self, **values):
        self.settings.update(values)
        secretscan.save_settings(values)

    def show_folder(self):
        if self.folder:
            self.folder_label.set_text(short_path(self.folder))
            self.folder_label.set_tooltip_text(self.folder)
            self.folder_label.remove_css_class("dim-label")
        else:
            self.folder_label.set_text("No folder picked yet")
            self.folder_label.set_tooltip_text(None)
            self.folder_label.add_css_class("dim-label")
        self.scan_btn.set_sensitive(bool(self.folder))

    def pick_folder(self):
        open_file(self.win, self.set_folder, title="Pick a repo or folder to scan", folder=True)

    def set_folder(self, path, check_mode=True):
        if not path:
            return
        self.folder = path
        self.save(folder=path)
        self.show_folder()
        self.result = None
        self.table.clear("Press Scan to check this folder.")
        self.detail.set_text("")
        self.allow_btn.set_sensitive(False)
        self.show_counts()
        self.status.idle("")
        self.refresh_hook(switch_mode=check_mode)

    def current_mode(self) -> str:
        return MODE_KEYS[self.mode.get_selected()]

    def mode_changed(self, save=True):
        mode = self.current_mode()
        self.depth_box.set_visible(mode == "history")
        if save:
            self.save(mode=mode)

    def block_ids_changed(self):
        on = self.block_ids.get_active()
        self.save(block_account_ids=on)
        if not self.result:
            return
        for f in self.result.findings + self.result.allowed:
            if f.kind == "account_id":
                f.level = "block" if on else "warn"
        self.result.findings.sort(key=lambda f: (secretscan.LEVEL_ORDER[f.level], f.path,
                                                 f.line, f.commit))
        self.fill_table()

    # ---- the commit hook
    def refresh_hook(self, switch_mode=False):
        self._hook_gen += 1
        gen = self._hook_gen
        folder = self.folder
        if not folder:
            self.show_hook({"state": "none"})
            return

        def done(state):
            if gen != self._hook_gen:
                return
            self.show_hook(state)
            if switch_mode and state.get("state") == "not_git" and \
                    self.current_mode() != "files":
                self.mode.set_selected(MODE_KEYS.index("files"))
                self.status.idle("That folder isn't a git repo, so it'll be scanned as plain "
                                 "files.")

        def failed(exc):
            if gen == self._hook_gen:
                self.show_hook({"state": "error", "message": str(exc)})
        run_bg(lambda: secretscan.hook_status(folder), done, failed)

    def show_hook(self, state):
        self.hook = state
        s = state.get("state")
        for c in ("ok-text", "warn-text", "dim-label"):
            self.hook_label.remove_css_class(c)
        text, css, btn, active, tip = {
            "on": ("Commit hook: on", "ok-text", "Remove commit hook", True,
                   "Each commit in this repo is checked for secrets first"),
            "off": ("Commit hook: off", "dim-label", "Install commit hook", True, None),
            "other": ("Commit hook: another hook is there", "warn-text", "Install commit hook",
                      True, "This repo already has a pre-commit hook that isn't AWS Kit's"),
            "not_git": ("Commit hook: not a git repo", "dim-label", "Install commit hook",
                        False, None),
            "no_git": ("Commit hook: git isn't installed", "dim-label", "Install commit hook",
                       False, None),
            "error": ("Commit hook: can't tell", "warn-text", "Install commit hook", False,
                      state.get("message")),
        }.get(s, ("Commit hook: pick a folder first", "dim-label", "Install commit hook",
                  False, None))
        if s == "on" and state.get("chained"):
            text += ", runs your old hook first"
        self.hook_label.set_text(text)
        self.hook_label.add_css_class(css)
        self.hook_label.set_tooltip_text(tip or state.get("path") or None)
        self.hook_btn.set_label(btn)
        self.hook_btn.set_sensitive(active)

    def toggle_hook(self):
        folder = self.folder
        state = self.hook.get("state")
        if state == "on":
            self.hook_job(lambda: secretscan.remove_hook(folder))
        elif state == "other":
            ask(self.win, "There's already a pre-commit hook in this repo",
                f"{self.hook.get('path', '')}\n\nAWS Kit can rename it to "
                "pre-commit.before-awskit and run it first, then check for secrets. A commit "
                "stops if either one fails. Removing AWS Kit's hook later puts yours back.",
                "Run both",
                lambda: self.hook_job(lambda: secretscan.install_hook(folder, chain=True)))
        else:
            self.hook_job(lambda: secretscan.install_hook(folder))

    def hook_job(self, work):
        self.hook_btn.set_sensitive(False)

        def done(message):
            self.status.idle(message)
            if not secretscan.find_awskit_on_path() and self.hook.get("state") != "on":
                show_message(self.win, "awskit isn't on your PATH",
                             "The hook runs awskit secrets, so until awskit is on PATH it "
                             "lets commits through without checking them. The installer adds "
                             "it to ~/.local/bin (Linux) or AWSKit\\bin (Windows).")
            self.refresh_hook()

        def failed(exc):
            self.refresh_hook()
            if isinstance(exc, (HookError, ScanError, OSError)):
                show_message(self.win, "Couldn't change the commit hook", str(exc))
            else:
                show_message(self.win, "Couldn't change the commit hook",
                             str(exc) or type(exc).__name__)
        run_bg(work, done, failed)

    # ---- scanning
    def run(self):
        if not self.folder:
            self.pick_folder()
            return
        folder, mode = self.folder, self.current_mode()
        history = int(self.depth.get_value())
        block = self.block_ids.get_active()
        self.save(mode=mode, history_commits=history)
        cancel = self.new_cancel()
        self.scan_btn.set_sensitive(False)
        self.allow_btn.set_sensitive(False)
        self.status.busy(f"Scanning {MODES[mode].lower()}...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: secretscan.scan(folder, mode, history, block, progress=progress,
                                       cancel=cancel), self.done, self.failed)

    def done(self, result):
        self.result = result
        self.scan_btn.set_sensitive(True)
        self.fill_table()
        notes = list(result.notes)
        self.status.idle(result.summary() + (f" {len(notes)} note(s) below." if notes and
                                             not result.findings else ""))
        self.detail.set_text("Notes from the scan:\n\n" + "\n".join(notes) if notes else "")
        self.refresh_hook()

    def failed(self, exc):
        self.scan_btn.set_sensitive(True)
        self.status.idle("")
        show_message(self.win, "Couldn't scan", str(exc) if isinstance(exc, ScanError)
                     else (str(exc) or type(exc).__name__))

    def fill_table(self):
        r = self.result
        if r is None:
            return
        columns = self.table.view.get_columns()  # Commit, the last one, is for history only
        columns.get_item(columns.get_n_items() - 1).set_visible(r.mode == "history")
        self.table.set_rows([f.row() for f in r.findings], r.findings)
        if not r.findings:
            what = {"staged": "in the staged changes", "history": "in those commits"}.get(
                r.mode, "in these files")
            self.table.clear(f"Nothing to fix {what}." +
                             (f" {len(r.allowed)} allowed." if r.allowed else ""))
        self.show_counts()

    def show_counts(self):
        clear_box(self.counts_box)
        r = self.result
        if r is None:
            self.counts_box.append(label("Pick a repo or folder, choose what to scan, and "
                                         "press Scan.", "headline"))
            return
        c = r.counts()
        if not c["block"] and not c["warn"]:
            self.counts_box.append(label("Nothing to fix.", "headline ok-text"))
        for key, text, css in (("block", "to fix", "sev-high"),
                               ("warn", "warning" if c["warn"] == 1 else "warnings",
                                "sev-low")):
            if c[key]:
                box = hbox(6)
                badge = label(key.upper(), f"sev {css}", xalign=0.5)
                badge.set_valign(Gtk.Align.CENTER)
                box.append(badge)
                box.append(label(f"{c[key]} {text}", "headline"))
                self.counts_box.append(box)
        if c["allowed"]:
            self.counts_box.append(label(f"{c['allowed']} allowed", "dim-label"))
        unit = r.unit if r.scanned != 1 else r.unit.rstrip("s")
        self.counts_box.append(label(f"in {r.scanned} {unit}", "dim-label"))

    def selected(self, row):
        if row is None:
            self.allow_btn.set_sensitive(False)
            return
        self.detail.set_text(row.obj.detail_text())
        self.allow_btn.set_sensitive(True)

    # ---- allowing a false positive
    def allow_selected(self):
        row = self.table.selected_item()
        if row is None or self.result is None:
            return
        f = row.obj
        ask(self.win, f"Allow this {f.what.lower()}?",
            f"{f.where}\n\nAdds its sha256 to {secretscan.ALLOW_FILE} at the top of the repo, "
            "so scans and the commit hook skip this value from now on, wherever it is. Only do "
            "this if it isn't a real secret.", "Allow it", lambda: self.do_allow(f))

    def do_allow(self, f):
        r = self.result
        try:
            path, _ = secretscan.add_allow_entries(r.root, [f])
        except OSError as exc:
            show_message(self.win, f"Couldn't update {secretscan.ALLOW_FILE}", str(exc))
            return
        reason = f"a sha256 line in {secretscan.ALLOW_FILE}"
        same = [g for g in r.findings if g.value_hash == f.value_hash]
        for g in same:
            g.allowed = reason
            r.findings.remove(g)
            r.allowed.append(g)
        self.fill_table()
        self.detail.set_text("")
        self.allow_btn.set_sensitive(False)
        self.status.idle(f"Allowed. Added its sha256 to {path.name} at the top of the repo. "
                         "Commit that file so the hook and CI skip it too.")

    def export(self):
        if not self.result or not self.result.findings:
            show_message(self.win, "Nothing to export yet", "Run a scan first.")
            return
        rows = []
        for f in self.result.findings:
            r = f.row()
            r.update(note=f.note, fix=f.fix, commit=f.commit)
            rows.append(r)
        export_rows(self.win, rows, self.EXPORT_COLS, "secrets-scan.md", title="Secrets scan")
