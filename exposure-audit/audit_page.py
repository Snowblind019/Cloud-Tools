"""Exposure Audit page for the AWS Kit window."""
from __future__ import annotations

from datetime import datetime

from gi.repository import Gtk

from . import audit
from .common import SEVERITY_ORDER, error_text
from .widgets import (CheckListButton, DetailPane, Page, ResultTable, account_pickers, button,
                      chosen_profiles, clear_box, export_rows, fill_accounts, hbox, label,
                      on_main, run_bg, sev_badge, show_message, spacer, string_dropdown)


class AuditPage(Page):
    name = "audit"
    title = "Exposure Audit"

    COLS = [
        ("severity", "Severity", {"width": 95, "kind": "severity", "sort_key": "sev_rank"}),
        ("profile", "Profile", {"width": 110}),
        ("region", "Region", {"width": 105}),
        ("check", "Finding", {"width": 250}),
        ("resource", "Resource", {"width": 200, "kind": "mono"}),
        ("name", "Name", {"width": 130}),
        ("detail", "Detail", {"expand": True}),
    ]
    EXPORT_COLS = [("severity", "Severity"), ("profile", "Profile"), ("account", "Account"),
                   ("region", "Region"), ("check", "Finding"), ("resource", "Resource"),
                   ("name", "Name"), ("detail", "Detail"), ("fix", "Fix")]
    LEVELS = ["Everything", "Critical and high", "Medium and worse", "Low and worse"]
    LEVEL_MAX = [9, 1, 2, 3]

    def __init__(self, win):
        super().__init__(win, "Looks for things open to the internet or missing basic "
                         "protection: open security groups, public buckets and snapshots, "
                         "IMDSv1, unencrypted storage, root and IAM user hygiene. Read-only.")
        self.findings = []
        bar = self.toolbar()
        account_pickers(self)
        bar.append(self.accounts)
        bar.append(self.regions)
        self.checks = CheckListButton("Checks", all_label="All checks")
        self.checks.set_options([(k, c["title"]) for k, c in sorted(audit.CHECKS.items(),
                                                                     key=lambda x: x[1]["title"])])
        bar.append(self.checks)
        self.run_btn = button("Run audit", self.run, css="suggested-action")
        bar.append(self.run_btn)
        bar.append(spacer())
        self.level = string_dropdown(self.LEVELS)
        self.level.connect("notify::selected", lambda *_: self.apply_level())
        bar.append(self.level)
        bar.append(button("Export", self.export))
        self.append(bar)

        self.counts_box = hbox(8)
        self.counts_box.set_margin_start(12)
        self.counts_box.set_margin_bottom(6)
        self.counts_box.append(label("Press Run audit to start.", "headline"))
        self.append(self.counts_box)

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        self.table = ResultTable(self.COLS, on_select=self.selected,
                                 placeholder="No audit run yet.\nPick accounts and press Run audit.")
        paned.set_start_child(self.table)
        self.detail = DetailPane()
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(False)
        paned.set_position(440)
        self.append(paned)
        self.append(self.status)

    def profile_changed(self, profile):
        fill_accounts(self, reset=True)

    def profiles_changed(self):
        fill_accounts(self)

    def run(self):
        profiles = chosen_profiles(self)
        regions = self.regions.selected() or None
        checks = self.checks.selected() or None
        cancel = self.new_cancel()
        self.run_btn.set_sensitive(False)
        self.status.busy("Starting audit...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: audit.audit(profiles, regions, checks, progress=progress, cancel=cancel),
               self.done, self.failed)

    def done(self, result):
        self.findings, warnings = result
        self.run_btn.set_sensitive(True)
        rows = []
        for f in self.findings:
            r = f.row()
            r["sev_rank"] = SEVERITY_ORDER.get(f.severity, 9)
            rows.append(r)
        self.table.set_rows(rows, self.findings)
        if not self.findings:
            self.table.clear("No findings. Either it's in good shape or the checks lacked "
                             "permission, see the notes below.")
        self.show_counts()
        self.apply_level()
        self.status.idle(f"Audit finished at {datetime.now():%H:%M}.")
        if warnings:
            self.detail.set_text("Notes from the audit:\n\n" + "\n".join(warnings))

    def failed(self, exc):
        self.run_btn.set_sensitive(True)
        self.status.idle("")
        show_message(self.win, "Audit failed", error_text(exc))

    def show_counts(self):
        clear_box(self.counts_box)
        c = audit.counts(self.findings)
        if not self.findings:
            self.counts_box.append(label("No findings.", "headline"))
            return
        for sev, n in c.items():
            if n:
                box = hbox(4)
                box.append(sev_badge(sev))
                box.append(label(str(n), "headline"))
                self.counts_box.append(box)

    def apply_level(self):
        limit = self.LEVEL_MAX[self.level.get_selected()]
        self.table.set_filter(lambda it: it.data.get("sev_rank", 9) <= limit)

    def selected(self, row):
        if row is None:
            return
        f = row.obj
        lines = [f"[{f.severity.upper()}] {f.check}", f"Resource: {f.resource}"]
        if f.name:
            lines.append(f"Name: {f.name}")
        lines.append(f"Account: {f.profile or 'default'} ({f.account})   Region: {f.region}")
        if f.detail:
            lines += ["", f.detail]
        if f.fix:
            lines += ["", "How to fix: " + f.fix]
        self.detail.set_text("\n".join(lines))

    def export(self):
        if not self.findings:
            show_message(self.win, "Nothing to export yet", "Run the audit first.")
            return
        export_rows(self.win, [f.row() for f in self.findings], self.EXPORT_COLS,
                    "exposure-audit.md", title="Exposure audit")
