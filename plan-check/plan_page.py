"""Plan Check page for the AWS Kit window."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from gi.repository import Gdk, GLib, Gtk

from . import tfplan
from .common import SEVERITY_ORDER, have_pii_redact, pii_redact
from .widgets import (DetailPane, Page, ResultTable, button, flash, label, on_main, open_file,
                      run_bg, save_text, set_clipboard, show_message, spacer, vbox)


class PlanPage(Page):
    name = "plan"
    title = "Plan Check"

    RISK_COLS = [("severity", "Severity", {"width": 95, "kind": "severity", "sort_key": "rank"}),
                 ("address", "Resource", {"width": 240, "kind": "mono"}),
                 ("title", "Issue", {"expand": True})]
    CHANGE_COLS = [("mark", "", {"width": 44, "kind": "mono", "sort_key": "order"}),
                   ("address", "Resource", {"width": 260, "kind": "mono"}),
                   ("info", "Details", {"expand": True})]
    ORDER = {"delete": 0, "replace": 1, "update": 2, "create": 3, "forget": 4}

    def __init__(self, win):
        super().__init__(win, "Turns a Terraform plan into a short list of what changes and "
                         "flags the risky parts. Pick a folder to run terraform plan, open a "
                         "saved plan or plan JSON, or drop one onto this page.")
        self.folder = None
        self.summary = None
        bar = self.toolbar()
        self.folder_btn = button("Choose folder", self.choose_folder)
        bar.append(self.folder_btn)
        self.run_btn = button("Run plan", self.run_plan, css="suggested-action")
        self.run_btn.set_sensitive(False)
        bar.append(self.run_btn)
        bar.append(button("Open plan file", self.open_plan,
                          tooltip="A saved plan (terraform plan -out) or terraform show -json output"))
        bar.append(button("Paste JSON", self.paste,
                          tooltip="Read terraform show -json output from the clipboard"))
        bar.append(spacer())
        self.copy_btn = button("Copy summary", self.copy_summary)
        bar.append(self.copy_btn)
        self.redact_btn = button("Copy redacted", self.copy_redacted,
                                 tooltip="Runs the summary through PII Redact first")
        self.redact_btn.set_visible(have_pii_redact())
        bar.append(self.redact_btn)
        bar.append(button("Save Markdown", self.save_md))
        self.append(bar)

        self.headline = label("No plan loaded yet.", "headline", wrap=True)
        self.headline.set_margin_start(12)
        self.headline.set_margin_bottom(6)
        self.append(self.headline)

        lr = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        left = vbox(4)
        left.append(self.section("Things to look at"))
        self.risks = ResultTable(self.RISK_COLS, on_select=self.risk_selected, search=False,
                                 placeholder="Risky changes show up here.")
        self.risks.set_vexpand(True)
        left.append(self.risks)
        right = vbox(4)
        right.append(self.section("Changes"))
        self.changes = ResultTable(self.CHANGE_COLS, on_select=self.change_selected, search=False,
                                   placeholder="Creates, updates, replaces and destroys show up here.")
        self.changes.set_vexpand(True)
        right.append(self.changes)
        lr.set_start_child(left)
        lr.set_end_child(right)
        lr.set_position(580)

        tb = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        tb.set_vexpand(True)
        tb.set_start_child(lr)
        self.detail = DetailPane("Select a row to see more.")
        tb.set_end_child(self.detail)
        tb.set_resize_end_child(False)
        tb.set_position(400)
        self.append(tb)
        self.append(self.status)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self.dropped)
        self.add_controller(drop)

    def section(self, text):
        w = label(text, "heading")
        w.set_margin_start(12)
        w.set_margin_top(4)
        return w

    # ---- loading
    def choose_folder(self):
        open_file(self.win, self.set_folder, "Terraform folder", folder=True)

    def set_folder(self, path):
        self.folder = path
        self.folder_btn.set_label(Path(path).name or path)
        self.folder_btn.set_tooltip_text(path)
        self.run_btn.set_sensitive(True)

    def run_plan(self):
        if not self.folder:
            return
        if not tfplan.terraform_bin():
            show_message(self.win, "Terraform isn't installed",
                         "Install terraform or tofu, or open a plan JSON file instead.")
            return
        folder = self.folder
        self.run_btn.set_sensitive(False)
        self.status.busy(f"Running terraform plan in {folder}...", progress=False)
        log = on_main(self.status.text.set_text)
        run_bg(lambda: tfplan.plan_directory(folder, log=log), self.loaded, self.failed)

    def open_plan(self):
        open_file(self.win, self.load_path, "Open plan")

    def load_path(self, path):
        if os.path.isdir(path):
            self.set_folder(path)
            self.run_plan()
            return
        self.status.busy(f"Reading {Path(path).name}...", progress=False)
        run_bg(lambda: tfplan.load_plan(path), self.loaded, self.failed)

    def dropped(self, target, value, x, y):
        files = value.get_files()
        if files and files[0].get_path():
            self.load_path(files[0].get_path())
            return True
        return False

    def paste(self):
        def got(clip, result):
            try:
                text = clip.read_text_finish(result)
            except GLib.Error:
                text = None
            if not text:
                show_message(self.win, "The clipboard is empty")
                return
            try:
                self.loaded(tfplan.load_plan(text))
            except tfplan.PlanError as exc:
                self.failed(exc)
        self.get_clipboard().read_text_async(None, got)

    def loaded(self, plan):
        self.run_btn.set_sensitive(bool(self.folder))
        try:
            self.summary = tfplan.summarize(plan)
        except tfplan.PlanError as exc:
            self.failed(exc)
            return
        s = self.summary
        risk_rows = []
        for r in s.risks:
            d = r.as_dict()
            d["rank"] = SEVERITY_ORDER.get(r.severity, 9)
            risk_rows.append(d)
        self.risks.set_rows(risk_rows, s.risks)
        if not s.risks:
            self.risks.clear("Nothing risky found.")
        change_rows = []
        for c in s.changes:
            if c.forces:
                info = "replaced because of " + ", ".join(c.forces)
            elif c.changed:
                info = ", ".join(c.changed)
            else:
                info = tfplan.ACTION_WORD[c.action]
            change_rows.append({"mark": tfplan.ACTION_MARK[c.action], "address": c.address,
                                "info": info, "order": self.ORDER[c.action]})
        self.changes.set_rows(change_rows, s.changes)
        if not s.changes:
            self.changes.clear("No resource changes.")
        worst = tfplan.worst(s.risks)
        self.headline.set_text(s.headline() + (f"  Worst finding: {worst}." if worst else ""))
        self.detail.set_text(tfplan.report_text(s))
        self.status.idle(f"Loaded at {datetime.now():%H:%M}" +
                         (f", Terraform {s.tf_version}" if s.tf_version else "") + ".")

    def failed(self, exc):
        self.run_btn.set_sensitive(bool(self.folder))
        self.status.idle("")
        show_message(self.win, "Couldn't read the plan", str(exc))

    # ---- details
    def risk_selected(self, row):
        if row is None:
            return
        r = row.obj
        text = f"[{r.severity.upper()}] {r.address}\n{r.title}"
        if r.detail:
            text += f"\n\n{r.detail}"
        if r.fix:
            text += f"\n\nHow to fix: {r.fix}"
        self.detail.set_text(text)

    def change_selected(self, row):
        if row is None:
            return
        c = row.obj
        lines = [f"{tfplan.ACTION_WORD[c.action].capitalize()}: {c.address}", f"Type: {c.type}"]
        if c.module:
            lines.append(f"Module: {c.module}")
        if c.forces:
            lines.append("Replaced because these changed: " + ", ".join(c.forces))
        if c.changed:
            lines.append("Changed: " + ", ".join(c.changed))
        risks = [r for r in self.summary.risks if r.address == c.address]
        if risks:
            lines.append("")
            lines += [f"[{r.severity.upper()}] {r.title}" for r in risks]
        self.detail.set_text("\n".join(lines))

    # ---- output
    def report(self, markdown=False):
        return tfplan.report_text(self.summary, markdown=markdown) if self.summary else ""

    def copy_summary(self):
        if self.summary:
            set_clipboard(self, self.report())
            flash(self.copy_btn, "Copied")

    def copy_redacted(self):
        if not self.summary:
            return
        text = self.report()

        def done(red):
            set_clipboard(self, red)
            flash(self.redact_btn, "Copied")
        run_bg(lambda: pii_redact(text), done)

    def save_md(self):
        if self.summary:
            save_text(self.win, self.report(markdown=True), "plan-summary.md")
