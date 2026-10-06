"""Credentials page for the AWS Kit window."""
from __future__ import annotations

from datetime import datetime

from gi.repository import GLib, Gtk

from . import creds
from .common import error_text
from .widgets import (CheckListButton, DetailPane, Page, ResultTable, button, chosen_profiles,
                      clear_box, export_rows, fill_accounts, hbox, label, on_main, run_bg,
                      save_text, sev_badge, show_message, spacer, string_dropdown, vbox)


def _set_column_visible(table, title, visible):
    columns = table.view.get_columns()
    for n in range(columns.get_n_items()):
        col = columns.get_item(n)
        if col.get_title() == title:
            col.set_visible(visible)


def _plain(row) -> dict:
    """A table row without the sort-only fields, for exports."""
    return {k: v for k, v in row.items() if not k.startswith("_") and k != "sev_rank"}


class CredsPage(Page):
    name = "creds"
    title = "Credentials"

    FINDING_COLS = [
        ("severity", "Severity", {"width": 95, "kind": "severity", "sort_key": "sev_rank"}),
        ("profile", "Profile", {"width": 110}),
        ("kind", "Type", {"width": 72}),
        ("resource", "Identity", {"width": 210, "kind": "mono"}),
        ("check", "Finding", {"width": 250}),
        ("detail", "Detail", {"expand": True}),
    ]
    IDENTITY_COLS = [
        ("kind", "Type", {"width": 54}),
        ("profile", "Profile", {"width": 110}),
        ("name", "Name", {"width": 140, "kind": "mono"}),
        ("console", "Console", {"width": 102}),
        ("password", "Password used", {"width": 106, "sort_key": "_password_days"}),
        ("keys", "Access keys", {"width": 200, "expand": True, "sort_key": "_keys_count"}),
        ("activity", "Last activity", {"width": 108, "sort_key": "_activity_days"}),
        ("admin", "Admin", {"width": 106}),
        ("worst", "Worst", {"width": 84, "kind": "severity", "sort_key": "_rank"}),
        ("top", "Worst finding", {"width": 130, "expand": True}),
    ]
    FINDING_EXPORT = [("severity", "Severity"), ("profile", "Profile"), ("account", "Account"),
                      ("kind", "Type"), ("resource", "Identity"), ("check", "Finding"),
                      ("detail", "Detail"), ("fix", "Fix")]
    IDENTITY_EXPORT = [("kind", "Type"), ("profile", "Profile"), ("account", "Account"),
                       ("name", "Name"), ("console", "Console"), ("password", "Password used"),
                       ("keys", "Access keys"), ("activity", "Last activity"),
                       ("admin", "Admin"), ("worst", "Worst"), ("top", "Worst finding")]
    LEVELS = ["Everything", "Critical and high", "Medium and worse", "Low and worse"]
    LEVEL_MAX = [9, 1, 2, 3]
    DAYS = [30, 60, 90, 120, 180, 365]

    def __init__(self, win):
        super().__init__(win, "IAM users, access keys, roles and the root user: how old the "
                         "credentials are, when they were last used, who has admin, and what to "
                         "clean up. Read-only.")
        self.result = None
        self.profiles_used = []

        bar = self.toolbar()
        self.accounts = CheckListButton("Accounts", empty_label="current profile")
        fill_accounts(self)
        bar.append(self.accounts)
        bar.append(self._gap())
        bar.append(label("Keys older than"))
        self.key_age = string_dropdown([f"{d} days" for d in self.DAYS],
                                       self.DAYS.index(creds.DEFAULT_KEY_AGE))
        self.key_age.set_tooltip_text("Active access keys older than this should be rotated")
        bar.append(self.key_age)
        bar.append(self._gap())
        bar.append(label("Unused for"))
        self.unused = string_dropdown([f"{d} days" for d in self.DAYS],
                                      self.DAYS.index(creds.DEFAULT_UNUSED))
        self.unused.set_tooltip_text("Passwords, keys, users and roles not used for this long "
                                     "are flagged")
        bar.append(self.unused)
        bar.append(self._gap())
        self.run_btn = button("Check", self.run, css="suggested-action",
                              tooltip="Read IAM in each picked account. Nothing is changed.")
        bar.append(self.run_btn)
        bar.append(spacer())
        bar.append(self._export_menu())
        self.append(bar)
        self.key_age.connect("notify::selected", lambda *_: self.thresholds_changed())
        self.unused.connect("notify::selected", lambda *_: self.thresholds_changed())

        head = hbox(8)
        head.set_margin_start(12)
        head.set_margin_end(10)
        self.counts_box = hbox(8)
        self.counts_box.set_valign(Gtk.Align.CENTER)
        self.counts_box.append(label("Press Check to start.", "headline"))
        head.append(self.counts_box)
        self.notes_btn = Gtk.Button()
        notes = hbox(6)
        notes.append(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
        self.notes_label = label("Notes")
        notes.append(self.notes_label)
        self.notes_btn.set_child(notes)
        self.notes_btn.add_css_class("flat")
        self.notes_btn.set_tooltip_text("What couldn't be checked")
        self.notes_btn.connect("clicked", lambda *_: self.show_notes())
        self.notes_btn.set_visible(False)
        head.append(self.notes_btn)
        head.append(spacer())
        self.level = string_dropdown(self.LEVELS)
        self.level.set_tooltip_text("Hide findings, and identities, below this level")
        self.level.connect("notify::selected", lambda *_: self.apply_level())
        head.append(self.level)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        head.append(Gtk.StackSwitcher(stack=self.stack))
        self.append(head)

        self.summary = label("", wrap=True)
        self.summary.set_margin_start(12)
        self.summary.set_margin_end(12)
        self.summary.set_margin_top(6)
        self.summary.set_margin_bottom(8)
        self.summary.set_visible(False)
        self.append(self.summary)

        self.findings_table = ResultTable(
            self.FINDING_COLS, on_select=self.finding_selected,
            on_activate=self.finding_activated,
            placeholder="No check run yet.\nPick accounts and press Check.")
        self.identities_table = ResultTable(
            self.IDENTITY_COLS, on_select=self.identity_selected,
            on_activate=self.identity_activated,
            placeholder="No check run yet.\nPick accounts and press Check.")
        self.stack.add_titled(self.findings_table, "findings", "Findings")
        self.stack.add_titled(self.identities_table, "identities", "Identities")
        self.stack.connect("notify::visible-child-name", lambda *_: self.view_changed())
        for table in (self.findings_table, self.identities_table):
            _set_column_visible(table, "Profile", False)

        self.paned = paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        paned.set_start_child(self.stack)
        self.detail = DetailPane("Select a finding or an identity to see the details. "
                                 "Double-click a finding to jump to its identity.")
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(False)
        paned.set_shrink_end_child(False)
        paned.set_position(330)
        self._split_tries = 0
        paned.connect("map", lambda *_: GLib.idle_add(self._fit_split))
        self.append(paned)
        self.append(self.status)

    # ---- building
    def _gap(self):
        sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        sep.set_margin_start(4)
        sep.set_margin_end(4)
        sep.set_margin_top(6)
        sep.set_margin_bottom(6)
        return sep

    def _export_menu(self):
        menu = self.export_btn = Gtk.MenuButton(label="Export")
        menu.set_tooltip_text("Save the results as Markdown, CSV or JSON")
        pop = Gtk.Popover()
        box = vbox(2)
        for text, fn in (("Findings...", self.export_findings),
                         ("Identities...", self.export_identities),
                         ("Full report with commands...", self.export_report)):
            b = button(text, lambda fn=fn: (pop.popdown(), fn()))
            b.add_css_class("flat")
            b.get_child().set_xalign(0)
            box.append(b)
        pop.set_child(box)
        menu.set_popover(pop)
        return menu

    def _fit_split(self):
        """Once the page is first shown, give the details pane about a third of the height,
        whatever the window size. After that it's the user's to drag."""
        height = self.paned.get_height()
        if height < 100:
            self._split_tries += 1
            if self._split_tries < 20:
                GLib.timeout_add(50, self._fit_split)
            return False
        if self._split_tries >= 0:
            self.paned.set_position(height - max(170, round(height * 0.36)))
            self._split_tries = -1
        return False

    def thresholds(self) -> tuple:
        return self.DAYS[self.key_age.get_selected()], self.DAYS[self.unused.get_selected()]

    # ---- profiles
    def profile_changed(self, profile):
        fill_accounts(self, reset=True)

    def profiles_changed(self):
        fill_accounts(self)

    # ---- running
    def run(self):
        profiles = chosen_profiles(self)
        key_age, unused = self.thresholds()
        cancel = self.new_cancel()
        self.profiles_used = profiles
        self.run_btn.set_sensitive(False)
        self.status.busy("Starting...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: creds.check(profiles, key_age, unused, progress=progress, cancel=cancel),
               self.done, self.failed)

    def done(self, result):
        self.run_btn.set_sensitive(True)
        self.show_result(result)
        n = len(result.accounts)
        text = f"Checked {creds.plural(n, 'account')} at {datetime.now():%H:%M}."
        if result.warnings:
            text += (f" {creds.plural(len(result.warnings), 'note')} on what couldn't be "
                     "checked, see Notes.")
        self.status.idle(text)

    def failed(self, exc):
        self.run_btn.set_sensitive(True)
        self.status.idle("")
        show_message(self.win, "Check failed", error_text(exc))

    def thresholds_changed(self):
        """New thresholds only change the judgement, so the results update without asking
        AWS again."""
        if self.result is None or not self.result.accounts:
            return
        key_age, unused = self.thresholds()
        self.show_result(creds.analyze(self.result.accounts, key_age, unused,
                                       errors=self.result.errors))
        self.status.idle(f"Updated for keys older than {key_age} days and {unused} days unused.")

    def show_result(self, result):
        """Fill both tables from a creds.Result. Also used to show test data."""
        self.result = result
        now = result.now
        several = len({i.profile for i in result.identities} |
                      {f.profile for f in result.findings}) > 1
        for table in (self.findings_table, self.identities_table):
            _set_column_visible(table, "Profile", several)

        self.findings_table.set_rows([f.row() for f in result.findings], result.findings)
        if not result.findings:
            self.findings_table.clear(
                "No findings, but some things couldn't be checked. See Notes." if result.warnings
                else "No findings. Every identity looks tidy for these thresholds.")
        self.identities_table.set_rows([creds.identity_row(i, now) for i in result.identities],
                                       result.identities)
        if not result.identities:
            self.identities_table.clear("Nothing could be read. See Notes.")

        self.stack.get_page(self.findings_table).set_title(f"Findings ({len(result.findings)})")
        self.stack.get_page(self.identities_table).set_title(
            f"Identities ({len(result.identities)})")
        self.show_counts()
        self.summary.set_text(result.summary() if result.accounts else "")
        self.summary.set_visible(bool(result.accounts))
        self.notes_label.set_text(creds.plural(len(result.warnings), "note"))
        self.notes_btn.set_visible(bool(result.warnings))
        self.apply_level()
        if result.warnings:
            self.show_notes()
        else:
            self.detail.set_text("")

    def show_counts(self):
        clear_box(self.counts_box)
        if self.result is None:
            return
        c = creds.counts(self.result.findings)
        if not self.result.findings:
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
        self.findings_table.set_filter(lambda it: it.data.get("sev_rank", 9) <= limit)
        self.identities_table.set_filter(lambda it: limit == 9 or it.data.get("_rank", 9) <= limit)

    # ---- details
    def show_notes(self):
        if self.result is None or not self.result.warnings:
            return
        self.findings_table.selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.identities_table.selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.detail.set_text("Notes from the check, on what couldn't be checked:\n\n" +
                             "\n".join("- " + w for w in self.result.warnings))

    def finding_selected(self, row):
        if row is None or self.result is None:
            return
        f = row.obj
        self.detail.set_text(creds.finding_text(f, self.result.identity_for(f), self.result.now))

    def identity_selected(self, row):
        if row is None or self.result is None:
            return
        self.detail.set_text(creds.identity_text(row.obj, self.result.now))

    def view_changed(self):
        table = self.stack.get_visible_child()
        if table is None:
            return
        row = table.selected_item()
        if row is not None:
            (self.finding_selected if table is self.findings_table
             else self.identity_selected)(row)
        elif self.result is not None and self.result.warnings:
            self.show_notes()
        else:
            self.detail.set_text("")

    def finding_activated(self, row):
        """Double-click on a finding: show its identity."""
        if row is None or self.result is None:
            return
        ident = self.result.identity_for(row.obj)
        if ident is not None:
            self.select_identity(ident)

    def identity_activated(self, row):
        """Double-click on an identity: show only its findings."""
        if row is None or not row.obj.findings or self.findings_table.search is None:
            return
        self.level.set_selected(0)
        self.findings_table.search.set_text(row.obj.name)
        self.stack.set_visible_child_name("findings")

    def select_identity(self, ident):
        table = self.identities_table
        if table.search is not None and table.search.get_text():
            table.search.set_text("")
            table.query = ""
            table.filter.changed(Gtk.FilterChange.LESS_STRICT)
        self.stack.set_visible_child_name("identities")
        for n in range(table.sort_model.get_n_items()):
            if table.sort_model.get_item(n).obj is ident:
                table.selection.set_selected(n)
                if hasattr(table.view, "scroll_to"):
                    table.view.scroll_to(n, None, Gtk.ListScrollFlags.FOCUS, None)
                return

    # ---- export
    def _need_result(self) -> bool:
        if self.result is None:
            show_message(self.win, "Nothing to export yet", "Run the check first.")
            return False
        return True

    def export_findings(self):
        if self._need_result():
            export_rows(self.win, [_plain(f.row()) for f in self.result.findings],
                        self.FINDING_EXPORT, "credentials-findings.md",
                        title="Credentials: findings")

    def export_identities(self):
        if self._need_result():
            now = self.result.now
            export_rows(self.win, [_plain(creds.identity_row(i, now))
                                   for i in self.result.identities],
                        self.IDENTITY_EXPORT, "credentials-identities.md",
                        title="Credentials: identities")

    def export_report(self):
        if self._need_result():
            save_text(self.win, creds.markdown_report(self.result, self.profiles_used),
                      "credentials-report.md")
