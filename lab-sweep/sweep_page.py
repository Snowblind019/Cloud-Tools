"""Lab Sweep page for the AWS Kit window."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from gi.repository import Gtk

from . import sweep
from .common import error_text, load_config, money, save_config
from .widgets import (ConfirmDeleteDialog, DetailPane, Page, ResultTable, account_pickers,
                      button, chosen_profiles, export_rows, fill_accounts, hbox, label, margins,
                      on_main, run_bg, show_message, spacer, vbox)


def age_days(dt):
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


class SweepPage(Page):
    name = "sweep"
    title = "Lab Sweep"

    COLS = [
        ("profile", "Profile", {"width": 110}),
        ("region", "Region", {"width": 105}),
        ("kind", "What", {"width": 170}),
        ("id", "ID", {"width": 190, "kind": "mono"}),
        ("name", "Name", {"width": 140}),
        ("state", "State", {"width": 90}),
        ("cost", "Est/mo", {"width": 75, "kind": "cost", "sort_key": "monthly"}),
        ("age", "Age", {"width": 55, "sort_key": "age_days"}),
        ("action", "Teardown", {"width": 95}),
        ("detail", "Detail", {"expand": True}),
    ]
    EXPORT_COLS = [("profile", "Profile"), ("account", "Account"), ("region", "Region"),
                   ("kind", "What"), ("id", "ID"), ("name", "Name"), ("state", "State"),
                   ("cost", "Est/mo"), ("age", "Age"), ("action", "Teardown"),
                   ("detail", "Detail"), ("note", "Note")]

    def __init__(self, win):
        super().__init__(win, "Finds things still costing money in every enabled region. "
                         "Scanning only reads. Nothing is deleted unless you tick it, press "
                         "Delete, and type delete.")
        self.items = []
        self.warnings = []

        bar = self.toolbar()
        account_pickers(self)
        bar.append(self.accounts)
        bar.append(self.regions)
        self.scan_btn = button("Scan", self.scan, css="suggested-action")
        bar.append(self.scan_btn)
        bar.append(button("Month-to-date spend", self.spend,
                          tooltip="Asks Cost Explorer what you've actually spent this month. "
                                  "Each request costs $0.01."))
        bar.append(spacer())
        bar.append(button("Settings", self.settings))
        bar.append(button("Export", self.export))
        self.append(bar)

        self.summary = label("Press Scan to look for leftovers.", "headline")
        self.summary.set_margin_start(12)
        self.summary.set_margin_bottom(6)
        self.append(self.summary)

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        self.table = ResultTable(self.COLS, checkable=True, on_select=self.selected,
                                 on_check=self.update_selection,
                                 placeholder="Nothing scanned yet.\nPick accounts and press Scan.")
        paned.set_start_child(self.table)
        self.detail = DetailPane()
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(False)
        paned.set_position(430)
        self.append(paned)

        actions = hbox(6)
        margins(actions, 8)
        actions.append(button("Tick everything deletable", lambda: self.table.set_all_checked(
            True, lambda it: it.obj.can_delete and not it.obj.kept)))
        actions.append(button("Untick all", lambda: self.table.set_all_checked(False)))
        actions.append(button("Keep ticked", self.keep_ticked,
                              tooltip="Add the ticked items to the keep list so they're never "
                                      "offered for deletion"))
        actions.append(spacer())
        self.sel_label = label("", "dim-label")
        actions.append(self.sel_label)
        actions.append(button("Dry run", self.dry_run, tooltip="Show what would happen, in order"))
        self.delete_btn = button("Delete ticked", self.teardown, css="destructive-action")
        self.delete_btn.set_sensitive(False)
        actions.append(self.delete_btn)
        self.append(actions)
        self.append(self.status)

    # ---------------------------------------------------------------- scanning
    def profile_changed(self, profile):
        fill_accounts(self, reset=True)

    def profiles_changed(self):
        fill_accounts(self)

    def scan(self):
        profiles = chosen_profiles(self)
        regions = self.regions.selected() or None
        cancel = self.new_cancel()
        self.scan_btn.set_sensitive(False)
        self.status.busy("Starting scan...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: sweep.scan(profiles, regions, progress=progress, cancel=cancel),
               self.scan_done, self.failed)

    def scan_done(self, result):
        self.items, self.warnings = result
        self.scan_btn.set_sensitive(True)
        self.show_items()
        stopped = " (stopped early)" if self.cancel.is_set() else ""
        self.status.idle(f"Scan finished{stopped} at {datetime.now():%H:%M}.")
        if self.warnings:
            self.detail.set_text("Notes from the scan:\n\n" + "\n".join(self.warnings))

    def show_items(self):
        rows = []
        for it in self.items:
            r = it.row()
            r["age_days"] = age_days(it.created)
            r["_dim"] = it.kept or not it.can_delete
            rows.append(r)
        self.table.set_rows(rows, self.items, [it.can_delete and not it.kept for it in self.items])
        if not self.items:
            self.table.clear("Nothing found that costs money. Nice and clean.")
        self.summary.set_text(sweep.summary_line(self.items))
        self.update_selection()

    def failed(self, exc):
        self.scan_btn.set_sensitive(True)
        self.status.idle("")
        show_message(self.win, "Scan failed", error_text(exc))

    def selected(self, row):
        if row is None:
            return
        it = row.obj
        lines = [f"{it.kind_label}: {it.id}"]
        if it.name:
            lines.append(f"Name: {it.name}")
        lines.append(f"Account: {it.profile or 'default'} ({it.account})   Region: {it.region}")
        if it.state:
            lines.append(f"State: {it.state}")
        if it.detail:
            lines.append(f"Detail: {it.detail}")
        lines.append(f"Estimated: {money(it.monthly)} a month")
        if it.created:
            lines.append(f"Created: {it.created:%Y-%m-%d %H:%M} ({row.data.get('age')} ago)")
        if it.tags:
            lines.append("Tags: " + ", ".join(f"{k}={v}" for k, v in sorted(it.tags.items())))
        if it.kept:
            lines.append("Kept: it's on the keep list or has the keep tag.")
        elif not it.can_delete:
            lines.append("Teardown: manual.")
        if it.note:
            lines.append("")
            lines.append(it.note)
        self.detail.set_text("\n".join(lines))

    def update_selection(self):
        ticked = [r.obj for r in self.table.checked()]
        self.delete_btn.set_sensitive(bool(ticked))
        if ticked:
            self.sel_label.set_text(f"{len(ticked)} ticked, about "
                                    f"{money(sweep.total_monthly(ticked))}/month")
        else:
            self.sel_label.set_text("")

    # ---------------------------------------------------------------- teardown
    def plan_lines(self, ticked):
        order = sorted(ticked, key=lambda i: (sweep.KINDS[i.kind].order, i.region, i.id))
        return [f"{i.profile or 'default':<14} {i.region:<15} {i.kind_label:<28} {i.id}"
                + (f"  {i.name}" if i.name else "") for i in order]

    def dry_run(self):
        ticked = [r.obj for r in self.table.checked()]
        if not ticked:
            self.detail.set_text("Tick some rows first.")
            return
        self.detail.set_text("Teardown would go in this order:\n\n" +
                             "\n".join(self.plan_lines(ticked)) +
                             "\n\nNAT gateways go before their Elastic IPs, AMIs before their "
                             "snapshots, and database instances before their clusters.")

    def teardown(self):
        ticked = [r.obj for r in self.table.checked()]
        if not ticked:
            return
        heading = (f"Delete {len(ticked)} item(s), about "
                   f"{money(sweep.total_monthly(ticked))}/month?")
        ConfirmDeleteDialog(self.win, heading, self.plan_lines(ticked),
                            lambda: self.run_teardown(ticked)).present()

    def run_teardown(self, ticked):
        cancel = self.new_cancel()
        self.delete_btn.set_sensitive(False)
        self.status.busy("Deleting...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: sweep.teardown(ticked, progress=progress, cancel=cancel),
               self.teardown_done, self.failed)

    def teardown_done(self, results):
        ok = sum(1 for _, success, _ in results if success)
        log = []
        for it, success, msg in results:
            log.append(f"{'ok  ' if success else 'FAIL'} {it.kind_label:<28} {it.id}: {msg}")
        outcome = {id(it): success for it, success, _ in results}
        for row in self.table.items():
            if id(row.obj) in outcome:
                success = outcome[id(row.obj)]
                row.data["action"] = "deleted" if success else "failed"
                row.data["_dim"] = success
                row.checked = False
                row.checkable = not success
        self.table.refresh_rows()
        self.update_selection()
        self.detail.set_text(f"{ok} of {len(results)} done.\n\n" + "\n".join(log) +
                             "\n\nSome things take a few minutes to go away, and some only free "
                             "up their dependents once they're gone. Scan again in a few "
                             "minutes to check.")
        self.status.idle(f"Teardown finished: {ok} of {len(results)} done.")

    def keep_ticked(self):
        ticked = [r.obj for r in self.table.checked()]
        if not ticked:
            return
        cfg = load_config()
        keep = list(cfg.get("keep") or [])
        for it in ticked:
            if it.id not in keep:
                keep.append(it.id)
            it.kept = True
        cfg["keep"] = keep
        save_config(cfg)
        self.show_items()
        self.status.idle(f"Added {len(ticked)} item(s) to the keep list.")

    # ---------------------------------------------------------------- extras
    def spend(self):
        profiles = chosen_profiles(self)
        self.status.busy("Asking Cost Explorer...", progress=False)

        def work():
            out = []
            for p in profiles:
                try:
                    out.append(sweep.month_spend(p))
                except Exception as exc:  # noqa: BLE001
                    out.append({"profile": p or "default", "error": error_text(exc, p)})
            return out

        def done(results):
            lines = []
            for r in results:
                if "error" in r:
                    lines.append(f"{r['profile']}: {r['error']}")
                    continue
                lines.append(f"{r['profile']}: {money(r['total'])} {r['unit']} so far this month "
                             f"(since {r['start']})")
                for svc, amt in r["services"]:
                    lines.append(f"  {money(amt):>10}  {svc}")
                lines.append("")
            lines.append("Cost Explorer data can lag up to a day. Each request costs $0.01.")
            self.detail.set_text("\n".join(lines))
            self.status.idle("Spend loaded.")
        run_bg(work, done, self.failed)

    def export(self):
        if not self.items:
            show_message(self.win, "Nothing to export yet", "Run a scan first.")
            return
        rows = []
        for it in self.items:
            r = it.row()
            rows.append(r)
        export_rows(self.win, rows, self.EXPORT_COLS, "lab-sweep.md", title="Lab sweep")

    def settings(self):
        SweepSettings(self.win, on_saved=lambda: self.show_items() if self.items else None).present()


class SweepSettings(Gtk.Window):
    def __init__(self, parent, on_saved=None):
        super().__init__(title="Lab Sweep settings", modal=True, transient_for=parent)
        self.set_default_size(560, 640)
        self.on_saved = on_saved
        cfg = load_config()
        outer = vbox(8)
        margins(outer, 16)

        outer.append(label("Keep list", "heading"))
        outer.append(label("IDs, ARNs or names that are never offered for deletion, one per line.",
                           "dim-label", wrap=True))
        self.keep = Gtk.TextView(monospace=True)
        self.keep.get_buffer().set_text("\n".join(cfg.get("keep") or []))
        sc = Gtk.ScrolledWindow()
        sc.set_min_content_height(120)
        sc.set_vexpand(True)
        sc.set_child(self.keep)
        outer.append(sc)

        grid = Gtk.Grid(column_spacing=10, row_spacing=8)
        self.keep_tag = Gtk.Entry(text=cfg.get("keep_tag", ""))
        self.regions = Gtk.Entry(text=", ".join(cfg.get("regions") or []),
                                 placeholder_text="Empty means every enabled region")
        self.threshold = Gtk.SpinButton.new_with_range(0, 10000, 1)
        self.threshold.set_value(float(cfg.get("notify_threshold", 1.0)))
        self.timer_profiles = Gtk.Entry(text=", ".join(cfg.get("timer_profiles") or []),
                                        placeholder_text="Empty means the current profile")
        self.sns = Gtk.Entry(text=cfg.get("sns_topic", ""),
                             placeholder_text="arn:aws:sns:us-east-1:111111111111:lab-alerts")
        rows = [("Keep tag", self.keep_tag, "Resources with this tag key are always kept."),
                ("Regions", self.regions, "Comma separated."),
                ("Notify above ($/month)", self.threshold, "For the daily check."),
                ("Daily check profiles", self.timer_profiles, "Comma separated."),
                ("SNS topic for daily check", self.sns, "Optional. Also sends the list there.")]
        for n, (name, widget, tip) in enumerate(rows):
            grid.attach(label(name), 0, n, 1, 1)
            widget.set_hexpand(True)
            widget.set_tooltip_text(tip)
            grid.attach(widget, 1, n, 1, 1)
        outer.append(grid)

        outer.append(label("Daily check", "heading"))
        outer.append(label("A systemd user timer runs the sweep every day and sends a desktop "
                           "notification if anything is still costing money.", "dim-label",
                           wrap=True))
        row = hbox(6)
        self.at = Gtk.Entry(text="21:00", width_chars=6)
        row.append(label("Time"))
        row.append(self.at)
        row.append(button("Turn on", self.timer_on))
        row.append(button("Turn off", self.timer_off))
        self.timer_msg = label("", "dim-label", wrap=True)
        outer.append(row)
        outer.append(self.timer_msg)

        bottom = hbox(8)
        bottom.append(spacer())
        bottom.append(button("Cancel", self.close))
        bottom.append(button("Save", self.save, css="suggested-action"))
        outer.append(bottom)
        self.set_child(outer)

    def save(self):
        cfg = load_config()
        buf = self.keep.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        cfg["keep"] = [x.strip() for x in text.splitlines() if x.strip()]
        cfg["keep_tag"] = self.keep_tag.get_text().strip()
        cfg["regions"] = [r.strip() for r in self.regions.get_text().replace(" ", ",").split(",")
                          if r.strip()]
        cfg["notify_threshold"] = float(self.threshold.get_value())
        cfg["timer_profiles"] = [p.strip() for p in self.timer_profiles.get_text().split(",")
                                 if p.strip()]
        cfg["sns_topic"] = self.sns.get_text().strip()
        if not save_config(cfg):
            show_message(self, "Couldn't save settings")
            return
        if self.on_saved:
            self.on_saved()
        self.close()

    def timer_on(self):
        import contextlib
        import io

        from .cli import install_timer
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = install_timer(self.at.get_text().strip(), SimpleNamespace(profile=None))
        self.timer_msg.set_text(buf.getvalue().strip() or ("Done." if rc == 0 else "Failed."))

    def timer_off(self):
        import contextlib
        import io

        from .cli import remove_timer
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            remove_timer()
        self.timer_msg.set_text(buf.getvalue().strip())
