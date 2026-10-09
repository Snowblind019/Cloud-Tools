"""Lab Sweep page for the AWS Kit window."""
from __future__ import annotations

import sys
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
        # What teardown did to each item since the scan, by id(item): deleted or failed.
        # Redrawing the table (Keep ticked, Settings) keeps it, so a deleted row can't come
        # back as one that can be ticked and deleted again.
        self.outcomes = {}
        # "scan", "teardown" or "spend" while one runs. Only one at a time, so a scan can't
        # take over the status bar's Stop button from a teardown, or start a second one.
        self.job = None

        bar = self.toolbar()
        account_pickers(self)
        bar.append(self.accounts)
        bar.append(self.regions)
        self.scan_btn = button("Scan", self.scan, css="suggested-action")
        bar.append(self.scan_btn)
        self.spend_btn = button("Month-to-date spend", self.spend,
                                tooltip="Asks Cost Explorer what you've actually spent this month. "
                                        "Each request costs $0.01.")
        bar.append(self.spend_btn)
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
        actions.append(button("Tick everything deletable", self.tick_all_deletable,
                              tooltip="Ticks the deletable rows the filter is showing"))
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

    def set_job(self, job):
        """Scan, spend and Delete stay off while any of them runs."""
        self.job = job
        self.scan_btn.set_sensitive(job is None)
        self.spend_btn.set_sensitive(job is None)
        self.update_selection()

    def scan(self):
        if self.job:
            return
        profiles = chosen_profiles(self)
        regions = self.regions.selected() or None
        cancel = self.new_cancel()
        self.set_job("scan")
        self.status.busy("Starting scan...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: sweep.scan(profiles, regions, progress=progress, cancel=cancel),
               self.scan_done, self.failed)

    def scan_done(self, result):
        self.items, self.warnings = result
        self.outcomes = {}
        self.set_job(None)
        self.show_items()
        stopped = " (stopped early)" if self.cancel.is_set() else ""
        self.status.idle(f"Scan finished{stopped} at {datetime.now():%H:%M}.")
        # The last scan's notes, or nothing: old ones would say a check failed when it didn't
        self.detail.set_text("Notes from the scan:\n\n" + "\n".join(self.warnings)
                             if self.warnings else "")

    def item_row(self, it) -> dict:
        r = it.row()
        done = self.outcomes.get(id(it))
        if done and not it.kept:
            r["action"] = done
        r["_dim"] = it.kept or not it.can_delete or done == "deleted"
        return r

    def show_items(self):
        rows = []
        for it in self.items:
            r = self.item_row(it)
            r["age_days"] = age_days(it.created)
            rows.append(r)
        self.table.set_rows(rows, self.items,
                            [it.can_delete and not it.kept and
                             self.outcomes.get(id(it)) != "deleted" for it in self.items])
        # Notes are checks that couldn't run (sign-in expired, no permission, no connection),
        # so with nothing else found the scan mustn't look clean
        if not self.items:
            self.table.clear("Nothing found, but some checks couldn't run. See the notes "
                             "below." if self.warnings else
                             "Nothing found that costs money. Nice and clean.")
        if self.warnings and all(it.kept for it in self.items):
            self.summary.set_text("Nothing found, but some checks couldn't run.")
        else:
            self.summary.set_text(sweep.summary_line(self.items))
        self.update_selection()

    def keep_rules_changed(self):
        """The keep list or keep tag may have changed in Settings. Work out which rows are
        kept again, so a newly kept item can't be ticked any more."""
        if not self.items:
            return
        sweep.apply_keep(self.items)
        self.show_items()

    def failed(self, exc):
        self.set_job(None)
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

    def tick_all_deletable(self):
        """Tick the deletable rows the filter is showing. Hidden rows are left alone."""
        for r in self.table.visible_items():
            if r.checkable and r.obj.can_delete and not r.obj.kept:
                r.checked = True
        self.update_selection()

    def ticked_rows(self):
        """The ticked items, and the ids of the ones the filter is hiding."""
        shown = {id(r.obj) for r in self.table.visible_items()}
        ticked = [r.obj for r in self.table.checked()]
        return ticked, {id(it) for it in ticked if id(it) not in shown}

    def update_selection(self):
        ticked, hidden = self.ticked_rows()
        self.delete_btn.set_sensitive(bool(ticked) and self.job is None)
        if ticked:
            self.sel_label.set_text(f"{len(ticked)} ticked, about "
                                    f"{money(sweep.total_monthly(ticked))}/month"
                                    + (f", {len(hidden)} hidden by the filter" if hidden else ""))
        else:
            self.sel_label.set_text("")

    # ---------------------------------------------------------------- teardown
    def plan_lines(self, ticked, hidden=()):
        order = sorted(ticked, key=lambda i: (sweep.KINDS[i.kind].order, i.region, i.id))
        return [f"{i.profile or 'default':<14} {i.region:<15} {i.kind_label:<28} {i.id}"
                + (f"  {i.name}" if i.name else "")
                + ("  (hidden by the filter)" if id(i) in hidden else "") for i in order]

    def dry_run(self):
        ticked, hidden = self.ticked_rows()
        if not ticked:
            self.detail.set_text("Tick some rows first.")
            return
        self.detail.set_text("Teardown would go in this order:\n\n" +
                             "\n".join(self.plan_lines(ticked, hidden)) +
                             "\n\nNAT gateways go before their Elastic IPs, AMIs before their "
                             "snapshots, and database instances before their clusters.")

    def teardown(self):
        ticked, hidden = self.ticked_rows()
        if not ticked or self.job:
            return
        heading = (f"Delete {len(ticked)} item(s), about "
                   f"{money(sweep.total_monthly(ticked))}/month?")
        if hidden:
            heading += (f" {len(hidden)} of them are hidden by the filter on the table. "
                        "They're marked in the list below.")
        ConfirmDeleteDialog(self.win, heading, self.plan_lines(ticked, hidden),
                            lambda: self.run_teardown(ticked)).present()

    def run_teardown(self, ticked):
        if self.job:
            return
        cancel = self.new_cancel()
        self.set_job("teardown")
        self.status.busy("Deleting...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: sweep.teardown(ticked, progress=progress, cancel=cancel),
               self.teardown_done, self.teardown_failed)

    def teardown_failed(self, exc):
        self.set_job(None)
        self.status.idle("")
        show_message(self.win, "Teardown failed", error_text(exc))

    def teardown_done(self, results):
        ok = sum(1 for _, success, _ in results if success)
        log = []
        for it, success, msg in results:
            log.append(f"{'ok  ' if success else 'FAIL'} {it.kind_label:<28} {it.id}: {msg}")
        outcome = {id(it): success for it, success, _ in results}
        for it, success, _ in results:
            if not it.kept:
                self.outcomes[id(it)] = "deleted" if success else "failed"
        for row in self.table.items():
            if id(row.obj) in outcome:
                success = outcome[id(row.obj)]
                kept = row.obj.kept and not success
                row.data["action"] = "deleted" if success else "kept" if kept else "failed"
                row.data["_dim"] = success or kept
                row.checked = False
                row.checkable = not success and not kept
        self.table.refresh_rows()
        self.set_job(None)
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
        cfg["keep"] = keep
        if not save_config(cfg):
            show_message(self.win, "Couldn't save the keep list")
            return
        for it in ticked:
            it.kept = True
        self.show_items()
        msg = f"Added {len(ticked)} item(s) to the keep list."
        if self.job is None:
            self.status.idle(msg)
        else:
            # Leave the status bar alone so its Stop button still stops the running job.
            # Teardown reads the keep list before each item, so this still counts for the
            # items it hasn't reached yet.
            self.detail.set_text(msg)

    # ---------------------------------------------------------------- extras
    def spend(self):
        if self.job:
            return
        profiles = chosen_profiles(self)
        self.set_job("spend")
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
            self.set_job(None)
            self.status.idle("Spend loaded.")
        run_bg(work, done, self.failed)

    def export(self):
        if not self.items:
            show_message(self.win, "Nothing to export yet", "Run a scan first.")
            return
        rows = [{k: v for k, v in self.item_row(it).items() if not k.startswith("_")}
                for it in self.items]
        export_rows(self.win, rows, self.EXPORT_COLS, "lab-sweep.md", title="Lab sweep")

    def settings(self):
        SweepSettings(self.win, on_saved=self.keep_rules_changed).present()


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
        rows = [("Keep tag", self.keep_tag,
                 "Resources with this tag key are kept. It only works for types whose tags come "
                 "back with the scan: EC2 instances, NAT gateways, Elastic IPs, EBS volumes and "
                 "snapshots, AMIs, VPC endpoints, VPNs, transit gateway attachments, Client VPN, "
                 "Network Firewall, RDS, Secrets Manager, CloudHSM and GuardDuty. Use the keep "
                 "list for anything else."),
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
        how = ("A scheduled task" if sys.platform == "win32" else "A systemd user timer")
        outer.append(label(f"{how} runs the sweep every day and sends a desktop notification "
                           "if anything is still costing money.", "dim-label", wrap=True))
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
