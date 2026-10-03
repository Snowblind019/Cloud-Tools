"""CloudTrail page for the AWS Kit window."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gi.repository import Gtk

from . import profiles, trail
from .common import AwsContext, error_text
from .widgets import (CheckListButton, DetailPane, Page, ResultTable, all_regions, button,
                      label, on_main, run_bg, show_message, spacer, string_dropdown)


class TrailPage(Page):
    name = "trail"
    title = "CloudTrail"

    COLS = [
        ("time", "Time", {"width": 150}),
        ("who", "Who", {"width": 200}),
        ("action", "Action", {"width": 230}),
        ("resources", "Resource", {"width": 220}),
        ("result", "Result", {"width": 150, "kind": "result"}),
        ("ip", "Source IP", {"width": 130}),
        ("region", "Region", {"expand": True}),
    ]
    WINDOWS = [("Last 15 minutes", 15), ("Last hour", 60), ("Last 6 hours", 360),
               ("Last 24 hours", 1440), ("Last 7 days", 10080), ("Last 30 days", 43200),
               ("Last 90 days", 129600)]

    def __init__(self, win):
        super().__init__(win, "Who did what, from CloudTrail event history. It's free, needs no "
                         "trail, and covers the last 90 days of management events. Handy for "
                         "chasing down AccessDenied errors in your own builds.")
        self.events = []
        row1 = self.toolbar()
        self.attr_keys = [None] + list(trail.LOOKUP_KEYS)
        self.attr = string_dropdown(["Anything"] + [v[1] for v in trail.LOOKUP_KEYS.values()])
        self.attr.connect("notify::selected", lambda *_: self.attr_changed())
        row1.append(self.attr)
        self.value = Gtk.Entry(placeholder_text="Pick a filter on the left, then type here")
        self.value.set_hexpand(True)
        self.value.set_sensitive(False)
        self.value.connect("activate", lambda *_: self.search())
        row1.append(self.value)
        row1.append(button("My actions", self.mine,
                           tooltip="Search for the session name of the current profile"))
        self.append(row1)

        row2 = self.toolbar()
        self.window = string_dropdown([w[0] for w in self.WINDOWS], 1)
        row2.append(self.window)
        self.regions = CheckListButton("Regions")
        row2.append(self.regions)
        self.errors = Gtk.CheckButton(label="Errors only")
        self.errors.set_tooltip_text("Only failed calls, like AccessDenied")
        row2.append(self.errors)
        self.writes = Gtk.CheckButton(label="Hide reads")
        self.writes.set_tooltip_text("Hide Describe, List and Get calls")
        row2.append(self.writes)
        self.search_btn = button("Search", self.search, css="suggested-action")
        row2.append(self.search_btn)
        row2.append(spacer())
        hint = label(trail.GLOBAL_HINT, "dim-label", wrap=True)
        hint.set_max_width_chars(60)
        row2.append(hint)
        self.append(row2)
        self.fill_regions()

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        self.table = ResultTable(self.COLS, on_select=self.selected,
                                 placeholder="Pick a time window and press Search.")
        paned.set_start_child(self.table)
        self.detail = DetailPane("Select an event to see the full record.")
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(False)
        paned.set_position(400)
        self.append(paned)
        self.append(self.status)

    def fill_regions(self):
        region = "us-east-1"
        info = next((p for p in profiles.list_profiles() if p["name"] == self.win.profile), None)
        if info and info.get("region"):
            region = info["region"]
        self.regions.set_options([(r, r) for r in all_regions()], sorted({region, "us-east-1"}))

    def profile_changed(self, profile):
        self.fill_regions()

    def attr_changed(self):
        key = self.attr_keys[self.attr.get_selected()]
        self.value.set_sensitive(key is not None)
        if key:
            self.value.set_placeholder_text(trail.LOOKUP_KEYS[key][1])
            self.value.grab_focus()
        else:
            self.value.set_text("")
            self.value.set_placeholder_text("Pick a filter on the left, then type here")

    def mine(self):
        profile = self.win.profile
        self.status.busy("Checking who you are...", progress=False)

        def done(name):
            self.attr.set_selected(self.attr_keys.index("user"))
            self.value.set_text(name)
            self.status.idle("")
            self.search()
        run_bg(lambda: trail.my_session_name(AwsContext(profile)), done, self.failed)

    def search(self):
        key = self.attr_keys[self.attr.get_selected()]
        value = self.value.get_text().strip() if key else None
        if key and not value:
            self.value.grab_focus()
            return
        minutes = self.WINDOWS[self.window.get_selected()][1]
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
        regions = self.regions.selected() or ["us-east-1"]
        profile = self.win.profile
        errors, writes = self.errors.get_active(), self.writes.get_active()
        cancel = self.new_cancel()
        self.search_btn.set_sensitive(False)
        self.status.busy("Reading event history...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: trail.lookup(profile, regions, start, end, key, value, errors, writes,
                                    limit=1000, progress=progress, cancel=cancel),
               self.done, self.failed)

    def done(self, result):
        self.events, warnings = result
        self.search_btn.set_sensitive(True)
        self.table.set_rows([e.row() for e in self.events], self.events)
        if not self.events:
            self.table.clear("No events matched. Event history can lag about 5 minutes, and "
                             "global services like IAM log to us-east-1.")
        failed = sum(1 for e in self.events if e.error)
        self.status.idle(f"{len(self.events)} event(s), {failed} failed.")
        if warnings:
            self.detail.set_text("Notes:\n\n" + "\n".join(warnings))

    def failed(self, exc):
        self.search_btn.set_sensitive(True)
        self.status.idle("")
        show_message(self.win, "Lookup failed", error_text(exc, self.win.profile))

    def selected(self, row):
        if row is None:
            return
        why = trail.explain_denied(row.obj)
        self.detail.set_text((why + "\n\n" if why else "") + row.obj.detail_text())
