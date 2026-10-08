"""Least Privilege page for the AWS Kit window."""
from __future__ import annotations

from pathlib import Path

from gi.repository import Gdk, Gio, GLib, Gtk

from . import appearance, leastpriv, profiles
from .common import AuthError, AwsContext, error_text, write_atomic
from .widgets import (CheckListButton, Page, ResultTable, all_regions, button, clear_box,
                      flash, hbox, label, margins, on_main, open_file, run_bg, set_clipboard,
                      sev_badge, show_message, spacer, string_dropdown, vbox)

CSS = b"""
.lp-summary { padding: 8px 12px; margin: 0 10px 8px 10px; border-radius: 8px;
              background: alpha(currentColor, 0.06); }
.lp-note { padding: 6px 12px; }
.lp-needed { color: #3584e4; }
.lp-lastaccessed { color: #a347ba; }
"""
_css_done = False


def _install_css():
    global _css_done
    if _css_done:
        return
    provider = Gtk.CssProvider()
    try:
        provider.load_from_data(CSS)
    except TypeError:  # some PyGObject versions want the length too
        provider.load_from_data(CSS, len(CSS))
    display = Gdk.Display.get_default()
    if display is not None:
        Gtk.StyleContext.add_provider_for_display(display, provider,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)
    _css_done = True


class UsageTable(ResultTable):
    """ResultTable with one more cell kind, "lp", for the Calls column: a plain count, a red
    "2 denied", a blue "needed" for permissions a call needs on top of its own, and a purple
    "last accessed" for actions that only IAM last accessed data knows about."""

    def _bind_cell(self, factory, list_item, key, kind):
        super()._bind_cell(factory, list_item, key, "text" if kind == "lp" else kind)
        lab = list_item.get_child()
        for c in ("lp-needed", "lp-lastaccessed"):
            lab.remove_css_class(c)
        if kind != "lp":
            return
        text = lab.get_text()
        if text.endswith("denied"):
            lab.add_css_class("bad-text")
        elif text == "needed":
            lab.add_css_class("lp-needed")
        elif text == "last accessed":
            lab.add_css_class("lp-lastaccessed")


class LeastPrivPage(Page):
    name = "leastpriv"
    title = "Least Privilege"

    COLS = [
        ("service", "Service", {"width": 100}),
        ("action", "Action", {"width": 170}),
        ("resource", "Resource", {"expand": True, "kind": "mono"}),
        ("calls_text", "Calls", {"width": 100, "kind": "lp", "sort_key": "calls_sort"}),
        ("last_date", "Last used", {"width": 98, "sort_key": "last_sort"}),
    ]
    MODE_HINTS = (
        ("Quick: finds the role's sessions from its AssumeRole events, then reads what each "
         "session did."),
        ("Thorough: reads every event in the window and keeps the role's. Event history gives "
         "about 100 events a second per region, so a busy 90 days can take a while."),
    )

    def __init__(self, win):
        super().__init__(win, "Drafts the smallest IAM policy that covers what a role or user "
                         "actually did, from CloudTrail. Then checks the draft and compares it "
                         "with what the role has now. Read-only.")
        _install_css()
        self.result = None
        self.files = []
        self.roles = {}          # profile -> list of roles
        self._roles_loading = None
        self._split_set = {}      # paned -> the position this page last gave it
        self._highlighted = None  # Sid of the highlighted statement

        # ---- row 1: who, when, where, how
        row1 = self.toolbar()
        self.who = Gtk.Entry(placeholder_text="Role or IAM user name, or its ARN")
        self.who.set_hexpand(True)
        self.who.connect("activate", lambda *_: self.build())
        row1.append(self.who)
        row1.append(self._role_picker())
        self.window = string_dropdown([w[0] for w in leastpriv.WINDOWS], 2)
        self.window.set_tooltip_text("How far back to read Event history. It keeps 90 days.")
        row1.append(self.window)
        self.regions = CheckListButton("Regions")
        self.regions.set_tooltip_text("IAM calls, and STS calls through the global endpoint, "
                                      "are recorded in us-east-1, so keep it ticked.")
        row1.append(self.regions)
        self.mode = string_dropdown(["Quick", "Thorough"])
        self.mode.connect("notify::selected", lambda *_: self.update_hint())
        row1.append(self.mode)
        self.build_btn = button("Build policy", self.build, css="suggested-action")
        row1.append(self.build_btn)
        row1.append(self._files_button())
        self.append(row1)

        # ---- row 2: what goes into the draft
        row2 = self.toolbar()
        row2.set_margin_top(0)
        self.specific = Gtk.CheckButton(label="Specific resources", active=True)
        self.specific.set_tooltip_text("Name the buckets, tables, functions and keys it used. "
                                       "Off gives Resource \"*\" everywhere.")
        self.denied_cb = Gtk.CheckButton(label="Add denied calls")
        self.denied_cb.set_tooltip_text("Calls it tried and wasn't allowed to make. They're "
                                        "left out unless you tick this.")
        self.la_cb = Gtk.CheckButton(label="Add actions from IAM last accessed", active=True)
        self.la_cb.set_tooltip_text("Actions IAM says it used that Event history doesn't show. "
                                    "They get Resource \"*\", since IAM doesn't say on what.")
        for cb in (self.specific, self.denied_cb, self.la_cb):
            cb.connect("toggled", lambda *_: self.options_changed())
            row2.append(cb)
        row2.append(spacer())
        self.hint = label("", "dim-label", wrap=True)
        self.hint.set_max_width_chars(70)
        self.hint.set_xalign(1.0)
        self.hint.set_justify(Gtk.Justification.RIGHT)
        row2.append(self.hint)
        self.clear_files_btn = button("Use Event history", self.clear_files,
                                      tooltip="Forget the files and read Event history again")
        self.clear_files_btn.set_visible(False)
        row2.append(self.clear_files_btn)
        self.append(row2)

        # ---- the story in two lines
        self.summary_box = vbox(2, "lp-summary")
        self.headline = label("Pick a role or user and press Build policy.", "headline",
                              wrap=True)
        self.subline = label("It reads CloudTrail Event history, which is free and keeps 90 "
                             "days, or CloudTrail files you open.", "dim-label", wrap=True)
        self.summary_box.append(self.headline)
        self.summary_box.append(self.subline)
        self.append(self.summary_box)

        # ---- table and draft side by side, notes below
        self.table = UsageTable(self.COLS, on_select=self.selected,
                                placeholder="Type a role or user, or pick one with the arrow, "
                                "and press Build policy.\nOr open CloudTrail files.")
        right = vbox(0)
        bar = hbox(6)
        margins(bar, 6)
        bar.set_margin_start(10)
        bar.set_margin_end(10)
        bar.append(label("Draft policy", "heading"))
        bar.append(spacer())
        self.copy_btn = button("Copy", self.copy)
        self.save_btn = button("Save", self.save)
        self.check_btn = button("Check in Policy Check", self.to_policy_check,
                                tooltip="Open the draft in Policy Check, where you can edit it "
                                "and ask Access Analyzer too")
        for b in (self.copy_btn, self.save_btn, self.check_btn):
            b.set_sensitive(False)
            bar.append(b)
        right.append(bar)
        self.view = Gtk.TextView(editable=False, monospace=True)
        self.view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        for side in ("left", "right", "top", "bottom"):
            getattr(self.view, f"set_{side}_margin")(10)
        self.buffer = self.view.get_buffer()
        self.hl_tag = self.buffer.create_tag("hl")
        self.hl_tag.set_property("weight", 700)
        self._color_highlight()
        appearance.on_change(lambda _variant: self._color_highlight())
        self.buffer.set_text("The draft policy shows up here.")
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(self.view)
        scroller.set_vexpand(True)
        right.append(scroller)

        self.hpaned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.hpaned.set_start_child(self.table)
        self.hpaned.set_end_child(right)
        self.hpaned.set_resize_start_child(True)
        self.hpaned.set_shrink_start_child(False)
        self.hpaned.set_shrink_end_child(False)
        self.table.set_size_request(420, -1)
        right.set_size_request(340, -1)
        self.hpaned.connect("notify::max-position", self._first_split)

        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self._build_tabs()

        self.vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        self.vpaned.set_vexpand(True)
        self.vpaned.set_start_child(self.hpaned)
        self.vpaned.set_end_child(self.notebook)
        self.vpaned.set_resize_end_child(False)
        self.vpaned.set_shrink_end_child(False)
        self.notebook.set_size_request(-1, 120)
        self.vpaned.connect("notify::max-position", self._first_split)
        self.append(self.vpaned)
        self.append(self.status)
        self.fill_regions()
        self.update_hint()

    def _color_highlight(self):
        """The highlighted statement in the draft, in the accent color."""
        accent = appearance.current_accent()
        band, ink = Gdk.RGBA(), Gdk.RGBA()
        ink.parse(accent)
        band.parse(accent)
        band.alpha = 0.18
        self.hl_tag.set_property("paragraph-background-rgba", band)
        self.hl_tag.set_property("foreground-rgba", ink)

    # ------------------------------------------------------------------ building the UI
    def _role_picker(self):
        self.pick = Gtk.MenuButton()
        self.pick.set_tooltip_text("Pick one of the account's roles")
        pop = Gtk.Popover()
        box = vbox(6)
        margins(box, 8)
        self.role_search = Gtk.SearchEntry(placeholder_text="Filter roles")
        self.role_search.connect("search-changed", lambda *_: self.role_list.invalidate_filter())
        box.append(self.role_search)
        self.role_status = label("", "dim-label", wrap=True)
        box.append(self.role_status)
        self.role_list = Gtk.ListBox()
        self.role_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.role_list.set_filter_func(self._role_filter)
        self.role_list.connect("row-activated", self._role_chosen)
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sc.set_min_content_width(340)
        sc.set_min_content_height(80)
        sc.set_max_content_height(380)
        sc.set_propagate_natural_height(True)
        sc.set_child(self.role_list)
        box.append(sc)
        pop.set_child(box)
        pop.connect("show", lambda *_: self.load_roles())
        self.pick.set_popover(pop)
        return self.pick

    def _files_button(self):
        menu = Gtk.MenuButton(label="Open files")
        menu.set_tooltip_text("Read CloudTrail files instead: aws cloudtrail lookup-events "
                              "output, trail log files, or .json.gz files from S3")
        pop = Gtk.Popover()
        box = vbox(4)
        margins(box, 6)
        for text, fn in (("Pick files...", self.pick_files),
                         ("Pick a folder...", self.pick_folder)):
            b = Gtk.Button(label=text)
            b.add_css_class("flat")
            b.connect("clicked", lambda _b, f=fn: (pop.popdown(), f()))
            box.append(b)
        pop.set_child(box)
        menu.set_popover(pop)
        return menu

    def _table_tab(self, cols, placeholder):
        t = ResultTable(cols, placeholder=placeholder, search=False)
        t.set_margin_top(4)
        return t

    def _build_tabs(self):
        self.notes_box = vbox(0)
        sc = Gtk.ScrolledWindow()
        sc.set_child(self.notes_box)
        self.notes_label = Gtk.Label(label="Notes")
        self.notebook.append_page(sc, self.notes_label)

        self.findings_box = Gtk.ListBox()
        self.findings_box.set_selection_mode(Gtk.SelectionMode.NONE)
        sc = Gtk.ScrolledWindow()
        sc.set_child(self.findings_box)
        self.findings_label = Gtk.Label(label="Policy Check")
        self.notebook.append_page(sc, self.findings_label)

        self.unused_table = self._table_tab(
            [("namespace", "Service", {"width": 160}), ("service", "Name", {"expand": True}),
             ("last", "Last used", {"width": 160, "sort_key": "last_sort"}),
             ("region", "Region", {"width": 120})],
            "IAM last accessed data shows up here after a build.")
        self.unused_label = Gtk.Label(label="Unused services")
        self.notebook.append_page(self.unused_table, self.unused_label)

        self.denied_table = self._table_tab(
            [("full", "Action", {"width": 220}), ("resource", "Resource", {"width": 240,
                                                                          "kind": "mono"}),
             ("calls", "Calls", {"width": 60}), ("last", "Last tried", {"width": 170,
                                                                        "sort_key": "last_sort"}),
             ("why", "Why", {"expand": True})],
            "No denied calls.")
        self.denied_label = Gtk.Label(label="Denied calls")
        self.notebook.append_page(self.denied_table, self.denied_label)

        self.unmapped_table = self._table_tab(
            [("source", "Event source", {"width": 220}), ("event", "Event", {"width": 200}),
             ("calls", "Calls", {"width": 60}), ("why", "Why", {"expand": True})],
            "Every call was mapped to an IAM action.")
        self.unmapped_label = Gtk.Label(label="Couldn't map")
        self.notebook.append_page(self.unmapped_table, self.unmapped_label)
        self._fill_notes([])

    def _first_split(self, paned, *_):
        """Size the panes from the space they get: the table about 57% of the width, the
        notes about 30% of the height. Once you drag a handle, it stays where you put it."""
        top = paned.get_property("max-position")
        if top < 200:
            return
        last = self._split_set.get(paned)
        if last is not None and abs(paned.get_position() - last) > 2:
            return
        if paned is self.hpaned:
            pos = int((paned.get_width() or top) * 0.57)
        else:
            total = paned.get_height() or top
            pos = total - min(240, max(150, int(total * 0.30)))
        pos = max(paned.get_property("min-position"), min(pos, top))
        self._split_set[paned] = pos
        paned.set_position(pos)

    # ------------------------------------------------------------------ profile and regions
    def fill_regions(self):
        region = "us-east-1"
        info = next((p for p in profiles.list_profiles() if p["name"] == self.win.profile), None)
        if info and info.get("region"):
            region = info["region"]
        self.regions.set_options([(r, r) for r in all_regions()],
                                 leastpriv.default_regions(region))

    def profile_changed(self, profile):
        self.fill_regions()
        self.role_list.remove_all()
        self.role_status.set_text("")

    def profiles_changed(self):
        self.fill_regions()

    def update_hint(self):
        if self.files:
            n = len(self.files)
            shown = Path(self.files[0]).name + (f" and {n - 1} more" if n > 1 else "")
            self.hint.set_text(f"Reading {shown} instead of Event history. The time window "
                               "and regions don't apply.")
        else:
            self.hint.set_text(self.MODE_HINTS[self.mode.get_selected()])
        self.clear_files_btn.set_visible(bool(self.files))
        for w in (self.regions, self.mode):
            w.set_sensitive(not self.files)

    # ------------------------------------------------------------------ roles
    def load_roles(self):
        profile = self.win.profile
        if profile in self.roles:
            self._fill_roles(self.roles[profile])
            return
        if self._roles_loading == profile:
            return
        self._roles_loading = profile
        self.role_status.set_text("Loading roles...")

        def done(roles):
            self._roles_loading = None
            self.roles[profile] = roles
            if profile == self.win.profile:
                self._fill_roles(roles)

        def failed(exc):
            self._roles_loading = None
            self.role_status.set_text("Couldn't list roles: " + (
                str(exc) if isinstance(exc, AuthError) else error_text(exc, profile)))
        run_bg(lambda: leastpriv.list_roles(AwsContext(profile)), done, failed)

    def _fill_roles(self, roles):
        self.role_list.remove_all()
        for r in roles:
            row = Gtk.ListBoxRow()
            box = vbox(0)
            margins(box, 4)
            box.append(label(r["name"]))
            if r["path"] not in ("/", ""):
                box.append(label(r["path"], "dim-label caption"))
            row.set_child(box)
            row.role = r
            self.role_list.append(row)
        self.role_status.set_text(f"{len(roles)} role(s). Service-linked roles aren't listed."
                                  if roles else "No roles in this account.")

    def _role_filter(self, row):
        q = self.role_search.get_text().strip().lower()
        return not q or q in getattr(row, "role", {}).get("name", "").lower()

    def _role_chosen(self, listbox, row):
        role = getattr(row, "role", None)
        if role:
            self.who.set_text(role["name"])
            self.pick.popdown()
            self.who.grab_focus()
            self.who.set_position(-1)

    # ------------------------------------------------------------------ files
    def pick_files(self):
        dialog = Gtk.FileDialog(title="Open CloudTrail files")
        flt = Gtk.FileFilter()
        flt.set_name("CloudTrail JSON (.json, .json.gz)")
        for pattern in ("*.json", "*.json.gz", "*.gz"):
            flt.add_pattern(pattern)
        anything = Gtk.FileFilter()
        anything.set_name("All files")
        anything.add_pattern("*")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(flt)
        filters.append(anything)
        dialog.set_filters(filters)

        def done(dlg, res):
            try:
                files = dlg.open_multiple_finish(res)
            except GLib.Error:
                return
            paths = [files.get_item(i).get_path() for i in range(files.get_n_items())]
            self.use_files([p for p in paths if p])
        dialog.open_multiple(self.win, None, done)

    def pick_folder(self):
        open_file(self.win, lambda path: self.use_files([path]), "Open a folder of CloudTrail "
                  "files", folder=True)

    def use_files(self, paths):
        if not paths:
            return
        self.files = list(paths)
        self.update_hint()
        self.build()

    def clear_files(self):
        self.files = []
        self.update_hint()

    # ------------------------------------------------------------------ running
    def options(self):
        return leastpriv.Options(specific=self.specific.get_active(),
                                 include_denied=self.denied_cb.get_active(),
                                 include_last_accessed=self.la_cb.get_active())

    def build(self):
        who = self.who.get_text().strip()
        if not who and not self.files:
            self.who.grab_focus()
            self.status.idle("Type a role or user name first, or pick one with the arrow.")
            return
        days = leastpriv.WINDOWS[self.window.get_selected()][1]
        regions = self.regions.selected() or leastpriv.default_regions(None)
        thorough = self.mode.get_selected() == 1
        files = list(self.files) or None
        compare = True if not files else bool(who)
        profile = self.win.profile
        options = self.options()
        cancel = self.new_cancel()
        self.build_btn.set_sensitive(False)
        if files:
            text = "Reading files..."
        elif thorough:
            text = "Reading every event in the window. This can take a while..."
        else:
            text = "Finding the role's sessions..."
        self.status.busy(text, cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: leastpriv.run(profile, who, days, regions, thorough, files, compare,
                                     options=options, progress=progress, cancel=cancel),
               self.done, self.failed)

    def done(self, result):
        self.build_btn.set_sensitive(True)
        self.show_result(result)
        self.status.idle(result.status_text())

    def failed(self, exc):
        self.build_btn.set_sensitive(True)
        self.status.idle("")
        if isinstance(exc, (leastpriv.LeastPrivError, AuthError)):
            msg = str(exc)
        else:
            msg = error_text(exc, self.win.profile)
        show_message(self.win, "Couldn't draft a policy", msg)

    def options_changed(self):
        if self.result is not None:
            self.show_result(self.result.rebuild(self.options()))

    # ------------------------------------------------------------------ showing
    def show_result(self, result):
        """Fill the page from a leastpriv.Result. Also used for the screenshot."""
        self.result = result
        rows = result.rows()
        self.table.set_rows(rows, rows)
        if not rows:
            self.table.clear("No calls found for this role or user. See the notes below.")
        self._highlighted = None
        if result.text:
            self.buffer.set_text(result.text)
        else:
            self.buffer.set_text("No calls to build a policy from.")
        for b in (self.copy_btn, self.save_btn, self.check_btn):
            b.set_sensitive(bool(result.text))
        lines = result.summary()
        self.headline.set_text(lines[0])
        self.subline.set_text("  ".join(lines[1:]))
        self._fill_findings(result.findings)
        unused = result.unused_rows()
        self.unused_table.set_rows(unused)
        if not unused:
            self.unused_table.clear("Nothing unused." if result.current and
                                    result.current.services is not None else
                                    "No IAM last accessed data. It's read when comparing with "
                                    "AWS, see the notes.")
        never = len(result.never_used())
        self.unused_label.set_text(f"Unused services ({never})" if never else "Unused services")
        denied = result.denied_rows()
        for r in denied:
            r["why"] = (r["message"] or "").replace("\n", ". ") or r["source"]
            r["_dim"] = False
        self.denied_table.set_rows(denied)
        if not denied:
            self.denied_table.clear("No denied calls.")
        self.denied_label.set_text(f"Denied calls ({len(denied)})" if denied else "Denied calls")
        unmapped = result.unmapped_rows()
        self.unmapped_table.set_rows(unmapped)
        if not unmapped:
            self.unmapped_table.clear("Every call was mapped to an IAM action.")
        self.unmapped_label.set_text(f"Couldn't map ({len(unmapped)})" if unmapped
                                     else "Couldn't map")
        notes = result.notes()
        self.notes_label.set_text(f"Notes ({len(notes)})" if notes else "Notes")
        self._fill_notes(notes)

    def _fill_notes(self, notes):
        clear_box(self.notes_box)
        if not notes:
            self.notes_box.append(margins(label(
                "After a build, the notes say what was read, what couldn't be, and what the "
                "draft can't see, like data events.", "dim-label", wrap=True), 12))
            return
        for n in notes:
            self.notes_box.append(label(n, "lp-note", wrap=True, selectable=True))

    def _fill_findings(self, findings):
        clear_box(self.findings_box)
        if self.result is None or self.result.doc is None:
            self.findings_label.set_text("Policy Check")
            return
        if not findings:
            self.findings_box.append(margins(label("Policy Check found no problems in the "
                                                   "draft.", "ok-text"), 12))
            self.findings_label.set_text("Policy Check")
            return
        worst = findings[0].severity
        self.findings_label.set_text(f"Policy Check ({len(findings)}, {worst})")
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
            if f.detail:
                box.append(label(f.detail, wrap=True, selectable=True))
            if f.fix:
                box.append(label("Fix: " + f.fix, "dim-label", wrap=True, selectable=True))
            self.findings_box.append(box)

    def selected(self, item):
        """Say where the picked action came from, and highlight its statement."""
        if item is None or self.result is None:
            return
        row = item.data
        self.status.idle(self.row_text(row))
        self.highlight(self._statement_of(row))

    def _statement_of(self, row):
        if not row.get("in_draft") or not self.result.text:
            return None
        group = row["origin"]
        if group == "implied":
            group = "implied" if row["full"] == "iam:PassRole" else "events"
        return next((s["sid"] for s in self.result.statements
                     if row["full"] in s["actions"] and s["origin"] == group), None)

    def highlight(self, sid):
        """Show the policy with one statement highlighted. The text goes back in with the
        highlight on each line separately: GTK sometimes skips a tag on lines that have no
        start or end of it inside them, so every line gets its own."""
        text = self.result.text if self.result else ""
        if not text:
            return
        at = text.find(f'"Sid": "{sid}"') if sid else -1
        buf = self.buffer
        if at < 0:
            if buf.get_char_count() and self._highlighted:
                buf.set_text(text)
            self._highlighted = None
            return
        start = text.rfind("\n    {", 0, at) + 1
        end = text.find("\n    }", at)
        end = len(text) if end < 0 else text.find("\n", end + 1)
        end = len(text) if end < 0 else end + 1
        buf.set_text("")
        buf.insert(buf.get_end_iter(), text[:start])
        for line in text[start:end].splitlines(True):
            body = line.rstrip("\n")
            buf.insert_with_tags(buf.get_end_iter(), body, self.hl_tag)
            if len(body) < len(line):
                buf.insert(buf.get_end_iter(), "\n")
        buf.insert(buf.get_end_iter(), text[end:])
        self._highlighted = sid
        mark = buf.get_mark("lp-statement")
        if mark is None:
            mark = buf.create_mark("lp-statement", buf.get_iter_at_offset(start), True)
        else:
            buf.move_mark(mark, buf.get_iter_at_offset(start))
        self.view.scroll_to_mark(mark, 0.05, True, 0.0, 0.1)

        def again():
            # Right after new text, GTK only has guessed line heights. Scroll once more when
            # the lines have been laid out.
            if buf.get_mark("lp-statement") is mark and self._highlighted == sid:
                self.view.scroll_to_mark(mark, 0.05, True, 0.0, 0.1)
            return False
        GLib.timeout_add(120, again)

    def row_text(self, row) -> str:
        res = ", ".join(row["resources"][:2]) + (" and more" if len(row["resources"]) > 2
                                                  else "")
        origin = row["origin"]
        if origin == "denied":
            why = (row.get("message") or "").splitlines()[0] if row.get("message") else ""
            tail = "" if row["in_draft"] else " Tick Add denied calls to put it in the draft."
            return f"{row['full']} was denied {row['calls']} time(s). {why}{tail}".strip()
        if origin == "implied":
            return f"{row['full']} on {res}: {row['source'].lower()}, which needs it too."
        if origin == "last-accessed":
            tail = "" if row["in_draft"] else (" Tick Add actions from IAM last accessed to put "
                                              "it in the draft.")
            return (f"{row['full']}: IAM last accessed data says it was used on {row['last']}, "
                    f"but not on what.{tail}")
        return f"{row['full']} on {res}: {row['calls']} call(s), last on {row['last']}."

    # ------------------------------------------------------------------ actions
    def copy(self):
        if self.result and self.result.text:
            set_clipboard(self, self.result.text)
            flash(self.copy_btn, "Copied")

    def save(self):
        if not (self.result and self.result.text):
            return
        text = self.result.text
        name = f"{self.result.principal.name}-least-privilege.json"
        dialog = Gtk.FileDialog(title="Save the draft policy", initial_name=name)

        def done(dlg, res):
            try:
                gfile = dlg.save_finish(res)
            except GLib.Error:
                return
            path = gfile.get_path()
            try:
                write_atomic(path, text)
                self.status.idle(f"Saved {path}")
            except OSError as exc:
                show_message(self.win, "Couldn't save", exc.strerror or str(exc))
        dialog.save(self.win, None, done)

    def to_policy_check(self):
        if not (self.result and self.result.text):
            return
        page = self.win.pages.get("policy")
        if page is None:
            return
        page.set_text(self.result.text)
        self.win.show_page("policy")


__all__ = ["LeastPrivPage"]
