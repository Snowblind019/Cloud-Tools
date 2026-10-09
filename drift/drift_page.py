"""Drift page for the AWS Kit window."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from gi.repository import Gdk, GLib, Gtk, Pango

from . import drift, tfplan
from .common import error_text, write_atomic
from .widgets import (DetailPane, Page, ResultTable, account_pickers, button, chosen_profiles,
                      clear_box, confirm_terraform, export_rows, fill_accounts, flash, hbox,
                      label, margins, on_main, open_file, run_bg, set_clipboard, show_message,
                      spacer, string_dropdown, vbox)

CSS = b"""
.drift-chip { border-radius: 999px; padding: 1px 2px 1px 10px;
              background: alpha(currentColor, 0.07); border: 1px solid alpha(currentColor, 0.14); }
.drift-chip button { min-height: 18px; min-width: 18px; padding: 1px; margin: 0;
                     border-radius: 999px; }
.drift-chip .dim-label { font-size: 0.9em; }
.drift-sub { margin-top: 1px; }
"""
_css_done = False


def _install_css():
    global _css_done
    if _css_done or Gdk.Display.get_default() is None:
        return
    provider = Gtk.CssProvider()
    try:
        provider.load_from_data(CSS)
    except TypeError:  # some PyGObject versions want the length too
        provider.load_from_data(CSS, len(CSS))
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                              Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _css_done = True


class DriftTable(ResultTable):
    """ResultTable with a Status badge that says what it is (GONE, CHANGED, NOT IN
    TERRAFORM) in the severity colors, instead of a severity word."""

    SEV_CLASSES = ("sev", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info",
                   "dimmed")

    def _bind_cell(self, factory, list_item, key, kind):
        if kind != "status":
            return super()._bind_cell(factory, list_item, key, kind)
        lab = list_item.get_child()
        data = list_item.get_item().data
        for c in self.SEV_CLASSES:
            lab.remove_css_class(c)
        lab.add_css_class("sev")
        lab.add_css_class("sev-" + data.get("_severity", "info"))
        if data.get("_dim"):
            lab.add_css_class("dimmed")
        lab.set_halign(Gtk.Align.START)
        lab.set_text(str(data.get("badge", "")).upper())
        lab.set_tooltip_text(data.get("_status"))
        return None

    def _bind_check(self, factory, list_item):
        super()._bind_check(factory, list_item)
        if not list_item.get_item().checkable:
            list_item.get_child().set_tooltip_text(
                "Only rows that aren't in Terraform can be ticked, for import blocks")


class DriftPage(Page):
    name = "drift"
    title = "Drift"

    COLS = [
        ("badge", "Status", {"width": 150, "kind": "status", "sort_key": "_rank"}),
        ("type", "Type", {"width": 205, "kind": "mono"}),
        ("id", "ID", {"width": 205, "kind": "mono"}),
        ("name", "Name", {"width": 135}),
        ("region", "Region", {"width": 95}),
        ("detail", "Detail", {"expand": True}),
    ]
    FILTERS = ["Everything", "Not in Terraform", "Gone", "Changed"]
    FILTER_STATUS = [None, "unmanaged", "gone", "changed"]
    EMPTY = ("Add a state file or a Terraform folder, then press Compare.\n"
             "Drift lists what's in the account but not in Terraform, what's in the state but "
             "gone from AWS, and settings changed outside Terraform.")

    def __init__(self, win):
        super().__init__(win, "Compares your Terraform state with what's really in the AWS "
                         "account: things made outside Terraform, things deleted outside it, and "
                         "settings changed since the last apply. Read-only.")
        _install_css()
        self.sources = []        # {"path", "kind", "stack"}
        self.inventory = None
        self.report = None
        self.exact = {}          # stack label -> drift entries, or the error text
        self.read_at = None
        self._gen = 0

        # ---- row 1: sources, accounts, Compare
        bar = self.toolbar()
        bar.append(button("State file", self.pick_file,
                          tooltip="A terraform.tfstate file, terraform show -json output, or plan "
                                  "JSON. Reading it doesn't run anything."))
        bar.append(button("Folder", self.pick_folder,
                          tooltip="A Terraform folder. Drift runs terraform show -json there to "
                                  "read its state, after asking."))
        self.chips = hbox(6)
        self.chips.set_valign(Gtk.Align.CENTER)
        chip_scroll = Gtk.ScrolledWindow()
        chip_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        chip_scroll.set_propagate_natural_height(True)
        chip_scroll.set_hexpand(True)
        chip_scroll.set_child(self.chips)
        chip_scroll.set_margin_start(4)
        chip_scroll.set_margin_end(4)
        bar.append(chip_scroll)
        account_pickers(self, all_regions_label="Same as the state")
        self.regions.set_tooltip_text("Regions to read. By default, the regions your states use.")
        bar.append(self.accounts)
        bar.append(self.regions)
        self.compare_btn = button("Compare", self.compare, css="suggested-action",
                                  tooltip="Read the account and compare it with the states")
        bar.append(self.compare_btn)
        self.append(bar)

        # ---- row 2: filters, exact check, ignore list, import blocks, export
        bar2 = self.toolbar()
        bar2.set_margin_top(0)
        self.filter_dd = string_dropdown(self.FILTERS)
        self.filter_dd.connect("notify::selected", lambda *_: self.apply_filter())
        bar2.append(self.filter_dd)
        self.only_mine = Gtk.CheckButton(label="Only what my Terraform manages")
        self.only_mine.set_active(True)
        self.only_mine.set_tooltip_text(
            "Only list things not in Terraform for the types and regions your states manage at "
            "least once. Untick to also see the rest, like console experiments in other "
            "regions.")
        self.only_mine.connect("toggled", lambda *_: self.show_report())
        bar2.append(self.only_mine)
        bar2.append(spacer())
        self.exact_btn = button("Exact check with Terraform", self.exact_check,
                                tooltip="Runs terraform plan -refresh-only in each folder and "
                                        "shows Terraform's own view of what changed. Needs the "
                                        "backend and credentials. It doesn't change the state.")
        self.exact_btn.set_sensitive(False)
        bar2.append(self.exact_btn)
        bar2.append(self._ignore_menu())
        bar2.append(self._import_menu())
        bar2.append(button("Export", self.export,
                           tooltip="Save the list as Markdown, CSV or JSON"))
        self.append(bar2)

        # ---- summary
        head = vbox(0)
        head.set_margin_start(12)
        head.set_margin_end(12)
        head.set_margin_bottom(6)
        self.headline = label("No comparison yet.", "headline", wrap=True)
        head.append(self.headline)
        self.subline = label("", "dim-label drift-sub", wrap=True)
        self.subline.set_visible(False)
        head.append(self.subline)
        self.append(head)

        # ---- table and details
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)
        self.table = DriftTable(self.COLS, checkable=True, on_select=self.selected,
                                on_check=self.checks_changed, placeholder=self.EMPTY)
        paned.set_start_child(self.table)
        self.detail = DetailPane("Select a row to see what's different and what to do.")
        self.detail.set_size_request(-1, 210)   # room for a few changes even at 800 high
        self.fix_btn = button("Copy import block", self.copy_fix)
        self.fix_btn.set_visible(False)
        self.detail.extra.append(self.fix_btn)
        paned.set_end_child(self.detail)
        paned.set_resize_end_child(False)
        paned.set_shrink_end_child(False)
        paned.set_position(400)
        self.append(paned)
        self.append(self.status)
        self.status.idle("Add a state file or a folder to start.")
        self.show_chips()

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self.dropped)
        self.add_controller(drop)

    # =============================================================== menus

    def _ignore_menu(self):
        mb = Gtk.MenuButton(label="Ignore list")
        mb.set_tooltip_text("Things to hide from the results, by ID, name, address or tag")
        pop = Gtk.Popover()
        box = vbox(8)
        margins(box, 10)
        box.append(label("Hide these from the results", "heading"))
        hint = label("One per line: an ID, ARN, name or Terraform address, or tag:KEY or "
                     "tag:KEY=VALUE. Saved in the AWS Kit settings.", "dim-label", wrap=True)
        hint.set_max_width_chars(48)
        box.append(hint)
        self.ignore_view = Gtk.TextView(monospace=True)
        for side in ("left", "right", "top", "bottom"):
            getattr(self.ignore_view, f"set_{side}_margin")(6)
        sc = Gtk.ScrolledWindow()
        sc.set_child(self.ignore_view)
        sc.set_size_request(400, 170)
        box.append(sc)
        row = hbox(6)
        row.append(button("Add selected", self.ignore_selected,
                          tooltip="Add the row selected in the table"))
        row.append(button("Add ticked", self.ignore_ticked,
                          tooltip="Add every ticked row"))
        row.append(spacer())
        self.ignore_save = button("Save", self.save_ignore, css="suggested-action")
        row.append(self.ignore_save)
        box.append(row)
        pop.set_child(box)
        pop.connect("show", lambda *_: self.fill_ignore())
        mb.set_popover(pop)
        self.ignore_pop = pop
        return mb

    def _import_menu(self):
        self.import_mb = Gtk.MenuButton(label="Import blocks")
        self.import_mb.set_tooltip_text("Terraform import blocks for the ticked rows that aren't "
                                        "in Terraform")
        pop = Gtk.Popover()
        box = vbox(6)
        margins(box, 10)
        self.ticked_label = label("Nothing ticked yet.", "heading")
        box.append(self.ticked_label)
        hint = label("Tick rows that aren't in Terraform. The blocks bring them under Terraform "
                     "(1.5 or newer), with names made from their Name tags.", "dim-label",
                     wrap=True)
        hint.set_max_width_chars(40)
        box.append(hint)
        row = hbox(6)
        row.append(button("Tick all shown", self.tick_all))
        row.append(button("Clear", lambda: self.table.set_all_checked(False)))
        box.append(row)
        box.append(Gtk.Separator())
        self.copy_imports_btn = button("Copy import blocks", self.copy_imports)
        box.append(self.copy_imports_btn)
        self.save_imports_btn = button("Save as imports.tf", self.save_imports)
        box.append(self.save_imports_btn)
        pop.set_child(box)
        pop.connect("show", lambda *_: self.checks_changed())
        self.import_mb.set_popover(pop)
        self.import_pop = pop
        return self.import_mb

    # =============================================================== sources

    def pick_file(self):
        open_file(self.win, self.add_file, "Open a Terraform state or plan JSON")

    def pick_folder(self):
        open_file(self.win, self.add_folder, "Terraform folder", folder=True)

    def dropped(self, target, value, x, y):
        files = [f.get_path() for f in value.get_files() if f.get_path()]
        for path in files:
            if os.path.isdir(path):
                self.add_folder(path)
            else:
                self.add_file(path)
        return bool(files)

    def _known(self, path) -> bool:
        real = os.path.realpath(path)
        if any(os.path.realpath(s["path"]) == real for s in self.sources):
            self.status.idle(f"{Path(path).name} is already in the list.")
            return True
        return False

    def add_file(self, path):
        if self._known(path):
            return
        if os.path.isdir(path):
            self.add_folder(path)
            return
        self.status.busy(f"Reading {Path(path).name}...", progress=False)
        label_ = self._label(path)
        run_bg(lambda: drift.load_source(path, run_terraform=False, label=label_),
               lambda st: self.source_loaded(path, "file", st),
               lambda exc: self.source_failed(path, exc))

    def add_folder(self, path):
        if self._known(path):
            return
        if not tfplan.terraform_bin():
            show_message(self.win, "Terraform isn't installed",
                         "Reading a folder runs terraform show -json there, which needs terraform "
                         "or tofu. You can add its state file instead: terraform state pull > "
                         "state.json")
            return
        profile = self.win.profile

        def go():
            self.status.busy(f"Running terraform show in {Path(path).name}...", progress=False)
            label_ = self._label(path)
            run_bg(lambda: drift.load_source(path, profile=profile, run_terraform=True,
                                             label=label_),
                   lambda st: self.source_loaded(path, "folder", st),
                   lambda exc: self.source_failed(path, exc))
        confirm_terraform(self.win, path, go, what="terraform show",
                          detail="Drift reads the folder's state with terraform show -json.")

    def _label(self, path) -> str:
        p = Path(path)
        name = p.name or str(p)
        taken = {s["stack"].label for s in self.sources}
        if name in taken or name in ("terraform.tfstate", "state.json"):
            name = f"{p.parent.name}/{p.name}" if p.parent.name else name
        n, base = 2, name
        while name in taken:
            name = f"{base} ({n})"
            n += 1
        return name

    def source_loaded(self, path, kind, stack):
        if self._known(path):
            return
        label_ = self._label(path)
        if label_ != stack.label:  # another one with the same name was added meanwhile
            stack.label = label_
            for m in stack.resources:
                m.stack = label_
        self.sources.append({"path": path, "kind": kind, "stack": stack})
        self.show_chips()
        what = f"{stack.total} managed resource" + ("" if stack.total == 1 else "s")
        self.status.idle(f"Added {stack.label}: {what}." +
                         ("" if self.inventory else " Press Compare when you're ready."))
        self.sources_changed()

    def source_failed(self, path, exc):
        self.status.idle("")
        show_message(self.win, f"Couldn't read {Path(path).name}",
                     str(exc) if isinstance(exc, drift.DriftError) else error_text(exc))

    def remove_source(self, src):
        if src in self.sources:
            self.sources.remove(src)
            self.exact.pop(src["stack"].label, None)
            self.show_chips()
            self.sources_changed()

    def show_chips(self):
        clear_box(self.chips)
        if not self.sources:
            self.chips.append(label("No states added yet.", "dim-label"))
        for src in self.sources:
            st = src["stack"]
            chip = hbox(6, "drift-chip")
            chip.set_valign(Gtk.Align.CENTER)
            icon = Gtk.Image.new_from_icon_name("folder-symbolic" if src["kind"] == "folder"
                                                else "text-x-generic-symbolic")
            chip.append(icon)
            name = label(st.label)
            name.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            name.set_max_width_chars(26)
            chip.append(name)
            chip.append(label(str(st.total), "dim-label"))
            close = Gtk.Button.new_from_icon_name("window-close-symbolic")
            close.add_css_class("flat")
            close.add_css_class("circular")
            close.set_tooltip_text("Remove")
            close.connect("clicked", lambda _b, s=src: self.remove_source(s))
            chip.append(close)
            kind = {"folder": "Terraform folder", "plan": "plan JSON"}.get(
                src["kind"] if src["kind"] == "folder" else st.kind, "state file")
            tip = f"{src['path']}\n{kind}, {st.total} managed AWS resources"
            if st.tf_version:
                tip += f", Terraform {st.tf_version}"
            chip.set_tooltip_text(tip)
            self.chips.append(chip)
        self.exact_btn.set_sensitive(any(s["kind"] == "folder" for s in self.sources))

    def sources_changed(self):
        """Match the states again against the last read of AWS, without calling AWS."""
        if self.inventory is not None and self.sources:
            self.evaluate()
            when = f" at {self.read_at:%H:%M}" if self.read_at else ""
            self.status.idle(f"Compared with the last read of AWS{when}. Press Compare to read "
                             "it again.")
        elif not self.sources:
            self.report = None
            self.show_report()

    def stacks(self):
        return [s["stack"] for s in self.sources]

    # =============================================================== comparing

    def compare(self, after=None):
        if not self.sources:
            show_message(self.win, "Add a state first",
                         "Add a state file with State file, or a Terraform folder with Folder.")
            return
        self._gen += 1
        gen = self._gen
        stacks = self.stacks()
        profiles = chosen_profiles(self)
        regions = self.regions.selected() or None
        cancel = self.new_cancel()
        self.compare_btn.set_sensitive(False)
        self.exact_btn.set_sensitive(False)
        self.status.busy("Reading the account...", cancel)
        progress = on_main(self.status.progress)
        if after is None:
            self.exact = {}  # Terraform's view goes with the read it was made next to

        def done(inv):
            if gen != self._gen:
                return
            if not self.sources:
                # Every state was removed while it read, so there's nothing to compare.
                self._idle_buttons()
                self.status.idle("")
                return
            if not inv.accounts:
                self._idle_buttons()
                self.status.idle("")
                show_message(self.win, "Couldn't read the account",
                             "\n".join(inv.notes) or "No profile could be read.")
                return
            self.inventory = inv
            self.read_at = datetime.now()
            self.evaluate()
            self._idle_buttons()
            if after:
                after()
            else:
                self.status.idle(f"Compared at {self.read_at:%H:%M}." + self._note_hint())

        run_bg(lambda: drift.read_account(stacks, profiles, regions, progress=progress,
                                          cancel=cancel), done, lambda exc: self.failed(exc, gen))

    def _note_hint(self) -> str:
        n = len(self.report.notes) if self.report else 0
        return f" {n} note{'s' if n != 1 else ''} on what couldn't be checked, below." if n else ""

    def _idle_buttons(self):
        self.compare_btn.set_sensitive(True)
        self.exact_btn.set_sensitive(any(s["kind"] == "folder" for s in self.sources))

    def failed(self, exc, gen=None):
        if gen is not None and gen != self._gen:
            return
        self._idle_buttons()
        self.status.idle("")
        show_message(self.win, "Couldn't compare", str(exc) if isinstance(exc, drift.DriftError)
                     else error_text(exc, self.win.profile))

    def evaluate(self):
        try:
            self.report = drift.evaluate(self.stacks(), self.inventory,
                                         drift.load_settings()["ignore"], self.exact)
        except Exception as exc:  # noqa: BLE001 - never leave an older result showing
            self.report = None
            self.show_report()
            show_message(self.win, "Couldn't compare", str(exc) or type(exc).__name__)
            return
        self.show_report()

    def exact_check(self):
        folders = [s for s in self.sources if s["kind"] == "folder"]
        if not folders:
            return
        if not tfplan.terraform_bin():
            show_message(self.win, "Terraform isn't installed",
                         "The exact check runs terraform plan -refresh-only, which needs "
                         "terraform or tofu.")
            return
        todo = list(folders)

        def ask_next():
            if not todo:
                self._run_exact(folders)
                return
            src = todo.pop(0)
            confirm_terraform(self.win, src["path"], ask_next, what="terraform plan -refresh-only",
                              detail="It asks AWS for the current state of everything the folder "
                                     "manages. The plan isn't applied, so the state isn't changed.")
        ask_next()

    def _run_exact(self, folders):
        self._gen += 1
        gen = self._gen
        profile = self.win.profile
        self.compare_btn.set_sensitive(False)
        self.exact_btn.set_sensitive(False)
        self.status.busy("Running terraform plan -refresh-only...", progress=False)
        log = on_main(self.status.text.set_text)

        def work():
            out = {}
            for src in folders:
                st = src["stack"]
                log(f"Running terraform plan -refresh-only in {st.label}...")
                try:
                    out[st.label] = drift.exact_check(src["path"], profile=profile)
                except drift.DriftError as exc:
                    out[st.label] = str(exc).replace("\n", " ")[:600]
            return out

        def done(results):
            if gen != self._gen:
                return
            labels = {s["stack"].label for s in self.sources}
            results = {k: v for k, v in results.items() if k in labels}
            if not results:
                # The folders were removed while Terraform ran.
                self._idle_buttons()
                self.status.idle("")
                return
            self.exact.update(results)
            ok = [k for k, v in results.items() if isinstance(v, list)]
            text = (f"Exact check done for {', '.join(ok)}." if ok else
                    "The exact check didn't work, see the notes below.")
            if self.inventory is None:
                self.compare(after=lambda: self.status.idle(text + self._note_hint()))
                return
            self.evaluate()
            self._idle_buttons()
            self.status.idle(text + self._note_hint())
        run_bg(work, done, lambda exc: self.failed(exc, gen))

    # =============================================================== showing

    def show_all(self) -> bool:
        return not self.only_mine.get_active()

    def show_report(self):
        r = self.report
        if r is None:
            self.table.clear(self.EMPTY)
            self.headline.set_text("No comparison yet.")
            self.subline.set_visible(False)
            self.detail.set_text("")
            self.checks_changed()
            return
        show_all = self.show_all()
        ticked = {it.obj.id for it in self.table.checked()}
        findings = r.visible(show_all)
        rows, checkable = [], []
        for f in findings:
            # Only what's worth searching for with the filter box; keys starting with _
            # aren't searched.
            full = f.row()
            row = {k: full[k] for k in ("badge", "type", "id", "name", "region", "detail",
                                        "address", "stack", "account")}
            row.update({"_dim": not f.in_scope, "_rank": full["rank"],
                        "_severity": full["severity"], "_status": full["status"]})
            rows.append(row)
            checkable.append(f.status == "unmanaged")
        self.table.set_rows(rows, findings, checkable)
        for it in self.table.items():
            if it.checkable and it.obj.id in ticked:
                it.checked = True
        if not findings:
            self.table.clear("No drift found. The account matches your states for everything "
                             "Drift reads." + (" Some things couldn't be checked, see the notes "
                                               "below." if r.notes else ""))
        self.headline.set_text(r.headline(show_all))
        sub = r.subline(show_all)
        self.subline.set_text(sub)
        self.subline.set_visible(bool(sub))
        self.apply_filter()
        self.show_notes()
        self.checks_changed()

    def show_notes(self):
        notes = self.report.notes if self.report else []
        self.fix_btn.set_visible(False)
        self.detail.set_text("Notes from the comparison:\n\n" + "\n".join(f"- {n}" for n in notes)
                             if notes else "")

    def apply_filter(self):
        want = self.FILTER_STATUS[self.filter_dd.get_selected()]
        self.table.set_filter(None if want is None else
                              (lambda it: it.obj is not None and it.obj.status == want))

    def selected(self, row):
        if row is None or row.obj is None:
            self.show_notes()
            return
        f = row.obj
        self.detail.set_text(f.detail_text())
        if f.status == "unmanaged":
            self.fix_btn.set_label("Copy import block")
            self.fix_btn.set_visible(True)
        elif f.status == "gone" and f.state_rm:
            self.fix_btn.set_label("Copy state rm")
            self.fix_btn.set_visible(True)
        else:
            self.fix_btn.set_visible(False)

    def copy_fix(self):
        row = self.table.selected_item()
        if row is None or row.obj is None:
            return
        text = row.obj.import_block or row.obj.state_rm
        if text:
            set_clipboard(self, text + "\n")
            flash(self.fix_btn, "Copied")

    # =============================================================== import blocks

    def ticked(self) -> list:
        return [it.obj for it in self.table.checked() if it.obj is not None]

    def checks_changed(self):
        n = len(self.ticked())
        self.ticked_label.set_text(f"{n} row{'s' if n != 1 else ''} ticked" if n else
                                   "Nothing ticked yet.")
        self.copy_imports_btn.set_sensitive(bool(n))
        self.save_imports_btn.set_sensitive(bool(n))
        self.import_mb.set_label(f"Import blocks ({n})" if n else "Import blocks")

    def tick_all(self):
        shown = {id(it) for it in self.table.visible_items()}
        self.table.set_all_checked(True, lambda it: id(it) in shown)

    def copy_imports(self):
        text = drift.import_text(self.ticked())
        if text:
            set_clipboard(self, text)
            flash(self.copy_imports_btn, "Copied")

    def save_imports(self):
        text = drift.import_text(self.ticked())
        if not text:
            return
        self.import_pop.popdown()
        dialog = Gtk.FileDialog(title="Save import blocks", initial_name="imports.tf")

        def done(dlg, result):
            try:
                path = dlg.save_finish(result).get_path()
            except GLib.Error:
                return  # cancelled
            try:
                write_atomic(path, text)
            except OSError as exc:
                show_message(self.win, "Couldn't save", str(exc))
                return
            self.status.idle(f"Saved {Path(path).name}. Run terraform plan "
                             "-generate-config-out=generated.tf next to it.")
        dialog.save(self.win, None, done)

    # =============================================================== ignore list

    def fill_ignore(self):
        self.ignore_view.get_buffer().set_text("\n".join(drift.load_settings()["ignore"]))

    def _ignore_lines(self) -> list:
        buf = self.ignore_view.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _add_ignore(self, findings):
        lines = self._ignore_lines()
        for f in findings:
            entry = f.address if f.status in ("gone", "changed") and f.address else f.id
            if entry and entry not in lines:
                lines.append(entry)
        self.ignore_view.get_buffer().set_text("\n".join(lines))

    def ignore_selected(self):
        row = self.table.selected_item()
        if row is not None and row.obj is not None:
            self._add_ignore([row.obj])

    def ignore_ticked(self):
        self._add_ignore(self.ticked())

    def save_ignore(self):
        if not drift.save_settings({"ignore": self._ignore_lines()}):
            show_message(self.win, "Couldn't save the ignore list",
                         "The AWS Kit settings file couldn't be written.")
            return
        flash(self.ignore_save, "Saved")
        if self.inventory is not None and self.sources:
            self.evaluate()
        GLib.timeout_add(500, lambda: self.ignore_pop.popdown() or False)

    # =============================================================== export

    def export(self):
        if not self.report:
            show_message(self.win, "Nothing to export yet", "Press Compare first.")
            return
        rows = [f.row() for f in self.report.visible(self.show_all())]
        export_rows(self.win, rows, drift.EXPORT_COLS, "drift.md", title="Drift")

    # =============================================================== profiles

    def profile_changed(self, profile):
        fill_accounts(self, reset=True)

    def profiles_changed(self):
        fill_accounts(self)
