"""Building blocks shared by every page: tables, detail pane, status bar, pickers, dialogs."""
from __future__ import annotations

import os
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

from .common import (ClipboardError, export_text, have_pii_redact, pii_redact,  # noqa: E402
                     write_clipboard)

CSS = b"""
.sev { border-radius: 5px; padding: 1px 7px; font-weight: bold; font-size: 0.85em; color: white; }
.sev-critical { background: #8f1f8f; }
.sev-high { background: #c01c28; }
.sev-medium { background: #c64600; }
.sev-low { background: #1c71d8; }
.sev-info { background: #5e5c64; }
.cost-big { color: #e01b24; font-weight: bold; }
.cost-mid { color: #e66100; font-weight: bold; }
.dimmed { opacity: 0.55; }
.headline { font-size: 1.2em; font-weight: bold; }
.mono { font-family: monospace; }
.pagetitle { font-size: 1.15em; font-weight: bold; }
.statusbar { padding: 4px 10px; border-top: 1px solid alpha(currentColor, 0.15); }
.ok-text { color: #26a269; font-weight: bold; }
.bad-text { color: #e01b24; font-weight: bold; }
.warn-text { color: #e66100; }
.finding-row { padding: 8px 12px; }
.mapwarn { padding: 6px 10px; background: alpha(#e66100, 0.16); border-bottom: 1px solid alpha(#e66100, 0.4); }
"""


def install_css():
    provider = Gtk.CssProvider()
    try:
        provider.load_from_data(CSS)
    except TypeError:  # some PyGObject versions want the length too
        provider.load_from_data(CSS, len(CSS))
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                              Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


# =================================================================== threads

def run_bg(work, on_done, on_error=None):
    """Run work() in a thread, then on_done(result) or on_error(exc) on the GTK thread."""
    def call(fn, arg):
        fn(arg)
        return False

    def target():
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001
            if on_error:
                GLib.idle_add(call, on_error, exc)
            return
        GLib.idle_add(call, on_done, result)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t


def on_main(fn):
    """Wrap fn so calling it from a worker thread runs it on the GTK thread."""
    def wrapper(*args):
        def go():
            fn(*args)
            return False
        GLib.idle_add(go)
    return wrapper


# =================================================================== small helpers

def label(text="", css=None, xalign=0.0, wrap=False, selectable=False):
    w = Gtk.Label(label=text, xalign=xalign, wrap=wrap, selectable=selectable)
    if wrap:
        w.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    for c in (css or "").split():
        w.add_css_class(c)
    return w


def button(text, callback=None, tooltip=None, css=None):
    b = Gtk.Button(label=text)
    if callback:
        b.connect("clicked", lambda *_: callback())
    if tooltip:
        b.set_tooltip_text(tooltip)
    for c in (css or "").split():
        b.add_css_class(c)
    return b


def hbox(spacing=6, css=None):
    b = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=spacing)
    for c in (css or "").split():
        b.add_css_class(c)
    return b


def vbox(spacing=6, css=None):
    b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    for c in (css or "").split():
        b.add_css_class(c)
    return b


def margins(widget, size=10):
    for side in ("top", "bottom", "start", "end"):
        getattr(widget, f"set_margin_{side}")(size)
    return widget


def spacer():
    s = Gtk.Box()
    s.set_hexpand(True)
    return s


def sev_badge(severity):
    w = label((severity or "").upper(), f"sev sev-{severity}", xalign=0.5)
    w.set_valign(Gtk.Align.CENTER)
    w.set_halign(Gtk.Align.START)
    return w


def clear_box(box):
    child = box.get_first_child()
    while child:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def set_clipboard(widget, text):
    """GNOME keeps the clipboard after an app closes. Niri, Hyprland, Sway and plain X11
    usually don't, so wl-copy or xclip are used there to keep it alive."""
    if "GNOME" not in os.environ.get("XDG_CURRENT_DESKTOP", "").upper():
        try:
            write_clipboard(text)
            return
        except ClipboardError:
            pass
    value = GObject.Value(GObject.TYPE_STRING, text)
    widget.get_clipboard().set_content(Gdk.ContentProvider.new_for_value(value))


def string_dropdown(options, selected=0):
    dd = Gtk.DropDown.new_from_strings(list(options))
    dd.set_selected(selected)
    return dd


def flash(btn, text, ms=1200):
    old = btn.get_label()
    btn.set_label(text)

    def back():
        btn.set_label(old)
        return False
    GLib.timeout_add(ms, back)


# =================================================================== table

class RowItem(GObject.Object):
    __gtype_name__ = "AwsKitRowItem"
    checked = GObject.Property(type=bool, default=False)

    def __init__(self, data: dict, obj=None, checkable=True):
        super().__init__()
        self.data = data
        self.obj = obj
        self.checkable = checkable


class ResultTable(Gtk.Box):
    """A sortable, filterable ColumnView over a list of dicts.

    columns: list of (key, title, options). Options can hold width, expand,
    kind ("text", "severity", "cost", "mono") and sort_key.
    """

    def __init__(self, columns, checkable=False, on_select=None, on_activate=None,
                 on_check=None, placeholder="Nothing to show yet.", search=True):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.columns = columns
        self.on_select = on_select
        self.on_activate = on_activate
        self.on_check = on_check
        self.query = ""
        self.extra_filter = None

        self.store = Gio.ListStore.new(RowItem)
        self.filter = Gtk.CustomFilter.new(self._match)
        self.filter_model = Gtk.FilterListModel(model=self.store, filter=self.filter)
        self.sort_model = Gtk.SortListModel(model=self.filter_model)
        self.selection = Gtk.SingleSelection(model=self.sort_model, autoselect=False,
                                             can_unselect=True)
        self.selection.connect("notify::selected", self._selected)
        self.view = Gtk.ColumnView(model=self.selection)
        self.view.set_show_row_separators(True)
        self.view.connect("activate", self._activated)
        self.sort_model.set_sorter(self.view.get_sorter())

        if checkable:
            f = Gtk.SignalListItemFactory()
            f.connect("setup", self._setup_check)
            f.connect("bind", self._bind_check)
            f.connect("unbind", self._unbind_check)
            col = Gtk.ColumnViewColumn(title="", factory=f)
            col.set_fixed_width(38)
            self.view.append_column(col)

        for key, title, opts in columns:
            opts = opts or {}
            kind = opts.get("kind", "text")
            f = Gtk.SignalListItemFactory()
            f.connect("setup", self._setup_cell, kind)
            f.connect("bind", self._bind_cell, key, kind)
            col = Gtk.ColumnViewColumn(title=title, factory=f)
            col.set_resizable(True)
            if opts.get("width"):
                col.set_fixed_width(opts["width"])
            if opts.get("expand"):
                col.set_expand(True)
            col.set_sorter(Gtk.CustomSorter.new(self._compare, opts.get("sort_key", key)))
            self.view.append_column(col)

        self.search = None
        if search:
            self.search = Gtk.SearchEntry(placeholder_text="Filter rows")
            self.search.connect("search-changed", self._search_changed)
            self.search.set_margin_start(10)
            self.search.set_margin_end(10)
            self.search.set_margin_bottom(6)
            self.append(self.search)

        self.stack = Gtk.Stack()
        self.stack.set_vexpand(True)
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(self.view)
        scroller.set_vexpand(True)
        self.empty = label(placeholder, "dim-label", xalign=0.5, wrap=True)
        self.empty.set_justify(Gtk.Justification.CENTER)
        self.empty.set_valign(Gtk.Align.CENTER)
        margins(self.empty, 30)
        self.stack.add_named(self.empty, "empty")
        self.stack.add_named(scroller, "table")
        self.append(self.stack)

    # ---- data
    def set_rows(self, rows, objs=None, checkable=None):
        items = []
        for i, row in enumerate(rows):
            items.append(RowItem(row, objs[i] if objs else None,
                                 checkable[i] if checkable else True))
        self.store.splice(0, self.store.get_n_items(), items)
        self.stack.set_visible_child_name("table" if items else "empty")

    def clear(self, placeholder=None):
        self.store.remove_all()
        if placeholder:
            self.empty.set_text(placeholder)
        self.stack.set_visible_child_name("empty")

    def items(self):
        return [self.store.get_item(i) for i in range(self.store.get_n_items())]

    def visible_items(self):
        return [self.sort_model.get_item(i) for i in range(self.sort_model.get_n_items())]

    def checked(self):
        return [it for it in self.items() if it.checked]

    def set_all_checked(self, value, predicate=None):
        for it in self.items():
            if it.checkable and (predicate is None or predicate(it)):
                it.checked = value
            elif not it.checkable:
                it.checked = False
        if self.on_check:
            self.on_check()

    def refresh_rows(self):
        """Redraw after row data changed. New wrapper objects make the view rebind every cell."""
        fresh = []
        for it in self.items():
            new = RowItem(it.data, it.obj, it.checkable)
            new.checked = it.checked
            fresh.append(new)
        self.store.splice(0, len(fresh), fresh)

    def selected_item(self):
        return self.selection.get_selected_item()

    def set_filter(self, fn):
        self.extra_filter = fn
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    # ---- filter and sort
    def _search_changed(self, entry):
        self.query = entry.get_text().strip().lower()
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    def _match(self, item, *_):
        if self.extra_filter and not self.extra_filter(item):
            return False
        if not self.query:
            return True
        return any(self.query in str(v).lower() for k, v in item.data.items()
                   if not k.startswith("_"))

    @staticmethod
    def _compare(a, b, key):
        va, vb = a.data.get(key), b.data.get(key)
        if va is None and vb is None:
            return 0
        if va is None:
            return 1
        if vb is None:
            return -1
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            return (va > vb) - (va < vb)
        sa, sb = str(va).lower(), str(vb).lower()
        return (sa > sb) - (sa < sb)

    # ---- cells
    def _setup_cell(self, factory, list_item, kind):
        lab = Gtk.Label(xalign=0)
        lab.set_ellipsize(Pango.EllipsizeMode.END)
        lab.set_margin_start(4)
        lab.set_margin_end(4)
        if kind == "mono":
            lab.add_css_class("mono")
        list_item.set_child(lab)

    def _bind_cell(self, factory, list_item, key, kind):
        lab = list_item.get_child()
        item = list_item.get_item()
        value = item.data.get(key, "")
        text = "" if value is None else str(value)
        for c in ("sev", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info",
                  "cost-big", "cost-mid", "dimmed", "bad-text", "ok-text"):
            lab.remove_css_class(c)
        lab.set_halign(Gtk.Align.FILL)
        if kind == "severity" and text:
            lab.add_css_class("sev")
            lab.add_css_class(f"sev-{text}")
            lab.set_halign(Gtk.Align.START)
            text = text.upper()
        elif kind == "cost":
            amount = item.data.get("monthly")
            if isinstance(amount, (int, float)) and not item.data.get("_dim"):
                if amount >= 50:
                    lab.add_css_class("cost-big")
                elif amount >= 10:
                    lab.add_css_class("cost-mid")
        elif kind == "result":
            lab.add_css_class("ok-text" if text == "OK" else "bad-text")
        if item.data.get("_dim"):
            lab.add_css_class("dimmed")
        lab.set_text(text)
        lab.set_tooltip_text(text if len(text) > 28 else None)

    def _setup_check(self, factory, list_item):
        cb = Gtk.CheckButton()
        cb.set_halign(Gtk.Align.CENTER)
        list_item.set_child(cb)

    def _bind_check(self, factory, list_item):
        cb = list_item.get_child()
        item = list_item.get_item()
        cb.set_sensitive(item.checkable)
        cb.set_tooltip_text(None if item.checkable else "Can't be deleted from here")
        cb._awskit_binding = item.bind_property(
            "checked", cb, "active",
            GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE)
        cb._awskit_handler = cb.connect("toggled", lambda *_: self.on_check and self.on_check())

    def _unbind_check(self, factory, list_item):
        cb = list_item.get_child()
        binding = getattr(cb, "_awskit_binding", None)
        if binding is not None:
            binding.unbind()
            cb._awskit_binding = None
        handler = getattr(cb, "_awskit_handler", None)
        if handler:
            cb.disconnect(handler)
            cb._awskit_handler = None

    # ---- signals
    def _selected(self, *_):
        if self.on_select:
            self.on_select(self.selection.get_selected_item())

    def _activated(self, view, position):
        if self.on_activate:
            self.on_activate(self.sort_model.get_item(position))


# =================================================================== detail pane

class DetailPane(Gtk.Box):
    """Read-only monospace text with Copy and Copy redacted buttons."""

    def __init__(self, placeholder="Select a row to see the details.", title="Details"):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.placeholder = placeholder
        bar = hbox(6)
        bar.set_margin_start(10)
        bar.set_margin_end(10)
        bar.set_margin_top(6)
        self.title = label(title, "heading")
        bar.append(self.title)
        bar.append(spacer())
        self.extra = hbox(6)
        bar.append(self.extra)
        self.copy_btn = button("Copy", self.copy)
        bar.append(self.copy_btn)
        self.redact_btn = button("Copy redacted", self.copy_redacted,
                                 tooltip="Runs the text through PII Redact before copying")
        self.redact_btn.set_visible(have_pii_redact())
        bar.append(self.redact_btn)
        self.append(bar)

        self.view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
        self.view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        for side in ("left", "right", "top", "bottom"):
            getattr(self.view, f"set_{side}_margin")(8)
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(self.view)
        scroller.set_vexpand(True)
        scroller.set_min_content_height(100)
        self.append(scroller)
        self.set_text("")

    def set_text(self, text):
        self.text = text or ""
        self.view.get_buffer().set_text(self.text or self.placeholder)
        self.copy_btn.set_sensitive(bool(self.text))
        self.redact_btn.set_sensitive(bool(self.text))

    def copy(self):
        if self.text:
            set_clipboard(self, self.text)
            flash(self.copy_btn, "Copied")

    def copy_redacted(self):
        if not self.text:
            return
        text = self.text

        def done(red):
            set_clipboard(self, red)
            flash(self.redact_btn, "Copied")
        run_bg(lambda: pii_redact(text), done)


# =================================================================== status bar

class StatusBar(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.add_css_class("statusbar")
        self.spinner = Gtk.Spinner()
        self.append(self.spinner)
        self.text = label("")
        self.text.set_ellipsize(Pango.EllipsizeMode.END)
        self.text.set_hexpand(True)
        self.append(self.text)
        self.bar = Gtk.ProgressBar()
        self.bar.set_valign(Gtk.Align.CENTER)
        self.bar.set_size_request(160, -1)
        self.bar.set_visible(False)
        self.append(self.bar)
        self.stop_btn = button("Stop")
        self.stop_btn.set_visible(False)
        self.append(self.stop_btn)
        self.cancel = None
        self.stop_btn.connect("clicked", self._stop)

    def busy(self, text, cancel=None, progress=True):
        self.spinner.start()
        self.text.set_text(text)
        self.bar.set_fraction(0)
        self.bar.set_visible(progress)
        self.cancel = cancel
        self.stop_btn.set_visible(cancel is not None)
        self.stop_btn.set_sensitive(True)

    def progress(self, done, total, text):
        if total:
            self.bar.set_fraction(done / total)
        self.text.set_text(f"{done}/{total}  {text}" if total else text)

    def idle(self, text=""):
        self.spinner.stop()
        self.text.set_text(text)
        self.bar.set_visible(False)
        self.stop_btn.set_visible(False)
        self.cancel = None

    def _stop(self, *_):
        if self.cancel is not None:
            self.cancel.set()
            self.stop_btn.set_sensitive(False)
            self.text.set_text("Stopping after the calls already running...")


# =================================================================== pickers

class CheckListButton(Gtk.MenuButton):
    """A button that opens a list of checkboxes. Used for profiles, regions and checks."""

    def __init__(self, title, all_label=None, on_change=None, empty_label="none"):
        super().__init__()
        self.title = title
        self.all_label = all_label
        self.empty_label = empty_label
        self.on_change = on_change
        self.checks = {}
        self.all_check = None
        pop = Gtk.Popover()
        outer = vbox(6)
        margins(outer, 8)
        self.list_box = vbox(2)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_propagate_natural_height(True)
        scroller.set_propagate_natural_width(True)
        scroller.set_max_content_height(420)
        scroller.set_child(self.list_box)
        outer.append(scroller)
        row = hbox(6)
        row.append(button("All", lambda: self.set_all(True)))
        row.append(button("None", lambda: self.set_all(False)))
        outer.append(row)
        pop.set_child(outer)
        self.set_popover(pop)
        self._update_label()

    def set_options(self, options, selected=None, tooltips=None):
        """options: list of (value, text). selected: values to tick. Empty means 'all'."""
        clear_box(self.list_box)
        self.checks = {}
        self.all_check = None
        selected = set(selected or [])
        if self.all_label:
            self.all_check = Gtk.CheckButton(label=self.all_label)
            self.all_check.set_active(not selected)
            self.all_check.connect("toggled", self._all_toggled)
            self.list_box.append(self.all_check)
            self.list_box.append(Gtk.Separator())
        for value, text in options:
            cb = Gtk.CheckButton(label=text)
            cb.set_active(value in selected)
            if tooltips and value in tooltips:
                cb.set_tooltip_text(tooltips[value])
            cb.connect("toggled", self._toggled)
            self.checks[value] = cb
            self.list_box.append(cb)
        self._update_label()

    def selected(self):
        """Ticked values. An empty list means 'all' when there's an all option."""
        if self.all_check is not None and self.all_check.get_active():
            return []
        return [v for v, cb in self.checks.items() if cb.get_active()]

    def set_selected(self, values):
        values = set(values or [])
        for v, cb in self.checks.items():
            cb.handler_block_by_func(self._toggled)
            cb.set_active(v in values)
            cb.handler_unblock_by_func(self._toggled)
        if self.all_check is not None:
            self.all_check.handler_block_by_func(self._all_toggled)
            self.all_check.set_active(not values)
            self.all_check.handler_unblock_by_func(self._all_toggled)
        self._update_label()

    def set_all(self, value):
        if self.all_check is not None and value:
            self.all_check.set_active(True)
            return
        for cb in self.checks.values():
            cb.set_active(value)
        if self.all_check is not None and not value:
            self.all_check.set_active(False)

    def _all_toggled(self, cb):
        if cb.get_active():
            for c in self.checks.values():
                c.handler_block_by_func(self._toggled)
                c.set_active(False)
                c.handler_unblock_by_func(self._toggled)
        self._update_label()
        if self.on_change:
            self.on_change()

    def _toggled(self, cb):
        if self.all_check is not None and cb.get_active() and self.all_check.get_active():
            self.all_check.handler_block_by_func(self._all_toggled)
            self.all_check.set_active(False)
            self.all_check.handler_unblock_by_func(self._all_toggled)
        self._update_label()
        if self.on_change:
            self.on_change()

    def _update_label(self):
        sel = [v for v, cb in self.checks.items() if cb.get_active()]
        if self.all_check is not None and (self.all_check.get_active() or not sel):
            text = self.all_label
        elif not sel:
            text = self.empty_label
        elif len(sel) == 1:
            text = self.checks[sel[0]].get_label()
        else:
            text = f"{len(sel)} picked"
        self.set_label(f"{self.title}: {text}")


def all_regions():
    """Every commercial region boto3 knows about. No API call."""
    try:
        import boto3
        return sorted(boto3.session.Session().get_available_regions("ec2"))
    except Exception:  # noqa: BLE001
        return ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]


def profile_options():
    from . import profiles
    out, tips = [], {}
    for p in profiles.list_profiles():
        text = p["name"]
        if p["account"]:
            text += f"  ({p['account']})"
        out.append((p["name"], text))
        status = profiles.offline_status(p)
        tips[p["name"]] = f"{p['kind']}" + (f", {status}" if status else "")
    return out, tips


# =================================================================== dialogs

def export_rows(parent, rows, columns, default_name, title=None):
    dialog = Gtk.FileDialog(title="Export", initial_name=default_name)

    def done(dlg, result):
        try:
            gfile = dlg.save_finish(result)
        except GLib.Error:
            return  # cancelled
        path = gfile.get_path()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(export_text(path, rows, columns, title=title))
        except OSError as exc:
            show_message(parent, "Couldn't save", str(exc))

    dialog.save(parent, None, done)


def save_text(parent, text, default_name):
    dialog = Gtk.FileDialog(title="Save", initial_name=default_name)

    def done(dlg, result):
        try:
            gfile = dlg.save_finish(result)
        except GLib.Error:
            return
        try:
            with open(gfile.get_path(), "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            show_message(parent, "Couldn't save", str(exc))

    dialog.save(parent, None, done)


def open_file(parent, callback, title="Open", folder=False):
    dialog = Gtk.FileDialog(title=title)

    def done(dlg, result):
        try:
            gfile = dlg.select_folder_finish(result) if folder else dlg.open_finish(result)
        except GLib.Error:
            return
        callback(gfile.get_path())

    if folder:
        dialog.select_folder(parent, None, done)
    else:
        dialog.open(parent, None, done)


def show_message(parent, heading, body=""):
    dlg = Gtk.AlertDialog(message=heading, detail=body)
    dlg.set_buttons(["OK"])
    dlg.show(parent)


def ask(parent, heading, body, yes_label, on_yes, no_label="Cancel"):
    """A two-button question. on_yes runs only when the second button is pressed;
    Escape, closing it or the first button do nothing."""
    dlg = Gtk.AlertDialog(message=heading, detail=body)
    dlg.set_buttons([no_label, yes_label])
    dlg.set_cancel_button(0)
    dlg.set_default_button(0)

    def chosen(d, res):
        try:
            if d.choose_finish(res) != 1:
                return
        except GLib.Error:
            return
        on_yes()
    dlg.choose(parent, None, chosen)


# Folders the user has agreed to run Terraform in, this session.
_trusted_tf_folders = set()


def trust_terraform_folder(folder):
    """Marks a folder as fine to run Terraform in for the rest of this session."""
    _trusted_tf_folders.add(os.path.realpath(str(folder)))


def confirm_terraform(parent, folder, on_yes, what="terraform plan", detail=""):
    """Running Terraform in a folder runs that folder's code: providers it names are
    downloaded and started, and data sources such as external run programs, with your AWS
    credentials. So ask once per folder per session before doing it."""
    key = os.path.realpath(str(folder))
    if key in _trusted_tf_folders:
        on_yes()
        return

    def yes():
        _trusted_tf_folders.add(key)
        on_yes()
    ask(parent, f"Run {what} in this folder?",
        f"{folder}\n\n" + (detail + "\n\n" if detail else "") +
        "This runs the Terraform code in the folder, with your AWS credentials. "
        "Terraform downloads and starts the providers it asks for, and some data sources run "
        "programs. Only do this for code you trust.", "Run it", yes)


class ConfirmDeleteDialog(Gtk.Window):
    """Lists what will be deleted and only enables Delete after typing 'delete'."""

    def __init__(self, parent, heading, lines, on_confirm, word="delete"):
        super().__init__(title="Confirm teardown", modal=True, transient_for=parent)
        self.set_default_size(640, 480)
        self.on_confirm = on_confirm
        self.word = word
        box = vbox(10)
        margins(box, 16)
        box.append(label(heading, "headline", wrap=True))
        box.append(label("This can't be undone. KMS keys, secrets and private CAs wait 7 days "
                         "before they're gone, and you can cancel those in the console.",
                         "dim-label", wrap=True))
        view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
        view.get_buffer().set_text("\n".join(lines))
        for side in ("left", "right", "top", "bottom"):
            getattr(view, f"set_{side}_margin")(6)
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(view)
        scroller.set_vexpand(True)
        box.append(scroller)
        box.append(label(f"Type {word} to confirm:"))
        self.entry = Gtk.Entry()
        self.entry.connect("changed", self._changed)
        self.entry.connect("activate", lambda *_: self._go())
        box.append(self.entry)
        row = hbox(8)
        row.append(spacer())
        row.append(button("Cancel", self.close))
        self.go_btn = button("Delete", self._go, css="destructive-action")
        self.go_btn.set_sensitive(False)
        row.append(self.go_btn)
        box.append(row)
        self.set_child(box)
        key = Gtk.EventControllerKey()
        key.connect("key-pressed", self._key)
        self.add_controller(key)

    def _key(self, ctrl, keyval, keycode, state):
        if keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False

    def _changed(self, entry):
        self.go_btn.set_sensitive(entry.get_text().strip().lower() == self.word)

    def _go(self):
        if self.entry.get_text().strip().lower() == self.word:
            self.close()
            self.on_confirm()


# =================================================================== account pickers

def account_pickers(page, all_regions_label="All enabled"):
    page.accounts = CheckListButton("Accounts", empty_label="current profile")
    page.regions = CheckListButton("Regions", all_label=all_regions_label)
    page.regions.set_options([(r, r) for r in all_regions()])
    fill_accounts(page)


def fill_accounts(page, reset=False):
    opts, tips = profile_options()
    names = [v for v, _ in opts]
    current = page.win.profile
    keep = [] if reset else [k for k in page.accounts.selected() if k in names]
    page.accounts.set_options(opts, keep or ([current] if current in names else []), tips)


def chosen_profiles(page):
    return page.accounts.selected() or [page.win.profile]


class Page(Gtk.Box):
    """Base for each sidebar page."""
    name = ""
    title = ""

    def __init__(self, win, intro=""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.win = win
        self.cancel = threading.Event()
        head = vbox(2)
        head.set_margin_start(12)
        head.set_margin_end(12)
        head.set_margin_top(10)
        head.set_margin_bottom(4)
        head.append(label(self.title, "pagetitle"))
        if intro:
            head.append(label(intro, "dim-label", wrap=True))
        self.append(head)
        self.status = StatusBar()

    def toolbar(self):
        bar = hbox(6)
        bar.set_margin_start(10)
        bar.set_margin_end(10)
        bar.set_margin_top(6)
        bar.set_margin_bottom(8)
        return bar

    def new_cancel(self):
        self.cancel = threading.Event()
        return self.cancel

    def profile_changed(self, profile):
        """The header bar profile changed."""

    def profiles_changed(self):
        """~/.aws/config may have new profiles."""
