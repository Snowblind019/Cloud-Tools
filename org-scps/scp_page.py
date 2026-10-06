"""Org & SCPs page for the AWS Kit window."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from gi.repository import Gdk, Gio, GLib, GObject, Gtk, Pango

from . import scpcheck
from .common import error_text
from .widgets import (DetailPane, Page, ResultTable, button, clear_box, confirm_terraform, flash,
                      hbox, label, on_main, open_file, run_bg, set_clipboard, show_message,
                      spacer, vbox)

CSS = b"""
.scp-pill { border-radius: 999px; padding: 1px 8px; font-size: 0.78em; font-weight: bold; }
.scp-count { background: alpha(currentColor, 0.10); font-weight: normal; }
.scp-mgmt { background: alpha(#3584e4, 0.18); color: #3584e4; }
.scp-limit { background: alpha(#e66100, 0.18); color: #e66100; }
.scp-draft { background: #1c71d8; color: white; }
.scp-st-allow { background: #26a269; color: white; }
.scp-st-deny, .scp-st-noallow { background: #c01c28; color: white; }
.scp-st-depends, .scp-st-warn { background: #c64600; color: white; }
.scp-st-info { background: #77767b; color: white; }
.scp-verdict { font-size: 1.45em; font-weight: 800; }
.scp-v-allowed { color: #26a269; }
.scp-v-denied { color: #e01b24; }
.scp-v-depends, .scp-v-error { color: #e66100; }
.scp-vb { padding: 8px 12px; border-radius: 10px; }
.scp-vb-allowed { background: alpha(#26a269, 0.10); border: 1px solid alpha(#26a269, 0.40); }
.scp-vb-denied { background: alpha(#e01b24, 0.08); border: 1px solid alpha(#e01b24, 0.40); }
.scp-vb-depends, .scp-vb-error { background: alpha(#e66100, 0.08);
                                 border: 1px solid alpha(#e66100, 0.40); }
.scp-vb-empty { background: alpha(currentColor, 0.04);
                border: 1px dashed alpha(currentColor, 0.2); }
.scp-id { font-family: monospace; font-size: 0.82em; opacity: 0.65; }
.scp-name { font-weight: 600; }
.scp-small { font-size: 0.9em; }
.scp-section { font-weight: bold; font-size: 0.92em; opacity: 0.75; }
.scp-card { padding: 6px 10px; border-radius: 8px; background: alpha(currentColor, 0.045); }
.scp-note { padding: 5px 12px; background: alpha(#e5a50a, 0.16);
            border-top: 1px solid alpha(#e5a50a, 0.35);
            border-bottom: 1px solid alpha(#e5a50a, 0.35); }
.scp-head { padding: 8px 12px 4px 12px; }
.scp-box-title { font-weight: bold; font-size: 1.05em; }
.scp-ok { color: #26a269; }
.scp-bad { color: #e01b24; }
.scp-warn { color: #e66100; }
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
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                              Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)
    _css_done = True


ICONS = {"root": "network-workgroup-symbolic", "ou": "folder-symbolic",
         "account": "network-server-symbolic", "management": "user-home-symbolic"}


def icon_for(org, node):
    if org is not None and node.id == org.management:
        return ICONS["management"]
    return ICONS.get(node.kind, "folder-symbolic")
KIND_WORDS = {"root": "Root", "ou": "Organizational unit", "account": "Account"}
STATUS_WORDS = {"allow": "ALLOW", "deny": "DENY", "noallow": "NO ALLOW", "depends": "DEPENDS",
                "info": "INFO", "warn": "NOTE"}


def keep_ratio(paned, ratio):
    """Puts the handle at ratio of the paned's width (or height) whenever its size changes,
    until the user drags the handle. Fixed positions tuned for one window size overflow at
    another."""
    state = {"user": False, "pressed": False, "ours": None}

    def place(*_):
        if state["user"]:
            return
        horizontal = paned.get_orientation() == Gtk.Orientation.HORIZONTAL
        size = paned.get_width() if horizontal else paned.get_height()
        if size <= 1:
            return
        lo, hi = paned.get_property("min-position"), paned.get_property("max-position")
        pos = max(lo, min(hi, int(size * ratio)))
        if pos != paned.get_position():
            state["ours"] = pos
            paned.set_position(pos)

    def moved(*_):
        if state["pressed"] and paned.get_position() != state["ours"]:
            state["user"] = True

    def pressed(*_):
        state["pressed"] = True

    def released(*_):
        state["pressed"] = False
    click = Gtk.GestureClick()
    click.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
    click.connect("pressed", pressed)
    click.connect("released", released)
    click.connect("stopped", released)
    paned.add_controller(click)
    paned.connect("notify::max-position", place)
    paned.connect("notify::position", moved)


def short_dropdown(options):
    """A dropdown whose button cuts long text short with "...", so the longest item doesn't
    set its width. The open list still shows every item in full."""
    dd = Gtk.DropDown.new_from_strings(list(options))

    def setup(_f, item, ellipsize):
        lab = Gtk.Label(xalign=0)
        if ellipsize:
            lab.set_ellipsize(Pango.EllipsizeMode.END)
        item.set_child(lab)

    def bind(_f, item):
        item.get_child().set_text(item.get_item().get_string())
    button_factory = Gtk.SignalListItemFactory()
    button_factory.connect("setup", setup, True)
    button_factory.connect("bind", bind)
    list_factory = Gtk.SignalListItemFactory()
    list_factory.connect("setup", setup, False)
    list_factory.connect("bind", bind)
    dd.set_factory(button_factory)
    dd.set_list_factory(list_factory)
    return dd


def pill(text, css):
    w = label(text, "scp-pill " + css, xalign=0.5)
    w.set_valign(Gtk.Align.CENTER)
    w.set_halign(Gtk.Align.START)
    return w


class OrgItem(GObject.Object):
    __gtype_name__ = "AwsKitScpOrgItem"

    def __init__(self, node):
        super().__init__()
        self.node = node


class ScpPage(Page):
    name = "scp"
    title = "Org & SCPs"

    POLICY_COLS = [("shown", "Policy", {"width": 190}),
                   ("type", "Type", {"width": 48}),
                   ("where", "Attached at", {"width": 140}),
                   ("summary", "What it does", {"expand": True})]

    def __init__(self, win):
        super().__init__(win, "Your AWS Organization as a tree, with the service control "
                         "policies that apply where. Test whether an action would be blocked "
                         "in an account, by what and why, or try a draft SCP first. Read-only.")
        _install_css()
        self.org = None
        self._kids = {}         # the org's children_map, made once per load
        self.node_id = None
        self.account_ids = []
        self.target_ids = []
        self.draft = None
        self.verdict = None
        self._draft_timer = 0

        bar = self.toolbar()
        self.read_btn = button("Read from AWS", self.read_aws)
        bar.append(self.read_btn)
        bar.append(button("State file", self.open_state,
                          tooltip="A .tfstate file or terraform show -json output"))
        bar.append(button("Folder", self.open_folder,
                          tooltip="A Terraform folder. Runs terraform show there, after asking."))
        bar.append(button("Open snapshot", self.open_snapshot,
                          tooltip="An org saved earlier with Save snapshot"))
        self.save_btn = button("Save snapshot", self.save_snapshot,
                               tooltip="Save the org to a file, to test offline later")
        self.save_btn.set_sensitive(False)
        bar.append(self.save_btn)
        bar.append(spacer())
        self.source_label = label("Nothing loaded yet", "dim-label")
        self.source_label.set_ellipsize(Pango.EllipsizeMode.START)
        bar.append(self.source_label)
        self.append(bar)
        self._update_read_tooltip()

        self.note_bar = label("", "scp-note scp-small", wrap=True)
        self.note_bar.set_visible(False)
        self.append(self.note_bar)

        main = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        main.set_vexpand(True)
        main.set_start_child(self._build_tree())
        main.set_resize_start_child(False)
        main.set_shrink_start_child(False)
        right = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        right.set_start_child(self._build_details())
        right.set_end_child(self._build_test())
        right.set_shrink_start_child(False)
        right.set_shrink_end_child(False)
        keep_ratio(right, 0.44)
        self.right_paned = right
        main.set_end_child(right)
        keep_ratio(main, 0.27)
        self.main_paned = main
        self.append(main)
        self.append(self.status)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self._dropped)
        self.add_controller(drop)

    # =============================================================== layout
    def _build_tree(self):
        box = vbox(0)
        box.set_size_request(290, -1)
        head = hbox(6)
        head.set_margin_start(12)
        head.set_margin_end(10)
        head.set_margin_bottom(4)
        head.append(label("Organization", "heading"))
        head.append(spacer())
        self.tree_count = label("", "dim-label scp-small")
        head.append(self.tree_count)
        box.append(head)

        self.tree_store = Gio.ListStore.new(OrgItem)
        self.tree_model = Gtk.TreeListModel.new(self.tree_store, False, True, self._children)
        self.tree_sel = Gtk.SingleSelection(model=self.tree_model, autoselect=False,
                                            can_unselect=False)
        self.tree_sel.connect("notify::selected", self._tree_selected)
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", self._tree_setup)
        factory.connect("bind", self._tree_bind)
        self.tree_view = Gtk.ListView(model=self.tree_sel, factory=factory)
        self.tree_view.add_css_class("navigation-sidebar")
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(self.tree_view)
        scroller.set_vexpand(True)
        self.tree_stack = Gtk.Stack()
        empty = label("Read your organization from AWS, or open a Terraform state, a folder "
                      "or a snapshot.\n\nYou can also drop a file here.", "dim-label",
                      xalign=0.5, wrap=True)
        empty.set_justify(Gtk.Justification.CENTER)
        empty.set_valign(Gtk.Align.CENTER)
        empty.set_margin_start(24)
        empty.set_margin_end(24)
        self.tree_stack.add_named(empty, "empty")
        self.tree_stack.add_named(scroller, "tree")
        self.tree_stack.set_vexpand(True)
        box.append(self.tree_stack)
        return box

    def _build_details(self):
        box = vbox(0)
        head = hbox(10, "scp-head")
        self.node_icon = Gtk.Image.new_from_icon_name("network-workgroup-symbolic")
        self.node_icon.set_pixel_size(28)
        head.append(self.node_icon)
        titles = vbox(1)
        line = hbox(8)
        self.node_title = label("No organization loaded", "headline")
        self.node_title.set_ellipsize(Pango.EllipsizeMode.END)
        line.append(self.node_title)
        self.node_kind = pill("", "scp-count")
        self.node_kind.set_visible(False)
        line.append(self.node_kind)
        self.node_extra = pill("management account", "scp-mgmt")
        self.node_extra.set_visible(False)
        line.append(self.node_extra)
        titles.append(line)
        self.node_path = label("", "dim-label scp-small")
        self.node_path.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        titles.append(self.node_path)
        titles.set_hexpand(True)
        head.append(titles)
        box.append(head)

        split = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        split.set_vexpand(True)
        pol_box = vbox(2)
        sec = label("Policies that apply here", "scp-section")
        sec.set_margin_start(12)
        sec.set_margin_top(4)
        sec.set_margin_bottom(2)
        pol_box.append(sec)
        self.policies = ResultTable(self.POLICY_COLS, on_select=self._policy_selected,
                                    search=False, placeholder="Pick something in the tree.")
        self.policies.set_vexpand(True)
        pol_box.append(self.policies)
        pol_box.set_size_request(300, -1)
        split.set_start_child(pol_box)
        split.set_shrink_start_child(False)

        side = vbox(4)
        side.set_margin_end(10)
        self.side_stack = Gtk.Stack()
        self.side_stack.set_vexpand(True)
        self.blocked_box = vbox(6)
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sc.set_child(self.blocked_box)
        sc.set_vexpand(True)
        self.side_stack.add_titled(sc, "blocked", "What's blocked here")
        self.detail = DetailPane("Select a policy on the left to see its JSON.", title="")
        self.detail.title.set_visible(False)
        self.side_stack.add_titled(self.detail, "json", "Policy JSON")
        switcher = Gtk.StackSwitcher(stack=self.side_stack)
        switcher.set_halign(Gtk.Align.START)
        switcher.set_margin_top(2)
        side.append(switcher)
        side.append(self.side_stack)
        side.set_size_request(260, -1)
        split.set_end_child(side)
        split.set_shrink_end_child(False)
        split.set_resize_end_child(True)
        keep_ratio(split, 0.6)
        self.details_split = split
        box.append(split)
        self._blocked_placeholder("Pick an account, OU or the root to see what's blocked there.")
        return box

    def _build_test(self):
        outer = vbox(4)
        outer.set_margin_top(6)
        head = hbox(8)
        head.set_margin_start(12)
        head.set_margin_end(12)
        head.append(label("Test an action", "scp-box-title"))
        head.append(label("Would SCPs block it, and why? Offline, from what's loaded.",
                          "dim-label scp-small"))
        outer.append(head)
        split = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        split.set_vexpand(True)

        form = vbox(6)
        form.set_margin_start(12)
        form.set_margin_end(8)
        form.set_margin_bottom(8)
        grid = Gtk.Grid(column_spacing=8, row_spacing=6)
        self.account_dd = short_dropdown(["Load an organization first"])
        self.account_dd.set_hexpand(True)
        self.action_entry = Gtk.Entry(placeholder_text="Like s3:DeleteBucket")
        self.resource_entry = Gtk.Entry(placeholder_text="* for any, or an ARN")
        self.resource_entry.set_text("*")
        self.region_entry = Gtk.Entry(placeholder_text="Like us-east-1")
        self.principal_entry = Gtk.Entry(placeholder_text="Role or user ARN (optional)")
        self.context_entry = Gtk.Entry(
            placeholder_text="key=value, like aws:PrincipalTag/team=data")
        self.region_entry.set_tooltip_text("aws:RequestedRegion. Leave empty to see whether "
                                           "the answer depends on it.")
        self.principal_entry.set_tooltip_text("aws:PrincipalArn. A service-linked role isn't "
                                              "affected by SCPs.")
        self.context_entry.set_tooltip_text("More condition keys, separated by spaces. A key "
                                            "given twice gets both values. !key means it isn't "
                                            "set.")
        rows = [("Account", self.account_dd), ("Action", self.action_entry),
                ("Resource", self.resource_entry), ("Region", self.region_entry),
                ("Principal ARN", self.principal_entry), ("More context", self.context_entry)]
        for i, (text, widget) in enumerate(rows):
            lab = label(text, "dim-label")
            grid.attach(lab, 0, i, 1, 1)
            widget.set_hexpand(True)
            grid.attach(widget, 1, i, 1, 1)
            if isinstance(widget, Gtk.Entry):
                widget.connect("activate", lambda *_: self.run_test())
        form.append(grid)
        row = hbox(8)
        self.draft_check = Gtk.CheckButton(label="Try a draft SCP")
        self.draft_check.set_tooltip_text("Paste an SCP to see what it would block before you "
                                          "attach it")
        self.draft_check.connect("toggled", lambda *_: self._draft_toggled())
        row.append(self.draft_check)
        row.append(spacer())
        self.test_btn = button("Test", self.run_test, css="suggested-action",
                               tooltip="Enter in any box does the same")
        self.test_btn.set_size_request(96, -1)
        row.append(self.test_btn)
        form.append(row)

        self.draft_reveal = Gtk.Revealer()
        dbox = vbox(4)
        self.draft_view = Gtk.TextView(monospace=True)
        self.draft_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        for side in ("left", "right", "top", "bottom"):
            getattr(self.draft_view, f"set_{side}_margin")(6)
        self.draft_buffer = self.draft_view.get_buffer()
        self.draft_buffer.connect("changed", lambda *_: self._draft_changed())
        dsc = Gtk.ScrolledWindow()
        dsc.set_child(self.draft_view)
        dsc.set_min_content_height(110)
        dsc.add_css_class("frame")
        dbox.append(dsc)
        arow = hbox(8)
        arow.append(label("Attach at", "dim-label"))
        self.attach_dd = short_dropdown(["Root"])
        self.attach_dd.set_hexpand(True)
        self.attach_dd.connect("notify::selected", lambda *_: self._draft_changed(now=True))
        arow.append(self.attach_dd)
        dbox.append(arow)
        srow = hbox(8)
        self.draft_status = label("Paste an SCP above.", "dim-label scp-small", wrap=True)
        self.draft_status.set_hexpand(True)
        srow.append(self.draft_status)
        open_btn = button("Open file", lambda: open_file(self.win, self._load_draft_file,
                                                         "Open a draft SCP"))
        open_btn.set_valign(Gtk.Align.START)
        srow.append(open_btn)
        dbox.append(srow)
        self.draft_reveal.set_child(dbox)
        form.append(self.draft_reveal)
        fsc = Gtk.ScrolledWindow()
        fsc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        fsc.set_child(form)
        fsc.set_size_request(320, -1)
        split.set_start_child(fsc)
        split.set_shrink_start_child(False)
        split.set_resize_start_child(False)

        res = vbox(6)
        res.set_margin_end(12)
        res.set_margin_bottom(8)
        self.verdict_box = vbox(2, "scp-vb scp-vb-empty")
        vhead = hbox(8)
        self.verdict_label = label("No test yet", "scp-verdict dim-label", wrap=True)
        self.verdict_label.set_hexpand(True)
        vhead.append(self.verdict_label)
        self.copy_btn = button("Copy result", self.copy_result,
                               tooltip="Copy the result and the explanation as text")
        self.copy_btn.add_css_class("flat")
        self.copy_btn.set_valign(Gtk.Align.START)
        self.copy_btn.set_sensitive(False)
        vhead.append(self.copy_btn)
        self.verdict_box.append(vhead)
        self.reason_label = label("Pick an account, type an action and press Test.",
                                  "dim-label", wrap=True, selectable=True)
        self.verdict_box.append(self.reason_label)
        self.unset_label = label("", "scp-small", wrap=True, selectable=True)
        self.unset_label.set_visible(False)
        self.verdict_box.append(self.unset_label)
        res.append(self.verdict_box)
        self.lines_box = vbox(4)
        res.append(self.lines_box)
        self.context_label = label("", "dim-label scp-small", wrap=True, selectable=True)
        res.append(self.context_label)
        rsc = Gtk.ScrolledWindow()
        rsc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        rsc.set_child(res)
        rsc.set_vexpand(True)
        rsc.set_size_request(260, -1)
        self.result_scroller = rsc
        split.set_end_child(rsc)
        split.set_shrink_end_child(False)
        keep_ratio(split, 0.42)
        self.test_split = split
        outer.append(split)
        return outer

    # =============================================================== tree
    def _children(self, item, *_):
        if self.org is None:
            return None
        kids = self._kids.get(item.node.id)
        if not kids:
            return None
        store = Gio.ListStore.new(OrgItem)
        for kid in kids:
            store.append(OrgItem(kid))
        return store

    def _tree_setup(self, factory, list_item):
        expander = Gtk.TreeExpander()
        row = hbox(8)
        row.set_margin_top(3)
        row.set_margin_bottom(3)
        icon = Gtk.Image()
        icon.set_pixel_size(16)
        row.append(icon)
        text = vbox(0)
        name = label("", "scp-name")
        name.set_ellipsize(Pango.EllipsizeMode.END)
        text.append(name)
        ident = label("", "scp-id")
        ident.set_ellipsize(Pango.EllipsizeMode.END)
        text.append(ident)
        text.set_hexpand(True)
        row.append(text)
        badges = hbox(4)
        badges.set_valign(Gtk.Align.CENTER)
        row.append(badges)
        expander.set_child(row)
        expander._parts = (icon, name, ident, badges)
        list_item.set_child(expander)

    def _tree_bind(self, factory, list_item):
        expander = list_item.get_child()
        tree_row = list_item.get_item()
        expander.set_list_row(tree_row)
        node = tree_row.get_item().node
        icon, name, ident, badges = expander._parts
        icon.set_from_icon_name(icon_for(self.org, node))
        name.set_text(node.name or node.id)
        ident.set_text(node.id)
        clear_box(badges)
        org = self.org
        if org is None:
            return
        rcp_full = scpcheck.FULL_ACCESS[scpcheck.RCP][0]
        attached = [(p, a) for p, a in org.attached(node.id) if p.id != rcp_full]
        if node.id == org.management:
            badges.append(pill("mgmt", "scp-mgmt"))
        full = scpcheck.FULL_ACCESS[scpcheck.SCP][0]
        if org.enabled_type(scpcheck.SCP) and node.id != org.management and \
                node.id not in org.unread_targets and not any(p.id == full for p, _ in attached):
            b = pill("allow list", "scp-limit")
            b.set_tooltip_text("FullAWSAccess isn't attached here, so only what the attached "
                               "SCPs allow gets through.")
            badges.append(b)
        if self.draft is not None and self.draft.target == node.id:
            badges.append(pill("draft", "scp-draft"))
        n_scp = sum(1 for p, _ in attached if p.type == scpcheck.SCP)
        n_rcp = sum(1 for p, _ in attached if p.type == scpcheck.RCP)
        if n_scp or n_rcp:
            text = f"{n_scp} SCP{'s' if n_scp != 1 else ''}"
            if n_rcp:
                text += f" · {n_rcp} RCP{'s' if n_rcp != 1 else ''}"
            b = pill(text, "scp-count")
            b.set_tooltip_text("\n".join(
                f"{p.short_type}: {p.name}" + (" (assumed)" if assumed else "")
                for p, assumed in attached))
            badges.append(b)

    def _rebuild_tree(self, keep=None):
        self.tree_store.remove_all()
        if self.org is None or self.org.root not in self.org.nodes:
            self.tree_stack.set_visible_child_name("empty")
            return
        self.tree_store.append(OrgItem(self.org.nodes[self.org.root]))
        self.tree_stack.set_visible_child_name("tree")
        self.select_node(keep if keep in self.org.nodes else self.org.root)

    def select_node(self, node_id):
        for i in range(self.tree_model.get_n_items()):
            row = self.tree_model.get_item(i)
            if row is not None and row.get_item().node.id == node_id:
                self.tree_sel.set_selected(i)
                self.show_node(node_id)
                return True
        return False

    def _tree_selected(self, *_):
        row = self.tree_sel.get_selected_item()
        if row is None:
            return
        node = row.get_item().node
        self.show_node(node.id)
        if node.kind == "account" and node.id in self.account_ids:
            self.account_dd.set_selected(self.account_ids.index(node.id))

    # =============================================================== node details
    def show_node(self, node_id):
        org = self.org
        if org is None or node_id not in org.nodes:
            return
        self.node_id = node_id
        node = org.nodes[node_id]
        self.node_icon.set_from_icon_name(icon_for(org, node))
        self.node_title.set_text(f"{node.name or node.id}")
        self.node_kind.set_text(f"{KIND_WORDS[node.kind]}  {node.id}")
        self.node_kind.set_visible(True)
        self.node_extra.set_visible(node.id == org.management)
        try:
            path = org.path(node_id)
        except scpcheck.ScpError:
            path = [node]
        where = " / ".join(n.name or n.id for n in path)
        if node.guessed_parent:
            where += "   (its place in the tree is a guess, see the note above)"
        self.node_path.set_text(where)
        rows = scpcheck.policy_rows(org, node_id, self.draft)
        for r in rows:
            note = r["note"] if r["note"] in ("assumed", "draft") else ""
            r["shown"] = r["name"] + (f" ({note})" if note else "")
        self.policies.set_rows(rows, rows)
        if not rows:
            self.policies.clear("No SCPs or RCPs apply here.")
        self.detail.set_text("")
        self.detail.title.set_visible(False)
        self.side_stack.set_visible_child_name("blocked")
        self._show_blocked(scpcheck.summarize(org, node_id, self.draft))

    def _policy_selected(self, item):
        if item is None or self.org is None:
            return
        r = item.obj
        if r["draft"] and self.draft is not None:
            pol = self.draft.policy
        else:
            pol = self.org.policies.get(r["policy_id"])
        if pol is None:
            return
        title = pol.display if pol.draft else pol.name
        if r["assumed"]:
            title += ", assumed attached"
        self.detail.title.set_text(f"{title}  ({pol.short_type}, "
                                   f"{self.org.where(r['where_id'])})")
        self.detail.title.set_visible(True)
        if pol.doc is not None:
            text = json.dumps(pol.doc, indent=2)
        else:
            text = pol.error or "Its text isn't known."
        self.detail.set_text(text)
        self.side_stack.set_visible_child_name("json")

    def _blocked_placeholder(self, text):
        clear_box(self.blocked_box)
        w = label(text, "dim-label", wrap=True)
        w.set_margin_top(6)
        self.blocked_box.append(w)

    def _show_blocked(self, summary):
        clear_box(self.blocked_box)
        if summary["exempt"]:
            card = vbox(4, "scp-card")
            top = hbox(6)
            top.append(pill("EXEMPT", "scp-st-allow"))
            top.append(label("Management account", "scp-name"))
            card.append(top)
            card.append(label(summary["exempt"], wrap=True))
            self.blocked_box.append(card)
            return
        for lim in summary["limits"]:
            card = vbox(3, "scp-card")
            top = hbox(6)
            top.append(pill("ALLOW LIST", "scp-limit"))
            top.append(label(lim["where"], "scp-name"))
            card.append(top)
            card.append(label(lim["text"], "scp-small", wrap=True, selectable=True))
            self.blocked_box.append(card)
        for d in summary["denies"]:
            card = vbox(3, "scp-card")
            top = hbox(6)
            top.append(pill("DENY", "scp-st-deny"))
            name = label(("RCP " if d["type"] == "RCP" else "") + d["policy"], "scp-name")
            name.set_ellipsize(Pango.EllipsizeMode.END)
            top.append(name)
            if d["draft"]:
                top.append(pill("draft", "scp-draft"))
            where = label(d["where"], "dim-label scp-small")
            where.set_ellipsize(Pango.EllipsizeMode.END)
            where.set_hexpand(True)
            where.set_xalign(1)
            top.append(where)
            card.append(top)
            card.append(label(d["text"], "scp-small", wrap=True, selectable=True))
            self.blocked_box.append(card)
        if not summary["denies"] and not summary["limits"]:
            self.blocked_box.append(label("Nothing is blocked here. Every level allows "
                                          "everything and nothing is denied.", "dim-label",
                                          wrap=True))
        elif not summary["limits"]:
            self.blocked_box.append(label("No allow lists: every level from the root down "
                                          "allows everything, so only the denies above limit "
                                          "it.", "dim-label scp-small", wrap=True))
        for n in summary["notes"]:
            self.blocked_box.append(label(n, "dim-label scp-small", wrap=True))

    # =============================================================== loading
    def _update_read_tooltip(self):
        who = self.win.profile or "the default credentials"
        self.read_btn.set_tooltip_text(f"Read the org with {who}. Needs the management account "
                                       "or a delegated administrator.")

    def profile_changed(self, profile):
        self._update_read_tooltip()

    def read_aws(self):
        profile = self.win.profile
        cancel = self.new_cancel()
        self.read_btn.set_sensitive(False)
        self.status.busy(f"Reading the organization with {profile or 'the default credentials'}"
                         "...", cancel)
        progress = on_main(self.status.progress)
        run_bg(lambda: scpcheck.read_live(profile, progress=progress, cancel=cancel),
               self.loaded, self.failed)

    def open_state(self):
        open_file(self.win, self.load_path, "Open Terraform state")

    def open_snapshot(self):
        open_file(self.win, self.load_path, "Open snapshot")

    def open_folder(self):
        open_file(self.win, self.load_folder, "Terraform folder", folder=True)

    def load_path(self, path):
        if os.path.isdir(path):
            self.load_folder(path)
            return
        self.status.busy(f"Reading {Path(path).name}...", progress=False)
        run_bg(lambda: scpcheck.load_file(path), self.loaded, self.failed)

    def load_folder(self, folder):
        from . import tfplan
        if not tfplan.terraform_bin():
            show_message(self.win, "Terraform isn't installed",
                         "Reading a folder needs terraform or tofu. Open its state file or the "
                         "output of terraform show -json instead.")
            return
        profile = self.win.profile

        def go():
            self.status.busy(f"Running terraform show in {Path(folder).name}...", progress=False)
            run_bg(lambda: scpcheck.load_folder(folder, profile), self.loaded, self.failed)
        confirm_terraform(self.win, folder, go, what="terraform show")

    def _dropped(self, target, value, x, y):
        files = value.get_files()
        if files and files[0].get_path():
            self.load_path(files[0].get_path())
            return True
        return False

    def loaded(self, org):
        self.read_btn.set_sensitive(True)
        try:
            self.set_org(org)
        except Exception as exc:  # noqa: BLE001 - never leave a half-shown org
            self.failed(exc)
            return
        self.status.idle(f"Loaded {org.summary_line()} at {datetime.now():%H:%M}.")

    def failed(self, exc):
        self.read_btn.set_sensitive(True)
        if isinstance(exc, scpcheck.Cancelled):
            self.status.idle("Stopped. The organization shown, if any, is the one loaded before.")
            return
        self.status.idle("")
        text = str(exc) if isinstance(exc, scpcheck.ScpError) else error_text(exc,
                                                                              self.win.profile)
        show_message(self.win, "Couldn't read the organization", text)

    def set_org(self, org):
        keep = self.node_id
        self.org = org
        self._kids = org.children_map()
        self.draft = None
        self.save_btn.set_sensitive(True)
        self.source_label.set_text(scpcheck.source_short(org))
        self.source_label.set_tooltip_text(f"Organization {org.id or '(ID unknown)'}, read "
                                           f"{org.read_at}")
        c = org.counts()
        self.tree_count.set_text(f"{scpcheck.plural(c['accounts'], 'account')}, "
                                 f"{scpcheck.plural(c['ous'], 'OU')}")
        if org.notes:
            more = len(org.notes) - 2
            self.note_bar.set_text("  ".join(org.notes[:2]) +
                                   (f"  ({more} more note{'s' if more != 1 else ''}, hover to "
                                    "read)" if more > 0 else ""))
            self.note_bar.set_tooltip_text("\n\n".join(org.notes))
            self.note_bar.set_visible(True)
        else:
            self.note_bar.set_visible(False)
        accounts = org.accounts()
        self.account_ids = [a.id for a in accounts]
        labels = [f"{a.name or a.id}  ({a.id})" + ("  management" if a.id == org.management
                                                     else "") for a in accounts]
        self.account_dd.set_model(Gtk.StringList.new(labels or ["No accounts"]))
        walk = org.walk()
        self.target_ids = [n.id for n, _ in walk]
        self.attach_dd.set_model(Gtk.StringList.new(
            ["    " * depth + (n.name or n.id) + (f"  ({n.id})" if n.kind != "root" else "")
             for n, depth in walk]))
        first = next((i for i, a in enumerate(accounts) if a.id != org.management), 0)
        self.account_dd.set_selected(first)
        self._clear_result()
        self._rebuild_tree(keep)
        if self.draft_check.get_active():
            self._draft_changed(now=True)

    def save_snapshot(self):
        if self.org is None:
            return
        dialog = Gtk.FileDialog(title="Save snapshot", initial_name=scpcheck.DEFAULT_SNAPSHOT_NAME)
        org = self.org

        def done(dlg, result):
            try:
                gfile = dlg.save_finish(result)
            except GLib.Error:
                return
            try:
                path = scpcheck.save_snapshot(org, gfile.get_path())
            except OSError as exc:
                show_message(self.win, "Couldn't save the snapshot", str(exc))
                return
            self.status.idle(f"Saved the org to {path}.")
        dialog.save(self.win, None, done)

    # =============================================================== draft
    def _draft_toggled(self):
        on = self.draft_check.get_active()
        self.draft_reveal.set_reveal_child(on)
        if on:
            self.draft_view.grab_focus()
        self._draft_changed(now=True)

    def _draft_text(self):
        b = self.draft_buffer
        return b.get_text(b.get_start_iter(), b.get_end_iter(), False)

    def _draft_changed(self, now=False):
        if self._draft_timer:
            GLib.source_remove(self._draft_timer)
            self._draft_timer = 0
        if now:
            self._check_draft()
        else:
            self._draft_timer = GLib.timeout_add(350, self._check_draft)

    def _check_draft(self):
        self._draft_timer = 0
        old = self.draft
        self.draft = None
        text = self._draft_text()
        status = self.draft_status
        for c in ("scp-ok", "scp-bad", "scp-warn", "dim-label"):
            status.remove_css_class(c)
        if not self.draft_check.get_active():
            status.set_text("Paste an SCP above.")
            status.add_css_class("dim-label")
        elif not text.strip():
            status.set_text("Paste an SCP above. The next Test includes it, as if attached "
                            "where you pick.")
            status.add_css_class("dim-label")
        elif len(text) > scpcheck.MAX_POLICY_TEXT:
            status.set_text("That's over 64 KB. An SCP can be 5,120 characters at most.")
            status.add_css_class("scp-bad")
        else:
            doc, problems, warnings = scpcheck.check_draft(text)
            if problems:
                status.set_text("\n".join(problems))
                status.add_css_class("scp-bad")
            else:
                i = self.attach_dd.get_selected()
                target = self.target_ids[i] if self.org and i < len(self.target_ids) else ""
                n = len(doc["Statement"]) if isinstance(doc["Statement"], list) else 1
                msg = (f"Looks fine: {n} statement{'s' if n != 1 else ''}. "
                       "The next Test includes it.")
                if warnings:
                    msg += " " + " ".join(warnings)
                    status.add_css_class("scp-warn")
                else:
                    status.add_css_class("scp-ok")
                status.set_text(msg)
                if self.org is not None and target:
                    self.draft = scpcheck.Draft(scpcheck.Policy(
                        "draft", "draft SCP", scpcheck.SCP, json.dumps(doc, indent=2),
                        draft=True, doc=doc), target)
        changed = (old is None) != (self.draft is None) or (
            old is not None and self.draft is not None and
            (old.target != self.draft.target or old.policy.text != self.draft.policy.text))
        if changed and self.org is not None:
            self._rebuild_tree(self.node_id)
        return False

    def _load_draft_file(self, path):
        try:
            p = Path(path)
            if p.stat().st_size > scpcheck.MAX_POLICY_TEXT:
                show_message(self.win, "That file is too big",
                             "It's over 64 KB. An SCP can be 5,120 characters at most.")
                return
            self.draft_buffer.set_text(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            show_message(self.win, "Couldn't open the file", str(exc))

    # =============================================================== testing
    def run_test(self):
        if self.org is None:
            self._show_error("Load an organization first",
                             "Read it from AWS, or open a Terraform state, a folder or a "
                             "snapshot.")
            return
        i = self.account_dd.get_selected()
        if not self.account_ids or i >= len(self.account_ids):
            self._show_error("There are no accounts to test", "This organization has no "
                             "accounts in what was loaded.")
            return
        if self.draft_check.get_active():
            if self._draft_timer:
                self._draft_changed(now=True)
            if self.draft is None and self._draft_text().strip():
                self._show_error("The draft SCP has problems", self.draft_status.get_text())
                return
        try:
            v = scpcheck.check_action(
                self.org, self.account_ids[i], self.action_entry.get_text(),
                self.resource_entry.get_text(), self.region_entry.get_text(),
                self.principal_entry.get_text().strip(), self.context_entry.get_text(),
                self.draft if self.draft_check.get_active() else None)
        except scpcheck.ScpError as exc:
            self._show_error("Can't run that test", str(exc))
            return
        self.show_verdict(v)

    def _set_verdict_style(self, kind):
        for c in ("scp-vb-allowed", "scp-vb-denied", "scp-vb-depends", "scp-vb-error",
                  "scp-vb-empty"):
            self.verdict_box.remove_css_class(c)
        self.verdict_box.add_css_class(f"scp-vb-{kind}")
        for c in ("scp-v-allowed", "scp-v-denied", "scp-v-depends", "scp-v-error",
                  "dim-label"):
            self.verdict_label.remove_css_class(c)
        self.verdict_label.add_css_class("dim-label" if kind == "empty" else f"scp-v-{kind}")

    def _clear_result(self):
        self.verdict = None
        self._set_verdict_style("empty")
        self.verdict_label.set_text("No test yet")
        self.reason_label.set_text("Pick an account, type an action and press Test.")
        self.reason_label.add_css_class("dim-label")
        self.unset_label.set_visible(False)
        clear_box(self.lines_box)
        self.context_label.set_text("")
        self.copy_btn.set_sensitive(False)

    def _show_error(self, heading, text):
        self.verdict = None
        self._set_verdict_style("error")
        self.verdict_label.set_text(heading)
        self.reason_label.remove_css_class("dim-label")
        self.reason_label.set_text(text)
        self.unset_label.set_visible(False)
        clear_box(self.lines_box)
        self.context_label.set_text("")
        self.copy_btn.set_sensitive(False)

    def show_verdict(self, v):
        self.verdict = v
        self._set_verdict_style(v.outcome)
        self.verdict_label.set_text(v.headline)
        self.reason_label.remove_css_class("dim-label")
        self.reason_label.set_text(v.reason)
        if v.if_unset:
            keys = scpcheck.unset_keys(v)
            self.unset_label.set_text(f"If {scpcheck.join(keys)} "
                                      f"{'is' if len(keys) == 1 else 'are'} not set: "
                                      f"{v.if_unset['headline']}.")
            self.unset_label.set_visible(True)
        else:
            self.unset_label.set_visible(False)
        clear_box(self.lines_box)
        part = None
        for ln in v.lines:
            if ln["part"] != part and ln["part"] in ("SCP", "RCP"):
                part = ln["part"]
                head = label("Service control policies, from the root down" if part == "SCP"
                             else "Resource control policies, for the resource's account",
                             "scp-section")
                head.set_margin_top(2)
                self.lines_box.append(head)
            row = hbox(8)
            tag = pill(STATUS_WORDS.get(ln["status"], ln["status"].upper()),
                       f"scp-st-{ln['status']}")
            tag.set_valign(Gtk.Align.START)
            tag.set_size_request(76, -1)
            row.append(tag)
            body = vbox(0)
            top = hbox(6)
            top.append(label(ln["where"], "scp-name scp-small"))
            if ln["draft"]:
                top.append(pill("draft", "scp-draft"))
            body.append(top)
            body.append(label(ln["text"], "scp-small", wrap=True, selectable=True))
            body.set_hexpand(True)
            row.append(body)
            self.lines_box.append(row)
        org_notes = set(self.org.notes) if self.org else set()
        notes = [n for n in v.notes if n not in org_notes]
        for n in notes:
            self.lines_box.append(label("Note: " + n, "dim-label scp-small", wrap=True))
        if v.context:
            self.context_label.set_text("Context used: " + "; ".join(
                f"{c['key']}={c['value']} ({c['from']})" for c in v.context))
        else:
            self.context_label.set_text("")
        self.copy_btn.set_sensitive(True)

    def copy_result(self):
        if self.verdict is not None:
            set_clipboard(self, scpcheck.verdict_text(self.verdict, use_color=False))
            flash(self.copy_btn, "Copied")

    # used by scripts and tests that fill the form
    def fill_test(self, account=None, action="", resource="", region="", principal="",
                  context=""):
        if account is not None and self.org is not None:
            node = self.org.find(account, ("account",))
            self.account_dd.set_selected(self.account_ids.index(node.id))
        self.action_entry.set_text(action)
        self.resource_entry.set_text(resource or "*")
        self.region_entry.set_text(region)
        self.principal_entry.set_text(principal)
        self.context_entry.set_text(context)
