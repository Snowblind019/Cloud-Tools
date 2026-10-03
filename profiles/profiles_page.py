"""Profiles page and the small profile picker window."""
from __future__ import annotations

from gi.repository import Gdk, GLib, Gtk, Pango

from . import profiles
from .widgets import (Page, ResultTable, button, flash, hbox, label, margins, run_bg,
                      set_clipboard, spacer, string_dropdown, vbox)


class ProfilesView(Gtk.Box):
    """Profile list with Use, Sign in and Check. Used by the page and the picker window."""

    COLS = [("current", "", {"width": 70}), ("name", "Profile", {"width": 200}),
            ("kind", "Type", {"width": 80}), ("account", "Account", {"width": 125, "kind": "mono"}),
            ("role", "Role", {"width": 190}), ("region", "Region", {"width": 100}),
            ("status", "Status", {"expand": True})]

    def __init__(self, win, compact=False, on_picked=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.win = win
        self.on_picked = on_picked
        self.checked = {}
        cols = self.COLS if not compact else [c for c in self.COLS if c[0] != "region"]
        self.table = ResultTable(cols, on_activate=self.use,
                                 placeholder="No profiles found in ~/.aws/config or "
                                             "~/.aws/credentials.\nRun aws configure sso to add one.")
        self.table.set_vexpand(True)
        if self.table.search:
            self.table.search.set_placeholder_text("Type to filter, Enter to pick")
            self.table.search.connect("activate", self.search_enter)
        self.append(self.table)
        bar = hbox(6)
        margins(bar, 8)
        bar.append(button("Use this profile", self.use, css="suggested-action"))
        bar.append(button("Sign in (SSO)", self.login,
                          tooltip="Runs aws sso login, which opens your browser"))
        if not compact:
            bar.append(button("Check all", self.check_all,
                              tooltip="Calls sts get-caller-identity for each profile"))
            bar.append(button("No profile", self.clear,
                              tooltip="Go back to the default credential chain"))
        bar.append(spacer())
        self.msg = label("", "dim-label")
        self.msg.set_ellipsize(Pango.EllipsizeMode.END)
        self.msg.set_hexpand(True)
        bar.append(self.msg)
        bar.append(button("Refresh", self.reload))
        self.append(bar)
        self.reload()

    def reload(self):
        current = profiles.current_profile()
        rows, objs = [], []
        for p in profiles.list_profiles():
            rows.append({"current": "current" if p["name"] == current else "", "name": p["name"],
                         "kind": p["kind"], "account": p["account"], "role": p["role"],
                         "region": p["region"],
                         "status": self.checked.get(p["name"]) or profiles.offline_status(p)})
            objs.append(p)
        self.table.set_rows(rows, objs)

    def chosen(self, row=None):
        row = row or self.table.selected_item()
        if row is None:
            self.msg.set_text("Select a profile first.")
        return row

    def use(self, row=None):
        row = self.chosen(row)
        if row is None:
            return
        name = row.obj["name"]
        self.win.set_profile(name)
        status = profiles.offline_status(row.obj)
        self.reload()
        if status in ("expired", "not signed in"):
            self.msg.set_text(f"Using {name}, but it isn't signed in. Press Sign in.")
            return
        self.msg.set_text(f"Using {name}. Terminals with the shell hook switch at their next prompt.")
        if self.on_picked:
            self.on_picked(name)

    def search_enter(self, entry):
        rows = self.table.visible_items()
        if rows:
            self.use(rows[0])

    def clear(self):
        self.win.set_profile(None)
        self.msg.set_text("No profile picked. Tools use the default credential chain.")
        self.reload()

    def login(self):
        row = self.chosen()
        if row is None:
            return
        name = row.obj["name"]
        if row.obj["kind"] != "sso":
            self.msg.set_text(f"{name} isn't an SSO profile, so there's nothing to sign in to.")
            return
        self.msg.set_text(f"Opening the browser to sign in to {name}...")

        def done(result):
            ok, message = result
            self.msg.set_text(message)
            self.checked.pop(name, None)
            self.reload()
            if ok:
                self.win.set_profile(name)
                self.reload()
                if self.on_picked:
                    self.on_picked(name)
        run_bg(lambda: profiles.sso_login(name), done)

    def check_all(self):
        names = [p["name"] for p in profiles.list_profiles()]
        if not names:
            return
        self.msg.set_text(f"Checking {len(names)} profile(s)...")

        def work():
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as pool:
                return dict(zip(names, pool.map(profiles.check_profile, names)))

        def done(results):
            for name, r in results.items():
                self.checked[name] = (f"ok, {r['arn'].split(':')[-1]}" if r["status"] == "ok"
                                      else r["message"])
            ok = sum(1 for r in results.values() if r["status"] == "ok")
            self.msg.set_text(f"{ok} of {len(results)} working.")
            self.reload()
        run_bg(work, done)


class ProfilesPage(Page):
    name = "profiles"
    title = "Profiles"
    SHELLS = ["bash", "zsh", "fish"]

    def __init__(self, win):
        super().__init__(win, "Pick which AWS profile your terminals and this window use. The "
                         "pick is saved to ~/.config/awskit/current-profile, and the shell hook "
                         "picks it up at the next prompt.")
        self.view = ProfilesView(win)
        self.view.set_vexpand(True)
        self.append(self.view)

        setup = vbox(6)
        margins(setup, 12)
        setup.append(label("Shell setup", "heading"))
        setup.append(label("Add this line to your shell config to get awsp and the prompt helper. "
                           "Then awsp opens a small picker, awsp NAME switches directly, and every "
                           "open terminal follows.", "dim-label", wrap=True))
        row = hbox(6)
        self.shell = string_dropdown(self.SHELLS)
        row.append(self.shell)
        self.snippet = label("", "mono", selectable=True)
        self.snippet.set_hexpand(True)
        row.append(self.snippet)
        self.copy_btn = button("Copy", self.copy_snippet)
        row.append(self.copy_btn)
        setup.append(row)
        setup.append(label("To show the profile in a bash prompt, add PS1='$(__awskit_ps1)'\"$PS1\" "
                           "after that line. Starship already shows it with its aws module.",
                           "dim-label", wrap=True))
        self.append(setup)
        self.shell.connect("notify::selected", lambda *_: self.update_snippet())
        self.update_snippet()

    def update_snippet(self):
        shell = self.SHELLS[self.shell.get_selected()]
        rc = {"bash": "~/.bashrc", "zsh": "~/.zshrc", "fish": "~/.config/fish/config.fish"}[shell]
        line = ("awskit shell-init fish | source" if shell == "fish"
                else f'eval "$(awskit shell-init {shell})"')
        self.snippet.set_text(line)
        self.snippet.set_tooltip_text(f"Add to {rc}")

    def copy_snippet(self):
        set_clipboard(self, self.snippet.get_text())
        flash(self.copy_btn, "Copied")

    def profile_changed(self, profile):
        self.view.reload()

    def profiles_changed(self):
        self.view.reload()


class PickerWindow(Gtk.ApplicationWindow):
    """Small window for a keybind: type to filter, Enter to pick, Esc to close."""

    def __init__(self, app):
        super().__init__(application=app, title="AWS profile")
        self.set_default_size(780, 440)
        self.profile = profiles.current_profile()
        self.view = ProfilesView(self, compact=True, on_picked=lambda name: self.close())
        self.set_child(self.view)
        keys = Gtk.EventControllerKey()
        keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        keys.connect("key-pressed", self.key)
        self.add_controller(keys)
        if self.view.table.search:
            GLib.idle_add(self._focus)

    def _focus(self):
        self.view.table.search.grab_focus()
        return False

    def key(self, ctrl, keyval, code, state):
        if keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False

    def set_profile(self, name):
        self.profile = name
        profiles.set_current_profile(name)
