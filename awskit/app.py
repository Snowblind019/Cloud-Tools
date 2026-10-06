"""AWS Kit's windows: the main window with a sidebar of tools, plus the small profile
picker, PII Redact paste window, PII Redact settings window and Image Redact window for
keybinds."""
from __future__ import annotations

import sys

from .common import prepare_gtk_env

# Has to happen before GTK loads, or GTK 4 can crash on WSL. See prepare_gtk_env.
prepare_gtk_env()

try:
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gio, GLib, Gtk
except (ImportError, ValueError) as exc:
    if sys.platform == "win32":
        sys.exit(f"GTK 4 isn't set up ({exc}).\n"
                 "Run install-windows.cmd from the Cloud-Tools folder. It installs GTK for "
                 "your user, without admin.\n"
                 "Every tool also works from the terminal: awskit --help")
    sys.exit(f"GTK 4 for Python is missing ({exc}).\n"
             "Fedora:        sudo dnf install python3-gobject gtk4\n"
             "Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0\n"
             "Arch:          sudo pacman -S python-gobject gtk4\n"
             "Every tool also works from the terminal: awskit --help")

from . import profiles  # noqa: E402
from .common import (APP_ID, APP_NAME, CURRENT_PROFILE_FILE, IMAGE_APP_ID,  # noqa: E402
                     PICKER_APP_ID, REDACT_APP_ID, REDACT_SETTINGS_APP_ID, VERSION)
from .audit_page import AuditPage  # noqa: E402
from .creds_page import CredsPage  # noqa: E402
from .drift_page import DriftPage  # noqa: E402
from .image_page import ImagePage, ImageWindow  # noqa: E402
from .leastpriv_page import LeastPrivPage  # noqa: E402
from .map_page import MapPage  # noqa: E402
from .plan_page import PlanPage  # noqa: E402
from .policy_page import PolicyPage  # noqa: E402
from .profiles_page import PickerWindow, ProfilesPage  # noqa: E402
from .redact_page import RedactPage, RedactSettingsWindow, RedactWindow  # noqa: E402
from .scp_page import ScpPage  # noqa: E402
from .secrets_page import SecretsPage  # noqa: E402
from .sweep_page import SweepPage  # noqa: E402
from .trail_page import TrailPage  # noqa: E402
from .widgets import button, clear_box, hbox, install_css, label, margins, vbox  # noqa: E402

PAGE_CLASSES = [RedactPage, ImagePage, SecretsPage, SweepPage, AuditPage, CredsPage, TrailPage,
                LeastPrivPage, PlanPage, DriftPage, PolicyPage, ScpPage, ProfilesPage, MapPage]
PAGES = [cls.name for cls in PAGE_CLASSES]

# Small windows that open on their own, for keybinds and launcher entries.
MODES = {"picker": PICKER_APP_ID, "redact-window": REDACT_APP_ID,
         "redact-settings": REDACT_SETTINGS_APP_ID, "image-window": IMAGE_APP_ID}


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app, page=None):
        super().__init__(application=app, title=APP_NAME)
        self.set_default_size(1240, 800)
        self.profile = profiles.current_profile()

        header = Gtk.HeaderBar()
        self.set_titlebar(header)
        self.profile_btn = Gtk.MenuButton()
        self.profile_btn.set_tooltip_text("The AWS profile this window and your terminals use")
        self.profile_pop = Gtk.Popover()
        self.profile_pop.connect("show", lambda *_: self.fill_profile_menu())
        self.profile_btn.set_popover(self.profile_pop)
        header.pack_end(self.profile_btn)
        about = Gtk.MenuButton(icon_name="open-menu-symbolic")
        about_pop = Gtk.Popover()
        about_box = vbox(4)
        margins(about_box, 10)
        about_box.append(label(f"{APP_NAME} {VERSION}", "heading"))
        about_box.append(label("Ctrl+1 to Ctrl+9 open the first nine pages, and Ctrl+Page Up "
                               "and Ctrl+Page Down go through all of them.\nEvery tool also runs "
                               "in the terminal: awskit --help", "dim-label", wrap=True))
        about_pop.set_child(about_box)
        about.set_popover(about_pop)
        header.pack_end(about)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_hexpand(True)
        self.pages = {}
        for cls in PAGE_CLASSES:
            p = cls(self)
            self.pages[cls.name] = p
            self.stack.add_titled(p, cls.name, cls.title)
        sidebar = Gtk.StackSidebar(stack=self.stack)
        sidebar.set_size_request(170, -1)
        body = hbox(0)
        body.append(sidebar)
        body.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        body.append(self.stack)
        self.set_child(body)
        self.update_profile_button()
        if page in self.pages:
            self.stack.set_visible_child_name(page)

        shortcuts = Gtk.ShortcutController()
        shortcuts.set_scope(Gtk.ShortcutScope.GLOBAL)
        for n, cls in enumerate(PAGE_CLASSES[:9], 1):
            shortcuts.add_shortcut(Gtk.Shortcut(
                trigger=Gtk.ShortcutTrigger.parse_string(f"<Control>{n}"),
                action=Gtk.CallbackAction.new(self._goto, cls.name)))
        for key, step in (("Page_Down", 1), ("Page_Up", -1)):
            shortcuts.add_shortcut(Gtk.Shortcut(
                trigger=Gtk.ShortcutTrigger.parse_string(f"<Control>{key}"),
                action=Gtk.CallbackAction.new(self._step, step)))
        self.add_controller(shortcuts)

        # Follow profile switches made from a terminal with awsp.
        try:
            self.monitor = Gio.File.new_for_path(str(CURRENT_PROFILE_FILE)).monitor_file(
                Gio.FileMonitorFlags.NONE, None)
            self.monitor.connect("changed", self._profile_file_changed)
        except GLib.Error:
            self.monitor = None

    def _goto(self, widget, args, name):
        self.show_page(name)
        return True

    def _step(self, widget, args, step):
        names = [cls.name for cls in PAGE_CLASSES]
        current = self.stack.get_visible_child_name()
        i = names.index(current) if current in names else 0
        self.show_page(names[(i + step) % len(names)])
        return True

    def show_page(self, name):
        if name in self.pages:
            self.stack.set_visible_child_name(name)

    # ---- profile switching
    def update_profile_button(self):
        self.profile_btn.set_label(f"Profile: {self.profile or 'default chain'}")

    def fill_profile_menu(self):
        box = vbox(2)
        margins(box, 8)
        box.append(label("Use profile", "heading"))
        listing = profiles.list_profiles()
        if not listing:
            box.append(label("No profiles in ~/.aws/config yet.", "dim-label"))
        for p in listing:
            status = profiles.offline_status(p)
            text = p["name"] + (f"   {p['account']}" if p["account"] else "")
            b = Gtk.ToggleButton(label=text)
            b.set_active(p["name"] == self.profile)
            b.add_css_class("flat")
            if status:
                b.set_tooltip_text(status)
            b.connect("clicked", lambda _b, name=p["name"]: self._pick(name))
            box.append(b)
        box.append(Gtk.Separator())
        none = Gtk.Button(label="No profile (default credential chain)")
        none.add_css_class("flat")
        none.connect("clicked", lambda *_: self._pick(None))
        box.append(none)
        manage = Gtk.Button(label="Manage profiles")
        manage.add_css_class("flat")
        manage.connect("clicked", lambda *_: (self.profile_pop.popdown(), self.show_page("profiles")))
        box.append(manage)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_propagate_natural_height(True)
        scroller.set_propagate_natural_width(True)
        scroller.set_max_content_height(480)
        scroller.set_child(box)
        self.profile_pop.set_child(scroller)

    def _pick(self, name):
        self.profile_pop.popdown()
        self.set_profile(name)

    def set_profile(self, name):
        profiles.set_current_profile(name)
        self._apply_profile(name)

    def _apply_profile(self, name):
        if name == self.profile:
            return
        self.profile = name
        self.update_profile_button()
        for p in self.pages.values():
            p.profile_changed(name)

    def _profile_file_changed(self, monitor, gfile, other, event):
        if event in (Gio.FileMonitorEvent.CHANGES_DONE_HINT, Gio.FileMonitorEvent.CREATED,
                     Gio.FileMonitorEvent.DELETED):
            self._apply_profile(profiles.current_profile())


class App(Gtk.Application):
    def __init__(self, page=None, initial_text=None, initial_file=None, paste=False):
        flags = getattr(Gio.ApplicationFlags, "DEFAULT_FLAGS", Gio.ApplicationFlags.FLAGS_NONE)
        if initial_text is not None or initial_file or paste:
            flags |= Gio.ApplicationFlags.NON_UNIQUE  # pre-filled windows always open fresh
        super().__init__(application_id=MODES.get(page, APP_ID), flags=flags)
        self.page = page
        self.initial_text = initial_text
        self.initial_file = initial_file
        self.paste = paste
        action = Gio.SimpleAction.new("show-page", GLib.VariantType.new("s"))
        action.connect("activate", self._show_page)
        self.add_action(action)
        quit_action = Gio.SimpleAction.new("quit", None)
        # Closing each window instead of quitting outright lets Image Redact ask about
        # unsaved changes first.
        quit_action.connect("activate", lambda *_: [w.close() for w in list(self.get_windows())])
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])

    def do_startup(self):
        Gtk.Application.do_startup(self)
        install_css()

    def do_activate(self):
        win = self.get_active_window()
        if win is None:
            if self.page == "picker":
                win = PickerWindow(self)
            elif self.page == "redact-window":
                win = RedactWindow(self, self.initial_text)
            elif self.page == "redact-settings":
                win = RedactSettingsWindow(application=self)
            elif self.page == "image-window":
                win = ImageWindow(self, self.initial_file, self.paste)
            else:
                win = MainWindow(self, self.page)
        win.present()

    def _show_page(self, action, value):
        win = self.get_active_window()
        if isinstance(win, MainWindow):
            win.show_page(value.get_string())


def main(page=None, initial_text=None, initial_file=None, paste=False) -> int:
    app = App(page, initial_text, initial_file, paste)
    try:
        app.register(None)
    except GLib.Error:
        pass
    if app.get_is_remote() and page in PAGES:
        # Already open: switch the running window to the asked-for page.
        app.activate_action("show-page", GLib.Variant.new_string(page))
    return app.run([sys.argv[0]])


__all__ = ["main", "App", "MainWindow", "PAGES", "button", "clear_box"]
