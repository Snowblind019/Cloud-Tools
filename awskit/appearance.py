"""Appearance for every AWS Kit window: light or dark (or follow the system), a color
scheme, an accent color and the text size. theme.py does the colors; this applies them to
GTK, keeps every open AWS Kit window in step, and has the Appearance window."""
from __future__ import annotations

import subprocess
import sys
import threading

from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from . import theme
from .common import CONFIG_FILE, is_wsl, load_config, save_config, windows_tool

# Over GTK's own theme, under AWS Kit's own rules and the user's gtk.css.
THEME_PRIORITY = Gtk.STYLE_PROVIDER_PRIORITY_SETTINGS + 100
ACCENT_PRIORITY = Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 10
THEME_DIR = "/org/gtk/libgtk/theme/Default"


class _State:
    provider = None           # the recolored theme
    accent_provider = None    # AWS Kit's own blue bits, in the accent color
    applied = None            # (settings, variant) last applied
    base_font = None          # gtk-font-name before any text size change
    font_changed = False
    initial_dark = None       # what GTK chose by itself, before anything here changed it
    css_cache = {}
    monitor = None
    portal = None
    started = False
    wsl_asked = False
    wsl_dark = None           # Windows' answer, once reg.exe has given it
    listeners = []            # called with the variant after every change


# =================================================================== settings

def load_settings() -> dict:
    return theme.clean_settings(load_config().get("appearance"))


def save_settings(settings: dict) -> bool:
    cfg = load_config()
    cfg["appearance"] = theme.clean_settings(settings)
    return save_config(cfg)


# =================================================================== GTK's theme

def stock_css(variant: str):
    """GTK's built-in stylesheet for light or dark, from the running GTK. None if this GTK
    doesn't have it where it's expected (very old or very new GTK)."""
    if variant in _State.css_cache:
        return _State.css_cache[variant]
    text = None
    for path in (f"{THEME_DIR}/Default-{variant}.css",):
        try:
            data = Gio.resources_lookup_data(path, Gio.ResourceLookupFlags.NONE)
            text = data.get_data().decode("utf-8")
            break
        except (GLib.Error, UnicodeDecodeError):
            continue
    _State.css_cache[variant] = text
    return text


def _settings():
    return Gtk.Settings.get_default()


def _has_setting(name: str) -> bool:
    try:
        return Gtk.Settings.find_property(name) is not None
    except (AttributeError, TypeError):
        return False


def _gtk_dark_now() -> bool:
    s = _settings()
    if s is None:
        return False
    if _has_setting("gtk-interface-color-scheme"):
        try:
            if s.get_property("gtk-interface-color-scheme") == Gtk.InterfaceColorScheme.DARK:
                return True
        except (AttributeError, TypeError):
            pass
    try:
        if s.get_property("gtk-application-prefer-dark-theme"):
            return True
        return "dark" in (s.get_property("gtk-theme-name") or "").lower()
    except TypeError:
        return False


def _set_gtk_dark(dark: bool):
    s = _settings()
    if s is None:
        return
    if _has_setting("gtk-interface-color-scheme"):      # GTK 4.20 and newer
        try:
            s.set_property("gtk-interface-color-scheme", Gtk.InterfaceColorScheme.DARK if dark
                           else Gtk.InterfaceColorScheme.LIGHT)
            return
        except (AttributeError, TypeError):
            pass
    try:
        s.set_property("gtk-application-prefer-dark-theme", dark)
    except TypeError:
        pass


# =================================================================== the system's choice

def _portal_scheme():
    """1 dark, 2 light, 0 no preference, None when the desktop portal can't say."""
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    except GLib.Error:
        return None
    for method, unwrap in (("ReadOne", 1), ("Read", 2)):
        try:
            res = bus.call_sync("org.freedesktop.portal.Desktop",
                                "/org/freedesktop/portal/desktop",
                                "org.freedesktop.portal.Settings", method,
                                GLib.Variant("(ss)", ("org.freedesktop.appearance",
                                                      "color-scheme")),
                                None, Gio.DBusCallFlags.NONE, 400, None)
        except GLib.Error:
            continue
        value = res.get_child_value(0)
        for _ in range(unwrap):
            if value.get_type_string() == "v":
                value = value.get_variant()
        try:
            return int(value.unpack())
        except (TypeError, ValueError):
            return None
    return None


def _windows_dark():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows"
                            r"\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except (ImportError, OSError):
        return None


def _wsl_dark():
    """Windows' app setting, read from WSL with Windows' own reg.exe. It's looked for on
    the PATH too, since Windows' drive isn't at /mnt/c when wsl.conf moves it."""
    reg = windows_tool("reg.exe")
    if not reg:
        return None
    try:
        r = subprocess.run([reg, "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                            r"\Themes\Personalize", "/v", "AppsUseLightTheme"],
                           capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in r.stdout.splitlines():
        if "AppsUseLightTheme" in line:
            return line.split()[-1].lower() in ("0x0", "0")
    return None


def _ask_windows_from_wsl():
    """reg.exe can take a moment to start from WSL, so it runs in the background, and the
    windows change when it answers. One question at a time."""
    if _State.wsl_asked:
        return
    _State.wsl_asked = True

    def work():
        found = _wsl_dark()

        def done():
            _State.wsl_asked = False
            if found is not None and found != _State.wsl_dark:
                _State.wsl_dark = found
                _State.applied = None
                apply()
            return False
        GLib.idle_add(done)
    threading.Thread(target=work, daemon=True).start()


def _recheck_system():
    """Windows and WSL have no signal for a change of Windows' app color, so with Follow
    system it's read again every so often."""
    settings = _State.applied[0] if _State.applied else None
    if settings is None or settings["style"] != "system":
        return True
    if is_wsl():
        if _State.wsl_dark is not None:
            _ask_windows_from_wsl()
    elif sys.platform == "win32":
        found = _windows_dark()
        if found is not None and found != (_State.applied[1] == "dark"):
            _State.applied = None
            apply()
    return True


def system_dark() -> bool:
    """Whether the desktop asks for dark apps."""
    if _State.initial_dark is None:
        _State.initial_dark = _gtk_dark_now()
    if sys.platform == "win32":
        found = _windows_dark()
    elif is_wsl():
        _ask_windows_from_wsl()
        found = _State.wsl_dark
    else:
        scheme = _portal_scheme()
        # 0 is "no preference", which desktops use for their default light look
        found = None if scheme is None else scheme == 1
    return _State.initial_dark if found is None else found


def resolve_variant(settings: dict) -> str:
    if settings["style"] in ("light", "dark"):
        return settings["style"]
    return "dark" if system_dark() else "light"


# =================================================================== applying

def _load_provider(attr: str, css: str, priority: int):
    display = Gdk.Display.get_default()
    if display is None:
        return
    old = getattr(_State, attr)
    if not css:
        if old is not None:
            Gtk.StyleContext.remove_provider_for_display(display, old)
            setattr(_State, attr, None)
        return
    provider = old or Gtk.CssProvider()
    try:
        provider.load_from_string(css)
    except AttributeError:  # GTK before 4.12
        data = css.encode("utf-8")
        try:
            provider.load_from_data(data, len(data))
        except TypeError:
            provider.load_from_data(data)
    if old is None:
        Gtk.StyleContext.add_provider_for_display(display, provider, priority)
        setattr(_State, attr, provider)


def theme_css(settings: dict, variant: str) -> str:
    """The recolored stylesheet for these settings, or "" when GTK's own is right."""
    if not theme.needs_css(settings):
        return ""
    css = stock_css(variant)
    if css is None:
        return ""
    return theme.recolor(css, variant, settings["colors"], theme.accent_hex(settings),
                         asset_base=f"resource://{THEME_DIR}/")


def _apply_text_size(percent: int):
    s = _settings()
    if s is None:
        return
    if _State.base_font is None:
        _State.base_font = s.get_property("gtk-font-name") or ""
    base = _State.base_font
    if not base:
        return
    desc = Pango.FontDescription.from_string(base)
    size = desc.get_size()
    if percent == 100 or size <= 0:
        # Only put back what was changed here, so GTK keeps following the desktop's font
        if _State.font_changed:
            s.set_property("gtk-font-name", base)
            _State.font_changed = False
        return
    new = desc.copy()
    if desc.get_size_is_absolute():
        new.set_absolute_size(size * percent / 100)
    else:
        new.set_size(int(size * percent / 100))
    s.set_property("gtk-font-name", new.to_string())
    _State.font_changed = True


def apply(settings: dict = None) -> str:
    """Apply appearance settings (the saved ones by default) to every window of this
    process. Returns "light" or "dark"."""
    settings = theme.clean_settings(load_settings() if settings is None else settings)
    if _State.initial_dark is None:
        _State.initial_dark = _gtk_dark_now()
    variant = resolve_variant(settings)
    if _State.applied != (settings, variant):
        _set_gtk_dark(variant == "dark")
        _load_provider("provider", theme_css(settings, variant), THEME_PRIORITY)
        _load_provider("accent_provider", theme.accent_css(
            theme.variant_accent(theme.accent_hex(settings), variant)), ACCENT_PRIORITY)
        _apply_text_size(settings["text_size"])
        _State.applied = (dict(settings), variant)
        for fn in list(_State.listeners):
            try:
                fn(variant)
            except Exception:  # noqa: BLE001 - a listener mustn't stop the others
                pass
    return variant


def on_change(fn):
    """Call fn(variant) after every appearance change in this process."""
    _State.listeners.append(fn)


def current_accent() -> str:
    """The accent in use, for AWS Kit's own drawing. GTK's blue when none is picked."""
    settings, variant = _State.applied if _State.applied else (load_settings(), "light")
    return theme.variant_accent(theme.accent_hex(settings), variant) or theme.GTK_ACCENT


def start():
    """At startup: apply the saved appearance, then follow changes made in another AWS Kit
    window (through the config file) and the desktop's light or dark switch."""
    if _State.started:
        return
    _State.started = True
    apply()
    try:
        _State.monitor = Gio.File.new_for_path(str(CONFIG_FILE)).monitor_file(
            Gio.FileMonitorFlags.NONE, None)
        _State.monitor.connect("changed", _config_changed)
    except GLib.Error:
        _State.monitor = None
    if sys.platform == "win32" or is_wsl():
        GLib.timeout_add_seconds(45, _recheck_system)
    else:
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            _State.portal = bus.signal_subscribe(
                "org.freedesktop.portal.Desktop", "org.freedesktop.portal.Settings",
                "SettingChanged", "/org/freedesktop/portal/desktop",
                "org.freedesktop.appearance", Gio.DBusSignalFlags.NONE, _portal_changed)
        except GLib.Error:
            _State.portal = None


_pending = [0]


def _config_changed(monitor, gfile, other, event):
    if event == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED or _pending[0]:
        return

    def later():
        _pending[0] = 0
        apply()
        return False
    _pending[0] = GLib.timeout_add(250, later)


def _portal_changed(conn, sender, path, iface, signal, params):
    try:
        namespace, key, _value = params.unpack()
    except (TypeError, ValueError):
        return
    if namespace == "org.freedesktop.appearance" and key == "color-scheme":
        _State.applied = None                  # the same settings can mean a new variant
        apply()


# =================================================================== the window

def _set_rgb(cr, rgb, alpha=1.0):
    cr.set_source_rgba(rgb[0], rgb[1], rgb[2], alpha)


def _rounded(cr, x, y, w, h, r):
    import math
    cr.new_sub_path()
    cr.arc(x + w - r, y + r, r, -math.pi / 2, 0)
    cr.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
    cr.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
    cr.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
    cr.close_path()


class SchemeCard(Gtk.DrawingArea):
    """A little drawing of a window in a color scheme."""

    def __init__(self):
        super().__init__()
        self.colors = None
        self.set_content_width(116)
        self.set_content_height(70)
        self.set_draw_func(self._draw)

    def set_colors(self, colors):
        self.colors = colors
        self.queue_draw()

    def _draw(self, area, cr, w, h):
        c = self.colors
        if not c:
            return
        _rounded(cr, 0.5, 0.5, w - 1, h - 1, 7)
        cr.save()
        cr.clip_preserve()
        _set_rgb(cr, c["bg"])
        cr.fill()
        _set_rgb(cr, c["header"])
        cr.rectangle(0, 0, w, 15)
        cr.fill()
        _set_rgb(cr, c["view"])
        cr.rectangle(32, 15, w - 32, h - 15)
        cr.fill()
        _set_rgb(cr, c["fg"], 0.85)
        for i, width in enumerate((18, 14, 16)):
            _rounded(cr, 7, 23 + i * 10, width, 4, 2)
            cr.fill()
        _set_rgb(cr, c["fg"], 0.55)
        for i, width in enumerate((52, 40)):
            _rounded(cr, 40, 24 + i * 10, width, 4, 2)
            cr.fill()
        _set_rgb(cr, c["accent"])
        _rounded(cr, w - 40, h - 18, 32, 11, 5)
        cr.fill()
        cr.restore()
        _set_rgb(cr, c["fg"], 0.25)
        cr.set_line_width(1)
        _rounded(cr, 0.5, 0.5, w - 1, h - 1, 7)
        cr.stroke()


class AccentDot(Gtk.DrawingArea):
    def __init__(self, hexv, size=22):
        super().__init__()
        self.rgb = theme.parse_hex(hexv)[:3]
        self.set_content_width(size)
        self.set_content_height(size)
        self.set_draw_func(self._draw)

    def _draw(self, area, cr, w, h):
        import math
        _set_rgb(cr, self.rgb)
        cr.arc(w / 2, h / 2, min(w, h) / 2 - 1, 0, 2 * math.pi)
        cr.fill()


class AppearanceWindow(Gtk.Window):
    """Pick light or dark, a color scheme, an accent and the text size. Each choice shows
    right away in every open AWS Kit window and is saved."""

    def __init__(self, parent=None):
        super().__init__(title="Appearance", transient_for=parent, modal=False)
        self.set_default_size(600, -1)
        self.set_resizable(False)
        self.settings = load_settings()
        self._quiet = False
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        for side in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{side}")(18)

        # ---- light or dark
        self.style_buttons = {}
        row = Gtk.Box(spacing=0)
        row.add_css_class("linked")
        group = None
        for key, text in (("system", "Follow system"), ("light", "Light"), ("dark", "Dark")):
            b = Gtk.ToggleButton(label=text)
            if group:
                b.set_group(group)
            group = group or b
            b.connect("toggled", self._style_toggled, key)
            self.style_buttons[key] = b
            row.append(b)
        box.append(self._section("Style", row))

        # ---- color schemes
        self.cards = {}
        self.scheme_buttons = {}
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                           max_children_per_line=5, min_children_per_line=5,
                           column_spacing=8, row_spacing=8)
        group = None
        for s in theme.SCHEMES:
            card = SchemeCard()
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            inner.append(card)
            inner.append(Gtk.Label(label=s.name))
            b = Gtk.ToggleButton()
            b.set_child(inner)
            b.add_css_class("flat")
            b.set_tooltip_text("GTK's own colors" if s.key == "default" else
                               f"{s.name}, in light or dark")
            if group:
                b.set_group(group)
            group = group or b
            b.connect("toggled", self._scheme_toggled, s.key)
            self.cards[s.key] = card
            self.scheme_buttons[s.key] = b
            flow.append(b)
        box.append(self._section("Colors", flow))

        # ---- accent
        acc = Gtk.Box(spacing=6)
        self.accent_buttons = {}
        b = Gtk.ToggleButton(label="Scheme's own")
        b.set_tooltip_text("The accent that goes with the color scheme")
        b.connect("toggled", self._accent_toggled, "default")
        self.accent_buttons["default"] = b
        acc.append(b)
        for key, name, hexv in theme.ACCENTS:
            ab = Gtk.ToggleButton()
            ab.set_child(AccentDot(hexv))
            ab.add_css_class("flat")
            ab.add_css_class("circular")
            ab.set_tooltip_text(name)
            ab.set_group(b)
            ab.connect("toggled", self._accent_toggled, key)
            self.accent_buttons[key] = ab
            acc.append(ab)
        custom = Gtk.ToggleButton(label="Custom")
        custom.set_group(b)
        custom.set_tooltip_text("Pick any color. Very light or very dark colors are "
                                "adjusted so text on them stays readable.")
        custom.connect("toggled", self._custom_toggled)
        self.accent_buttons["custom"] = custom
        acc.append(custom)
        self.custom_color = None
        box.append(self._section("Accent", acc))

        # ---- text size
        self.size_dd = Gtk.DropDown.new_from_strings(
            [f"{name} ({pct}%)" for pct, name in theme.TEXT_SIZES])
        self.size_dd.connect("notify::selected", self._size_changed)
        size_row = Gtk.Box(spacing=8)
        size_row.append(self.size_dd)
        box.append(self._section("Text size", size_row))

        # ---- bottom
        self.note = Gtk.Label(xalign=0, wrap=True)
        self.note.add_css_class("dim-label")
        self.note.set_max_width_chars(70)
        box.append(self.note)
        bottom = Gtk.Box(spacing=8)
        reset = Gtk.Button(label="Reset to defaults")
        reset.connect("clicked", lambda *_: self._set(dict(theme.DEFAULTS)))
        bottom.append(reset)
        filler = Gtk.Box()
        filler.set_hexpand(True)
        bottom.append(filler)
        close = Gtk.Button(label="Close")
        close.add_css_class("suggested-action")
        close.connect("clicked", lambda *_: self.close())
        bottom.append(close)
        box.append(bottom)
        self.set_child(box)

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", lambda c, kv, kc, st: kv == Gdk.KEY_Escape and
                     (self.close() or True))
        self.add_controller(keys)
        _State.listeners.append(self._applied_elsewhere)
        self.connect("close-request", self._closing)
        self._show(self.settings)

    def _section(self, title, widget):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        head = Gtk.Label(label=title, xalign=0)
        head.add_css_class("heading")
        b.append(head)
        b.append(widget)
        return b

    def _closing(self, *_):
        if self._applied_elsewhere in _State.listeners:
            _State.listeners.remove(self._applied_elsewhere)
        return False

    # ---- showing the current choice
    def _show(self, settings):
        self._quiet = True
        try:
            self.style_buttons[settings["style"]].set_active(True)
            self.scheme_buttons[settings["colors"]].set_active(True)
            accent = settings["accent"]
            if accent.startswith("#"):
                self.custom_color = accent
                self.accent_buttons["custom"].set_active(True)
            else:
                self.accent_buttons.get(accent, self.accent_buttons["default"]).set_active(True)
            sizes = [pct for pct, _ in theme.TEXT_SIZES]
            pct = settings["text_size"]
            model = self.size_dd.get_model()
            if model.get_n_items() > len(sizes):
                model.splice(len(sizes), model.get_n_items() - len(sizes), [])
            if pct in sizes:
                self.size_dd.set_selected(sizes.index(pct))
            else:
                # A size set with awskit appearance --text-size, between the usual ones.
                # Showing Normal here instead meant picking Normal changed nothing.
                model.append(f"Custom ({pct}%)")
                self.size_dd.set_selected(len(sizes))
        finally:
            self._quiet = False
        self._refresh_cards()

    def _refresh_cards(self):
        variant = _State.applied[1] if _State.applied else resolve_variant(self.settings)
        css = stock_css(variant)
        acc_setting = self.settings["accent"]
        for s in theme.SCHEMES:
            accent = theme.accent_hex({"colors": s.key, "accent": acc_setting})
            self.cards[s.key].set_colors(theme.preview(css or "", variant, s.key, accent))
        if css is None:
            self.note.set_text("This GTK doesn't have its built-in theme where AWS Kit looks "
                               "for it, so only Light, Dark and the text size apply here.")
        else:
            self.note.set_text("Changes show right away in every open AWS Kit window and are "
                               "saved. The terminal has the same settings: awskit appearance")

    def _applied_elsewhere(self, variant):
        saved = load_settings()
        if saved != self.settings:
            self.settings = saved
            self._show(saved)
        else:
            self._refresh_cards()

    # ---- changes
    def _set(self, settings):
        settings = theme.clean_settings(settings)
        if not save_settings(settings):
            self._show(self.settings)
            dlg = Gtk.AlertDialog(message="Couldn't save the appearance",
                                  detail=f"{CONFIG_FILE} couldn't be written, so nothing was "
                                  "changed. Check that the folder exists and is yours.")
            dlg.show(self)
            return
        self.settings = settings
        apply(self.settings)
        self._show(self.settings)

    def _change(self, **kw):
        if self._quiet:
            return
        s = dict(self.settings)
        s.update(kw)
        self._set(s)

    def _style_toggled(self, button, key):
        if button.get_active():
            self._change(style=key)

    def _scheme_toggled(self, button, key):
        if button.get_active():
            self._change(colors=key)

    def _accent_toggled(self, button, key):
        if button.get_active():
            self._change(accent=key)

    def _custom_toggled(self, button):
        if not button.get_active() or self._quiet:
            return
        self._pick_custom()

    def _pick_custom(self):
        start = Gdk.RGBA()
        start.parse(self.custom_color or theme.accent_hex(self.settings) or theme.GTK_ACCENT)

        def chosen(rgba):
            if rgba is None:
                self._show(self.settings)          # cancelled: back to what was picked
                return
            self._change(accent=theme.to_hex(rgba.red, rgba.green, rgba.blue))
        try:
            dialog = Gtk.ColorDialog(with_alpha=False, title="Accent color")

            def done(dlg, res):
                try:
                    chosen(dlg.choose_rgba_finish(res))
                except GLib.Error:
                    chosen(None)
            dialog.choose_rgba(self, start, None, done)
        except AttributeError:  # GTK before 4.10
            dlg = Gtk.ColorChooserDialog(title="Accent color", transient_for=self,
                                         modal=True)
            dlg.set_use_alpha(False)
            dlg.set_rgba(start)

            def response(d, r):
                chosen(d.get_rgba() if r == Gtk.ResponseType.OK else None)
                d.destroy()
            dlg.connect("response", response)
            dlg.present()

    def _size_changed(self, dd, _pspec):
        i = dd.get_selected()
        if 0 <= i < len(theme.TEXT_SIZES):
            self._change(text_size=theme.TEXT_SIZES[i][0])


def show_window(parent=None):
    for w in Gtk.Window.list_toplevels():
        if isinstance(w, AppearanceWindow):
            w.present()
            return w
    w = AppearanceWindow(parent)
    w.present()
    return w
