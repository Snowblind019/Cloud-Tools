"""Appearance: the color schemes and accents (theme.py), the awskit appearance command, and
applying them in a real GTK window under xvfb-run.

Run from the repo root:  python3 -m unittest tests.test_appearance -v
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
# test_tools sets up the fake AWS environment and a temp config folder. Every test file
# shares that one, since awskit reads XDG_CONFIG_HOME once, when it's first imported.
import test_tools  # noqa: E402,F401

TMP = test_tools.TMP

from awskit import common, theme  # noqa: E402

SAMPLE = """
@define-color theme_bg_color #f6f5f4;
.background { color: #2e3436; background-color: #f6f5f4; }
.view, iconview, textview > text { color: black; background-color: #ffffff; }
headerbar { background: #ebebeb; border-bottom: 1px solid #cdc7c2; }
button.suggested-action { color: white; background-color: #3584e4; }
button.suggested-action:hover { background-color: #4a90e6; }
selection { background-color: rgba(53, 132, 228, 0.5); }
.error { color: #e01b24; }
.success { color: #2ec27e; }
row:hover { background-color: rgba(0, 0, 0, 0.07); }
check { -gtk-icon-source: url("assets/check-symbolic.svg"); }
image { -gtk-icon-source: -gtk-icontheme("open-menu-symbolic"); }
spinner { -gtk-icon-source: url("resource:///org/gtk/libgtk/x.svg"); }
"""


def stock(variant):
    """GTK's real stylesheet, when GTK 4 for Python is installed."""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gio, Gtk  # noqa: F401  (loading Gtk registers its files)
        data = Gio.resources_lookup_data(f"/org/gtk/libgtk/theme/Default/Default-{variant}.css",
                                         Gio.ResourceLookupFlags.NONE)
        return data.get_data().decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def colors_of(css, selector):
    return theme._rule_colors(css, selector)


class ColorMathTests(unittest.TestCase):
    def test_round_trip(self):
        for hexv in ("#3584e4", "#f6f5f4", "#2e3436", "#e01b24", "#000000", "#ffffff"):
            c = theme.parse_hex(hexv)
            back = theme.to_hex(*theme.oklch_to_rgb(*theme.rgb_to_oklch(*c[:3])))
            self.assertEqual(back, hexv)

    def test_out_of_gamut_keeps_lightness_and_hue(self):
        r, g, b = theme.oklch_to_rgb(0.7, 0.5, 150)
        self.assertTrue(all(0 <= x <= 1 for x in (r, g, b)))
        L, C, H = theme.rgb_to_oklch(r, g, b)
        self.assertAlmostEqual(L, 0.7, places=2)
        self.assertLess(abs(H - 150), 3)

    def test_readable_accent(self):
        for hexv in ("#ffffaa", "#000033", "#3584e4"):
            L = theme.rgb_to_oklch(*theme.parse_hex(theme.readable_accent(hexv))[:3])[0]
            self.assertTrue(0.449 <= L <= 0.701, (hexv, L))
        self.assertEqual(theme.readable_accent("nope"), "")


class SettingsTests(unittest.TestCase):
    def test_odd_values_become_defaults(self):
        self.assertEqual(theme.clean_settings(None), theme.DEFAULTS)
        got = theme.clean_settings({"style": "neon", "colors": 5, "accent": "url(x)",
                                    "text_size": True})
        self.assertEqual(got, theme.DEFAULTS)
        self.assertEqual(theme.clean_settings({"text_size": 1000})["text_size"], 100)

    def test_good_values_are_kept(self):
        got = theme.clean_settings({"style": "dark", "colors": "forest", "accent": "#AABBCC",
                                    "text_size": 125, "extra": 1})
        self.assertEqual(got, {"style": "dark", "colors": "forest", "accent": "#aabbcc",
                               "text_size": 125})

    def test_accent_choice(self):
        self.assertEqual(theme.accent_hex({"colors": "default", "accent": "default"}), "")
        self.assertEqual(theme.accent_hex({"colors": "forest", "accent": "default"}), "#3a944a")
        self.assertEqual(theme.accent_hex({"colors": "forest", "accent": "red"}), "#e62d42")
        self.assertTrue(theme.accent_hex({"colors": "default", "accent": "#ffffff"}))

    def test_odd_types_dont_break_anything(self):
        for value in ([], {}, 5, None, ["teal"], {"a": 1}):
            got = theme.clean_settings({"style": value, "colors": value, "accent": value,
                                        "text_size": value})
            self.assertEqual(got, theme.DEFAULTS, value)

    def test_only_colors_and_accents_need_a_stylesheet(self):
        # light or dark on its own is GTK's setting, so a user's own GTK theme stays
        self.assertFalse(theme.needs_css(theme.DEFAULTS))
        self.assertFalse(theme.needs_css(dict(theme.DEFAULTS, style="dark")))
        self.assertTrue(theme.needs_css(dict(theme.DEFAULTS, accent="green")))
        self.assertTrue(theme.needs_css(dict(theme.DEFAULTS, colors="sand")))

    def test_accent_stays_readable_as_text_on_dark(self):
        navy = theme.variant_accent("#1a237e", "dark")
        self.assertGreaterEqual(theme.rgb_to_oklch(*theme.parse_hex(navy)[:3])[0], 0.64)
        self.assertEqual(theme.variant_accent("#1a237e", "light"), "#1a237e")
        self.assertEqual(theme.variant_accent("#ed5b00", "dark"), "#ed5b00")
        self.assertEqual(theme.variant_accent("", "dark"), "")


class RecolorTests(unittest.TestCase):
    def test_default_without_accent_changes_no_color(self):
        out = theme.recolor(SAMPLE, "light", "default", "")
        self.assertEqual(out, SAMPLE)

    def test_accent_family_follows_the_accent(self):
        out = theme.recolor(SAMPLE, "light", "default", "#3a944a")
        self.assertIn("button.suggested-action { color: white; background-color: #3a944a; }",
                      out)
        hover = out.split("button.suggested-action:hover { background-color: ")[1][:7]
        L, C, H = theme.rgb_to_oklch(*theme.parse_hex(hover)[:3])
        self.assertLess(abs(H - theme.rgb_to_oklch(*theme.parse_hex("#3a944a")[:3])[2]), 8)
        self.assertRegex(out, r"selection \{ background-color: rgba\(\d+, \d+, \d+, 0\.5\); \}")
        self.assertNotIn("53, 132, 228", out)
        # red, green and see-through shading stay as they are
        self.assertIn(".error { color: #e01b24; }", out)
        self.assertIn(".success { color: #2ec27e; }", out)
        self.assertIn("rgba(0, 0, 0, 0.07)", out)
        self.assertIn("@define-color theme_bg_color #f6f5f4;", out)    # grays untouched

    def test_scheme_moves_grays_and_keeps_order(self):
        out = theme.recolor(SAMPLE, "light", "sand", "")
        fg, bg = colors_of(out, ".background")
        text, view = colors_of(out, ".view, iconview, textview > text")
        L = lambda c: theme.rgb_to_oklch(*c[:3])[0]  # noqa: E731
        self.assertLess(L(bg), L(view))                  # the view stays the lightest
        self.assertLess(L(text), L(fg))                  # view text stays the darkest
        self.assertGreater(theme.rgb_to_oklch(*bg[:3])[1], 0.015)    # tinted
        self.assertNotIn("#f6f5f4", out)

    def test_urls_point_at_gtk(self):
        out = theme.recolor(SAMPLE, "light", "ocean", "", asset_base="resource:///t/Default/")
        self.assertIn('url("resource:///t/Default/assets/check-symbolic.svg")', out)
        self.assertIn('url("resource:///org/gtk/libgtk/x.svg")', out)
        self.assertIn('-gtk-icontheme("open-menu-symbolic")', out)

    def test_every_scheme_is_readable_on_gtks_own_stylesheet(self):
        for variant in ("light", "dark"):
            css = stock(variant)
            if css is None:
                self.skipTest("GTK 4's built-in stylesheet isn't available")
            for s in theme.SCHEMES:
                accent = theme.accent_hex({"colors": s.key, "accent": "default"})
                out = theme.recolor(css, variant, s.key, accent)
                fg, bg = colors_of(out, ".background")
                text, view = colors_of(out, ".view, iconview, textview > text")
                with self.subTest(variant=variant, scheme=s.key):
                    self.assertGreaterEqual(theme.contrast(fg, bg), 7)
                    self.assertGreaterEqual(theme.contrast(text, view), 7)
                    pv = theme.preview(css, variant, s.key, accent)
                    self.assertGreaterEqual(theme.contrast((1, 1, 1), pv["accent"]), 2.9)
                    self.assertEqual(out.count("{"), css.count("{"))   # no rule lost
                    if variant == "dark":
                        self.assertLess(theme.rgb_to_oklch(*bg[:3])[0], 0.45)
                        for _k, _n, hexv in theme.ACCENTS:
                            m = theme.Mapper(css, "dark", s, hexv)
                            link = m.map(theme.parse_hex(theme.GTK_ACCENT)[:3])
                            self.assertGreaterEqual(theme.contrast(link, bg), 3.2, _k)
                    else:
                        self.assertGreater(theme.rgb_to_oklch(*bg[:3])[0], 0.9)


class SystemTests(unittest.TestCase):
    def test_portal_answers(self):
        try:
            from awskit import appearance
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        from unittest import mock
        appearance._State.initial_dark = True          # say GTK started dark
        try:
            with mock.patch.object(appearance, "is_wsl", lambda: False), \
                    mock.patch.object(appearance.sys, "platform", "linux"):
                for answer, dark in ((1, True), (2, False), (0, False), (None, True)):
                    with mock.patch.object(appearance, "_portal_scheme", lambda a=answer: a):
                        self.assertEqual(appearance.system_dark(), dark, answer)
        finally:
            appearance._State.initial_dark = None

    def test_a_bad_config_still_opens(self):
        try:
            from awskit import appearance
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        cfg = common.load_config()
        cfg["appearance"] = {"accent": [], "style": {}, "colors": 7, "text_size": "big"}
        common.save_config(cfg)
        self.assertEqual(appearance.load_settings(), theme.DEFAULTS)


class CommandTests(unittest.TestCase):
    def run_cli(self, argv):
        from awskit import cli
        out, errs = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), errs.getvalue()

    def saved(self):
        return json.loads(common.CONFIG_FILE.read_text())["appearance"]

    def test_set_show_and_reset(self):
        code, out, _ = self.run_cli(["appearance", "--style", "dark", "--colors", "plum",
                                     "--accent", "Teal", "--text-size", "110"])
        self.assertEqual(code, 0)
        self.assertEqual(self.saved(), {"style": "dark", "colors": "plum", "accent": "teal",
                                        "text_size": 110})
        self.assertIn("Colors:     plum", out)
        code, out, _ = self.run_cli(["appearance", "--reset"])
        self.assertEqual(self.saved(), theme.DEFAULTS)
        self.assertIn("default (GTK's blue)", out)

    def test_reset_works_on_a_broken_config(self):
        cfg = common.load_config()
        cfg["appearance"] = {"accent": [], "colors": {}}
        common.save_config(cfg)
        code, _, _ = self.run_cli(["appearance", "--reset"])
        self.assertEqual(code, 0)
        self.assertEqual(self.saved(), theme.DEFAULTS)

    def test_bad_values_change_nothing(self):
        self.run_cli(["appearance", "--reset"])
        for argv in (["--accent", "url(evil)"], ["--text-size", "5"], ["--colors", "neon"]):
            code, _, errs = self.run_cli(["appearance"] + argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(self.saved(), theme.DEFAULTS)


GTK_CHECK = r'''
import json, os, sys
root = sys.argv[1]
os.environ["XDG_CONFIG_HOME"] = sys.argv[2]
sys.path.insert(0, root)
from gi.repository import GLib, Gtk
from awskit import app, appearance, common, theme

out = {}
a = app.App(page="redact")


def rgb(c):
    return [round(c.red, 3), round(c.green, 3), round(c.blue, 3)]


def fg():
    return rgb(a.get_active_window().get_color())


def first():
    out["start_fg"] = fg()
    out["font0"] = Gtk.Settings.get_default().get_property("gtk-font-name")
    s = {"style": "dark", "colors": "ocean", "accent": "orange", "text_size": 125}
    appearance.save_settings(s)
    out["variant"] = appearance.apply(s)
    out["dark_fg"] = fg()
    out["font1"] = Gtk.Settings.get_default().get_property("gtk-font-name")
    out["has_provider"] = appearance._State.provider is not None
    out["accent"] = appearance.current_accent()
    w = appearance.show_window(a.get_active_window())
    out["window"] = [w.settings["colors"], w.scheme_buttons["ocean"].get_active(),
                     w.accent_buttons["orange"].get_active()]
    w.scheme_buttons["forest"].set_active(True)          # a click in the window
    out["after_click"] = appearance.load_settings()["colors"]
    w.close()


def style_only():
    s = {"style": "dark", "colors": "default", "accent": "default", "text_size": 100}
    appearance.save_settings(s)
    appearance.apply(s)
    out["style_only"] = [appearance._State.provider is None, fg()]


def from_elsewhere():
    # Another AWS Kit window (another process) saves new settings: this one follows.
    cfg = common.load_config()
    cfg["appearance"] = dict(theme.DEFAULTS)
    common.save_config(cfg)


def followed():
    out["followed"] = appearance._State.applied[0] == theme.DEFAULTS
    out["back_fg"] = fg()
    out["font2"] = Gtk.Settings.get_default().get_property("gtk-font-name")
    out["no_provider"] = appearance._State.provider is None
    print(json.dumps(out))
    a.quit()


steps = [(600, first), (600, style_only), (600, from_elsewhere), (1500, followed)]


def run(i=0):
    if i < len(steps):
        ms, fn = steps[i]

        def go():
            try:
                fn()
            except Exception as exc:
                import traceback
                traceback.print_exc()
                print(json.dumps({"error": repr(exc)}))
                a.quit()
                return False
            run(i + 1)
            return False
        GLib.timeout_add(ms, go)


def start():
    if a.get_active_window() is None:
        return True
    run()
    return False


GLib.timeout_add(200, start)
a.run([])
'''


class WindowTests(unittest.TestCase):
    def test_apply_window_and_other_processes(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        folder = Path(tempfile.mkdtemp(prefix="look-", dir=TMP))
        (folder / "check.py").write_text(GTK_CHECK, encoding="utf-8")
        cmd = [sys.executable, str(folder / "check.py"), str(ROOT), str(folder)]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                self.skipTest("no display and no xvfb-run")
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
        self.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
        got = json.loads(lines[-1])
        self.assertNotIn("error", got)
        self.assertEqual(got["variant"], "dark")
        self.assertTrue(got["has_provider"])
        self.assertLess(sum(got["start_fg"]), 1.5)            # dark text on light
        self.assertGreater(sum(got["dark_fg"]), 2.4)          # light text on dark
        self.assertNotEqual(got["font0"], got["font1"])       # bigger text
        self.assertEqual(got["accent"], "#ed5b00")
        self.assertEqual(got["window"], ["ocean", True, True])
        self.assertEqual(got["after_click"], "forest")
        self.assertTrue(got["style_only"][0])                 # no stylesheet of its own
        self.assertGreater(sum(got["style_only"][1]), 2.4)    # but GTK's dark
        self.assertTrue(got["followed"])
        self.assertEqual(got["back_fg"], got["start_fg"])
        self.assertEqual(got["font2"], got["font0"])
        self.assertTrue(got["no_provider"])


if __name__ == "__main__":
    unittest.main()
