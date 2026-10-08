"""Zooming and scrolling in Image Redact and Cloud Map with the wheel and a touchpad, in a
real GTK window under xvfb-run. The scroll events are fakes with the same methods GTK's
gives the handler.

Run from the repo root:  python3 -m unittest tests.test_image_zoom -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="awskit-test-")

CHECK = r'''
import json, os, sys
root = sys.argv[1]
os.environ["XDG_CONFIG_HOME"] = sys.argv[2]
sys.path.insert(0, root)
from gi.repository import Gdk, GLib, Gtk
from awskit import app, cloudmap

out = {}
a = app.App(page="image")


class Dev:
    def __init__(self, source):
        self.source = source

    def get_source(self):
        return self.source


class Fake:
    """Stands in for Gtk.EventControllerScroll inside the scroll handler."""
    def __init__(self, state=0, source=Gdk.InputSource.MOUSE, unit=Gdk.ScrollUnit.WHEEL):
        self.state, self.dev, self.unit = state, Dev(source), unit

    def get_current_event_state(self):
        return self.state

    def get_current_event_device(self):
        return self.dev

    def get_unit(self):
        return self.unit


CTRL, SHIFT = Gdk.ModifierType.CONTROL_MASK, Gdk.ModifierType.SHIFT_MASK
TOUCHPAD = Gdk.InputSource.TOUCHPAD


def ed():
    return a.get_active_window().pages["image"].editor


def under(e, vx, vy):
    sx, sy, ox, oy = e._layout()
    return [round((sx + vx - ox) / e.zoom, 1), round((sy + vy - oy) / e.zoom, 1)]


def load():
    a.get_active_window().set_default_size(1240, 800)
    ed().open_path(os.path.join(root, "image-redact/examples/sample-screenshot.png"),
                   confirmed=True)


def wheel():
    e = ed()
    frame = e.scroller.get_parent()
    phases = [c.get_propagation_phase() for c in list(frame.observe_controllers())
              if isinstance(c, Gtk.EventControllerScroll)]
    out["on_frame_capture"] = phases == [Gtk.PropagationPhase.CAPTURE]
    out["none_on_area"] = not [c for c in list(e.area.observe_controllers())
                               if isinstance(c, Gtk.EventControllerScroll)]
    e.set_zoom(1.0)
    e._pointer_view = (300.0, 200.0)
    before = under(e, 300, 200)
    e._scrolled(Fake(), 0, -1)              # plain wheel, no Ctrl: zooms in
    e._scrolled(Fake(), 0, -1)
    e._scrolled(Fake(CTRL), 0, -1)          # Ctrl+wheel too, before any of it is drawn
    out["zoom_in"] = e.zoom
    out["anchor_same"] = under(e, 300, 200) == before
    out["before"], out["after"] = before, under(e, 300, 200)
    e._scrolled(Fake(), 0, 1)
    out["zoom_out"] = e.zoom
    z = e.zoom
    for _ in range(3):
        e._scrolled(Fake(), 0, 0.25)        # parts of a notch: nothing yet
    out["part_notch"] = e.zoom == z
    e._scrolled(Fake(), 0, 0.25)            # the fourth part makes a notch
    out["whole_notch"] = e.zoom
    out["no_delta"] = e._scrolled(Fake(), 0, 0) and e.zoom == out["whole_notch"]


def layout_then_scroll():
    e = ed()
    v = e.scroller.get_vadjustment()
    z, start = e.zoom, v.get_value()
    out["shift_handled"] = e._scrolled(Fake(SHIFT), 0, 1)
    out["shift_scrolls"] = [e.zoom == z, v.get_value() > start]
    out["touchpad_passes"] = e._scrolled(Fake(source=TOUCHPAD, unit=Gdk.ScrollUnit.SURFACE),
                                         0, 20) is False and e.zoom == z
    e._scrolled(Fake(CTRL, TOUCHPAD, Gdk.ScrollUnit.SURFACE), 0, -30)
    out["ctrl_touchpad_zooms"] = round(e.zoom / z, 3)
    e._scrolled(Fake(unit=Gdk.ScrollUnit.SURFACE), 0, -15)
    out["fine_wheel_zooms"] = e.zoom > z


def settle():
    e = ed()
    out["anchor_released"] = e._zoom_anchor is None
    a.get_active_window().stack.set_visible_child_name("map")
    m = a.get_active_window().pages["map"]
    m.type_dd.set_selected(1)
    m.set_snapshot(cloudmap.load_input(os.path.join(
        root, "cloud-map/examples/two-az-vpc-state.json")), None)


def map_canvas():
    c = a.get_active_window().pages["map"].canvas
    c.pointer = (200.0, 150.0)
    z, oy = c.zoom, c.oy
    c._scrolled(Fake(source=TOUCHPAD, unit=Gdk.ScrollUnit.SURFACE), 0, 30)
    out["map_touchpad"] = [c.zoom == z, round((c.oy - oy) * c.zoom)]
    c._scrolled(Fake(), 0, -1)
    out["map_notch"] = round(c.zoom / z, 3)
    z = c.zoom
    c._scrolled(Fake(CTRL, TOUCHPAD, Gdk.ScrollUnit.SURFACE), 0, -30)
    out["map_ctrl_touchpad"] = round(c.zoom / z, 3)
    print(json.dumps(out))
    a.quit()


steps = [(600, load), (1500, wheel), (600, layout_then_scroll), (800, settle),
         (1500, map_canvas)]


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


class ZoomTests(unittest.TestCase):
    def test_wheel_and_touchpad(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        folder = Path(tempfile.mkdtemp(prefix="zoom-", dir=TMP))
        (folder / "check.py").write_text(CHECK, encoding="utf-8")
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
        # The wheel is caught above the scroller, so a smooth scroll the scroller started
        # can't swallow it (the old "zooms only sometimes").
        self.assertTrue(got["on_frame_capture"])
        self.assertTrue(got["none_on_area"])
        self.assertEqual(got["zoom_in"], 2.0)                # 1.0 -> 1.25 -> 1.5 -> 2.0
        self.assertTrue(got["anchor_same"], (got["before"], got["after"]))
        self.assertEqual(got["zoom_out"], 1.5)
        self.assertTrue(got["part_notch"])
        self.assertEqual(got["whole_notch"], 1.25)
        self.assertTrue(got["no_delta"])
        self.assertTrue(got["shift_handled"])
        self.assertEqual(got["shift_scrolls"], [True, True])
        self.assertTrue(got["touchpad_passes"])
        self.assertEqual(got["ctrl_touchpad_zooms"], round(2 ** (30 / 150), 3))
        self.assertTrue(got["fine_wheel_zooms"])
        self.assertTrue(got["anchor_released"])               # layout done, anchor let go
        self.assertEqual(got["map_touchpad"], [True, 30])     # moved 30 pixels, same zoom
        self.assertEqual(got["map_notch"], 1.2)
        self.assertEqual(got["map_ctrl_touchpad"], round(1.2 ** 0.5, 3))  # 30 of 60 px


if __name__ == "__main__":
    unittest.main()
