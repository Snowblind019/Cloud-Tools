"""Zooming and scrolling in Image Redact and Cloud Map with the wheel and a touchpad, in a
real GTK window under xvfb-run. The scroll events are fakes with the same methods GTK's
gives the handler. Also clicking on the image in Image Redact, which runs the same way.

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
    for _ in range(3):                      # Ctrl+wheel, before any of it is drawn
        e._scrolled(Fake(CTRL), 0, -1)
    out["zoom_in"] = e.zoom
    out["anchor_same"] = under(e, 300, 200) == before
    out["before"], out["after"] = before, under(e, 300, 200)
    e._scrolled(Fake(CTRL), 0, 1)
    out["zoom_out"] = e.zoom
    z = e.zoom
    for _ in range(3):
        e._scrolled(Fake(CTRL), 0, 0.25)    # parts of a notch: nothing yet
    out["part_notch"] = e.zoom == z
    e._scrolled(Fake(CTRL), 0, 0.25)        # the fourth part makes a notch
    out["whole_notch"] = e.zoom
    out["no_delta"] = e._scrolled(Fake(CTRL), 0, 0) and e.zoom == out["whole_notch"]
    z = e.zoom
    out["ctrl_tilt"] = e._scrolled(Fake(CTRL), 1, 0) and e.zoom == z
    e.set_zoom(2.5)                         # room to scroll both ways for the next step


def layout_then_scroll():
    e = ed()
    h, v = e.scroller.get_hadjustment(), e.scroller.get_vadjustment()
    out["room"] = [h.get_upper() - h.get_page_size() > 200,
                   v.get_upper() - v.get_page_size() > 200]

    def where():
        return [round(h.get_value()), round(v.get_value())]

    z, start = e.zoom, where()
    out["wheel_handled"] = e._scrolled(Fake(), 0, 1)     # plain wheel down: scrolls down
    down = where()
    e._scrolled(Fake(), 0, -1)                            # and back up
    out["wheel_scrolls"] = [e.zoom == z, down[0] == start[0], down[1] > start[1],
                            where() == start]
    e._scrolled(Fake(SHIFT), 0, 1)                        # Shift+wheel: sideways
    right = where()
    e._scrolled(Fake(SHIFT), 1, 0)                        # already turned sideways
    out["shift_scrolls"] = [e.zoom == z, right[0] > start[0], right[1] == start[1],
                            where()[0] > right[0]]
    at = where()
    e._scrolled(Fake(), -1, 0)                            # a tilting wheel, to the left
    out["tilt_scrolls"] = where()[0] < at[0] and where()[1] == at[1]
    out["touchpad_passes"] = e._scrolled(Fake(source=TOUCHPAD, unit=Gdk.ScrollUnit.SURFACE),
                                         0, 20) is False and e.zoom == z
    out["shift_touchpad_passes"] = e._scrolled(
        Fake(SHIFT, TOUCHPAD, Gdk.ScrollUnit.SURFACE), 0, 20) is False
    at = where()
    e._scrolled(Fake(unit=Gdk.ScrollUnit.SURFACE), 0, 15)     # a fine wheel scrolls too
    out["fine_wheel_scrolls"] = [e.zoom == z, where()[1] - at[1]]
    e._scrolled(Fake(CTRL, TOUCHPAD, Gdk.ScrollUnit.SURFACE), 0, -30)
    out["ctrl_touchpad_zooms"] = round(e.zoom / z, 3)
    z = e.zoom
    e._scrolled(Fake(CTRL, unit=Gdk.ScrollUnit.SURFACE), 0, -15)
    out["ctrl_fine_wheel_zooms"] = e.zoom > z
    e.zoom_fit()


def scroll_before_layout():
    e = ed()
    e.set_zoom(1.5)                         # from fit: centered, with room every way
    e._pointer_view = (300.0, 200.0)
    before = under(e, 300, 200)
    e._scrolled(Fake(CTRL), 0, -1)          # zoom in at the pointer, to 2.0
    e._scrolled(Fake(), 0, 1)               # and a notch down before that's laid out
    step = e.scroller.get_vadjustment().get_page_size() ** (2 / 3) / e.zoom
    out["scroll_pending"] = {"zoom": e.zoom, "want": [before[0], before[1] + step]}


def pan_before_layout():
    e = ed()
    out["scroll_pending"]["got"] = under(e, 300, 200)
    e._pointer_view = (900.0, 500.0)        # toward the bottom right, past the old size
    out["pan_pending"] = {"want": under(e, 900, 500)}
    e._scrolled(Fake(CTRL), 0, -1)          # zoom in at the pointer, to 3.0
    e._pan_begin(None, 0, 0)                # and start a middle-drag right away


def pan_after_layout():
    e = ed()
    e._pan_update(None, -30, 0)             # 30 pixels left moves the view right
    want = out["pan_pending"]["want"]
    out["pan_pending"].update(want=[want[0] + 30 / e.zoom, want[1]], got=under(e, 900, 500),
                              zoom=e.zoom)


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


steps = [(600, load), (1500, wheel), (600, layout_then_scroll), (600, scroll_before_layout),
         (600, pan_before_layout), (600, pan_after_layout), (800, settle), (1500, map_canvas)]


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


CLICK_CHECK = r"""
import json, os, sys
root = sys.argv[1]
os.environ["XDG_CONFIG_HOME"] = sys.argv[2]
sys.path.insert(0, root)
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk
from awskit import app, imageredact

out = {}
a = app.App(page="image")


class Gesture:
    def get_current_event_state(self):
        return 0


def ed():
    return a.get_active_window().pages["image"].editor


def click(e, x, y, n):
    # What GTK calls for one press and release: the click, then the drag that starts on it.
    e._pressed(None, n, x, y)
    e._drag_begin(Gesture(), x, y)
    e._drag_end(Gesture(), 0, 0)


def load():
    a.get_active_window().set_default_size(1240, 800)
    e = ed()
    e.ed.cfg["find_on_open"] = False
    e.open_path(os.path.join(root, "image-redact/examples/sample-screenshot.png"),
                confirmed=True)


def double_click():
    e = ed()
    e.ed.commit_text(("new", (60, 60)), "hello")
    e.set_tool("select")
    x, y = e.to_view(70, 70)
    click(e, x, y, 1)
    click(e, x, y, 2)
    focus = e.get_root().get_focus()
    out["popover"] = e.text_pop.get_visible()
    out["typing_goes_to_entry"] = focus is not None and (
        focus is e.text_entry or focus.is_ancestor(e.text_entry))
    out["entry_text"] = e.text_entry.get_text()
    e.text_entry.set_text("changed")
    e.text_entry.emit("activate")
    out["text"] = [s["text"] for s in e.ed.shapes if s["kind"] == "text"]


def detection_drops_selection():
    e = ed()
    word = imageredact.Word("123456789012", 20, 20, 120, 14, 95, (0, 1), None)
    e.ed.passes = [[word]]
    e._apply_boxes()
    box = next(s for s in e.ed.shapes if s.get("auto"))
    x, y = e.to_view((box["x1"] + box["x2"]) / 2, (box["y1"] + box["y2"]) / 2)
    click(e, x, y, 1)
    out["selected"] = [e.ed.selected is box, e.color_btn.get_visible()]
    email = imageredact.Word("jane.doe@example.com", 20, 300, 200, 14, 95, (0, 2), None)
    e.ed.passes = [[word, email]]           # Find PII again finds more, so its boxes change
    e._apply_boxes()
    out["after"] = [e.ed.selected is None, e.color_btn.get_visible()]


def slow_then_fast():
    # A slow open that finishes after a later one used to replace it without asking.
    import shutil, time
    sample = os.path.join(root, "image-redact/examples/sample-screenshot.png")
    paths = [os.path.join(sys.argv[2], n + ".png") for n in ("slow", "fast")]
    for path in paths:
        shutil.copy(sample, path)
    real = imageredact.load_image_bytes

    def load_image_bytes(path):
        if path.endswith("slow.png"):
            time.sleep(1.0)
        return real(path)
    imageredact.load_image_bytes = load_image_bytes
    e = ed()
    e.open_path(paths[0], confirmed=True)
    e.open_path(paths[1], confirmed=True)


def after_opens():
    out["opened"] = os.path.basename(ed().ed.source_path or "")
    print(json.dumps(out))
    a.quit()


steps = [(600, load), (1500, double_click), (300, detection_drops_selection),
         (300, slow_then_fast), (2500, after_opens)]


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
"""

def run_check(test, script):
    """Run a check script in a real GTK window and return the JSON it prints last."""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
    except (ImportError, ValueError):
        test.skipTest("GTK 4 for Python isn't installed")
    folder = Path(tempfile.mkdtemp(prefix="zoom-", dir=TMP))
    (folder / "check.py").write_text(script, encoding="utf-8")
    cmd = [sys.executable, str(folder / "check.py"), str(ROOT), str(folder)]
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        if not shutil.which("xvfb-run"):
            test.skipTest("no display and no xvfb-run")
        cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
    test.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
    got = json.loads(lines[-1])
    test.assertNotIn("error", got)
    return got


class ZoomTests(unittest.TestCase):
    def test_wheel_and_touchpad(self):
        got = run_check(self, CHECK)
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
        self.assertTrue(got["ctrl_tilt"])
        self.assertEqual(got["room"], [True, True])
        # A plain wheel scrolls up and down and never zooms, Shift+wheel goes sideways.
        self.assertTrue(got["wheel_handled"])
        self.assertEqual(got["wheel_scrolls"], [True, True, True, True])
        self.assertEqual(got["shift_scrolls"], [True, True, True, True])
        self.assertTrue(got["tilt_scrolls"])
        self.assertTrue(got["touchpad_passes"])
        self.assertTrue(got["shift_touchpad_passes"])
        self.assertEqual(got["fine_wheel_scrolls"], [True, 15])
        self.assertEqual(got["ctrl_touchpad_zooms"], round(2 ** (30 / 150), 3))
        self.assertTrue(got["ctrl_fine_wheel_zooms"])
        # A wheel notch or a middle-drag that comes before a zoom is laid out goes on from
        # where the zoom is going, instead of the image jumping to where the scrollbars
        # still were.
        for key in ("scroll_pending", "pan_pending"):
            for want, have in zip(got[key]["want"], got[key]["got"]):
                self.assertAlmostEqual(want, have, delta=0.25, msg=(key, got[key]))
        self.assertEqual(got["scroll_pending"]["zoom"], 2.0)
        self.assertEqual(got["pan_pending"]["zoom"], 3.0)
        self.assertTrue(got["anchor_released"])               # layout done, anchor let go
        self.assertEqual(got["map_touchpad"], [True, 30])     # moved 30 pixels, same zoom
        self.assertEqual(got["map_notch"], 1.2)
        self.assertEqual(got["map_ctrl_touchpad"], round(1.2 ** 0.5, 3))  # 30 of 60 px


class ClickTests(unittest.TestCase):
    def test_double_click_edits_text_and_detection_clears_controls(self):
        # Also: only the last of two opens counts.
        got = run_check(self, CLICK_CHECK)
        # The drag that starts on the second press used to take the focus back, so the
        # entry showed but typing went nowhere.
        self.assertTrue(got["popover"])
        self.assertTrue(got["typing_goes_to_entry"])
        self.assertEqual(got["entry_text"], "hello")
        self.assertEqual(got["text"], ["changed"])
        # A selected detected box that detection replaces takes its controls with it.
        self.assertEqual(got["selected"], [True, True])
        self.assertEqual(got["after"], [True, False])
        self.assertEqual(got["opened"], "fast.png")


if __name__ == "__main__":
    unittest.main()
