"""The reachability panel on the Cloud Map page, in a real GTK window under xvfb-run.

Run from the repo root:  python3 -m unittest tests.test_map_reach_page -v
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
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="awskit-test-")

PAGE_CHECK = r'''
import json, os, sys
root = sys.argv[1]
os.environ["XDG_CONFIG_HOME"] = sys.argv[2]
sys.path.insert(0, root)
from gi.repository import GLib
from awskit import app, cloudmap

out = {}
a = app.App(page="map")

def page():
    return a.get_active_window().pages["map"]

def pick(dd, text):
    p = page()
    i = next(i for i, e in enumerate(p.reach_points) if e.label.startswith(text))
    dd.set_selected(i)

def load():
    p = page()
    out["before"] = p.reach_box.get_sensitive()
    p.type_dd.set_selected(1)
    p.set_snapshot(cloudmap.load_input(os.path.join(root, "cloud-map/examples/two-az-vpc-state.json")), None)

def check_open():
    p = page()
    out["after"] = p.reach_box.get_sensitive()
    out["points"] = len(p.reach_points)
    pick(p.reach_from, "The internet (anywhere")
    pick(p.reach_to, "bastion")
    p.reach_port.set_text("22")
    p.check_reach()
    out["open"] = [p.d_title.get_text(), p.d_title.has_css_class("ok-text"),
                   bool(p.canvas.path and p.canvas.path[0]), list(p.canvas.path[2])]
    out["copy_text"] = p.detail.text.splitlines()[0]

def check_blocked():
    p = page()
    pick(p.reach_from, "lab-web")
    pick(p.reach_to, "lab-postgres")
    out["port_default"] = p.reach_port.get_text()
    p.check_reach()
    out["blocked"] = [p.d_title.get_text(), p.d_title.has_css_class("bad-text"),
                      len(p.canvas.path[2])]
    p.relayout()

def after_relayout():
    p = page()
    out["kept"] = p.d_title.get_text()
    p.reach_port.set_text("http")
    p.check_reach()
    p.reach_port.set_text("²")        # a digit to isdigit(), but not a number to int()
    p.check_reach()
    out["clear_ok"] = p.reach_clear.get_sensitive()
    p.clear_reach()
    out["cleared"] = [p.canvas.path, p.reach_clear.get_sensitive(), p.d_title.get_text()]
    print(json.dumps(out))
    a.quit()

steps = [(400, load), (2500, check_open), (500, check_blocked), (2500, after_relayout)]

def run(i=0):
    if i < len(steps):
        ms, fn = steps[i]
        def go():
            try:
                fn()
            except Exception as exc:
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


class ReachPanelTests(unittest.TestCase):
    def test_panel_checks_highlights_and_clears(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        folder = Path(tempfile.mkdtemp(prefix="reach-page-", dir=TMP))
        (folder / "check.py").write_text(PAGE_CHECK, encoding="utf-8")
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
        self.assertFalse(got["before"])                       # nothing loaded, nothing to pick
        self.assertTrue(got["after"])
        self.assertGreater(got["points"], 5)
        self.assertEqual(got["open"][:3], ["Reachable", True, True])
        self.assertEqual(got["open"][3], [])                   # nothing blocked, nothing red
        self.assertTrue(got["copy_text"].startswith("From"))   # Copy gives the CLI's text
        self.assertEqual(got["port_default"], "5432")          # the database's port, filled in
        self.assertEqual(got["blocked"][:2], ["Blocked", True])
        self.assertEqual(got["blocked"][2], 1)                 # the database box in red
        self.assertEqual(got["kept"], "Blocked")               # survives a relayout
        self.assertTrue(got["clear_ok"])                       # a bad port changes nothing
        self.assertEqual(got["cleared"], [None, False, "Nothing selected"])


if __name__ == "__main__":
    unittest.main()
