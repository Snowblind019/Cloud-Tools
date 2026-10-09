"""The Cloud Map page, in a real GTK window under xvfb-run: the reachability panel, and
the canvas, search and built-in editor.

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

def two_loads():
    # The last snapshot, read again at startup, is slow. A file opened meanwhile has to stay.
    import time
    from awskit import mapmodel as mm
    snap = cloudmap.load_input(os.path.join(root, "cloud-map/examples/two-az-vpc-state.json"))
    paths = [os.path.join(sys.argv[2], n + ".cloudmap.json") for n in ("slow", "fast")]
    for path in paths:
        snap.save(path)
    real = mm.Snapshot.load.__func__

    def load(cls, path):
        if str(path).endswith("slow.cloudmap.json"):
            time.sleep(1.0)
        return real(cls, path)
    mm.Snapshot.load = classmethod(load)
    page().load_snapshot(paths[0], quiet=True)
    page().load_snapshot(paths[1], source={"kind": "file"})

def after_loads():
    out["last_load"] = os.path.basename(page().source.get("snapshot", ""))
    print(json.dumps(out))
    a.quit()

steps = [(400, load), (2500, check_open), (500, check_blocked), (2500, after_relayout),
         (300, two_loads), (2500, after_loads)]

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
        self.assertEqual(got["last_load"], "fast.cloudmap.json")


# A stand-in for draw.io's web app: just enough of its JSON embed protocol for host.js
# (init, load, and the editor object AWS Kit's Done and Cancel use).
FAKE_DRAWIO_PAGE = r"""<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script>
(function () {
  var xml = null;
  addEventListener("message", function (evt) {
    var msg = JSON.parse(evt.data);
    if (msg.action === "load") {
      xml = msg.xml;
      window.awskitUi = { editor: { modified: false }, getFileData: function () { return xml; } };
      parent.postMessage(JSON.stringify({ event: "load" }), location.origin);
    }
  });
  parent.postMessage(JSON.stringify({ event: "init" }), location.origin);
})();
</script></body></html>"""

PAGE_FIXES = r'''
import json, os, sys, time, urllib.request
from pathlib import Path
root, folder = sys.argv[1], Path(sys.argv[2])
os.environ["XDG_CONFIG_HOME"] = str(folder)
os.environ["AWSKIT_DRAWIO"] = str(folder / "drawio")
sys.path.insert(0, root)
from gi.repository import GLib
from awskit import app, cloudmap, mapdrawio, mapeditor, mapicons, maplayoutmem
from awskit.common import DRAWIO_MARKER

# A draw.io folder with a stand-in for the web app and a square for each AWS icon.
drawio = folder / "drawio"
(drawio / "js").mkdir(parents=True)
(drawio / "stencils").mkdir()
(drawio / "index.html").write_text(FAKE_DRAWIO_PAGE, encoding="utf-8")
(drawio / "js" / "PreConfig.js").write_text("", encoding="utf-8")
(drawio / DRAWIO_MARKER).write_text("test", encoding="ascii")
names = set(mapdrawio.SHAPES.values()) | set(mapdrawio.GROUP_ICONS.values())
shapes = "".join(f'<shape name="{n}" w="10" h="10" aspect="fixed"><foreground>'
                 '<rect x="0" y="0" w="10" h="10"/><fill/></foreground></shape>'
                 for n in sorted(names))
(drawio / "stencils" / "aws4.xml").write_text(f'<shapes name="mxgraph.aws4">{shapes}</shapes>',
                                              encoding="utf-8")

# draw.io's icons take a moment to load, the way they do the first time.
cached = mapicons.IconSet._from_cache
mapicons.IconSet._from_cache = lambda self: (time.sleep(1.5), cached(self))[1]

out = {}
a = app.App(page="map")
snaps = folder / "snaps"
snaps.mkdir()
example = os.path.join(root, "cloud-map/examples/two-az-vpc-state.json")

def page():
    return a.get_active_window().pages["map"]

def frame_js(code):
    page().editing.view.evaluate_javascript(
        "document.getElementById('drawio').contentWindow." + code + "; 1", -1, None, None, None,
        None, None)

def load():
    p = page()
    p.type_dd.set_selected(1)
    cloudmap.load_input(example).save(snaps / "prod.cloudmap.json")
    p.load_snapshot(snaps / "prod.cloudmap.json", source={"kind": "file"})

def icons_and_search():
    p = page()
    scene = p.canvas.scene
    # Icons drawn while draw.io's were loading were stand-ins. Once they're in, none is left.
    stale = [k for k, surf in scene.icon_cache.items()
             if bytes(surf.get_data()) != bytes(scene._icon_surface(*k).get_data())]
    out["icons"] = [scene.icons.loaded, len(scene.icons.shapes) > 0, len(stale)]
    p.search.set_text("lab")

def other_map_type():
    p = page()
    out["matches"] = len(p.matches)
    p.type_dd.set_selected(0)          # the access map has none of those boxes

def next_match():
    p = page()
    p.find(next_match=True)
    c = p.canvas
    out["after_type"] = [c.selected is None or c.selected in c.scene.rects,
                         p.status.text.get_text().startswith("Match")]
    p.type_dd.set_selected(1)

def prefetch():
    # A window much bigger than the old tile limit: drawing ahead has to finish.
    c = page().canvas
    c.set_zoom(8.0)
    c.tile_zoom = c.zoom
    if c.sharpen_id:
        GLib.source_remove(c.sharpen_id)
        c.sharpen_id = 0
    if c.prefetch_id:
        GLib.source_remove(c.prefetch_id)
        c.prefetch_id = 0
    c.visible = lambda: (100, 100, 100 + 4800 / 8.0, 100 + 2400 / 8.0)    # inside the map
    runs = 0
    while runs < 400:
        runs += 1
        c._prefetch()
        if not c.prefetch_id:
            break
        GLib.source_remove(c.prefetch_id)
        c.prefetch_id = 0
    out["prefetch"] = [runs < 400, len(c.tiles)]
    del c.visible
    c.fit()

def edit():
    out["webkit"] = mapeditor.webkit_problem()
    if out["webkit"]:
        a.quit()
        return
    page().editing.start()

def scan_finishes():
    p = page()
    out["editing"] = [p.editing.mode, bool(p.editing.bridge and p.editing.bridge.loaded)]
    # A scan started before Edit finishes while draw.io is open, with another snapshot.
    cloudmap.load_input(example).save(snaps / "dev.cloudmap.json")
    p.source = {"kind": "scan"}
    p.set_snapshot(cloudmap.load_input(example), snaps / "dev.cloudmap.json")

def save():
    e = page().editing
    xml = e.path.read_text().replace('awskit_geo="20,60,', 'awskit_geo="20,0,', 1)
    req = urllib.request.Request(e.bridge.url + "save", data=xml.encode(), method="POST")
    out["saved"] = json.loads(urllib.request.urlopen(req, timeout=10).read())["ok"]

def close_with_changes():
    def pinned(name):
        side = maplayoutmem.sidecar_path(snaps / name)
        if not side.exists():
            return 0
        nodes = maplayoutmem.load(side)["maps"].get("network", {}).get("nodes", {})
        return sum(1 for n in nodes.values() if n.get("pinned"))
    out["pinned"] = [pinned("prod.cloudmap.json"), pinned("dev.cloudmap.json")]
    frame_js("awskitUi.editor.modified = true")
    a.get_active_window().close()

def still_open():
    out["kept_open"] = [a.get_active_window() is not None, page().editing.mode]
    frame_js("awskitUi.editor.modified = false")

def close_saved():
    out["closing"] = True
    a.get_active_window().close()      # nothing unsaved now, so it closes

steps = [(400, load), (5000, icons_and_search), (1200, other_map_type), (2500, next_match),
         (2500, prefetch), (300, edit), (4000, scan_finishes), (2500, save),
         (3000, close_with_changes), (1500, still_open), (800, close_saved)]

def run(i=0):
    if i < len(steps):
        ms, fn = steps[i]
        def go():
            try:
                fn()
            except Exception as exc:
                import traceback
                traceback.print_exc()
                out["error"] = repr(exc)
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
print(json.dumps(out))
'''


class MapPageTests(unittest.TestCase):
    """The rest of the Cloud Map page: the canvas, search, and editing in the built-in
    draw.io (with a stand-in for draw.io when WebKitGTK is installed)."""

    def test_canvas_search_and_editor(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        folder = Path(tempfile.mkdtemp(prefix="map-page-", dir=TMP))
        script = PAGE_FIXES.replace("FAKE_DRAWIO_PAGE", repr(FAKE_DRAWIO_PAGE), 1)
        (folder / "check.py").write_text(script, encoding="utf-8")
        cmd = [sys.executable, str(folder / "check.py"), str(ROOT), str(folder)]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                self.skipTest("no display and no xvfb-run")
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
        self.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
        got = json.loads(lines[-1])
        self.assertNotIn("error", got, r.stderr[-2000:])
        self.assertEqual(got["icons"], [True, True, 0])        # no stand-in icon left over
        self.assertGreater(got["matches"], 0)
        # Enter after the map changed doesn't go to a box that isn't on it any more.
        self.assertEqual(got["after_type"], [True, False])
        self.assertTrue(got["prefetch"][0], got["prefetch"])    # drawing ahead stops
        self.assertGreater(got["prefetch"][1], 96)
        if got["webkit"]:
            return                                             # no WebKitGTK here
        self.assertEqual(got["editing"], ["embedded", True])
        self.assertTrue(got["saved"])
        # The save went into the edited snapshot's layout, not the one a scan put on the
        # page while draw.io was open.
        self.assertEqual(got["pinned"], [1, 0])
        # Closing with changes in draw.io asks first, and with none it just closes.
        self.assertEqual(got.get("kept_open"), [True, "embedded"])
        self.assertTrue(got.get("closing"))


if __name__ == "__main__":
    unittest.main()
