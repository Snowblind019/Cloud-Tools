"""Opens Cloud Map's offline draw.io editor in WebKitGTK through the bridge, moves a box,
saves, and prints what happened as JSON. tests/test_tools.py runs it (with networking
blocked when it can) for CloudMapEditorWebTests; it can also be run by hand:

    xvfb-run python3 tests/editor_check.py OUT_FOLDER
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import GLib, Gtk, WebKit  # noqa: E402

from awskit import cloudmap, mapeditor, maptf  # noqa: E402

BOX = "i-0a1b2c3d4e5f60093"


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    snap = maptf.read([str(ROOT / "cloud-map" / "examples" / "two-az-vpc-state.json")])
    xml, _ = cloudmap.export(snap, "network", snapshot_name="two-az-vpc.cloudmap.json")
    path = out / "check.drawio"
    path.write_text(xml, encoding="utf-8")
    result = {"loaded": False, "saved": 0, "exit": None, "outside": [], "errors": [],
              "moved": None}
    bridge = mapeditor.Bridge(path, on_exit=lambda info: result.update(exit=info))
    url = bridge.start()
    prefix = url
    app = Gtk.Application(application_id="io.github.snowblind019.AwsKitEditorCheck")

    def activate(a):
        win = Gtk.ApplicationWindow(application=a)
        win.set_default_size(1280, 800)
        view = WebKit.WebView(network_session=WebKit.NetworkSession.new_ephemeral())

        def started(_v, _res, request):
            uri = request.get_uri()
            if not uri.startswith((prefix, "data:", "blob:", "about:")):
                result["outside"].append(uri)
        view.connect("resource-load-started", started)
        win.set_child(view)
        win.present()
        view.load_uri(url)
        t0 = time.time()

        def finish():
            result["saved"] = bridge.saves
            result["errors"] = bridge.errors
            a.quit()
            return False

        def saved_check():
            if bridge.saves or time.time() - t0 > 60:
                GLib.timeout_add(1500, finish)
                return False
            return True

        def moved(v, res, *_):
            try:
                result["moved"] = v.evaluate_javascript_finish(res).to_string()
            except GLib.Error as exc:
                result["moved"] = f"error: {exc.message}"
            v.evaluate_javascript("awskitSave(true)", -1, None, None, None, None, None)
            GLib.timeout_add(200, saved_check)

        def poll():
            if bridge.loaded:
                result["loaded"] = True
                GLib.timeout_add(1500, move)
                return False
            if time.time() - t0 > 60:
                finish()
                return False
            return True

        def move():
            js = ("(function(){var g=document.getElementById('drawio').contentWindow.awskitUi"
                  ".editor.graph; var c=g.model.getCell(%s); g.moveCells([c], 0, 80); "
                  "return JSON.stringify(c.geometry);})()" % json.dumps(BOX))
            view.evaluate_javascript(js, -1, None, None, None, moved, None)
            return False
        GLib.timeout_add(300, poll)
    app.connect("activate", activate)
    app.run([])
    bridge.stop()
    result["file"] = str(path)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
