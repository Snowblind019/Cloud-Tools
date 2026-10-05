"""Cloud Map's draw.io editor: the local bridge server, and opening the editor on each
platform. No GTK at import time.

The editor is the draw.io web app the installers downloaded (see awskit/common.py for
the pinned version), always run offline. One design works everywhere:

- Bridge starts a small HTTP server on 127.0.0.1 only, on a random port, with a random
  token in every path. It serves editor/host.html, the draw.io files, and the one
  .drawio file being edited, and nothing else.
- host.html loads draw.io in an iframe in embed mode and speaks its JSON protocol: on
  init it fetches the diagram and loads it, on save it posts the XML back, on exit it
  tells the bridge.
- Every response carries a Content-Security-Policy that only allows 127.0.0.1 at that
  port, so whatever draw.io tries, the browser won't reach anywhere else.
- Saves are written atomically, then on_save runs (layout memory reads the file).

Each platform only needs something to show the bridge's URL: WebKitGTK inside the
Cloud Map page on Linux, an Edge app window on Windows, the Windows browser from WSL,
or the default browser as a last resort. draw.io desktop, when installed, opens the
.drawio file directly instead, and the page watches the file for its saves.
"""
from __future__ import annotations

import collections
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from .common import drawio_dir, drawio_installed, is_wsl, windows_tool
from .common import write_atomic as _write_atomic

HERE = Path(__file__).resolve().parent
EDITOR_DIR = HERE / "editor"
MAX_UPLOAD = 64 * 1024 * 1024
# How long a page in another window can go quiet before the session counts as closed.
# Browsers slow the heartbeat of a minimized or hidden window to about once a minute, so
# this is generous; closing the window normally is noticed within seconds anyway.
OUTSIDE_IDLE_S = 600.0
# Content types for what draw.io serves. Python's mimetypes can be changed by the Windows
# registry (.js as text/plain, for one), which the nosniff header would then block.
CONTENT_TYPES = {
    ".html": "text/html", ".htm": "text/html", ".js": "application/javascript",
    ".mjs": "application/javascript", ".css": "text/css", ".json": "application/json",
    ".xml": "application/xml", ".svg": "image/svg+xml", ".png": "image/png",
    ".gif": "image/gif", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
    ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
    ".otf": "font/otf", ".eot": "application/vnd.ms-fontobject", ".txt": "text/plain",
    ".wasm": "application/wasm", ".webmanifest": "application/manifest+json",
    ".mp3": "audio/mpeg", ".mp4": "video/mp4", ".pdf": "application/pdf",
}

# draw.io's URL options, checked against drawio.com/doc/faq/supported-url-parameters and
# drawio.com/doc/faq/embed-mode (draw.io 32.0):
#   embed=1 proto=json  embed mode, with the JSON postMessage protocol host.js speaks
#   spin=1              a spinner until the diagram is loaded
#   saveAndExit=1       a Save and Exit button next to Save
#   stealth=1           turns off features that need outside web services (PDF export...)
#   lockdown=1          also no realtime cache, no logging and no remote export
#   pwa=0               no progressive web app install
#   local=1 browser=0   device storage only, nothing kept in the browser
#   (offline=1 isn't used: in draw.io 32 it also hides the Save and Exit buttons that
#   embed mode needs, and stealth plus lockdown turn off the same outside services.)
#   drafts=0            no drafts kept in the browser's storage
#   gapi=0 db=0 od=0 tr=0 gh=0 gl=0 picker=0  no Google, Dropbox, OneDrive, Trello,
#                       GitHub or GitLab integration, and no Google file picker
#   splash=0 math=0     no splash screen, no MathJax
#   libraries=1 libs=   the shape libraries panel, with the AWS (aws4) library shown
#   ui=, dark=          the classic theme (menus, shapes on the left, format panel on the
#                       right, Save and Exit at the top right), dark or light to match the map
DRAWIO_PARAMS = {
    "embed": "1", "proto": "json", "spin": "1", "saveAndExit": "1", "stealth": "1",
    "lockdown": "1", "pwa": "0", "local": "1", "browser": "0", "drafts": "0", "gapi": "0",
    "db": "0", "od": "0", "tr": "0", "gh": "0", "gl": "0", "picker": "0", "splash": "0",
    "math": "0", "libraries": "1", "libs": "general;aws4", "ui": "kennedy", "lang": "en",
}

# draw.io's Editor configuration, given through PreConfig.js. compressXml=false keeps
# saved files readable, the same as AWS Kit writes them.
DRAWIO_CONFIG = {"compressXml": False, "defaultLibraries": "general;aws4",
                 "sidebarTitles": True, "showStartScreen": False}

# Added to draw.io's own PreConfig.js when the bridge serves it. It keeps a handle on the
# editor (for AWS Kit's Done button), passes the configuration above, and stops links
# (help pages, the GitHub link in the corner) from leaving 127.0.0.1, on top of the
# Content-Security-Policy. draw.io's files on disk aren't changed.
PRECONFIG_EXTRA = """
// ---- added by AWS Kit's Cloud Map bridge
window.DRAWIO_CONFIG = %s;
window.checkAllLoaded = function () {
  if (mxScriptsLoaded && mxWinLoaded) {
    App.main(function (ui) { window.awskitUi = ui; });
  }
};
(function () {
  function outside(url) {
    try {
      var u = new URL(url, location.href);
      return u.origin !== location.origin && u.protocol !== "blob:" && u.protocol !== "data:";
    } catch (e) { return false; }
  }
  var open = window.open;
  window.open = function (url) {
    if (url && outside(url)) { return null; }
    return open.apply(window, arguments);
  };
  document.addEventListener("click", function (evt) {
    var a = evt.target && evt.target.closest ? evt.target.closest("a[href]") : null;
    if (a && outside(a.href)) { evt.preventDefault(); evt.stopPropagation(); }
  }, true);
  var css = document.createElement("style");
  css.textContent = 'a[href^="http"]:not([href^="' + location.origin + '"]) { display: none !important; }';
  (document.head || document.documentElement).appendChild(css);
})();
"""

# How shapes drawn by hand look, so they're readable on the map's page color. draw.io
# writes these into each new shape's style.
DRAWN_STYLES = {
    "dark": {"fillColor": "#202020", "strokeColor": "#B4B2A9", "fontColor": "#F1EFE8"},
    "light": {"fillColor": "#FFFFFF", "strokeColor": "#5F5E5A", "fontColor": "#2C2C2A"},
}


# The page and its grid in the map's colors. draw.io's own dark grid is drawn on a white
# page, since the map's colors are fixed (adaptiveColors="none").
PAGE_COLORS = {"dark": {"page": "#1F1F1E", "grid": "#2E2E2C"},
               "light": {"page": "#FFFFFF", "grid": "#ECEBE6"}}


def drawio_config(theme="dark") -> dict:
    colors = DRAWN_STYLES.get(theme, DRAWN_STYLES["dark"])
    page = PAGE_COLORS.get(theme, PAGE_COLORS["dark"])
    config = dict(DRAWIO_CONFIG)
    config.update({"defaultGridColor": page["grid"], "defaultDarkGridColor": page["grid"],
                   "defaultPageBackgroundColor": page["page"],
                   "defaultDarkPageBackgroundColor": page["page"]})
    config["defaultVertexStyle"] = dict(colors)
    config["defaultEdgeStyle"] = {"edgeStyle": "orthogonalEdgeStyle", "rounded": "0",
                                  "jettySize": "auto", "orthogonalLoop": "1",
                                  "strokeColor": colors["strokeColor"],
                                  "fontColor": colors["fontColor"]}
    return config

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

BLOCKED_FILES = ("service-worker.js", "workbox-")


def csp(port) -> str:
    """Only this server: the page can't load, send or connect anywhere else."""
    me = f"http://127.0.0.1:{port}"
    return ("default-src 'self'; "
            f"script-src 'self' 'unsafe-inline' 'unsafe-eval' {me}; "
            f"style-src 'self' 'unsafe-inline' {me}; "
            f"img-src 'self' data: blob: {me}; font-src 'self' data: {me}; "
            f"connect-src 'self' {me}; frame-src 'self' {me}; child-src 'self' blob:; "
            "worker-src 'self' blob:; media-src 'self' data: blob:; object-src 'none'; "
            "base-uri 'self'; form-action 'none'; frame-ancestors 'self'")


class BridgeError(Exception):
    pass


def check_drawio(folder=None) -> Path:
    folder = Path(folder) if folder else drawio_dir()
    if not drawio_installed(folder):
        raise BridgeError(f"draw.io isn't downloaded to {folder}. Run the installer again "
                          "(./install.sh, or install-windows.cmd), or give it a draw.war "
                          "with --drawio-zip.")
    return folder


def looks_like_drawio(text: str) -> bool:
    head = text.lstrip()[:200]
    return head.startswith("<mxfile") or head.startswith("<mxGraphModel") or \
        (head.startswith("<?xml") and ("<mxfile" in text[:2000] or "<mxGraphModel" in text[:2000]))


def write_atomic(path: Path, text: str):
    """Write text to path so a reader never sees half a file. The temporary file has a
    new random name each time, so nothing planted next to path can redirect the write."""
    _write_atomic(Path(path), text)


class Bridge:
    """The local server between the draw.io page and AWS Kit. Callbacks run on the
    server's threads, so GTK code should hand them to the main loop."""

    def __init__(self, file_path, drawio=None, title="", theme="dark", on_save=None,
                 on_exit=None, on_event=None, idle_timeout=OUTSIDE_IDLE_S, library=None):
        self.file = Path(file_path)
        self.drawio = check_drawio(drawio)
        self.title = title or self.file.stem
        self.theme = theme
        self.on_save = on_save
        self.on_exit = on_exit
        self.on_event = on_event
        self.idle_timeout = idle_timeout
        self.library = Path(library) if library else None
        self.token = secrets.token_urlsafe(24)
        self.server = None
        self.thread = None
        self.saves = 0
        self.loaded = False
        self.closed = False
        self.last_seen = time.monotonic()
        self.requests = collections.deque(maxlen=500)  # (method, path) of recent requests
        self.errors = []
        self._lock = threading.Lock()
        self._watchdog = None

    # ---- lifecycle
    @property
    def port(self):
        return self.server.server_address[1] if self.server else 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/{self.token}/"

    def start(self) -> str:
        bridge = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = False

        class Handler(BridgeHandler):
            pass
        Handler.bridge = bridge
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="awskit-bridge",
                                       daemon=True)
        self.thread.start()
        if self.idle_timeout:
            self._watchdog = threading.Thread(target=self._watch, name="awskit-bridge-watch",
                                              daemon=True)
            self._watchdog.start()
        return self.url

    def stop(self):
        server, self.server = self.server, None
        self.closed = True
        if server is not None:
            # shutdown() waits for serve_forever, so it can't run on a request thread.
            threading.Thread(target=lambda: (server.shutdown(), server.server_close()),
                             daemon=True).start()

    def running(self) -> bool:
        return self.server is not None

    def _watch(self):
        """Stops the server once the page has gone quiet: a browser window closed without
        Exit stops sending its heartbeat."""
        while self.server is not None:
            time.sleep(1.0)
            if not self.loaded:
                continue
            if time.monotonic() - self.last_seen > self.idle_timeout:
                self._finish({"saved": False, "reason": "closed"})
                return

    def _finish(self, info):
        with self._lock:
            if self.closed:
                return
            self.closed = True
        try:
            if self.on_exit:
                self.on_exit(info)
        finally:
            self.stop()

    # ---- what the page asks for
    def drawio_url(self) -> str:
        params = dict(DRAWIO_PARAMS)
        params["dark"] = "1" if self.theme == "dark" else "0"
        query = "&".join(f"{k}={quote(str(v), safe=';')}" for k, v in params.items())
        return f"drawio/index.html?{query}"

    def host_page(self) -> bytes:
        text = (EDITOR_DIR / "host.html").read_text(encoding="utf-8")
        colors = {"dark": ("#1F1F1E", "#F1EFE8"), "light": ("#FFFFFF", "#2C2C2A")}
        bg, fg = colors.get(self.theme, colors["dark"])
        from html import escape
        text = (text.replace("__TITLE__", escape(self.title))
                    .replace("__DRAWIO_URL__", escape(self.drawio_url()))
                    .replace("__BACKGROUND__", bg).replace("__TEXT__", fg))
        return text.encode("utf-8")

    def preconfig(self) -> bytes:
        try:
            base = (self.drawio / "js" / "PreConfig.js").read_text(encoding="utf-8")
        except OSError:
            base = ""
        return (base + PRECONFIG_EXTRA % json.dumps(drawio_config(self.theme))).encode("utf-8")

    def static_file(self, rel: str):
        """A draw.io file, or None if rel isn't a plain path inside the draw.io folder."""
        rel = unquote(rel)
        if not rel or rel.startswith(("/", "\\")) or any(c in rel for c in "\\\0:"):
            return None
        parts = rel.split("/")
        if any(p in ("", ".", "..") for p in parts):
            return None
        if parts[-1].startswith(BLOCKED_FILES):
            return None
        try:
            root = self.drawio.resolve()
            path = (self.drawio / rel).resolve()
            if root not in path.parents or not path.is_file():
                return None
        except (OSError, ValueError):
            return None              # a name too long for the file system, for one
        return path

    def saved(self, text: str):
        if not looks_like_drawio(text):
            raise BridgeError("That isn't a draw.io diagram.")
        write_atomic(self.file, text)
        self.saves += 1
        if self.on_save:
            self.on_save(self.file)


def _json_object(body) -> dict:
    """A request body as a JSON object, or {} for anything else."""
    try:
        info = json.loads(body or b"{}")
    except ValueError:
        return {}
    return info if isinstance(info, dict) else {}


class BridgeHandler(http.server.BaseHTTPRequestHandler):
    bridge: Bridge = None
    timeout = 120                    # an idle connection doesn't hold a thread forever
    server_version = "AWSKit"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet: nothing to the terminal
        pass

    # ---- helpers
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", cache=False):
        b = self.bridge
        self.send_response(code)
        if code >= 400:
            # A refused request's body may not have been read, so the connection can't be
            # reused: whatever follows on it would be read as a new request.
            self.close_connection = True
            self.send_header("Connection", "close")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp(b.port))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Cache-Control", "private, max-age=3600" if cache else "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data, code=200):
        self._send(code, json.dumps(data).encode("utf-8"), "application/json")

    def _route(self):
        """The path after the token, or None when the request isn't allowed."""
        b = self.bridge
        host = self.headers.get("Host", "")
        if host not in (f"127.0.0.1:{b.port}", f"localhost:{b.port}"):
            return None      # another site's page pointed at this port (DNS rebinding)
        path = urlsplit(self.path).path
        prefix = f"/{b.token}/"
        given = path[:len(prefix)].encode("utf-8", "surrogateescape")
        if len(path) < len(prefix) or not secrets.compare_digest(given, prefix.encode("ascii")):
            return None
        return path[len(prefix):]

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_UPLOAD:
            return None
        return self.rfile.read(n)

    # ---- methods
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        b = self.bridge
        rel = self._route()
        b.requests.append(("GET", urlsplit(self.path).path))
        if rel is None:
            self._send(403, b"Forbidden")
            return
        b.last_seen = time.monotonic()
        if rel in ("", "index.html"):
            self._send(200, b.host_page(), "text/html; charset=utf-8")
        elif rel == "host.js":
            self._send(200, (EDITOR_DIR / "host.js").read_bytes(),
                       "application/javascript; charset=utf-8")
        elif rel == "file":
            try:
                text = b.file.read_bytes()
            except OSError as exc:
                self._send(500, str(exc).encode("utf-8"))
                return
            self._send(200, text, "application/xml; charset=utf-8")
        elif rel == "config":
            self._json(drawio_config(b.theme))
        elif rel == "library.xml" and b.library is not None:
            try:
                self._send(200, b.library.read_bytes(), "application/xml; charset=utf-8")
            except OSError:
                self._send(404, b"Not found")
        elif rel == "drawio/js/PreConfig.js":
            self._send(200, b.preconfig(), "application/javascript; charset=utf-8")
        elif rel.startswith("drawio/"):
            path = b.static_file(rel[len("drawio/"):])
            if path is None:
                self._send(404, b"Not found")
                return
            ctype = CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json",
                                                       "application/xml", "image/svg+xml"):
                ctype += "; charset=utf-8"
            self._send(200, path.read_bytes(), ctype, cache=True)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        b = self.bridge
        rel = self._route()
        b.requests.append(("POST", urlsplit(self.path).path))
        if rel is None:
            self._send(403, b"Forbidden")
            return
        body = self._body()
        if body is None:
            self._send(413, b"Too large")
            return
        b.last_seen = time.monotonic()
        if rel == "save":
            try:
                b.saved(body.decode("utf-8"))
            except (BridgeError, UnicodeDecodeError, OSError) as exc:
                b.errors.append(str(exc))
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            except Exception as exc:  # noqa: BLE001 - the file is saved, memory failed
                b.errors.append(f"Saved, but reading the layout back failed: {exc}")
                self._json({"ok": True, "warning": str(exc)})
                return
            self._json({"ok": True})
        elif rel == "exit":
            info = _json_object(body)
            self._json({"ok": True})
            try:
                self.wfile.flush()       # the reply is out before AWS Kit (or the command) ends
            except OSError:
                pass
            b._finish({"saved": bool(info.get("saved")), "reason": "exit"})
        elif rel in ("alive", "event"):
            info = _json_object(body)
            if info.get("event") == "loaded" or info.get("loaded"):
                b.loaded = True
            if rel == "event" and b.on_event:
                b.on_event(info)
            self._json({"ok": True})
        elif rel == "closed":
            # The page went away (closed or reloaded). The watchdog decides, so a reload
            # that comes straight back doesn't end the session.
            b.last_seen = time.monotonic() - max(0.0, (b.idle_timeout or 0) - 4)
            self._json({"ok": True})
        else:
            self._send(404, b"Not found")


# =================================================================== opening it

def webkit_problem():
    """Why the embedded editor can't be used here, or "" when WebKitGTK 6.0 loads."""
    if sys.platform == "win32":
        return "WebKitGTK isn't part of GTK for Windows"
    if is_wsl():
        prepare_webkit_env()
    try:
        import gi
        gi.require_version("WebKit", "6.0")
        from gi.repository import WebKit
    except (ImportError, ValueError):
        return "WebKitGTK 6.0 isn't installed"
    return "" if hasattr(WebKit, "WebView") else "WebKitGTK 6.0 has no WebView here"


def prepare_webkit_env():
    """WSL usually has no GPU WebKit can use. These turn its GPU paths off, before WebKit
    loads. Names checked against WebKitGTK 2.46 to 2.52."""
    for name in ("WEBKIT_DISABLE_DMABUF_RENDERER", "WEBKIT_DISABLE_COMPOSITING_MODE",
                 "WEBKIT_SKIA_ENABLE_CPU_RENDERING"):
        os.environ.setdefault(name, "1")


def _registry_path(name):
    """A program's path from Windows' App Paths registry key, which installers fill in."""
    try:
        import winreg
    except ImportError:
        return None
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{name}") as key:
                value = winreg.QueryValue(key, None)
        except OSError:
            continue
        value = (value or "").strip().strip('"')
        if value and os.path.isfile(value):
            return value
    return None


def _env_dirs(*names):
    return [os.environ[n] for n in names if os.environ.get(n)]


def edge_candidates():
    """Where Microsoft Edge normally lives, on Windows and seen from WSL."""
    out = []
    if sys.platform == "win32":
        for base in _env_dirs("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            out.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
    else:
        out += ["/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
                "/mnt/c/Program Files/Microsoft/Edge/Application/msedge.exe"]
    return out


def find_edge():
    """msedge.exe: the App Paths key first, then its standard install folders."""
    if sys.platform == "win32":
        found = _registry_path("msedge.exe")
        if found:
            return found
    elif not is_wsl():
        return None
    for path in edge_candidates():
        if os.path.isfile(path):
            return path
    return None


def drawio_desktop_candidates():
    out = []
    if sys.platform == "win32":
        for base in _env_dirs("LOCALAPPDATA"):
            out.append(os.path.join(base, "Programs", "draw.io", "draw.io.exe"))
        for base in _env_dirs("ProgramFiles", "ProgramFiles(x86)"):
            out.append(os.path.join(base, "draw.io", "draw.io.exe"))
    return out


def find_drawio_desktop():
    """draw.io desktop, if it's installed (Windows), or its command (Linux)."""
    if sys.platform == "win32":
        found = _registry_path("draw.io.exe")
        if found:
            return found
        for path in drawio_desktop_candidates():
            if os.path.isfile(path):
                return path
        return None
    for name in ("drawio", "draw.io"):
        found = shutil.which(name)
        if found:
            return found
    return None


TARGETS = {"edge": "Edge app window", "browser": "Default browser",
           "desktop": "draw.io desktop"}


def available_targets():
    """Which ways of opening the editor outside AWS Kit exist here, best first."""
    out = []
    if find_edge():
        out.append("edge")
    out.append("browser")
    if find_drawio_desktop():
        out.append("desktop")
    return out


def choose_target(setting, available):
    """The setting if it's available here, else the best one that is."""
    if setting in available:
        return setting
    return available[0] if available else "browser"


def _popen(cmd):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=flags,
                            close_fds=True)


def edge_profile_dir() -> str:
    """A separate Edge profile for the editor: no extensions, no sync, and its own
    process, so the window opens straight away and closing it ends cleanly."""
    from .common import data_dir
    folder = data_dir() / "edge-profile"
    folder.mkdir(parents=True, exist_ok=True)
    return str(folder)


def edge_command(edge, url, profile=None):
    cmd = [edge, f"--app={url}", "--new-window", "--no-first-run",
           "--no-default-browser-check", "--disable-sync", "--window-size=1440,900"]
    if profile:
        cmd.insert(1, f"--user-data-dir={profile}")
    return cmd


def open_in_edge(url):
    edge = find_edge()
    if not edge:
        raise BridgeError("Microsoft Edge wasn't found.")
    profile = edge_profile_dir() if sys.platform == "win32" else None
    return _popen(edge_command(edge, url, profile))


def browser_command(url):
    """How to open url in the default browser here, as a command, or None to use
    Python's webbrowser module."""
    if sys.platform == "win32":
        return None                  # os.startfile
    if is_wsl():
        if shutil.which("wslview"):
            return ["wslview", url]
        explorer = windows_tool("explorer.exe") or (
            "/mnt/c/Windows/explorer.exe" if os.path.isfile("/mnt/c/Windows/explorer.exe") else None)
        if explorer:
            return [explorer, url]
    if shutil.which("xdg-open"):
        return ["xdg-open", url]
    return None


def open_in_browser(url):
    if sys.platform == "win32":
        os.startfile(url)  # noqa: S606 - opens the default browser
        return None
    cmd = browser_command(url)
    if cmd:
        return _popen(cmd)
    import webbrowser
    webbrowser.open(url)
    return None


def open_in_desktop(path):
    exe = find_drawio_desktop()
    if not exe:
        raise BridgeError("draw.io desktop isn't installed.")
    return _popen([exe, str(path)])


def open_outside(target, url, path):
    """Open the editor outside AWS Kit. Returns (target used, process or None). Falls
    back to the next way when one fails."""
    order = [target] + [t for t in ("edge", "browser") if t != target]
    last = None
    for t in order:
        try:
            if t == "edge":
                return t, open_in_edge(url)
            if t == "desktop":
                return t, open_in_desktop(path)
            return t, open_in_browser(url)
        except (BridgeError, OSError) as exc:
            last = exc
    raise BridgeError(f"Couldn't open the editor: {last}")
