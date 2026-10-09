"""Tests for the Image Redact fixes from the security review: nothing goes out before
text detection is done, only real image types open, Windows programs come from fixed
places, no copy of the image is left behind, boxes are always solid and fully cover,
failures aren't silent, and files are written and moved safely.

Run from the repo root:  python3 tests/test_security_image.py (or every test file with
python3 -m unittest discover -s tests)
"""
import contextlib
import errno
import io
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tools  # noqa: E402  (shared environment and sys.path setup)
from awskit import imageedit, imageredact  # noqa: E402

import cairo  # noqa: E402

ROOT = test_tools.ROOT
make_png, pixel = test_tools.make_png, test_tools.pixel


def account_words(top=20):
    """One OCR pass that read an account ID, the way tesseract reports it."""
    return [imageredact.Word("123456789012", 20, top, 120, 14, 95, (0, 1), None)]


def huge_png_header(w, h):
    """The start of a PNG that says it's w by h. Nothing past the header is needed, since
    the size has to be refused before anything gets decoded."""
    ihdr = struct.pack(">II", w, h) + bytes([8, 6, 0, 0, 0])
    return imageredact.PNG_SIGNATURE + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\0" * 4


def covered(png, box):
    """Pixels inside box (x1, y1, x2, y2) that aren't black."""
    s = cairo.ImageSurface.create_from_png(io.BytesIO(png))
    s.flush()
    data, stride = s.get_data(), s.get_stride()
    x1, y1, x2, y2 = box
    return [(x, y) for y in range(y1, y2) for x in range(x1, x2)
            if data[y * stride + x * 4: y * stride + x * 4 + 3] != b"\0\0\0"]


class Folder(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="awskit-fix-")

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.folder, *parts)


# =================================================================== 1, 10: save and copy

class EditorWaitsForDetectionTests(Folder):
    def setUp(self):
        super().setUp()
        self.ed = imageedit.Editor()
        self.ed.load(make_png(300, 120), self.path("shot.png"))

    def test_save_and_copy_wait_while_detection_runs(self):
        ed = self.ed
        gen = ed.start_finding()
        self.assertTrue(ed.finding)
        out = ed.write(self.path("out.png"))
        self.assertEqual((out.kind, out.message), ("error", imageedit.BUSY))
        self.assertFalse(os.path.exists(self.path("out.png")))
        with self.assertRaises(imageredact.ImageError):
            ed.copy_png()
        msg = ed.found(gen, [account_words()])
        self.assertIn("1 account ID", msg)
        self.assertFalse(ed.finding)
        self.assertEqual(ed.write(self.path("out.png")).kind, "done")
        with open(self.path("out.png"), "rb") as fh:
            self.assertEqual(pixel(fh.read(), 50, 27), (0, 0, 0))
        self.assertEqual(pixel(ed.copy_png(), 50, 27), (0, 0, 0))

    def test_a_new_image_drops_the_old_detection(self):
        ed = self.ed
        old = ed.start_finding()
        ed.load(make_png(300, 120), None)
        self.assertFalse(ed.finding)
        self.assertIsNone(ed.found(old, [account_words()]))
        self.assertEqual(ed.shapes, [])

    def test_copy_counts_only_once_it_is_on_the_clipboard(self):
        ed = self.ed
        self.ed.set_tool("cover")
        ed.drag_begin(10, 10, 1.0)
        ed.drag_update(60, 40, False, 1.0)
        ed.drag_end(1.0)
        self.assertTrue(ed.unsaved)
        ed.copy_png()
        self.assertTrue(ed.unsaved)      # the clipboard write could still fail
        ed.copied()
        self.assertFalse(ed.unsaved)

    def test_failed_detection_lets_you_save(self):
        ed = self.ed
        gen = ed.start_finding()
        msg = ed.find_failed(gen, imageredact.OcrError("tesseract failed: boom\nmore"))
        self.assertEqual(msg, "tesseract failed: boom")
        self.assertFalse(ed.finding)
        self.assertEqual(ed.write(self.path("out.png")).kind, "done")


class FakeWidget:
    def __init__(self):
        self.on = True

    def set_sensitive(self, on):         # GTK
        self.on = on

    def state(self, flags):              # ttk
        self.on = flags != ["disabled"]

    def __getattr__(self, name):         # set_tooltip_text, set_label, configure
        return lambda *a, **k: None


class FakeWindow:
    """Stands in for the GTK ImageEditor or the TkEditor, to call their methods on."""

    def __init__(self, ed):
        self.ed, self.ocr_ok, self.zoom, self.statuses = ed, True, 1.0, []
        for name in ("save_btn", "copy_btn", "name_entry", "folder_btn", "find_btn",
                     "undo_btn", "redo_btn", "delete_btn", "zoom_label", "zoom_btn"):
            setattr(self, name, FakeWidget())

    def set_status(self, text, busy=False):
        self.statuses.append((text, busy))


_image_tk = []


def import_image_tk():
    """image_tk needs tkinter and Pillow. Where they're missing, stand-ins let the module
    load so its methods can be called on a FakeWindow."""
    if _image_tk:
        return _image_tk[0]
    try:
        from awskit import image_tk
        _image_tk.append(image_tk)
        return image_tk
    except ImportError:
        pass

    class Stub(types.ModuleType):
        def __getattr__(self, name):
            if name.startswith("__"):
                raise AttributeError(name)
            value = type(name, (), {})
            setattr(self, name, value)
            return value
    with mock.patch.dict(sys.modules, {"tkinter": Stub("tkinter"), "PIL": Stub("PIL")}):
        sys.modules.pop("awskit.image_tk", None)
        from awskit import image_tk
    _image_tk.append(image_tk)
    return image_tk


def import_image_page():
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from awskit import image_page
    except (ImportError, ValueError):
        return None
    return image_page


class WindowsWaitForDetectionTests(Folder):
    """The Save and Copy buttons and shortcuts in both windows."""

    def setUp(self):
        super().setUp()
        self.ed = imageedit.Editor()
        self.ed.load(make_png(300, 120), self.path("shot.png"))
        self.ed.folder = self.folder

    def windows(self):
        image_tk = import_image_tk()
        out = [("tk", image_tk, image_tk.TkEditor, "write_clipboard_image")]
        page = import_image_page()
        if page is not None:
            out.append(("gtk", page, page.ImageEditor, "set_clipboard_image"))
        return out

    def test_buttons_and_shortcuts_wait(self):
        for name, module, cls, clip in self.windows():
            with self.subTest(name):
                win = FakeWindow(self.ed)
                self.ed.start_finding()
                cls._update_state(win)
                self.assertFalse(win.save_btn.on)
                self.assertFalse(win.copy_btn.on)
                self.assertFalse(win.find_btn.on)
                self.assertTrue(win.name_entry.on)
                put = mock.Mock()
                with mock.patch.object(module, clip, put):
                    cls.copy(win)      # what Ctrl+C calls
                    cls.save(win)      # what Ctrl+S calls
                put.assert_not_called()
                self.assertEqual(os.listdir(self.folder), [])
                self.assertEqual(win.statuses[-1], (imageedit.BUSY, True))
                self.ed._finding = None
                cls._update_state(win)
                self.assertTrue(win.save_btn.on)
                self.assertTrue(win.copy_btn.on)

    def test_a_failed_copy_still_asks_before_closing(self):
        from awskit.common import ClipboardError
        for name, module, cls, clip in self.windows():
            with self.subTest(name):
                self.ed.unsaved = True
                win = FakeWindow(self.ed)
                if name == "gtk":
                    from gi.repository import GLib
                    error = GLib.Error("no clipboard")
                else:
                    error = ClipboardError("no clipboard")
                with mock.patch.object(module, clip, mock.Mock(side_effect=error)):
                    cls.copy(win)
                self.assertTrue(self.ed.unsaved)
                with mock.patch.object(module, clip, mock.Mock()):
                    cls.copy(win)
                self.assertFalse(self.ed.unsaved)


# =================================================================== 14: log size

class TkLogTests(Folder):
    def test_log_starts_over_once_it_is_big(self):
        image_tk = import_image_tk()
        log = Path(self.folder) / "image-redact.log"
        log.write_text("x" * (image_tk.LOG_LIMIT + 10))
        win = FakeWindow(None)
        try:
            raise ValueError("boom")
        except ValueError as exc:
            with mock.patch.object(image_tk, "CONFIG_DIR", Path(self.folder)):
                image_tk.TkEditor._report_error(win, ValueError, exc, exc.__traceback__)
                size = log.stat().st_size
                self.assertLess(size, 10_000)
                self.assertIn("ValueError: boom", log.read_text())
                image_tk.TkEditor._report_error(win, ValueError, exc, exc.__traceback__)
                self.assertGreater(log.stat().st_size, size)   # small logs keep growing
        self.assertIn("Something went wrong", win.statuses[-1][0])


class TkShortcutTests(unittest.TestCase):
    def test_ctrl_z_undoes_with_caps_lock_on(self):
        """Caps Lock makes Tk send a capital Z, which used to redo. Only Shift redoes."""
        image_tk = import_image_tk()
        calls = []

        class Root:
            def __init__(self):
                self.bound = {}

            def bind(self, sequence, handler):
                self.bound[sequence] = handler
        win = types.SimpleNamespace(root=Root(), _typing=lambda: False)
        for name in ("open_dialog", "paste", "save", "copy", "find_pii", "undo", "redo",
                     "post_folder_menu", "zoom_fit", "step_zoom", "focus_name", "_key"):
            setattr(win, name, lambda *_a, name=name: calls.append(name))
        win._guard = types.MethodType(image_tk.TkEditor._guard, win)
        image_tk.TkEditor._bind_keys(win)
        shift, lock = 0x0001, 0x0002
        for sequence, state, want in (("<Control-z>", 0, "undo"), ("<Control-Z>", lock, "undo"),
                                      ("<Control-Z>", shift, "redo"),
                                      ("<Control-z>", shift | lock, "redo"),
                                      ("<Control-y>", 0, "redo"), ("<Control-S>", lock, "save")):
            calls.clear()
            handler = win.root.bound[sequence]
            self.assertEqual(handler(types.SimpleNamespace(state=state)), "break")
            self.assertEqual(calls, [want], (sequence, state))

    def test_a_failed_callback_keeps_the_job_loop_going(self):
        """If one background job's callback raised, the loop stopped for good, and Open,
        Paste and text detection never finished after that."""
        import queue
        image_tk = import_image_tk()
        later, done, errors = [], [], []
        win = types.SimpleNamespace(jobs=queue.Queue(),
                                    root=types.SimpleNamespace(after=lambda ms, fn: later.append(fn)),
                                    _report_error=lambda *exc: errors.append(exc[1]),
                                    _poll=lambda: None)

        def broken(value):
            raise ValueError(value)
        win.jobs.put((broken, "first"))
        win.jobs.put((done.append, "second"))
        image_tk.TkEditor._poll(win)
        self.assertEqual(done, ["second"])
        self.assertEqual([str(e) for e in errors], ["first"])
        self.assertEqual(len(later), 1)

    def test_only_the_last_open_or_paste_counts(self):
        """A slow open that finished after a paste replaced the pasted image."""
        image_tk = import_image_tk()
        jobs, loaded = [], []
        win = types.SimpleNamespace(confirm_discard=lambda: True, set_status=lambda *a, **k: None,
                                    run_bg=lambda work, done, failed=None: jobs.append(done),
                                    load_png=lambda png, path: loaded.append(path))
        for name in ("_latest", "open_path", "paste", "_pasted", "_paste_failed"):
            setattr(win, name, types.MethodType(getattr(image_tk.TkEditor, name), win))
        win.open_path("slow.png")
        win.paste()
        jobs[1](b"pasted")                 # the paste comes back first
        jobs[0](b"slow")                   # then the open asked for before it
        self.assertEqual(loaded, [None])


# =================================================================== 2, 8: opening files

class FakePillow:
    """Just enough of Pillow to see what load_image_bytes asks it for."""

    def __init__(self, size=(40, 30), fail=None):
        self.formats, self.decoded = [], False
        test = self

        class UnidentifiedImageError(OSError):
            pass

        class DecompressionBombError(Exception):
            pass

        class Img:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        img = Img()
        img.size = size

        def open_(path, mode="r", formats=None):
            test.formats.append(formats)
            if fail == "unknown":
                raise UnidentifiedImageError("cannot identify image file")
            if fail == "bomb":
                raise DecompressionBombError("too many pixels")
            return img

        def transpose(image):
            test.decoded = True
            return image
        self.image = types.SimpleNamespace(open=open_, UnidentifiedImageError=UnidentifiedImageError,
                                           DecompressionBombError=DecompressionBombError)
        self.ops = types.SimpleNamespace(exif_transpose=transpose)

    def modules(self):
        pil = types.ModuleType("PIL")
        pil.Image, pil.ImageOps = self.image, self.ops
        return {"PIL": pil, "PIL.Image": self.image, "PIL.ImageOps": self.ops}


class OpenTests(Folder):
    def postscript(self):
        path = self.path("fake.png")
        with open(path, "w") as fh:
            fh.write("%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\nshowpage\n")
        return path

    def test_postscript_named_png_is_refused(self):
        with self.assertRaisesRegex(imageredact.ImageError, "isn't a PNG, JPEG"):
            imageredact.load_image_bytes(self.postscript())

    def test_pillow_is_told_which_types_to_open(self):
        fake = FakePillow(fail="unknown")
        with mock.patch.dict(sys.modules, fake.modules()):
            with self.assertRaisesRegex(imageredact.ImageError, "isn't a PNG, JPEG"):
                imageredact.load_image_bytes(self.postscript())
        self.assertEqual(fake.formats, [["PNG", "JPEG", "WEBP", "BMP", "GIF", "TIFF"]])

    def test_pillow_size_limits(self):
        path = self.path("big.bmp")
        with open(path, "wb") as fh:
            fh.write(b"BM" + b"\0" * 60)
        fake = FakePillow(size=(12000, 10000))
        with mock.patch.dict(sys.modules, fake.modules()):
            with self.assertRaisesRegex(imageredact.ImageError, "too big to open: 12000x10000"):
                imageredact.load_image_bytes(path)
        self.assertFalse(fake.decoded)
        fake = FakePillow(fail="bomb")
        with mock.patch.dict(sys.modules, fake.modules()):
            with self.assertRaisesRegex(imageredact.ImageError, "too big to open"):
                imageredact.load_image_bytes(path)

    def test_gdkpixbuf_checks_type_and_size_too(self):
        path = self.path("big.bmp")
        header = (b"BM" + struct.pack("<IHHI", 54, 0, 0, 54) +
                  struct.pack("<IiiHHIIiiII", 40, 20000, 10000, 1, 24, 0, 0, 2835, 2835, 0, 0))
        with open(path, "wb") as fh:
            fh.write(header + b"\0" * 64)
        with mock.patch.dict(sys.modules, {"PIL": None}):   # no Pillow, like a bare Linux
            try:
                import gi
                gi.require_version("GdkPixbuf", "2.0")
            except (ImportError, ValueError):
                self.skipTest("GdkPixbuf not installed")
            with self.assertRaisesRegex(imageredact.ImageError, "too big to open: 20000x10000"):
                imageredact.load_image_bytes(path)
            with self.assertRaisesRegex(imageredact.ImageError, "isn't a PNG, JPEG"):
                imageredact.load_image_bytes(self.postscript())

    def test_huge_png_is_refused_before_decoding(self):
        data = huge_png_header(20000, 10000)
        with self.assertRaisesRegex(imageredact.ImageError, "too big to open: 20000x10000"):
            imageredact.surface_from_png(data)
        path = self.path("huge.png")
        with open(path, "wb") as fh:
            fh.write(data)
        with self.assertRaisesRegex(imageredact.ImageError, "too big"):
            imageredact.load_image_bytes(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = imageredact.main([path, "-o", self.path("out.png")])
        self.assertEqual(code, 1)
        self.assertIn("too big to open", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertEqual(imageredact.png_size(make_png(30, 20)), (30, 20))
        imageredact.surface_from_png(make_png(30, 20))   # normal ones still open


# =================================================================== 3: Windows programs

class WindowsProgramTests(Folder):
    def touch(self, *parts):
        path = self.path(*parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb").close()
        return path

    def test_tesseract_only_exe_from_path_folders(self):
        here = self.path("cwd")
        self.touch("cwd", "tesseract.exe")
        self.touch("cwd", "rel", "tesseract.exe")
        self.touch("bats", "tesseract.bat")
        self.touch("bats", "tesseract.cmd")
        exe = self.touch("bin", "tesseract.exe")
        old = os.getcwd()
        env = {"LOCALAPPDATA": "", "ProgramFiles": "", "ProgramFiles(x86)": ""}
        try:
            os.chdir(here)
            with mock.patch.object(imageredact, "WINDOWS", True):
                for path, want in (
                        (["", ".", "rel", self.path("bats"), self.path("bin")], exe),
                        (["", ".", "rel", self.path("bats")], None)):
                    env["PATH"] = os.pathsep.join(path)
                    with mock.patch.dict(os.environ, env):
                        self.assertEqual(imageredact.tesseract_path(), want)
                env["PATH"] = ""
                env["LOCALAPPDATA"] = self.folder
                installed = self.touch("Programs\\Tesseract-OCR", "tesseract.exe")
                with mock.patch.dict(os.environ, env):
                    self.assertEqual(imageredact.tesseract_path(), installed)
        finally:
            os.chdir(old)

    def test_powershell_comes_from_the_windows_folder(self):
        ps = self.touch("Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        self.touch("cwd", "powershell.exe")
        old = os.getcwd()
        try:
            os.chdir(self.path("cwd"))
            with mock.patch.object(imageredact, "WINDOWS", True):
                with mock.patch.dict(os.environ, {"SystemRoot": self.path("Windows"),
                                                  "PATH": "." + os.pathsep + self.path("cwd")}):
                    self.assertEqual(imageredact.powershell_path(), ps)
                    self.assertTrue(imageredact.windows_ocr_available())
                with mock.patch.dict(os.environ, {"SystemRoot": self.path("nothing"),
                                                  "PATH": "." + os.pathsep + self.path("cwd")}):
                    self.assertIsNone(imageredact.powershell_path())
                    self.assertFalse(imageredact.windows_ocr_available())
        finally:
            os.chdir(old)


# =================================================================== 4: temporary copies

class NoCopyLeftBehindTests(Folder):
    @unittest.skipUnless(shutil.which("tesseract"), "tesseract not installed")
    def test_tesseract_reads_from_stdin(self):
        calls = []
        real = imageredact._run_tool

        def spy(cmd, data=None, env=None, timeout=180):
            calls.append((cmd, data))
            return real(cmd, data=data, env=env, timeout=timeout)
        png = (ROOT / "image-redact" / "examples" / "sample-screenshot.png").read_bytes()
        with mock.patch.object(imageredact, "_run_tool", spy), \
                mock.patch.object(imageredact.tempfile, "mkdtemp",
                                  mock.Mock(side_effect=AssertionError("wrote a temp copy"))):
            passes = imageredact.read_text(png)
        self.assertTrue(any(w.text for words in passes for w in words))
        self.assertTrue(calls)
        for cmd, data in calls:
            self.assertEqual(cmd[1], "stdin")
            self.assertTrue(data.startswith(imageredact.PNG_SIGNATURE))

    def test_windows_tesseract_reads_a_private_file_that_is_removed(self):
        seen = []

        def fake_tesseract(cmd, data=None, env=None, timeout=180):
            seen.append((cmd[1], os.path.exists(cmd[1]), data))
            return subprocess.CompletedProcess(cmd, 0, b"<html></html>", b"")
        png = (ROOT / "image-redact" / "examples" / "sample-screenshot.png").read_bytes()
        with mock.patch.object(imageredact, "WINDOWS", True), \
                mock.patch.object(imageredact, "tesseract_path", lambda: "tesseract.exe"), \
                mock.patch.object(imageredact, "_run_tool", fake_tesseract):
            imageredact.read_text(png)
        self.assertTrue(seen)
        for path, existed, data in seen:
            self.assertTrue(existed)
            self.assertIsNone(data)
            self.assertFalse(os.path.exists(path))              # removed afterwards
            self.assertIn("awskit-ocr-", path)

    def test_windows_ocr_file_is_removed_after(self):
        seen = []

        def fake_powershell(cmd, data=None, env=None, timeout=180):
            path = env["AWSKIT_OCR_IMAGE"]
            with open(path, "rb") as fh:
                self.assertTrue(fh.read(8) == imageredact.PNG_SIGNATURE)
            seen.append(os.path.dirname(path))
            return subprocess.CompletedProcess(cmd, 0, b"0\t40\t40\t240\t28\t123456789012\n", b"")
        with mock.patch.object(imageredact, "tesseract_path", lambda: None), \
                mock.patch.object(imageredact, "windows_ocr_available", lambda: True), \
                mock.patch.object(imageredact, "powershell_path", lambda: "powershell.exe"), \
                mock.patch.object(imageredact, "_run_tool", fake_powershell):
            passes = imageredact.read_text(make_png(300, 120))
        self.assertEqual(passes[0][0].text, "123456789012")
        self.assertTrue(seen)
        self.assertTrue(all(os.path.basename(f).startswith("awskit-ocr-") for f in seen))
        self.assertFalse(any(os.path.exists(f) for f in seen))
        self.assertEqual(imageredact._temp_folders, set())

    @unittest.skipIf(os.name == "nt", "uses a shell script")
    def test_closing_mid_detection_stops_ocr_and_removes_the_copy(self):
        slow = self.path("slow-ocr")
        with open(slow, "w") as fh:
            fh.write("#!/bin/sh\nexec sleep 60\n")
        os.chmod(slow, 0o755)
        script = (
            "import io, os, sys, threading, time\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from awskit import imageredact as ir\n"
            "import cairo\n"
            "ir.tesseract_path = lambda: None\n"
            "ir.windows_ocr_available = lambda: True\n"
            "ir.powershell_path = lambda: sys.argv[2]\n"
            "s = cairo.ImageSurface(cairo.FORMAT_RGB24, 60, 20)\n"
            "buf = io.BytesIO(); s.write_to_png(buf)\n"
            "threading.Thread(target=ir.read_text, args=(buf.getvalue(),), daemon=True).start()\n"
            "for _ in range(1000):\n"
            "    with ir._cleanup_lock:\n"
            "        procs, folders = list(ir._running), list(ir._temp_folders)\n"
            "    if procs and folders and os.listdir(folders[0]):\n"
            "        break\n"
            "    time.sleep(0.01)\n"
            "print(folders[0]); print(procs[0].pid)\n")
        r = subprocess.run([sys.executable, "-c", script, str(ROOT), slow],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        folder, pid = r.stdout.split()
        self.assertTrue(os.path.basename(folder).startswith("awskit-ocr-"))
        self.assertFalse(os.path.exists(folder))
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid), 0)


# =================================================================== 5, 6: drawing

class SolidBoxTests(unittest.TestCase):
    def test_see_through_colors_still_save_solid(self):
        png = make_png(120, 80)
        cover = imageredact.cover_shape([10, 10, 50, 40, "AccountID"], (0, 0, 0, 0.2))
        filled = {"kind": "rect", "x1": 60, "y1": 10, "x2": 110, "y2": 40, "fill": True,
                  "color": [0, 0, 0, 0.3], "width": 4}
        oval = {"kind": "oval", "x1": 10, "y1": 45, "x2": 110, "y2": 78, "fill": True,
                "color": [0, 0, 0, 0.0], "width": 4}
        out = imageredact.encode(png, [cover, filled, oval], ".png")
        self.assertEqual(covered(out, (10, 10, 50, 40)), [])
        self.assertEqual(covered(out, (60, 10, 110, 40)), [])
        self.assertEqual(pixel(out, 60, 61), (0, 0, 0))

    def test_see_through_is_only_for_the_screen(self):
        s = cairo.ImageSurface(cairo.FORMAT_RGB24, 40, 40)
        cr = cairo.Context(s)
        cr.set_source_rgb(1, 1, 1)
        cr.paint()
        imageredact.draw_shapes(cr, [imageredact.cover_shape([0, 0, 40, 40], (0, 0, 0, 1))],
                                see_through=True)
        buf = io.BytesIO()
        s.write_to_png(buf)
        self.assertGreater(pixel(buf.getvalue(), 20, 20)[0], 100)

    def test_rounded_covers_cover_every_pixel(self):
        sizes = [(200, 20), (200, 100), (80, 40), (7, 5), (1, 1), (33, 31), (300, 300), (9, 120)]
        radii = [1, 3, 7.5, 20, 60, 150]
        for w, h in sizes:
            png = make_png(w + 100, h + 100)
            for r in radii:
                with self.subTest(w=w, h=h, r=r):
                    box = imageredact.cover_shape([50, 50, 50 + w, 50 + h, "x"], (0, 0, 0, 1),
                                                  radius=r)
                    out = imageredact.encode(png, [box], ".png")
                    self.assertEqual(covered(out, (50, 50, 50 + w, 50 + h)), [])
        # The rounding still shows: the corner of the grown box stays clear.
        out = imageredact.encode(make_png(300, 200), [imageredact.cover_shape(
            [50, 50, 250, 150], (0, 0, 0, 1), radius=60)], ".png")
        self.assertEqual(pixel(out, 33, 33), (255, 255, 255))


# =================================================================== 7: partial detection

class PartialDetectionTests(Folder):
    def fake_passes(self, inverted):
        def run(exe, surface, scale, invert, language, results, index, folder=None):
            if not invert:
                results[index] = account_words()
            elif inverted is not None:
                results[index] = inverted
        return run

    def read(self, inverted):
        with mock.patch.object(imageredact, "tesseract_path", lambda: "tesseract"), \
                mock.patch.object(imageredact, "ocr_plan", lambda s: [False, True]), \
                mock.patch.object(imageredact, "_run_pass", self.fake_passes(inverted)):
            return imageredact.detect(make_png(300, 120))

    def test_a_failed_pass_is_reported(self):
        with self.assertRaises(imageredact.PartialOcrError) as ctx:
            self.read(imageredact.OcrError("tesseract failed: boom"))
        exc = ctx.exception
        self.assertEqual(str(exc), "Only part of the text check ran: tesseract failed: boom.")
        self.assertEqual([b[4] for b in exc.boxes], ["AccountID"])
        with self.assertRaisesRegex(imageredact.PartialOcrError, "stopped partway"):
            self.read(None)     # a pass that crashed

    def test_all_passes_failing_is_a_plain_error(self):
        def run(exe, surface, scale, invert, language, results, index, folder=None):
            results[index] = imageredact.OcrError("tesseract failed: boom")
        with mock.patch.object(imageredact, "tesseract_path", lambda: "tesseract"), \
                mock.patch.object(imageredact, "ocr_plan", lambda s: [False, True]), \
                mock.patch.object(imageredact, "_run_pass", run):
            with self.assertRaises(imageredact.OcrError) as ctx:
                imageredact.read_text(make_png(300, 120))
        self.assertNotIsInstance(ctx.exception, imageredact.PartialOcrError)

    def partial(self, png, language="eng"):
        raise imageredact.PartialOcrError(imageredact.OcrError("tesseract failed: boom"),
                                          [account_words()])

    def test_command_line_warns_and_exits_1(self):
        src, out = self.path("shot.png"), self.path("out.png")
        imageredact.write_atomic(src, make_png(300, 120))
        err = io.StringIO()
        with mock.patch.object(imageredact, "read_text", self.partial), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(imageredact.main([src, "-o", out]), 1)
            self.assertEqual(imageredact.main([src, "--list"]), 1)
        self.assertIn("warning: Only part of the text check ran", err.getvalue())
        with open(out, "rb") as fh:
            self.assertEqual(pixel(fh.read(), 50, 27), (0, 0, 0))

    def test_clip_warns(self):
        told, put = [], []
        with mock.patch.object(imageredact, "read_text", self.partial), \
                mock.patch.object(imageredact, "read_clipboard_image", lambda: make_png(300, 120)), \
                mock.patch.object(imageredact, "write_clipboard_image", put.append), \
                mock.patch.object(imageredact, "tell", lambda msg, title="": told.append(msg)):
            self.assertEqual(imageredact.main(["clip"]), 1)
        self.assertTrue(told[0].startswith("Only part of the text check ran"))
        self.assertEqual(pixel(put[0], 50, 27), (0, 0, 0))

    def test_editor_shows_it_and_reads_again(self):
        ed = imageedit.Editor()
        ed.load(make_png(300, 120), None)
        gen = ed.start_finding()
        try:
            self.partial(None)
        except imageredact.PartialOcrError as exc:
            msg = ed.find_failed(gen, exc)
        self.assertTrue(msg.startswith("Only part of the text check ran"))
        self.assertIn("1 account ID", msg)
        self.assertFalse(ed.finding)
        self.assertTrue(ed.ocr_warning)       # so Find PII reads it again
        self.assertTrue(ed.apply_passes().startswith("Only part"))
        self.assertEqual(ed.found(ed.start_finding(), [account_words()]),
                         "Covered 1: 1 account ID. Check it over and cover anything it missed.")
        self.assertEqual(ed.ocr_warning, "")


# =================================================================== 9, 11: files

class FileTests(Folder):
    def test_write_atomic_never_changes_the_umask(self):
        path = self.path("sub", "a.png")
        with mock.patch("os.umask", mock.Mock(side_effect=AssertionError("umask changed"))):
            imageredact.write_atomic(path, b"data")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644 & ~imageredact.UMASK)

    def replace_failing(self, src, dest, code):
        real = os.replace

        def fake(a, b, *args, **kw):
            if (os.fspath(a), os.fspath(b)) == (src, dest):
                raise OSError(code, os.strerror(code))
            return real(a, b, *args, **kw)
        return mock.patch("os.replace", fake)

    def test_failed_move_leaves_the_file_there_alone(self):
        src, dest = self.path("a.png"), self.path("b.png")
        imageredact.write_atomic(src, make_png(10, 10))
        imageredact.write_atomic(dest, b"keep me")
        with self.replace_failing(src, dest, errno.EACCES):
            with self.assertRaises(OSError):
                imageredact.relocate(src, dest)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"keep me")
        self.assertTrue(os.path.exists(src))

    def test_move_to_another_drive_copies_then_removes(self):
        src, dest = self.path("a.png"), self.path("b.png")
        data = make_png(10, 10)
        imageredact.write_atomic(src, data)
        imageredact.write_atomic(dest, b"old")
        with self.replace_failing(src, dest, errno.EXDEV):
            self.assertEqual(imageredact.relocate(src, dest), dest)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertFalse(os.path.exists(src))

    def test_names_windows_would_misread(self):
        for typed in ("D:x.png", "a.png:b", 'x<y>z"|?*.png', "tab\there.png", "C:\\x\\y.png"):
            with self.subTest(typed=typed):
                name = imageredact.clean_name(typed, ".png")
                self.assertFalse(set(name) & set('<>:"/\\|?*'), name)
                self.assertFalse(any(ord(c) < 32 for c in name), name)
                self.assertEqual(os.path.basename(name), name)
                self.assertTrue(name.endswith(".png"))
        self.assertEqual(imageredact.clean_name("D:x.png"), "D-x.png")
        self.assertEqual(imageredact.clean_name("a/b.jpg"), "a-b.jpg")


# =================================================================== 12: -o

class OutputTests(Folder):
    def setUp(self):
        super().setUp()
        self.src = self.path("a.png")
        self.original = make_png(300, 120)
        imageredact.write_atomic(self.src, self.original)
        self.detect = mock.Mock(return_value=([[20, 20, 140, 34, "AccountID"]], (300, 120)))

    def run_cli(self, *argv):
        err = io.StringIO()
        with mock.patch.object(imageredact, "detect", self.detect), \
                contextlib.redirect_stderr(err):
            code = imageredact.main(list(argv))
        return code, err.getvalue()

    def test_input_is_not_replaced_without_force(self):
        for out in (self.src, self.path(".", "a.png")):
            code, err = self.run_cli(self.src, "-o", out)
            self.assertEqual(code, 1)
            self.assertIn("--force", err)
        self.detect.assert_not_called()
        with open(self.src, "rb") as fh:
            self.assertEqual(fh.read(), self.original)
        code, _ = self.run_cli(self.src, "-o", self.src, "--force")
        self.assertEqual(code, 0)
        with open(self.src, "rb") as fh:
            self.assertEqual(pixel(fh.read(), 50, 27), (0, 0, 0))

    def test_only_types_it_can_write(self):
        code, err = self.run_cli(self.src, "-o", self.path("x.webp"))
        self.assertEqual(code, 1)
        self.assertIn("can't save .webp", err)
        self.assertFalse(os.path.exists(self.path("x.webp")))
        code, _ = self.run_cli(self.src, "-o", self.path("x.jpg"))
        self.assertEqual(code, 0)
        with open(self.path("x.jpg"), "rb") as fh:
            self.assertEqual(fh.read(2), b"\xff\xd8")
        code, _ = self.run_cli(self.src, "-o", self.path("noext"))
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.path("noext.png")))
        code, _ = self.run_cli(self.src, "-o", self.path("dir") + "/")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.path("dir", "a-redacted.png")))


if __name__ == "__main__":
    unittest.main()
