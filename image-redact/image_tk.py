"""Image Redact on Windows: the same editor as the GTK window, drawn with tkinter.

tkinter comes with Python on Windows, and pycairo and Pillow install with pip, so nothing
here needs admin rights. The editing itself is imageedit.py, the same code the Linux window
runs, and the canvas is drawn with the same cairo code, so it looks the same too.

AWSKIT_UI=tk awskit image opens this window on Linux as well, which is how it gets tested.
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
import traceback
from tkinter import colorchooser, filedialog, messagebox, ttk

import cairo
from PIL import Image, ImageTk

from . import imageedit as ie
from . import imageredact as ir
from . import redact
from .common import CONFIG_DIR, ClipboardError, read_clipboard_image, write_clipboard_image

WINDOWS = sys.platform == "win32"
PAD = ie.PAD
BG = (0.93, 0.93, 0.94)
INK = (0.13, 0.13, 0.15, 1.0)
INK_OFF = (0.6, 0.6, 0.63, 1.0)
APP_ID = "Snowblind019.AWSKit.ImageRedact"
LOG_LIMIT = 1_000_000  # bytes


# =================================================================== small helpers

def surface_photo(surface):
    surface.flush()
    w, h = surface.get_width(), surface.get_height()
    img = Image.frombuffer("RGBA", (w, h), bytes(surface.get_data()), "raw", "BGRA",
                           surface.get_stride(), 1)
    return ImageTk.PhotoImage(img)


def icon_photo(kind, size=18, rgba=INK):
    s = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ie.draw_icon(cairo.Context(s), kind, size, size, rgba)
    return surface_photo(s)


def swatch_photo(color, w=28, h=18):
    s = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, h)
    cr = cairo.Context(s)
    ir.rounded_rect(cr, 1, 1, w - 2, h - 2, 3)
    cr.set_source_rgba(*color)
    cr.fill_preserve()
    cr.set_source_rgba(0, 0, 0, 0.35)
    cr.set_line_width(1)
    cr.stroke()
    return surface_photo(s)


def app_icon_photo(size):
    s = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ie.draw_app_icon(cairo.Context(s), size)
    return surface_photo(s)


def to_hex(color):
    return "#%02x%02x%02x" % tuple(int(round(c * 255)) for c in color[:3])


class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tip, self.job = widget, text, None, None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _e):
        self.job = self.widget.after(550, self._show)

    def _show(self):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 8
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", background="#ffffe8",
                 relief="solid", borderwidth=1, wraplength=360, padx=6, pady=3).pack()

    def _hide(self, _e=None):
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.tip:
            self.tip.destroy()
            self.tip = None


# =================================================================== PII Redact settings

class RedactSettings(tk.Toplevel):
    """PII Redact's checkboxes and word lists, which decide what gets covered. They're the
    same settings file the Linux PII Redact uses."""

    def __init__(self, parent, on_saved):
        super().__init__(parent)
        self.title("What gets covered")
        self.geometry("620x720")
        self.on_saved = on_saved
        self.cfg = redact.load_config()
        self.vars = {}
        self._job = None

        outer = ttk.Frame(self, padding=(14, 12))
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Checked items get covered. Changes save right away and also "
                  "apply to PII Redact.", wraplength=560).pack(anchor="w", pady=(0, 8))

        holder = ttk.Frame(outer)
        holder.pack(fill="both", expand=True)
        canvas = tk.Canvas(holder, highlightthickness=0, borderwidth=0)
        bar = ttk.Scrollbar(holder, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        canvas.bind("<Enter>", lambda e: canvas.bind_all(
            "<MouseWheel>", lambda ev: canvas.yview_scroll(int(-ev.delta / 120), "units")))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        section = None
        for cat in redact.CATEGORIES:
            if cat.section != section:
                section = cat.section
                ttk.Label(body, text=section, font=("Segoe UI", 10, "bold") if WINDOWS
                          else ("Sans", 10, "bold")).pack(anchor="w", pady=(10, 2))
            var = tk.BooleanVar(value=self.cfg["categories"][cat.id])
            var.trace_add("write", lambda *_: self._changed())
            self.vars[cat.id] = var
            ttk.Checkbutton(body, text=cat.title, variable=var).pack(anchor="w")
            if cat.desc:
                ttk.Label(body, text=cat.desc, foreground="#666", wraplength=520).pack(
                    anchor="w", padx=(24, 0))

        self.always = self._words(outer, "Always cover (one per line: your name, GitHub handle, "
                                  "employer, domains you own)", self.cfg["always_redact"])
        self.never = self._words(outer, "Never cover (one per line)", self.cfg["never_redact"])
        row = ttk.Frame(outer)
        row.pack(fill="x", pady=(8, 0))
        self.status = ttk.Label(row, text="Changes save automatically")
        self.status.pack(side="left")
        ttk.Button(row, text="Close", command=self._close).pack(side="right")
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _words(self, parent, title, lines):
        ttk.Label(parent, text=title, wraplength=560).pack(anchor="w", pady=(10, 2))
        text = tk.Text(parent, height=4, width=60, font=("Consolas", 10) if WINDOWS else None)
        text.insert("1.0", "\n".join(lines))
        text.bind("<<Modified>>", lambda e: (text.edit_modified(False), self._changed()))
        text.pack(fill="x")
        return text

    def _changed(self):
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(400, self._save)

    def _save(self):
        self._job = None

        def lines(widget):
            return [x.strip() for x in widget.get("1.0", "end").splitlines() if x.strip()]
        cfg = redact.load_config()
        cfg["categories"] = {cid: v.get() for cid, v in self.vars.items()}
        cfg["always_redact"] = lines(self.always)
        cfg["never_redact"] = lines(self.never)
        if redact.save_config(cfg):
            self.status.configure(text="Saved")
            self.on_saved()
        else:
            self.status.configure(text=f"Couldn't save to {redact.CONFIG_FILE}")

    def _close(self):
        if self._job:
            self.after_cancel(self._job)
            self._save()
        self.destroy()


# =================================================================== the editor

class TkEditor:
    def __init__(self, root, path=None, paste=False):
        self.root = root
        self.ed = ie.Editor()
        self.zoom, self.fit = 1.0, True
        self.sx = self.sy = 0.0           # scroll offset when the image is bigger than the view
        self.ox = self.oy = PAD
        self.photo = None
        self.text_request = None
        self.text_window = None
        self._render_job = None
        self._loading_style = False
        self._pan = None
        self._settings = None
        self.jobs = queue.Queue()
        self.icons = {}
        # Icons are drawn in pixels, so they grow with the display scaling.
        try:
            self.scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
        except tk.TclError:
            self.scale = 1.0
        self.ocr_ok, self.ocr_msg = ir.ocr_status()

        root.title("Image Redact")
        root.geometry("1180x800")
        root.minsize(940, 560)
        try:
            self._app_icons = [app_icon_photo(64), app_icon_photo(32), app_icon_photo(16)]
            root.iconphoto(True, *self._app_icons)
        except tk.TclError:
            pass
        style = ttk.Style(root)
        if not WINDOWS and "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Status.TLabel", padding=(6, 0))
        # ttk buttons default to 11 characters wide, which crowds the toolbar.
        style.configure("TButton", width=-5, padding=(8, 3))
        style.configure("Toolbutton", padding=(6, 3))

        self._build_toolbar()
        self._build_file_bar()
        self._build_canvas()
        self._bind_keys()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.report_callback_exception = self._report_error
        self.set_tool("cover")
        self._update_state()
        self.set_status("Paste a screenshot (Ctrl+V) or click Open." if self.ocr_ok else
                        self.ocr_msg.splitlines()[0] + " You can still cover things by hand.")
        root.after(50, self._poll)
        if path:
            root.after(100, lambda: self.open_path(path, confirmed=True))
        elif paste:
            root.after(100, self.paste)

    # ================================================================== layout
    def _icon(self, kind, size=18):
        size = int(round(size * self.scale))
        key = (kind, size)
        if key not in self.icons:
            self.icons[key] = (icon_photo(kind, size), icon_photo(kind, size, INK_OFF))
        on, off = self.icons[key]
        return (on, "disabled", off)

    def _button(self, parent, text=None, icon=None, command=None, tip=None, **kw):
        b = ttk.Button(parent, text=text, image=self._icon(icon, 16) if icon else "",
                       command=command, **kw)
        if tip:
            Tooltip(b, tip)
        return b

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(side="top", fill="x")
        self._button(bar, "Open", command=self.open_dialog,
                     tip="Open an image (Ctrl+O)").pack(side="left")
        self._button(bar, "Paste", command=self.paste,
                     tip="Paste a screenshot (Ctrl+V)").pack(side="left", padx=(4, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.find_btn = self._button(bar, "Find PII", command=self.find_pii,
                                     tip="Read the text and cover account IDs, keys, emails and "
                                         "the rest (Ctrl+F)")
        self.find_btn.pack(side="left")
        self.peek = tk.BooleanVar(value=False)
        peek = ttk.Checkbutton(bar, text="See through", variable=self.peek, style="Toolbutton",
                               command=self.render)
        peek.pack(side="left", padx=(4, 0))
        Tooltip(peek, "Show what's under the solid boxes, to check they cover the right thing. "
                      "Saved and copied images are always solid.")
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)

        self.tool_var = tk.StringVar(value="cover")
        tools = ttk.Frame(bar)
        tools.pack(side="left")
        for tid, _name, _key, tip in ie.TOOLS:
            b = ttk.Radiobutton(tools, image=self._icon(tid), variable=self.tool_var, value=tid,
                                style="Toolbutton", command=lambda t=tid: self.set_tool(t))
            b.pack(side="left")
            Tooltip(b, tip)

        # Style controls get shown and hidden depending on the tool, in this order.
        self.style_frame = ttk.Frame(bar)
        self.style_frame.pack(side="left", padx=(8, 0))
        self.color_btn = ttk.Button(self.style_frame, command=self.pick_color)
        Tooltip(self.color_btn, "Color")
        self.fill_var = tk.BooleanVar()
        self.fill_btn = ttk.Checkbutton(self.style_frame, text="Fill", variable=self.fill_var,
                                        style="Toolbutton", command=self._fill_changed)
        Tooltip(self.fill_btn, "Fill boxes and ovals instead of outlining them")
        self.width_label = ttk.Label(self.style_frame, text="Width")
        self.width_spin = self._spin(1, 40, 1, "width", "Line width")
        self.size_label = ttk.Label(self.style_frame, text="Size")
        self.size_spin = self._spin(8, 200, 2, "size", "Text size")
        self.corners_label = ttk.Label(self.style_frame, text="Corners")
        self.corners_spin = self._spin(0, 60, 1, "corners",
                                       "Round the corners of Cover and Box shapes. Rounded "
                                       "covers grow a little so the corners still cover "
                                       "everything.")
        self.style_widgets = [
            ("show_color", [self.color_btn]), ("show_fill", [self.fill_btn]),
            ("show_width", [self.width_label, self.width_spin]),
            ("show_size", [self.size_label, self.size_spin]),
            ("show_corners", [self.corners_label, self.corners_spin])]

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.undo_btn = self._button(bar, icon="undo", command=self.undo, tip="Undo (Ctrl+Z)")
        self.redo_btn = self._button(bar, icon="redo", command=self.redo,
                                     tip="Redo (Ctrl+Shift+Z)")
        self.delete_btn = self._button(bar, icon="delete", command=self.delete_selected,
                                       tip="Delete the selected shape (Delete)")
        for b in (self.undo_btn, self.redo_btn, self.delete_btn):
            b.pack(side="left", padx=(0, 2))

        menu_btn = ttk.Menubutton(bar, image=self._icon("menu", 16))
        menu_btn.pack(side="right")
        Tooltip(menu_btn, "Options")
        menu = tk.Menu(menu_btn, tearoff=False)
        self.auto_var = tk.BooleanVar(value=self.ed.cfg["find_on_open"])
        menu.add_checkbutton(label="Find PII when an image opens", variable=self.auto_var,
                             command=self._auto_toggled)
        menu.add_command(label="Choose what gets covered", command=self.open_settings)
        menu.add_separator()
        menu.add_command(label="Keyboard shortcuts", command=lambda: messagebox.showinfo(
            "Keyboard shortcuts", ie.SHORTCUTS_HELP + " Delete removes the selected shape, "
            "arrow keys nudge it.", parent=self.root))
        menu_btn["menu"] = menu

    def _spin(self, low, high, step, key, tip):
        var = tk.StringVar()
        spin = ttk.Spinbox(self.style_frame, from_=low, to=high, increment=step, width=4,
                           textvariable=var, command=lambda: self._spin_changed(key, var))
        spin.bind("<Return>", lambda e: self._spin_changed(key, var))
        spin.bind("<FocusOut>", lambda e: self._spin_changed(key, var))
        spin.var, spin.low, spin.high = var, low, high
        Tooltip(spin, tip)
        return spin

    def _build_canvas(self):
        frame = ttk.Frame(self.root, padding=(8, 0, 8, 0))
        frame.pack(side="top", fill="both", expand=True)
        self.canvas = tk.Canvas(frame, highlightthickness=1, highlightbackground="#c8c8cc",
                                background=to_hex(BG), takefocus=1)
        self.canvas.pack(fill="both", expand=True)
        self.canvas_img = self.canvas.create_image(0, 0, anchor="nw")
        c = self.canvas
        c.bind("<Configure>", lambda e: self._resized())
        c.bind("<ButtonPress-1>", self._press)
        c.bind("<B1-Motion>", self._motion_drag)
        c.bind("<ButtonRelease-1>", self._release)
        c.bind("<Double-Button-1>", self._double)
        c.bind("<ButtonPress-2>", self._pan_begin)
        c.bind("<B2-Motion>", self._pan_move)
        c.bind("<Motion>", self._hover)
        c.bind("<MouseWheel>", self._wheel)
        c.bind("<Button-4>", lambda e: self._wheel(e, 120))
        c.bind("<Button-5>", lambda e: self._wheel(e, -120))

    def _build_file_bar(self):
        bar = ttk.Frame(self.root, padding=(8, 6, 8, 8))
        bar.pack(side="bottom", fill="x")
        ttk.Label(bar, text="Name").pack(side="left")
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(bar, textvariable=self.name_var, width=30)
        self.name_entry.pack(side="left", padx=(6, 6))
        self.name_entry.bind("<Return>", lambda e: self.apply_name())
        self.name_entry.bind("<FocusOut>", lambda e: self.apply_name(quiet=True))
        Tooltip(self.name_entry, "Press Enter to rename. Once it's saved, this renames the "
                                 "file itself (F2).")
        ttk.Label(bar, text="in").pack(side="left")
        self.folder_btn = ttk.Menubutton(bar, width=18)
        self.folder_btn.pack(side="left", padx=(6, 6))
        self.folder_menu = tk.Menu(self.folder_btn, tearoff=False,
                                   postcommand=self._fill_folder_menu)
        self.folder_btn["menu"] = self.folder_menu
        self.folder_tip = Tooltip(self.folder_btn, "")

        self.save_btn = self._button(bar, "Save", command=self.save,
                                     tip="Save the finished image (Ctrl+S)")
        self.save_btn.pack(side="right")
        self.copy_btn = self._button(bar, "Copy", command=self.copy,
                                     tip="Copy the finished image (Ctrl+C)")
        self.copy_btn.pack(side="right", padx=(0, 4))
        zoom = ttk.Frame(bar)
        zoom.pack(side="right", padx=(0, 10))
        self._button(zoom, icon="zoom-out", command=lambda: self.step_zoom(-1),
                     tip="Zoom out (Ctrl+-)").pack(side="left")
        self.zoom_btn = self._button(zoom, "100%", command=lambda: self.set_zoom(1.0),
                                     tip="Actual size", width=5)
        self.zoom_btn.pack(side="left")
        self._button(zoom, icon="zoom-in", command=lambda: self.step_zoom(1),
                     tip="Zoom in (Ctrl++)").pack(side="left")
        self._button(zoom, icon="fit", command=self.zoom_fit,
                     tip="Fit in the window (Ctrl+0)").pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=70)
        self.status_var = tk.StringVar()
        self.status = ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel",
                                anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        self._update_folder_button()

    def _bind_keys(self):
        r = self.root
        pairs = {"o": self.open_dialog, "v": self.paste, "s": self.save, "c": self.copy,
                 "f": self.find_pii, "z": self.undo, "y": self.redo, "m": self.post_folder_menu,
                 "0": self.zoom_fit, "equal": lambda: self.step_zoom(1),
                 "plus": lambda: self.step_zoom(1), "minus": lambda: self.step_zoom(-1),
                 "KP_Add": lambda: self.step_zoom(1), "KP_Subtract": lambda: self.step_zoom(-1)}
        for key, fn in pairs.items():
            # Ctrl+Shift+Z redoes. Whether Z comes as a capital depends on Caps Lock too, so
            # it goes by Shift instead, and Ctrl+Z with Caps Lock on still undoes.
            handler = self._guard(fn, shifted=self.redo if key == "z" else None)
            r.bind(f"<Control-{key}>", handler)
            if len(key) == 1 and key.isalpha():
                r.bind(f"<Control-{key.upper()}>", handler)
        r.bind("<F2>", lambda e: self.focus_name())
        r.bind("<KeyPress>", self._key)

    def _typing(self):
        try:
            w = self.root.focus_get()
        except (KeyError, tk.TclError):  # Tk can't name the focus while a menu is open
            return False
        return isinstance(w, (tk.Entry, ttk.Entry, tk.Text, ttk.Spinbox, tk.Spinbox))

    def _guard(self, fn, shifted=None):
        def handler(e):
            if self._typing():
                return None
            state = getattr(e, "state", 0)
            if shifted is not None and isinstance(state, int) and state & 0x0001:
                shifted()
            else:
                fn()
            return "break"
        return handler

    # ================================================================== status and threads
    def set_status(self, text, busy=False):
        self.status_var.set(text)
        if busy:
            self.progress.pack(side="left", padx=(0, 6), before=self.status)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def run_bg(self, work, done, failed=None):
        def target():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                if failed:
                    self.jobs.put((failed, exc))
                return
            self.jobs.put((done, result))
        threading.Thread(target=target, daemon=True).start()

    def _poll(self):
        # One failed callback mustn't stop the loop, or Open, Paste and text detection
        # would never finish again.
        try:
            while True:
                try:
                    fn, value = self.jobs.get_nowait()
                except queue.Empty:
                    break
                try:
                    fn(value)
                except Exception:
                    self._report_error(*sys.exc_info())
        finally:
            self.root.after(50, self._poll)

    def _report_error(self, exc, value, tb):
        text = "".join(traceback.format_exception(exc, value, tb))
        log = CONFIG_DIR / "image-redact.log"
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # Start the log over once it gets big, so it can't fill the disk.
            try:
                mode = "w" if log.stat().st_size > LOG_LIMIT else "a"
            except OSError:
                mode = "a"
            with open(log, mode, encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError:
            pass
        self.set_status(f"Something went wrong: {value}. Details are in "
                        f"{ir.short_path(str(log))}")

    def _update_state(self):
        have = self.ed.surface is not None
        # Nothing goes out while text detection is still deciding what to cover.
        ready = have and not self.ed.finding
        for w in (self.save_btn, self.copy_btn):
            w.state(["!disabled"] if ready else ["disabled"])
        for w in (self.name_entry, self.folder_btn):
            w.state(["!disabled"] if have else ["disabled"])
        self.find_btn.state(["!disabled"] if ready and self.ocr_ok else ["disabled"])
        self.undo_btn.state(["!disabled"] if self.ed.undo_stack else ["disabled"])
        self.redo_btn.state(["!disabled"] if self.ed.redo_stack else ["disabled"])
        self.delete_btn.state(["!disabled"] if self.ed.selected is not None else ["disabled"])
        self.zoom_btn.configure(text=f"{round(self.zoom * 100)}%")

    def refresh(self):
        self.render()
        self._update_state()

    # ================================================================== drawing
    def render(self, *_):
        if self._render_job is None:
            self._render_job = self.root.after_idle(self._render_now)

    def _render_now(self):
        self._render_job = None
        w, h = max(self.canvas.winfo_width(), 2), max(self.canvas.winfo_height(), 2)
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, h)
        cr = cairo.Context(surface)
        cr.set_source_rgb(*BG)
        cr.paint()
        if self.ed.surface is None:
            self._paint_empty(cr, w, h)
        else:
            self.ox, self.oy = self._offsets(w, h)
            ie.paint(cr, self.ed, self.ox, self.oy, self.zoom, peek=self.peek.get())
        self.photo = surface_photo(surface)
        self.canvas.itemconfigure(self.canvas_img, image=self.photo)
        if self.text_window is not None:
            self.canvas.tag_raise(self.text_window)

    def _paint_empty(self, cr, w, h):
        lines = [("Paste a screenshot with Ctrl+V, or click Open", 17, True),
                 ("", 10, False),
                 ("Account IDs, keys, ARNs, emails and other identifying text get", 13, False),
                 ("covered with solid boxes. Then draw over anything it missed", 13, False),
                 ("and save or copy it.", 13, False)]
        heights = [size * 1.5 for _, size, _ in lines]
        y = (h - sum(heights)) / 2
        cr.set_source_rgba(0.35, 0.35, 0.4, 1)
        for (text, size, bold), lh in zip(lines, heights):
            cr.select_font_face(ir.TEXT_FONT, cairo.FONT_SLANT_NORMAL,
                                cairo.FONT_WEIGHT_BOLD if bold else cairo.FONT_WEIGHT_NORMAL)
            cr.set_font_size(size)
            tw = cr.text_extents(text).x_advance
            cr.move_to((w - tw) / 2, y + size)
            cr.show_text(text)
            y += lh
        cr.set_source_rgba(0.35, 0.35, 0.4, 0.3)
        cr.set_line_width(2)
        cr.set_dash([8, 6])
        cr.rectangle(PAD, PAD, w - 2 * PAD, h - 2 * PAD)
        cr.stroke()

    def _offsets(self, w, h):
        iw, ih = self.ed.size
        cw, ch = iw * self.zoom + 2 * PAD, ih * self.zoom + 2 * PAD
        self.sx = min(max(self.sx, 0), max(cw - w, 0))
        self.sy = min(max(self.sy, 0), max(ch - h, 0))
        ox = (w - iw * self.zoom) / 2 if cw <= w else PAD - self.sx
        oy = (h - ih * self.zoom) / 2 if ch <= h else PAD - self.sy
        return ox, oy

    def to_image(self, x, y):
        return (x - self.ox) / self.zoom, (y - self.oy) / self.zoom

    def to_view(self, x, y):
        return self.ox + x * self.zoom, self.oy + y * self.zoom

    # ================================================================== zoom and scroll
    def _resized(self):
        if self.fit:
            self.zoom_fit(keep=True)
        else:
            self.render()

    def zoom_fit(self, keep=False):
        self.fit = True
        z = ie.fit_zoom(self.ed.size, self.canvas.winfo_width(), self.canvas.winfo_height())
        if z:
            self.zoom = z
        self.sx = self.sy = 0
        self.refresh()

    def set_zoom(self, zoom, anchor=None):
        if self.ed.surface is None:
            return
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        vx, vy = anchor if anchor else (w / 2, h / 2)
        # Worked out fresh rather than from the last drawn frame, which is behind when
        # several wheel notches come in before the next redraw.
        ox, oy = self._offsets(max(w, 2), max(h, 2))
        ix, iy = (vx - ox) / self.zoom, (vy - oy) / self.zoom
        self.fit = False
        self.zoom = ie.clamp_zoom(zoom)
        # Keep the spot under the pointer in place.
        self.sx = PAD + ix * self.zoom - vx
        self.sy = PAD + iy * self.zoom - vy
        self.refresh()

    def step_zoom(self, direction, anchor=None):
        self.set_zoom(ie.step_zoom(self.zoom, direction), anchor)

    def _wheel(self, event, delta=None):
        """The wheel scrolls up and down, Shift+wheel left and right (a tilting wheel comes
        in the same way on Windows), and Ctrl+wheel zooms toward the pointer."""
        delta = delta if delta is not None else event.delta
        if self.ed.surface is None or not delta:
            return
        ctrl, shift = event.state & 0x0004, event.state & 0x0001
        if not ctrl:
            step = -60 * (delta / 120)
            if shift:
                self.sx += step
            else:
                self.sy += step
            self.render()
            return
        # 120 is one notch. Precision touchpads and smooth wheels send smaller parts, which
        # add up until a whole notch is there. A pause or a change of direction starts again.
        total, last_dir, last_time = getattr(self, "_wheel_acc", (0.0, 0, 0.0))
        now = time.monotonic()
        direction = 1 if delta > 0 else -1
        if direction != last_dir or now - last_time > 0.4:
            total = 0.0
        total += delta / 120
        steps = int(total + (0.02 if total > 0 else -0.02))
        self._wheel_acc = (total - steps, direction, now)
        for _ in range(abs(steps)):
            self.step_zoom(1 if steps > 0 else -1, (event.x, event.y))

    def _pan_begin(self, event):
        self._pan = (event.x, event.y, self.sx, self.sy)

    def _pan_move(self, event):
        if self._pan:
            x0, y0, sx, sy = self._pan
            self.sx, self.sy = sx - (event.x - x0), sy - (event.y - y0)
            self.fit = False
            self.render()

    # ================================================================== mouse
    def _press(self, event):
        self.canvas.focus_set()
        self._cancel_text()
        if self.ed.surface is None:
            return
        self.ed.drag_begin(*self.to_image(event.x, event.y), self.zoom)
        self._sync_style_controls()
        self.refresh()

    def _motion_drag(self, event):
        shift = bool(event.state & 0x0001)
        if self.ed.drag_update(*self.to_image(event.x, event.y), shift, self.zoom):
            self.render()

    def _release(self, event):
        request = self.ed.drag_end(self.zoom)
        self.refresh()
        if request:
            self._show_text_entry(request)

    def _double(self, event):
        if self.ed.surface is None:
            return
        request = self.ed.text_at_double_click(*self.to_image(event.x, event.y), self.zoom)
        if request:
            self._show_text_entry(request)

    def _hover(self, event):
        if self.ed.surface is None:
            return
        if self.ed.tool != "select":
            self.canvas.configure(cursor="crosshair")
            return
        ix, iy = self.to_image(event.x, event.y)
        if self.ed.handle_at(ix, iy, (ie.HANDLE + 3) / self.zoom) is not None:
            self.canvas.configure(cursor="crosshair")
            return
        over = self.ed.shape_at(ix, iy, 5 / self.zoom)
        self.canvas.configure(cursor="fleur" if over else "arrow")
        hover = self.ed.hover_text(ix, iy, 5 / self.zoom)
        if hover:
            self.status_var.set(hover)

    def _key(self, event):
        if self._typing() or self.text_window is not None:
            return None
        if event.state & 0x0004:  # Ctrl combos are bound separately
            return None
        key = event.keysym
        if key in ("Delete", "BackSpace"):
            self.delete_selected()
            return "break"
        if key == "Escape":
            self.ed.escape()
            self._sync_style_controls()
            self.refresh()
            return "break"
        moves = {"Left": (-1, 0), "Right": (1, 0), "Up": (0, -1), "Down": (0, 1)}
        if key in moves and self.ed.selected is not None:
            step = 10 if event.state & 0x0001 else 1
            self.ed.nudge(moves[key][0] * step, moves[key][1] * step)
            self.refresh()
            return "break"
        # Alt is 0x20000 on Windows and Mod1 (0x8) elsewhere. On Windows 0x8 is NumLock.
        alt = event.state & (0x20000 if WINDOWS else 0x0008)
        for tid, _name, shortcut, _tip in ie.TOOLS:
            if key.lower() == shortcut and not alt:
                self.set_tool(tid)
                return "break"
        return None

    # ================================================================== text
    def _show_text_entry(self, request):
        self._cancel_text()
        self.text_request = request
        kind, value = request
        ix, iy = (value["x"], value["y"]) if kind == "edit" else value
        vx, vy = self.to_view(ix, iy)
        entry = ttk.Entry(self.canvas, width=30)
        if kind == "edit":
            entry.insert(0, value["text"])
        self.text_window = self.canvas.create_window(vx, vy, window=entry, anchor="nw")
        self._text_entry = entry
        self._status_before_text = self.status_var.get()
        entry.bind("<Return>", lambda e: self._commit_text())
        entry.bind("<KP_Enter>", lambda e: self._commit_text())
        entry.bind("<Escape>", lambda e: self._cancel_text())
        entry.focus_set()
        self.set_status("Type the text, then Enter to place it or Esc to cancel.")

    def _commit_text(self):
        request, self.text_request = self.text_request, None
        text = self._text_entry.get() if self.text_window is not None else ""
        self._cancel_text()
        if self.ed.commit_text(request, text):
            self.refresh()
        return "break"

    def _cancel_text(self):
        if self.text_window is not None:
            self.canvas.delete(self.text_window)
            self._text_entry.destroy()
            self.text_window = None
            self.status_var.set(self._status_before_text)
            self.canvas.focus_set()

    # ================================================================== tools and style
    def set_tool(self, tid):
        self.tool_var.set(tid)
        self.ed.set_tool(tid)
        self.canvas.configure(cursor="arrow" if tid == "select" else "crosshair")
        self._sync_style_controls()
        self.refresh()

    def _sync_style_controls(self):
        st = self.ed.style()
        self._loading_style = True
        self._swatch = swatch_photo(st["color"], int(28 * self.scale), int(18 * self.scale))
        self.color_btn.configure(image=self._swatch)
        self.fill_var.set(st["fill"])
        for spin, key in ((self.width_spin, "width"), (self.size_spin, "size"),
                          (self.corners_spin, "corners")):
            spin.var.set(str(int(round(st[key]))))
        for child in self.style_frame.winfo_children():
            child.pack_forget()
        for flag, widgets in self.style_widgets:
            if st[flag]:
                for w in widgets:
                    w.pack(side="left", padx=(6 if isinstance(w, ttk.Label) else 2, 0))
        self._loading_style = False

    def _apply_style(self, **change):
        if self._loading_style:
            return
        if self.ed.set_style(**change):
            self.refresh()

    def pick_color(self):
        st = self.ed.style()
        _, picked = colorchooser.askcolor(color=to_hex(st["color"]), parent=self.root,
                                          title="Color")
        if not picked:
            return
        rgb = [int(picked[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        self._apply_style(color=rgb + [1.0])
        self._sync_style_controls()

    def _fill_changed(self):
        self._apply_style(fill=self.fill_var.get())

    def _spin_changed(self, key, var):
        spin = {"width": self.width_spin, "size": self.size_spin,
                "corners": self.corners_spin}[key]
        try:
            value = float(var.get())
        except ValueError:
            self._sync_style_controls()
            return
        value = min(max(value, spin.low), spin.high)
        current = self.ed.style()[key]
        if abs(value - current) < 1e-6:
            return
        self._apply_style(**{key: value})

    def _auto_toggled(self):
        self.ed.cfg["find_on_open"] = self.auto_var.get()
        self.ed.save_cfg()

    def open_settings(self):
        if self._settings is not None and self._settings.winfo_exists():
            self._settings.lift()
            return
        self._settings = RedactSettings(self.root, self._redact_settings_saved)

    def _redact_settings_saved(self):
        # While the text is being read again, the new settings apply when that's done.
        if self.ed.passes is not None and not self.ed.finding:
            self._apply_boxes()

    # ================================================================== undo
    def undo(self):
        if self.ed.undo():
            self._sync_style_controls()
            self.refresh()

    def redo(self):
        if self.ed.redo():
            self._sync_style_controls()
            self.refresh()

    def delete_selected(self):
        if self.ed.delete_selected():
            self._sync_style_controls()
            self.refresh()

    # ================================================================== loading
    def confirm_discard(self, action="open another image"):
        if not self.ed.unsaved:
            return True
        return messagebox.askyesno("Discard changes?",
                                   f"Your changes to this image haven't been saved or copied. "
                                   f"Discard them and {action}?",
                                   icon="warning", default="no", parent=self.root)

    def open_dialog(self):
        if not self.confirm_discard():
            return
        start = self.ed.source_path and os.path.dirname(self.ed.source_path)
        if not start:
            shots = os.path.join(ir.pictures_folder(), "Screenshots")
            start = shots if os.path.isdir(shots) else ir.pictures_folder()
        path = filedialog.askopenfilename(
            parent=self.root, title="Open an image", initialdir=start,
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff"),
                       ("All files", "*.*")])
        if path:
            self.open_path(path, confirmed=True)

    def _latest(self):
        """Wraps one open or paste's callbacks. Starting another open or paste makes the
        older one's result count for nothing, so a slow open that finishes after a paste
        can't replace the pasted image without asking."""
        self._load_seq = getattr(self, "_load_seq", 0) + 1
        seq = self._load_seq

        def wrap(fn):
            def call(*args):
                if seq == self._load_seq:
                    return fn(*args)
                return None
            return call
        return wrap

    def open_path(self, path, confirmed=False):
        if not confirmed and not self.confirm_discard():
            return
        latest = self._latest()
        self.set_status(f"Opening {os.path.basename(path)}...", busy=True)
        self.run_bg(lambda: ir.load_image_bytes(path),
                    latest(lambda png: self.load_png(png, path)),
                    latest(lambda exc: self.set_status(str(exc))))

    def paste(self):
        if not self.confirm_discard():
            return
        latest = self._latest()
        self.set_status("Reading the clipboard...", busy=True)
        self.run_bg(read_clipboard_image, latest(self._pasted), latest(self._paste_failed))

    def _pasted(self, png):
        if png:
            self.load_png(png, None)
        else:
            self.set_status("The clipboard doesn't have an image in it. Take a screenshot "
                            "with Win+Shift+S, then paste.")

    def _paste_failed(self, exc):
        self.set_status(str(exc) if isinstance(exc, ClipboardError)
                        else f"Couldn't read an image from the clipboard: {exc}")

    def load_png(self, png, path):
        try:
            self.ed.load(png, path)
        except ir.ImageError as exc:
            self.set_status(str(exc))
            return
        self.name_var.set(self.ed.name)
        self._update_folder_button()
        self._sync_style_controls()
        self.zoom_fit()
        self.canvas.focus_set()
        if self.ocr_ok and self.ed.cfg["find_on_open"]:
            self.find_pii()
        else:
            self.set_status(self.ed.describe())

    # ================================================================== detection
    def find_pii(self):
        ed = self.ed
        if ed.png is None or not self.ocr_ok or ed.finding:
            return
        if ed.passes is not None and not ed.ocr_warning:
            self._apply_boxes()
            return
        png, lang = ed.png, ed.cfg["language"]
        gen = ed.start_finding()
        self._update_state()
        self.set_status("Reading the text in the image...", busy=True)

        def finished(apply):
            selected = ed.selected
            msg = apply()
            if msg is not None:
                self.set_status(msg)
                if ed.selected is not selected:
                    # A detected box that was selected is gone, so its controls go too.
                    self._sync_style_controls()
                self.refresh()
        self.run_bg(lambda: ir.read_text(png, lang),
                    lambda passes: finished(lambda: ed.found(gen, passes)),
                    lambda exc: finished(lambda: ed.find_failed(gen, exc)))

    def _apply_boxes(self):
        selected = self.ed.selected
        self.set_status(self.ed.apply_passes())
        if self.ed.selected is not selected:
            self._sync_style_controls()
        self.refresh()

    # ================================================================== files
    def _update_folder_button(self):
        folder = self.ed.folder
        name = os.path.basename(folder.rstrip("\\/")) or folder
        self.folder_btn.configure(text=name)
        self.folder_tip.text = (f"{ir.short_path(folder)}\nPick where it saves. Once saved, "
                                "picking a folder moves the file (Ctrl+M).")

    def _fill_folder_menu(self):
        m = self.folder_menu
        m.delete(0, "end")
        m.add_command(label="Move to" if self.ed.saved_path else "Save in", state="disabled")
        current = os.path.abspath(self.ed.folder)
        for f in self.ed.folder_choices():
            m.add_command(label=("\u2713 " if f == current else "    ") + ir.short_path(f),
                          command=lambda path=f: self.set_folder(path))
        m.add_separator()
        m.add_command(label="Choose another folder", command=self.choose_folder)
        m.add_command(label="Open this folder", command=self.show_folder)

    def post_folder_menu(self):
        if self.ed.surface is None:
            return
        self._fill_folder_menu()
        self.folder_menu.tk_popup(self.folder_btn.winfo_rootx(), self.folder_btn.winfo_rooty())

    def choose_folder(self):
        folder = filedialog.askdirectory(
            parent=self.root, initialdir=self.ed.folder if os.path.isdir(self.ed.folder) else None,
            title="Move to folder" if self.ed.saved_path else "Save in folder")
        if folder:
            self.set_folder(folder)

    def show_folder(self):
        folder = os.path.dirname(self.ed.saved_path) if self.ed.saved_path else self.ed.folder
        try:
            if WINDOWS:
                os.startfile(folder)  # noqa: S606 - opens File Explorer
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except OSError as exc:
            self.set_status(f"Couldn't open the folder: {exc}")

    def focus_name(self):
        if self.ed.surface is None:
            return
        self.name_entry.focus_set()
        stem = os.path.splitext(self.name_var.get())[0]
        self.name_entry.selection_range(0, len(stem))
        self.name_entry.icursor(len(stem))

    def _show_outcome(self, outcome, quiet=False):
        if outcome.kind == "ask":
            dest, verb = outcome.dest, outcome.message
            if messagebox.askyesno(f"Replace {os.path.basename(dest)}?",
                                   f"There's already a file with that name in "
                                   f"{ir.short_path(os.path.dirname(dest))}. Replace it?",
                                   icon="warning", default="no", parent=self.root):
                result = self.ed.write(dest) if verb == "Save" else self.ed.relocate(dest, verb)
                self._show_outcome(result)
                return
        elif outcome.kind == "error":
            if quiet:
                self.set_status(outcome.message)
            else:
                messagebox.showerror("Something went wrong", outcome.message, parent=self.root)
        elif outcome.kind == "done" and outcome.message and not quiet:
            self.set_status(outcome.message)
        self.name_var.set(self.ed.name)
        self._update_folder_button()

    def apply_name(self, quiet=False):
        if self.ed.surface is None:
            return
        self._show_outcome(self.ed.rename(self.name_var.get()), quiet=quiet)

    def set_folder(self, folder):
        self._show_outcome(self.ed.move_to(folder))

    def save(self):
        if self.ed.surface is None:
            return
        if self.ed.finding:
            self.set_status(ie.BUSY, busy=True)
            return
        self.apply_name(quiet=True)
        plan = self.ed.plan_save()
        self._show_outcome(plan if plan.kind == "ask" else self.ed.write(plan.dest))

    def copy(self):
        if self.ed.surface is None:
            return
        if self.ed.finding:
            self.set_status(ie.BUSY, busy=True)
            return
        try:
            png = self.ed.copy_png()
            write_clipboard_image(png)
        except (ir.ImageError, ClipboardError) as exc:
            self.set_status(str(exc))
            return
        self.ed.copied()  # only once it's really on the clipboard
        self.set_status("Copied the finished image. It's ready to paste.")

    def close(self):
        if self.ed.unsaved and not messagebox.askyesno(
                "Close without saving?", "Your changes to this image haven't been saved or "
                "copied. Close anyway?", icon="warning", default="no", parent=self.root):
            return
        self.root.destroy()


def _windows_setup():
    """Sharp text on high-DPI screens, and its own taskbar icon instead of Python's."""
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except (AttributeError, OSError):
        pass


def main(path=None, paste=False) -> int:
    if WINDOWS:
        _windows_setup()
    root = tk.Tk(className="ImageRedact")
    TkEditor(root, path, paste)
    root.mainloop()
    return 0
