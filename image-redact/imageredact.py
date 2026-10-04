"""Image Redact: finds account IDs, keys, emails and other identifying text in screenshots
and covers it with solid boxes, using the same rules and settings as PII Redact.

This file has the text detection, the shapes and how they're drawn, saving, renaming and
moving files, and the command line. It has no GTK in it, so the commands work without a
window. The editor is in image_page.py. Run `awskit image --help` for every option.
"""
from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

from . import redact
from .common import (CONFIG_DIR, ClipboardError, is_wsl, notify, read_clipboard_image,
                     write_clipboard_image)

CONFIG_FILE = CONFIG_DIR / "image.json"

SAVE_TYPES = (".png", ".jpg", ".jpeg")
OPEN_TYPES = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff")

DEFAULT_CONFIG = {
    # Run text detection as soon as an image opens.
    "find_on_open": True,
    # Color of the boxes text detection and the Cover tool draw.
    "box_color": [0.0, 0.0, 0.0, 1.0],
    # Color, line width, fill and text size for the drawing tools.
    "draw_color": [0.878, 0.106, 0.141, 1.0],
    "width": 4,
    "fill": False,
    "text_size": 28,
    # Folders you saved or moved to lately, newest first.
    "recent_folders": [],
    # Tesseract language codes, like "eng" or "eng+ron".
    "language": "eng",
}


# =================================================================== config

def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return cfg
    if not isinstance(data, dict):
        return cfg
    for key, value in data.items():
        if key not in cfg:
            continue
        if isinstance(cfg[key], bool):
            if isinstance(value, bool):
                cfg[key] = value
        elif isinstance(cfg[key], (int, float)):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cfg[key] = value
        elif isinstance(cfg[key], list) and isinstance(value, list):
            if key.endswith("_color"):
                if len(value) == 4 and all(isinstance(v, (int, float)) for v in value):
                    cfg[key] = [min(max(float(v), 0.0), 1.0) for v in value]
            else:
                cfg[key] = [str(v) for v in value if isinstance(v, str) and v][:8]
        elif isinstance(cfg[key], str) and isinstance(value, str) and value.strip():
            cfg[key] = value.strip()
    return cfg


def save_config(cfg: dict) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, CONFIG_FILE)
        return True
    except OSError:
        return False


def remember_folder(cfg: dict, folder: str) -> dict:
    folder = os.path.abspath(folder)
    recent = [f for f in cfg.get("recent_folders", []) if f != folder]
    cfg["recent_folders"] = [folder] + recent[:7]
    return cfg


# =================================================================== images

class ImageError(Exception):
    pass


def _cairo():
    try:
        import cairo
    except ImportError:
        raise ImageError("pycairo is missing. Fedora: sudo dnf install python3-cairo. "
                         "Debian/Ubuntu: sudo apt install python3-gi-cairo") from None
    return cairo


def load_image_bytes(path: str) -> bytes:
    """Read an image file and return it as PNG bytes, turned the right way up."""
    path = str(path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        raise ImageError(f"Couldn't open {path}: {exc.strerror or exc}") from exc
    if head == b"\x89PNG\r\n\x1a\n":
        with open(path, "rb") as fh:
            data = fh.read()
        surface_from_png(data)  # make sure cairo can read it
        return data
    try:
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf, GLib
    except (ImportError, ValueError) as exc:
        raise ImageError("Only PNG files can be opened without GdkPixbuf.") from exc
    try:
        pixbuf = GdkPixbuf.Pixbuf.new_from_file(path)
        pixbuf = pixbuf.apply_embedded_orientation() or pixbuf
        ok, data = pixbuf.save_to_bufferv("png", ["compression"], ["1"])
    except GLib.Error as exc:
        raise ImageError(f"Couldn't read {os.path.basename(path)} as an image: "
                         f"{exc.message}") from exc
    if not ok:
        raise ImageError(f"Couldn't read {os.path.basename(path)} as an image.")
    return bytes(data)


def surface_from_png(data: bytes):
    cairo = _cairo()
    try:
        return cairo.ImageSurface.create_from_png(io.BytesIO(data))
    except (cairo.Error, MemoryError) as exc:
        raise ImageError(f"Couldn't read the image: {exc}") from exc


# =================================================================== text detection

class OcrError(Exception):
    pass


INSTALL_HINT = ("Text detection needs tesseract.\n"
                "Fedora:        sudo dnf install tesseract tesseract-langpack-eng\n"
                "Debian/Ubuntu: sudo apt install tesseract-ocr\n"
                "Arch:          sudo pacman -S tesseract tesseract-data-eng")


def tesseract_path():
    return shutil.which("tesseract")


def ocr_status() -> tuple:
    """(True, version line) when tesseract is ready, otherwise (False, how to install it)."""
    exe = tesseract_path()
    if not exe:
        return False, INSTALL_HINT
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"tesseract is installed but won't run: {exc}"
    first = (r.stdout or r.stderr).strip().splitlines()
    return True, first[0] if first else "tesseract"


def ocr_languages() -> list:
    exe = tesseract_path()
    if not exe:
        return []
    try:
        r = subprocess.run([exe, "--list-langs"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    lines = (r.stdout or r.stderr).strip().splitlines()
    return [x.strip() for x in lines[1:] if x.strip()]


@dataclass
class Word:
    text: str
    left: float
    top: float
    width: float
    height: float
    conf: float
    line: tuple
    chars: list = None  # (left, right) for each character, when tesseract gave them


def brightness(surface) -> tuple:
    """Share of dark pixels and share of light pixels, from a small copy of the image."""
    cairo = _cairo()
    w, h = surface.get_width(), surface.get_height()
    scale = min(1.0, 320.0 / max(w, h, 1))
    sw, sh = max(int(w * scale), 1), max(int(h * scale), 1)
    small = cairo.ImageSurface(cairo.FORMAT_RGB24, sw, sh)
    cr = cairo.Context(small)
    cr.set_source_rgb(1, 1, 1)
    cr.paint()
    cr.scale(scale, scale)
    cr.set_source_surface(surface, 0, 0)
    cr.paint()
    small.flush()
    data = bytes(small.get_data())
    green = data[1::4]
    total = len(green) or 1
    dark = sum(1 for v in green if v < 90) / total
    light = sum(1 for v in green if v > 165) / total
    return dark, light


def ocr_plan(surface) -> list:
    """Which passes to run. Tesseract reads dark text on light backgrounds best, so dark
    screenshots like terminals get flipped first, and mixed ones get read both ways."""
    dark, light = brightness(surface)
    passes = []
    if light >= 0.15 or dark < 0.5:
        passes.append(False)
    if dark >= 0.15:
        passes.append(True)
    return passes or [False]


def ocr_scale(surface) -> float:
    """Enlarging small text helps tesseract a lot. HiDPI screenshots already have big text."""
    pixels = surface.get_width() * surface.get_height()
    if pixels <= 2_300_000:
        return 2.0
    if pixels <= 4_500_000:
        return 1.5
    return 1.0


def _prepare(surface, scale: float, invert: bool, path: str):
    cairo = _cairo()
    w, h = surface.get_width(), surface.get_height()
    out = cairo.ImageSurface(cairo.FORMAT_RGB24, max(int(w * scale), 1), max(int(h * scale), 1))
    cr = cairo.Context(out)
    cr.set_source_rgb(1, 1, 1)
    cr.paint()
    cr.scale(scale, scale)
    cr.set_source_surface(surface, 0, 0)
    cr.get_source().set_filter(cairo.FILTER_BILINEAR)
    cr.paint()
    if invert:
        cr.identity_matrix()
        cr.set_operator(cairo.OPERATOR_DIFFERENCE)
        cr.set_source_rgb(1, 1, 1)
        cr.paint()
    out.write_to_png(path)


class _HocrParser(HTMLParser):
    """Reads tesseract's hOCR output: lines, words, and the box of every character."""

    LINE_CLASSES = {"ocr_line", "ocr_caption", "ocr_textfloat", "ocr_header"}

    def __init__(self, scale, tag):
        super().__init__(convert_charrefs=True)
        self.scale, self.tag = scale, tag
        self.words, self.stack = [], []
        self.line_no = 0
        self.word = None
        self.char = None

    @staticmethod
    def _numbers(title, key):
        m = re.search(key + r" ([-\d.]+(?: [-\d.]+)*)", title or "")
        return [float(v) for v in m.group(1).split()] if m else []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "")
        self.stack.append(cls)
        if cls in self.LINE_CLASSES:
            self.line_no += 1
        elif cls == "ocrx_word":
            box = self._numbers(a.get("title"), "bbox")
            conf = self._numbers(a.get("title"), "x_wconf")
            if len(box) == 4:
                self.word = {"box": box, "conf": conf[0] if conf else 0.0, "text": [],
                             "chars": [], "line": self.line_no}
        elif cls == "ocrx_cinfo" and self.word is not None:
            box = self._numbers(a.get("title"), "x_bboxes")
            self.char = {"box": box, "text": ""}

    def handle_data(self, data):
        if self.char is not None:
            self.char["text"] += data
        elif self.word is not None and self.stack and self.stack[-1] == "ocrx_word":
            if data.strip():
                self.word["text"].append(("", data.strip(), None))

    def handle_endtag(self, tag):
        cls = self.stack.pop() if self.stack else ""
        if cls == "ocrx_cinfo" and self.char is not None and self.word is not None:
            text, box = self.char["text"], self.char["box"]
            if text:
                n = len(text)
                for i, c in enumerate(text):
                    if len(box) == 4:
                        x0 = box[0] + (box[2] - box[0]) * i / n
                        x1 = box[0] + (box[2] - box[0]) * (i + 1) / n
                        self.word["chars"].append((x0, x1))
                    self.word["text"].append((c, None, None))
            self.char = None
        elif cls == "ocrx_word" and self.word is not None:
            self._finish_word()
            self.word = None

    def _finish_word(self):
        w, k = self.word, self.scale
        text = "".join(c if c else full for c, full, _ in w["text"]).strip()
        if not text:
            return
        x0, y0, x1, y1 = w["box"]
        chars = w["chars"] if len(w["chars"]) == len(text) else None
        if chars:
            # Character boxes are more reliable than the word box tesseract reports.
            x0 = min(c[0] for c in chars)
            x1 = max(c[1] for c in chars)
            chars = [(a / k, b / k) for a, b in chars]
        self.words.append(Word(text, x0 / k, y0 / k, (x1 - x0) / k, (y1 - y0) / k, w["conf"],
                               (self.tag, w["line"]), chars))


def parse_hocr(text: str, scale: float, tag) -> list:
    parser = _HocrParser(scale, tag)
    parser.feed(text)
    parser.close()
    return parser.words


def _run_pass(exe, surface, scale, invert, language, folder, results, index):
    path = os.path.join(folder, f"pass{index}.png")
    try:
        _prepare(surface, scale, invert, path)
        r = subprocess.run([exe, path, "stdout", "-l", language, "--psm", "3",
                            "--dpi", str(int(96 * scale)), "-c", "hocr_char_boxes=1", "hocr"],
                           capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        results[index] = OcrError("Text detection took too long and was stopped.")
        return
    except OSError as exc:
        results[index] = OcrError(f"Couldn't run tesseract: {exc}")
        return
    err = r.stderr.decode("utf-8", "replace")
    if r.returncode != 0:
        if "Failed loading language" in err or "Error opening data file" in err:
            results[index] = OcrError(
                f"Tesseract doesn't have the language data for '{language}'.\n" + INSTALL_HINT)
        else:
            results[index] = OcrError("tesseract failed: " + (err.strip().splitlines() or
                                                              ["unknown error"])[-1])
        return
    results[index] = parse_hocr(r.stdout.decode("utf-8", "replace"), scale, index)


def read_text(png: bytes, language: str = "eng") -> list:
    """Run OCR on an image. Returns one list of words per pass, in image pixels."""
    exe = tesseract_path()
    if not exe:
        raise OcrError(INSTALL_HINT)
    surface = surface_from_png(png)
    scale = ocr_scale(surface)
    plan = ocr_plan(surface)
    results = [None] * len(plan)
    # mkdtemp folders are private to you, and get removed with whatever was in them.
    folder = tempfile.mkdtemp(prefix="awskit-ocr-")
    try:
        threads = [threading.Thread(target=_run_pass, daemon=True,
                                    args=(exe, surface, scale, inv, language, folder, results, i))
                   for i, inv in enumerate(plan)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    passes = [r for r in results if isinstance(r, list)]
    errors = [r for r in results if isinstance(r, Exception)]
    if errors and not passes:
        raise errors[0]
    return passes


# =================================================================== matching

DIGIT_LOOKALIKES = str.maketrans({"O": "0", "o": "0", "Q": "0", "l": "1", "I": "1",
                                  "S": "5", "B": "8"})
HEX_LOOKALIKES = str.maketrans({"O": "0", "o": "0", "l": "1", "I": "1"})
HEX = set("0123456789abcdefABCDEF")
JOIN_AFTER = set("-:/@_")
JOIN_BEFORE = set("-:/@_")
# OCR often reads _ as a space: AWS SECRET ACCESS KEY= or AWSReservedSSO Admin 4f3c...
CAPS_SETTING = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z0-9]*(?:[ _]+[A-Z0-9]+)+(?=[ ]?[=:])")
SSO_SPACED = re.compile(r"\bAWSReservedSSO([ _])[\w+=,.@-]+?([ _])[0-9a-f]{16}(?![0-9a-f])")


def _fix_run(run: str) -> str:
    """Undo the usual OCR mix-ups in something that's clearly a number or a hex ID."""
    if len(run) >= 3:
        digits = sum(c.isdigit() for c in run)
        if digits / len(run) >= 0.6:
            return run.translate(DIGIT_LOOKALIKES)
    if len(run) >= 8:
        hexed = run.translate(HEX_LOOKALIKES)
        if hexed != run and set(hexed) <= HEX and sum(c.isdigit() for c in hexed) >= len(run) * 0.3:
            return hexed
    return run


def normalize(text: str) -> tuple:
    """A cleaned-up copy of OCR text, plus where each of its characters came from.

    OCR reads 1 as l, 0 as O, i- as 1-, and adds spaces inside IDs, like 'iam: :1234' or
    'subnet -0f9e'. The patterns are run on this copy as well as the raw text.
    """
    chars = list(text)
    for m in re.finditer(r"[A-Za-z0-9]+", text):
        fixed = _fix_run(m.group())
        if fixed != m.group():
            chars[m.start():m.end()] = list(fixed)
    fixed_text = "".join(chars)
    for m in re.finditer(r"(?<![A-Za-z0-9])[1lI](?=-[0-9a-fA-F]{8,17}(?![0-9A-Za-z]))", fixed_text):
        chars[m.start()] = "i"
    fixed_text = "".join(chars)
    for m in CAPS_SETTING.finditer(fixed_text):
        for i in range(m.start(), m.end()):
            if chars[i] == " ":
                chars[i] = "_"
    for m in SSO_SPACED.finditer("".join(chars)):
        for g in (1, 2):
            chars[m.start(g)] = "_"
    out, index = [], []
    n = len(chars)
    for i, c in enumerate(chars):
        if c == " " and 0 < i < n - 1:
            before, after = chars[i - 1], chars[i + 1]
            if after != " " and before != " " and (
                    (before in JOIN_AFTER and (after.isalnum() or after in JOIN_BEFORE))
                    or (after in JOIN_BEFORE and before.isalnum())):
                continue
        out.append(c)
        index.append(i)
    return "".join(out), index


def _fix_widths(row) -> list:
    """Tesseract sometimes reports a low-confidence word as far wider than it is, running
    over the words after it. Trim each word to where the next one starts, and the last one
    to a sensible width for its number of characters."""
    row = sorted(row, key=lambda w: w.left)
    widths = sorted(w.width / max(len(w.text), 1) for w in row if w.conf >= 60)
    typical = widths[len(widths) // 2] if widths else None
    out = []
    for i, w in enumerate(row):
        if w.chars:
            out.append(w)
            continue
        right = w.left + w.width
        if i + 1 < len(row):
            right = min(right, max(row[i + 1].left - 1, w.left + 1))
        if typical and w.width / max(len(w.text), 1) > typical * 1.8:
            right = min(right, w.left + typical * 1.2 * len(w.text))
        out.append(Word(w.text, w.left, w.top, right - w.left, w.height, w.conf, w.line))
    return out


def _layout(words) -> tuple:
    """Lay words out as text, one line per OCR line, and remember where each word sits."""
    lines = {}
    for w in words:
        lines.setdefault(w.line, []).append(w)
    parts, placed, line_boxes = [], [], {}
    pos = 0
    for key in sorted(lines):
        row = _fix_widths(lines[key])
        top = min(w.top for w in row)
        bottom = max(w.top + w.height for w in row)
        line_boxes[key] = (top, bottom)
        for j, w in enumerate(row):
            if j:
                parts.append(" ")
                pos += 1
            placed.append((pos, pos + len(w.text), w))
            parts.append(w.text)
            pos += len(w.text)
        parts.append("\n")
        pos += 1
    return "".join(parts), placed, line_boxes


def _span_boxes(s, e, label, placed, line_boxes):
    """Turn a character span into one rectangle per line it touches."""
    per_line = {}
    for ws, we, w in placed:
        if we <= s or ws >= e:
            continue
        n = max(len(w.text), 1)
        cw = w.width / n
        cs, ce = max(s, ws) - ws, min(e, we) - ws
        # Inside a word, character boxes say exactly where a match starts and ends. Without
        # them it's estimated from the average character width. Whole-word edges get
        # normal padding, edges inside a word a little less so neighbors stay readable.
        if w.chars:
            # Tesseract's character boxes can be off by a few pixels, so inside a word the
            # edge moves out half a character. A neighbor that's punctuation, like the quote
            # or colon around an ID, gets covered too, since hiding it gives nothing away.
            x0, x1 = w.chars[cs][0], w.chars[ce - 1][1]
            if cs > 0:
                reach = cw * 0.5
                if not w.text[cs - 1].isalnum():
                    reach = min(max(x0 - w.chars[cs - 1][0], reach), cw * 1.5)
                x0 -= reach
            if ce < n:
                reach = cw * 0.5
                if not w.text[ce].isalnum():
                    reach = min(max(w.chars[ce][1] - x1, reach), cw * 1.5)
                x1 += reach
            slack = 0.0
        else:
            x0 = w.left + cw * cs
            x1 = w.left + cw * ce
            slack = max(cw * 0.4, 1.5)
        left = (x0, cs > 0, slack)
        right = (x1, ce < n, slack)
        box = per_line.get(w.line)
        if box:
            left = box[0] if box[0][0] <= x0 else left
            right = box[1] if box[1][0] >= x1 else right
        per_line[w.line] = (left, right)
    out = []
    for key, ((x0, part0, slack0), (x1, part1, slack1)) in per_line.items():
        top, bottom = line_boxes[key]
        h = bottom - top
        pad_x, pad_y = max(2.0, h * 0.18), max(2.0, h * 0.2)
        x0 -= slack0 if part0 else pad_x
        x1 += slack1 if part1 else pad_x
        out.append([x0, top - pad_y, x1, bottom + pad_y, label])
    return out


def boxes_from_words(words, opts) -> list:
    """Every rectangle that needs covering in one OCR pass, as [x1, y1, x2, y2, label]."""
    text, placed, line_boxes = _layout(words)
    spans = {(s, e): label for s, e, label in redact.find_spans(text, opts)}
    norm, index = normalize(text)
    if norm != text:
        for s, e, label in redact.find_spans(norm, opts):
            spans.setdefault((index[s], index[e - 1] + 1), label)
    boxes = []
    for (s, e), label in spans.items():
        boxes.extend(_span_boxes(s, e, label, placed, line_boxes))
    return boxes


def _overlap(a, b) -> bool:
    ix = min(a[2], b[2]) - max(a[0], b[0])
    iy = min(a[3], b[3]) - max(a[1], b[1])
    if ix <= 0 or iy <= 0:
        return False
    inter = ix * iy
    smaller = min((a[2] - a[0]) * (a[3] - a[1]), (b[2] - b[0]) * (b[3] - b[1]))
    return smaller > 0 and inter / smaller >= 0.5


def merge_boxes(boxes) -> list:
    boxes = [list(b) for b in boxes]
    merged = True
    while merged:
        merged = False
        out = []
        for b in boxes:
            for o in out:
                if _overlap(o, b):
                    o[0], o[1] = min(o[0], b[0]), min(o[1], b[1])
                    o[2], o[3] = max(o[2], b[2]), max(o[3], b[3])
                    merged = True
                    break
            else:
                out.append(b)
        boxes = out
    return boxes


def find_boxes(passes, opts, size) -> list:
    """Rectangles to cover, from every OCR pass, merged and kept inside the image."""
    w, h = size
    boxes = []
    for words in passes:
        boxes.extend(boxes_from_words(words, opts))
    out = []
    for x1, y1, x2, y2, label in merge_boxes(boxes):
        x1, y1 = max(0.0, x1), max(0.0, y1)
        x2, y2 = min(float(w), x2), min(float(h), y2)
        if x2 - x1 >= 1 and y2 - y1 >= 1:
            out.append([round(x1, 1), round(y1, 1), round(x2, 1), round(y2, 1), label])
    out.sort(key=lambda b: (b[1], b[0]))
    return out


LABEL_NAMES = {
    "AccountID": "account ID", "AccessKey": "access key", "SecretKey": "secret key",
    "SessionToken": "session token", "IAMUniqueID": "IAM ID", "IAMUser": "IAM user name",
    "SessionName": "session name", "SSOHash": "SSO role suffix", "OrgID": "org ID",
    "OrgUnitID": "OU ID", "OrgRootID": "org root ID", "DirectoryID": "directory ID",
    "ResourceID": "resource ID", "ID": "UUID", "CanonicalID": "canonical ID",
    "HostedZoneID": "hosted zone ID", "CloudFrontID": "CloudFront ID",
    "Hostname": "AWS hostname", "Bucket": "bucket name", "Email": "email", "IPv4": "IP",
    "IPv6": "IP", "MAC": "MAC address", "Phone": "phone number", "SSN": "SSN",
    "CardNumber": "card number", "Username": "username", "Custom": "word from your list",
    "Secret": "secret", "Owner": "name", "User": "user name", "Org": "org name",
    "Name": "name", "DOB": "birth date", "PrivateKey": "private key", "SSHKey": "SSH key",
    "JWT": "token", "Token": "token", "Credentials": "password in a URL",
}
PLURALS = {"word from your list": "words from your list", "password in a URL":
           "passwords in URLs", "MAC address": "MAC addresses", "SSO role suffix":
           "SSO role suffixes", "secret": "secrets"}


def label_name(label: str) -> str:
    return LABEL_NAMES.get(label, label)


def summary(labels) -> str:
    counts = Counter(label_name(lb) for lb in labels)
    if not counts:
        return "Didn't find anything to cover"
    parts = []
    for name, n in counts.most_common():
        parts.append(f"{n} {PLURALS.get(name, name + 's') if n > 1 else name}")
    return f"Covered {sum(counts.values())}: " + ", ".join(parts)


def redaction_options():
    return redact.options_from(redact.load_config())


# =================================================================== shapes

# Shapes are plain dicts so they copy easily for undo and save as JSON:
#   cover, rect, oval, line, arrow: x1, y1, x2, y2
#   pen: points [[x, y], ...]
#   text: x, y (top left), text, size
# plus color [r, g, b, a], width, fill, and for detected boxes auto=True and a label.

def cover_shape(box, color, auto=False):
    x1, y1, x2, y2 = box[:4]
    shape = {"kind": "cover", "x1": x1, "y1": y1, "x2": x2, "y2": y2,
             "color": list(color), "width": 0, "fill": True}
    if auto:
        shape["auto"] = True
        shape["label"] = box[4] if len(box) > 4 else ""
    return shape


def is_cover(shape) -> bool:
    return shape["kind"] == "cover" or (shape["kind"] in ("rect", "oval") and shape.get("fill"))


def rect_of(shape) -> tuple:
    x1, x2 = sorted((shape["x1"], shape["x2"]))
    y1, y2 = sorted((shape["y1"], shape["y2"]))
    return x1, y1, x2, y2


_measure = {}


def text_size(text: str, size: float) -> tuple:
    layout = _text_layout(None, text, size)
    _, logical = layout.get_pixel_extents()
    return max(logical.width, 1), max(logical.height, 1)


def _text_layout(cr, text, size):
    import gi
    gi.require_version("Pango", "1.0")
    gi.require_version("PangoCairo", "1.0")
    from gi.repository import Pango, PangoCairo
    if cr is None:
        if "cr" not in _measure:
            cairo = _cairo()
            _measure["cr"] = cairo.Context(cairo.ImageSurface(cairo.FORMAT_ARGB32, 1, 1))
        cr = _measure["cr"]
    layout = PangoCairo.create_layout(cr)
    desc = Pango.FontDescription.from_string("Sans Bold")
    desc.set_absolute_size(max(size, 1) * Pango.SCALE)
    layout.set_font_description(desc)
    layout.set_text(text or " ", -1)
    return layout


def bbox(shape) -> tuple:
    kind = shape["kind"]
    if kind == "pen":
        xs = [p[0] for p in shape["points"]]
        ys = [p[1] for p in shape["points"]]
        return min(xs), min(ys), max(xs), max(ys)
    if kind == "text":
        w, h = text_size(shape["text"], shape["size"])
        return shape["x"], shape["y"], shape["x"] + w, shape["y"] + h
    return rect_of(shape)


def _seg_dist(px, py, ax, ay, bx, by) -> float:
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def hit(shape, x, y, tol) -> bool:
    kind = shape["kind"]
    half = shape.get("width", 0) / 2 + tol
    if kind in ("line", "arrow"):
        return _seg_dist(x, y, shape["x1"], shape["y1"], shape["x2"], shape["y2"]) <= half
    if kind == "pen":
        pts = shape["points"]
        if len(pts) == 1:
            return math.hypot(x - pts[0][0], y - pts[0][1]) <= half
        return any(_seg_dist(x, y, *pts[i], *pts[i + 1]) <= half for i in range(len(pts) - 1))
    x1, y1, x2, y2 = bbox(shape)
    if kind == "text" or is_cover(shape):
        return x1 - tol <= x <= x2 + tol and y1 - tol <= y <= y2 + tol
    if kind == "oval":
        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
        rx, ry = max((x2 - x1) / 2, 0.5), max((y2 - y1) / 2, 0.5)
        d = math.hypot((x - cx) / rx, (y - cy) / ry)
        return abs(d - 1) * min(rx, ry) <= half
    near_x = x1 - half <= x <= x2 + half
    near_y = y1 - half <= y <= y2 + half
    on_side = (abs(x - x1) <= half or abs(x - x2) <= half) and near_y
    on_top = (abs(y - y1) <= half or abs(y - y2) <= half) and near_x
    return on_side or on_top


def translate(shape, dx, dy):
    if shape["kind"] == "pen":
        shape["points"] = [[p[0] + dx, p[1] + dy] for p in shape["points"]]
    elif shape["kind"] == "text":
        shape["x"] += dx
        shape["y"] += dy
    else:
        for k in ("x1", "x2"):
            shape[k] += dx
        for k in ("y1", "y2"):
            shape[k] += dy


def _arrow_head(shape):
    x1, y1, x2, y2 = shape["x1"], shape["y1"], shape["x2"], shape["y2"]
    length = math.hypot(x2 - x1, y2 - y1) or 1.0
    ux, uy = (x2 - x1) / length, (y2 - y1) / length
    head = min(max(12.0, shape.get("width", 4) * 3.6), length * 0.6)
    half = head * 0.55
    bx, by = x2 - ux * head, y2 - uy * head
    return (x2, y2), (bx - uy * half, by + ux * half), (bx + uy * half, by - ux * half), (bx, by)


def draw_shape(cr, shape, see_through=False):
    cairo = _cairo()
    r, g, b, a = shape.get("color", (0, 0, 0, 1))
    kind = shape["kind"]
    width = max(float(shape.get("width", 4)), 0.5)
    filled = is_cover(shape)
    if filled and see_through:
        a *= 0.35
    cr.set_source_rgba(r, g, b, a)
    cr.set_line_width(width)
    cr.set_line_cap(cairo.LINE_CAP_ROUND)
    cr.set_line_join(cairo.LINE_JOIN_ROUND)
    if kind in ("cover", "rect"):
        x1, y1, x2, y2 = rect_of(shape)
        cr.rectangle(x1, y1, x2 - x1, y2 - y1)
        if filled:
            cr.fill()
        else:
            cr.set_line_join(cairo.LINE_JOIN_MITER)
            cr.stroke()
    elif kind == "oval":
        x1, y1, x2, y2 = rect_of(shape)
        if x2 - x1 < 0.5 or y2 - y1 < 0.5:
            return
        cr.save()
        cr.translate((x1 + x2) / 2, (y1 + y2) / 2)
        cr.scale((x2 - x1) / 2, (y2 - y1) / 2)
        cr.arc(0, 0, 1, 0, 2 * math.pi)
        cr.restore()
        if filled:
            cr.fill()
        else:
            cr.stroke()
    elif kind == "line":
        cr.move_to(shape["x1"], shape["y1"])
        cr.line_to(shape["x2"], shape["y2"])
        cr.stroke()
    elif kind == "arrow":
        tip, left, right, base = _arrow_head(shape)
        cr.move_to(shape["x1"], shape["y1"])
        cr.line_to(*base)
        cr.stroke()
        cr.move_to(*tip)
        cr.line_to(*left)
        cr.line_to(*right)
        cr.close_path()
        cr.fill_preserve()
        cr.set_line_width(max(width * 0.5, 1))
        cr.stroke()
    elif kind == "pen":
        pts = shape["points"]
        if len(pts) == 1:
            cr.arc(pts[0][0], pts[0][1], width / 2, 0, 2 * math.pi)
            cr.fill()
            return
        cr.move_to(*pts[0])
        for i in range(1, len(pts) - 1):
            # Curve through the midpoints so freehand lines come out smooth.
            qx, qy = pts[i]
            mx, my = (pts[i][0] + pts[i + 1][0]) / 2, (pts[i][1] + pts[i + 1][1]) / 2
            px, py = cr.get_current_point()
            cr.curve_to(px + 2 / 3 * (qx - px), py + 2 / 3 * (qy - py),
                        mx + 2 / 3 * (qx - mx), my + 2 / 3 * (qy - my), mx, my)
        cr.line_to(*pts[-1])
        cr.stroke()
    elif kind == "text":
        from gi.repository import PangoCairo
        layout = _text_layout(cr, shape["text"], shape["size"])
        cr.move_to(shape["x"], shape["y"])
        PangoCairo.show_layout(cr, layout)
        cr.new_path()


def draw_shapes(cr, shapes, see_through=False):
    for shape in shapes:
        cr.save()
        draw_shape(cr, shape, see_through)
        cr.restore()


def flatten(png: bytes, shapes, background=None):
    """The image with every shape painted into its pixels, as a new cairo surface."""
    cairo = _cairo()
    source = surface_from_png(png)
    w, h = source.get_width(), source.get_height()
    out = cairo.ImageSurface(cairo.FORMAT_RGB24 if background else cairo.FORMAT_ARGB32, w, h)
    cr = cairo.Context(out)
    if background:
        cr.set_source_rgb(*background)
        cr.paint()
    cr.set_source_surface(source, 0, 0)
    cr.paint()
    draw_shapes(cr, shapes)
    out.flush()
    return out


def encode(png: bytes, shapes, ext: str = ".png") -> bytes:
    """The finished image as file bytes. It's a fresh render, so nothing from the
    original file comes along: no layers, no metadata, no hidden pixels."""
    ext = ext.lower()
    if ext in (".jpg", ".jpeg"):
        surface = flatten(png, shapes, background=(1, 1, 1))
        buf = io.BytesIO()
        surface.write_to_png(buf)
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf
        loader = GdkPixbuf.PixbufLoader.new_with_type("png")
        loader.write(buf.getvalue())
        loader.close()
        ok, data = loader.get_pixbuf().save_to_bufferv("jpeg", ["quality"], ["92"])
        if not ok:
            raise ImageError("Couldn't make a JPEG from the image.")
        return bytes(data)
    surface = flatten(png, shapes)
    buf = io.BytesIO()
    surface.write_to_png(buf)
    return buf.getvalue()


# =================================================================== files

def pictures_folder() -> str:
    try:
        from gi.repository import GLib
        folder = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_PICTURES)
        if folder:
            return folder
    except (ImportError, ValueError, AttributeError):
        pass
    return str(Path.home() / "Pictures")


def file_type(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    return ".jpg" if ext in (".jpg", ".jpeg") else ".png"


def default_name(source_path=None, now=None) -> str:
    if source_path:
        stem, ext = os.path.splitext(os.path.basename(source_path))
        return f"{stem}-redacted{'.jpg' if ext.lower() in ('.jpg', '.jpeg') else '.png'}"
    now = now or datetime.now()
    return now.strftime("redacted-%Y-%m-%d-%H%M%S.png")


def clean_name(text: str, current_ext: str = ".png") -> str:
    """A safe file name from what was typed. Keeps .png, .jpg or .jpeg, and adds the
    current type when there's no extension (or one that can't be saved)."""
    name = text.strip().replace("/", "-").replace("\\", "-").replace("\0", "").strip()
    if not name.strip("."):
        raise ValueError("Give the file a name.")
    if os.path.splitext(name)[1].lower() in SAVE_TYPES:
        return name
    return name + current_ext


def short_path(path: str) -> str:
    home = str(Path.home())
    path = str(path)
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def write_atomic(path: str, data: bytes):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".awskit-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644 & ~_umask())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


def relocate(src: str, dest: str) -> str:
    """Rename or move a saved image. If the extension changes, it's converted too.
    Whatever is already at dest gets replaced, so ask first."""
    src, dest = os.path.abspath(src), os.path.abspath(dest)
    if src == dest:
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if file_type(src) != file_type(dest):
        data = encode(load_image_bytes(src), [], file_type(dest))
        write_atomic(dest, data)
        os.unlink(src)
        return dest
    if os.path.exists(dest):
        if os.path.isdir(dest):
            raise OSError(f"{dest} is a folder")
        try:
            os.replace(src, dest)
            return dest
        except OSError:
            os.unlink(dest)  # different drive, so shutil.move below copies it over
    shutil.move(src, dest)
    return dest


# =================================================================== commands

def windows_to_linux(path: str) -> str:
    """On WSL, accept C:\\Users\\... paths too."""
    if is_wsl() and re.match(r"^[A-Za-z]:[\\/]", path):
        try:
            r = subprocess.run(["wslpath", "-u", path], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return path


def detect(png: bytes, cfg=None):
    """Find what to cover. Returns (boxes, size)."""
    cfg = cfg or load_config()
    surface = surface_from_png(png)
    size = (surface.get_width(), surface.get_height())
    passes = read_text(png, cfg["language"])
    return find_boxes(passes, redaction_options(), size), size


def tell(message, title="Image Redact"):
    print(message, file=sys.stderr)
    if not sys.stderr.isatty():
        notify(title, message, icon="image-x-generic")


def run_gui(path=None, paste=False):
    from .app import main as gui_main
    return gui_main("image-window", initial_file=path, paste=paste)


def cmd_check() -> int:
    ok, msg = ocr_status()
    print(("Text detection: " + msg) if ok else msg)
    if ok:
        langs = ocr_languages()
        want = load_config()["language"]
        missing = [x for x in want.split("+") if x not in langs]
        print("Languages: " + (", ".join(langs) or "none found"))
        if missing:
            print(f"Missing language data for: {', '.join(missing)}")
            ok = False
    try:
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf
        names = sorted({f.get_name() for f in GdkPixbuf.Pixbuf.get_formats()})
        print("Can open: " + ", ".join(names))
    except (ImportError, ValueError):
        print("GdkPixbuf is missing, so only PNG files can be opened.")
    return 0 if ok else 1


def cmd_file(path, args) -> int:
    path = windows_to_linux(path)
    try:
        png = load_image_bytes(path)
        boxes, _ = detect(png)
    except (ImageError, OcrError) as exc:
        print(f"awskit image: {exc}", file=sys.stderr)
        return 1
    if args.list:
        if args.json:
            print(json.dumps([{"x1": b[0], "y1": b[1], "x2": b[2], "y2": b[3],
                               "what": label_name(b[4])} for b in boxes], indent=2))
        else:
            for b in boxes:
                print(f"{label_name(b[4]):<20} x {b[0]:.0f}-{b[2]:.0f}  y {b[1]:.0f}-{b[3]:.0f}")
            print(summary([b[4] for b in boxes]), file=sys.stderr)
        return 0
    out = os.path.expanduser(args.output)
    if out.endswith(("/", os.sep)) or os.path.isdir(out):
        out = os.path.join(out, default_name(path))
    elif not os.path.splitext(out)[1]:
        out += file_type(path)
    color = load_config()["box_color"]
    shapes = [cover_shape(b, color, auto=True) for b in boxes]
    try:
        write_atomic(out, encode(png, shapes, file_type(out)))
    except (OSError, ImageError) as exc:
        print(f"awskit image: couldn't save {out}: {exc}", file=sys.stderr)
        return 1
    print(f"{summary([b[4] for b in boxes])}. Saved {out}", file=sys.stderr)
    print("Text detection can miss things, so look it over before sharing.", file=sys.stderr)
    return 0


def cmd_clip(args) -> int:
    if args.gui:
        return run_gui(paste=True)
    try:
        png = read_clipboard_image()
    except ClipboardError as exc:
        tell(str(exc))
        return 1
    if not png:
        tell("The clipboard doesn't have an image in it.")
        return 1
    try:
        boxes, _ = detect(png)
        color = load_config()["box_color"]
        out = encode(png, [cover_shape(b, color, auto=True) for b in boxes])
        write_clipboard_image(out)
    except (ImageError, OcrError, ClipboardError) as exc:
        tell(str(exc))
        return 1
    tell(summary([b[4] for b in boxes]) + ". Ready to paste, but look it over first.",
         title="Clipboard image redacted")
    return 0


DESCRIPTION = """\
Cover account IDs, keys, emails and other identifying text in screenshots with
solid boxes. It reads the text with tesseract and uses your PII Redact settings,
so it finds the same things PII Redact does.

commands:
  (none)               open the Image Redact window
  FILE                 open FILE in the window
  FILE -o OUT          cover what it finds and save to OUT, without a window
  FILE --list          print what it would cover
  clip                 cover what it finds in the clipboard image and put it back
  clip -g              open the clipboard image in the window instead
  check                check that text detection is set up
"""

EPILOG = """\
examples:
  awskit image ~/Pictures/Screenshots/shot.png
  awskit image shot.png -o shot-redacted.png
  awskit image shot.png -o ~/Pictures/Shared/
  awskit image clip

Text detection can miss things, so always look the image over before sharing it.
"""


def build_parser(prog="awskit image"):
    p = argparse.ArgumentParser(prog=prog, usage="%(prog)s [command | FILE] [options]",
                                description=DESCRIPTION, epilog=EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help=argparse.SUPPRESS)
    p.add_argument("-o", "--output", metavar="OUT",
                   help="save the covered image here, a file or a folder")
    p.add_argument("-l", "--list", action="store_true", help="print what it would cover")
    p.add_argument("--json", action="store_true", help="with --list, print JSON")
    p.add_argument("-g", "--gui", action="store_true", help="open in the window")
    return p


def main(argv=None, prog="awskit image") -> int:
    args = build_parser(prog).parse_args(sys.argv[1:] if argv is None else argv)
    if args.target == "check":
        return cmd_check()
    if args.target == "clip":
        return cmd_clip(args)
    if args.target and (args.output or args.list) and not args.gui:
        return cmd_file(args.target, args)
    if args.output or args.list:
        print("awskit image: give an image file, like: awskit image shot.png -o out.png",
              file=sys.stderr)
        return 2
    path = windows_to_linux(args.target) if args.target else None
    if path and not os.path.isfile(path):
        print(f"awskit image: no such file: {path}", file=sys.stderr)
        return 1
    return run_gui(os.path.abspath(path) if path else None)
