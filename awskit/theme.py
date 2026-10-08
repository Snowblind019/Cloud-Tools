"""Color themes for the AWS Kit window: ready-made color schemes and accent colors, made by
recoloring GTK's own built-in theme. No GTK in here, so it can be tested on its own.

GTK's built-in theme (the one every GTK 4 app gets without libadwaita) writes its colors
out as plain values, so it can't be recolored by redefining a few named colors. Instead
recolor() goes through the theme's stylesheet and maps every color:

- grays (window, sidebar, view, borders, text) onto the color scheme, keeping how light
  each one is relative to the window and the text, so hover, pressed and border shades
  keep working,
- the blues that make up the accent (selection, focus ring, suggested buttons, links)
  onto the accent color, keeping how much lighter or darker each one is,
- anything else (red for errors, green for success, orange for warnings) as it is.

The stylesheet comes from the GTK that's running, so it always matches its widgets.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional

# GTK's accent blue, the reference every accent color is mapped from.
GTK_ACCENT = "#3584e4"


# =================================================================== color math (OKLab)

def _to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _from_linear(c: float) -> float:
    return 12.92 * c if c <= 0.0031308 else 1.055 * (max(c, 0.0) ** (1 / 2.4)) - 0.055


def rgb_to_oklch(r: float, g: float, b: float) -> tuple:
    """sRGB channels 0-1 to (L 0-1, chroma, hue in degrees)."""
    r, g, b = _to_linear(r), _to_linear(g), _to_linear(b)
    l_ = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m_ = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s_ = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    L = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_
    a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_
    bb = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_
    return L, math.hypot(a, bb), math.degrees(math.atan2(bb, a)) % 360


def _oklab_to_linear(L: float, a: float, b: float) -> tuple:
    l_ = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    return (4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
            -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
            -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_)


def oklch_to_rgb(L: float, C: float, H: float) -> tuple:
    """(L, chroma, hue) to sRGB channels 0-1. Colors outside sRGB keep their lightness and
    hue and lose chroma until they fit."""
    L = min(max(L, 0.0), 1.0)
    h = math.radians(H)

    def fits(c):
        lin = _oklab_to_linear(L, c * math.cos(h), c * math.sin(h))
        return all(-1e-4 <= x <= 1 + 1e-4 for x in lin), lin
    ok, lin = fits(C)
    if not ok:
        lo, hi = 0.0, C
        for _ in range(24):
            mid = (lo + hi) / 2
            if fits(mid)[0]:
                lo = mid
            else:
                hi = mid
        lin = fits(lo)[1]
    return tuple(min(max(_from_linear(x), 0.0), 1.0) for x in lin)


def parse_hex(text: str) -> Optional[tuple]:
    """'#abc', '#aabbcc' or '#aabbccdd' to (r, g, b, a), channels 0-1."""
    h = text.lstrip("#")
    if len(h) in (3, 4):
        h = "".join(ch * 2 for ch in h)
    if len(h) not in (6, 8) or not re.fullmatch(r"[0-9a-fA-F]+", h):
        return None
    vals = [int(h[i:i + 2], 16) / 255 for i in range(0, len(h), 2)]
    return tuple(vals) if len(vals) == 4 else (*vals, 1.0)


def to_hex(r: float, g: float, b: float) -> str:
    return "#" + "".join(f"{round(min(max(x, 0), 1) * 255):02x}" for x in (r, g, b))


# =================================================================== themes

@dataclass(frozen=True)
class Scheme:
    """A ready-made color scheme. hue and tints (dark, light) set the tint of the grays;
    accent is the scheme's own accent color. The lightness targets (OKLab L) of the view,
    the window and the text can be changed per variant."""
    key: str
    name: str
    hue: Optional[float] = None            # None: GTK's own grays
    tints: tuple = (0.0, 0.0)              # chroma of the window color, dark and light
    accent: str = ""                       # "" keeps GTK's blue
    dark: dict = field(default_factory=dict)
    light: dict = field(default_factory=dict)

    def targets(self, variant: str) -> dict:
        base = ({"view": 0.265, "bg": 0.30, "fg": 0.93} if variant == "dark" else
                {"view": 0.993, "bg": 0.962, "fg": 0.33})
        base.update(self.dark if variant == "dark" else self.light)
        return base

    def tint(self, variant: str) -> float:
        return self.tints[0] if variant == "dark" else self.tints[1]


SCHEMES = [
    Scheme("default", "Default"),
    Scheme("ocean", "Ocean", 245, (0.035, 0.012), "#3584e4"),
    Scheme("midnight", "Midnight", 270, (0.045, 0.014), "#7c6ff0",
           dark={"view": 0.195, "bg": 0.23, "fg": 0.92}),
    Scheme("fjord", "Fjord", 240, (0.028, 0.01), "#5e81ac",
           dark={"view": 0.30, "bg": 0.335, "fg": 0.93}),
    Scheme("forest", "Forest", 155, (0.03, 0.012), "#3a944a"),
    Scheme("plum", "Plum", 320, (0.035, 0.012), "#9141ac"),
    Scheme("ember", "Ember", 50, (0.03, 0.014), "#e66100"),
    Scheme("rose", "Rose", 5, (0.03, 0.012), "#d5486a"),
    Scheme("sand", "Sand", 85, (0.025, 0.03), "#c88800",
           light={"view": 0.985, "bg": 0.945, "fg": 0.34}),
    Scheme("slate", "Slate", 250, (0.012, 0.006), "#2190a4",
           dark={"view": 0.24, "bg": 0.275, "fg": 0.93}),
]
SCHEME_KEYS = [s.key for s in SCHEMES]

# GNOME's accent colors, picked so white text on them is readable.
ACCENTS = [("blue", "Blue", "#3584e4"), ("teal", "Teal", "#2190a4"),
           ("green", "Green", "#3a944a"), ("yellow", "Yellow", "#c88800"),
           ("orange", "Orange", "#ed5b00"), ("red", "Red", "#e62d42"),
           ("pink", "Pink", "#d56199"), ("purple", "Purple", "#9141ac"),
           ("slate", "Slate", "#6f8396")]
ACCENT_HEX = {key: hexv for key, _name, hexv in ACCENTS}

TEXT_SIZES = [(90, "Smaller"), (100, "Normal"), (110, "Larger"), (125, "Large"),
              (140, "Largest")]
STYLES = ["system", "light", "dark"]

DEFAULTS = {"style": "system", "colors": "default", "accent": "default", "text_size": 100}


def scheme(key: str) -> Scheme:
    return next((s for s in SCHEMES if s.key == key), SCHEMES[0])


def clean_settings(raw) -> dict:
    """The appearance settings from the config, with anything odd replaced by defaults."""
    out = dict(DEFAULTS)
    if not isinstance(raw, dict):
        return out
    style, colors, accent = (raw.get(k) for k in ("style", "colors", "accent"))
    if isinstance(style, str) and style in STYLES:
        out["style"] = style
    if isinstance(colors, str) and colors in SCHEME_KEYS:
        out["colors"] = colors
    if isinstance(accent, str) and (accent == "default" or accent in ACCENT_HEX or
                                    re.fullmatch(r"#[0-9a-fA-F]{6}", accent)):
        out["accent"] = accent.lower()
    size = raw.get("text_size")
    if isinstance(size, (int, float)) and not isinstance(size, bool) and 70 <= size <= 200:
        out["text_size"] = int(size)
    return out


def accent_hex(settings: dict) -> str:
    """The accent color to use, or "" for GTK's own blue."""
    accent = settings.get("accent", "default")
    if accent == "default":
        return scheme(settings.get("colors", "default")).accent
    if accent in ACCENT_HEX:
        return ACCENT_HEX[accent]
    return readable_accent(accent)


def readable_accent(hexv: str) -> str:
    """A custom accent, made dark enough for white text on it and light enough to see on a
    dark window."""
    c = parse_hex(hexv)
    if c is None:
        return ""
    L, C, H = rgb_to_oklch(*c[:3])
    return to_hex(*oklch_to_rgb(min(max(L, 0.45), 0.70), C, H))


def variant_accent(hexv: str, variant: str) -> str:
    """The accent for light or dark. On a dark window it's kept at least as light as GTK's
    own blue, since links, focus rings and highlights use it as a text color there."""
    c = parse_hex(hexv) if hexv else None
    if c is None or variant != "dark":
        return hexv
    L, C, H = rgb_to_oklch(*c[:3])
    if L >= 0.65:
        return hexv
    return to_hex(*oklch_to_rgb(0.65, C, H))


def needs_css(settings: dict) -> bool:
    """False when GTK's own theme is right as it is. Light or dark on its own is a GTK
    setting, so a high contrast or third-party GTK theme stays in place for those."""
    return not (settings["colors"] == "default" and settings["accent"] == "default")


# =================================================================== recoloring

COLOR_RE = re.compile(r"#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3,4}\b"
                      r"|\brgba?\(\s*[0-9.]+\s*,\s*[0-9.]+\s*,\s*[0-9.]+\s*(?:,\s*[0-9.]+\s*)?\)"
                      r"|(?<=[\s:,(])(?:white|black)\b")


def _parse(token: str) -> Optional[tuple]:
    if token.startswith("#"):
        return parse_hex(token)
    if token == "white":
        return (1.0, 1.0, 1.0, 1.0)
    if token == "black":
        return (0.0, 0.0, 0.0, 1.0)
    nums = [float(x) for x in re.findall(r"[0-9.]+", token)]
    if len(nums) not in (3, 4) or any(n > 255 for n in nums[:3]):
        return None
    a = nums[3] if len(nums) == 4 else 1.0
    return nums[0] / 255, nums[1] / 255, nums[2] / 255, min(max(a, 0.0), 1.0)


def _format(rgb: tuple, alpha: float, token: str) -> str:
    if alpha >= 1 and not token.startswith("rgba"):
        return to_hex(*rgb)
    r, g, b = (round(x * 255) for x in rgb)
    a = f"{alpha:.3f}".rstrip("0").rstrip(".") or "0"
    return f"rgba({r}, {g}, {b}, {a})"


def _rule_colors(css: str, selector: str) -> tuple:
    """(color, background-color) of the first rule with exactly this selector."""
    m = re.search(r"(?m)^" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    if not m:
        return None, None
    body = m.group(1)

    def prop(name):
        pm = re.search(r"(?:^|[;\s])" + name + r"\s*:\s*([^;]+)", body)
        return _parse(pm.group(1).strip()) if pm else None
    return prop("color"), prop("background-color")


class Mapper:
    """Maps the colors of one GTK stylesheet (light or dark) onto a scheme and accent."""

    def __init__(self, css: str, variant: str, scheme_: Optional[Scheme], accent: str):
        self.variant = variant
        self.scheme = scheme_ if scheme_ is not None and scheme_.hue is not None else None
        self.cache = {}
        fg, bg = _rule_colors(css, ".background")
        text, view = _rule_colors(css, ".view, iconview, textview > text")
        dark = variant == "dark"
        # GTK's own values, if the stylesheet doesn't say
        bg = bg or parse_hex("#353535" if dark else "#f6f5f4")
        fg = fg or parse_hex("#eeeeec" if dark else "#2e3436")
        view = view or parse_hex("#2d2d2d" if dark else "#ffffff")
        self.stock = {k: rgb_to_oklch(*v[:3])[0] for k, v in
                      (("view", view), ("bg", bg), ("fg", fg))}
        self.accent = None
        a = parse_hex(variant_accent(accent, variant)) if accent else None
        if a is not None:
            ref = rgb_to_oklch(*parse_hex(GTK_ACCENT)[:3])
            new = rgb_to_oklch(*a[:3])
            self.accent = (ref, new)
        if self.scheme is not None:
            t = self.scheme.targets(variant)
            pairs = sorted((self.stock[k], t[k]) for k in ("view", "bg", "fg"))
            self.anchors = pairs
            self.target_bg, self.target_fg = t["bg"], t["fg"]
            self.tint = self.scheme.tint(variant)

    # ---- grays
    def _lightness(self, L: float) -> float:
        pts = self.anchors
        if L <= pts[0][0]:
            (x0, y0), (x1, y1) = pts[0], pts[1]
        elif L >= pts[-1][0]:
            (x0, y0), (x1, y1) = pts[-2], pts[-1]
        else:
            i = next(k for k in range(1, len(pts)) if L <= pts[k][0])
            (x0, y0), (x1, y1) = pts[i - 1], pts[i]
        slope = (y1 - y0) / (x1 - x0) if abs(x1 - x0) > 1e-6 else 1.0
        if not pts[0][0] <= L <= pts[-1][0]:
            slope = min(max(slope, 0.5), 2.0)   # keep shading outside the anchors sane
        return min(max(y0 + (L - x0) * slope, 0.0), 1.0)

    def _gray(self, L: float) -> tuple:
        L2 = self._lightness(L)
        span = abs(self.target_fg - self.target_bg) or 1.0
        t = min(abs(L2 - self.target_bg) / span, 1.0)
        return oklch_to_rgb(L2, self.tint * (1 - 0.7 * t), self.scheme.hue)

    # ---- one color
    def map(self, rgb: tuple) -> tuple:
        key = tuple(round(x, 4) for x in rgb)
        if key in self.cache:
            return self.cache[key]
        L, C, H = rgb_to_oklch(*rgb)
        out = rgb
        if C < 0.03:
            if self.scheme is not None:
                out = self._gray(L)
        elif self.accent is not None:
            (rL, rC, rH), (nL, nC, nH) = self.accent
            if abs((H - rH + 180) % 360 - 180) <= 30:
                out = oklch_to_rgb(L + (nL - rL), C * (nC / rC), (H + nH - rH) % 360)
        self.cache[key] = out
        return out

    def token(self, token: str) -> str:
        c = _parse(token)
        if c is None:
            return token
        r, g, b, a = c
        if a < 1 and (r, g, b) in ((0.0, 0.0, 0.0), (1.0, 1.0, 1.0)):
            return token                # see-through black and white shade what's under
        new = self.map((r, g, b))
        if to_hex(*new) == to_hex(r, g, b):
            return token                # unchanged, written the way it was
        return _format(new, a, token)


def recolor(css: str, variant: str, scheme_key: str = "default", accent: str = "",
            asset_base: str = "") -> str:
    """GTK's stylesheet for variant ("light" or "dark") with its colors mapped to the
    scheme and accent. asset_base is where the stylesheet's own relative url()s point,
    since the result is loaded from memory."""
    mapper = Mapper(css, variant, scheme(scheme_key), accent)
    out = COLOR_RE.sub(lambda m: mapper.token(m.group(0)), css)
    if asset_base:
        base = asset_base.rstrip("/") + "/"
        out = re.sub(r"""url\(\s*(["']?)(?![a-z]+:)([^"')]+)\1\s*\)""",
                     lambda m: f'url("{base}{m.group(2)}")', out)
    return out


def preview(css: str, variant: str, scheme_key: str, accent: str) -> dict:
    """The main colors of a scheme, for the swatches in the Appearance window."""
    mapper = Mapper(css, variant, scheme(scheme_key), accent)
    dark = variant == "dark"
    fg, bg = _rule_colors(css, ".background")
    _text, view = _rule_colors(css, ".view, iconview, textview > text")
    bg = bg or parse_hex("#353535" if dark else "#f6f5f4")
    fg = fg or parse_hex("#eeeeec" if dark else "#2e3436")
    view = view or parse_hex("#2d2d2d" if dark else "#ffffff")
    L, C, H = rgb_to_oklch(*bg[:3])
    header = oklch_to_rgb(L - (0.06 if dark else 0.035), C, H)
    return {"bg": mapper.map(bg[:3]), "fg": mapper.map(fg[:3]), "view": mapper.map(view[:3]),
            "header": mapper.map(header), "accent": mapper.map(parse_hex(GTK_ACCENT)[:3])}


def accent_css(accent: str) -> str:
    """Rules for AWS Kit's own widgets that use GTK's blue, so they follow the accent too."""
    if not accent:
        return ""
    return (f".lp-needed {{ color: {accent}; }}\n"
            f".scp-mgmt {{ background: alpha({accent}, 0.18); color: {accent}; }}\n"
            f".scp-draft {{ background: {accent}; color: white; }}\n")


def contrast(c1: tuple, c2: tuple) -> float:
    """WCAG contrast ratio of two sRGB colors (channels 0-1)."""
    def lum(c):
        r, g, b = (_to_linear(x) for x in c[:3])
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    a, b = sorted((lum(c1), lum(c2)), reverse=True)
    return (a + 0.05) / (b + 0.05)
