"""Draws the Windows shortcut icons, awskit.ico and image-redact.ico. Run it from the repo
root after changing a design: python3 windows/make_icons.py (needs pycairo and Pillow)."""
import io
import math
import os
import sys

import cairo
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from awskit import imageedit  # noqa: E402
from awskit.imageredact import rounded_rect  # noqa: E402

SIZES = (256, 128, 64, 48, 32, 24, 16)


def draw_awskit(cr, size):
    """A dark panel with a sidebar of tools, in AWS colors."""
    s = size / 64
    cr.scale(s, s)
    rounded_rect(cr, 4, 4, 56, 56, 11)
    cr.set_source_rgb(0.137, 0.184, 0.243)
    cr.fill()
    cr.set_source_rgb(1.0, 0.6, 0.0)
    rounded_rect(cr, 11, 13, 14, 38, 4)
    cr.fill()
    cr.set_source_rgb(0.137, 0.184, 0.243)
    for y in (18, 27, 36):
        rounded_rect(cr, 14, y, 8, 4, 2)
        cr.fill()
    cr.set_source_rgb(0.9, 0.92, 0.95)
    for y, w in ((15, 24), (25, 18), (35, 22), (45, 14)):
        rounded_rect(cr, 30, y, w, 5, 2.5)
        cr.fill()
    cr.set_source_rgb(1.0, 0.6, 0.0)
    cr.arc(49, 47.5, 4, 0, 2 * math.pi)
    cr.fill()


def save_ico(draw, path):
    images = []
    for size in SIZES:
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
        draw(cairo.Context(surface), size)
        buf = io.BytesIO()
        surface.write_to_png(buf)
        images.append(Image.open(io.BytesIO(buf.getvalue())).convert("RGBA"))
    images[0].save(path, sizes=[im.size for im in images], append_images=images[1:])


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    save_ico(draw_awskit, os.path.join(here, "awskit.ico"))
    save_ico(imageedit.draw_app_icon, os.path.join(here, "image-redact.ico"))
    print("Wrote awskit.ico and image-redact.ico")
