"""Cloud Map's layout memory: where you moved things in draw.io, kept for the next
export. No GTK.

Without this, rearranging boxes in draw.io and rescanning next week would throw the
arrangement away. After every save, remember() reads the .drawio file back and stores
a sidecar next to the snapshot, <name>.layout.json, one section per map type:

- nodes: every box's position and size, relative to its container, and its container's
  ID. Boxes moved or resized by hand are "pinned". Detail cards (security groups,
  endpoints) float on their own draw.io layer, so they're kept relative to their VPC.
- edges: the waypoints and end points of lines moved by hand.
- styles: style changes made in draw.io (colors, fonts, widths), as overrides.
- extra: cells drawn by hand (notes, text, extra arrows), as raw XML.

Changed captions go to the labels file, so they stick in every map.

apply() puts it back on a fresh Layout, which both the .drawio writer and the viewer
draw, so the app and the file always show the same arrangement:

- known box, same container: its remembered position
- known box, different container (it moved to another subnet in AWS): placed
  automatically in the new one
- new box: its automatic position if that's free, otherwise the nearest free space
  below it, without moving anything pinned. Containers grow to fit
- removed box: dropped, and the gap stays

Each box AWS Kit writes carries awskit_geo (its geometry as written), awskit_lh and
awskit_sh (short hashes of its label and style) and awskit_pin, so reading a file back
only treats what changed in draw.io as a change, even if AWS changed in between.

Redacted files have keyed-hash cell IDs. They're mapped back to real IDs with the same
key, so the sidecar always uses real IDs. The sidecar never goes into a redacted export:
positions are applied by ID, and cells drawn by hand get hashed IDs and redacted text.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import math
import re
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from urllib.parse import unquote

from . import maplayout as ml
from . import mapmodel as mm
from .mapdrawio import (GENERATED_PREFIXES, LAYER_IDS, LAYOUT_STYLE_KEYS, MARGIN, parse_style,
                        points_text, short_hash)

FORMAT = "awskit-cloudmap-layout"
VERSION = 1
SUFFIX = ".layout.json"
GRID = ml.GRID
GAP = ml.GAP
PAD = ml.PAD
ROLES_SKIPPED = ("icon", "flag-outline", "flag-badge", "flag-edge")
ROUTE_KEYS = ("exitX", "exitY", "entryX", "entryY")
# What a style change can be kept as when the original style can't be worked out again.
VISUAL_KEYS = ("fillColor", "strokeColor", "fontColor", "fontSize", "fontStyle", "fontFamily",
               "strokeWidth", "dashed", "dashPattern", "opacity", "fillOpacity",
               "strokeOpacity", "textOpacity", "shadow", "gradientColor", "rounded", "glass")
META_KEYS = ("awskit_map", "awskit_theme", "awskit_show", "awskit_accounts",
             "awskit_regions", "awskit_vpcs", "awskit_service_linked", "awskit_default_vpcs",
             "awskit_redacted", "awskit_snapshot")


class MemoryError_(ValueError):
    pass


# =================================================================== the sidecar

def sidecar_path(snapshot_path) -> Path:
    """<name>.layout.json next to <name>.cloudmap.json."""
    p = Path(snapshot_path)
    name = p.name
    stem = name[: -len(".cloudmap.json")] if name.endswith(".cloudmap.json") else p.stem
    return p.with_name(stem + SUFFIX)


def empty() -> dict:
    return {"format": FORMAT, "version": VERSION, "maps": {}}


def load(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty()
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        return empty()
    if not isinstance(data.setdefault("maps", {}), dict):
        data["maps"] = {}
    data["maps"] = {k: sec for k, sec in data["maps"].items() if isinstance(sec, dict)}
    for sec in data["maps"].values():
        _clean_section(sec)
    return data


def _clean_section(sec):
    """Drops remembered positions that aren't usable numbers (a hand-edited sidecar), and
    keeps the rest within COORD_LIMIT."""
    for key, kind in (("nodes", dict), ("edges", dict), ("styles", dict), ("extra", list)):
        if key in sec and not isinstance(sec[key], kind):
            sec[key] = kind()
    styles = sec.get("styles", {})
    for nid, over in list(styles.items()):
        if not isinstance(over, dict):
            del styles[nid]
    if "extra" in sec:
        sec["extra"] = [x for x in sec["extra"] if isinstance(x, str)]
    nodes = sec.get("nodes")
    if isinstance(nodes, dict):
        for nid, rec in list(nodes.items()):
            try:
                for k in ("x", "y"):
                    rec[k] = coord(rec[k])
                for k in ("w", "h"):
                    rec[k] = coord(rec[k], size=True)
            except (KeyError, TypeError, ValueError):
                del nodes[nid]
    edges = sec.get("edges")
    if isinstance(edges, dict):
        for eid, rec in list(edges.items()):
            try:
                rec["points"] = [[coord(x), coord(y)] for x, y in rec.get("points", [])]
                route = rec.get("route") or {}
                for k, v in route.items():
                    route[k] = float(v)
                    if not math.isfinite(route[k]):
                        raise ValueError(k)
            except (AttributeError, TypeError, ValueError):
                del edges[eid]


def save(memory, path):
    from .common import write_atomic
    path = Path(path)
    write_atomic(path, json.dumps(memory, indent=1, sort_keys=True) + "\n")
    return path


def section(memory, map_type, create=True) -> dict:
    maps = memory.setdefault("maps", {})
    if map_type not in maps:
        if not create:
            return {}
        maps[map_type] = {}
    sec = maps[map_type]
    for key, default in (("nodes", {}), ("edges", {}), ("styles", {}), ("extra", [])):
        sec.setdefault(key, default)
    return sec


def tidy(memory, map_type) -> int:
    """Forget the positions of everything not moved by hand, so the automatic layout
    places them again around the pinned ones. Returns how many were forgotten."""
    sec = section(memory, map_type)
    gone = [k for k, rec in sec["nodes"].items() if not rec.get("pinned")]
    for k in gone:
        sec["nodes"].pop(k)
    return len(gone)


def reset(memory, map_type) -> bool:
    """Forget everything about one map type's layout."""
    return memory.get("maps", {}).pop(map_type, None) is not None


def reset_file(sidecar, map_type) -> bool:
    """Reset one map type's layout in a sidecar file. The file goes away when nothing is
    left in it. A working .drawio left behind is never read back in: AWS Kit no longer
    knows it, so the next edit writes it fresh."""
    path = Path(sidecar)
    if not path.exists():
        return False
    memory = load(path)
    gone = reset(memory, map_type)
    if memory.get("maps"):
        save(memory, path)
    else:
        path.unlink()
    return gone


def summary_of(memory, map_type) -> dict:
    """How much of a map's layout is remembered, for the page and the CLI."""
    sec = (memory or {}).get("maps", {}).get(map_type) or {}
    nodes = sec.get("nodes", {})
    return {"boxes": len(nodes), "pinned": sum(1 for r in nodes.values() if r.get("pinned")),
            "edges": len(sec.get("edges", {})), "styles": len(sec.get("styles", {})),
            "extra": len(sec.get("extra", []))}


def file_hash(text) -> str:
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


def mark_seen(memory, map_type, drawio_path, text=None):
    """Note what the working .drawio file holds now, written or read by AWS Kit, so a
    change made outside AWS Kit (draw.io desktop) can be told apart later."""
    if text is None:
        text = Path(drawio_path).read_bytes()
    section(memory, map_type)["file"] = {"name": Path(drawio_path).name, "sha256": file_hash(text)}


def changed_outside(memory, map_type, drawio_path) -> bool:
    """True when the working .drawio file was changed since AWS Kit last wrote or read it."""
    path = Path(drawio_path)
    try:
        data = path.read_bytes()
    except OSError:
        return False
    seen = ((memory or {}).get("maps", {}).get(map_type) or {}).get("file") or {}
    if seen.get("name") != path.name:
        return False          # not a file AWS Kit wrote for this map
    return seen.get("sha256") != file_hash(data)


# =================================================================== reading a .drawio

# Coordinates and sizes from a file are kept within this, so an edited file with inf, nan
# or a box a billion pixels tall can't stop every later layout and export.
COORD_LIMIT = 200_000.0
# A diagram bigger than this (as text, or unpacked from a compressed page) is refused.
MAX_DIAGRAM = 64 * 1024 * 1024


def coord(value, size=False) -> float:
    try:
        v = float(value or 0)
    except (TypeError, ValueError):
        raise MemoryError_(f"The draw.io file has a coordinate that isn't a number: {value!r}") from None
    if not math.isfinite(v):
        raise MemoryError_(f"The draw.io file has a coordinate that isn't a number: {value!r}")
    return min(max(v, 0.0 if size else -COORD_LIMIT), COORD_LIMIT)


def _inflate(data: str) -> str:
    """A compressed draw.io page, unpacked with a size limit (a small file can unpack to
    gigabytes)."""
    raw = base64.b64decode(data)
    d = zlib.decompressobj(-15)
    out = d.decompress(raw, MAX_DIAGRAM)
    if d.unconsumed_tail:
        raise MemoryError_("The draw.io page is too big to read.")
    return out.decode("utf-8")


class Cell:
    __slots__ = ("id", "el", "cell", "attrs", "geo", "points", "style")

    def __init__(self, el, cell):
        self.el = el
        self.cell = cell
        self.id = el.get("id") or ""
        self.attrs = dict(el.attrib) if el is not cell else {}
        geo = cell.find("mxGeometry")
        self.geo = None
        self.points = []
        if geo is not None:
            self.geo = tuple(coord(geo.get(k), size=k in ("width", "height"))
                             for k in ("x", "y", "width", "height"))
            arr = geo.find("Array")
            if arr is not None:
                self.points = [(coord(p.get("x")), coord(p.get("y")))
                               for p in arr.findall("mxPoint")]
        self.style = cell.get("style", "")

    @property
    def parent(self):
        return self.cell.get("parent", "")

    @property
    def label(self):
        return self.el.get("label", "") if self.attrs else self.cell.get("value", "")

    @property
    def vertex(self):
        return self.cell.get("vertex") == "1"

    @property
    def edge(self):
        return self.cell.get("edge") == "1"


def _diagram_xml(text):
    """The mxGraphModel element of the first page, whether stored plain or compressed."""
    if len(text) > MAX_DIAGRAM:
        raise MemoryError_("The draw.io file is too big to read.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise MemoryError_(f"That isn't a readable draw.io file: {exc}") from exc
    if root.tag == "mxGraphModel":
        return root, root
    diagram = root.find("diagram") if root.tag == "mxfile" else None
    if diagram is None:
        raise MemoryError_("That isn't a draw.io file.")
    model = diagram.find("mxGraphModel")
    if model is None:
        data = (diagram.text or "").strip()
        if not data:
            raise MemoryError_("The draw.io file has an empty page.")
        try:
            model = ET.fromstring(unquote(_inflate(data)))
        except (ValueError, zlib.error, ET.ParseError) as exc:
            raise MemoryError_(f"Couldn't read the compressed page: {exc}") from exc
    return diagram, model


def read_cells(text):
    """(diagram element, {id: Cell} in file order) from .drawio text."""
    diagram, model = _diagram_xml(text)
    root = model.find("root")
    if root is None:
        raise MemoryError_("The draw.io page has no cells.")
    cells = {}
    for el in root:
        if el.tag == "mxCell":
            cell = el
        elif el.tag in ("UserObject", "object"):
            cell = el.find("mxCell")
            if cell is None:
                continue
        else:
            continue
        c = Cell(el, cell)
        if c.id:
            cells[c.id] = c
    return diagram, cells


def meta_of(diagram, cells) -> dict:
    root = cells.get("0")
    meta = {k: v for k, v in (root.attrs if root is not None else {}).items() if k in META_KEYS}
    if "awskit_map" not in meta:
        did = diagram.get("id", "") if diagram is not None else ""
        if did.startswith("awskit-"):
            meta["awskit_map"] = did[len("awskit-"):]
    return meta


def _split(value):
    return [v for v in str(value or "").split(",") if v]


def options_of(meta) -> dict:
    """make_layout() arguments from a file's metadata."""
    return {"map_type": meta.get("awskit_map", "access"),
            "show": set(_split(meta.get("awskit_show"))) if "awskit_show" in meta else None,
            "accounts": _split(meta.get("awskit_accounts")),
            "regions": _split(meta.get("awskit_regions")),
            "vpcs": _split(meta.get("awskit_vpcs")),
            "service_linked": meta.get("awskit_service_linked") == "1",
            "default_vpcs": meta.get("awskit_default_vpcs") == "1"}


def filter_hash(id_fn, value) -> str:
    """How an account or VPC filter is written in a redacted file: hashed with the
    redaction key, so it can be matched again here but not read by anyone else."""
    return id_fn("filter:" + str(value).lower())


def meta_for(lay_options: dict, redacted=False, snapshot_name="", id_fn=None) -> dict:
    """The metadata AWS Kit writes on a .drawio root, from make_layout() arguments. In a
    redacted file the account and VPC filters are hashed (or left out without id_fn),
    since they're account IDs, VPC IDs or names."""
    show = lay_options.get("show")

    def picked(key):
        values = [str(v) for v in lay_options.get(key) or []]
        if redacted:
            values = [filter_hash(id_fn, v) for v in values] if id_fn else []
        return ",".join(values)
    out = {"awskit_map": lay_options.get("map_type", "access"),
           "awskit_accounts": picked("accounts"),
           "awskit_regions": ",".join(lay_options.get("regions") or []),
           "awskit_vpcs": picked("vpcs"),
           "awskit_service_linked": "1" if lay_options.get("service_linked") else "0",
           "awskit_default_vpcs": "1" if lay_options.get("default_vpcs") else "0",
           "awskit_redacted": "1" if redacted else "0"}
    if show is not None:
        out["awskit_show"] = ",".join(sorted(show))
    if snapshot_name and not redacted:
        out["awskit_snapshot"] = snapshot_name
    return out


def _floats(text):
    try:
        return tuple(float(v) for v in str(text).split(","))
    except ValueError:
        return ()


def _same_geo(a, b, tol=0.5) -> bool:
    return len(a) == len(b) and all(abs(x - y) <= tol for x, y in zip(a, b))


def _parse_points(text):
    out = []
    for part in str(text or "").split():
        xy = _floats(part)
        if len(xy) == 2:
            out.append(xy)
    return out


def _same_points(a, b, tol=0.5) -> bool:
    return len(a) == len(b) and all(_same_geo(p, q, tol) for p, q in zip(a, b))


def label_text(label) -> tuple:
    """(title, caption) from a label as AWS Kit writes it, after editing in draw.io:
    the bold part is the title, the rest is the caption."""
    text = str(label or "")
    text = re.sub(r"(?i)<br\s*/?>|</div>|</p>", "\n", text)
    m = re.search(r"(?is)<(b|strong)>(.*?)</\1>", text)
    if m:
        title = m.group(2)
        rest = text[:m.start()] + "\n" + text[m.end():]
    else:
        lines = [x for x in re.sub(r"<[^>]+>", "", text).split("\n") if x.strip()]
        title, rest = (lines[0] if lines else ""), "\n".join(lines[1:])

    def clean(s):
        return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s)).split())
    return clean(title), clean(rest)


def _squash(text) -> str:
    return re.sub(r"\s+", "", str(text or ""))


def _abs_positions(cells):
    """Absolute top-left of every vertex, following parents up to the layer."""
    out = {}

    def find(cid, depth=0):
        if cid in out:
            return out[cid]
        c = cells.get(cid)
        if c is None or not c.vertex or c.geo is None or depth > 64:
            return (0.0, 0.0)
        px, py = find(c.parent, depth + 1) if c.parent in cells and cells[c.parent].vertex else (0.0, 0.0)
        out[cid] = (px + c.geo[0], py + c.geo[1])
        return out[cid]
    for cid in cells:
        find(cid)
    return out


def remember(drawio_path, snap, sidecar, labels_file=None, key=None, extra_labels=None):
    """Read a saved .drawio back into the sidecar, and changed captions into the labels
    file. Returns a summary dict. snap is the Snapshot the map was drawn from."""
    from . import cloudmap, mapdrawio
    if Path(drawio_path).stat().st_size > MAX_DIAGRAM:
        raise MemoryError_("The draw.io file is too big to read.")
    raw = Path(drawio_path).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MemoryError_(f"That isn't a readable draw.io file: {exc}") from exc
    diagram, cells = read_cells(text)
    meta = meta_of(diagram, cells)
    if "awskit_map" not in meta:
        raise MemoryError_("This file wasn't drawn by AWS Kit, so there's no layout to remember.")
    opts = options_of(meta)
    map_type = opts["map_type"]
    redacted = meta.get("awskit_redacted") == "1"
    theme_name = meta.get("awskit_theme", "dark")

    # The same map again, without memory, for the styles AWS Kit gives each cell and the
    # real IDs behind a redacted file's hashed ones.
    labels = cloudmap.load_labels(extra_labels) if labels_file is None else _read_labels(labels_file)
    if redacted:
        _, id_fn = cloudmap.redactors() if key is None else (None, key)
        for name, kind in (("accounts", "account"), ("vpcs", "vpc")):
            if not opts[name]:
                continue
            known = {}
            for n in snap.nodes.values():
                if n.kind == kind:
                    for v in (n.id, n.name, mm.title_of(n)):
                        if v:
                            known[filter_hash(id_fn, v)] = v
            # Files from before filters were hashed hold the plain values, which stay.
            opts[name] = [known.get(v, v) for v in opts[name]]
    view = ml.build_view(snap, ml.Options(opts["map_type"], opts["show"], opts["accounts"],
                                          opts["regions"], opts["vpcs"], opts["service_linked"],
                                          opts["default_vpcs"], labels))
    if redacted:
        real = {id_fn(nid): nid for nid in view.nodes}
        real.update({id_fn(e.id): e.id for e in view.edges})
    else:
        real = {}
    try:
        base_lay = cloudmap.make_layout(snap, redacted=redacted, labels=labels, **opts)
        writer = mapdrawio.Writer(base_lay, theme_name)
        base_boxes = {b.id: b for b in base_lay.boxes}
        base_links = {lk.id: lk for lk in base_lay.links}
    except (ml.LayoutError, ValueError):
        writer, base_boxes, base_links = None, {}, {}

    memory = load(sidecar)
    sec = section(memory, map_type)
    absolute = _abs_positions(cells)
    layers = set(LAYER_IDS.values())
    summary = {"map_type": map_type, "boxes": 0, "moved": 0, "edges": 0, "styles": 0,
               "captions": 0, "extra": 0}
    extra = []
    new_labels = {}

    def rid(cid):
        return real.get(cid, cid) if redacted else cid

    def is_container(cid):
        """An AWS Kit container (a VPC, a subnet...), not a card that holds its icon."""
        if cid in base_boxes:
            return base_boxes[cid].role == "container"
        c = cells.get(cid)
        return c is not None and "pointerEvents=0" in c.style

    def holder_of(c):
        """The container a box sits in, skipping cards it may have been dropped into."""
        p, n = c.parent, 0
        while p and p not in layers and p in cells and not is_container(p) and n < 64:
            p, n = cells[p].parent, n + 1
        return "" if (not p or p in layers or p not in cells) else p

    for cid, c in cells.items():
        if cid == "0" or c.parent == "0" or cid.startswith(GENERATED_PREFIXES):
            continue
        generated = c.attrs.get("awskit") == "1"
        if not generated:
            extra.append(_extra_xml(c, rid if redacted else None))
            continue
        if c.attrs.get("role") in ROLES_SKIPPED:
            continue
        nid = rid(cid)
        saved_style = parse_style(c.style)
        style_changed = "awskit_sh" in c.attrs and short_hash(c.style) != c.attrs["awskit_sh"]
        if c.vertex and c.geo is not None:
            summary["boxes"] += 1
            x, y, w, h = c.geo
            ax, ay = absolute.get(cid, (x, y))
            if c.attrs.get("awskit_in"):
                container = rid(c.attrs["awskit_in"])
                cx, cy = absolute.get(c.attrs["awskit_in"], (MARGIN, MARGIN))
                parent, rx, ry = container, ax - cx, ay - cy
            else:
                holder = holder_of(c)
                if not holder:
                    parent, rx, ry = "", ax - MARGIN, ay - MARGIN
                else:
                    hx, hy = absolute.get(holder, (0.0, 0.0))
                    parent, rx, ry = rid(holder), ax - hx, ay - hy
            moved = "awskit_geo" in c.attrs and not _same_geo(_floats(c.attrs["awskit_geo"]),
                                                               (x, y, w, h))
            pinned = moved or c.attrs.get("awskit_pin") == "1"
            summary["moved"] += 1 if moved else 0
            sec["nodes"][nid] = {"parent": parent, "x": round(rx, 2), "y": round(ry, 2),
                                 "w": round(w, 2), "h": round(h, 2), "pinned": bool(pinned)}
            if not redacted and "awskit_lh" in c.attrs and short_hash(c.label) != c.attrs["awskit_lh"]:
                v = view.nodes.get(nid)
                if v is not None:
                    title, caption = label_text(c.label)
                    entry = {}
                    if title and _squash(title) != _squash(v.title):
                        entry["title"] = title
                    if _squash(caption) != _squash(v.caption):
                        entry["caption"] = caption
                    if entry:
                        new_labels[nid] = entry
            if style_changed:
                base = writer.box_style(base_boxes[cid]) if cid in base_boxes else None
                over = _overrides(saved_style, base)
                if over:
                    sec["styles"][nid] = over
                else:
                    sec["styles"].pop(nid, None)
        elif c.edge:
            pts = [(x, y) for x, y in c.points]
            moved = "awskit_pts" in c.attrs and not _same_points(_parse_points(c.attrs["awskit_pts"]), pts)
            base_parts = writer.edge_parts(base_links[cid], base_links[cid].kind) \
                if (writer is not None and cid in base_links) else {}
            route = {k: saved_style[k] for k in ROUTE_KEYS if k in saved_style}
            rerouted = style_changed and any(base_parts.get(k) != v for k, v in route.items())
            pinned = moved or rerouted or c.attrs.get("awskit_pin") == "1"
            if pinned:
                summary["edges"] += 1
                sec["edges"][nid] = {"points": [[round(x - MARGIN, 2), round(y - MARGIN, 2)]
                                                for x, y in pts],
                                     "route": route, "pinned": True}
            else:
                sec["edges"].pop(nid, None)
            if style_changed:
                over = _overrides(saved_style, base_parts or None)
                if over:
                    sec["styles"][nid] = over
                else:
                    sec["styles"].pop(nid, None)
    sec["extra"] = [x for x in extra if x]
    summary["extra"] = len(sec["extra"])
    summary["styles"] = len(sec["styles"])
    if not redacted:
        mark_seen(memory, map_type, drawio_path, raw)
    save(memory, sidecar)
    if new_labels and not redacted:
        summary["captions"] = len(new_labels)
        _save_labels(new_labels, labels_file)
    return summary


def _overrides(saved: dict, base) -> dict:
    """The style keys draw.io changed: different from what AWS Kit wrote, leaving out the
    ones that come from the layout."""
    if base is None:
        return {k: saved[k] for k in VISUAL_KEYS if k in saved}
    return {k: v for k, v in saved.items()
            if k not in LAYOUT_STYLE_KEYS and base.get(k) != v}


def _extra_xml(c, rid=None) -> str:
    el = ET.fromstring(ET.tostring(c.el))         # a copy
    if rid is not None:
        cell = el if el.tag == "mxCell" else el.find("mxCell")
        for attr in ("parent", "source", "target"):
            if cell is not None and cell.get(attr):
                cell.set(attr, rid(cell.get(attr)))
    return ET.tostring(el, encoding="unicode")


def _read_labels(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return {str(k): v for k, v in data.items() if isinstance(v, (str, dict))}
    except (OSError, ValueError, AttributeError):
        return {}


def _save_labels(new, path=None):
    """Merge caption edits into the labels file (the one in ~/.config/awskit/cloud-map/
    unless path says otherwise)."""
    from . import cloudmap
    path = Path(path) if path else cloudmap.LABELS_FILE
    labels = _read_labels(path)
    for nid, entry in new.items():
        old = labels.get(nid)
        cur = {"caption": old} if isinstance(old, str) else dict(old or {})
        cur.update(entry)
        labels[nid] = cur["caption"] if set(cur) == {"caption"} else cur
    path.parent.mkdir(parents=True, exist_ok=True)
    from .common import write_atomic
    write_atomic(path, json.dumps(labels, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


# =================================================================== applying it

def _overlaps(a, b, gap) -> bool:
    return not (a[0] + a[2] + gap <= b[0] or b[0] + b[2] + gap <= a[0] or
                a[1] + a[3] + gap <= b[1] or b[1] + b[3] + gap <= a[1])


STRIP_ROOM = 34      # the section title above a row of detail cards (Security groups...)


def _free_spot(box, placed, top):
    """A new box's own spot (from the automatic layout) if nothing placed is in the way,
    else the nearest free spot straight below it, so columns stay lined up. Gateways on
    a container's top border slide along it instead."""
    if box.role == "chip":
        for dx in range(0, 4000, GRID):
            for x in (box.x - dx, box.x + dx):
                if x >= PAD and _clear(box, x, box.y, placed, GAP / 2):
                    return x, box.y
        return box.x, box.y
    y = max(box.y, top)
    if _clear(box, box.x, y, placed, GAP):
        return box.x, y
    bottom = max([o.y + o.h for o in placed] + [y]) + GAP + STRIP_ROOM
    start = int(math.ceil(y / GRID) * GRID)
    for yy in range(start, int(bottom) + GRID, GRID):
        if _clear(box, box.x, yy, placed, GAP):
            return box.x, yy
    return box.x, int(math.ceil(bottom / GRID) * GRID)


def _clear(box, x, y, placed, gap) -> bool:
    for o in placed:
        # Detail cards have their section title above them.
        pad = STRIP_ROOM if box.layer != "base" and o.layer == "base" else 0
        if _overlaps((x, y - pad, box.w, box.h + pad), (o.x, o.y, o.w, o.h), gap):
            return False
    return True


def _rows(boxes) -> list:
    """Boxes grouped by their top edge, top row first."""
    rows = []
    for b in sorted(boxes, key=lambda b: (b.y, b.x)):
        if rows and abs(rows[-1][0].y - b.y) < 1:
            rows[-1].append(b)
        else:
            rows.append([b])
    return rows


def _row_shift(row, placed) -> int:
    """How far a row has to move down to be clear of what's placed: nothing if it's
    clear with half the usual gap, else the first spot with the full gap."""
    if all(_clear(b, b.x, b.y, placed, GAP / 2) for b in row):
        return 0
    for dy in range(GRID, 40000, GRID):
        if all(_clear(b, b.x, b.y + dy, placed, GAP) for b in row):
            return dy
    return 0


def apply(lay, sec, id_fn=None, text_fn=None):
    """Put remembered positions, routes, styles and hand-drawn cells onto a fresh Layout.
    id_fn maps real IDs to the layout's (for redacted exports), and text_fn redacts the
    text of hand-drawn cells there."""
    if not sec or not any(sec.get(k) for k in ("nodes", "edges", "styles", "extra")):
        return lay
    rid = id_fn or (lambda x: x)
    nodes = {rid(k): v for k, v in sec.get("nodes", {}).items()}
    edges = {rid(k): v for k, v in sec.get("edges", {}).items()}
    styles = {rid(k): v for k, v in sec.get("styles", {}).items()}
    boxes = {b.id: b for b in lay.boxes}

    # Logical containers: nested boxes by their cell parent, detail cards by their VPC.
    def holder(b):
        if b.parent:
            return b.parent if b.parent in boxes else ""
        h = b.hints.get("container", "") if b.layer != "base" else ""
        return h if h in boxes else ""
    for b in lay.boxes:
        h = holder(b)
        if not b.parent and h:
            c = boxes[h]
            b.x, b.y = b.ax - c.ax, b.ay - c.ay   # relative to the VPC while things move
    auto = {b.id: (b.x, b.y) for b in lay.boxes}
    kids = {}
    for b in lay.boxes:
        kids.setdefault(holder(b), []).append(b)
    depth = {}

    def depth_of(bid, n=0):
        if bid not in depth:
            h = holder(boxes[bid]) if bid in boxes else ""
            depth[bid] = 0 if not h or n > 64 else depth_of(h, n + 1) + 1
        return depth[bid]

    # Remembered positions and sizes first. A container keeps its remembered size and
    # only grows from there; a card keeps its size only if it was resized by hand.
    status = {}
    for b in lay.boxes:
        rec = nodes.get(b.id)
        if rec and (rid(rec["parent"]) if rec.get("parent") else "") == holder(b):
            b.x, b.y = rec["x"], rec["y"]
            if b.role == "container" or rec.get("pinned"):
                b.w, b.h = rec["w"], rec["h"]
            b.hints["remembered"] = True
            if rec.get("pinned"):
                b.hints["pinned"] = True
            status[b.id] = "pinned" if rec.get("pinned") else "kept"
        else:
            status[b.id] = "new"

    # Then each container from the innermost out: pinned boxes stay put, the rest keep
    # their spot if it's free or move down to the nearest free one, and the container
    # grows to fit.
    order = sorted((bid for bid in kids if bid), key=lambda bid: -depth_of(bid)) + [""]
    for pid in order:
        group = kids.get(pid, [])
        parent = boxes.get(pid)
        tops = [auto[b.id][1] for b in group if b.role != "chip"]
        top = min(tops) if tops else 0
        placed = [b for b in group if status[b.id] == "pinned"]
        # Boxes that weren't moved go row by row from the top. A row that something now
        # overlaps (a pinned box, or a container above that grew) moves down as a whole,
        # so rows of cards stay rows, and what's below follows only if it has to.
        kept = [b for b in group if status[b.id] == "kept"]
        for b in [b for b in kept if b.role == "chip"]:
            b.x, b.y = _free_spot(b, placed, top)
            placed.append(b)
        for row in _rows([b for b in kept if b.role != "chip"]):
            dy = _row_shift(row, placed)
            for b in row:
                b.y += dy
                placed.append(b)
        for b in [b for b in group if status[b.id] == "new"]:
            b.x, b.y = _free_spot(b, placed, top)
            placed.append(b)
        if parent is not None and group:
            need_w = max(b.x + b.w for b in group) + PAD
            need_h = max([b.y + b.h for b in group if b.role != "chip"] + [0]) + PAD
            parent.w = max(parent.w, ml.snap_up(need_w))
            parent.h = max(parent.h, ml.snap_up(need_h))

    # Absolute positions again, from the top down (boxes are listed parents first).
    for b in lay.boxes:
        h = holder(b)
        c = boxes.get(h) if h else None
        if c is None:
            b.ax, b.ay = b.x, b.y
        elif b.parent:
            b.ax, b.ay = c.ax + b.x, c.ay + b.y
        else:                              # a detail card: absolute again
            b.ax, b.ay = c.ax + b.x, c.ay + b.y
            b.x, b.y = b.ax, b.ay
    def styled(saved):
        if not text_fn:
            return dict(saved)
        kept = redact_style(";".join(f"{k}={v}" for k, v in saved.items()), text_fn)
        return parse_style(kept)
    for b in lay.boxes:
        if b.id in styles:
            b.hints["style"] = styled(styles[b.id])

    # Section titles above the detail cards follow them.
    for t in lay.texts:
        if t.style != "strip":
            continue
        _, vpc, layer = t.id.split(":", 2) if t.id.count(":") >= 2 else ("", "", "")
        band = [b for b in lay.boxes if b.layer == layer and b.hints.get("container") == vpc]
        c = boxes.get(vpc)
        if band and c is not None:
            t.x, t.y = c.ax + PAD, min(b.ay for b in band) - 30
            t.w = max(c.w - 2 * PAD, 100)

    # Lines: remembered routes where they were moved by hand, the rest routed again.
    changed = bool(nodes)
    reroute = []
    for lk in lay.links:
        if lk.id in styles:
            lk.hints["style"] = styled(styles[lk.id])
        rec = edges.get(lk.id)
        if rec and rec.get("pinned"):
            lk.points = [(float(x), float(y)) for x, y in rec.get("points", [])]
            route = rec.get("route") or {}
            try:
                lk.exit = (float(route["exitX"]), float(route["exitY"])) if "exitX" in route else lk.exit
                lk.entry = (float(route["entryX"]), float(route["entryY"])) if "entryX" in route else lk.entry
            except (KeyError, ValueError):
                pass
            lk.hints["pinned"] = True
        elif changed:
            lk.exit = lk.entry = None
            lk.points = []
            reroute.append(lk)
    if reroute:
        ml._route_links(lay.boxes, None, reroute)

    # Hand-drawn cells, with redacted text and hashed IDs in a redacted export.
    lay.extra = [_transform_extra(x, id_fn, text_fn) for x in sec.get("extra", [])]
    lay.extra = [x for x in lay.extra if x]

    # The legend and footnote go below everything again, and the page fits it all.
    bottom = max([b.ay + b.h for b in lay.boxes] + [_extra_bottom(lay.extra)] + [0])
    right = max([b.ax + b.w for b in lay.boxes] + [_extra_right(lay.extra)] + [600])
    tops = [e.y for e in lay.legend] + [t.y for t in lay.texts if t.style == "footnote"]
    if tops:
        delta = ml.snap_up(bottom + 40) - min(tops)
        for e in lay.legend:
            e.y += delta
        for t in lay.texts:
            if t.style == "footnote":
                t.y += delta
                t.w = max(t.w, right)
    foot = [t for t in lay.texts if t.style == "footnote"]
    end = max([t.y + t.h for t in foot] + [e.y + 30 for e in lay.legend] + [bottom])
    lay.width = ml.snap_up(max(right, 600))
    lay.height = ml.snap_up(end)
    return lay


def _transform_extra(raw, id_fn=None, text_fn=None):
    if not id_fn and not text_fn:
        return raw
    try:
        el = ET.fromstring(raw)
    except ET.ParseError:
        return ""
    cell = el if el.tag == "mxCell" else el.find("mxCell")
    if id_fn:
        if el.get("id"):
            el.set("id", id_fn(el.get("id")))
        if cell is not None:
            for attr in ("parent", "source", "target"):
                v = cell.get(attr)
                if v and v not in LAYER_IDS.values():
                    cell.set(attr, id_fn(v))
    if text_fn:
        keep = {"id", "placeholders"}
        for attr, value in list(el.attrib.items()):
            if attr not in keep and el is not cell:
                el.set(attr, text_fn(value))
        if cell is not None and cell.get("value"):
            cell.set("value", text_fn(cell.get("value")))
        if cell is not None and cell.get("style"):
            cell.set("style", redact_style(cell.get("style"), text_fn))
    return ET.tostring(el, encoding="unicode")


# Style keys that can carry a picture or an address. A redacted export leaves them out:
# a picture can't be checked for what it shows.
_STYLE_LINKS = {"image", "imagesrc", "link", "href", "url"}


def redact_style(style, text_fn) -> str:
    """A draw.io style for a redacted export: picture and link keys are dropped, and so
    is any value that redaction would change (an account ID in a note's style, say)."""
    keep = []
    for part in str(style or "").split(";"):
        if not part:
            continue
        key, _, value = part.partition("=")
        if key.strip().lower() in _STYLE_LINKS or "://" in value or value.startswith("data:"):
            continue
        if value and text_fn(value) != value:
            continue
        keep.append(part)
    return ";".join(keep) + (";" if keep else "")


def _extra_geo(raw):
    try:
        el = ET.fromstring(raw)
    except ET.ParseError:
        return None
    cell = el if el.tag == "mxCell" else el.find("mxCell")
    if cell is None or cell.get("parent") not in LAYER_IDS.values():
        return None
    geo = cell.find("mxGeometry")
    if geo is None or cell.get("vertex") != "1":
        return None
    try:
        return tuple(coord(geo.get(k), size=k in ("width", "height")) - (MARGIN if k in ("x", "y") else 0)
                     for k in ("x", "y", "width", "height"))
    except ValueError:
        return None


def _extra_bottom(extra):
    geos = [g for g in (_extra_geo(x) for x in extra) if g]
    return max([g[1] + g[3] for g in geos] + [0])


def _extra_right(extra):
    geos = [g for g in (_extra_geo(x) for x in extra) if g]
    return max([g[0] + g[2] for g in geos] + [0])


__all__ = ["apply", "remember", "load", "save", "sidecar_path", "tidy", "reset", "reset_file", "summary_of",
           "mark_seen", "changed_outside", "points_text"]
