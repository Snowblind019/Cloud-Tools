"""Cloud Map's command line, and the entry points the window will use later.

    awskit map scan    scan a live AWS environment into a snapshot
    awskit map tf      read Terraform state or plans into a snapshot
    awskit map export  draw a snapshot as a .drawio, SVG or PNG file
    awskit map edit    open a map in the offline draw.io editor, keeping the layout
    awskit map remember  keep the layout of a .drawio edited in draw.io
    awskit map layout  show, tidy up or reset a snapshot's saved layout
    awskit map design  new, check, build or edit a design that becomes Terraform
    awskit map         scan the current profile and draw it in one step

Scanning and drawing are separate, so one scan can be drawn many ways.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import mapmodel as mm
from .common import CONFIG_DIR, AuthError, color, load_config, write_atomic

MAP_DIR = CONFIG_DIR / "cloud-map"
LABELS_FILE = MAP_DIR / "labels.json"
KEY_FILE = MAP_DIR / "redact.key"


def err(msg):
    print(color(msg, "red", sys.stderr.isatty()), file=sys.stderr)


def note(msg):
    print(color("Note: " + msg, "yellow", sys.stderr.isatty()), file=sys.stderr)


def split_list(values) -> list:
    out = []
    for v in values or []:
        out += [x.strip() for x in str(v).split(",") if x.strip()]
    return out


# =================================================================== settings

def load_labels(extra=None) -> dict:
    """Caption overrides, keyed by node ID. A value is either the caption, or an object
    with caption and title. The viewer will write edits back to this file."""
    labels = {}
    for path in [LABELS_FILE] + ([Path(extra)] if extra else []):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            if extra and str(path) == str(extra):
                raise ValueError(f"Labels file not found: {extra}") from None
            continue
        except (OSError, ValueError) as exc:
            raise ValueError(f"Couldn't read labels file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path} should be a JSON object keyed by node ID.")
        labels.update({str(k): v for k, v in data.items() if isinstance(v, (str, dict))})
    return labels


_key_lock = threading.Lock()


def _read_key():
    """The saved key, or None when there isn't one yet."""
    try:
        data = KEY_FILE.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError(f"Couldn't read the redaction key {KEY_FILE}: {exc}") from exc
    try:
        key = bytes.fromhex(data)
    except ValueError:
        key = b""
    if len(key) < 32:
        raise ValueError(f"The redaction key {KEY_FILE} is damaged. Delete it and a new one is "
                         "made, but maps redacted with the old key can't be read back after that.")
    return key


def redact_key() -> bytes:
    """The key for redacted cell IDs, made once and kept, so redacted IDs stay the same
    between exports. A plain hash isn't enough: 12-digit account IDs can be guessed.
    A new key is created readable by you only, and never replaces one that's there."""
    with _key_lock:
        key = _read_key()
        if key is not None:
            return key
        key = secrets.token_bytes(32)
        MAP_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".redact-", suffix=".tmp", dir=str(MAP_DIR))
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(key.hex() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, KEY_FILE)           # fails if another process just made one
            except FileExistsError:
                pass
            except OSError:
                if not KEY_FILE.exists():        # a file system without hard links
                    os.replace(tmp, KEY_FILE)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return _read_key()


def redactors(extra_words=()):
    """(text_fn, id_fn) using your PII Redact settings and the saved key. extra_words are
    redacted wherever they appear, on top of your always-redact list."""
    from . import redact
    opts = redact.options_from(redact.load_config())
    opts.always = list(opts.always) + [w for w in extra_words if w and len(w) >= 3]
    key = redact_key()

    def text_fn(text):
        return redact.redact(str(text), opts)[0]

    def id_fn(cell_id):
        return "c" + hmac.new(key, str(cell_id).encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    return text_fn, id_fn


# =================================================================== entry points

FORMATS = ("drawio", "svg", "png")


def make_layout(snap, map_type="access", show=None, accounts=(), regions=(), vpcs=(),
                redacted=False, service_linked=False, default_vpcs=False, labels=None,
                memory=None, snapshot_name=""):
    """Snapshot to a Layout, the one thing every output draws from: the .drawio writer,
    the viewer page, SVG and PNG. memory is the layout memory (a loaded sidecar), so
    whatever was moved in draw.io stays where it was put."""
    from . import maplayout, maplayoutmem
    opts = maplayout.Options(map_type, show, list(accounts), list(regions), list(vpcs),
                             service_linked, default_vpcs, labels or {})
    view = maplayout.build_view(snap, opts)
    view.warnings = list(snap.warnings)
    text_fn = id_fn = None
    if redacted:
        # Bucket names show up as plain titles, where PII Redact has no "bucket" setting
        # name to go on, so every bucket name in the map is added to the list.
        words = sorted({n.name for n in snap.nodes.values() if n.kind == "bucket" and n.name})
        text_fn, id_fn = redactors(words)
        scope = snap.scope or {}
        hide = [p for p in scope.get("profiles", []) if p and p != "default"]
        hide += [Path(str(i)).name for i in scope.get("inputs", []) if i]
        view = maplayout.redact_view(view, text_fn, id_fn, hide=hide)
    lay = maplayout.layout(view)
    if memory:
        sec = maplayoutmem.section(memory, map_type, create=False)
        lay = maplayoutmem.apply(lay, sec, id_fn, text_fn)
    lay.meta = maplayoutmem.meta_for(
        {"map_type": map_type, "show": opts.show, "accounts": list(accounts),
         "regions": list(regions), "vpcs": list(vpcs), "service_linked": service_linked,
         "default_vpcs": default_vpcs}, redacted, snapshot_name, id_fn)
    return lay


def render(lay, fmt="drawio", theme_name="dark"):
    """A Layout as file contents: str for .drawio, bytes for SVG and PNG (2x)."""
    if fmt == "drawio":
        from . import mapdrawio
        meta = dict(getattr(lay, "meta", None) or {})
        if meta:
            meta["awskit_theme"] = theme_name
        return mapdrawio.write(lay, theme_name, meta=meta)
    from . import maprender
    if fmt == "svg":
        return maprender.render_svg(lay, theme_name)
    if fmt == "png":
        return maprender.render_png(lay, theme_name, scale=2.0)
    raise ValueError(f"Format has to be one of {', '.join(FORMATS)}.")


def format_of(path, fmt=None) -> str:
    """The format asked for, or the one the file name ends in, or drawio."""
    if fmt:
        return fmt
    ext = Path(str(path or "")).suffix.lower().lstrip(".")
    return ext if ext in FORMATS else "drawio"


def write_file(path, data):
    path = Path(path)
    write_atomic(path, data)
    return path


def export(snap, map_type="access", theme_name="dark", show=None, accounts=(), regions=(),
           vpcs=(), redacted=False, service_linked=False, default_vpcs=False, labels=None,
           fmt="drawio", memory=None, snapshot_name=""):
    """Snapshot to file contents. Returns (contents, layout): .drawio text, or SVG or PNG
    bytes."""
    lay = make_layout(snap, map_type, show, accounts, regions, vpcs, redacted,
                      service_linked, default_vpcs, labels, memory, snapshot_name)
    return render(lay, fmt, theme_name), lay


def memory_for(snapshot_path):
    """The layout memory next to a snapshot, or None if there isn't one."""
    from . import maplayoutmem
    if not snapshot_path:
        return None
    path = maplayoutmem.sidecar_path(snapshot_path)
    return maplayoutmem.load(path) if path.exists() else None


def work_file(snapshot_path, map_type) -> Path:
    """The .drawio file the page edits: <name>-<type>.drawio next to the snapshot."""
    return Path(snapshot_path).with_name(f"{stem_of(snapshot_path)}-{map_type}.drawio")


def prepare_edit(snap, snapshot_path, map_type="access", theme_name="dark", labels=None,
                 **opts):
    """Write the working .drawio for the editor, with the saved layout. If the file was
    changed outside AWS Kit since (draw.io desktop), its layout is read in first.
    Returns (path, layout, what was read in or None)."""
    from . import mapeditor, maplayoutmem
    path = work_file(snapshot_path, map_type)
    side = maplayoutmem.sidecar_path(snapshot_path)
    pulled = None
    if path.exists() and maplayoutmem.changed_outside(maplayoutmem.load(side), map_type, path):
        try:
            pulled = maplayoutmem.remember(path, snap, side)
        except (ValueError, OSError):
            pulled = None          # not readable: it's rewritten below
    memory = maplayoutmem.load(side) if side.exists() else None
    lay = make_layout(snap, map_type, labels=labels if labels is not None else load_labels(),
                      memory=memory, snapshot_name=Path(snapshot_path).name, **opts)
    text = render(lay, "drawio", theme_name)
    mapeditor.write_atomic(path, text)
    memory = memory or maplayoutmem.empty()
    maplayoutmem.mark_seen(memory, map_type, path, text)
    maplayoutmem.save(memory, side)
    return path, lay, pulled


def scan(profiles, regions=None, access=True, network=True, progress=None, cancel=None):
    from . import mapscan
    return mapscan.scan(profiles, regions, access=access, network=network,
                        known_accounts=load_config().get("known_accounts") or [],
                        progress=progress, cancel=cancel)


def read_terraform(paths, plan=False, log=None):
    from . import maptf
    return maptf.read(paths, plan=plan, log=log,
                      known_accounts=load_config().get("known_accounts") or [])


def default_snapshot_name() -> str:
    return "cloud-map" + mm.SUFFIX


def stem_of(path) -> str:
    name = Path(path).name
    if name.endswith(mm.SUFFIX):
        return name[: -len(mm.SUFFIX)]
    return Path(path).stem


# =================================================================== commands

def _profiles(args) -> list:
    from . import profiles as prof
    if getattr(args, "all_profiles", False):
        return prof.profile_names()
    picked = split_list(getattr(args, "profile", None))
    return picked or [prof.current_profile()]


def _show(args, map_type):
    from . import maplayout
    if not args.show:
        return None
    wanted = set(split_list(args.show))
    if "all" in wanted:
        return set(maplayout.SHOW_CHOICES)
    if "none" in wanted:
        return set()
    return wanted


def _progress(enabled):
    from .cli import progress_printer
    return progress_printer(enabled)


def _summary(snap):
    kinds = {}
    for n in snap.nodes.values():
        kinds[n.kind] = kinds.get(n.kind, 0) + 1
    flagged = sum(1 for n in snap.nodes.values() if n.flags) + \
        sum(1 for e in snap.edges.values() if e.flags)
    accounts = kinds.get("account", 0)
    parts = [mm.plural(accounts, "account")]
    for k, word in (("role", "role"), ("vpc", "VPC"), ("subnet", "subnet"),
                    ("instance", "instance")):
        if kinds.get(k):
            parts.append(mm.plural(kinds[k], word))
    text = ", ".join(parts)
    if flagged:
        text += f", {mm.plural(flagged, 'flagged problem')}"
    return text


def cmd_scan(args) -> int:
    parts_access = args.access or not (args.access or args.network)
    parts_network = args.network or not (args.access or args.network)
    profiles = _profiles(args)
    show = _progress(sys.stderr.isatty() and not args.quiet)
    snap = scan(profiles, split_list(args.region) or None, parts_access, parts_network,
                progress=show)
    if not snap.nodes:
        for w in snap.warnings:
            err(w)
        return 1
    out = args.output or default_snapshot_name()
    snap.save(out)
    print(f"Wrote {out}: {_summary(snap)}")
    for w in snap.warnings:
        note(w)
    return 0


def cmd_tf(args) -> int:
    from . import maptf
    try:
        snap = read_terraform(args.path, plan=args.plan,
                              log=lambda m: print(color(m, "dim", sys.stderr.isatty()),
                                                  file=sys.stderr))
    except maptf.TfError as exc:
        err(str(exc))
        return 1
    out = args.output or (stem_of(args.path[0]) + mm.SUFFIX)
    snap.save(out)
    print(f"Wrote {out}: {_summary(snap)}")
    for w in snap.warnings:
        note(w)
    return 0


def _write_export(snap, args, map_type, out, fmt="drawio", snapshot_path=None) -> int:
    from . import maplayout
    memory = None if getattr(args, "no_memory", False) else memory_for(snapshot_path)
    try:
        labels = load_labels(getattr(args, "labels", None))
        data, lay = export(snap, map_type, args.theme, _show(args, map_type),
                           split_list(getattr(args, "accounts", None)),
                           split_list(getattr(args, "regions", None)),
                           split_list(getattr(args, "vpcs", None)), args.redact,
                           getattr(args, "service_linked", False),
                           getattr(args, "default_vpcs", False), labels, fmt, memory,
                           Path(snapshot_path).name if snapshot_path else "")
    except (maplayout.LayoutError, ValueError) as exc:
        err(str(exc))
        return 1
    except ImportError as exc:
        err(f"SVG and PNG need cairo for Python ({exc}). Fedora: sudo dnf install "
            "python3-cairo. Debian/Ubuntu: sudo apt install python3-cairo")
        return 1
    write_file(out, data)
    cards = sum(1 for b in lay.boxes if b.role != "container")
    flagged = sum(1 for b in lay.boxes if b.flags) + sum(1 for lk in lay.links if lk.flags)
    text = (f"Wrote {out}: {map_type} map, {mm.plural(cards, 'resource')}, "
            f"{mm.plural(len(lay.links), 'line')}")
    if flagged:
        text += f", {flagged} marked in red"
    if args.redact:
        text += ", redacted"
    if memory and any(b.hints.get("remembered") for b in lay.boxes):
        text += ", with your saved layout"
    print(text)
    return 0


def cmd_export(args) -> int:
    try:
        snap = mm.Snapshot.load(args.snapshot)
    except mm.SnapshotError as exc:
        err(str(exc))
        return 1
    fmt = format_of(args.output, args.format)
    out = args.output or f"{stem_of(args.snapshot)}-{args.type}.{fmt}"
    return _write_export(snap, args, args.type, out, fmt, args.snapshot)


def cmd_onestep(args) -> int:
    map_type = args.one_type
    profiles = _profiles(args)
    show = _progress(sys.stderr.isatty() and not args.quiet)
    snap = scan(profiles, split_list(args.region) or None, map_type in ("access", "combined"),
                map_type in ("network", "combined"), progress=show)
    if not snap.nodes:
        for w in snap.warnings:
            err(w)
        return 1
    if args.save:
        snap.save(args.save)
        print(f"Wrote {args.save}: {_summary(snap)}")
    for w in snap.warnings:
        note(w)
    args.theme = args.one_theme
    fmt = format_of(args.output, args.one_format)
    out = args.output or f"cloud-map-{map_type}.{fmt}"
    return _write_export(snap, args, map_type, out, fmt, args.save)


def cmd_remember(args) -> int:
    """Read a .drawio edited outside AWS Kit back into the layout memory."""
    from . import maplayoutmem
    drawio = Path(args.drawio)
    snap_path = args.snapshot
    if not snap_path:
        try:
            diagram, cells = maplayoutmem.read_cells(drawio.read_text(encoding="utf-8"))
            name = maplayoutmem.meta_of(diagram, cells).get("awskit_snapshot", "")
        except (OSError, ValueError) as exc:
            err(f"Couldn't read {drawio}: {exc}")
            return 1
        # Only a plain file name next to the map: the name comes from inside the file.
        safe = name and Path(name).name == name and name not in (".", "..")
        snap_path = str(drawio.with_name(name)) if safe else ""
        if not snap_path or not Path(snap_path).exists():
            err("Give the snapshot this map was drawn from with --snapshot.")
            return 1
    try:
        snap = mm.Snapshot.load(snap_path)
        got = maplayoutmem.remember(drawio, snap, maplayoutmem.sidecar_path(snap_path))
    except (mm.SnapshotError, ValueError, OSError) as exc:
        err(str(exc))
        return 1
    print(f"Remembered the {got['map_type']} layout in "
          f"{maplayoutmem.sidecar_path(snap_path).name}: {mm.plural(got['boxes'], 'box', 'boxes')}"
          f" ({got['moved']} moved by hand), {mm.plural(got['edges'], 'line')} rerouted, "
          f"{mm.plural(got['styles'], 'style change')}, {mm.plural(got['captions'], 'caption')}, "
          f"{mm.plural(got['extra'], 'shape')} of your own")
    return 0


def cmd_edit(args) -> int:
    """Open a map in the offline draw.io editor outside the window, and keep its layout
    after every save, the way the page does on Windows."""
    import threading
    from . import mapeditor, maplayout, maplayoutmem
    try:
        snap = mm.Snapshot.load(args.snapshot)
        mapeditor.check_drawio()
        labels = load_labels(args.labels)
        path, _, pulled = prepare_edit(
            snap, args.snapshot, args.type, args.theme, labels, show=_show(args, args.type),
            accounts=split_list(args.accounts), regions=split_list(args.regions),
            vpcs=split_list(args.vpcs), service_linked=args.service_linked,
            default_vpcs=args.default_vpcs)
    except (mm.SnapshotError, mapeditor.BridgeError, maplayout.LayoutError, ValueError,
            OSError) as exc:
        err(str(exc))
        return 1
    if pulled:
        print("Read in the layout saved outside AWS Kit first.")
    side = maplayoutmem.sidecar_path(args.snapshot)
    target = args.open or mapeditor.choose_target(
        (load_config().get("cloud_map") or {}).get("editor", ""), mapeditor.available_targets())
    if target == "desktop":
        try:
            mapeditor.open_in_desktop(path)
        except (mapeditor.BridgeError, OSError) as exc:
            err(str(exc))
            return 1
        print(f"Opened {path} in draw.io desktop. After saving it there, keep the layout with:\n"
              f"  awskit map remember {path}")
        return 0
    finished = threading.Event()

    def saved(p):
        got = maplayoutmem.remember(p, snap, side)
        print(f"Saved. Kept in {side.name}: {got['moved']} moved, "
              f"{mm.plural(got['styles'], 'style change')}, {mm.plural(got['captions'], 'caption')}, "
              f"{mm.plural(got['extra'], 'shape')} of your own", flush=True)
    bridge = mapeditor.Bridge(path, title=f"{stem_of(args.snapshot)} {args.type} map",
                              theme=args.theme, on_save=saved,
                              on_exit=lambda info: finished.set())
    url = bridge.start()
    try:
        if target == "none":
            print(f"The editor is at {url}")
        else:
            used, _ = mapeditor.open_outside(target, url, path)
            print(f"Opened the editor in the {mapeditor.TARGETS[used].lower()}.")
        print("Each save there is kept. Close the window, or press Ctrl+C, when you're done.",
              flush=True)
        while not finished.wait(0.5):
            pass
    except mapeditor.BridgeError as exc:
        err(f"{exc} Open {url} yourself, or press Ctrl+C.")
        try:
            while not finished.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
    except KeyboardInterrupt:
        print(file=sys.stderr)
    finally:
        bridge.stop()
    return 0


def _print_problems(design, problems, region=None):
    from . import mapdesign
    where = region or design.region or "no region"
    print(f"{design.path.name}, {where}: {mapdesign.summary(problems)}")
    for p in problems:
        tone = "red" if p.severity == "error" else "yellow"
        print("  " + color(f"{p.severity:<8}", tone, sys.stdout.isatty()) + p.message)


def cmd_design(args) -> int:
    from . import mapdesign
    action = args.design_action
    if action == "new":
        target = Path(args.output) if args.output else Path(args.name)
        if target.is_dir():
            target = target / args.name
        region = args.region or _default_region()
        try:
            path = mapdesign.new_design(target, args.name if not args.output else None, region,
                                        args.theme, overwrite=args.force)
        except (mapdesign.DesignError, OSError) as exc:
            err(str(exc))
            return 1
        print(f"Wrote {path}, a new design for {region}. Open it with: awskit map design edit {path}")
        return 0
    try:
        design = mapdesign.read(args.design)
    except mapdesign.DesignError as exc:
        err(str(exc))
        return 1
    if action == "check":
        problems = mapdesign.check(design, args.region)
        _print_problems(design, problems, args.region)
        return 1 if mapdesign.errors(problems) else 0
    if action == "build":
        problems = mapdesign.check(design, args.region)
        if mapdesign.errors(problems):
            _print_problems(design, problems, args.region)
            err("Nothing was written. Fix the errors in the design and build again.")
            return 1
        log = (lambda m: print(color(m, "dim", sys.stderr.isatty()), file=sys.stderr))
        try:
            result = mapdesign.build(design, args.output, args.region, fmt=not args.no_fmt,
                                     validate=not args.no_validate, log=log)
        except (mapdesign.BuildError, mapdesign.DesignError, OSError) as exc:
            err(str(exc))
            return 1
        for p in problems:
            note(p.message)
        print(f"Wrote {len(result.files)} files to {result.folder}:")
        for f in result.files:
            print(f"  {f}")
        for f in result.removed:
            print(f"  removed {f}, which the design doesn't make any more")
        if result.formatted:
            print(result.formatted)
        failed = False
        for cmd, ok, text in result.checks:
            if ok is None:
                note(text)
                continue
            print(f"{cmd}: {'passed' if ok else 'failed'}")
            if not ok:
                failed = True
                print("  " + text.replace("\n", "\n  "))
        print("AWS Kit never runs apply. To see what it would build: cd "
              f"{result.folder / 'examples' / 'basic'} && terraform plan")
        return 1 if failed else 0
    if action == "edit":
        return _edit_design(design, args)
    return 1


def _default_region() -> str:
    from . import mapdesign
    try:
        import botocore.session
        region = botocore.session.get_session().get_config_variable("region")
        if region:
            return region
    except Exception:  # noqa: BLE001 - only a default
        pass
    return mapdesign.DEFAULT_REGION


def _edit_design(design, args) -> int:
    """The design in the offline draw.io editor with the designer library, checked after
    every save."""
    import threading
    from . import mapdesign, mapeditor
    try:
        mapeditor.check_drawio()
    except mapeditor.BridgeError as exc:
        err(str(exc))
        return 1
    theme_name = design.theme if design.theme in ("dark", "light") else "dark"
    target = args.open or mapeditor.choose_target(
        (load_config().get("cloud_map") or {}).get("editor", ""), mapeditor.available_targets())
    if target == "desktop":
        try:
            mapeditor.open_in_desktop(design.path)
        except (mapeditor.BridgeError, OSError) as exc:
            err(str(exc))
            return 1
        print(f"Opened {design.path} in draw.io desktop. Its shape library is "
              f"{mapdesign.library_path(theme_name)}: add it with File, Open Library. "
              f"Check the design with: awskit map design check {design.path}")
        return 0
    finished = threading.Event()

    def saved(p):
        d = mapdesign.read(p)
        _print_problems(d, mapdesign.check(d))
    bridge = mapeditor.Bridge(design.path, title=f"{design.name} design", theme=theme_name,
                              on_save=saved, on_exit=lambda info: finished.set(),
                              library=mapdesign.library_path(theme_name))
    url = bridge.start()
    try:
        if target == "none":
            print(f"The editor is at {url}")
        else:
            used, _ = mapeditor.open_outside(target, url, design.path)
            print(f"Opened the design in the {mapeditor.TARGETS[used].lower()}.")
        print("Each save is checked here. Close the window, or press Ctrl+C, when you're done.",
              flush=True)
        while not finished.wait(0.5):
            pass
    except mapeditor.BridgeError as exc:
        err(f"{exc} Open {url} yourself, or press Ctrl+C.")
        try:
            while not finished.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
    except KeyboardInterrupt:
        print(file=sys.stderr)
    finally:
        bridge.stop()
    return 0


def cmd_layout(args) -> int:
    from . import maplayoutmem
    path = maplayoutmem.sidecar_path(args.snapshot)
    memory = maplayoutmem.load(path)
    if args.reset:
        gone = maplayoutmem.reset_file(path, args.type)
        print(f"Cleared the saved {args.type} layout." if gone else
              f"There was no saved {args.type} layout.")
        return 0
    if args.tidy:
        n = maplayoutmem.tidy(memory, args.type)
        maplayoutmem.save(memory, path)
        print(f"Tidied up: {mm.plural(n, 'box', 'boxes')} go back to the automatic layout. "
              "Boxes you moved by hand stay put.")
        return 0
    got = maplayoutmem.summary_of(memory, args.type)
    print(f"{path.name}, {args.type} map: {mm.plural(got['boxes'], 'box', 'boxes')} remembered, "
          f"{got['pinned']} moved by hand, {mm.plural(got['edges'], 'line')} rerouted, "
          f"{mm.plural(got['styles'], 'style change')}, "
          f"{mm.plural(got['extra'], 'shape')} of your own")
    return 0


# =================================================================== parser

def build_parser(prog="awskit map") -> argparse.ArgumentParser:
    from . import maplayout
    p = argparse.ArgumentParser(
        prog=prog,
        description="Draw an AWS environment as a draw.io diagram: an access map (org, "
                    "accounts, Identity Center, roles, trust) or a network map (VPCs, "
                    "subnets, routing). With no command, scans the current profile and "
                    "draws it in one step.",
        epilog="Commands: scan, tf, export, edit, remember, layout, design. Each has its own --help, like: "
               f"{prog} export --help")
    sub = p.add_subparsers(dest="action", metavar="COMMAND")

    def add_profiles(sp):
        sp.add_argument("-p", "--profile", "--profiles", action="append", metavar="NAME",
                        help="AWS profile to scan. Repeat it or use commas for several. "
                             "Defaults to the one picked in awskit.")
        sp.add_argument("--all-profiles", action="store_true",
                        help="Scan every profile in ~/.aws/config")
        sp.add_argument("-r", "--region", "--regions", action="append", metavar="REGION",
                        help="Only these regions (repeat or use commas). Defaults to every "
                             "enabled region, or the regions in your settings.")
        sp.add_argument("-q", "--quiet", action="store_true", help="No progress line")

    def add_drawing(sp, dest_prefix=""):
        sp.add_argument("--theme", dest=dest_prefix + "theme", default="dark",
                        choices=("dark", "light"), help="Colors (default dark)")
        sp.add_argument("--format", dest=dest_prefix + "format", choices=FORMATS,
                        help="drawio, svg or png (2x). Defaults to the -o file's extension, "
                             "or drawio.")
        sp.add_argument("--show", action="append", metavar="LAYERS",
                        help="Detail layers to include: " + ", ".join(maplayout.SHOW_CHOICES) +
                             ", all or none. Defaults depend on the map type.")
        sp.add_argument("--redact", action="store_true",
                        help="Run every label, tooltip and data attribute through PII Redact, "
                             "and replace cell IDs with keyed hashes")
        sp.add_argument("--labels", metavar="FILE",
                        help="Extra captions file, on top of ~/.config/awskit/cloud-map/labels.json")
        sp.add_argument("--service-linked", action="store_true",
                        help="Include service-linked roles (hidden by default)")
        sp.add_argument("--default-vpcs", action="store_true",
                        help="Include default VPCs that have nothing in them")

    s = sub.add_parser("scan", help="Scan a live AWS environment into a snapshot",
                       description="Reads Organizations, IAM Identity Center, IAM, CloudTrail, "
                                   "budgets and the network. Read-only. Parts the profile "
                                   "can't read are skipped and listed at the end.")
    add_profiles(s)
    s.add_argument("--access", action="store_true", help="Only the access data")
    s.add_argument("--network", action="store_true", help="Only the network data")
    s.add_argument("-o", "--output", metavar="FILE",
                   help=f"Snapshot to write (default {default_snapshot_name()})")
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser("tf", help="Read Terraform state or a plan into a snapshot",
                       description="Takes `terraform show -json` output, a .tfstate file, a "
                                   "saved plan, or a folder. Several inputs are drawn as one "
                                   "map. Never runs apply.")
    t.add_argument("path", nargs="+", help="State or plan JSON, .tfstate, saved plan, or folder")
    t.add_argument("--plan", action="store_true",
                   help="For a folder, run terraform plan and draw that instead of the "
                        "current state")
    t.add_argument("-o", "--output", metavar="FILE",
                   help="Snapshot to write (default: named after the first input)")
    t.set_defaults(func=cmd_tf)

    e = sub.add_parser("export", help="Draw a snapshot as a .drawio, SVG or PNG file")
    e.add_argument("snapshot", help="A .cloudmap.json snapshot")
    e.add_argument("--type", default="access", choices=maplayout.MAP_TYPES,
                   help="access, network or combined (default access)")
    add_drawing(e)
    e.add_argument("--accounts", action="append", metavar="IDS",
                   help="Only these accounts, by ID or name (commas or repeat)")
    e.add_argument("--regions", "--region", action="append", metavar="REGIONS",
                   help="Only these regions")
    e.add_argument("--vpcs", action="append", metavar="IDS", help="Only these VPCs, by ID or name")
    e.add_argument("-o", "--output", metavar="FILE",
                   help="File to write (default: SNAPSHOT-TYPE.drawio, or .svg or .png)")
    e.add_argument("--no-memory", action="store_true",
                   help="Ignore the saved layout (SNAPSHOT's .layout.json) and draw it fresh")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("remember", help="Keep the layout of a .drawio you edited in draw.io",
                       description="Reads a .drawio drawn by AWS Kit and edited in draw.io, and "
                                   "saves where things were moved, style changes, new captions "
                                   "and shapes you drew, for the next export. The page does "
                                   "this by itself after every save.")
    r.add_argument("drawio", help="The edited .drawio file")
    r.add_argument("--snapshot", metavar="FILE",
                   help="The snapshot it was drawn from (default: the one named in the file, "
                        "next to it)")
    r.set_defaults(func=cmd_remember)

    ed = sub.add_parser("edit", help="Open a map in the offline draw.io editor, keeping the layout",
                        description="Writes the map with its saved layout to SNAPSHOT-TYPE.drawio "
                                    "next to the snapshot, opens it in the draw.io editor AWS Kit "
                                    "downloaded (an Edge app window, the default browser or draw.io "
                                    "desktop), and keeps the layout after every save. Fully offline.")
    ed.add_argument("snapshot", help="A .cloudmap.json snapshot")
    ed.add_argument("--type", default="access", choices=maplayout.MAP_TYPES,
                    help="access, network or combined (default access)")
    ed.add_argument("--theme", default="dark", choices=("dark", "light"), help="Colors (default dark)")
    ed.add_argument("--open", choices=("edge", "browser", "desktop", "none"),
                    help="What to open it in. Defaults to the page's setting, or the best one "
                         "here. none just prints the address.")
    ed.add_argument("--show", action="append", metavar="LAYERS", help="Detail layers, as for export")
    ed.add_argument("--labels", metavar="FILE", help="Extra captions file")
    ed.add_argument("--accounts", action="append", metavar="IDS", help="Only these accounts")
    ed.add_argument("--regions", "--region", action="append", metavar="REGIONS",
                    help="Only these regions")
    ed.add_argument("--vpcs", action="append", metavar="IDS", help="Only these VPCs")
    ed.add_argument("--service-linked", action="store_true", help="Include service-linked roles")
    ed.add_argument("--default-vpcs", action="store_true",
                    help="Include default VPCs that have nothing in them")
    ed.set_defaults(func=cmd_edit)

    de = sub.add_parser("design", help="Draw a network in draw.io and get Terraform for it",
                        description="The designer: a design is a .drawio file drawn with the AWS "
                                    "Kit Designer library. check validates it, build writes a "
                                    "Terraform module and an example into DESIGN-tf/. It never "
                                    "runs apply.")
    dsub = de.add_subparsers(dest="design_action", metavar="ACTION", required=True)
    dn = dsub.add_parser("new", help="Create a design from the template")
    dn.add_argument("name", help="The design's name, which is also its file name")
    dn.add_argument("--region", help="The region it's for (default: your AWS config's, or us-east-1)")
    dn.add_argument("--theme", default="dark", choices=("dark", "light"), help="Colors (default dark)")
    dn.add_argument("-o", "--output", metavar="PATH", help="Where to write it (default NAME.drawio here)")
    dn.add_argument("--force", action="store_true", help="Overwrite a file that's there")
    dc = dsub.add_parser("check", help="Validate a design and print its problems")
    dc.add_argument("design", help="A design .drawio file")
    dc.add_argument("--region", help="Check it for this region instead of the design's own")
    db = dsub.add_parser("build", help="Write Terraform from a design")
    db.add_argument("design", help="A design .drawio file")
    db.add_argument("-o", "--output", metavar="FOLDER",
                    help="Where to write it (default DESIGN-tf next to the design). Only an "
                         "empty folder, or one the designer made")
    db.add_argument("--region", help="Build it for this region instead of the design's own")
    db.add_argument("--no-validate", action="store_true",
                    help="Don't run terraform (or tofu) init and validate on the result")
    db.add_argument("--no-fmt", action="store_true", help="Don't run terraform fmt on the result")
    dd = dsub.add_parser("edit", help="Open a design in the offline draw.io editor")
    dd.add_argument("design", help="A design .drawio file")
    dd.add_argument("--open", choices=("edge", "browser", "desktop", "none"),
                    help="What to open it in, like awskit map edit")
    de.set_defaults(func=cmd_design)

    lo = sub.add_parser("layout", help="Show, tidy up or reset a snapshot's saved layout")
    lo.add_argument("snapshot", help="A .cloudmap.json snapshot")
    lo.add_argument("--type", default="access", choices=maplayout.MAP_TYPES,
                    help="Which map's layout (default access)")
    act = lo.add_mutually_exclusive_group()
    act.add_argument("--tidy", action="store_true",
                     help="Put everything you didn't move by hand back where the automatic "
                          "layout wants it")
    act.add_argument("--reset", action="store_true", help="Forget this map's layout")
    lo.set_defaults(func=cmd_layout)

    p.add_argument("--type", dest="one_type", default="access", choices=maplayout.MAP_TYPES,
                   help="One step: map type to scan and draw (default access)")
    add_drawing(p, "one_")
    p.add_argument("-p", "--profile", "--profiles", action="append", metavar="NAME",
                   help="One step: profile to scan (default the current one)")
    p.add_argument("--all-profiles", action="store_true", help="One step: scan every profile")
    p.add_argument("-r", "--region", "--regions", action="append", metavar="REGION",
                   help="One step: only these regions")
    p.add_argument("--save", metavar="SNAPSHOT", help="One step: also keep the snapshot")
    p.add_argument("-q", "--quiet", action="store_true", help="No progress line")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="One step: file to write (default cloud-map-TYPE.drawio)")
    return p


def main(argv=None, prog="awskit map") -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser(prog)
    args = parser.parse_args(argv)
    func = getattr(args, "func", None) or cmd_onestep
    try:
        return func(args) or 0
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except AuthError as exc:
        err(str(exc))
        return 1


def now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
