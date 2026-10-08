"""awskit command line. Running it with no arguments opens the window."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from .common import (APP_ID, APP_NAME, CONFIG_FILE, IMAGE_APP_ID, PICKER_APP_ID,
                     REDACT_APP_ID, REDACT_SETTINGS_APP_ID, SEVERITY_COLOR, SEVERITY_ORDER,
                     VERSION, AuthError, ClipboardError, color, load_config, money, notify,
                     parse_when, pii_redact, save_config, table_text, terminal_safe, to_markdown,
                     write_clipboard)

PAGES = ("redact", "image", "secrets", "sweep", "audit", "creds", "trail", "leastpriv", "plan",
         "drift", "policy", "scp", "profiles", "map")

# Tools that keep their command line in their own module. Each has
# register_cli(sub, add_profiles), which adds its subcommand and sets func.
CLI_MODULES = ("secretscan", "creds", "leastpriv", "drift", "scpcheck")


def err(msg):
    print(color(msg, "red", sys.stderr.isatty()), file=sys.stderr)


def stdin_has_data() -> bool:
    try:
        return not sys.stdin.isatty() and not sys.stdin.closed
    except (AttributeError, ValueError):
        return False


def resolve_profiles(args) -> list:
    from . import profiles as prof
    if getattr(args, "all_profiles", False):
        return prof.profile_names()
    if getattr(args, "profile", None):
        return args.profile
    return [prof.current_profile()]


def sev_colorizer(key, value):
    if key == "severity":
        return SEVERITY_COLOR.get(str(value), None)
    return None


def fail_exit(findings, threshold) -> int:
    if not threshold:
        return 0
    limit = SEVERITY_ORDER[threshold]
    return 2 if any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in findings) else 0


def progress_printer(enabled):
    lock = threading.Lock()

    def show(done, total, text):
        if not enabled:
            return
        with lock:
            line = f"\r  {done}/{total}  {text}"[:100]
            sys.stderr.write(line.ljust(100))
            sys.stderr.flush()
            if done == total:
                sys.stderr.write("\r" + " " * 100 + "\r")
    return show


def emit_text(text, args):
    if getattr(args, "redact", False):
        text = pii_redact(text)
    if getattr(args, "copy", False):
        try:
            write_clipboard(text)
            print("Copied to the clipboard.", file=sys.stderr)
        except ClipboardError as exc:
            err(str(exc))
    print(text, end="" if text.endswith("\n") else "\n")


# =================================================================== sweep

SWEEP_COLS = [("profile", "Profile"), ("region", "Region"), ("kind", "What"), ("id", "ID"),
              ("name", "Name"), ("state", "State"), ("cost", "Est/mo"), ("age", "Age"),
              ("action", "Teardown")]


def cmd_sweep(args) -> int:
    from . import sweep
    if args.install_timer is not None:
        return install_timer(args.install_timer, args)
    if args.remove_timer:
        return remove_timer()
    profiles = resolve_profiles(args)
    if args.notify and not args.profile and not args.all_profiles:
        profiles = load_config().get("timer_profiles") or profiles

    if args.spend:
        rc = 0
        for p in profiles:
            try:
                data = sweep.month_spend(p)
            except AuthError as exc:
                err(str(exc))
                rc = 1
                continue
            except Exception as exc:  # noqa: BLE001
                from .common import error_text
                err(f"{p or 'default'}: {error_text(exc, p)}")
                rc = 1
                continue
            print(color(f"{data['profile']}: {money(data['total'])} {data['unit']} so far this month "
                        f"(since {data['start']})", "bold"))
            for svc, amt in data["services"]:
                print(f"  {money(amt):>10}  {svc}")
        print(color("Each Cost Explorer request costs $0.01.", "dim"))
        return rc

    show = progress_printer(sys.stderr.isatty() and not args.quiet and not args.json)
    items, warnings = sweep.scan(profiles, args.region, args.kind, progress=show)

    if args.notify:
        return sweep_notify(items, warnings, profiles)

    if args.json:
        print(json.dumps({"items": [i.as_dict() for i in items], "warnings": warnings},
                         indent=2, default=str))
    else:
        if items:
            cols = SWEEP_COLS if len(profiles) > 1 else [c for c in SWEEP_COLS if c[0] != "profile"]
            print(table_text([i.row() for i in items], cols, max_width=44,
                             colorize=lambda k, v: "dim" if v in ("kept", "manual") else None))
            print()
        print(color(sweep.summary_line(items), "bold"))
        print(color("Prices are rough us-east-1 numbers. Run with --spend for the real bill so far.",
                    "dim"))
        for w in warnings:
            print(color("Note: " + w, "yellow"), file=sys.stderr)

    if args.teardown:
        return sweep_teardown(items, args)
    return 1 if warnings and not items else 0


def sweep_teardown(items, args) -> int:
    from . import sweep
    targets = [i for i in items if i.can_delete and not i.kept]
    manual = [i for i in items if not i.can_delete and not i.kept]
    if not targets:
        print("Nothing here can be deleted automatically.")
        return 0
    print()
    print(color(f"Teardown would remove {len(targets)} item(s), about "
                f"{money(sweep.total_monthly(targets))}/month:", "bold"))
    for i in targets:
        print(f"  {i.region:<15} {i.kind_label:<26} {i.id}  {i.name}")
    if manual:
        print(color(f"{len(manual)} item(s) need manual cleanup and won't be touched.", "dim"))
    if args.dry_run:
        print(color("Dry run, nothing deleted.", "yellow"))
        return 0
    if not sys.stdin.isatty():
        err("Teardown needs you at the keyboard to confirm. Run it in a terminal.")
        return 1
    answer = input(color("Type delete to go ahead: ", "red"))
    if answer.strip().lower() != "delete":
        print("Cancelled.")
        return 0
    show = progress_printer(sys.stderr.isatty())
    results = sweep.teardown(targets, progress=show)
    ok = 0
    for item, success, msg in results:
        mark = color("ok  ", "green") if success else color("FAIL", "red")
        print(f"{mark} {item.kind_label:<26} {item.id}: {msg}")
        ok += success
    print(color(f"{ok} of {len(results)} done. Scan again in a few minutes to catch things that "
                "depended on them.", "bold"))
    return 0 if ok == len(results) else 1


def sweep_notify(items, warnings, profiles) -> int:
    from . import sweep
    cfg = load_config()
    live = [i for i in items if not i.kept]
    total = sweep.total_monthly(live)
    if warnings and not items:
        notify("Lab sweep couldn't run", "\n".join(warnings[:3]), urgent=True,
               icon="dialog-warning")
        print("\n".join(warnings), file=sys.stderr)
        return 1
    print(sweep.summary_line(items))
    if warnings:
        print("\n".join(warnings), file=sys.stderr)
    if not live or (total < cfg.get("notify_threshold", 1.0) and not any(
            i.monthly is None for i in live)):
        if warnings:
            # Some checks didn't run, so "nothing found" may not be the whole story.
            notify("Lab sweep: some checks couldn't run", "\n".join(warnings[:3]),
                   icon="dialog-warning")
            return 1
        return 0
    top = sorted(live, key=lambda i: -(i.monthly or 0))[:5]
    lines = [f"{i.kind_label} in {i.region} ({money(i.monthly)}/mo)" for i in top]
    if len(live) > 5:
        lines.append(f"and {len(live) - 5} more")
    if warnings:
        lines.append(f"{len(warnings)} check(s) couldn't run")
    notify(f"Still running: about {money(total)}/month", "\n".join(lines), urgent=total >= 20,
           icon="dialog-warning")
    topic = cfg.get("sns_topic")
    if topic:
        try:
            from .common import AwsContext
            region = topic.split(":")[3]
            ctx = AwsContext(profiles[0] if profiles else None)
            body = sweep.summary_line(items) + "\n\n" + "\n".join(
                f"{i.profile or 'default'} {i.region} {i.kind_label} {i.id} {i.name} "
                f"{money(i.monthly)}/mo" for i in live)
            ctx.client("sns", region).publish(TopicArn=topic, Subject="AWS lab sweep",
                                              Message=body[:250000])
        except Exception as exc:  # noqa: BLE001
            err(f"Couldn't publish to SNS: {exc}")
    return 0


WINDOWS_TASK = "AWS Kit Lab Sweep"


def windows_launcher():
    """(pythonw.exe, awskit.pyw) from the Windows install, or None when running from a
    plain checkout. The installer puts awskit.pyw next to the app folder."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    script = Path(__file__).resolve().parent.parent.parent / "awskit.pyw"
    if pythonw.exists() and script.exists():
        return str(pythonw), str(script)
    return None


def windows_task_xml(command: str, arguments: str, at: str) -> str:
    """A Task Scheduler task for the current user that runs daily, and catches up after a
    missed run like the systemd timer's Persistent=true. No admin needed to add it."""
    from xml.sax.saxutils import escape
    hh, mm = at.split(":")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Runs the AWS Kit lab sweep and notifies you if anything is still costing money.</Description></RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T{int(hh):02d}:{mm}:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{escape(command)}</Command><Arguments>{escape(arguments)}</Arguments></Exec>
  </Actions>
</Task>
"""


def _install_windows_task(at, args) -> int:
    import tempfile
    launcher = windows_launcher()
    if not launcher:
        err("The daily check needs AWS Kit installed with install-windows.cmd.")
        return 1
    pythonw, script = launcher
    bad = [p for p in args.profile or [] if not PROFILE_NAME.fullmatch(p)]
    if bad:
        err(f"{bad[0]} isn't a profile name AWS Kit can schedule (letters, digits and . _ - @ + = , / only).")
        return 1
    arguments = f'"{script}" sweep --notify --quiet'
    for p in args.profile or []:
        arguments += f' --profile "{p}"'
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-16") as fh:
            fh.write(windows_task_xml(pythonw, arguments, at))
        r = subprocess.run([system32("schtasks.exe"), "/Create", "/F", "/TN", WINDOWS_TASK, "/XML", path],
                           capture_output=True, text=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        err(f"Couldn't run schtasks: {exc}")
        return 1
    finally:
        os.unlink(path)
    if r.returncode != 0:
        err((r.stderr or r.stdout).strip() or "schtasks failed.")
        return 1
    hh, mm = at.split(":")
    print(f"Lab sweep will run every day at {int(hh):02d}:{mm} and notify you if anything is "
          "still costing money.")
    print("SSO sign-ins expire, so if you aren't signed in at that time you'll get a "
          "notification saying so instead.")
    print(f"It's in Task Scheduler as {WINDOWS_TASK}.")
    return 0


def _remove_windows_task() -> int:
    try:
        r = subprocess.run([system32("schtasks.exe"), "/Delete", "/F", "/TN", WINDOWS_TASK],
                           capture_output=True, text=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        err(f"Couldn't run schtasks: {exc}")
        return 1
    print("Removed the daily sweep." if r.returncode == 0 else "No daily sweep was set up.")
    return 0


# Profile names a scheduled sweep takes, so nothing in one can change the command line.
PROFILE_NAME = re.compile(r"[\w.@+=,/-]+")


def systemd_quote(word: str) -> str:
    """One argument for a systemd ExecStart line: quoted, with % and $ doubled so systemd
    doesn't expand them."""
    word = str(word).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + word.replace("%", "%%").replace("$", "$$") + '"'


def system32(name: str) -> str:
    """A program in Windows' System32 by its full path, so a file of the same name in the
    current folder is never run instead."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return os.path.join(root, "System32", name)


def systemd_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user"


def install_timer(at, args) -> int:
    if not re.fullmatch(r"\d{1,2}:\d{2}", at or ""):
        err("Give a time like 21:00.")
        return 1
    if sys.platform == "win32":
        return _install_windows_task(at, args)
    exe = shutil.which("awskit") or str(Path.home() / ".local" / "bin" / "awskit")
    unit_dir = systemd_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    bad = [p for p in args.profile or [] if not PROFILE_NAME.fullmatch(p)]
    if bad:
        err(f"{bad[0]} isn't a profile name AWS Kit can schedule (letters, digits and . _ - @ + = , / only).")
        return 1
    words = [exe, "sweep", "--notify", "--quiet"]
    for p in args.profile or []:
        words += ["--profile", p]
    (unit_dir / "awskit-sweep.service").write_text(
        "[Unit]\nDescription=AWS Kit lab sweep\n\n[Service]\nType=oneshot\n"
        f"ExecStart={' '.join(systemd_quote(w) for w in words)}\n", encoding="utf-8")
    hh, mm = at.split(":")
    (unit_dir / "awskit-sweep.timer").write_text(
        "[Unit]\nDescription=Run the AWS Kit lab sweep every day\n\n[Timer]\n"
        f"OnCalendar=*-*-* {int(hh):02d}:{mm}:00\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n", encoding="utf-8")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", "awskit-sweep.timer"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            err(r.stderr.strip())
            return 1
    print(f"Lab sweep will run every day at {int(hh):02d}:{mm} and notify you if anything is "
          "still costing money.")
    print("SSO sign-ins expire, so if you aren't signed in at that time you'll get a "
          "notification saying so instead.")
    print("Check it with: systemctl --user list-timers awskit-sweep.timer")
    return 0


def remove_timer() -> int:
    if sys.platform == "win32":
        return _remove_windows_task()
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", "awskit-sweep.timer"],
                       capture_output=True)
    removed = []
    for name in ("awskit-sweep.service", "awskit-sweep.timer"):
        path = systemd_dir() / name
        if path.exists():
            path.unlink()
            removed.append(str(path))
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print("Removed the daily sweep." if removed else "No daily sweep was set up.")
    return 0


# =================================================================== audit

AUDIT_COLS = [("severity", "Severity"), ("profile", "Profile"), ("region", "Region"),
              ("check", "Finding"), ("resource", "Resource"), ("name", "Name"),
              ("detail", "Detail")]


def cmd_audit(args) -> int:
    from . import audit
    profiles = resolve_profiles(args)
    show = progress_printer(sys.stderr.isatty() and not args.json)
    findings, warnings = audit.audit(profiles, args.region, args.check, progress=show)
    rows = [f.row() for f in findings]
    if args.json:
        print(json.dumps({"findings": rows, "warnings": warnings}, indent=2, default=str))
    elif args.markdown:
        cols = AUDIT_COLS + [("fix", "Fix")]
        text = to_markdown(rows, cols, title="Exposure audit", intro=audit.counts_text(findings))
        Path(args.markdown).write_text(text, encoding="utf-8")
        print(f"Wrote {args.markdown}")
    else:
        cols = AUDIT_COLS if len(profiles) > 1 else [c for c in AUDIT_COLS if c[0] != "profile"]
        if rows:
            print(table_text(rows, cols, max_width=50, colorize=sev_colorizer))
            print()
        print(color(audit.counts_text(findings), "bold"))
        if args.verbose:
            for f in findings:
                if f.fix:
                    print(f"\n{f.check}: {f.resource}\n  Fix: {f.fix}")
        else:
            print(color("Add -v to see how to fix each one.", "dim"))
        for w in warnings:
            print(color("Note: " + w, "yellow"), file=sys.stderr)
    return fail_exit(findings, args.fail_on)


# =================================================================== trail

TRAIL_COLS = [("flag", "Flag"), ("time", "Time"), ("who", "Who"), ("action", "Action"),
              ("resources", "Resource"), ("result", "Result"), ("ip", "Source IP")]


def cmd_trail(args) -> int:
    from datetime import datetime, timezone

    from . import trail
    from .common import AwsContext
    profile = resolve_profiles(args)[0]
    try:
        start = parse_when(args.since)
        end = parse_when(args.until) if args.until else datetime.now(timezone.utc)
    except ValueError as exc:
        err(str(exc))
        return 1
    attr = value = None
    for key in trail.LOOKUP_KEYS:
        v = getattr(args, key, None)
        if v:
            attr, value = key, v
            break
    try:
        ctx = AwsContext(profile)
        if args.mine:
            attr, value = "user", trail.my_session_name(ctx)
        regions = args.region or ([ctx.default_region] if not args.all_regions else ctx.enabled_regions())
        events, warnings = trail.lookup(profile, regions, start, end, attr, value, args.errors,
                                        args.writes, args.limit, security_only=args.security)
    except AuthError as exc:
        err(str(exc))
        return 1
    if args.json:
        print(json.dumps([e.raw for e in events], indent=2, default=str))
        return 0
    if events:
        def colorize(k, v):
            if k == "result" and v != "OK":
                return "red"
            return sev_colorizer("severity", v) if k == "flag" else None
        print(table_text([e.row() for e in events], TRAIL_COLS, max_width=48, colorize=colorize))
    print(color(f"\n{len(events)} event(s). Event history can lag about 5 minutes behind.", "bold"))
    if not args.region and not args.all_regions:
        print(color(trail.GLOBAL_HINT, "dim"))
    if args.errors and events:
        print()
        for e in events[:10]:
            why = trail.explain_denied(e)
            if why:
                print(color(f"{e.action} at {e.row()['time']}", "bold"))
                print("  " + terminal_safe(why).replace("\n", "\n  "))
    if args.security and events:
        print()
        seen = set()
        for e in events:
            if e.alert and e.alert[1] not in seen:
                seen.add(e.alert[1])
                print(color(f"{e.alert[1]}: ", "bold") + e.alert[2])
    for w in warnings:
        print(color("Note: " + w, "yellow"), file=sys.stderr)
    return 0


# =================================================================== plan

def cmd_plan(args) -> int:
    from . import tfplan
    try:
        if args.source:
            plan = tfplan.load_plan(args.source)
        elif stdin_has_data():
            plan = tfplan.load_plan(sys.stdin.read())
        else:
            print(color("Running terraform plan in this folder...", "dim"), file=sys.stderr)
            plan = tfplan.load_plan(".")
        summary = tfplan.summarize(plan)
    except tfplan.PlanError as exc:
        err(str(exc))
        return 1
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
        err(f"That plan couldn't be read: {type(exc).__name__} {exc}")
        return 1
    if args.json:
        print(json.dumps({"headline": summary.headline(), "counts": summary.counts(),
                          "risks": [r.as_dict() for r in summary.risks],
                          "changes": [c.as_dict() for c in summary.changes],
                          "outputs": summary.outputs, "drift": summary.drift}, indent=2))
    else:
        text = tfplan.report_text(summary, markdown=args.markdown)
        if sys.stdout.isatty() and not args.copy and not args.redact and not args.markdown:
            for line in text.splitlines():
                s = line.lstrip()
                if s.startswith("[CRITICAL]"):
                    line = color(line, "magenta")
                elif s.startswith("[HIGH]") or s.startswith("- "):
                    line = color(line, "red")
                elif s.startswith("[MEDIUM]") or s.startswith("-/+") or s.startswith("~"):
                    line = color(line, "yellow")
                elif s.startswith("+ "):
                    line = color(line, "green")
                print(line)
        else:
            emit_text(text, args)
    return fail_exit(summary.risks, args.fail_on)


# =================================================================== policy

def cmd_policy(args) -> int:
    from . import iampolicy
    from .common import AwsContext
    note = ""
    kind = None if args.kind == "auto" else args.kind
    ctx = None
    try:
        if args.arn:
            ctx = AwsContext(resolve_profiles(args)[0])
            doc, fetched_kind, label = iampolicy.fetch_policy(ctx, args.arn)
            kind = kind or fetched_kind
            note = f"Loaded {label} from AWS."
        else:
            if args.file and args.file != "-":
                text = Path(args.file).read_text(encoding="utf-8")
            elif stdin_has_data() or args.file == "-":
                text = sys.stdin.read()
            else:
                return run_gui("policy")
            doc, note = iampolicy.load_policy(text)
    except (iampolicy.PolicyError, OSError) as exc:
        err(str(exc))
        return 1
    except AuthError as exc:
        err(str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001
        from .common import error_text
        err(error_text(exc))
        return 1
    kind = kind or iampolicy.detect_kind(doc)
    findings = iampolicy.analyze(doc, kind)
    if args.aws:
        try:
            ctx = ctx or AwsContext(resolve_profiles(args)[0])
            findings += iampolicy.validate_with_aws(ctx, doc, kind)
        except AuthError as exc:
            err(str(exc))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    if args.json:
        print(json.dumps({"kind": kind, "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        text = iampolicy.report_text(findings, kind, note)
        if sys.stdout.isatty():
            for line in text.splitlines():
                for sev, name in SEVERITY_COLOR.items():
                    if line.startswith(f"[{sev.upper()}]"):
                        line = color(line, name)
                print(line)
        else:
            print(text, end="")
    return fail_exit(findings, args.fail_on)


# =================================================================== appearance

def cmd_appearance(args) -> int:
    from . import theme
    cfg = load_config()
    settings = theme.clean_settings(cfg.get("appearance"))
    if args.list:
        print("Styles:     " + ", ".join(theme.STYLES))
        print("Colors:     " + ", ".join(theme.SCHEME_KEYS))
        print("Accents:    default (the color scheme's own), " +
              ", ".join(k for k, _n, _h in theme.ACCENTS) + ", or a color like #3584e4")
        print("Text sizes: " + ", ".join(f"{pct} ({name.lower()})"
                                         for pct, name in theme.TEXT_SIZES))
        return 0
    changed = False
    if args.reset:
        settings, changed = dict(theme.DEFAULTS), True
    if args.style:
        settings["style"], changed = args.style, True
    if args.colors:
        settings["colors"], changed = args.colors, True
    if args.accent:
        accent = args.accent.strip().lower()
        if accent != "default" and accent not in theme.ACCENT_HEX and \
                not re.fullmatch(r"#[0-9a-f]{6}", accent):
            err(f"{args.accent} isn't an accent. Use default, one of "
                f"{', '.join(theme.ACCENT_HEX)}, or a color like #3584e4.")
            return 2
        settings["accent"], changed = accent, True
    if args.text_size is not None:
        if not 70 <= args.text_size <= 200:
            err("The text size is a percentage from 70 to 200, like 110.")
            return 2
        settings["text_size"], changed = args.text_size, True
    if changed:
        cfg["appearance"] = theme.clean_settings(settings)
        if not save_config(cfg):
            err(f"Couldn't save {CONFIG_FILE}.")
            return 1
        settings = cfg["appearance"]
        print("Saved. Open AWS Kit windows change right away.", file=sys.stderr)
    accent = settings["accent"]
    if accent == "default":
        own = theme.scheme(settings["colors"]).accent
        accent = f"default ({own})" if own else "default (GTK's blue)"
    print(f"Style:      {settings['style']}")
    print(f"Colors:     {settings['colors']}")
    print(f"Accent:     {accent}")
    print(f"Text size:  {settings['text_size']}%")
    return 0


# =================================================================== profile

def cmd_profile(args) -> int:
    from . import profiles as prof
    if args.list or args.check:
        rows = []
        current = prof.current_profile()
        for p in prof.list_profiles():
            status = prof.offline_status(p)
            if args.check:
                r = prof.check_profile(p["name"])
                status = r["message"] if r["status"] != "ok" else f"ok ({r['account']})"
            rows.append({"cur": "*" if p["name"] == current else "", "name": p["name"],
                         "kind": p["kind"], "account": p["account"], "role": p["role"],
                         "region": p["region"], "status": status})
        if not rows:
            print("No profiles found in ~/.aws/config or ~/.aws/credentials.")
            return 0
        print(table_text(rows, [("cur", ""), ("name", "Profile"), ("kind", "Type"),
                                ("account", "Account"), ("role", "Role"), ("region", "Region"),
                                ("status", "Status")]))
        return 0
    if args.current:
        print(prof.current_profile() or "")
        return 0
    if args.clear:
        prof.set_current_profile(None)
        print("No profile selected. AWS tools will use the default credential chain.",
              file=sys.stderr)
        return 0
    if args.login:
        ok, msg = prof.sso_login(args.login)
        (print if ok else err)(msg)
        return 0 if ok else 1
    if args.name:
        names = prof.profile_names()
        if args.name not in names:
            close = [n for n in names if args.name.lower() in n.lower()]
            if len(close) == 1:
                args.name = close[0]
            else:
                err(f"No profile named {args.name}." + (f" Did you mean: {', '.join(close)}?"
                                                         if close else ""))
                return 1
        prof.set_current_profile(args.name)
        info = next((p for p in prof.list_profiles() if p["name"] == args.name), {})
        status = prof.offline_status(info)
        print(f"Using {args.name}" + (f" ({status})" if status else ""), file=sys.stderr)
        if status in ("expired", "not signed in"):
            print(f"Sign in with: aws sso login --profile {args.name}", file=sys.stderr)
        return 0
    return run_gui("picker")


def cmd_shell_init(args) -> int:
    from . import profiles as prof
    try:
        print(prof.shell_hook(args.shell), end="")
    except ValueError as exc:
        err(str(exc))
        return 1
    return 0


# =================================================================== install

def apps_dir() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "applications"


def share_dir() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "awskit"


def desktop_entries(exe: str) -> dict:
    main = (
        "[Desktop Entry]\nType=Application\n"
        f"Name={APP_NAME}\nGenericName=AWS and Terraform tools\n"
        "Comment=Redact output and screenshots, secrets scan, lab sweep, exposure and credential "
        "audits, CloudTrail, least privilege, plan, drift, policy and SCP checks, cloud maps\n"
        f"Exec=\"{exe}\" gui\nIcon=network-server\nTerminal=false\n"
        "Categories=Development;Utility;\n"
        "Keywords=aws;terraform;iam;cloudtrail;security;cost;redact;secrets;scp;drift;\n"
        f"StartupNotify=true\nStartupWMClass={APP_ID}\n"
        "Actions=image;secrets;sweep;audit;creds;trail;leastpriv;plan;drift;policy;scp;map;\n"
    )
    for page, title in (("image", "Image Redact"), ("secrets", "Secrets Scan"),
                        ("sweep", "Lab Sweep"), ("audit", "Exposure Audit"),
                        ("creds", "Credentials"), ("trail", "CloudTrail"),
                        ("leastpriv", "Least Privilege"), ("plan", "Plan Check"),
                        ("drift", "Drift"), ("policy", "Policy Check"), ("scp", "Org & SCPs"),
                        ("map", "Cloud Map")):
        main += f"\n[Desktop Action {page}]\nName={title}\nExec=\"{exe}\" gui {page}\n"
    picker = (
        "[Desktop Entry]\nType=Application\nName=AWS Profile Picker\n"
        "Comment=Switch the AWS profile your terminals use\n"
        f"Exec=\"{exe}\" profile\nIcon=avatar-default\nTerminal=false\n"
        "Categories=Development;Utility;\nKeywords=aws;profile;sso;\n"
        f"StartupWMClass={PICKER_APP_ID}\n"
    )
    redact = (
        "[Desktop Entry]\nType=Application\nName=PII Redact\nGenericName=Redaction tool\n"
        "Comment=Strip account IDs, keys and personal info out of pasted text\n"
        f"Exec=\"{exe}\" redact gui\nIcon=dialog-password\nTerminal=false\n"
        "Categories=Utility;\nKeywords=redact;pii;aws;terraform;boto3;privacy;\n"
        f"StartupNotify=true\nStartupWMClass={REDACT_APP_ID}\n"
        "Actions=clip;settings;\n"
        f"\n[Desktop Action clip]\nName=Redact clipboard\nExec=\"{exe}\" redact clip\n"
        f"\n[Desktop Action settings]\nName=Settings\nExec=\"{exe}\" redact settings\n"
    )
    redact_settings = (
        "[Desktop Entry]\nType=Application\nName=PII Redact Settings\n"
        "Comment=Choose what PII Redact hides\n"
        f"Exec=\"{exe}\" redact settings\nIcon=preferences-system\nTerminal=false\n"
        f"Categories=Settings;\nStartupWMClass={REDACT_SETTINGS_APP_ID}\n"
    )
    image = (
        "[Desktop Entry]\nType=Application\nName=Image Redact\nGenericName=Screenshot redaction\n"
        "Comment=Cover account IDs, keys and personal info in screenshots\n"
        f"Exec=\"{exe}\" image %f\nIcon=image-x-generic\nTerminal=false\n"
        "Categories=Graphics;Utility;\n"
        "MimeType=image/png;image/jpeg;image/webp;image/bmp;\n"
        "Keywords=redact;screenshot;pii;aws;privacy;annotate;censor;\n"
        f"StartupNotify=true\nStartupWMClass={IMAGE_APP_ID}\n"
        "Actions=paste;clip;\n"
        f"\n[Desktop Action paste]\nName=Open clipboard image\nExec=\"{exe}\" image clip -g\n"
        f"\n[Desktop Action clip]\nName=Redact clipboard image\nExec=\"{exe}\" image clip\n"
    )
    return {f"{APP_ID}.desktop": main, f"{PICKER_APP_ID}.desktop": picker,
            f"{REDACT_APP_ID}.desktop": redact,
            f"{REDACT_SETTINGS_APP_ID}.desktop": redact_settings,
            f"{IMAGE_APP_ID}.desktop": image}


def launcher_script(module_args: str, comment: str) -> str:
    """The awskit command. It doesn't use python3 -m awskit, which would look for Python
    modules in whatever folder you run it from first (a cloned repo's json.py, say)."""
    import shlex
    start = ('import os, sys; sys.path[0] = os.environ.pop("AWSKIT_HOME"); '
             'from awskit.cli import main; sys.exit(main())')
    return ("#!/bin/sh\n"
            f"# {comment}, written by awskit install\n"
            f"AWSKIT_HOME={shlex.quote(str(share_dir()))} "
            f"exec python3 -c {shlex.quote(start)} {module_args}\"$@\"\n")


DRAWIO_SKIP = ("WEB-INF/", "META-INF/")


def unpack_drawio(war: str, dest: Path, version: str):
    """Unpack draw.io's web app (a .war is a zip) into dest, replacing what's there. The
    Java server parts and source maps are left out. Writes the version marker last, so a
    half-finished unpack is never taken for a good one."""
    import zipfile
    from .common import DRAWIO_MARKER
    # AWSKIT_DRAWIO can point anywhere, so only a folder AWS Kit unpacked before (it has
    # the marker), an empty one or none at all is replaced.
    if dest.is_symlink() or (dest.exists() and not (dest / DRAWIO_MARKER).exists()
                             and (not dest.is_dir() or any(dest.iterdir()))):
        raise ValueError(f"{dest} has files AWS Kit didn't put there, so it's left alone. "
                         "Point AWSKIT_DRAWIO at an empty folder, or remove it.")
    tmp = dest.with_name(dest.name + ".new")
    if tmp.is_symlink():
        tmp.unlink()
    elif tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    root = tmp.resolve()
    with zipfile.ZipFile(war) as zf:
        if "index.html" not in zf.namelist():
            raise ValueError("That file isn't draw.io's web app (no index.html in it).")
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if info.is_dir() or name.startswith(DRAWIO_SKIP) or name.endswith(".map"):
                continue
            target = (tmp / name).resolve()
            if root not in target.parents:
                raise ValueError(f"Unsafe path in the zip: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
    (tmp / DRAWIO_MARKER).write_text(version + "\n", encoding="ascii")
    if dest.exists():
        shutil.rmtree(dest)
    tmp.replace(dest)


def sha256_of(path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def install_drawio(zip_path=None, dest=None) -> bool:
    """Download (or take from zip_path) the pinned draw.io web app, check its SHA-256 and
    unpack it. Only does the work when the pinned version changes. Cloud Map uses it for
    its AWS icons and its offline editor. Returns False if it couldn't, which isn't fatal."""
    import tempfile
    import urllib.request
    from .common import (DRAWIO_SHA256, DRAWIO_URL, DRAWIO_VERSION, drawio_dir,
                         drawio_installed)
    dest = Path(dest) if dest else drawio_dir()
    if not zip_path and drawio_installed(dest) == DRAWIO_VERSION:
        print(f"draw.io {DRAWIO_VERSION} is already in {dest}")
        return True
    tmp_dir = None
    try:
        if zip_path:
            war = str(Path(zip_path).expanduser())
        else:
            tmp_dir = tempfile.mkdtemp(prefix="awskit-drawio-")
            war = os.path.join(tmp_dir, "draw.war")
            print(f"Downloading draw.io {DRAWIO_VERSION} (about 48 MB) for Cloud Map's icons "
                  "and editor...")
            req = urllib.request.Request(DRAWIO_URL, headers={"User-Agent": f"awskit/{VERSION}"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(war, "wb") as out:
                shutil.copyfileobj(resp, out, 1 << 20)
        got = sha256_of(war)
        if got != DRAWIO_SHA256:
            err(f"That draw.io download doesn't match the pinned version {DRAWIO_VERSION}.\n"
                f"  expected SHA-256 {DRAWIO_SHA256}\n  got      {got}\n"
                "Nothing was changed. Download draw.war from the link below and try again.")
            print(f"  {DRAWIO_URL}", file=sys.stderr)
            return False
        unpack_drawio(war, dest, DRAWIO_VERSION)
        print(f"Unpacked draw.io {DRAWIO_VERSION} into {dest}")
        return True
    except (OSError, ValueError) as exc:
        err(f"Couldn't set up draw.io: {exc}")
        print("Cloud Map still draws maps, with simple stand-in icons, but can't open its "
              "editor. On a network that blocks "
              f"GitHub, download\n  {DRAWIO_URL}\nanother way, then run:\n"
              "  ./install.sh --drawio-zip /path/to/draw.war", file=sys.stderr)
        return False
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def cmd_install(args) -> int:
    if sys.platform == "win32":
        err("On Windows, run install-windows.cmd from the Cloud-Tools folder instead. It "
            "installs AWS Kit for your user, without admin.")
        return 1
    from . import TOOL_DIRS
    from .redact import remove_old_install
    repo = Path(__file__).resolve().parent.parent
    target = share_dir()
    if target.resolve() != repo:
        # Copy the shared app folder plus each tool's folder, keeping them side by side
        # the same way they sit in the repo.
        target.mkdir(parents=True, exist_ok=True)
        for name in ("awskit",) + TOOL_DIRS:
            src, dest = repo / name, target / name
            if not src.is_dir():
                continue
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest, ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "docs", "examples", "*.md"))
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / "awskit"
    if exe.exists() or exe.is_symlink():
        exe.unlink()             # a link (pipx, a dev setup) is replaced, not written through
    exe.write_text(launcher_script("", "AWS Kit launcher"), encoding="utf-8")
    exe.chmod(0o755)
    # pii-redact keeps working as its own command, so old keybinds and habits still work.
    shortcut = bin_dir / "pii-redact"
    if shortcut.exists() or shortcut.is_symlink():
        shortcut.unlink()
    shortcut.write_text(launcher_script("redact ", "PII Redact, same as awskit redact"),
                        encoding="utf-8")
    shortcut.chmod(0o755)
    apps = apps_dir()
    apps.mkdir(parents=True, exist_ok=True)
    old = remove_old_install(apps)
    for name, content in desktop_entries(str(exe)).items():
        (apps / name).write_text(content, encoding="utf-8")
    if shutil.which("update-desktop-database"):
        # So Image Redact shows up under Open With for images.
        subprocess.run(["update-desktop-database", str(apps)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
    print(f"Installed {exe} and {shortcut}")
    print(f"Launcher entries added to {apps}: AWS Kit, AWS Profile Picker, PII Redact, "
          "PII Redact Settings, Image Redact")
    if not getattr(args, "no_drawio", False):
        install_drawio(getattr(args, "drawio_zip", None))
    if old:
        print("Removed launcher entries from the old standalone PII Redact. Your PII Redact "
              "settings carry over.")
    if str(bin_dir) not in os.environ.get("PATH", "").split(":"):
        print(f"Note: {bin_dir} isn't in your PATH, so use the full path or add it to PATH.")
    print("\nFor awsp and the prompt helper, add this to ~/.bashrc or ~/.zshrc:")
    print('  eval "$(awskit shell-init bash)"')
    print("or for fish, to ~/.config/fish/config.fish:")
    print("  awskit shell-init fish | source")
    return 0


def cmd_uninstall(args) -> int:
    if sys.platform == "win32":
        err("On Windows, remove AWS Kit from Settings, Apps, Installed apps.")
        return 1
    removed = []
    bin_dir = Path.home() / ".local" / "bin"
    exe = bin_dir / "awskit"
    for path in [exe, bin_dir / "pii-redact"] + [apps_dir() / n for n in desktop_entries(str(exe))]:
        if path.exists():
            path.unlink()
            removed.append(str(path))
    share = share_dir()
    repo = Path(__file__).resolve().parent.parent
    if share.exists() and (share.resolve() == repo or (share / ".git").exists()):
        # AWS Kit runs straight from this folder (a clone), so only what install added goes.
        from .common import DRAWIO_MARKER
        drawio = share / "drawio"
        if (drawio / DRAWIO_MARKER).exists() and not drawio.is_symlink():
            shutil.rmtree(drawio)
            removed.append(str(drawio))
        print(f"Kept {share}, since it's a copy of the code you run AWS Kit from.")
    elif share.exists():
        shutil.rmtree(share)
        removed.append(str(share))
    remove_timer()
    print("Removed:\n  " + "\n  ".join(removed) if removed else "Nothing to remove.")
    from .common import CONFIG_DIR
    print(f"Your settings are still in {CONFIG_DIR}. Delete that folder too if you want them gone.")
    print("Remove the awskit shell-init line from your shell config as well.")
    return 0


# =================================================================== gui

def run_gui(page=None) -> int:
    from .app import main as gui_main
    return gui_main(page)


def cmd_gui(args) -> int:
    return run_gui(args.page)


# =================================================================== parser

def build_parser() -> argparse.ArgumentParser:
    from . import audit, iampolicy, sweep, theme, trail
    p = argparse.ArgumentParser(
        prog="awskit",
        description="AWS and Terraform tools. Run with no arguments to open the window.",
        epilog="Each command has its own --help, like: awskit sweep --help")
    p.add_argument("--version", action="version", version=f"awskit {VERSION}")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    def add_profiles(sp, many=True):
        sp.add_argument("-p", "--profile", action="append",
                        help="AWS profile to use" + (" (repeat for several)" if many else "") +
                        ". Defaults to the one picked in awskit.")
        if many:
            sp.add_argument("--all-profiles", action="store_true",
                            help="Use every profile in ~/.aws/config")

    sub.add_parser("redact", add_help=False,
                   help="Redact account IDs, keys and other identifying info (same as pii-redact)")
    sub.add_parser("image", add_help=False,
                   help="Cover account IDs, keys and other identifying text in screenshots")
    sub.add_parser("map", add_help=False,
                   help="Draw access and network maps of AWS or Terraform as draw.io diagrams")

    g = sub.add_parser("gui", help="Open the window")
    g.add_argument("page", nargs="?", choices=PAGES, help="Page to open on")
    g.set_defaults(func=cmd_gui)

    s = sub.add_parser("sweep", help="Find things still costing money, and tear them down",
                       description="Lists billable leftovers in every enabled region.")
    add_profiles(s)
    s.add_argument("-r", "--region", action="append", help="Only this region (repeatable)")
    s.add_argument("-k", "--kind", action="append", choices=sweep.kind_choices(), metavar="KIND",
                   help="Only this resource type (repeatable): " + ", ".join(sweep.kind_choices()))
    s.add_argument("--json", action="store_true", help="Print JSON")
    s.add_argument("--teardown", action="store_true",
                   help="After scanning, offer to delete what was found")
    s.add_argument("--dry-run", action="store_true", help="With --teardown, only show the plan")
    s.add_argument("--spend", action="store_true",
                   help="Show month-to-date spend from Cost Explorer ($0.01 per call)")
    s.add_argument("--notify", action="store_true",
                   help="Desktop notification if anything is running (used by the timer)")
    s.add_argument("-q", "--quiet", action="store_true", help="No progress line")
    s.add_argument("--install-timer", metavar="HH:MM", nargs="?", const="21:00",
                   help="Run --notify every day at this time (a systemd user timer, or a "
                        "scheduled task on Windows)")
    s.add_argument("--remove-timer", action="store_true", help="Remove the daily timer")
    s.set_defaults(func=cmd_sweep)

    a = sub.add_parser("audit", help="Find things open to the internet or missing protection")
    add_profiles(a)
    a.add_argument("-r", "--region", action="append", help="Only this region (repeatable)")
    a.add_argument("-c", "--check", action="append", choices=audit.check_choices(),
                   metavar="CHECK", help="Only this check: " + ", ".join(audit.check_choices()))
    a.add_argument("--json", action="store_true", help="Print JSON")
    a.add_argument("--markdown", metavar="FILE", help="Write a Markdown report to FILE")
    a.add_argument("-v", "--verbose", action="store_true", help="Show the fix for each finding")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER), metavar="SEVERITY",
                   help="Exit with code 2 if anything this bad or worse is found")
    a.set_defaults(func=cmd_audit)

    t = sub.add_parser("trail", help="Who did what, from CloudTrail event history",
                       description="Searches CloudTrail event history. " + trail.GLOBAL_HINT)
    add_profiles(t, many=False)
    t.add_argument("-r", "--region", action="append", help="Region to search (repeatable)")
    t.add_argument("--all-regions", action="store_true", help="Search every enabled region")
    t.add_argument("--since", default="1h", help="How far back: 30m, 2h, 3d, or a date (default 1h)")
    t.add_argument("--until", help="End time, same format as --since (default now)")
    group = t.add_mutually_exclusive_group()
    for key, (_, label) in trail.LOOKUP_KEYS.items():
        group.add_argument(f"--{key}", metavar="VALUE", help=label)
    group.add_argument("--mine", action="store_true", help="Only events from your own session")
    t.add_argument("-e", "--errors", action="store_true", help="Only failed calls, like AccessDenied")
    t.add_argument("-w", "--writes", action="store_true", help="Hide read-only calls")
    t.add_argument("-s", "--security", action="store_true",
                   help="Only security events worth a look: root use, sign-ins without MFA, "
                        "CloudTrail, IAM, KMS, Organizations and network changes, denied calls")
    t.add_argument("-n", "--limit", type=int, default=200, help="Most events to show (default 200)")
    t.add_argument("--json", action="store_true", help="Print the raw events as JSON")
    t.set_defaults(func=cmd_trail)

    pl = sub.add_parser("plan", help="Summarize a Terraform plan and flag risky changes",
                        description="Reads `terraform show -json` output from a file or stdin, a "
                        "saved plan file, or runs terraform plan in a folder (the current one by "
                        "default).")
    pl.add_argument("source", nargs="?", help="Plan JSON, saved plan file, or Terraform folder")
    pl.add_argument("--markdown", action="store_true", help="Markdown output, for PRs")
    pl.add_argument("--json", action="store_true", help="JSON output")
    pl.add_argument("-c", "--copy", action="store_true", help="Copy the summary to the clipboard")
    pl.add_argument("--redact", action="store_true", help="Run the summary through PII Redact")
    pl.add_argument("--fail-on", choices=list(SEVERITY_ORDER), metavar="SEVERITY",
                    help="Exit with code 2 if a risk this bad or worse is found")
    pl.set_defaults(func=cmd_plan)

    po = sub.add_parser("policy", help="Check an IAM policy for risky permissions",
                        description="Reads a policy from FILE or stdin. With no input, opens "
                        "the window.")
    po.add_argument("file", nargs="?", help="Policy JSON file, or - for stdin")
    add_profiles(po, many=False)
    po.add_argument("--arn", help="Load from AWS instead: managed policy ARN, role ARN, or role/NAME")
    po.add_argument("--kind", default="auto", choices=("auto",) + iampolicy.KINDS,
                    help="Policy type (default: work it out)")
    po.add_argument("--aws", action="store_true",
                    help="Also run IAM Access Analyzer policy validation (free)")
    po.add_argument("--json", action="store_true", help="JSON output")
    po.add_argument("--fail-on", choices=list(SEVERITY_ORDER), metavar="SEVERITY",
                    help="Exit with code 2 if anything this bad or worse is found")
    po.set_defaults(func=cmd_policy)

    pr = sub.add_parser("profile", help="Pick the AWS profile your terminals use",
                        description="With no arguments, opens the picker window.")
    pr.add_argument("name", nargs="?", help="Profile to switch to")
    pr.add_argument("-l", "--list", action="store_true", help="List profiles")
    pr.add_argument("--check", action="store_true", help="List profiles and test each one")
    pr.add_argument("--current", action="store_true", help="Print the current profile")
    pr.add_argument("--clear", action="store_true", help="Go back to no profile")
    pr.add_argument("--login", metavar="NAME", help="Run aws sso login for NAME")
    pr.set_defaults(func=cmd_profile)

    ap = sub.add_parser("appearance", help="Light or dark, color scheme, accent and text size",
                        description="Shows or changes how the AWS Kit windows look. The same "
                        "settings as Appearance in the window's menu.")
    ap.add_argument("--style", choices=("system", "light", "dark"),
                    help="Follow the system's light or dark setting, or pick one")
    ap.add_argument("--colors", choices=theme.SCHEME_KEYS, metavar="SCHEME",
                    help="Color scheme: " + ", ".join(theme.SCHEME_KEYS))
    ap.add_argument("--accent", help="default, blue, teal, green, yellow, orange, red, pink, "
                                     "purple, slate, or a color like #3584e4")
    ap.add_argument("--text-size", type=int, metavar="PERCENT",
                    help="90, 100, 110, 125 or 140 (any from 70 to 200 works)")
    ap.add_argument("--reset", action="store_true", help="Back to how GTK looks by itself")
    ap.add_argument("-l", "--list", action="store_true", help="List every choice")
    ap.set_defaults(func=cmd_appearance)

    sh = sub.add_parser("shell-init", help="Print the shell hook for awsp and the prompt")
    sh.add_argument("shell", nargs="?", default="powershell" if sys.platform == "win32"
                    else "bash", choices=("bash", "zsh", "fish", "powershell", "pwsh"))
    sh.set_defaults(func=cmd_shell_init)

    i = sub.add_parser("install", help="Install to ~/.local and add launcher entries")
    i.add_argument("--drawio-zip", metavar="PATH",
                   help="Use a draw.war you already downloaded, for networks that block GitHub")
    i.add_argument("--no-drawio", action="store_true",
                   help="Skip the draw.io download (Cloud Map then uses stand-in icons and has "
                        "no editor)")
    i.set_defaults(func=cmd_install)
    u = sub.add_parser("uninstall", help="Remove awskit")
    u.set_defaults(func=cmd_uninstall)

    import importlib
    for name in CLI_MODULES:
        importlib.import_module(f"awskit.{name}").register_cli(sub, add_profiles)
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return run_gui(None)
    if argv[0] == "redact":
        # PII Redact has its own command line, shared with the pii-redact command.
        from .redact import main as redact_main
        return redact_main(argv[1:], prog="awskit redact")
    if argv[0] == "image":
        from .imageredact import main as image_main
        return image_main(argv[1:], prog="awskit image")
    if argv[0] == "map":
        # Cloud Map has subcommands of its own (scan, tf, export).
        from .cloudmap import main as map_main
        return map_main(argv[1:], prog="awskit map")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except AuthError as exc:
        err(str(exc))
        return 1
