"""Shared pieces used by every tool: config, AWS sessions, regions, errors, output."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

VERSION = "1.0.0"
APP_NAME = "AWS Kit"
APP_ID = "io.github.Snowblind019.AwsKit"
PICKER_APP_ID = APP_ID + ".Profiles"
REDACT_APP_ID = APP_ID + ".Redact"
REDACT_SETTINGS_APP_ID = APP_ID + ".RedactSettings"

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "awskit"
CONFIG_FILE = CONFIG_DIR / "config.json"
CURRENT_PROFILE_FILE = CONFIG_DIR / "current-profile"

DEFAULT_CONFIG = {
    # Resource IDs or ARNs that Lab Sweep should never offer to delete.
    "keep": [],
    # Resources tagged with this key (any value) are also kept.
    "keep_tag": "awskit:keep",
    # Empty means every region enabled in the account.
    "regions": [],
    # Scheduled sweeps only notify when the estimated monthly total is above this.
    "notify_threshold": 1.0,
    # Profiles the scheduled sweep checks. Empty means the current profile.
    "timer_profiles": [],
    # SNS topic ARN for scheduled sweep summaries. Empty means desktop notification only.
    "sns_topic": "",
}


# =================================================================== config

def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key, value in data.items():
                if key in cfg and isinstance(value, type(cfg[key])):
                    cfg[key] = value
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg: dict) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(CONFIG_FILE)
        return True
    except OSError:
        return False


# =================================================================== boto3

def need_boto3():
    try:
        import boto3  # noqa: F401
        import botocore  # noqa: F401
    except ImportError:
        sys.exit("boto3 is missing.\n"
                 "Fedora:        sudo dnf install python3-boto3\n"
                 "Debian/Ubuntu: sudo apt install python3-boto3\n"
                 "Arch:          sudo pacman -S python-boto3\n"
                 "Or:            pip install --user boto3")


def boto_config():
    from botocore.config import Config
    return Config(retries={"max_attempts": 8, "mode": "adaptive"},
                  connect_timeout=6, read_timeout=30,
                  user_agent_extra=f"awskit/{VERSION}")


class AuthError(Exception):
    """Credentials are missing or expired. The message says how to fix it."""


def error_text(exc, profile=None) -> str:
    """Turn boto errors into one readable line."""
    name = type(exc).__name__
    who = f" for profile {profile}" if profile else ""
    login = f"aws sso login --profile {profile}" if profile else "aws sso login"
    if isinstance(exc, AuthError):
        return str(exc)
    if name in ("SSOTokenLoadError", "UnauthorizedSSOTokenError", "TokenRetrievalError",
                "SSOError", "PendingAuthorizationExpiredError"):
        return f"Sign-in{who} has expired. Run: {login}"
    if name == "NoCredentialsError":
        return f"No credentials found{who}. Pick a profile or run aws configure."
    if name == "ProfileNotFound":
        return f"Profile not found: {profile}"
    if name in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"):
        return "Can't reach AWS. Check your connection."
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error", {})
        code = err.get("Code", name)
        msg = err.get("Message", "")
        if code in ("ExpiredToken", "ExpiredTokenException", "RequestExpired"):
            return f"Credentials{who} have expired. Run: {login}"
        if code in ("UnrecognizedClientException", "InvalidClientTokenId"):
            return f"AWS doesn't recognize these credentials{who}."
        return f"{code}: {msg}" if msg else code
    return str(exc) or name


def is_access_denied(exc) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    code = response.get("Error", {}).get("Code", "")
    return code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                    "AuthorizationError", "AuthorizationErrorException", "Forbidden",
                    "UnauthorizedAccess") or "AccessDenied" in code


def error_code(exc) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code", "")
    return ""


class AwsContext:
    """One profile's credentials, resolved once and shared safely across threads.

    boto3 sessions aren't thread safe, so each worker thread gets its own session
    built from the same frozen credentials. That also means an SSO profile only
    reads its token once per scan.
    """

    def __init__(self, profile: str | None = None):
        need_boto3()
        import boto3
        self.profile = profile or None
        try:
            base = boto3.Session(profile_name=self.profile)
            creds = base.get_credentials()
            if creds is None:
                who = f" for profile {self.profile}" if self.profile else ""
                raise AuthError(f"No credentials found{who}. Pick a profile or run "
                                "aws configure.")
            self._frozen = creds.get_frozen_credentials()
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001 - boto raises many types here
            raise AuthError(error_text(exc, self.profile)) from exc
        self.default_region = base.region_name or "us-east-1"
        self._base = base
        self._local = threading.local()
        self._identity = None
        self._lock = threading.Lock()

    @property
    def label(self) -> str:
        return self.profile or "default"

    def _session(self):
        sess = getattr(self._local, "session", None)
        if sess is None:
            import boto3
            sess = boto3.Session(aws_access_key_id=self._frozen.access_key,
                                 aws_secret_access_key=self._frozen.secret_key,
                                 aws_session_token=self._frozen.token,
                                 region_name=self.default_region)
            self._local.session = sess
            self._local.clients = {}
        return sess

    def client(self, service: str, region: str | None = None):
        sess = self._session()
        key = (service, region or self.default_region)
        clients = self._local.clients
        if key not in clients:
            clients[key] = sess.client(service, region_name=key[1], config=boto_config())
        return clients[key]

    def identity(self) -> dict:
        with self._lock:
            if self._identity is None:
                try:
                    self._identity = self.client("sts").get_caller_identity()
                except Exception as exc:  # noqa: BLE001
                    raise AuthError(error_text(exc, self.profile)) from exc
            return self._identity

    @property
    def account(self) -> str:
        return self.identity().get("Account", "")

    def available_regions(self, service: str) -> set:
        try:
            return set(self._base.get_available_regions(service))
        except Exception:  # noqa: BLE001
            return set()

    def enabled_regions(self) -> list:
        """Regions turned on in this account, falling back to the usual set."""
        cfg_regions = load_config().get("regions") or []
        if cfg_regions:
            return list(cfg_regions)
        try:
            resp = self.client("ec2", self.default_region).describe_regions(AllRegions=False)
            regions = sorted(r["RegionName"] for r in resp.get("Regions", []))
            if regions:
                return regions
        except Exception:  # noqa: BLE001
            pass
        return sorted(self.available_regions("ec2")) or [self.default_region]

    def regions_for(self, service: str, regions) -> list:
        """Only the regions where a service actually has an endpoint."""
        known = self.available_regions(service)
        if not known:
            return list(regions)
        return [r for r in regions if r in known]


def paginate(client, method: str, key: str, **kwargs):
    """Yield every item under key across all pages."""
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(key, []) or []
    else:
        yield from getattr(client, method)(**kwargs).get(key, []) or []


def tags_dict(tags) -> dict:
    out = {}
    for t in tags or []:
        k = t.get("Key") if "Key" in t else t.get("key")
        v = t.get("Value") if "Value" in t else t.get("value")
        if k is not None:
            out[k] = v or ""
    return out


def name_tag(tags) -> str:
    return tags_dict(tags).get("Name", "")


# =================================================================== time

def parse_duration(text: str) -> timedelta:
    """'90m', '2h', '3d', '1w' -> timedelta. A bare number means hours."""
    text = (text or "").strip().lower()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw]?)", text)
    if not m:
        raise ValueError(f"Can't read duration '{text}'. Use something like 30m, 2h, 3d or 1w.")
    value = float(m.group(1))
    unit = m.group(2) or "h"
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return timedelta(seconds=value * seconds)


def parse_when(text: str) -> datetime:
    """Accept '2h' (meaning 2 hours ago) or an ISO date/time."""
    text = (text or "").strip()
    try:
        return datetime.now(timezone.utc) - parse_duration(text)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Can't read time '{text}'. Use 2h, 3d, or 2026-10-01 14:30.") from exc
    if dt.tzinfo is None:
        dt = dt.astimezone()  # treat as local time
    return dt.astimezone(timezone.utc)


def local_time(dt) -> str:
    if not isinstance(dt, datetime):
        return str(dt or "")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def age_text(dt) -> str:
    if not isinstance(dt, datetime):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    secs = (datetime.now(timezone.utc) - dt).total_seconds()
    if secs < 3600:
        return f"{max(int(secs // 60), 0)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


# =================================================================== output

def money(value) -> str:
    if value is None:
        return "?"
    if value == 0:
        return "$0"
    if value < 10:
        return f"${value:,.2f}"
    return f"${value:,.0f}"


def to_csv(rows, columns) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([title for _, title in columns])
    for row in rows:
        writer.writerow([row.get(key, "") for key, _ in columns])
    return buf.getvalue()


def to_markdown(rows, columns, title=None, intro=None) -> str:
    def cell(v):
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    lines = []
    if title:
        lines += [f"# {title}", ""]
    if intro:
        lines += [intro, ""]
    lines.append("| " + " | ".join(t for _, t in columns) + " |")
    lines.append("|" + "|".join("---" for _ in columns) + "|")
    for row in rows:
        lines.append("| " + " | ".join(cell(row.get(k, "")) for k, _ in columns) + " |")
    return "\n".join(lines) + "\n"


def to_json(rows) -> str:
    return json.dumps(rows, indent=2, default=str) + "\n"


def export_text(path: str, rows, columns, title=None) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        return to_csv(rows, columns)
    if ext == ".json":
        return to_json(rows)
    return to_markdown(rows, columns, title=title)


ANSI = {"red": "31", "yellow": "33", "green": "32", "blue": "34", "magenta": "35",
        "bold": "1", "dim": "2", "cyan": "36"}


def color(text, name, enabled=None) -> str:
    if enabled is None:
        enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if not enabled or name not in ANSI:
        return str(text)
    return f"\033[{ANSI[name]}m{text}\033[0m"


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {"critical": "magenta", "high": "red", "medium": "yellow", "low": "blue",
                  "info": "dim"}


def table_text(rows, columns, max_width=60, colorize=None) -> str:
    """Plain aligned table for the terminal. colorize(key, value) can return a color name."""
    if not rows:
        return ""
    def cut(v):
        s = str(v if v is not None else "").replace("\n", " ")
        return s if len(s) <= max_width else s[: max_width - 1] + "…"
    widths = []
    for key, title in columns:
        w = max([len(title)] + [len(cut(r.get(key, ""))) for r in rows])
        widths.append(w)
    head = "  ".join(color(t.ljust(w), "bold") for (_, t), w in zip(columns, widths))
    out = [head]
    for r in rows:
        cells = []
        for (key, _), w in zip(columns, widths):
            text = cut(r.get(key, "")).ljust(w)
            c = colorize(key, r.get(key)) if colorize else None
            cells.append(color(text, c) if c else text)
        out.append("  ".join(cells).rstrip())
    return "\n".join(out)


# =================================================================== exposure

RISKY_PORTS = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
    161: "SNMP", 389: "LDAP", 445: "SMB", 1433: "SQL Server", 1521: "Oracle",
    2049: "NFS", 2375: "Docker API", 2376: "Docker API", 2379: "etcd", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM", 5986: "WinRM", 6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic",
    8086: "InfluxDB", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}
WEB_PORTS = {80, 443}


def open_port_risk(protocol, from_port, to_port) -> tuple:
    """How bad it is to open these ports to the whole internet. Returns (severity, label)."""
    proto = str(protocol if protocol is not None else "-1").lower()
    if proto in ("-1", "all"):
        return "critical", "all traffic"
    if proto in ("icmp", "1", "icmpv6", "58"):
        return "low", "ICMP"
    try:
        fp = int(from_port) if from_port is not None else 0
        tp = int(to_port) if to_port is not None else 65535
    except (TypeError, ValueError):
        fp, tp = 0, 65535
    if fp < 0:
        fp = 0
    if tp < 0:
        tp = 65535
    ports = f"port {fp}" if fp == tp else f"ports {fp}-{tp}"
    if tp - fp >= 1000:
        return "high", f"{proto} {ports}"
    hits = [f"{p} {n}" for p, n in sorted(RISKY_PORTS.items()) if fp <= p <= tp]
    if hits:
        return "high", ", ".join(hits[:4]) + (" and more" if len(hits) > 4 else "")
    if fp == tp and fp in WEB_PORTS:
        return "info", ports
    return "medium", f"{proto} {ports}"


# =================================================================== desktop

@lru_cache(maxsize=None)
def is_wsl() -> bool:
    """True inside Windows Subsystem for Linux."""
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False


def prepare_gtk_env():
    """Runs before GTK loads. WSL usually has no GL or Vulkan driver GTK can use, and
    GTK 4 aborts the whole app when its GL setup fails (Couldn't open libGLESv2.so.2).
    The cairo renderer draws in software and needs neither. Setting GSK_RENDERER
    yourself skips this, for example GSK_RENDERER=ngl awskit once GL works there."""
    if is_wsl() and "GSK_RENDERER" not in os.environ:
        os.environ["GSK_RENDERER"] = "cairo"
        os.environ.setdefault("GDK_DISABLE", "gl,vulkan")


def windows_tool(name: str):
    """Find a Windows program from WSL, even when the Windows PATH isn't shared."""
    found = shutil.which(name)
    if found:
        return found
    for folder in ("/mnt/c/Windows/System32",
                   "/mnt/c/Windows/System32/WindowsPowerShell/v1.0"):
        path = os.path.join(folder, name)
        if os.access(path, os.X_OK):
            return path
    return None


class ClipboardError(Exception):
    pass


CLIP_READ = {
    "wayland": ["wl-paste", "--no-newline", "--type", "text"],
    "xclip": ["xclip", "-selection", "clipboard", "-o"],
    "xsel": ["xsel", "--clipboard", "--output"],
}
CLIP_WRITE = {
    "wayland": ["wl-copy"],
    "xclip": ["xclip", "-selection", "clipboard", "-i"],
    "xsel": ["xsel", "--clipboard", "--input"],
}

# On WSL the Windows clipboard is used directly, since that's where you paste.
# PowerShell is told to send UTF-8 so non-ASCII text isn't mangled.
WINDOWS_READ_SCRIPT = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
                       "$t = Get-Clipboard -Raw; if ($t) { [Console]::Out.Write($t) }")


def clip_backends() -> list:
    """Clipboard tools that can be used here, best first."""
    found = []
    if is_wsl() and windows_tool("clip.exe"):
        found.append("windows")
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy") and shutil.which("wl-paste"):
        found.append("wayland")
    if os.environ.get("DISPLAY"):
        found += [tool for tool in ("xclip", "xsel") if shutil.which(tool)]
    return found


def clip_backend():
    backends = clip_backends()
    if backends:
        return backends[0]
    if os.environ.get("WAYLAND_DISPLAY"):
        raise ClipboardError("Can't reach the clipboard. Install wl-clipboard "
                             "(Fedora: sudo dnf install wl-clipboard).")
    raise ClipboardError("Can't reach the clipboard. Install wl-clipboard on Wayland "
                         "or xclip on X11.")


def _read_windows():
    """The Windows clipboard as text, or None if PowerShell can't be used here."""
    ps = windows_tool("powershell.exe")
    if not ps:
        return None
    try:
        r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", WINDOWS_READ_SCRIPT],
                           capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", errors="replace").lstrip("\ufeff").replace("\r\n", "\n")


def read_clipboard() -> str:
    backends = clip_backends()
    if backends[:1] == ["windows"]:
        text = _read_windows()
        if text is not None:
            return text
        # PowerShell is missing or blocked, so try wl-paste or xclip through WSLg.
        backends = backends[1:]
        if not backends:
            raise ClipboardError("Couldn't read the Windows clipboard: powershell.exe is "
                                 "missing or blocked. Installing wl-clipboard gives a "
                                 "fallback through WSLg.")
    backend = backends[0] if backends else clip_backend()
    try:
        r = subprocess.run(CLIP_READ[backend], capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"Couldn't read the clipboard: {exc}") from exc
    return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else ""


def write_clipboard(text: str):
    backend = clip_backend()
    if backend == "windows":
        # clip.exe only reads Unicode correctly as UTF-16 with a byte order mark,
        # and Windows apps expect CRLF line endings.
        cmd = [windows_tool("clip.exe")]
        data = b"\xff\xfe" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-16-le")
    else:
        cmd = CLIP_WRITE[backend]
        data = text.encode("utf-8")
    try:
        subprocess.run(cmd, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"Couldn't write to the clipboard: {exc}") from exc


def have_pii_redact() -> bool:
    """PII Redact is built into AWS Kit, so Copy redacted is always there."""
    return True


def pii_redact(text: str) -> str:
    """Run text through PII Redact with your PII Redact settings."""
    from . import redact
    out, _, _ = redact.redact(text, redact.options_from(redact.load_config()))
    return out


def notify(title: str, message: str, urgent=False, icon="dialog-information"):
    if not shutil.which("notify-send"):
        return
    cmd = ["notify-send", "-a", APP_NAME, "-i", icon, "-t", "10000"]
    if urgent:
        cmd += ["-u", "critical"]
    try:
        subprocess.run(cmd + [title, message], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass
