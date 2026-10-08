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

VERSION = "1.6.0"
APP_NAME = "AWS Kit"
APP_ID = "io.github.Snowblind019.AwsKit"
PICKER_APP_ID = APP_ID + ".Profiles"
REDACT_APP_ID = APP_ID + ".Redact"
REDACT_SETTINGS_APP_ID = APP_ID + ".RedactSettings"
IMAGE_APP_ID = APP_ID + ".ImageRedact"

if os.environ.get("XDG_CONFIG_HOME"):
    CONFIG_DIR = Path(os.environ["XDG_CONFIG_HOME"]) / "awskit"
elif os.name == "nt":
    CONFIG_DIR = Path(os.environ.get("APPDATA") or Path.home()) / "awskit"
else:
    CONFIG_DIR = Path.home() / ".config" / "awskit"
CONFIG_FILE = CONFIG_DIR / "config.json"
CURRENT_PROFILE_FILE = CONFIG_DIR / "current-profile"

# The draw.io web app (github.com/jgraph/drawio, Apache 2.0) that the installers download.
# Cloud Map draws draw.io's own AWS icons from it. It isn't kept in this repo. The
# installers read these lines, so keep them in this form. Bump all three together.
DRAWIO_VERSION = "32.0.2"
DRAWIO_SHA256 = "3cb8abec8e9bfc7504760c9cdc9194ecf7e8de178aa2a1d668801c32ecf1a1a7"
DRAWIO_URL = f"https://github.com/jgraph/drawio/releases/download/v{DRAWIO_VERSION}/draw.war"
DRAWIO_MARKER = "AWSKIT-DRAWIO-VERSION"

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
    # Account IDs Cloud Map treats as yours when it can't read the org, so a role trusted
    # by one of them isn't flagged as trusting an outside account.
    "known_accounts": [],
    # What the Cloud Map page showed last: snapshot, map type, filters, layers and theme.
    "cloud_map": {},
    # Secrets Scan: last folder, scan mode, and whether account IDs block a commit.
    "secrets_scan": {},
    # Drift: resources to leave out of the comparison, by ID or tag.
    "drift": {},
    # How the windows look: style, colors, accent and text size (see theme.py).
    "appearance": {},
}


# =================================================================== config

def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key, value in data.items():
                if key in cfg:
                    if isinstance(value, type(cfg[key])):
                        cfg[key] = value
                elif isinstance(key, str):
                    # Keys this version doesn't know (a newer AWS Kit's) are kept as they
                    # are, so saving the config here doesn't wipe them.
                    cfg[key] = value
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg: dict) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        write_atomic(CONFIG_FILE, json.dumps(cfg, indent=2) + "\n", mode=0o600)
        return True
    except OSError:
        return False


# =================================================================== files

def _read_umask() -> int:
    """The process umask, read once at startup. os.umask can only be read by setting it,
    which would briefly change it for every thread, so this does that just once."""
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("Umask:"):
                    return int(line.split()[1], 8)
    except (OSError, ValueError, IndexError):
        pass
    mask = os.umask(0o022)
    os.umask(mask)
    return mask


UMASK = _read_umask()


def write_atomic(path, data, mode=None):
    """Write text or bytes to path so a reader never sees half a file.

    The temporary file gets a new random name, created exclusively next to path, so a
    file or link someone planted there can't redirect the write. path itself is then
    replaced, never written through, so a link at path is swapped out rather than
    followed. mode sets the new file's permissions (0o600 for anything secret); by
    default an existing file keeps its permissions and a new one gets the usual ones."""
    import stat
    import tempfile
    path = Path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if mode is None:
        try:
            st = os.lstat(path)
            mode = stat.S_IMODE(st.st_mode) if stat.S_ISREG(st.st_mode) else None
        except OSError:
            mode = None
        if mode is None:
            mode = 0o666 & ~UMASK
    fd, tmp = tempfile.mkstemp(prefix=".awskit-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
        self._loader = None
        self._loader_lock = threading.Lock()

    @property
    def label(self) -> str:
        return self.profile or "default"

    def _session(self):
        sess = getattr(self._local, "session", None)
        if sess is None:
            import boto3
            import botocore.session
            # Every thread's session shares one loader, so each service's API model is
            # read once per scan instead of once per thread. That's most of the CPU a scan
            # uses, and it keeps the window smoother while a scan runs.
            with self._loader_lock:
                if self._loader is None:
                    from botocore.loaders import create_loader
                    self._loader = create_loader()
            # The profile's own settings (endpoint, CA bundle, retries), not whatever
            # AWS_PROFILE says, which may be another profile.
            core = botocore.session.Session(profile=self.profile)
            core.register_component("data_loader", self._loader)
            sess = boto3.Session(aws_access_key_id=self._frozen.access_key,
                                 aws_secret_access_key=self._frozen.secret_key,
                                 aws_session_token=self._frozen.token,
                                 region_name=self.default_region, botocore_session=core)
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


_NUMBER = re.compile(r"^[-+]?\d+(\.\d+)?$")


def csv_cell(value):
    """A value that a spreadsheet won't run as a formula: text starting with = + - @ or a
    tab gets a ' in front (names and tags come from AWS, and anyone can set those)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") \
            and not _NUMBER.match(value):
        return "'" + value
    return value


def to_csv(rows, columns) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([csv_cell(title) for _, title in columns])
    for row in rows:
        writer.writerow([csv_cell(row.get(key, "")) for key, _ in columns])
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


# Control characters and the ones that flip text direction. Names and tags from AWS, a
# Terraform state or a snapshot can hold them, and in a terminal they can move the cursor,
# recolor or hide lines, so terminal output shows them as ?.
_UNSAFE_CHARS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e"
                           "\u2066-\u2069\u2028\u2029]")


def terminal_safe(text) -> str:
    """text with control and text-direction characters shown as ?, newlines and tabs kept."""
    return _UNSAFE_CHARS.sub("?", str(text))


def table_text(rows, columns, max_width=60, colorize=None) -> str:
    """Plain aligned table for the terminal. colorize(key, value) can return a color name."""
    if not rows:
        return ""
    def cut(v):
        s = terminal_safe(str(v if v is not None else "").replace("\n", " ").replace("\t", " "))
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


def data_dir() -> Path:
    """Where the installers put AWS Kit: ~/.local/share/awskit, or %LOCALAPPDATA%\\AWSKit."""
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "AWSKit"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "awskit"


def drawio_dir() -> Path:
    """The downloaded draw.io web app. AWSKIT_DRAWIO points somewhere else."""
    if os.environ.get("AWSKIT_DRAWIO"):
        return Path(os.environ["AWSKIT_DRAWIO"])
    return data_dir() / "drawio"


def drawio_installed(folder=None):
    """The draw.io version unpacked in folder (or the usual place), or "" if it's not there."""
    folder = Path(folder) if folder else drawio_dir()
    if not (folder / "index.html").is_file():
        return ""
    try:
        return (folder / DRAWIO_MARKER).read_text(encoding="ascii").strip() or "unknown"
    except OSError:
        return "unknown"


def windows_tool(name: str):
    """Find a Windows program from WSL, even when the Windows PATH isn't shared. On
    Windows itself, System32 comes first and the current folder is never searched, so a
    program of the same name sitting in it can't be run by mistake."""
    if os.name == "nt":
        root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
        for folder in (os.path.join(root, "System32"),
                       os.path.join(root, "System32", "WindowsPowerShell", "v1.0")):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
        here = os.path.normcase(os.path.abspath(os.getcwd()))
        for folder in os.environ.get("PATH", "").split(os.pathsep):
            folder = folder.strip().strip('"')
            if not folder or not os.path.isabs(folder) or \
                    os.path.normcase(os.path.abspath(folder)) == here:
                continue
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
        return None
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
    if sys.platform == "win32":
        return ["win32"]
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
    if backends == ["win32"]:
        return _win32_read_text()
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
    if backend == "win32":
        _win32_write({13: (text.replace("\r\n", "\n").replace("\n", "\r\n") + "\0")
                      .encode("utf-16-le")})
        return
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


# ---- images on the clipboard, for Image Redact

CLIP_IMAGE_READ = {
    "wayland": ["wl-paste", "--type", "image/png"],
    "xclip": ["xclip", "-selection", "clipboard", "-t", "image/png", "-o"],
}
CLIP_IMAGE_WRITE = {
    "wayland": ["wl-copy", "--type", "image/png"],
    "xclip": ["xclip", "-selection", "clipboard", "-t", "image/png", "-i"],
}


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _windows_path(path: str):
    try:
        r = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def _windows_image(script_for_path, read: bool, png: bytes = b""):
    """Hand an image to or from the Windows clipboard through a temporary PNG file."""
    import tempfile
    ps = windows_tool("powershell.exe")
    if not ps:
        return None
    folder = tempfile.mkdtemp(prefix="awskit-clip-")
    path = os.path.join(folder, "clip.png")
    try:
        if not read:
            with open(path, "wb") as fh:
                fh.write(png)
        win = _windows_path(path)
        if not win:
            return None
        try:
            r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-STA", "-Command",
                                script_for_path(_ps_quote(win))],
                               capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        if not read:
            return b"ok"
        try:
            with open(path, "rb") as fh:
                return fh.read() or None
        except OSError:
            return b""  # PowerShell ran, but there was no image to save
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def read_clipboard_image():
    """The clipboard image as PNG bytes, or None when there isn't one."""
    backends = clip_backends()
    if backends == ["win32"]:
        return _win32_read_image()
    if backends[:1] == ["windows"]:
        data = _windows_image(lambda p: (
            "Add-Type -AssemblyName System.Windows.Forms, System.Drawing; "
            "$i = [Windows.Forms.Clipboard]::GetImage(); "
            f"if ($i) {{ $i.Save({p}, [Drawing.Imaging.ImageFormat]::Png) }}"), read=True)
        if data is not None:
            return data or None
        backends = backends[1:]
    for backend in backends:
        cmd = CLIP_IMAGE_READ.get(backend)
        if not cmd:
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout.startswith(b"\x89PNG"):
            return r.stdout
    return None


def write_clipboard_image(png: bytes):
    """Put a PNG image on the clipboard, in a way that outlives the app that copied it."""
    backends = clip_backends()
    if backends == ["win32"]:
        _win32_write_image(png)
        return
    if backends[:1] == ["windows"]:
        ok = _windows_image(lambda p: (
            "Add-Type -AssemblyName System.Windows.Forms, System.Drawing; "
            f"$i = [Drawing.Image]::FromFile({p}); "
            "[Windows.Forms.Clipboard]::SetImage($i); $i.Dispose()"), read=False, png=png)
        if ok:
            return
        backends = backends[1:]
    for backend in backends:
        cmd = CLIP_IMAGE_WRITE.get(backend)
        if not cmd:
            continue
        try:
            subprocess.run(cmd, input=png, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=True)
            return
        except (OSError, subprocess.SubprocessError):
            continue
    raise ClipboardError("Can't put an image on the clipboard. Install wl-clipboard on Wayland "
                         "or xclip on X11.")


# ---- native Windows clipboard, through the Win32 API

def _win32_api():
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    return ctypes, user32, kernel32


def _win32_open(user32):
    import time
    for _ in range(20):  # another app may have it open for a moment
        if user32.OpenClipboard(None):
            return
        time.sleep(0.05)
    raise ClipboardError("The clipboard is busy. Try again.")


def _win32_write(formats: dict):
    """formats: {clipboard format number: bytes}. Windows owns the memory once it's set."""
    ctypes, user32, kernel32 = _win32_api()
    _win32_open(user32)
    try:
        user32.EmptyClipboard()
        for fmt, data in formats.items():
            handle = kernel32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
            if not handle:
                raise ClipboardError("Couldn't get memory for the clipboard.")
            ptr = kernel32.GlobalLock(handle)
            ctypes.memmove(ptr, data, len(data))
            kernel32.GlobalUnlock(handle)
            if not user32.SetClipboardData(fmt, handle):
                kernel32.GlobalFree(handle)
                raise ClipboardError("Couldn't put that on the clipboard.")
    finally:
        user32.CloseClipboard()


def _win32_read_text() -> str:
    ctypes, user32, kernel32 = _win32_api()
    _win32_open(user32)
    try:
        handle = user32.GetClipboardData(13)  # CF_UNICODETEXT
        if not handle:
            return ""
        ptr = kernel32.GlobalLock(handle)
        try:
            return ctypes.wstring_at(ptr).replace("\r\n", "\n")
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _win32_write_image(png: bytes):
    """Copies as a bitmap, which every Windows app reads, and as PNG for the apps that
    prefer it, like browsers, Teams and Office."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise ClipboardError("Copying images needs Pillow: pip install Pillow") from exc
    buf = io.BytesIO()
    with Image.open(io.BytesIO(png)) as img:
        img.convert("RGB").save(buf, "BMP")
    _, user32, _ = _win32_api()
    png_format = user32.RegisterClipboardFormatW("PNG")
    _win32_write({8: buf.getvalue()[14:], png_format: png})  # CF_DIB is a BMP minus its header


def _win32_read_image():
    try:
        from PIL import Image, ImageGrab
    except ImportError as exc:
        raise ClipboardError("Pasting images needs Pillow: pip install Pillow") from exc
    try:
        grabbed = ImageGrab.grabclipboard()
    except OSError as exc:
        raise ClipboardError(f"Couldn't read the clipboard: {exc}") from exc
    if isinstance(grabbed, list):
        # A file copied in File Explorer comes through as its path.
        for path in grabbed:
            try:
                grabbed = Image.open(path)
                break
            except OSError:
                continue
        else:
            return None
    if grabbed is None:
        return None
    buf = io.BytesIO()
    grabbed.save(buf, "PNG")
    return buf.getvalue()


def have_pii_redact() -> bool:
    """PII Redact is built into AWS Kit, so Copy redacted is always there."""
    return True


def pii_redact(text: str) -> str:
    """Run text through PII Redact with your PII Redact settings."""
    from . import redact
    out, _, _ = redact.redact(text, redact.options_from(redact.load_config()))
    return out


# A Windows toast through Windows PowerShell, which every Windows 10 and 11 machine has.
# It shows under PowerShell's name, since registering an app for toasts needs a shortcut
# with an app ID. Title and text come in through environment variables.
WINDOWS_TOAST_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$t = [Security.SecurityElement]::Escape($env:AWSKIT_TOAST_TITLE)
$m = [Security.SecurityElement]::Escape($env:AWSKIT_TOAST_TEXT)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def _windows_toast(title: str, message: str):
    import base64
    ps = windows_tool("powershell.exe")
    if not ps:
        return
    encoded = base64.b64encode(WINDOWS_TOAST_SCRIPT.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ, AWSKIT_TOAST_TITLE=title[:120], AWSKIT_TOAST_TEXT=message[:400])
    try:
        subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-EncodedCommand", encoded], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        pass


def notify(title: str, message: str, urgent=False, icon="dialog-information"):
    if sys.platform == "win32":
        _windows_toast(title, message)
        return
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
