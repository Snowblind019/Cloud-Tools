"""Profiles: list what's in ~/.aws, track the picked profile, check sign-in, shell hooks."""
from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .common import CONFIG_DIR, CURRENT_PROFILE_FILE, error_text, local_time


def aws_config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config")


def aws_credentials_path() -> Path:
    return Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
                or Path.home() / ".aws" / "credentials")


def _read_ini(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        pass
    return parser


def list_profiles() -> list:
    """Every profile in ~/.aws/config and ~/.aws/credentials, with what we can tell offline."""
    cfg = _read_ini(aws_config_path())
    creds = _read_ini(aws_credentials_path())
    sessions = {}
    profiles = {}

    for section in cfg.sections():
        if section.startswith("sso-session "):
            sessions[section[len("sso-session "):].strip()] = dict(cfg.items(section))
    for section in cfg.sections():
        if section == "default":
            name = "default"
        elif section.startswith("profile "):
            name = section[len("profile "):].strip()
        else:
            continue
        profiles[name] = dict(cfg.items(section))
    for section in creds.sections():
        entry = profiles.setdefault(section, {})
        for key, value in creds.items(section):
            entry.setdefault(key, value)

    out = []
    for name, p in profiles.items():
        kind = "keys"
        account = p.get("sso_account_id", "")
        role = p.get("sso_role_name", "")
        session = p.get("sso_session", "")
        start_url = p.get("sso_start_url", "")
        if session or start_url:
            kind = "sso"
            if session and session in sessions:
                start_url = sessions[session].get("sso_start_url", start_url)
        elif p.get("role_arn"):
            kind = "role"
            m = re.match(r"arn:aws[\w-]*:iam::(\d{12}):role/(.+)", p["role_arn"])
            if m:
                account, role = m.group(1), m.group(2).split("/")[-1]
        elif p.get("credential_process"):
            kind = "process"
        elif p.get("web_identity_token_file"):
            kind = "web identity"
        elif not p.get("aws_access_key_id"):
            kind = "settings only"
        out.append({
            "name": name,
            "kind": kind,
            "account": account,
            "role": role,
            "region": p.get("region", ""),
            "sso_session": session,
            "sso_start_url": start_url,
            "source_profile": p.get("source_profile", ""),
            "mfa": bool(p.get("mfa_serial")),
        })
    out.sort(key=lambda x: (x["name"] != "default", x["name"].lower()))
    return out


def profile_names() -> list:
    return [p["name"] for p in list_profiles()]


# --------------------------------------------------------------- current profile

def current_profile():
    """The profile picked in awskit, else AWS_PROFILE, else default if it exists."""
    try:
        text = CURRENT_PROFILE_FILE.read_text(encoding="utf-8").strip()
        if text:
            return text
        return None  # an empty file means "no profile, use the default chain"
    except OSError:
        pass
    env = os.environ.get("AWS_PROFILE") or os.environ.get("AWS_DEFAULT_PROFILE")
    if env:
        return env
    return "default" if "default" in profile_names() else None


def set_current_profile(name):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CURRENT_PROFILE_FILE.write_text((name or "") + "\n", encoding="utf-8")


# --------------------------------------------------------------- sign-in status

def _sso_cache_dir() -> Path:
    return Path.home() / ".aws" / "sso" / "cache"


def _parse_expiry(text):
    if not text:
        return None
    text = text.replace("UTC", "+00:00").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def sso_expiry(profile: dict):
    """When the cached SSO token for a profile expires, read from ~/.aws/sso/cache. No API call."""
    if profile.get("kind") != "sso":
        return None
    keys = []
    if profile.get("sso_session"):
        keys.append(profile["sso_session"])
    if profile.get("sso_start_url"):
        keys.append(profile["sso_start_url"])
    for key in keys:
        path = _sso_cache_dir() / (hashlib.sha1(key.encode("utf-8")).hexdigest() + ".json")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        dt = _parse_expiry(data.get("expiresAt"))
        if dt:
            return dt
    return None


def offline_status(profile: dict) -> str:
    """A quick status from local files only, for listing many profiles at once."""
    if profile.get("kind") != "sso":
        return ""
    exp = sso_expiry(profile)
    if exp is None:
        return "not signed in"
    if exp <= datetime.now(timezone.utc):
        return "expired"
    return "signed in until " + local_time(exp)[11:16]


def check_profile(name) -> dict:
    """Call sts get-caller-identity for a profile. Returns status, account, arn, message."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        return {"status": "error", "message": "boto3 is missing"}
    try:
        sess = boto3.Session(profile_name=name or None)
        sts = sess.client("sts", config=Config(connect_timeout=5, read_timeout=10,
                                               retries={"max_attempts": 2}))
        ident = sts.get_caller_identity()
        return {"status": "ok", "account": ident.get("Account", ""),
                "arn": ident.get("Arn", ""), "message": "signed in"}
    except Exception as exc:  # noqa: BLE001
        msg = error_text(exc, name)
        status = "expired" if ("expired" in msg.lower() or "sso login" in msg) else "error"
        return {"status": status, "message": msg}


def sso_login(name, timeout=600) -> tuple:
    """Run aws sso login for a profile. Opens the browser. Returns (ok, message)."""
    aws = shutil.which("aws")
    if not aws:
        return False, ("The AWS CLI isn't installed, and it's needed for SSO sign-in. "
                       "Fedora: sudo dnf install awscli2")
    try:
        r = subprocess.run([aws, "sso", "login", "--profile", name], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "Sign-in timed out."
    except OSError as exc:
        return False, str(exc)
    if r.returncode == 0:
        return True, f"Signed in to {name}."
    text = (r.stderr or r.stdout or "").strip().splitlines()
    return False, text[-1] if text else "aws sso login failed."


# --------------------------------------------------------------- shell hooks

BASH_HOOK = r'''# awskit shell integration for bash and zsh.
# Keeps AWS_PROFILE in step with the profile picked in awskit (window or awsp).
__awskit_sync() {
  local f="${XDG_CONFIG_HOME:-$HOME/.config}/awskit/current-profile"
  [ -f "$f" ] || return 0
  local p
  p="$(cat "$f" 2>/dev/null)"
  if [ "$p" != "${__AWSKIT_LAST-__awskit_unset__}" ]; then
    __AWSKIT_LAST="$p"
    if [ -n "$p" ]; then export AWS_PROFILE="$p"; else unset AWS_PROFILE; fi
  fi
}
# Prints "(aws:name) " when a profile is active. Add $(__awskit_ps1) to PS1 to show it.
__awskit_ps1() { [ -n "${AWS_PROFILE:-}" ] && printf '(aws:%s) ' "$AWS_PROFILE"; }
# awsp            open the picker window
# awsp NAME       switch to NAME
# awsp --clear    go back to no profile
awsp() { command awskit profile "$@" && __awskit_sync; }
if [ -n "${ZSH_VERSION:-}" ]; then
  autoload -Uz add-zsh-hook && add-zsh-hook precmd __awskit_sync
else
  case ";${PROMPT_COMMAND:-};" in
    *";__awskit_sync;"*) ;;
    *) PROMPT_COMMAND="__awskit_sync${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
  esac
fi
__awskit_sync
'''

FISH_HOOK = r'''# awskit shell integration for fish.
# Keeps AWS_PROFILE in step with the profile picked in awskit (window or awsp).
function __awskit_sync --on-event fish_prompt
    set -l base $HOME/.config
    set -q XDG_CONFIG_HOME; and set base $XDG_CONFIG_HOME
    set -l f $base/awskit/current-profile
    test -f $f; or return 0
    set -l p (cat $f 2>/dev/null)
    if not set -q __awskit_last; or test "$p" != "$__awskit_last"
        set -g __awskit_last "$p"
        if test -n "$p"
            set -gx AWS_PROFILE $p
        else
            set -e AWS_PROFILE
        end
    end
end
# Prints "(aws:name) " when a profile is active, for use in fish_prompt.
function __awskit_prompt
    set -q AWS_PROFILE; and printf '(aws:%s) ' $AWS_PROFILE
end
function awsp
    command awskit profile $argv; and __awskit_sync
end
__awskit_sync
'''


def shell_hook(shell: str) -> str:
    shell = (shell or "bash").lower()
    if shell == "fish":
        return FISH_HOOK
    if shell in ("bash", "zsh", "sh"):
        return BASH_HOOK
    raise ValueError("Supported shells: bash, zsh, fish")
