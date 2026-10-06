"""Secrets Scan: finds AWS keys, tokens, private keys and passwords before they get into a
git repo, and installs a git pre-commit hook that stops them.

The patterns come from PII Redact (redact.py). A thin adapter here runs PII Redact's rules
and keeps which rule matched, then decides what each match is: a real secret that should
stop a commit (block), something worth a look (warn), or a placeholder like changeme or
${VAR} that isn't a secret at all. Everything runs locally: no AWS calls, no network.

The window is in secrets_page.py. Run `awskit secrets --help` for the command line.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from itertools import accumulate
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from . import redact as pii
from .common import load_config, save_config, write_atomic

CONFIG_KEY = "secrets_scan"
DEFAULT_SETTINGS = {"folder": "", "mode": "staged", "history_commits": 200,
                    "block_account_ids": False}
ALLOW_FILE = ".awskit-secrets-allow"
ALLOW_MARKER = "awskit:allow"
HOOK_MARKER = "awskit-secrets-hook"
CHAINED_HOOK = "pre-commit.before-awskit"
MAX_FILE = 2 * 1024 * 1024
MAX_LINE = MAX_FILE + 1024  # one line of git output, at most
DEFAULT_HISTORY = 200
GIT_TIMEOUT = 30          # small git calls
GIT_SCAN_TIMEOUT = 900    # a long git log -p
CONTEXT_LINES = 3

MODES = {"staged": "Staged changes", "all": "All files", "history": "Git history",
         "files": "Folder, not git"}

# Folders a plain folder scan skips: other people's code, caches and downloaded providers.
# A git scan doesn't need this, since it only looks at files git tracks or would track.
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".terraform", ".venv", "venv",
             "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache",
             ".gradle", ".eggs"}

# git -c settings for every call. A repo's own .git/config can name programs for git to
# run (core.fsmonitor, diff.external, textconv, a pager, gpg for signatures), and a
# cloned repo is someone else's file, so those are switched off. Prefixes and colors are
# pinned so the diff can be read the same way whatever the repo sets.
GIT_SAFE = ["-c", "core.quotepath=off", "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
            "-c", "color.ui=false", "-c", "log.showSignature=false", "-c", "log.showRoot=true",
            "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
            "-c", "diff.relative=false"]
DIFF_ARGS = ["-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--text", "-M",
             "--src-prefix=a/", "--dst-prefix=b/"]


class ScanError(Exception):
    """The scan couldn't run. The message says why in plain words."""


class HookError(Exception):
    """The hook couldn't be installed or removed. The message says why."""


# =================================================================== kinds

# kind: (what it's called, level, specific format?, how it's masked, which fix text)
# Specific formats (AKIA keys, ghp_ tokens) win over generic ones (a password setting)
# when two matches overlap.
KINDS = {
    "aws_access_key": ("AWS access key ID", "block", True, "edge", "aws_key"),
    "aws_secret_key": ("AWS secret access key", "block", True, "edge", "aws_key"),
    "aws_secret_maybe": ("Possible AWS secret key", "warn", True, "edge", "aws_key"),
    "aws_session_token": ("AWS session token", "block", True, "edge", "session"),
    "presigned_token": ("Session token in a presigned URL", "block", True, "edge", "session"),
    "bedrock_key": ("Amazon Bedrock API key", "block", True, "edge", "bedrock"),
    "signed_url": ("Signed URL signature", "warn", True, "edge", "signed_url"),
    "private_key": ("Private key", "block", True, "key", "private_key"),
    "github_token": ("GitHub token", "block", True, "edge", "github"),
    "gitlab_token": ("GitLab token", "block", True, "edge", "service"),
    "slack_token": ("Slack token", "block", True, "edge", "slack"),
    "slack_webhook": ("Slack webhook URL", "block", True, "edge", "slack"),
    "npm_token": ("npm token", "block", True, "edge", "service"),
    "pypi_token": ("PyPI token", "block", True, "edge", "service"),
    "openai_key": ("OpenAI API key", "block", True, "edge", "service"),
    "anthropic_key": ("Anthropic API key", "block", True, "edge", "service"),
    "google_api_key": ("Google API key", "warn", True, "edge", "google"),
    "stripe_live": ("Stripe live key", "block", True, "edge", "service"),
    "stripe_test": ("Stripe test key", "warn", True, "edge", "service"),
    "terraform_token": ("Terraform Cloud token", "block", True, "edge", "service"),
    "jwt": ("JWT", "warn", True, "edge", "jwt"),
    "auth_header": ("Authorization header", "block", False, "hidden", "secret"),
    "url_password": ("Password in a URL", "block", False, "hidden", "password"),
    "password": ("Password", "block", False, "hidden", "password"),
    "secret": ("Secret in a setting", "block", False, "hidden", "secret"),
    "token": ("Token in a setting", "block", False, "hidden", "secret"),
    "api_key": ("API key in a setting", "block", False, "hidden", "secret"),
    "account_id": ("AWS account ID", "warn", True, "partial", "account_id"),
    "internal_ip": ("Internal IP address", "warn", True, "partial", "internal_ip"),
    "email": ("Email address", "warn", True, "partial", "email"),
}

FIXES = {
    "aws_key": "Take it out of the file. Keep keys in ~/.aws/credentials, or better, use aws "
               "sso login or a role, and let code read them from the environment. If this key "
               "was ever pushed or shared, treat it as leaked: in IAM, make it inactive, create "
               "a new key if you still need one, then delete the old one.",
    "session": "Take it out of the file. Temporary credentials stop working when they expire, "
               "usually within hours. If it was pushed while still valid, use Revoke active "
               "sessions on the role in IAM.",
    "bedrock": "Take it out of the file and set AWS_BEARER_TOKEN_BEDROCK in your environment "
               "instead. A long-term key (ABSK...) belongs to an IAM user: if it was pushed or "
               "shared, delete it in IAM under that user's API keys for Amazon Bedrock. A "
               "short-term key (bedrock-api-key-...) works until it expires, at most 12 hours.",
    "signed_url": "A signed URL works for anyone who has it until it expires. Take it out and "
                  "make a new link when you need one.",
    "private_key": "Take the key out of the repo and make a new key pair. Swap the public key "
                   "wherever the old one is trusted (servers, GitHub, EC2 key pairs), then "
                   "delete the old one. Keep private keys in ~/.ssh or a secrets manager.",
    "github": "Revoke it in GitHub (Settings, Developer settings, or the app's settings) and "
              "make a new one. Read it from an environment variable, and use secrets in "
              "GitHub Actions.",
    "slack": "Revoke it in the Slack app's settings, or make a new webhook, and read it from "
             "an environment variable instead.",
    "service": "Revoke it in that service's settings, make a new one, and read it from an "
               "environment variable or a secrets manager instead.",
    "google": "Google API keys are sometimes meant to be public (Firebase web apps), but they "
              "should be restricted to your app in the Google Cloud console. If this one "
              "isn't, make a new restricted key and delete it.",
    "jwt": "A JWT works as a login until it expires. If it's a real one, take it out and use "
           "test tokens that are clearly fake.",
    "password": "Move it out of the file: an environment variable, a .env file listed in "
                ".gitignore, or AWS Secrets Manager or SSM Parameter Store (SecureString). If it "
                "was ever pushed, change the password.",
    "secret": "Move it out of the file: an environment variable, a .env file listed in "
              ".gitignore, or AWS Secrets Manager or SSM Parameter Store. If it was ever "
              "pushed, make a new one and retire the old one.",
    "account_id": "Account IDs aren't secret, but they help someone aim at your account. Fine "
                  "in a private repo. In a public one, read it from a variable, or use "
                  "data.aws_caller_identity in Terraform.",
    "internal_ip": "Shows part of your internal network. Fine in lab code. For anything real, "
                   "read it from a variable.",
    "email": "Fine if it's meant to be public. Otherwise take it out.",
}

ALLOW_HELP = ("Not a secret? Add awskit:allow in a comment on that line, or press Allow this "
              "(awskit secrets --allow FILE:LINE in the terminal) to add its sha256 to "
              f"{ALLOW_FILE}.")

LEVEL_ORDER = {"block": 0, "warn": 1}


# =================================================================== findings

@dataclass
class Finding:
    level: str
    kind: str
    what: str
    path: str
    line: int
    column: int
    preview: str
    length: int = 0
    note: str = ""
    allowed: str = ""
    context: str = ""
    commit: str = ""
    commit_date: str = ""
    commit_subject: str = ""
    occurrences: int = 1
    still_in_files: Optional[bool] = None
    # sha256 of the value, for the allow file. The value itself is never kept.
    value_hash: str = field(default="", repr=False)

    @property
    def fix(self) -> str:
        return FIXES.get(KINDS.get(self.kind, ("", "", False, "", "secret"))[4], FIXES["secret"])

    @property
    def where(self) -> str:
        return f"{self.path}:{self.line}"

    @property
    def short_preview(self) -> str:
        """The preview without the length, for table columns. The length stays for values
        that are all stars."""
        if self.preview.startswith("*"):
            return self.preview
        head = re.match(r"-----BEGIN (.+?)-----", self.preview)
        if head:  # OPENSSH PRIVATE KEY
            return head.group(1)
        return re.sub(r" \([\d,]+ characters\)$", "", self.preview)

    def row(self) -> dict:
        return {"level": "high" if self.level == "block" else "low",
                "level_name": self.level, "level_rank": LEVEL_ORDER.get(self.level, 9),
                "file": self.path, "line": self.line, "what": self.what,
                "preview": self.short_preview, "commit": self.commit[:8]}

    def as_dict(self) -> dict:
        d = {"level": self.level, "kind": self.kind, "what": self.what, "file": self.path,
             "line": self.line, "column": self.column, "preview": self.preview,
             "length": self.length}
        for key in ("note", "allowed", "commit", "commit_date"):
            if getattr(self, key):
                d[key] = getattr(self, key)
        if self.commit:
            d["occurrences"] = self.occurrences
            if self.still_in_files is not None:
                d["still_in_files"] = self.still_in_files
        return d

    def detail_text(self) -> str:
        lines = [f"[{self.level.upper()}] {self.what}", f"File: {self.path}, line {self.line}"]
        if self.commit:
            when = f" ({self.commit_date})" if self.commit_date else ""
            lines.append(f"Commit: {self.commit[:12]}{when} {self.commit_subject}".rstrip())
            if self.occurrences > 1:
                lines.append(f"Added in {self.occurrences} commits. This is the first one.")
        lines.append(f"Value: {self.preview}")
        if self.note:
            lines.append(self.note)
        if self.allowed:
            lines.append(f"Allowed by {self.allowed}.")
        if self.context:
            lines += ["", self.context]
        lines += ["", "How to fix", self.fix]
        if self.commit:
            if self.still_in_files is False:
                lines.append("It's gone from the files now, but it's still in git history, so "
                             "anyone with a clone can read it.")
            lines.append(f"This was added in commit {self.commit[:12]}. Removing it now doesn't "
                         "take it out of history, so rotate it if it's real. Rewriting history "
                         "(git filter-repo) only helps if nobody else has a copy yet.")
        if self.level == "block" or self.kind not in ("account_id", "internal_ip", "email"):
            lines += ["", ALLOW_HELP]
        return "\n".join(lines)


@dataclass
class ScanResult:
    mode: str
    root: str
    target: str
    findings: list = field(default_factory=list)
    allowed: list = field(default_factory=list)
    scanned: int = 0
    unit: str = "files"
    notes: list = field(default_factory=list)
    # The notes about files that couldn't be checked at all (binary, too big, unreadable),
    # which the commit hook shows too
    unchecked: list = field(default_factory=list)
    examples: int = 0
    is_git: bool = False
    cancelled: bool = False

    def counts(self) -> dict:
        return {"block": sum(1 for f in self.findings if f.level == "block"),
                "warn": sum(1 for f in self.findings if f.level == "warn"),
                "allowed": len(self.allowed)}

    def summary(self) -> str:
        c = self.counts()
        parts = []
        if c["block"]:
            parts.append(f"{c['block']} to fix")
        if c["warn"]:
            parts.append(f"{c['warn']} warning" + ("" if c["warn"] == 1 else "s"))
        if c["allowed"]:
            parts.append(f"{c['allowed']} allowed")
        unit = self.unit
        if self.scanned == 1 and unit.endswith("s"):
            unit = unit[:-1]
        head = f"Scanned {self.scanned} {unit}"
        if self.cancelled:
            head = "Stopped early. " + head
        return head + (", " + ", ".join(parts) if parts else ", nothing found") + "."

    def exit_code(self) -> int:
        return 1 if any(f.level == "block" for f in self.findings) else 0

    def as_dict(self) -> dict:
        return {"mode": self.mode, "root": self.root, "target": self.target,
                "scanned": self.scanned, "unit": self.unit, "counts": self.counts(),
                "summary": self.summary(), "findings": [f.as_dict() for f in self.findings],
                "allowed": [f.as_dict() for f in self.allowed],
                "examples_skipped": self.examples, "notes": list(self.notes),
                "stopped_early": self.cancelled}


# =================================================================== masking

def value_hash(value: str) -> str:
    """sha256 of a value, the same on Windows and Linux checkouts."""
    norm = value.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(norm.encode("utf-8", "surrogatepass")).hexdigest()


def _edge(value, show=4, cap=16) -> str:
    hidden = len(value) - 2 * show
    return value[:show] + "*" * min(hidden, cap) + value[-show:]


def _partial(value: str, kind: str) -> str:
    """Warnings aren't secrets, so enough shows to recognize them: an IP's network part,
    an email's domain, an account ID's ends."""
    if kind == "internal_ip":
        if "." in value and ":" not in value:
            return ".".join(value.split(".")[:2]) + ".*.*"
        return value.split(":")[0] + ":****"
    if kind == "email" and "@" in value:
        local, _, domain = value.partition("@")
        return local[:1] + "***@" + domain
    n = len(value)
    if n >= 12:
        return _edge(value, 4, 64)
    return _edge(value, 2, 64) if n >= 8 else "*" * n


def mask_value(value: str, kind: str) -> str:
    """The preview shown for a finding. Never the whole value."""
    n = len(value)
    style = KINDS.get(kind, ("", "", False, "hidden"))[3]
    if style == "key":
        # Only the BEGIN marker, never the rest of its line: a key flattened onto one line
        # has its whole body there.
        head = PEM_HEADER.match(value)
        if not head or "BEGIN" not in head.group():
            return _edge(value) + f" ({n:,} characters)" if n >= 16 else "*" * n
        return f"{head.group().strip()} ({n:,} characters)"
    if kind == "slack_webhook" and n > 40:
        return value[:24] + "****" + value[-4:] + f" ({n} characters)"
    if style == "edge" and n >= 16:
        out = _edge(value)
        return out + (f" ({n} characters)" if n - 8 > 16 else "")
    if style == "partial":
        return _partial(value, kind)
    return f"******** ({n} characters)"


def mask_inline(value: str, kind: Optional[str]) -> str:
    """How a value looks inside the context lines."""
    style = KINDS.get(kind, ("", "", False, "hidden"))[3] if kind else "hidden"
    if kind == "slack_webhook" and len(value) > 40:
        return value[:24] + "****" + value[-4:]
    if style == "edge" and len(value) >= 16:
        return _edge(value)
    if style == "partial":
        return _partial(value, kind)
    return "********"


# =================================================================== value checks

PLACEHOLDER_EXACT = {
    "changeme", "change_me", "change-me", "changethis", "changeit_please", "replaceme",
    "replace_me", "replace-me", "example", "examples", "sample", "placeholder", "dummy",
    "fake", "test", "testing", "todo", "tbd", "fixme", "none", "null", "nil", "undefined",
    "empty", "string", "str", "text", "value", "secret", "secrets", "password", "passwd",
    "pass", "pwd", "token", "apikey", "api_key", "api-key", "key", "redacted", "hidden",
    "masked", "notset", "not_set", "not-set", "unset", "default", "required", "optional",
    "true", "false", "yes", "no", "on", "off", "n/a", "na", "your_password",
    "yourpassword", "your-password", "your_secret", "your_token", "your_api_key", "mypassword",
    "my_password", "mysecret", "secretkey", "secret_key", "password1", "enabled", "disabled",
    "basic", "bearer", "oauth", "oauth2", "iam", "aws_iam", "jwt", "none_set", "sensitive",
    "sha256", "md5", "bcrypt", "plain", "plaintext", "int", "bool", "boolean", "number", "any",
    "object", "bytes", "secretstr", "optional[str]",
}
PLACEHOLDER_RE = re.compile(
    r"""^(.)\1*$"""                              # one character over and over: xxxx, ****
    r"""|[*•●]{3}|\.\.\.|…"""     # masked, or cut short like AKIA...
    r"""|^\$[A-Za-z_][A-Za-z0-9_]*$"""
    r"""|%\([\w.-]+\)[sd]|%s\b|^%[A-Za-z_][\w]*%$"""
    r"""|^<[^<>]+>$|^\[[^\[\]]+\]$|^\{[\w.-]*\}$|^\(\s*sensitive|^@@?[\w.-]+@@?$|^__[\w-]+__$"""
    r"""|^ENC\[|^\$ANSIBLE_VAULT|^!!?\w+(?:\s|$)|^\{\{resolve:"""   # YAML tags: !vault |, !Ref X
    r"""|^(?:vault|ssm|secretsmanager|secret|env|file|keyring|op|sops|awskms|gcpkms|azurekv):""",
    re.I)
# Templates and commands: ${VAR}, $(cat file), {{ var }}, {% x %}, <%= x %>, #{x}. Only
# with their closing part, since a random password can have ${ or <% in it too.
TEMPLATE_PAIRS = (("${", "}"), ("$(", ")"), ("{{", "}}"), ("{%", "%}"), ("<%", "%>"),
                  ("#{", "}"))
PLACEHOLDER_WORDS = {"your", "yours", "insert", "placeholder", "changeme", "replaceme",
                     "redacted", "example", "todo", "fixme", "tbd", "xxx", "xxxx", "xxxxx"}
WEAK_LETTERS = ("password", "passwd", "secret", "changeit", "test", "dummy", "fake", "sample",
                "demo", "example", "local", "default", "admin", "root", "guest", "letmein",
                "qwerty", "welcome", "postgres", "mysql", "mariadb", "redis", "mongo",
                "rabbit", "minio", "elastic", "docker", "hunter", "dev", "temp", "mock",
                "insecure")
WEAK_WORDS = {"test", "testing", "tests", "dummy", "fake", "sample", "demo", "example", "dev",
              "local", "localhost", "mock", "temp", "tmp", "changeme", "insecure", "secret",
              "password", "default", "notreal", "foo", "bar"}
REFERENCE_RE = re.compile(
    r"""^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"""            # an environment variable's name
    r"""|^(?:env|ENV|process\.env|os\.environ|os\.getenv|System\.getenv|getenv|config|"""
    r"""settings|secrets|vars|var|local|params|args|options|opts|self|this|props|ctx)[.\[(:]"""
    r"""|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$"""
    # code: typing.Optional[...], f(x), os.environ["X"]. It has to end like code too, since
    # plenty of random passwords start with letters and a ( or [.
    r"""|^[A-Za-z_][\w.]*[\[(][^\n]*[\])](?:\.\w+)*[,;]?$""")
HASH_RE = re.compile(r"^\$2[abxy]?\$\d\d\$|^\$(?:1|5|6|y|argon2\w*|pbkdf2[\w-]*|scrypt)\$"
                     r"|^\{(?:SSHA|SHA|SMD5|MD5|CRYPT|BCRYPT)\}|^(?:sha1|sha256|sha512|md5):",
                     re.I)
FILE_RE = re.compile(r"^[\w.-]+\.(?:pem|key|crt|cer|p12|pfx|jks|json|ya?ml|txt|env|ini|conf|"
                     r"cfg|toml|properties|gpg|asc|enc|der|ppk|pub)$", re.I)
TEXT_RE = re.compile(r"^[A-Za-z][A-Za-z ,.!?'’:;()\-]*$")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{12}")


def _words(value) -> list:
    return [w for w in re.split(r"[^a-z0-9]+", value.lower()) if w]


def identifier_like(v: str) -> bool:
    """A name written in CamelCase, like ExclusiveStartBackupArn or
    AwsS3BucketServerSideEncryptionByDefault: mostly whole words, which random keys aren't."""
    if not re.fullmatch(r"[A-Za-z0-9_]+", v) or not re.search(r"[a-z]", v) \
            or not re.search(r"[A-Z]", v):
        return False
    covered = sum(len(w) for w in re.findall(r"[A-Z]?[a-z]{2,}", v))
    return covered >= 0.75 * len(v.replace("_", ""))


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'`")
    if not v or v.lower() in PLACEHOLDER_EXACT or PLACEHOLDER_RE.search(v):
        return True
    for opener, closer in TEMPLATE_PAIRS:
        at = v.find(opener)
        if at >= 0 and v.find(closer, at + len(opener)) >= 0:
            return True
    if "EXAMPLE" in v or re.match(r"<\w[^<>]*>", v):
        return True  # AWS's docs mark made-up values with EXAMPLE; <code> is markup
    words = _words(v)
    if set(words) & PLACEHOLDER_WORDS:
        return True
    if ("change" in words or "replace" in words or "put" in words or "enter" in words) and \
            ("me" in words or "here" in words or "this" in words or "your" in words):
        return True
    if "here" in words and len(words) >= 2:
        return True
    return False


def _classes(v) -> int:
    return (any(c.islower() for c in v) + any(c.isupper() for c in v)
            + any(c.isdigit() for c in v) + any(not c.isalnum() for c in v))


def _path_like(v) -> bool:
    # Starts like a path and has only the characters paths are made of: a random password
    # can start with / too.
    if (v.startswith(("/", "./", "../", "~/", "~\\", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", v)) \
            and re.fullmatch(r"[\w.\-/\\~:@+ ()]+", v):
        return True
    if FILE_RE.match(v):
        return True
    if ("/" in v or "\\" in v) and re.fullmatch(r"[\w.\-/\\]+", v):
        segs = [s for s in re.split(r"[/\\]", v) if s]
        return bool(segs) and all(re.fullmatch(r"[A-Za-z0-9_.-]*", s) and
                                  (s == s.lower() or s == s.upper() or
                                   re.fullmatch(r"[A-Z]?[a-z0-9_.-]*", s)) for s in segs)
    return False


def _url_like(v) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I))


def _text_like(v) -> bool:
    return " " in v.strip() and bool(TEXT_RE.match(v.strip()))


def is_weak_password(v: str) -> bool:
    """A default, demo or test password, or a single plain word."""
    if v.isdigit() or len(set(v.lower())) <= 3:
        return True
    if re.fullmatch(r"[a-z]+", v) and len(v) <= 12:
        return True
    if set(_words(v)) & WEAK_WORDS:
        return True
    if len(v) <= 20 and pii.entropy(v) < 3.8:
        leet = v.lower().translate(str.maketrans("013457@$!", "oleastasi"))
        letters = re.sub(r"[^a-z]", "", leet)
        if any(w in letters for w in WEAK_LETTERS):
            return True
    return False


def password_level(value: str, key_norm: str = "") -> Optional[str]:
    """block, warn or None (not a password at all) for a password-like setting's value."""
    v = value.strip()
    if is_placeholder(v) or len(v) < 6:
        return None
    if key_norm and re.sub(r"[^a-z0-9]", "", v.lower()) == key_norm:
        return None  # password = password, a name not a value
    if REFERENCE_RE.match(v) or HASH_RE.match(v) or _path_like(v) or _url_like(v) \
            or _text_like(v):
        return None
    return "warn" if is_weak_password(v) or identifier_like(v) else "block"


def generic_level(value: str) -> Optional[str]:
    """block, warn or None for a secret, token or API key setting's value. These need to
    look random, since names like secret and token turn up in all kinds of settings."""
    v = value.strip()
    if is_placeholder(v) or len(v) < 8 or re.search(r"\s", v):
        return None  # keys and tokens never have spaces: that's text or an expression
    if REFERENCE_RE.match(v) or HASH_RE.match(v) or _path_like(v) or _url_like(v):
        return None
    if re.fullmatch(r"[A-Za-z]+(?:[-_.][A-Za-z]+)+", v) or re.fullmatch(r"[\d.]+", v) \
            or identifier_like(v):
        return None  # a name (db-password-secret, NextToken), or a version
    weak = bool(set(_words(v)) & WEAK_WORDS)
    classes, ent = _classes(v), pii.entropy(v)
    if len(v) >= 16 and classes >= 2 and ent >= 3.2:
        if UUID_RE.fullmatch(v):
            return "warn"  # usually an ID (a request, a client token), sometimes a key
        return "warn" if weak else "block"
    if classes >= 2 and ent >= 2.5:
        return "warn"
    if re.fullmatch(r"[A-Za-z]+", v) and len(v) >= 12:
        return "warn"  # supersecretkey
    return None


def _fake_token(body: str) -> bool:
    """The changing part of a known token format looks made up: ghp_xxxx, 0123456..."""
    if len(set(body.lower())) <= 4:
        return True
    return bool(re.search(r"(?i)x{4,}|0{6,}|your|example|placeholder|insert|dummy|fake|"
                          r"redacted|0123456|1234567|abcdefg|qwerty|asdfgh|zxcvbn", body))


# =================================================================== files

TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__", "testdata", "test-data",
             "test_data", "fixtures", "fixture", "__fixtures__", "mocks", "__mocks__"}
DOC_DIRS = {"docs", "doc", "documentation", "examples", "example", "samples", "sample"}
DOC_EXT = {".md", ".markdown", ".rst", ".adoc", ".asciidoc"}
DOC_NAME_PARTS = {"example", "examples", "sample", "samples", "template", "dist"}
# In code, a secret written into the file is always a quoted string. Unquoted values are
# variables and calls (password=args.password), so only quoted ones count there. In .env,
# YAML, INI, shell and similar files, unquoted values are the literal value.
CODE_EXT = {".py", ".pyw", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go",
            ".java", ".kt", ".kts", ".scala", ".groovy", ".gradle", ".rb", ".php", ".cs",
            ".fs", ".vb", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".swift", ".m", ".mm",
            ".dart", ".lua", ".pl", ".pm", ".r", ".jl", ".ex", ".exs", ".erl", ".clj", ".vue",
            ".svelte", ".tf", ".tfvars", ".hcl", ".ps1", ".psm1", ".sql"}
EMAIL_SKIP_NAMES = {"license", "licence", "copying", "authors", "contributors", "codeowners",
                    ".mailmap", "notice", "maintainers", "security", "code_of_conduct",
                    "package.json", "setup.py", "setup.cfg", "pyproject.toml", "cargo.toml",
                    "composer.json", "pom.xml", "citation.cff", "changelog", "changes",
                    "history", "news", "metadata", "pkg-info"}
EMAIL_SKIP_DOMAINS = {"example.com", "example.org", "example.net", "test.com", "email.com",
                      "domain.com", "company.com", "mail.com", "localhost", "yourdomain.com",
                      "yourcompany.com", "acme.com", "corp.com"}


@dataclass
class FileRole:
    code: bool = False
    test: bool = False
    docs: bool = False
    name: str = ""


def file_role(path: str) -> FileRole:
    parts = [p for p in re.split(r"[/\\]", path or "") if p]
    name = parts[-1].lower() if parts else ""
    dirs = {p.lower() for p in parts[:-1]}
    ext = os.path.splitext(name)[1]
    test = bool(dirs & TEST_DIRS) or bool(
        re.match(r"^(?:test_.+|.+_test|.+\.(?:test|spec)|conftest)\.[a-z0-9]+$", name))
    # .env.example, config.sample.yml, settings.php.dist, examples-1.json
    parts = set(re.split(r"[._-]+", name))
    docs = ext in DOC_EXT or bool(dirs & DOC_DIRS) or bool(parts & DOC_NAME_PARTS)
    return FileRole(code=ext in CODE_EXT, test=test, docs=docs, name=name)


# =================================================================== detection

@dataclass
class Candidate:
    start: int
    end: int
    kind: str
    level: str
    value: str
    note: str = ""
    what: str = ""
    example: bool = False

    @property
    def specific(self) -> bool:
        return KINDS[self.kind][2]


def _rule_kind(rule) -> Optional[str]:
    """Which of PII Redact's rules this tool uses, and as what."""
    pat = rule.regex.pattern
    cat, label = rule.cat, rule.label
    if cat == "private_keys":
        return "private_key"
    if cat == "tokens":
        if rule.check is pii.long_token_check:
            return None  # any long random string: too noisy in a repo (images, fonts)
        if label == "JWT":
            return "jwt"
        if "Authorization" in pat:
            return "auth_header"
        if "atlasv1" in pat:
            return "terraform_token"
        return "named_token"
    if cat == "aws_keys":
        if label == "AccessKey":
            return None if "Credential" in pat else "aws_access_key"
        if label == "SessionToken":
            return "presigned_token" if "Security-Token" in pat else "aws_session_token"
        if label == "Signature":
            return "signed_url"
        if label == "SecretKey":
            return "secret40"
        return None
    if cat == "url_creds":
        return "url_password"
    if cat == "secret_values":
        return "flag_password"
    if cat == "account_ids":
        return "account_id"
    if cat == "emails":
        return "email"
    if cat is None and label in ("IPv4", "IPv6"):
        return "ip"
    return None


PII_RULES = [(r, k) for r in pii.RULES for k in [_rule_kind(r)] if k]


def _token_body_ok(kind, value) -> bool:
    body = value.rsplit("/", 1)[-1] if kind == "slack_webhook" else value[4:]
    return not _fake_token(body)


def _bedrock_ok(kind, value) -> bool:
    """The part after the fixed start of a Bedrock API key looks random, not xxxx."""
    body = value[16:] if value.startswith("bedrock-") else value[22:]
    return len(set(body.rstrip("="))) >= 20 and "EXAMPLE" not in value


# A few developer secrets PII Redact doesn't have its own rule for: (kind, pattern, check)
EXTRA_RULES = [
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/"
                                 r"T[A-Z0-9]{6,}/[A-Za-z0-9]{6,}/[A-Za-z0-9]{16,}"),
     _token_body_ok),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
     _token_body_ok),
    ("pypi_token", re.compile(r"(?<![A-Za-z0-9_-])pypi-AgE[A-Za-z0-9_-]{50,}"), _token_body_ok),
    ("private_key", re.compile(r"(?<![A-Za-z0-9+/])LS0tLS1CRUdJTi[A-Za-z0-9+/]{60,}={0,2}"),
     lambda kind, value: _encoded_private_key(value)),
    # Amazon Bedrock API keys (AWS_BEARER_TOKEN_BEDROCK). A long-term one is ABSK and then
    # base64 that starts with BedrockAPIKey-. A short-term one is bedrock-api-key- and then
    # a presigned URL in base64.
    ("bedrock_key", re.compile(r"(?<![A-Za-z0-9+/])ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/]{40,}"
                               r"={0,2}"), _bedrock_ok),
    ("bedrock_key", re.compile(r"(?<![\w-])bedrock-api-key-[A-Za-z0-9+/]{100,}={0,2}"),
     _bedrock_ok),
]
XML_SECRET = re.compile(r"<(?P<tag>[A-Za-z_][\w.:-]{0,63})(?:\s[^<>\n]{0,200})?>"
                        r"(?P<val>[^<>\n]{1,500})</(?P=tag)\s*>")
KEY_BEFORE = re.compile(r"""(?:^|[^\w.-])(?P<key>[A-Za-z_][\w.-]{0,199})\\?["']?[ \t]*"""
                        r"""(?::=|=>|[=:])[ \t]*(?:\\?["'])?$""")
FLAG_BEFORE = re.compile(r"""--(?P<key>[A-Za-z][\w-]{0,63})[ \t]+["']?$""")
AWS40 = re.compile(r"[A-Za-z0-9/+]{40}")
SECRET_CONTEXT = re.compile(r"aws|secret|credential|access", re.I)
HASH_CONTEXT = re.compile(r"sha\d|hash|digest|checksum|integrity|fingerprint|nonce|salt|"
                          r"signature", re.I)
ACCOUNT_CONTEXT = re.compile(r"arn:aws|amazonaws|account|\baws\b|aws_|owner|principal|"
                             r"assume|\biam\b|\bsts\b|\becr\b|organization", re.I)
SIGNED_CONTEXT = re.compile(r"X-Amz-(?:Credential|Algorithm)|Key-Pair-Id", re.I)
EXAMPLE_WORD = re.compile("EXAMPLE")
ALLOW_RE = re.compile(re.escape(ALLOW_MARKER), re.I)
# Every BEGIN and END line of a PEM block, overlapping ones too (see _pem_pairs)
PEM_MARK = re.compile(r"(?=-----(BEGIN|END) ([A-Z0-9 ]+)-----)")
PRIVATE_LABEL = re.compile(r"[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?")
PEM_HEADER = re.compile(r"\s*-----(?:BEGIN|END) [A-Z0-9 ]+-----")
PEM_MARKER = re.compile(r"-----(?:BEGIN|END) [A-Z0-9 ]+-----")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal",
               "db", "database", "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo",
               "mongodb", "rabbitmq", "minio"}
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
JWT_IO_EXAMPLE = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
# What the context lines hide besides the findings themselves, as a safety net.
MASK_OPTS = pii.Options(enabled={"aws_keys", "private_keys", "tokens", "url_creds",
                                 "secret_values"})


def is_example_account(digits: str) -> bool:
    """AWS's documentation account IDs and obvious stand-ins like 111111111111."""
    return (digits in {"123456789012", "012345678901", "210987654321", "098765432109",
                       "123412341234"}
            or len(set(digits)) == 1
            or bool(re.fullmatch(r"(\d)\1{3}(\d)\2{3}(\d)\3{3}", digits)))


class _Text:
    """Line lookups for one piece of text."""

    def __init__(self, text):
        self.text = text
        self.nl = [m.start() for m in re.finditer("\n", text)]
        self._has = {}

    def line_index(self, pos) -> int:
        return bisect_left(self.nl, pos)

    def line_bounds(self, idx) -> tuple:
        start = self.nl[idx - 1] + 1 if idx > 0 else 0
        end = self.nl[idx] if idx < len(self.nl) else len(self.text)
        return start, end

    def line_at(self, pos) -> str:
        s, e = self.line_bounds(self.line_index(pos))
        return self.text[s:e]

    def line_has(self, regex, pos) -> bool:
        """Does regex match somewhere on pos's line? Worked out once per line, so a
        minified file with thousands of matches on one long line isn't read again for
        each of them."""
        key = (regex.pattern, self.line_index(pos))
        hit = self._has.get(key)
        if hit is None:
            hit = self._has[key] = bool(regex.search(self.line_at(pos)))
        return hit

    @property
    def count(self) -> int:
        return len(self.nl) + 1


def _key_for(text, s) -> str:
    lo = max(0, s - 300)
    i = text.rfind("\n", lo, s)
    prefix = text[i + 1 if i >= 0 else lo:s]
    m = KEY_BEFORE.search(prefix) or FLAG_BEFORE.search(prefix)
    return m.group("key") if m else ""


def _key_kind(norm) -> Optional[str]:
    base = pii.SECRET_QUALIFIERS.sub("", norm) or norm
    if base.endswith(("accesskeyid", "accesskey")) and "secret" not in base:
        return None  # an access key ID: the AKIA rule covers the real ones
    if base.endswith(("secretaccesskey", "awssecretkey", "awssecret")):
        return "aws_secret_key"
    if base.endswith(("sessiontoken", "securitytoken")):
        return "aws_session_token"
    if base.endswith(("password", "passwd", "passphrase", "pwd", "pass")):
        return "password"
    if base.endswith("privatekey"):
        return "private_key_value"
    if base.endswith(("apikey", "apitoken")):
        return "api_key"
    if base.endswith("token"):
        return "token"
    return "secret"


def _setting(key, value, s, e, role) -> Optional[Candidate]:
    """A value given to a setting named like a secret (password = ..., API_TOKEN: ...)."""
    norm = pii.key_norm(key) if key else ""
    if norm.endswith(("hash", "digest", "hashed")):
        return None  # a hash of a password, not the password
    kind = _key_kind(norm) if norm else "secret"
    if kind is None:
        return None
    v = value.strip()
    what = ""
    if kind in ("aws_secret_key", "aws_session_token") and "EXAMPLE" in v:
        return Candidate(s, e, kind, "block", v, example=True)
    if kind == "aws_secret_key":
        if AWS40.fullmatch(v):
            return Candidate(s, e, "aws_secret_key", "block", v, example="EXAMPLE" in v)
        kind = "secret"
    if kind == "aws_session_token":
        if len(v) >= 100 and re.fullmatch(r"[A-Za-z0-9/+=]+", v):
            return Candidate(s, e, "aws_session_token", "block", v, example="EXAMPLE" in v)
        kind = "token"
    if kind == "private_key_value":
        if "PRIVATE KEY" in v:
            return None  # the private key rules have it
        kind, what = "secret", "Private key in a setting"
    level = password_level(v, norm) if kind == "password" else generic_level(v)
    if not level:
        return None
    note = ""
    if level == "warn":
        note = ("Looks like a default, demo or test password, so it's a warning."
                if kind == "password" else "Looks like a made-up or test value, so it's a "
                "warning.")
    return Candidate(s, e, kind, level, v, note=note, what=what)


def _kv_candidates(text, role) -> list:
    out = []
    for s, e, _prio, cat, _label in pii.kv_spans(text, 0, "Redacted"):
        if cat not in ("secret_values", "account_ids", "emails"):
            continue
        quoted = s > 0 and text[s - 1] in "\"'" and text[e:e + 1] == text[s - 1]
        value = text[s:e]
        key = _key_for(text, s) if cat == "secret_values" else ""
        if not quoted:
            m = re.fullmatch(r"""[bBrRuU]{1,2}(["'])(.*?)\1[,;)]*""", value)
            if m:  # Python b"..." and r"..." strings
                s, e, value, quoted = s + m.start(2), s + m.end(2), m.group(2), True
            else:
                # Up to a comment. (A search, not re.split on [ \t]+(?:#|//), which took
                # minutes on a value with a long run of spaces in it.)
                comment = re.search(r"[ \t](?:#|//)", value)
                cut = (value[:comment.start()] if comment else value).rstrip()
                e = s + len(cut)
                value = cut
                if role.code:
                    continue
        if not value.strip():
            continue
        if cat == "account_ids":
            digits = re.sub(r"\D", "", value)
            if len(digits) == 12 and re.fullmatch(r"\d{12}|\d{4}-\d{4}-\d{4}", value.strip()):
                out.append(Candidate(s, e, "account_id", "warn", value,
                                     example=is_example_account(digits)))
            continue
        if cat == "emails":
            continue  # the email pattern finds these anyway
        c = _setting(key, value, s, e, role)
        if c:
            out.append(c)
    for m in XML_SECRET.finditer(text):
        if pii.key_hit(pii.key_norm(m.group("tag"))) != pii.SECRET_HIT:
            continue
        c = _setting(m.group("tag"), m.group("val"), m.start("val"), m.end("val"), role)
        if c:
            out.append(c)
    return out


def _named_token(v) -> Optional[tuple]:
    if re.match(r"gh[pousr]_", v):
        kind, body = "github_token", v[4:]
    elif v.startswith("github_pat_"):
        kind, body = "github_token", v[11:]
    elif v.startswith("glpat-"):
        kind, body = "gitlab_token", v[6:]
    elif v.startswith("xox"):
        kind, body = "slack_token", v[5:]
    elif v.startswith("sk-ant-"):
        kind, body = "anthropic_key", v[7:]
    elif v.startswith("sk-"):
        body = v[8:] if v.startswith("sk-proj-") else v[3:]
        if not pii.mixed_charset(body):
            return None  # sk-fading-circle and other CSS class names
        kind = "openai_key"
    elif v.startswith("AIza"):
        kind, body = "google_api_key", v[4:]
    elif v[:8] in ("sk_live_", "rk_live_"):
        kind, body = "stripe_live", v[8:]
    elif v[:8] in ("sk_test_", "rk_test_"):
        kind, body = "stripe_test", v[8:]
    else:
        return None
    if _fake_token(body):
        return None
    return kind, body


def _private_key_ok(value) -> bool:
    """A real key body, not a placeholder like MIIE... in docs. Keys inside JSON strings
    have their line breaks written as \\n."""
    # The BEGIN and END markers are taken out, not their whole lines: a key flattened onto
    # one line (spaces or nothing between its lines) has its body on the BEGIN line.
    text = PEM_MARKER.sub("\n", value.replace("\\r\\n", "\n").replace("\\n", "\n"))
    body = "\n".join(ln for ln in text.splitlines() if not re.match(r"\s*[\w-]+:\s", ln))
    b64 = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    return len(b64) >= 64 and pii.entropy(b64) >= 4.0 and not _fake_token(b64)


def _encoded_private_key(value) -> bool:
    """base64 of a PEM private key, like kubeconfig's client-key-data."""
    import base64
    head = value[:120]
    try:
        text = base64.b64decode(head[:len(head) // 4 * 4])
    except ValueError:
        return False
    return b"PRIVATE KEY-----" in text and len(value) >= 200


def _ip_ok(text, s, e, value) -> bool:
    if text[e:e + 1] == "/" or value.endswith("::"):
        return False  # a CIDR block like 10.0.0.0/16, or a prefix like fd00::
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_link_local or ip.is_loopback or any(ip in n for n in DOC_NETS):
        return False
    if ip.version == 4 and value.rsplit(".", 1)[1] in ("0", "1", "255"):
        return False  # networks, gateways and broadcasts are in every example
    if re.search(r"(?:\bv|version|ver)[\s:=\"']*$", text[max(0, s - 12):s], re.I):
        return False  # version 10.2.3.4
    return True


def _email_ok(value, role) -> bool:
    stem = role.name.split(".")[0]
    if role.name in EMAIL_SKIP_NAMES or stem in EMAIL_SKIP_NAMES or role.name.endswith(".gemspec"):
        return False
    local, _, domain = value.lower().partition("@")
    if domain in EMAIL_SKIP_DOMAINS or domain.endswith(
            (".example", ".test", ".invalid", ".localhost", ".local", "noreply.github.com")):
        return False
    if "noreply" in local or "no-reply" in local or "donotreply" in local:
        return False
    return local not in {"user", "username", "name", "email", "you", "your", "someone",
                         "somebody", "john", "jane", "john.doe", "jane.doe", "foo", "bar",
                         "test", "admin", "me", "first.last", "firstname.lastname"}


def _pem_pairs(text, private=False) -> list:
    """(start, end, label) of each BEGIN ... END block, in order and not overlapping. The
    same as a finditer over -----BEGIN X-----.*?-----END X----- (or, with private=True,
    over PII Redact's rule for a private key block with its END line), but done by pairing
    the BEGIN and END lines in one pass. Those regexes read to the end of the text for
    every BEGIN line that has no END line, so a big file of BEGIN lines took many minutes."""
    marks = [(m.start(), m.group(1), m.group(2), m.end(2) + 5) for m in PEM_MARK.finditer(text)]
    if private:
        marks = [mk for mk in marks if PRIVATE_LABEL.fullmatch(mk[2])]
    ends = {}
    for s, kind, label, e in marks:
        if kind == "END":
            ends.setdefault("" if private else label, []).append((s, e))
    out, pos = [], 0
    for s, kind, label, e in marks:
        if kind != "BEGIN" or s < pos:
            continue
        found = ends.get("" if private else label, [])
        i = bisect_left(found, (e,))  # the first END line after this BEGIN line
        if i < len(found):
            pos = found[i][1]
            out.append((s, pos, label))
    return out


def _rule_candidates(text, kind, rule, lines, role) -> list:
    out = []
    if kind == "private_key" and ".*?-----END" in rule.regex.pattern:
        spans = [(s, e) for s, e, _ in _pem_pairs(text, private=True)]
    else:
        spans = (m.span(rule.group) for m in rule.regex.finditer(text))
    for s, e in spans:
        if s < 0 or s == e:
            continue
        v = text[s:e]
        if rule.check:
            res = rule.check(v)
            if not res:
                continue
            if kind == "ip" and res != "private_ips":
                continue
        if kind == "private_key":
            if _private_key_ok(v):
                out.append(Candidate(s, e, "private_key", "block", v))
        elif kind == "jwt":
            if not v.endswith(JWT_IO_EXAMPLE):
                out.append(Candidate(s, e, "jwt", "warn", v))
            else:
                out.append(Candidate(s, e, "jwt", "warn", v, example=True))
        elif kind == "named_token":
            hit = _named_token(v)
            if hit:
                out.append(Candidate(s, e, hit[0], KINDS[hit[0]][1], v))
        elif kind == "terraform_token":
            if not _fake_token(v):
                out.append(Candidate(s, e, kind, "block", v))
        elif kind == "auth_header":
            level = generic_level(v)
            if level:
                out.append(Candidate(s, e, kind, level, v,
                                     note="" if level == "block" else
                                     "Looks short or made up, so it's a warning."))
        elif kind == "aws_access_key":
            if "EXAMPLE" in v:
                out.append(Candidate(s, e, kind, "block", v, example=True))
            elif not _fake_token(v[4:]):
                out.append(Candidate(s, e, kind, "block", v))
        elif kind in ("aws_session_token", "presigned_token"):
            if "EXAMPLE" in v:
                out.append(Candidate(s, e, kind, "block", v, example=True))
            elif len(v) >= 20 and not is_placeholder(unquote(v)):
                out.append(Candidate(s, e, kind, "block", v))
        elif kind == "signed_url":
            if len(v) >= 16 and lines.line_has(SIGNED_CONTEXT, s) and not is_placeholder(v):
                out.append(Candidate(s, e, kind, "warn", v,
                                     example=lines.line_has(EXAMPLE_WORD, s)))
        elif kind == "secret40":
            out.append(Candidate(s, e, "aws_secret_key", "block", v, example="EXAMPLE" in v))
        elif kind == "url_password":
            c = _url_password(text, s, e, v)
            if c:
                out.append(c)
        elif kind == "flag_password":
            if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
                s, e, v = s + 1, e - 1, v[1:-1]
            else:
                trimmed = v.rstrip(",.;:)")  # mysql -pSECRET, in a sentence
                e, v = s + len(trimmed), trimmed
            level = password_level(v)
            if level:
                out.append(Candidate(s, e, "password", level, v,
                                     note="" if level == "block" else
                                     "Looks like a default, demo or test password, so it's a "
                                     "warning."))
        elif kind == "account_id":
            digits = re.sub(r"\D", "", v)
            if lines.line_has(ACCOUNT_CONTEXT, s):
                out.append(Candidate(s, e, kind, "warn", v, example=is_example_account(digits)))
        elif kind == "email":
            if _email_ok(v, role):
                out.append(Candidate(s, e, kind, "warn", v))
        elif kind == "ip":
            if _ip_ok(text, s, e, v):
                out.append(Candidate(s, e, "internal_ip", "warn", v))
    return out


def _url_password(text, s, e, value) -> Optional[Candidate]:
    _user, _, pw = value.partition(":")
    pw_plain = unquote(pw)
    if is_placeholder(pw) or is_placeholder(pw_plain) or len(pw_plain) < 4:
        return None
    if REFERENCE_RE.match(pw_plain):
        return None
    host = re.match(r"[^/:?#\s\"'<>]*", text[e + 1:e + 260]).group().lower()
    if host in LOCAL_HOSTS or host.endswith(".local") or host.startswith("127."):
        return Candidate(s, e, "url_password", "warn", value,
                         note="Points at a local machine or a container, so it's a warning.")
    if is_weak_password(pw_plain):
        return Candidate(s, e, "url_password", "warn", value,
                         note="Looks like a default, demo or test password, so it's a warning.")
    return Candidate(s, e, "url_password", "block", value)


def detect(text: str, path: str = "", block_account_ids: bool = False) -> list:
    """Every secret-looking thing in text, as Candidates that don't overlap, in order.

    Candidates marked example=True are AWS documentation examples, kept apart so they can
    be counted but never reported."""
    role = file_role(path)
    lines = _Text(text)
    raw = []
    for rule, kind in PII_RULES:
        raw += _rule_candidates(text, kind, rule, lines, role)
    for kind, regex, check in EXTRA_RULES:
        for m in regex.finditer(text):
            v = m.group()
            if check(kind, v):
                what = "Private key, base64-encoded" if kind == "private_key" else ""
                raw.append(Candidate(m.start(), m.end(), kind, "block", v, what=what))
    kv = _kv_candidates(text, role)
    raw += kv

    # A 40-character random string is only an AWS secret key with something AWS-like
    # around it: a setting name, an access key ID nearby, or the words on its line.
    # Without that it's a warning, and inside a certificate it's nothing.
    # (Lookups use sorted lists and sets, so a big file with thousands of matches stays fast.)
    pem = [(s, e) for s, e, label in _pem_pairs(text) if "PRIVATE" not in label]
    pem_starts = [s for s, _ in pem]
    akia_lines = {lines.line_index(c.start) for c in raw if c.kind == "aws_access_key"}
    secret_spans = sorted((c.start, c.end) for c in kv)
    span_starts = [s for s, _ in secret_spans]
    span_reach = list(accumulate((e for _, e in secret_spans), max))
    from_settings = {id(c) for c in kv}
    final = []
    for c in raw:
        if c.kind == "aws_secret_key" and id(c) not in from_settings:
            i = bisect_right(pem_starts, c.start) - 1
            if i >= 0 and c.start < pem[i][1]:
                continue
            if text[c.start - 1:c.start] in ("-", "_", ".") and c.start > 0 or \
                    text[c.end:c.end + 1] in ("-", "_"):
                continue  # the end of a longer token, like django-insecure-...
            if identifier_like(c.value):
                continue  # AwsS3BucketServerSideEncryptionByDefault is 40 characters too
            if lines.line_has(HASH_CONTEXT, c.start):
                continue
            li = lines.line_index(c.start)
            j = bisect_right(span_starts, c.start) - 1
            context = ((j >= 0 and span_reach[j] >= c.end)  # inside a secret setting
                       or any(li + d in akia_lines for d in range(-5, 6))
                       or lines.line_has(SECRET_CONTEXT, c.start))
            if not context:
                c.kind, c.level = "aws_secret_maybe", "warn"
                c.note = ("A random 40-character string with nothing AWS-like around it, so "
                          "it's a warning.")
        if c.kind == "account_id" and block_account_ids:
            c.level = "block"
        if c.level == "block" and not c.specific and (role.test or role.docs):
            c.level = "warn"
            c.note = ("In a test or docs file, so it's a warning." +
                      (" " + c.note if c.note else ""))
        final.append(c)

    # Keep one match per spot: a real value before an AWS documentation example (so the
    # word EXAMPLE next to a real key can't hide it), block before warn, a known format
    # before a generic setting, then the longest. chosen stays sorted and its spans don't
    # overlap, so only the neighbors on each side need checking.
    final.sort(key=lambda c: (c.example, LEVEL_ORDER[c.level], not c.specific,
                              -(c.end - c.start), c.start))
    chosen, starts, ends = [], [], []
    for c in final:
        i = bisect_left(starts, c.start)
        if (i and ends[i - 1] > c.start) or (i < len(starts) and starts[i] < c.end):
            continue
        chosen.insert(i, c)
        starts.insert(i, c.start)
        ends.insert(i, c.end)

    # Point an access key ID and its secret key at each other.
    keys = [c for c in chosen if c.kind == "aws_access_key" and not c.example]
    secrets_by_line = {}
    for c in chosen:
        if c.kind == "aws_secret_key" and not c.example:
            secrets_by_line.setdefault(lines.line_index(c.start), []).append(c)
    for k in keys:
        kl = lines.line_index(k.start)
        near = [secrets_by_line[n][0] for n in range(kl - 5, kl + 6) if n in secrets_by_line]
        if near:
            s = near[0]
            sl = lines.line_index(s.start)
            if sl != kl:
                gap = abs(sl - kl)
                where = ("on the next line" if sl == kl + 1 else
                         "on the line above" if sl == kl - 1 else
                         f"{gap} lines {'below' if sl > kl else 'above'}")
                k.note = (k.note + " " if k.note else "") + f"Its secret key is {where}."
            if not s.note:
                s.note = "Goes with the access key ID next to it, so both work together."
    return chosen


# =================================================================== allow list

class AllowList:
    """The repo's .awskit-secrets-allow file: sha256:HASH, path:GLOB and re:REGEX lines."""

    def __init__(self, path=None):
        self.path = path
        self.hashes = set()
        self.globs = []
        self.patterns = []
        self.notes = []

    @classmethod
    def load(cls, root) -> "AllowList":
        allow = cls(Path(root) / ALLOW_FILE if root else None)
        if allow.path is None:
            return allow
        text, why = read_text(allow.path)
        if text is None:
            if why not in ("missing",):
                allow.notes.append(f"Couldn't read {ALLOW_FILE} ({why}), so it wasn't used.")
            return allow
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, value = line.partition(":")
            kind, value = kind.strip().lower(), value.strip()
            if kind == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", value):
                allow.hashes.add(value.lower())
            elif kind == "path" and value:
                allow.globs.append(value.replace("\\", "/"))
            elif kind == "re" and value:
                if len(value) > 500:
                    allow.notes.append(f"Line {n} of {ALLOW_FILE}: the pattern is too long, "
                                       "so it was skipped.")
                    continue
                try:
                    allow.patterns.append(re.compile(value))
                except re.error as exc:
                    allow.notes.append(f"Line {n} of {ALLOW_FILE}: {_safe(str(exc))}, so it "
                                       "was skipped.")
            else:
                allow.notes.append(f"Line {n} of {ALLOW_FILE} isn't sha256:, path: or re:, "
                                   "so it was skipped.")
        return allow

    def path_allowed(self, rel: str) -> bool:
        rel = rel.replace("\\", "/")
        name = rel.rsplit("/", 1)[-1]
        for g in self.globs:
            if g.endswith("/") and (rel.startswith(g) or ("/" + g) in ("/" + rel)):
                return True
            pats = [g, g[3:]] if g.startswith("**/") else [g]
            for p in pats:
                if fnmatch.fnmatchcase(rel, p) or ("/" not in p and fnmatch.fnmatchcase(name, p)):
                    return True
        return False

    def value_allowed(self, value: str, digest: str) -> str:
        if digest in self.hashes:
            return f"a sha256 line in {ALLOW_FILE}"
        for p in self.patterns:
            if p.search(value):
                return f"the pattern re:{p.pattern} in {ALLOW_FILE}"
        return ""


# Control characters, and the ones that flip the direction of text, from a scanned file
# or a file name would reach the terminal as they are: an escape sequence in a repo could
# hide the summary line or redraw what's on screen. They show as ? instead.
UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _safe(text: str) -> str:
    return UNSAFE_CHARS.sub("?", text)


def _clean_comment(text) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))[:200]


ALLOW_HEADER = """# AWS Kit Secrets Scan allow list. One entry per line:
#   sha256:HASH     a value that isn't a secret (its sha256, never the value itself)
#   path:GLOB       files to skip, like path:tests/fixtures/*.pem
#   re:REGEX        values to skip when the pattern matches them
# Lines starting with # are comments. Review changes to this file like code.
"""


def add_allow_entries(root, findings) -> tuple:
    """Append a sha256 line for each finding to root/.awskit-secrets-allow, keeping what's
    there. Returns (path, number added)."""
    path = Path(root) / ALLOW_FILE
    existing = ""
    if os.path.lexists(path):
        text, why = read_text(path)
        if text is None:
            raise OSError(f"Couldn't read {path} ({why}).")
        existing = text
    have = {m.lower() for m in re.findall(r"(?im)^\s*sha256:\s*([0-9a-f]{64})\s*$", existing)}
    lines = []
    for f in findings:
        if not f.value_hash or f.value_hash in have:
            continue
        have.add(f.value_hash)
        lines.append(f"# {_clean_comment(f.where)} {f.what}, allowed {date.today().isoformat()}")
        lines.append(f"sha256:{f.value_hash}")
    if not lines:
        return path, 0
    text = existing if existing else ALLOW_HEADER
    if text and not text.endswith("\n"):
        text += "\n"
    write_atomic(path, text + "\n".join(lines) + "\n")
    return path, len(lines) // 2


# =================================================================== scanning text

def _context_index(cands) -> tuple:
    """What _context needs from all of a text's candidates, worked out once per text:
    their starts and ends (sorted, since candidates don't overlap) and the found values
    to hide wherever else they show up."""
    # The same value can show up again where no pattern finds it (a test that checks the
    # key is gone, a comment), so every copy of a found value is hidden too. Plain
    # lowercase words are left out only when they're a warning (POSTGRES_PASSWORD=postgres
    # shouldn't hide every postgres), never when they stop a commit.
    values = {c.value for c in cands[:300] if 6 <= len(c.value) <= 4000
              and "\n" not in c.value and KINDS[c.kind][3] != "partial"
              and not (c.level == "warn" and re.fullmatch(r"[a-z]+", c.value))}
    values |= {v.rstrip("=") for v in values if len(v.rstrip("=")) >= 6}
    return ([c.start for c in cands], [c.end for c in cands], values,
            max((len(v) for v in values), default=0))


def _context(t: _Text, cands, cand, radius=CONTEXT_LINES, index=None) -> str:
    """The lines around a finding, with every secret in them hidden."""
    starts, ends, values, pad = index or _context_index(cands)
    li = t.line_index(cand.start)
    first, last = max(0, li - radius), min(t.count - 1, li + radius)
    # Only the start of a long line is shown (around the finding on its own line), so
    # only that part is searched. A minified file isn't read again for every finding.
    regions = []
    for idx in range(first, last + 1):
        ls, le = t.line_bounds(idx)
        lo, hi = ls, min(le, ls + 4000)
        if idx == li:
            col = cand.start
            lo, hi = max(ls, col - 1500), min(le, col + 1500)
        regions.append((lo, hi))
    groups = []
    for lo, hi in regions:
        a, b = bisect_right(ends, lo), bisect_left(starts, hi)
        groups += [(c.start, c.end, c) for c in cands[a:b]]
        w_lo = max(0, lo - pad)
        window = t.text[w_lo:hi + pad]
        for v in values:
            pos = window.find(v)
            while pos >= 0:
                groups.append((w_lo + pos, w_lo + pos + len(v), None))
                pos = window.find(v, pos + len(v))
    # PII Redact's own key, token and password rules as a safety net.
    for lo, hi in regions:
        for s, e, kind in pii.find_spans(t.text[lo:hi], MASK_OPTS):
            v = t.text[lo + s:lo + e]
            if kind == "Secret" and (is_placeholder(v) or REFERENCE_RE.match(v)
                                     or re.match(r"[A-Za-z_][\w.]*[\[(]", v)):
                continue  # os.environ["X"] and other code, not a value
            groups.append((lo + s, lo + e, None))
    # Findings sort before PII Redact's spans of the same size, so they keep their look.
    groups.sort(key=lambda g: (g[0], -(g[1] - g[0]), 0 if g[2] is not None else 1))
    merged = []
    for s, e, c in groups:
        if merged and s < merged[-1][1]:
            ps, pe, pc = merged[-1]
            if e <= pe:
                continue  # inside the one before
            keep = c if c is not None and c.start == ps and c.end == e else None
            merged[-1] = (ps, e, keep)
        else:
            merged.append((s, e, c))

    first_line = getattr(t, "first_line", 1)
    width = len(str(last + first_line))
    out = []
    for idx in range(first, last + 1):
        ls, le = t.line_bounds(idx)
        vs, ve = ls, le
        if le - ls > 240:
            if idx == li:
                vs = max(ls, cand.start - 100)
                ve = min(le, vs + 240)
            else:
                ve = ls + 240
        for s, e, _ in merged:  # never cut a hidden value in half
            if s < vs < e:
                vs = max(ls, s)
            if s < ve < e:
                ve = min(le, e)
        pieces, pos = [], vs
        for s, e, c in merged:
            if e <= vs or s >= ve:
                continue
            a, b = max(s, vs), min(e, ve)
            pieces.append(t.text[pos:a])
            part = t.text[a:b]
            if c is not None and c.kind == "private_key":
                # Only a BEGIN or END line stays readable, never the key itself, even when
                # the whole key sits on one line with its line breaks written as \n.
                head = PEM_HEADER.match(part)
                if head and head.end() == len(part.rstrip()):
                    pieces.append(part)
                elif head:
                    pieces.append(head.group() + "*" * 16)
                else:
                    pieces.append("*" * 16)
            elif c is not None and a == c.start and b == c.end and "\n" not in part:
                pieces.append(mask_inline(part, c.kind))
            else:
                pieces.append("********")
            pos = b
        pieces.append(t.text[pos:ve])
        body = _safe("".join(pieces).replace("\r", "").replace("\t", "    "))
        if vs > ls:
            body = "..." + body
        if ve < le:
            body += "..."
        number = idx + first_line
        mark = ">" if idx == li else " "
        out.append(f"{mark} {str(number).rjust(width)} | {body}")
    return "\n".join(out)


def mask_text(text: str) -> str:
    """text with everything that looks secret hidden, for one-off lines like a commit
    message."""
    spans = [(c.start, c.end) for c in detect(text) if c.kind not in ("internal_ip", "email")]
    spans += [(s, e) for s, e, _ in pii.find_spans(text, MASK_OPTS)]
    out, pos = [], 0
    for s, e in sorted(spans):
        if s < pos:
            s = pos
        if s >= e:
            continue
        out += [text[pos:s], "********"]
        pos = e
    return "".join(out) + text[pos:]


def scan_text(text, path, first_line=1, block_account_ids=False, allow=None, commit=None,
              with_context=True) -> tuple:
    """Scan one piece of text from path. Returns (findings, allowed, examples)."""
    cands = detect(text, path, block_account_ids)
    t = _Text(text)
    t.first_line = first_line
    index = _context_index(cands) if with_context else None
    subject = None
    findings, allowed, examples = [], [], 0
    for c in cands:
        if c.example:
            examples += 1
            continue
        li = t.line_index(c.start)
        ls, _ = t.line_bounds(li)
        digest = value_hash(c.value)
        reason = ""
        if t.line_has(ALLOW_RE, c.start):
            reason = f"{ALLOW_MARKER} on the line"
        elif "\n" in t.text[c.start:c.end] and li > 0 and \
                t.line_has(ALLOW_RE, t.line_bounds(li - 1)[0]):
            reason = f"{ALLOW_MARKER} on the line above"
        elif allow is not None:
            reason = allow.value_allowed(c.value, digest)
        kind_what = c.what or KINDS[c.kind][0]
        f = Finding(level=c.level, kind=c.kind, what=kind_what, path=path,
                    line=li + first_line, column=c.start - ls + 1,
                    preview=mask_value(c.value, c.kind), length=len(c.value), note=c.note,
                    allowed=reason, value_hash=digest)
        if commit:
            if subject is None:
                # Masked whole and only then cut short, so a key cut in half can't slip
                # past the patterns and show its first part.
                subject = _safe(mask_text(commit[2])[:120])
            f.commit, f.commit_date = commit[0], commit[1]
            f.commit_subject = subject
        if reason:
            allowed.append(f)
            continue
        if with_context:
            f.context = _context(t, cands, c, index=index)
        findings.append(f)
    return findings, allowed, examples


# =================================================================== files

def read_text(path) -> tuple:
    """(text, "") or (None, why): missing, link, special, big, binary or unreadable.
    Never follows a link, and never reads more than MAX_FILE."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except OSError:
        return None, "missing"
    if stat.S_ISLNK(st.st_mode):
        return None, "link"
    if not stat.S_ISREG(st.st_mode):
        return None, "special"
    if st.st_size > MAX_FILE:
        return None, "big"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | \
        getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None, "unreadable"
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None, "special"
            data = fh.read(MAX_FILE + 1)
    except OSError:
        return None, "unreadable"
    if len(data) > MAX_FILE:
        return None, "big"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace"), ""
    if b"\x00" in data[:8192]:
        return None, "binary"
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", "replace"), ""


class _Skips:
    """Counts what wasn't scanned, for the notes."""

    def __init__(self):
        self.binary = []
        self.big = []
        self.allowed = []
        self.unreadable = []

    def add(self, why, path):
        if why == "binary":
            self.binary.append(path)
        elif why == "big":
            self.big.append(path)
        elif why == "allowed":
            self.allowed.append(path)
        elif why in ("unreadable", "special"):
            self.unreadable.append(path)

    @staticmethod
    def _names(items):
        shown = ", ".join(items[:3])
        return shown + (f" and {len(items) - 3} more" if len(items) > 3 else "")

    def unchecked(self) -> list:
        """Notes on the files that couldn't be checked at all."""
        out = []
        if self.binary:
            out.append(f"Skipped {len(self.binary)} binary file(s): {self._names(self.binary)}.")
        if self.big:
            out.append(f"Skipped {len(self.big)} file(s) over 2 MB: {self._names(self.big)}.")
        if self.unreadable:
            out.append(f"Couldn't read {len(self.unreadable)} file(s): "
                       f"{self._names(self.unreadable)}.")
        return out

    def notes(self) -> list:
        out = self.unchecked()
        if self.allowed:
            out.append(f"Skipped {len(self.allowed)} file(s) listed with path: in "
                       f"{ALLOW_FILE}: {self._names(self.allowed)}.")
        return out


def _display(name: str) -> str:
    return _safe(name.encode("utf-8", "surrogateescape").decode("utf-8", "replace"))


def _under(rel: str, prefix: str) -> bool:
    return not prefix or rel == prefix or rel.startswith(prefix.rstrip("/") + "/")


class _Progress:
    def __init__(self, fn):
        self.fn = fn
        self.last = 0.0

    def __call__(self, done, total, text, force=False):
        if not self.fn:
            return
        now = time.monotonic()
        if force or now - self.last >= 0.08:
            self.last = now
            self.fn(done, total, text)


# =================================================================== git

def find_git() -> Optional[str]:
    """git's full path from PATH, never from the current folder (a repo could ship its own
    git.exe), and never a relative PATH entry."""
    names = ["git.exe", "git"] if os.name == "nt" else ["git"]
    here = os.path.normcase(os.path.abspath(os.getcwd())) if os.name == "nt" else None
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        folder = folder.strip().strip('"')
        if not folder or not os.path.isabs(folder):
            continue
        if here and os.path.normcase(os.path.abspath(folder)) == here:
            continue
        for name in names:
            cand = os.path.join(folder, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def _git_env() -> dict:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""})
    # Never fetch. In a partial clone, git log -p fetches missing files from the repo's
    # remote, and the repo's own config picks how (core.sshCommand, an ext:: URL, a
    # credential helper): that runs a program the repo names. GIT_ALLOW_PROTOCOL wins
    # over any config and allows no protocol at all; GIT_NO_LAZY_FETCH (newer git) stops
    # the fetch before it starts.
    env.update({"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "none"})
    env.pop("GIT_EXTERNAL_DIFF", None)
    return env


def _git_cmd(args) -> list:
    exe = find_git()
    if not exe:
        raise ScanError("git isn't installed, or isn't on PATH. Folder, not git (--files) "
                        "still works without it.")
    return [exe, "--no-pager"] + GIT_SAFE + list(args)


def _git_error(stderr: bytes, what="git") -> str:
    text = stderr.decode("utf-8", "replace").strip()
    if "dubious ownership" in text:
        return ("git won't read this repo because another user owns it. If you trust it, "
                "run the git config --global --add safe.directory command git suggests.")
    if "promisor remote" in text or "lazy fetch" in text:
        return ("Part of this repo's history isn't downloaded (it's a partial clone), and "
                "Secrets Scan never downloads anything. Get the full history yourself first, "
                "for example by cloning it again without --filter, then scan again.")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return _safe(f"{what} failed: " + (lines[-1] if lines else "no details")).strip()


def run_git(root, args, timeout=GIT_TIMEOUT, ok_codes=(0,)) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(_git_cmd(args), cwd=str(root), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           env=_git_env(), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"git took longer than {timeout} seconds, so it was stopped.") from exc
    except OSError as exc:
        raise ScanError(f"Couldn't run git: {exc}") from exc
    if r.returncode not in ok_codes:
        raise ScanError(_git_error(r.stderr))
    return r


def git_lines(root, args, timeout=GIT_SCAN_TIMEOUT, cancel=None):
    """Yield git's output a line at a time (bytes), so a huge diff is never held in memory
    at once. Stops git when cancel is set or the timeout passes."""
    err = tempfile.TemporaryFile()
    try:
        proc = subprocess.Popen(_git_cmd(args), cwd=str(root), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=err, env=_git_env(),
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        err.close()
        raise ScanError(f"Couldn't run git: {exc}") from exc
    timed_out = threading.Event()

    def kill():
        timed_out.set()
        proc.kill()
    timer = threading.Timer(timeout, kill)
    timer.daemon = True
    timer.start()
    stopped = finished = False
    try:
        # Read in pieces of at most 1 MB, so one huge line (a big file with no line breaks)
        # never sits in memory whole: past MAX_LINE the rest of it is dropped, and the
        # parser marks that file as over 2 MB.
        pending, size, n = [], 0, 0
        while True:
            chunk = proc.stdout.readline(1 << 20)
            if not chunk:
                if pending:
                    yield b"".join(pending)
                break
            if size < MAX_LINE:
                pending.append(chunk)
                size += len(chunk)
            if not chunk.endswith(b"\n"):
                continue
            n += 1
            if cancel is not None and n % 200 == 0 and cancel.is_set():
                stopped = True
                break
            yield b"".join(pending)
            pending, size = [], 0
        finished = not stopped
    finally:
        # Reading stopped early (cancelled, or the caller gave up): stop git too.
        if not finished and proc.poll() is None:
            proc.kill()
        try:
            proc.stdout.close()
        except OSError:
            pass
        rc = proc.wait()
        timer.cancel()
        err.seek(0)
        stderr = err.read(65536)
        err.close()
    if timed_out.is_set():
        raise ScanError(f"git took longer than {timeout} seconds, so it was stopped.")
    if rc != 0 and not stopped:
        raise ScanError(_git_error(stderr))


def git_root(folder) -> Optional[Path]:
    """The top of the git work tree folder is in, or None (not a repo, or no git)."""
    if not find_git():
        return None
    try:
        r = run_git(folder, ["rev-parse", "--show-toplevel"], ok_codes=(0, 128))
    except ScanError:
        return None
    out = r.stdout.decode("utf-8", "surrogateescape").strip()
    if r.returncode != 0 or not out:
        err = r.stderr.decode("utf-8", "replace")
        if "dubious ownership" in err:
            raise ScanError(_git_error(r.stderr))
        return None
    return Path(out)


def has_staged(root) -> bool:
    r = run_git(root, ["diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv"],
                ok_codes=(0, 1))
    return r.returncode == 1


def _unquote_path(s: str) -> str:
    """A path as git's diff prints it: maybe "quoted" with C escapes, maybe ending in a tab."""
    if s.endswith("\t"):
        s = s[:-1]
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        body, out, i = s[1:-1], bytearray(), 0
        simple = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "a": "\a", "b": "\b",
                  "f": "\f", "r": "\r", "v": "\v"}
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in "0123" and re.fullmatch(r"[0-7]{3}", body[i + 1:i + 4] or ""):
                    out.append(int(body[i + 1:i + 4], 8))
                    i += 4
                    continue
                out += simple.get(nxt, nxt).encode("utf-8")
                i += 2
                continue
            out += ch.encode("utf-8")
            i += 1
        return out.decode("utf-8", "replace")
    return s


@dataclass
class _FileChange:
    path: str
    commit: Optional[tuple]
    added: list
    binary: bool = False
    big: bool = False


HUNK = re.compile(rb"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
UTF16_BOMS = {b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}


def _utf16_line(content: bytes, enc: str) -> bytes:
    """One line of a UTF-16 file as git splits it, at the 0x0A byte, turned into UTF-8.
    The other byte of each line break is left over at the start of the next line (LE) or
    at the end of the line (BE), so it's dropped first."""
    if len(content) % 2:
        content = content[1:] if enc == "utf-16-le" else content[:-1]
    return content.decode(enc, "replace").encode("utf-8")


def parse_diff(lines, history=False, on_commit=None):
    """Read git diff or git log -p output (-U0) and yield a _FileChange per file with the
    added lines and their line numbers in the new file. Hunk lengths are counted, so a
    line that happens to start with +++ or diff --git is still read as content.
    on_commit(hash) is called for every commit header in git log output.

    A file whose first line starts with a UTF-16 byte order mark (Windows PowerShell 5
    writes those with >, like aws iam create-access-key > key.json) is read as UTF-16
    instead of being skipped as binary."""
    commit = None
    path = None
    added, size, binary, big = [], 0, False, False
    utf16 = None
    old_left = new_left = 0
    new_line = 0
    started = False
    header_name = ""

    def flush():
        if started and (path or binary):
            return _FileChange(path or "", commit, added, binary, big)
        return None

    for raw in lines:
        line = raw[:-1] if raw.endswith(b"\n") else raw
        if old_left > 0 or new_left > 0:
            tag = line[:1]
            if tag == b"+":
                if path and not big and not binary:
                    content = line[1:]
                    if new_line == 1 and content[:2] in UTF16_BOMS:
                        utf16 = UTF16_BOMS[content[:2]]
                        content = content[2:]
                    if utf16:
                        content = _utf16_line(content, utf16)
                    if b"\x00" in content:
                        binary, added = True, []
                    else:
                        size += len(content)
                        if size > MAX_FILE:
                            big, added = True, []
                        else:
                            added.append((new_line, content))
                new_line += 1
                new_left -= 1
                continue
            if tag == b"-":
                old_left -= 1
                continue
            if tag == b" ":
                old_left -= 1
                new_left -= 1
                new_line += 1
                continue
            if tag == b"\\":
                continue
            old_left = new_left = 0  # not what the hunk header promised, read it as a header
        if history and line.startswith(b"\x00\x00"):
            fc = flush()
            if fc:
                yield fc
            started, path, added, size, binary, big = False, None, [], 0, False, False
            utf16 = None
            parts = line[2:].decode("utf-8", "replace").split("\t", 2)
            when = ""
            try:
                when = datetime.fromtimestamp(int(parts[1]), timezone.utc).astimezone() \
                    .strftime("%Y-%m-%d")
            except (IndexError, ValueError, OSError, OverflowError):
                pass
            # The subject is cut short after it's masked (scan_text), not here
            commit = (parts[0], when, parts[2][:2000] if len(parts) > 2 else "")
            if on_commit:
                on_commit(parts[0])
            continue
        if line.startswith(b"diff --git "):
            fc = flush()
            if fc:
                yield fc
            started, path, added, size, binary, big = True, None, [], 0, False, False
            utf16 = None
            # Only used to name a binary file in the notes: the +++ line is the real path.
            m = re.search(rb' "?b/(.*?)"?$', line)
            header_name = m.group(1).decode("utf-8", "replace") if m else ""
            continue
        if not started:
            continue
        if line.startswith(b"+++ "):
            name = _unquote_path(line[4:].decode("utf-8", "replace"))
            if name == "/dev/null":
                path = None  # the file was deleted, nothing was added
            else:
                path = name[2:] if name.startswith("b/") else name
            continue
        if line.startswith(b"@@"):
            m = HUNK.match(line)
            if m:
                old_left = int(m.group(1)) if m.group(1) is not None else 1
                new_line = int(m.group(2))
                new_left = int(m.group(3)) if m.group(3) is not None else 1
            continue
        if line.startswith(b"Binary files ") or line.startswith(b"GIT binary patch"):
            binary = True
            if not path:
                path = header_name or None
            continue
    fc = flush()
    if fc:
        yield fc


def _blocks(added):
    """Runs of added lines that sit next to each other: (first line number, [lines])."""
    block, first, prev = [], None, None
    for n, content in added:
        if prev is not None and n != prev + 1:
            yield first, block
            block, first = [], None
        if first is None:
            first = n
        block.append(content.decode("utf-8", "replace"))
        prev = n
    if block:
        yield first, block


# =================================================================== settings

def load_settings() -> dict:
    """This tool's settings from the awskit config, under its own key."""
    out = dict(DEFAULT_SETTINGS)
    mine = load_config().get(CONFIG_KEY)
    if isinstance(mine, dict):
        for key, default in DEFAULT_SETTINGS.items():
            value = mine.get(key)
            if isinstance(value, type(default)) and \
                    isinstance(value, bool) == isinstance(default, bool):
                out[key] = value
    if out["mode"] not in MODES:
        out["mode"] = DEFAULT_SETTINGS["mode"]
    if not 1 <= out["history_commits"] <= 100000:
        out["history_commits"] = DEFAULT_SETTINGS["history_commits"]
    return out


def save_settings(values: dict) -> bool:
    """Save this tool's settings, keeping every other key in the config file as it is."""
    cfg = load_config()
    current = load_settings()
    current.update({k: v for k, v in values.items() if k in DEFAULT_SETTINGS})
    cfg[CONFIG_KEY] = current
    return save_config(cfg)


# =================================================================== the scan

def resolve_target(target) -> tuple:
    """(target path, git root or None, root for paths and the allow file, prefix of
    target inside root)."""
    path = Path(os.path.expanduser(str(target or ".")))
    if not path.exists():
        raise ScanError(f"{path} doesn't exist.")
    path = path.resolve()
    base = path if path.is_dir() else path.parent
    repo = git_root(base)
    root = repo.resolve() if repo else base
    try:
        prefix = path.relative_to(root).as_posix()
    except ValueError:
        prefix = ""
    if prefix == ".":
        prefix = ""
    return path, repo, root, prefix


def scan(target=".", mode=None, history=DEFAULT_HISTORY, block_account_ids=False,
         progress=None, cancel=None) -> ScanResult:
    """Scan target (a folder or file) the way mode says: staged, all, history or files.
    With mode None: staged changes when the repo has some, all files in a repo, or the
    plain folder otherwise."""
    path, repo, root, prefix = resolve_target(target)
    if mode is None:
        mode = ("staged" if has_staged(repo) else "all") if repo else "files"
    if mode not in MODES:
        raise ScanError(f"Unknown scan mode {mode}.")
    if mode != "files" and repo is None:
        if not find_git():
            raise ScanError("git isn't installed, or isn't on PATH. Folder, not git (--files) "
                            "still works without it.")
        raise ScanError(f"{path} isn't in a git repo. Scan it as a plain folder instead "
                        "(Folder, not git, or --files).")
    result = ScanResult(mode=mode, root=str(root), target=str(path), is_git=repo is not None)
    allow = AllowList.load(root)
    result.notes += allow.notes
    report = _Progress(progress)
    opts = dict(block_account_ids=block_account_ids, allow=allow)
    if mode == "staged":
        _scan_diff(result, root, prefix, ["diff", "--cached"] + DIFF_ARGS, opts, report,
                   cancel, history=False)
        result.unit = "staged files"
    elif mode == "history":
        n = max(1, int(history or DEFAULT_HISTORY))
        args = ["log", "-p", f"-n{n}", "--format=%x00%x00%H%x09%at%x09%s"] + DIFF_ARGS
        if _has_commits(root):
            _scan_diff(result, root, prefix, args, opts, report, cancel, history=True, total=n)
        else:
            result.notes.append("This repo has no commits yet.")
        result.unit = "commits"
        _mark_still_present(result, root, prefix, block_account_ids, cancel)
    elif mode == "all":
        names = _git_files(root)
        _scan_files(result, root, [(n, root / n) for n in names if _under(n, prefix)], opts,
                    report, cancel)
    else:
        _scan_files(result, root, list(_walk(path, root)), opts, report, cancel)
    result.findings.sort(key=lambda f: (LEVEL_ORDER[f.level], f.path, f.line, f.column,
                                        f.commit))
    if result.examples:
        result.notes.append(f"Skipped {result.examples} AWS documentation example(s), like "
                            "AKIAIOSFODNN7EXAMPLE or account 123456789012.")
    return result


def _has_commits(root) -> bool:
    r = run_git(root, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], ok_codes=(0, 1, 128))
    return r.returncode == 0


def _git_files(root) -> list:
    r = run_git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                timeout=120)
    names = []
    seen = set()
    for raw in r.stdout.split(b"\x00"):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _walk(path: Path, root: Path):
    """(relative name, full path) for every file under path, without following links."""
    if path.is_file():
        rel = path.relative_to(root).as_posix() if root in path.parents else path.name
        yield rel, path
        return
    for folder, dirs, files in os.walk(str(path), followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and
                         not os.path.islink(os.path.join(folder, d)))
        for name in sorted(files):
            full = Path(folder) / name
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                rel = full.name
            yield rel, full


def _scan_files(result, root, items, opts, report, cancel):
    skips = _Skips()
    real_root = os.path.realpath(str(root))
    total = len(items)
    for i, (rel, full) in enumerate(items):
        if cancel is not None and cancel.is_set():
            result.cancelled = True
            break
        shown = _display(rel)
        report(i, total, shown)
        if rel == ALLOW_FILE or rel.endswith("/" + ALLOW_FILE):
            continue
        if opts["allow"].path_allowed(rel):
            skips.add("allowed", shown)
            continue
        real = os.path.realpath(str(full))
        if real != real_root and not real.startswith(real_root.rstrip(os.sep) + os.sep):
            continue  # reached through a link that leads out of the repo
        text, why = read_text(full)
        if text is None:
            skips.add(why, shown)
            continue
        result.scanned += 1
        found, allowed, examples = scan_text(text, shown, 1, opts["block_account_ids"],
                                             opts["allow"])
        result.findings += found
        result.allowed += allowed
        result.examples += examples
    result.notes += skips.notes()
    result.unchecked += skips.unchecked()


def _scan_diff(result, root, prefix, args, opts, report, cancel, history=False, total=0):
    skips = _Skips()
    files = set()
    commits = set()
    first_seen = {}
    for fc in parse_diff(git_lines(root, args, cancel=cancel), history=history,
                         on_commit=commits.add):
        if cancel is not None and cancel.is_set():
            result.cancelled = True
            break
        shown = _display(fc.path)
        if not fc.path or not _under(fc.path, prefix):
            continue
        report(len(commits) if history else len(files), total, shown)
        if fc.path == ALLOW_FILE or fc.path.endswith("/" + ALLOW_FILE):
            continue
        if opts["allow"].path_allowed(fc.path):
            if shown not in skips.allowed:
                skips.add("allowed", shown)
            continue
        if fc.binary or fc.big:
            label = shown + (f" ({fc.commit[0][:8]})" if fc.commit else "")
            if label not in skips.binary and label not in skips.big:
                skips.add("binary" if fc.binary else "big", label)
            continue
        files.add(fc.path)
        for first, block in _blocks(fc.added):
            found, allowed, examples = scan_text("\n".join(block), shown, first,
                                                 opts["block_account_ids"], opts["allow"],
                                                 commit=fc.commit)
            result.allowed += allowed
            result.examples += examples
            if not history:
                result.findings += found
                continue
            # git log lists the newest commit first, so the last one seen is where it
            # was added. Keep that one and count the rest.
            for f in found:
                key = (f.path, f.kind, f.value_hash)
                if key in first_seen:
                    older = first_seen[key]
                    f.occurrences = older.occurrences + 1
                    result.findings[result.findings.index(older)] = f
                    first_seen[key] = f
                else:
                    first_seen[key] = f
                    result.findings.append(f)
    if cancel is not None and cancel.is_set():
        result.cancelled = True
    result.scanned = len(commits) if history else len(files)
    result.notes += skips.notes()
    result.unchecked += skips.unchecked()


def _mark_still_present(result, root, prefix, block_account_ids, cancel):
    """For history findings, check whether the value is still in the files today."""
    if not result.findings:
        return
    present = set()
    try:
        for name in _git_files(root):
            if cancel is not None and cancel.is_set():
                return
            if not _under(name, prefix):
                continue
            text, _why = read_text(root / name)
            if text is None:
                continue
            found, allowed, _ = scan_text(text, name, 1, block_account_ids, None,
                                          with_context=False)
            present.update(f.value_hash for f in found + allowed)
    except ScanError:
        return
    for f in result.findings:
        f.still_in_files = f.value_hash in present
        if not f.still_in_files:
            f.note = (f.note + " " if f.note else "") + \
                "Removed from the files later, but still in git history."


# =================================================================== the hook

HOOK_SCRIPT = f"""#!/bin/sh
# {HOOK_MARKER}: written by AWS Kit (awskit secrets --install-hook).
# Checks staged changes for AWS keys, tokens, private keys and passwords before each
# commit. Remove it with: awskit secrets --remove-hook
# Skip it for one commit with: git commit --no-verify

hooks_dir=$(dirname "$0")
if [ -f "$hooks_dir/{CHAINED_HOOK}" ] && [ -x "$hooks_dir/{CHAINED_HOOK}" ]; then
    "$hooks_dir/{CHAINED_HOOK}" "$@" || exit $?
fi

awskit=$(command -v awskit 2>/dev/null) || awskit=$(command -v awskit.cmd 2>/dev/null) || awskit=""
# Only a full path. With . or an empty entry in PATH, command -v can name ./awskit, a
# file the repo itself could ship.
case $awskit in
    /*) ;;
    *) awskit="" ;;
esac
if [ -z "$awskit" ]; then
    for candidate in "$HOME/.local/bin/awskit" \\
            "${{LOCALAPPDATA:-/nonexistent}}/AWSKit/bin/awskit.cmd"; do
        if [ -f "$candidate" ]; then
            awskit=$candidate
            break
        fi
    done
fi
if [ -z "$awskit" ]; then
    echo "AWS Kit: awskit isn't on PATH, so this commit wasn't checked for secrets." >&2
    echo "Install AWS Kit or add it to PATH. To remove this hook: awskit secrets --remove-hook" >&2
    exit 0
fi
exec "$awskit" secrets --staged --hook
"""


def hooks_dir(repo) -> Path:
    """Where git looks for hooks: .git/hooks, or core.hooksPath when it's set."""
    out = run_git(repo, ["rev-parse", "--git-path", "hooks"]).stdout
    d = Path(os.fsdecode(out.strip()))
    return d if d.is_absolute() else Path(repo) / d


def _is_ours(path: Path) -> bool:
    # read_text never follows a link or opens a FIFO, which would wait forever
    text, _why = read_text(path)
    return text is not None and HOOK_MARKER in text[:4096]


def hook_status(folder) -> dict:
    """state: on, off, other (someone else's pre-commit hook), not_git or no_git."""
    if not find_git():
        return {"state": "no_git", "chained": False, "path": "", "repo": ""}
    try:
        repo = git_root(Path(folder))
        if repo is None:
            return {"state": "not_git", "chained": False, "path": "", "repo": ""}
        d = hooks_dir(repo)
    except ScanError as exc:
        return {"state": "error", "chained": False, "path": "", "repo": "",
                "message": str(exc)}
    hook = d / "pre-commit"
    chained = os.path.lexists(d / CHAINED_HOOK)
    if not os.path.lexists(hook):
        state = "off"
    else:
        state = "on" if _is_ours(hook) else "other"
    return {"state": state, "chained": chained and state == "on", "path": str(hook),
            "repo": str(repo)}


def _inside_repo(repo, d: Path) -> bool:
    """Is the hooks folder inside the work tree or the repo's own .git folder? A cloned
    repo's config can point core.hooksPath anywhere, like ~/.local/bin."""
    common = Path(os.fsdecode(run_git(repo, ["rev-parse", "--git-common-dir"]).stdout.strip()))
    if not common.is_absolute():
        common = Path(repo) / common
    real = Path(os.path.realpath(str(d)))
    for base in (Path(os.path.realpath(str(repo))), Path(os.path.realpath(str(common)))):
        if real == base or base in real.parents:
            return True
    return False


def install_hook(folder, chain=False) -> str:
    """Write the pre-commit hook. Someone else's hook is only touched with chain=True, which
    renames it to pre-commit.before-awskit and runs it first."""
    repo = git_root(Path(folder))
    if repo is None:
        raise HookError(f"{folder} isn't in a git repo.")
    d = hooks_dir(repo)
    hook = d / "pre-commit"
    if not _inside_repo(repo, d):
        raise HookError(f"core.hooksPath points outside this repo, at {d}, so AWS Kit won't "
                        "write or rename files there: hooks in a shared folder run for other "
                        "repos too, and a repo you cloned can point it anywhere. To check "
                        "commits from that folder's pre-commit hook, add this line to it: "
                        "awskit secrets --staged --hook || exit 1")
    note = ""
    if os.path.lexists(hook) and not _is_ours(hook):
        if not chain:
            raise HookError(f"There's already a pre-commit hook in {d}, so it was left alone. "
                            "Use --chain (or Run both in the window) to keep it and run it "
                            f"first: it's renamed to {CHAINED_HOOK}.")
        if os.path.lexists(d / CHAINED_HOOK):
            raise HookError(f"{d / CHAINED_HOOK} already exists, so nothing was changed. "
                            "Move one of them out of the way first.")
        os.rename(hook, d / CHAINED_HOOK)
        note = f" Your old hook is now {CHAINED_HOOK} and runs first."
    d.mkdir(parents=True, exist_ok=True)
    write_atomic(hook, HOOK_SCRIPT, mode=0o755)
    return f"Installed the commit hook in {hook}.{note}"


def remove_hook(folder) -> str:
    repo = git_root(Path(folder))
    if repo is None:
        raise HookError(f"{folder} isn't in a git repo.")
    d = hooks_dir(repo)
    hook = d / "pre-commit"
    if not os.path.lexists(hook):
        return "No commit hook was installed."
    if not _is_ours(hook):
        raise HookError(f"{hook} isn't AWS Kit's hook, so it was left alone.")
    os.unlink(hook)
    if os.path.lexists(d / CHAINED_HOOK):
        os.rename(d / CHAINED_HOOK, hook)
        return f"Removed the commit hook and put your old one back as {hook}."
    return f"Removed the commit hook from {hook}."


# =================================================================== command line

COLS = [("level", "Level"), ("where", "File"), ("what", "What"), ("preview", "Preview")]

DESCRIPTION = """\
Finds AWS keys, tokens, private keys and passwords in a git repo before they're
committed, using PII Redact's patterns. Nothing leaves your machine.

what it scans (pick one):
  --staged       what's about to be committed (the default when there are staged changes)
  --all          every tracked file, plus new files git doesn't ignore (the default otherwise)
  --history [N]  lines added in the last N commits (default 200)
  --files        a plain folder or file, git or not

exit codes: 0 nothing to fix (warnings don't count), 1 something to fix, 2 couldn't scan.
That's what a git hook and CI want: exit 1 stops the commit or fails the job.
"""

EPILOG = """\
examples:
  awskit secrets                      staged changes, or every file if nothing is staged
  awskit secrets --all ~/aws-platform
  awskit secrets --history 50         were keys committed and removed later?
  awskit secrets --files ~/Downloads/lab
  awskit secrets --install-hook       check every commit in this repo from now on
  awskit secrets --allow app/config.py:12    a false positive: add it to the allow file

Allow a false positive with awskit:allow in a comment on its line, or with sha256:,
path: and re: lines in .awskit-secrets-allow at the top of the repo.
"""


def register_cli(sub, add_profiles):
    import argparse
    p = sub.add_parser("secrets", help="Find AWS keys, tokens and passwords before they're "
                       "committed, and add a commit hook",
                       description=DESCRIPTION, epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", nargs="?", default=".", help="Folder or file (default: this folder)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--staged", dest="mode", action="store_const", const="staged",
                      help="Check staged changes, what's about to be committed")
    mode.add_argument("--all", dest="mode", action="store_const", const="all",
                      help="Check every tracked file and new files git doesn't ignore")

    class History(argparse.Action):
        """--history N, or --history followed by the folder (awskit secrets --history ~/repo),
        which argparse would otherwise try to read as N."""

        def __call__(self, parser, namespace, value, option_string=None):
            if value is None or str(value).isdigit():
                setattr(namespace, self.dest, int(value) if value else DEFAULT_HISTORY)
                return
            setattr(namespace, self.dest, DEFAULT_HISTORY)
            namespace.history_path = value

    mode.add_argument("--history", nargs="?", action=History, metavar="N",
                      help=f"Check lines added in the last N commits (default {DEFAULT_HISTORY})")
    p.set_defaults(history_path=None)
    mode.add_argument("--files", dest="mode", action="store_const", const="files",
                      help="Check a plain folder or file, git or not")
    p.add_argument("--json", action="store_true", help="Print JSON (values are always masked)")
    p.add_argument("--markdown", metavar="FILE", help="Write a Markdown report to FILE")
    p.add_argument("--block-account-ids", action="store_true",
                   help="Treat AWS account IDs as something to fix, not a warning")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show the lines around each finding and how to fix it")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary line")
    hook = p.add_mutually_exclusive_group()
    hook.add_argument("--install-hook", action="store_true",
                      help="Add a git pre-commit hook that runs this on staged changes")
    hook.add_argument("--remove-hook", action="store_true", help="Remove that hook")
    hook.add_argument("--allow", action="append", metavar="FILE:LINE",
                      help="Add the finding at FILE:LINE to .awskit-secrets-allow (repeatable)")
    p.add_argument("--chain", action="store_true",
                   help="With --install-hook: keep an existing pre-commit hook and run it first")
    p.add_argument("--hook", action="store_true",
                   help="Short output for the commit hook (the hook passes this itself)")
    p.set_defaults(func=cmd_secrets)


def _colorizer(enabled):
    def colorize(key, value):
        if key == "level":
            return "red" if value == "BLOCK" else "yellow"
        return None
    return colorize if enabled else None


def _rows(findings, history) -> list:
    rows = []
    for f in findings:
        r = {"level": f.level.upper(), "where": f.where, "what": f.what,
             "preview": f.short_preview}
        if history:
            r["commit"] = f.commit[:8]
        rows.append(r)
    return rows


def hook_report(result: ScanResult, use_color=False) -> str:
    """What the commit hook prints: short, with how to fix and how to allow."""
    from .common import color
    blocks = [f for f in result.findings if f.level == "block"]
    warns = [f for f in result.findings if f.level == "warn"]
    out = []
    if blocks:
        out.append(color("AWS Kit stopped this commit: it adds something that looks like a "
                         "secret.", "red", use_color))
        out.append("")
        width = max(len(f.where) for f in blocks)
        for f in blocks:
            out.append(f"  {f.where.ljust(width)}  {f.what}: {f.preview}")
        out += ["",
                "How to fix it:",
                "  - Take it out of the file, then git add the file again.",
                "  - Keep secrets in environment variables, a .env file listed in .gitignore,",
                "    or AWS Secrets Manager or SSM Parameter Store.",
                "  - If a key was ever pushed or shared, rotate it. Deleting the line doesn't",
                "    take it back.",
                "",
                "Not a secret?",
                "  - Add awskit:allow in a comment on that line, or",
                "  - run: awskit secrets --allow FILE:LINE   (adds its sha256 to "
                f"{ALLOW_FILE})",
                "",
                "To skip this check for one commit: git commit --no-verify"]
    if warns:
        if out:
            out.append("")
        out.append(color(f"Warnings ({len(warns)}), these don't stop the commit:", "yellow",
                         use_color))
        width = max(len(f.where) for f in warns)
        for f in warns[:10]:
            out.append(f"  {f.where.ljust(width)}  {f.what}: {f.preview}")
        if len(warns) > 10:
            out.append(f"  and {len(warns) - 10} more. Run awskit secrets --staged to see them.")
    if result.unchecked:
        # Never look clean when something wasn't read
        if out:
            out.append("")
        out.append(color("Not checked, these don't stop the commit:", "yellow", use_color))
        out += [f"  {note}" for note in result.unchecked]
    return "\n".join(out) + ("\n" if out else "")


def _terminal_progress(enabled):
    """A progress line on stderr like the other tools', for scans that may not know their
    total (staged changes). Returns (show, clear)."""
    shown = []

    def show(done, total, text):
        if not enabled:
            return
        line = (f"  {done}/{total}  {text}" if total else f"  {text}")[:100]
        sys.stderr.write("\r" + line.ljust(100))
        sys.stderr.flush()
        shown.append(True)

    def clear():
        if shown:
            sys.stderr.write("\r" + " " * 101 + "\r")
            sys.stderr.flush()
    return show, clear


def cmd_secrets(args) -> int:
    from .cli import err
    from .common import color, table_text, to_markdown
    if args.install_hook or args.remove_hook:
        try:
            if args.install_hook:
                print(install_hook(args.path, chain=args.chain))
                print("Each commit is checked for secrets first. git commit --no-verify skips "
                      "it once.")
                if not (find_awskit_on_path()):
                    err("Note: awskit isn't on your PATH, so the hook lets commits through "
                        "unchecked until it is.")
            else:
                print(remove_hook(args.path))
        except (HookError, ScanError, OSError) as exc:
            err(str(exc))
            return 2
        return 0
    settings = load_settings()
    block_ids = bool(args.block_account_ids or settings.get("block_account_ids"))
    if args.allow:
        return _cmd_allow(args.allow, block_ids)

    mode = args.mode or ("history" if args.history is not None else None)
    if args.hook and mode is None:
        mode = "staged"
    target = args.history_path if args.history_path and args.path == "." else args.path
    show, clear = _terminal_progress(sys.stderr.isatty() and not args.json and not args.hook
                                     and not args.quiet)
    try:
        result = scan(target, mode, history=args.history or settings["history_commits"],
                      block_account_ids=block_ids, progress=show)
    except (ScanError, OSError) as exc:
        clear()
        if args.hook:
            print(f"AWS Kit couldn't check this commit for secrets: {exc}\n"
                  "Fix that, or skip the check once with git commit --no-verify.",
                  file=sys.stderr)
        else:
            err(str(exc))
        return 2
    clear()

    if args.hook:
        sys.stderr.write(hook_report(result, sys.stderr.isatty() and not os.environ.get(
            "NO_COLOR")))
        return result.exit_code()
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
        return result.exit_code()
    history = result.mode == "history"
    cols = COLS + ([("commit", "Commit")] if history else [])
    if args.markdown:
        rows = _rows(result.findings, history)
        for r, f in zip(rows, result.findings):
            r["fix"] = f.fix
        text = to_markdown(rows, cols + [("fix", "How to fix")], title="Secrets scan",
                           intro=result.summary())
        try:
            write_atomic(args.markdown, text)
        except OSError as exc:
            err(f"Couldn't write {args.markdown}: {exc}")
            return 2
        print(f"Wrote {args.markdown}")
    elif not args.quiet:
        tty = sys.stdout.isatty()
        if result.findings:
            print(table_text(_rows(result.findings, history), cols, max_width=60,
                             colorize=_colorizer(tty)))
            print()
        if args.verbose:
            for f in result.findings:
                print(color(f"{f.level.upper()}  {f.where}  {f.what}", "bold"))
                if f.note:
                    print("  " + f.note)
                if f.context:
                    print("  " + f.context.replace("\n", "\n  "))
                print("  How to fix: " + f.fix + "\n")
    print(color(result.summary(), "bold"))
    if result.findings and not args.verbose and not args.quiet:
        print(color("Add -v to see the lines around each one and how to fix it.", "dim"))
    if not args.quiet:
        for note in result.notes:
            print(color("Note: " + note, "yellow"), file=sys.stderr)
    return result.exit_code()


def find_awskit_on_path() -> bool:
    return bool(shutil.which("awskit") or shutil.which("awskit.cmd"))


def _cmd_allow(specs, block_ids) -> int:
    from .cli import err
    rc = 0
    for spec in specs:
        name, _, line = spec.rpartition(":")
        if not name or not line.isdigit():
            err(f"{spec}: use FILE:LINE, like config/app.env:12.")
            rc = 2
            continue
        try:
            path = Path(os.path.expanduser(name)).resolve()
            _, repo, root, rel = resolve_target(path)
        except ScanError as exc:
            err(str(exc))
            rc = 2
            continue
        text, why = read_text(path)
        if text is None:
            err(f"Couldn't read {name} ({why}).")
            rc = 2
            continue
        allow = AllowList.load(root)
        found, allowed, _ = scan_text(text, rel or path.name, 1, block_ids, allow,
                                      with_context=False)
        hits = [f for f in found if f.line == int(line)]
        if not hits:
            if any(f.line == int(line) for f in allowed):
                print(f"{spec} is already allowed.")
            else:
                err(f"Nothing was found on line {line} of {name}.")
                rc = 2
            continue
        try:
            where, added = add_allow_entries(root, hits)
        except OSError as exc:
            err(f"Couldn't update {ALLOW_FILE}: {exc}")
            rc = 2
            continue
        whats = ", ".join(sorted({f.what for f in hits}))
        print(f"Added {added} line(s) to {where} for {spec} ({whats}). Commit that file so "
              "the hook and CI skip it too.")
    return rc
