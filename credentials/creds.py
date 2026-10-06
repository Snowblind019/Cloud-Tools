"""Credentials: credential hygiene for IAM users, access keys, roles and the root user.

Exposure Audit looks outward, at what's open to the internet. This looks inward: every
identity in each account, how old its credentials are, when they were last used, who has
admin, and what should be cleaned up.

Read-only. Every call is a get or a list, plus iam:GenerateCredentialReport, which only asks
IAM to build the credential report so it can be read. Fixes are shown as AWS CLI commands
for you to run yourself.

The reading part (read_account) is kept apart from the logic (analyze_account), so the logic
can be tested with hand-made data and run again with new thresholds without asking AWS.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shlex
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from . import iampolicy
from .common import (SEVERITY_ORDER, AuthError, AwsContext, color, error_code, error_text,
                     is_access_denied, table_text, write_atomic)

DEFAULT_KEY_AGE = 90     # days before an active key should be rotated
DEFAULT_UNUSED = 90      # days without use before something counts as unused
GRACE_DAYS = 7           # a new password or key gets a week before "never used" counts
MAX_DAYS = 3650
REPORT_WAIT = 30         # seconds to wait for IAM to build the credential report
REPORT_POLL = 0.5        # first wait between checks on the report, doubled up to 2 seconds
MAX_MANAGED_FETCH = 150  # AWS managed policies read per account, at most
STEPS = 5                # progress steps per profile

KIND_ORDER = {"root": 0, "user": 1, "role": 2, "account": 3}
# Within one severity, the order findings are listed in, worst first. The first one is what
# the Identities table shows as an identity's worst finding.
CODE_ORDER = ["root_keys", "root_mfa", "admin_keys", "can_escalate", "console_no_mfa",
              "admin_user", "user_inactive", "key_unused", "key_never_used",
              "password_unused", "password_never_used", "role_unused", "role_never_used",
              "root_used", "two_keys", "key_old", "inline_policy", "ssh_keys",
              "service_creds", "signing_certs", "root_certs", "no_password_policy",
              "weak_password_policy", "inactive_keys"]
NO_DATE = ("", "N/A", "no_information", "not_supported")
SERVICE_LINKED_PATH = "/aws-service-role/"
SSO_PATH = "/aws-reserved/sso.amazonaws.com/"
AWS_POLICY = re.compile(r"arn:aws[\w-]*:iam::aws:policy/")

SERVICE_CRED_NAMES = {
    "codecommit.amazonaws.com": "CodeCommit Git over HTTPS",
    "cassandra.amazonaws.com": "Amazon Keyspaces (for Apache Cassandra)",
    "bedrock.amazonaws.com": "Amazon Bedrock API key",
}

# AWS managed policies seen in almost every account, so they don't need reading. The
# read-only ones have nothing that can change IAM, so they're empty here.
_EMPTY = {"Version": "2012-10-17", "Statement": []}
KNOWN_AWS_POLICIES = {
    "AdministratorAccess": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "IAMFullAccess": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["iam:*", "organizations:Describe*",
                                       "organizations:List*"], "Resource": "*"}]},
    "PowerUserAccess": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole",
                                       "iam:DeleteServiceLinkedRole", "iam:ListRoles",
                                       "organizations:DescribeOrganization",
                                       "account:ListRegions", "account:GetAccountInformation"],
         "Resource": "*"}]},
    "ReadOnlyAccess": _EMPTY,
    "SecurityAudit": _EMPTY,
    "job-function/ViewOnlyAccess": _EMPTY,
}

# IAM actions that let someone give themselves more permissions, from Policy Check's list.
IAM_ESCALATION = {a: why for a, why in iampolicy.PRIV_ESC.items() if a.startswith("iam:")}
# On a user's own ARN (user/${aws:username}, or the ARN itself) only these hand out new
# permissions. Managing your own keys, password and MFA there is normal.
SELF_GRANT = ("iam:AttachUserPolicy", "iam:PutUserPolicy")
ROLE_SELF_GRANT = ("iam:AttachRolePolicy", "iam:PutRolePolicy")
USERNAME_VAR = re.compile(r"\$\{aws:username\}", re.IGNORECASE)


class Stopped(Exception):
    """The check was cancelled."""


# =================================================================== small helpers

def mask_key(key_id) -> str:
    """AKIAIOSFODNN7EXAMPLE -> AKIA****MPLE. Shown anywhere the full ID isn't needed."""
    key_id = str(key_id or "")
    if not key_id:
        return ""
    if len(key_id) <= 8:
        return "****"
    return f"{key_id[:4]}****{key_id[-4:]}"


def parse_date(value):
    """A datetime in UTC, or None for the report's N/A, no_information and not_supported."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if text in NO_DATE:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_since(dt, now) -> int | None:
    if dt is None:
        return None
    return max(int((now - dt).total_seconds() // 86400), 0)


def ago(dt, now, never="never") -> str:
    d = days_since(dt, now)
    if d is None:
        return never
    if d == 0:
        return "today"
    return "1 day ago" if d == 1 else f"{d} days ago"


def when(dt, now, never="never") -> str:
    """2026-03-01 (218 days ago)"""
    if dt is None:
        return never
    return f"{dt.astimezone(timezone.utc):%Y-%m-%d} ({ago(dt, now)})"


def plural(n, word, many=None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


_SAFE = re.compile(r"[\w+=,.@:/-]+")


def q(text) -> str:
    """A shell word. IAM names never need quoting, but nothing here assumes it."""
    text = str(text)
    return text if _SAFE.fullmatch(text) else shlex.quote(text)


def as_doc(doc):
    """A policy document as a dict. boto3 decodes them, but a URL-encoded string is
    handled too."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            text = unquote(doc) if doc.lstrip().startswith("%") else doc
            out = json.loads(text)
            return out if isinstance(out, dict) else None
        except (ValueError, RecursionError):
            return None
    return None


def policy_name(arn: str) -> str:
    """arn:aws:iam::aws:policy/job-function/ViewOnlyAccess -> job-function/ViewOnlyAccess"""
    return str(arn).split(":policy/", 1)[-1]


def is_aws_policy(arn: str) -> bool:
    return bool(AWS_POLICY.match(str(arn)))


# =================================================================== data

@dataclass
class Finding:
    severity: str
    check: str
    resource: str          # what the Identity column shows, like alice (AKIA****ABCD)
    detail: str = ""
    fix: str = ""
    command: str = ""      # the exact AWS CLI to run, one command per line
    why: str = ""
    kind: str = ""         # root, user, role or account
    name: str = ""         # the identity's name, to tie the finding to its identity
    code: str = ""         # short name of the check, like key_unused
    profile: str = ""
    account: str = ""

    def row(self) -> dict:
        d = asdict(self)
        d["profile"] = self.profile or "default"
        d["sev_rank"] = SEVERITY_ORDER.get(self.severity, 9)
        return d


@dataclass
class AccessKey:
    id: str = ""            # empty when only the credential report was readable
    status: str = ""        # Active or Inactive
    created: datetime | None = None
    last_used: datetime | None = None
    service: str = ""
    region: str = ""
    slot: str = ""          # 1 or 2 in the credential report
    use_known: bool = True  # False when its last use couldn't be read at all

    @property
    def active(self) -> bool:
        return self.status == "Active"

    @property
    def masked(self) -> str:
        return mask_key(self.id) if self.id else f"key {self.slot or '?'}"

    @property
    def ref(self) -> str:
        """For commands: the real ID, or a placeholder to fill in."""
        return self.id or "ACCESS_KEY_ID"

    def use_text(self, now) -> str:
        if not self.use_known:
            return "last use couldn't be read"
        if not self.last_used:
            return "never used"
        where = " ".join(x for x in (f"for {self.service}" if self.service else "",
                                     f"in {self.region}" if self.region else "") if x)
        return f"last used {when(self.last_used, now)}" + (f" {where}" if where else "")


@dataclass
class Identity:
    kind: str                       # root, user or role
    name: str
    arn: str = ""
    profile: str = ""
    account: str = ""
    path: str = ""
    created: datetime | None = None
    in_report: bool = False
    console: bool | None = None     # None when not known
    mfa: bool | None = None
    mfa_devices: list = field(default_factory=list)
    password_last_used: datetime | None = None
    password_changed: datetime | None = None
    keys: list = field(default_factory=list)
    ssh_keys: list = field(default_factory=list)       # {"id", "status", "uploaded"}
    service_creds: list = field(default_factory=list)  # {"id", "service", "status", ...}
    untracked_known: bool = True    # False when SSH keys or service credentials weren't read
    certs: list = field(default_factory=list)          # {"id", "status", "uploaded"}
    groups: list = field(default_factory=list)
    attached: list = field(default_factory=list)       # (policy name, arn, group or "")
    inline: list = field(default_factory=list)         # (policy name, group or "")
    boundary: str = ""
    trust: list = field(default_factory=list)
    instance_profiles: list = field(default_factory=list)
    role_last_used: datetime | None = None
    role_last_region: str = ""
    aws_managed: str = ""           # set for service-linked and Identity Center roles
    admin: str = ""                 # yes, can become, no, or "" when it couldn't be told
    admin_why: str = ""
    admin_sources: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.profile, self.kind, self.name)

    @property
    def active_keys(self) -> list:
        return [k for k in self.keys if k.active]

    @property
    def inactive_keys(self) -> list:
        return [k for k in self.keys if not k.active]

    def last_activity(self):
        dates = [self.password_last_used, self.role_last_used] + [k.last_used for k in self.keys]
        dates = [d for d in dates if d]
        return max(dates) if dates else None

    @property
    def worst(self):
        return self.findings[0] if self.findings else None

    def label(self) -> str:
        return "root user" if self.kind == "root" else f"{self.kind} {self.name}"


@dataclass
class AccountData:
    """Everything read from one account, before any judgement is made."""
    profile: str = ""
    account: str = ""
    report: list | None = None          # credential report rows
    report_time: datetime | None = None
    summary: dict | None = None
    password_policy: dict | None = None
    password_policy_read: bool = False  # True once it's known, even when there's none
    auth: dict | None = None            # users, groups, roles and policies
    keys: dict = field(default_factory=dict)           # user -> [AccessKey]
    key_use_read: bool = True           # False when GetAccessKeyLastUsed wasn't allowed
    ssh: dict = field(default_factory=dict)            # user -> [dict]
    service_creds: dict = field(default_factory=dict)  # user -> [dict]
    mfa: dict = field(default_factory=dict)            # user -> [serial numbers]
    certs: dict = field(default_factory=dict)          # user -> [dict]
    managed_docs: dict = field(default_factory=dict)   # AWS managed policy ARN -> document
    denied: dict = field(default_factory=dict)         # what -> first AccessDenied error
    failed: dict = field(default_factory=dict)         # what -> readable error
    generate_denied: bool = False
    report_skipped: int = 0             # credential report rows that didn't line up

    @property
    def label(self) -> str:
        return self.profile or "default"


@dataclass
class Result:
    findings: list
    identities: list
    warnings: list
    stats: dict
    accounts: list                  # the AccountData, to analyze again with new thresholds
    key_age: int = DEFAULT_KEY_AGE
    unused: int = DEFAULT_UNUSED
    errors: list = field(default_factory=list)  # profiles that couldn't be read at all
    now: datetime | None = None

    def summary(self) -> str:
        return summary_text(self.stats, self.key_age, self.unused)

    def counts(self) -> dict:
        return counts(self.findings)

    def identity_for(self, finding):
        for i in self.identities:
            if i.key == (finding.profile, finding.kind, finding.name):
                return i
        return None

    def as_json(self) -> dict:
        now = self.now or datetime.now(timezone.utc)
        return {"summary": self.summary(), "counts": self.counts(),
                "key_age_days": self.key_age, "unused_days": self.unused,
                "findings": [f.row() for f in self.findings],
                "identities": [identity_json(i, now) for i in self.identities],
                "warnings": self.warnings}


# =================================================================== reading

NOTES = {
    # what: (the IAM actions, what couldn't be checked because of it)
    "report": ("iam:GenerateCredentialReport and iam:GetCredentialReport",
               "console passwords, MFA, key use and the root user weren't checked"),
    "summary": ("iam:GetAccountSummary",
                "the root user's MFA and keys only come from the credential report"),
    "password_policy": ("iam:GetAccountPasswordPolicy", "the password policy wasn't checked"),
    "auth": ("iam:GetAccountAuthorizationDetails",
             "roles, groups and policies weren't read, so admin access and unused roles "
             "weren't checked"),
    "keys": ("iam:ListAccessKeys",
             "access keys come from the credential report, without their IDs"),
    "key_last_used": ("iam:GetAccessKeyLastUsed",
                      "key use comes from the credential report"),
    "ssh": ("iam:ListSSHPublicKeys", "SSH keys weren't checked"),
    "service_creds": ("iam:ListServiceSpecificCredentials",
                      "service-specific credentials weren't checked"),
    "mfa": ("iam:ListMFADevices", "MFA device serial numbers weren't read"),
    "certs": ("iam:ListSigningCertificates", "signing certificate IDs weren't read"),
    "managed": ("iam:GetPolicy and iam:GetPolicyVersion",
                "some AWS managed policies weren't read, so admin access may be missing for "
                "the identities that use them"),
}
THINGS = {"report": "the credential report", "summary": "the account summary",
          "password_policy": "the password policy", "auth": "users, groups, roles and policies",
          "keys": "access keys", "key_last_used": "when access keys were last used",
          "ssh": "SSH keys", "service_creds": "service-specific credentials",
          "mfa": "MFA devices", "certs": "signing certificates",
          "managed": "AWS managed policies"}
REPORT_STATES = {
    "ReportInProgress": "IAM is still making the credential report. Run the check again in "
                        "a minute.",
    "ReportNotPresent": "There's no credential report yet. Run the check again in a minute.",
    "ReportExpired": "The credential report is more than 4 hours old. Run the check again "
                     "for a fresh one.",
}


def _record(data, what, exc):
    """Remember why something couldn't be read. Only the first error of a kind is kept."""
    if is_access_denied(exc):
        data.denied.setdefault(what, exc)
    else:
        data.failed.setdefault(what, error_text(exc, data.profile or None))


def parse_report(content) -> list:
    """The credential report CSV as a list of dicts, one per user plus <root_account>."""
    return report_rows(content)[0]


def _row_lines_up(row) -> bool:
    """A row with the right number of columns whose ARN belongs to its user. IAM names can
    hold commas, so a badly quoted name could otherwise shift values into the wrong columns,
    or pose as another user's row."""
    if None in row or None in row.values():
        return False  # too many or too few columns
    user, arn = row.get("user", "").strip(), row.get("arn", "").strip()
    if user == "<root_account>":
        return arn.startswith("arn:") and arn.endswith(":root")
    return arn.startswith("arn:") and ":user/" in arn and arn.endswith("/" + user)


def report_rows(content) -> tuple:
    """(rows, skipped): the rows that line up, and how many didn't."""
    if isinstance(content, bytes):
        content = content.decode("utf-8-sig", errors="replace")
    rows, skipped = [], 0
    for row in csv.DictReader(io.StringIO(content or "")):
        if not (row.get("user") or "").strip():
            continue
        if not _row_lines_up(row):
            skipped += 1
            continue
        rows.append({k: (v or "").strip() for k, v in row.items() if k})
    return rows, skipped


def _read_report(ctx, data, cancel=None):
    iam = ctx.client("iam")
    deadline = time.time() + REPORT_WAIT
    wait = REPORT_POLL
    while True:
        try:
            state = iam.generate_credential_report().get("State")
        except Exception as exc:  # noqa: BLE001
            if not is_access_denied(exc):
                _record(data, "report", exc)
                return
            # Maybe a recent report can still be read.
            data.generate_denied = True
            break
        if state == "COMPLETE" or time.time() > deadline:
            break
        if cancel is not None and cancel.is_set():
            raise Stopped()
        time.sleep(wait)
        wait = min(wait * 2, 2)
    try:
        resp = iam.get_credential_report()
    except Exception as exc:  # noqa: BLE001
        code = error_code(exc)
        if code in REPORT_STATES:
            msg = REPORT_STATES[code]
            if data.generate_denied:
                msg = ("There's no recent credential report, and this profile can't ask for "
                       "one (no permission for iam:GenerateCredentialReport).")
            data.failed.setdefault("report", msg)
        else:
            _record(data, "report", exc)
        return
    data.report, data.report_skipped = report_rows(resp.get("Content") or b"")
    data.report_time = parse_date(resp.get("GeneratedTime"))


def _read_settings(ctx, data):
    iam = ctx.client("iam")
    try:
        data.summary = iam.get_account_summary().get("SummaryMap", {}) or {}
    except Exception as exc:  # noqa: BLE001
        _record(data, "summary", exc)
    try:
        data.password_policy = iam.get_account_password_policy().get("PasswordPolicy") or {}
        data.password_policy_read = True
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchEntity":
            data.password_policy = None
            data.password_policy_read = True
        else:
            _record(data, "password_policy", exc)


def _read_auth(ctx, data, cancel=None):
    iam = ctx.client("iam")
    out = {"users": [], "groups": [], "roles": [], "policies": []}
    try:
        pages = iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"])
        for page in pages:
            if cancel is not None and cancel.is_set():
                raise Stopped()
            out["users"] += page.get("UserDetailList") or []
            out["groups"] += page.get("GroupDetailList") or []
            out["roles"] += page.get("RoleDetailList") or []
            out["policies"] += page.get("Policies") or []
    except Stopped:
        raise
    except Exception as exc:  # noqa: BLE001
        _record(data, "auth", exc)
        return
    data.auth = out


class _Gate:
    """Stops asking for something once AWS has said no, so a missing permission costs one
    call per account instead of one per user."""

    def __init__(self, data):
        self.data = data
        self.closed = set()
        self.lock = threading.Lock()

    def call(self, what, fn, **kwargs):
        if what in self.closed:
            return None
        try:
            return fn(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) == "NoSuchEntity":
                return None  # deleted while we were reading
            with self.lock:
                _record(self.data, what, exc)
                self.closed.add(what)
            return None


def _read_user(ctx, data, gate, name, row):
    iam = ctx.client("iam")
    resp = gate.call("keys", iam.list_access_keys, UserName=name)
    if resp is not None:
        keys = []
        for meta in resp.get("AccessKeyMetadata") or []:
            k = AccessKey(id=meta.get("AccessKeyId", ""), status=meta.get("Status", ""),
                          created=parse_date(meta.get("CreateDate")))
            used = gate.call("key_last_used", iam.get_access_key_last_used,
                             AccessKeyId=k.id) if k.id else None
            if used is not None:
                info = used.get("AccessKeyLastUsed") or {}
                k.last_used = parse_date(info.get("LastUsedDate"))
                if k.last_used:
                    k.service = "" if info.get("ServiceName") in NO_DATE else \
                        info.get("ServiceName", "")
                    k.region = "" if info.get("Region") in NO_DATE else info.get("Region", "")
            else:
                k.use_known = False  # not "never used": the credential report may still say
                data.key_use_read = False
            keys.append(k)
        keys.sort(key=lambda k: k.created or datetime.min.replace(tzinfo=timezone.utc))
        data.keys[name] = keys
    resp = gate.call("ssh", iam.list_ssh_public_keys, UserName=name)
    if resp is not None:
        data.ssh[name] = [{"id": k.get("SSHPublicKeyId", ""), "status": k.get("Status", ""),
                           "uploaded": parse_date(k.get("UploadDate"))}
                          for k in resp.get("SSHPublicKeys") or []]
    resp = gate.call("service_creds", iam.list_service_specific_credentials, UserName=name)
    if resp is not None:
        data.service_creds[name] = [
            {"id": c.get("ServiceSpecificCredentialId", ""), "status": c.get("Status", ""),
             "service": c.get("ServiceName", ""), "username": c.get("ServiceUserName", ""),
             "created": parse_date(c.get("CreateDate"))}
            for c in resp.get("ServiceSpecificCredentials") or []]
    if row is None or row.get("mfa_active") == "true":
        resp = gate.call("mfa", iam.list_mfa_devices, UserName=name)
        if resp is not None:
            data.mfa[name] = [d.get("SerialNumber", "") for d in resp.get("MFADevices") or []]
    if row is None or any(row.get(f"cert_{n}_last_rotated", "N/A") not in NO_DATE
                          for n in "12"):
        resp = gate.call("certs", iam.list_signing_certificates, UserName=name)
        if resp is not None:
            data.certs[name] = [{"id": c.get("CertificateId", ""), "status": c.get("Status", ""),
                                 "uploaded": parse_date(c.get("UploadDate"))}
                                for c in resp.get("Certificates") or []]


def _aws_policy_arns(data) -> list:
    """AWS managed policies attached to users, groups and roles (not service-linked roles),
    that aren't in KNOWN_AWS_POLICIES."""
    if not data.auth:
        return []
    arns = set()
    for u in data.auth["users"]:
        arns.update(p.get("PolicyArn", "") for p in u.get("AttachedManagedPolicies") or [])
    for g in data.auth["groups"]:
        arns.update(p.get("PolicyArn", "") for p in g.get("AttachedManagedPolicies") or [])
    for r in data.auth["roles"]:
        if str(r.get("Path", "")).startswith(SERVICE_LINKED_PATH):
            continue
        arns.update(p.get("PolicyArn", "") for p in r.get("AttachedManagedPolicies") or [])
    return sorted(a for a in arns if is_aws_policy(a) and policy_name(a) not in KNOWN_AWS_POLICIES)


def _read_managed(ctx, data, cache, cache_lock, cancel=None):
    """Read the AWS managed policies that aren't known already. They're the same in every
    account, so one cache is shared by all the accounts in a check."""
    wanted = _aws_policy_arns(data)
    gate = _Gate(data)
    if len(wanted) > MAX_MANAGED_FETCH:
        data.failed.setdefault("managed", f"{len(wanted)} different AWS managed policies are "
                               f"attached, and only the first {MAX_MANAGED_FETCH} were read")
        wanted = wanted[:MAX_MANAGED_FETCH]

    def one(arn):
        if cancel is not None and cancel.is_set():
            return
        with cache_lock:
            if arn in cache:
                data.managed_docs[arn] = cache[arn]
                return
        iam = ctx.client("iam")
        pol = gate.call("managed", iam.get_policy, PolicyArn=arn)
        if not pol:
            return
        version = pol.get("Policy", {}).get("DefaultVersionId")
        resp = gate.call("managed", iam.get_policy_version, PolicyArn=arn,
                         VersionId=version) if version else None
        doc = as_doc((resp or {}).get("PolicyVersion", {}).get("Document"))
        if doc is not None:
            with cache_lock:
                cache[arn] = doc
            data.managed_docs[arn] = doc

    if wanted:
        with ThreadPoolExecutor(max_workers=min(4, len(wanted))) as pool:
            list(pool.map(one, wanted))


PHASE_DONE = {"report": "credential report read", "settings": "account settings read",
              "auth": "users, groups, roles and policies read"}


def read_account(ctx, step=None, cancel=None, cache=None, cache_lock=None,
                 workers=6) -> AccountData:
    """Read everything Credentials needs from one account. Gaps are recorded in
    data.denied and data.failed, never raised. step(text, advance) reports progress and
    is called STEPS times with advance=1."""
    step = step or (lambda text, advance=1: None)
    cache = {} if cache is None else cache
    cache_lock = cache_lock or threading.Lock()
    data = AccountData(profile=ctx.profile or "", account=ctx.account)

    def check_cancel():
        if cancel is not None and cancel.is_set():
            raise Stopped()

    step("asking IAM for the credential report, users and roles", 0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_read_report, ctx, data, cancel): "report",
                   pool.submit(_read_settings, ctx, data): "settings",
                   pool.submit(_read_auth, ctx, data, cancel): "auth"}
        for fut in as_completed(futures):
            fut.result()
            step(PHASE_DONE[futures[fut]])
    check_cancel()

    rows = {r["user"]: r for r in data.report or [] if r.get("user") != "<root_account>"}
    if data.auth is not None:
        names = [u.get("UserName", "") for u in data.auth["users"] if u.get("UserName")]
    else:
        names = list(rows)
    gate = _Gate(data)

    def one(name):
        if cancel is not None and cancel.is_set():
            return
        _read_user(ctx, data, gate, name, rows.get(name))

    if names:
        with ThreadPoolExecutor(max_workers=min(workers, len(names))) as pool:
            list(pool.map(one, names))
    check_cancel()
    step("keys and other credentials read")
    _read_managed(ctx, data, cache, cache_lock, cancel)
    check_cancel()
    step("done")
    return data


# =================================================================== policies

_ALL = re.compile(r"arn:(\*|[\w-]+):\*(:\*?)*")


def _every_resource(resources) -> bool:
    """Resource "*" (or an ARN that's all wildcards), which admin needs."""
    for r in resources:
        r = str(r).strip()
        if (r and not r.strip("*")) or r == "arn:*" or _ALL.fullmatch(r):
            return True
    return False


def _can_be_iam(resource) -> bool:
    """Whether a Resource entry could match an IAM user, group, role or policy. Escalation
    needs one: iam:* on arn:aws:s3:::* can't touch IAM."""
    parts = str(resource).strip().split(":", 3)
    if parts[0] != "arn" or len(parts) < 3:
        return True  # "*", "arn:*" and the like
    return parts[2].lower() == "iam" or iampolicy.has_wildcard(parts[2])


def _is_self(resource, arn, kind) -> bool:
    """Whether a Resource entry matches the identity's own ARN. ${aws:username} is the
    user's name; a role has none, so it matches nothing there."""
    resource = str(resource).strip()
    if not arn:
        return kind == "user" and bool(USERNAME_VAR.search(resource))
    if USERNAME_VAR.search(resource):
        if kind != "user":
            return False
        name = arn.rsplit("/", 1)[-1]
        resource = USERNAME_VAR.sub(lambda _: name, resource)
    from fnmatch import fnmatchcase
    # Only * and ? are wildcards in IAM, so [ is made literal.
    return fnmatchcase(arn.lower(), resource.lower().replace("[", "[[]"))


def _actions(stmt) -> list:
    return [str(a) for a in iampolicy.as_list(stmt.get("Action"))]


def _patterns(stmt, catalog) -> list:
    """The actions from catalog a statement allows. NotAction allows everything it
    doesn't list."""
    not_actions = [str(a) for a in iampolicy.as_list(stmt.get("NotAction"))]
    if not_actions:
        return [a for a in catalog if not iampolicy.grants(not_actions, a)]
    return [a for a in catalog if iampolicy.grants(_actions(stmt), a)]


def _shown(stmt, hits) -> str:
    """How the policy itself spells the matching actions: iam:* rather than 15 names."""
    not_actions = [str(a) for a in iampolicy.as_list(stmt.get("NotAction"))]
    if not_actions:
        return "every action except " + ", ".join(not_actions[:3]) + \
            (" and more" if len(not_actions) > 3 else "")
    from fnmatch import fnmatchcase
    own = [p for p in _actions(stmt) if any(fnmatchcase(h.lower(), p.lower()) for h in hits)]
    own = own or hits
    return ", ".join(own[:3]) + (f" and {len(own) - 3} more" if len(own) > 3 else "")


def _where(stmt) -> str:
    resources = [str(r) for r in iampolicy.as_list(stmt.get("Resource"))]
    if "NotResource" in stmt or _every_resource(resources):
        return "any resource"
    return ", ".join(resources[:2]) + (" and more" if len(resources) > 2 else "")


def _admin_statement(stmt) -> str:
    """Why an Allow statement amounts to full admin, or ""."""
    resources = iampolicy.as_list(stmt.get("Resource"))
    every = _every_resource(resources) or "NotResource" in stmt
    if not every:
        return ""
    if any(a.strip() in ("*", "*:*") for a in _actions(stmt)):
        return "allows * on *"
    not_actions = [str(a) for a in iampolicy.as_list(stmt.get("NotAction"))]
    if not_actions and not any(iampolicy.grants(not_actions, a) for a in IAM_ESCALATION):
        return "allows every action except " + ", ".join(not_actions[:3]) + \
            (" and more" if len(not_actions) > 3 else "")
    return ""


def source_label(src) -> str:
    """AdministratorAccess through group admins, inline policy deploy, and so on."""
    base = src["policy"] if src["how"] == "attached" else f"inline policy {src['policy']}"
    if src.get("group"):
        return f"{base} through group {src['group']}"
    return base + (" (attached)" if src["how"] == "attached" else "")


def verdict(sources, arn="", kind="user") -> tuple:
    """sources: [(source, document or None)] for the identity with this ARN, a user or a
    role. Returns (admin, why, culprit sources), where admin is yes, can become, no, or ""
    when an unreadable policy leaves it open."""
    admin, escalate, passrole, pairs, unknown = [], [], [], {}, []
    self_grant = ROLE_SELF_GRANT if kind == "role" else SELF_GRANT
    for src, doc in sources:
        if doc is None:
            unknown.append(src)
            continue
        for stmt in iampolicy.statements(doc):
            if str(stmt.get("Effect", "")).capitalize() != "Allow":
                continue
            why = _admin_statement(stmt)
            if why:
                admin.append((src, why))
                continue
            resources = [str(r) for r in iampolicy.as_list(stmt.get("Resource"))]
            # user/${aws:username} is the caller's own user, even with a wildcard account.
            own = [r for r in resources if USERNAME_VAR.search(r)]
            others = [r for r in resources if r not in own and _can_be_iam(r)]
            broad = iampolicy.is_broad_resource(others) or "NotResource" in stmt
            if broad:
                hits = _patterns(stmt, IAM_ESCALATION)
                if hits:
                    escalate.append((src, f"{_shown(stmt, hits)} on {_where(stmt)}"))
                if _patterns(stmt, ["iam:PassRole"]):
                    passrole.append(src)
            elif any(_is_self(r, arn, kind) for r in own + others):
                hits = _patterns(stmt, self_grant)
                if hits:
                    escalate.append((src, f"{_shown(stmt, hits)} on the {kind} itself"))
            for action in _patterns(stmt, iampolicy.PASSROLE_PAIRS):
                pairs.setdefault(action, src)
    if admin:
        src, why = admin[0]
        label = source_label(src)
        text = label if src["policy"] == "AdministratorAccess" else f"{label} {why}"
        if len(admin) > 1:
            more = sorted({source_label(s) for s, _ in admin[1:]} - {label})
            if more:
                text += ", also " + ", ".join(more[:2])
        return "yes", text, _unique([s for s, _ in admin])
    if escalate or (passrole and pairs):
        parts = [f"{source_label(s)} allows {what}" for s, what in escalate[:2]]
        culprits = [s for s, _ in escalate]
        if passrole and pairs:
            action = sorted(pairs)[0]
            how = iampolicy.PASSROLE_PAIRS[action]
            if source_label(passrole[0]) == source_label(pairs[action]):
                parts.append(f"{source_label(passrole[0])} allows iam:PassRole on any role and "
                             f"{action}, so it can {how}")
            else:
                parts.append(f"{source_label(passrole[0])} allows iam:PassRole on any role, and "
                             f"{source_label(pairs[action])} allows {action}, so it can {how}")
            culprits += [passrole[0], pairs[action]]
        return "can become", "; ".join(parts), _unique(culprits)
    if unknown:
        return "", "couldn't read " + ", ".join(source_label(s) for s in unknown[:3]), []
    return "no", "", []


def _unique(sources) -> list:
    out, seen = [], set()
    for s in sources:
        k = (s["how"], s["policy"], s.get("arn", ""), s.get("group", ""))
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


def trust_text(doc) -> list:
    """Who a role trusts, in short: ec2.amazonaws.com, account 111122223333, GitHub OIDC."""
    out = []
    for stmt in iampolicy.statements(as_doc(doc) or {}):
        if str(stmt.get("Effect", "")).capitalize() != "Allow":
            continue
        for kind, values in iampolicy.principal_parts(stmt.get("Principal")).items():
            for v in values:
                if kind == "Service":
                    text = v
                elif kind == "Federated":
                    text = "GitHub OIDC" if "token.actions.githubusercontent.com" in v else \
                        ("SAML " + v.rsplit("/", 1)[-1] if ":saml-provider/" in v else v)
                elif v == "*":
                    text = "anyone (*)"
                else:
                    acct = iampolicy.account_of(v)
                    whole_account = acct and (v == acct or v.endswith(":root"))
                    text = f"account {acct}" if whole_account else v
                if text not in out:
                    out.append(text)
    return out


# =================================================================== building identities

def _row_keys(row) -> list:
    """Access keys from a credential report row, without IDs."""
    keys = []
    for n in ("1", "2"):
        created = parse_date(row.get(f"access_key_{n}_last_rotated"))
        active = row.get(f"access_key_{n}_active") == "true"
        if not created and not active:
            continue
        svc = row.get(f"access_key_{n}_last_used_service", "")
        reg = row.get(f"access_key_{n}_last_used_region", "")
        keys.append(AccessKey(status="Active" if active else "Inactive", created=created,
                              last_used=parse_date(row.get(f"access_key_{n}_last_used_date")),
                              service="" if svc in NO_DATE else svc,
                              region="" if reg in NO_DATE else reg, slot=n))
    return keys


def _row_certs(row) -> list:
    out = []
    for n in ("1", "2"):
        uploaded = parse_date(row.get(f"cert_{n}_last_rotated"))
        active = row.get(f"cert_{n}_active") == "true"
        if uploaded or active:
            out.append({"id": "", "status": "Active" if active else "Inactive",
                        "uploaded": uploaded, "slot": n})
    return out


def _fill_key_use(keys, row):
    """When GetAccessKeyLastUsed wasn't allowed, take key use from the credential report.
    Report slots are matched to keys by creation time, and only when that's unambiguous,
    since a mix-up would point a delete command at the key that's in use."""
    slots = _row_keys(row)
    for k in keys:
        if k.last_used or not k.created:
            continue
        match = [s for s in slots if s.created and abs((s.created - k.created).total_seconds()) < 2]
        if len(match) == 1:
            k.last_used, k.service, k.region = match[0].last_used, match[0].service, match[0].region
            k.use_known = True


def _sources_for_user(u, detail, groups, docs) -> list:
    out = []
    for p in detail.get("AttachedManagedPolicies") or []:
        arn = p.get("PolicyArn", "")
        out.append(({"how": "attached", "policy": p.get("PolicyName") or policy_name(arn),
                     "arn": arn, "group": ""}, docs.get(arn)))
    for p in detail.get("UserPolicyList") or []:
        out.append(({"how": "inline", "policy": p.get("PolicyName", ""), "arn": "", "group": ""},
                    as_doc(p.get("PolicyDocument"))))
    for g in u.groups:
        gd = groups.get(g)
        if gd is None:
            continue
        for p in gd.get("AttachedManagedPolicies") or []:
            arn = p.get("PolicyArn", "")
            out.append(({"how": "attached", "policy": p.get("PolicyName") or policy_name(arn),
                         "arn": arn, "group": g}, docs.get(arn)))
        for p in gd.get("GroupPolicyList") or []:
            out.append(({"how": "inline", "policy": p.get("PolicyName", ""), "arn": "",
                         "group": g}, as_doc(p.get("PolicyDocument"))))
    return out


def _policy_docs(data) -> dict:
    """Policy ARN -> default version document, for customer and AWS managed policies."""
    docs = {}
    for p in (data.auth or {}).get("policies") or []:
        for v in p.get("PolicyVersionList") or []:
            if v.get("IsDefaultVersion"):
                docs[p.get("Arn", "")] = as_doc(v.get("Document"))
    for arn, doc in data.managed_docs.items():
        docs[arn] = doc
    return _Docs(docs)


class _Docs(dict):
    """Policy documents by ARN, with the well-known AWS managed ones built in."""

    def get(self, arn, default=None):
        if arn in self:
            return self[arn]
        if is_aws_policy(arn) and policy_name(arn) in KNOWN_AWS_POLICIES:
            return KNOWN_AWS_POLICIES[policy_name(arn)]
        return default


def build_identities(data) -> list:
    """The root user, every IAM user and every role in one account, from what was read."""
    out = []
    rows = {r.get("user"): r for r in data.report or []}
    root_row = rows.pop("<root_account>", None)
    root = _build_root(data, root_row)
    if root is not None:
        out.append(root)
    docs = _policy_docs(data)
    groups = {g.get("GroupName"): g for g in (data.auth or {}).get("groups") or []}
    auth_users = {u.get("UserName"): u for u in (data.auth or {}).get("users") or []}
    names = list(auth_users) if data.auth is not None else list(rows)
    for name in sorted(names, key=str.lower):
        out.append(_build_user(data, name, auth_users.get(name), rows.get(name), groups, docs))
    for r in sorted((data.auth or {}).get("roles") or [], key=lambda r: r.get("RoleName", "").lower()):
        out.append(_build_role(data, r, docs))
    return out


def _build_root(data, row):
    summary = data.summary or {}
    if row is None and data.summary is None:
        return None
    i = Identity(kind="root", name="root", profile=data.profile, account=data.account,
                 arn=(row or {}).get("arn") or (f"arn:aws:iam::{data.account}:root"
                                                if data.account else ""))
    if row is not None:
        i.in_report = True
        i.created = parse_date(row.get("user_creation_time"))
        i.mfa = row.get("mfa_active") == "true"
        i.password_last_used = parse_date(row.get("password_last_used"))
        i.keys = _row_keys(row)
        i.certs = [c for c in _row_certs(row) if c["status"] == "Active"]
    if data.summary is not None:
        # The summary is live, while the report can be 4 hours old, so the summary wins:
        # MFA added or keys deleted since the report shouldn't still be flagged.
        i.mfa = bool(summary.get("AccountMFAEnabled"))
        if not summary.get("AccountAccessKeysPresent"):
            i.keys = []
        elif not i.keys:
            i.keys.append(AccessKey(status="Active"))
        if not summary.get("AccountSigningCertificatesPresent"):
            i.certs = []
        elif not i.certs:
            i.certs.append({"id": "", "status": "Active", "uploaded": None})
    i.console = True
    i.admin, i.admin_why = "yes", "The root user can do anything in the account."
    return i


def _build_user(data, name, detail, row, groups, docs):
    detail = detail or {}
    u = Identity(kind="user", name=name, profile=data.profile, account=data.account,
                 arn=detail.get("Arn") or (row or {}).get("arn", ""),
                 path=detail.get("Path", ""),
                 created=parse_date(detail.get("CreateDate")) or
                 parse_date((row or {}).get("user_creation_time")))
    if row is not None:
        u.in_report = True
        u.console = row.get("password_enabled") == "true"
        u.mfa = row.get("mfa_active") == "true"
        u.password_last_used = parse_date(row.get("password_last_used"))
        u.password_changed = parse_date(row.get("password_last_changed"))
    if name in data.keys:
        u.keys = data.keys[name]
        if not data.key_use_read and row is not None:
            _fill_key_use(u.keys, row)
    elif row is not None:
        u.keys = _row_keys(row)
    u.ssh_keys = data.ssh.get(name, [])
    u.service_creds = data.service_creds.get(name, [])
    # Once a list call failed, the users after it weren't read, and IAM doesn't record when
    # these are used, so "no activity" can't be told for them.
    u.untracked_known = all(name in got or (what not in data.denied and what not in data.failed)
                            for what, got in (("ssh", data.ssh),
                                              ("service_creds", data.service_creds)))
    u.mfa_devices = data.mfa.get(name, [])
    if name in data.certs:
        u.certs = data.certs[name]
    elif row is not None:
        u.certs = _row_certs(row)
    u.groups = list(detail.get("GroupList") or [])
    u.attached = [(p.get("PolicyName", ""), p.get("PolicyArn", ""), "")
                  for p in detail.get("AttachedManagedPolicies") or []]
    u.inline = [(p.get("PolicyName", ""), "") for p in detail.get("UserPolicyList") or []]
    for g in u.groups:
        gd = groups.get(g) or {}
        u.attached += [(p.get("PolicyName", ""), p.get("PolicyArn", ""), g)
                       for p in gd.get("AttachedManagedPolicies") or []]
        u.inline += [(p.get("PolicyName", ""), g) for p in gd.get("GroupPolicyList") or []]
    u.boundary = (detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn", "")
    if data.auth is not None and detail:
        u.admin, u.admin_why, u.admin_sources = verdict(_sources_for_user(u, detail, groups, docs),
                                                        u.arn, "user")
    return u


def _build_role(data, r, docs):
    path = r.get("Path", "") or "/"
    last = r.get("RoleLastUsed") or {}
    i = Identity(kind="role", name=r.get("RoleName", ""), arn=r.get("Arn", ""), path=path,
                 profile=data.profile, account=data.account,
                 created=parse_date(r.get("CreateDate")),
                 role_last_used=parse_date(last.get("LastUsedDate")),
                 role_last_region=last.get("Region", "") or "")
    if path.startswith(SERVICE_LINKED_PATH):
        i.aws_managed = "service-linked role"
    elif path.startswith(SSO_PATH):
        i.aws_managed = "IAM Identity Center role"
    i.attached = [(p.get("PolicyName", ""), p.get("PolicyArn", ""), "")
                  for p in r.get("AttachedManagedPolicies") or []]
    i.inline = [(p.get("PolicyName", ""), "") for p in r.get("RolePolicyList") or []]
    i.trust = trust_text(r.get("AssumeRolePolicyDocument"))
    i.instance_profiles = [p.get("InstanceProfileName", "")
                           for p in r.get("InstanceProfileList") or []]
    i.boundary = (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn", "")
    if i.aws_managed != "service-linked role":
        sources = [({"how": "attached", "policy": p.get("PolicyName") or policy_name(p.get("PolicyArn", "")),
                     "arn": p.get("PolicyArn", ""), "group": ""}, docs.get(p.get("PolicyArn", "")))
                   for p in r.get("AttachedManagedPolicies") or []]
        sources += [({"how": "inline", "policy": p.get("PolicyName", ""), "arn": "", "group": ""},
                     as_doc(p.get("PolicyDocument"))) for p in r.get("RolePolicyList") or []]
        i.admin, i.admin_why, i.admin_sources = verdict(sources, i.arn, "role")
    return i


# =================================================================== findings

WHY = {
    "root_keys": "Root access keys can do anything in the account, and no policy can limit "
                 "them. If one leaks, the whole account is gone.",
    "root_mfa": "Anyone who gets the root password, or can reset it through the root email "
                "address, can take over the account.",
    "root_used": "Root should only be used for the few tasks that need it. Using it day to day "
                 "means its password or keys are handled often, and what it does can't be "
                 "limited.",
    "root_certs": "Signing certificates are for old SOAP APIs and are almost never needed. On "
                  "the root user they're one more way in.",
    "console_no_mfa": "A password alone can be phished, guessed or reused from another site. "
                      "MFA stops most account takeovers.",
    "password_unused": "A password nobody uses is still a way in, and nobody would notice if "
                       "someone else started using it.",
    "password_never_used": "A password that was set and never used is usually left over from "
                           "setup, and it still works for anyone who has it.",
    "key_never_used": "A key nobody uses can still leak from wherever it was saved, and "
                      "nothing breaks when you delete it.",
    "key_unused": "An old key that nothing uses can still leak from a laptop, a repo or a CI "
                  "log, and nobody would miss it if it were gone.",
    "key_old": "The longer a key lives, the more places it gets copied to. Rotating it limits "
               "how long a leaked copy keeps working.",
    "two_keys": "Two active keys only make sense for a short time while rotating. The extra "
                "one is usually forgotten.",
    "inactive_keys": "Inactive keys can't be used, but anyone with IAM access can turn them "
                     "back on. Deleting them keeps things tidy.",
    "user_inactive": "A user nobody uses still has its permissions and credentials. Deleting "
                     "it removes a way in that nobody is watching.",
    "admin_keys": "An admin access key that leaks gives full control of the account, and "
                  "long-lived keys leak through code, logs and old laptops.",
    "admin_user": "Admin on a long-lived IAM user is always on. A role or IAM Identity Center "
                  "gives the same access only when it's needed, with short-lived credentials.",
    "can_escalate": "With these permissions the user can give itself more access than it "
                    "has, up to full admin, so in practice it's an admin.",
    "inline_policy": "Inline policies are hidden inside one user and easy to forget. Managed "
                     "policies or groups are easier to review and reuse.",
    "ssh_keys": "SSH keys on an IAM user are only used for CodeCommit over SSH. If that's not "
                "in use any more, they're a leftover way in.",
    "service_creds": "Service-specific credentials are passwords for one service. IAM doesn't "
                     "record when they're used, so it's easy to forget they exist.",
    "signing_certs": "Signing certificates are for old SOAP APIs and are almost never needed "
                     "today.",
    "role_unused": "A role nothing uses still has its permissions, and whoever it trusts can "
                   "still assume it. IAM only tracks role use for the last 400 days, and not "
                   "in every region, so check CloudTrail before deleting.",
    "no_password_policy": "Without a policy, IAM users can set short passwords that are easy "
                          "to guess.",
    "weak_password_policy": "Short passwords and reused old ones are the easiest to guess or "
                            "find in leaked password lists.",
}

FIX = {
    "root_keys": "Sign in as the root user, open Security credentials, then deactivate and "
                 "delete the access keys. Use an IAM role or Identity Center for whatever "
                 "used them.",
    "root_mfa": "Sign in as the root user, open Security credentials and assign an MFA device. "
                "A passkey or security key is best. In an organization with centralized root "
                "access, member accounts can have no root password at all instead.",
    "root_used": "Use IAM Identity Center or an IAM role for everyday work. Check what root did "
                 "in CloudTrail with the command below, or on the CloudTrail page.",
    "root_certs": "Sign in as the root user and delete them under Security credentials.",
    "console_no_mfa": "Have the user add MFA under Security credentials, or remove console "
                      "access if they don't need it. Better, move people to IAM Identity "
                      "Center.",
    "password_unused": "Remove console access. You can give it back later with "
                       "aws iam create-login-profile.",
    "key_unused": "Deactivate it, and delete it once you're sure nothing broke.",
    "key_old": "Rotate it: create a new key, switch whatever uses the old one, then deactivate "
               "and delete the old one. Better, use a role or IAM Identity Center so there "
               "are no long-lived keys.",
    "two_keys": "Keep the key that's in use and deactivate the other one.",
    "inactive_keys": "Delete them.",
    "user_inactive": "Delete the user if nobody needs it. Its password, keys, groups and "
                     "policies have to go first, which the commands below do.",
    "admin_keys": "Do admin work through IAM Identity Center or a role you assume with MFA, "
                  "and get rid of this user's keys. Short-lived credentials from "
                  "aws sso login or a role can't leak for long.",
    "admin_user": "Do admin work through IAM Identity Center or a role you assume with MFA, "
                  "and take admin off this user once you have that other way in.",
    "can_escalate": "Limit those actions to exact resources (for iam:PassRole, the exact roles "
                    "it should pass), or add a permissions boundary that blocks them.",
    "inline_policy": "Move the permissions into a managed policy or a group, then delete the "
                     "inline policy.",
    "ssh_keys": "Delete them if nobody pushes to CodeCommit over SSH as this user any more.",
    "service_creds": "Delete the ones you don't use.",
    "signing_certs": "Delete them unless something still uses the old SOAP APIs.",
    "role_unused": "Delete it if nothing needs it. Its policies have to be detached first, "
                   "which the commands below do.",
    "no_password_policy": "Set a password policy: at least 14 characters, no reuse of recent "
                          "passwords, and users can change their own. Or move people to IAM "
                          "Identity Center.",
    "weak_password_policy": "Raise the minimum length to 14 or more, stop reuse of recent "
                            "passwords, and let users change their own passwords.",
}


class _Maker:
    """Builds findings for one identity with the account fields filled in."""

    def __init__(self, ident):
        self.ident = ident
        self.out = []

    def add(self, severity, code, check, detail, command="", resource=None, fix=None,
            why=None):
        i = self.ident
        f = Finding(severity, check, resource or (i.name if i.kind != "root" else "root"),
                    detail, FIX.get(code, "") if fix is None else fix, command,
                    WHY.get(code, "") if why is None else why, i.kind, i.name, code,
                    i.profile, i.account)
        self.out.append(f)
        return f


def _user_ref(u) -> str:
    return f"--user-name {q(u.name)}"


def _key_cmd(u, k, action) -> str:
    if action == "deactivate":
        return (f"aws iam update-access-key {_user_ref(u)} --access-key-id {q(k.ref)} "
                "--status Inactive")
    return f"aws iam delete-access-key {_user_ref(u)} --access-key-id {q(k.ref)}"


def _key_hint(u, keys) -> list:
    missing = [k for k in keys if not k.id]
    if len(missing) == 1 and missing[0].created:
        # Say which one, so the command isn't pointed at the key that's in use.
        made = missing[0].created.astimezone(timezone.utc)
        return [f"# Find the ID of the key created {made:%Y-%m-%d %H:%M} UTC with: "
                f"aws iam list-access-keys {_user_ref(u)}"]
    if missing:
        return [f"# Find the key ID with: aws iam list-access-keys {_user_ref(u)}"]
    return []


def _retire_key(u, k) -> str:
    return "\n".join(_key_hint(u, [k]) + [
        _key_cmd(u, k, "deactivate"),
        "# Wait a while to be sure nothing breaks, then:",
        _key_cmd(u, k, "delete")])


def _remove_source_cmd(ident, src) -> str:
    n = q(ident.name)
    if ident.kind == "role":
        if src["how"] == "attached":
            return f"aws iam detach-role-policy --role-name {n} --policy-arn {q(src['arn'])}"
        return f"aws iam delete-role-policy --role-name {n} --policy-name {q(src['policy'])}"
    if src.get("group"):
        return f"aws iam remove-user-from-group --user-name {n} --group-name {q(src['group'])}"
    if src["how"] == "attached":
        return f"aws iam detach-user-policy --user-name {n} --policy-arn {q(src['arn'])}"
    return f"aws iam delete-user-policy --user-name {n} --policy-name {q(src['policy'])}"


def delete_user_commands(u) -> str:
    n = _user_ref(u)
    lines = ["# Remove what the user has, then delete it. The console's Delete user does "
             "all of this in one go."]
    if u.console:
        lines.append(f"aws iam delete-login-profile {n}")
    lines += _key_hint(u, u.keys)
    lines += [_key_cmd(u, k, "delete") for k in u.keys]
    lines += [f"aws iam delete-ssh-public-key {n} --ssh-public-key-id {q(s['id'])}"
              for s in u.ssh_keys if s.get("id")]
    lines += [f"aws iam delete-service-specific-credential {n} "
              f"--service-specific-credential-id {q(c['id'])}"
              for c in u.service_creds if c.get("id")]
    if any(not c.get("id") for c in u.certs):
        lines.append(f"# Signing certificates: aws iam list-signing-certificates {n}, then "
                     "delete-signing-certificate for each")
    lines += [f"aws iam delete-signing-certificate {n} --certificate-id {q(c['id'])}"
              for c in u.certs if c.get("id")]
    if u.mfa_devices:
        for serial in u.mfa_devices:
            lines.append(f"aws iam deactivate-mfa-device {n} --serial-number {q(serial)}")
            if ":mfa/" in serial:
                lines.append(f"aws iam delete-virtual-mfa-device --serial-number {q(serial)}")
    elif u.mfa:
        lines.append(f"# MFA: aws iam list-mfa-devices {n}, then deactivate-mfa-device for each")
    lines += [f"aws iam remove-user-from-group {n} --group-name {q(g)}" for g in u.groups]
    lines += [f"aws iam detach-user-policy {n} --policy-arn {q(arn)}"
              for _, arn, group in u.attached if not group]
    lines += [f"aws iam delete-user-policy {n} --policy-name {q(p)}"
              for p, group in u.inline if not group]
    lines.append(f"aws iam delete-user {n}")
    return "\n".join(lines)


def delete_role_commands(r) -> str:
    n = q(r.name)
    lines = ["# Detach its policies first, then delete the role:"]
    lines += [f"aws iam remove-role-from-instance-profile --instance-profile-name {q(p)} "
              f"--role-name {n}" for p in r.instance_profiles if p]
    lines += [f"aws iam detach-role-policy --role-name {n} --policy-arn {q(arn)}"
              for _, arn, _ in r.attached]
    lines += [f"aws iam delete-role-policy --role-name {n} --policy-name {q(p)}"
              for p, _ in r.inline]
    lines.append(f"aws iam delete-role --role-name {n}")
    return "\n".join(lines)


def root_findings(r, now, unused) -> list:
    m = _Maker(r)
    active = r.active_keys
    if active:
        bits = []
        for k in active:
            if k.created or k.last_used:
                bits.append(f"one created {when(k.created, now, 'at an unknown time')}, "
                            f"{k.use_text(now)}")
        m.add("critical", "root_keys", "Root user has access keys",
              f"{plural(len(active), 'active access key')}" + (": " + "; ".join(bits) if bits
                                                                 else "") + ".")
    if r.mfa is False:
        m.add("high", "root_mfa", "Root user has no MFA",
              "Anyone with the root password can sign in.")
    uses = []
    if r.password_last_used and days_since(r.password_last_used, now) < unused:
        uses.append(f"signed in to the console on {when(r.password_last_used, now)}")
    for k in r.keys:
        if k.last_used and days_since(k.last_used, now) < unused:
            where = f" in {k.region}" if k.region else ""
            uses.append(f"an access key was used on {when(k.last_used, now)}{where}")
    if uses:
        # The profile, so a check of several accounts points at the right one.
        who = f" -p {q(r.profile)}" if r.profile else ""
        m.add("medium", "root_used", f"Root user used in the last {unused} days",
              "Root " + " and ".join(uses) + ".",
              command=f"awskit trail --user root --all-regions --since {min(unused, 90)}d{who}")
    if any(c.get("status") == "Active" for c in r.certs):
        m.add("low", "root_certs", "Root user has signing certificates",
              "The root user has an active X.509 signing certificate.")
    return m.out


def user_findings(u, now, key_age, unused) -> list:
    m = _Maker(u)
    n = _user_ref(u)
    active = u.active_keys
    untracked = [s for s in u.ssh_keys if s.get("status") == "Active"] + \
        [c for c in u.service_creds if c.get("status") == "Active"]
    last = u.last_activity()

    if u.console and u.mfa is False:
        used = when(u.password_last_used, now, "never")
        m.add("high", "console_no_mfa", "Console user without MFA",
              f"Can sign in to the console with just a password. Last signed in: {used}.",
              command=f"# Only if they don't need the console:\naws iam delete-login-profile {n}")

    # A user with nothing used in the whole window gets one finding that says delete it,
    # instead of one per unused password and key. Users with SSH keys or service-specific
    # credentials are left out, since IAM doesn't record when those are used, and so are
    # users where key use couldn't be read, or a key or password was set in the last week.
    unknown = [k for k in u.keys if not k.use_known]
    fresh = [dt for dt in [u.password_changed if u.console else None] +
             [k.created for k in active] if dt and days_since(dt, now) <= GRACE_DAYS]
    inactive = False
    if u.in_report and not untracked and u.untracked_known and not unknown and not fresh and \
            u.created and days_since(u.created, now) >= unused and \
            (last is None or days_since(last, now) >= unused):
        inactive = True
        parts = [f"Created {when(u.created, now)}."]
        parts.append(f"Last activity {when(last, now)}." if last else
                     "Never signed in or used an access key.")
        if u.console:
            parts.append("Has a console password" + ("" if u.password_last_used else
                                                     " that was never used") + ".")
        if active:
            parts.append(f"{plural(len(active), 'active access key')}.")
        if not u.console and not u.keys:
            parts.append("Has no password or keys, so it can't do anything as it is.")
        m.add("medium", "user_inactive", f"No activity in {unused}+ days", " ".join(parts),
              command=delete_user_commands(u))

    if not inactive:
        if u.console and u.password_last_used is None:
            since = u.password_changed or u.created
            if since and days_since(since, now) > GRACE_DAYS:
                m.add("medium", "password_never_used", "Console password never used",
                      f"Console password set {when(since, now)} and never used.",
                      command=f"aws iam delete-login-profile {n}",
                      fix=FIX["password_unused"])
        elif u.console and days_since(u.password_last_used, now) >= unused:
            m.add("medium", "password_unused", f"Console password not used in {unused}+ days",
                  f"Console password last used {when(u.password_last_used, now)}.",
                  command=f"aws iam delete-login-profile {n}")
        for k in active:
            res = f"{u.name} ({k.masked})"
            age = days_since(k.created, now)
            if not k.use_known:
                # Never claim "never used" when it simply couldn't be read. Age still counts.
                if age is not None and age > key_age:
                    m.add("low", "key_old", f"Access key older than {key_age} days",
                          f"{k.masked} was created {when(k.created, now)}. When it was last "
                          "used couldn't be read, so check that before you deactivate it.",
                          resource=res,
                          command="\n".join(_key_hint(u, [k]) + [
                              f"aws iam get-access-key-last-used --access-key-id {q(k.ref)}",
                              f"aws iam create-access-key {n}",
                              "# Put the new key wherever the old one is used, then:",
                              _key_cmd(u, k, "deactivate"), _key_cmd(u, k, "delete")]))
            elif k.last_used is None:
                if age is None or age > GRACE_DAYS:
                    m.add("medium", "key_never_used", "Access key never used",
                          f"{k.masked} is active, created {when(k.created, now, 'at an unknown time')}"
                          ", and has never been used.", command=_retire_key(u, k), resource=res,
                          fix=FIX["key_unused"])
            elif days_since(k.last_used, now) >= unused:
                m.add("medium", "key_unused", f"Access key unused for {unused}+ days",
                      f"{k.masked} {k.use_text(now)}.", command=_retire_key(u, k), resource=res)
            elif age is not None and age > key_age:
                m.add("low", "key_old", f"Access key older than {key_age} days",
                      f"{k.masked} was created {when(k.created, now)} and is still in use, "
                      f"{k.use_text(now)}.", resource=res,
                      command="\n".join(_key_hint(u, [k]) + [
                          f"aws iam create-access-key {n}",
                          "# Put the new key wherever the old one is used, then:",
                          _key_cmd(u, k, "deactivate"), _key_cmd(u, k, "delete")]))
        if len(active) >= 2 and any(not k.use_known for k in active):
            m.add("low", "two_keys", "Two active access keys",
                  "; ".join(f"{k.masked} created {when(k.created, now, 'at an unknown time')}"
                            for k in active) + ". When they were last used couldn't be read, "
                  "so it isn't known which one to keep.",
                  command="\n".join(
                      ["# See which key is in use, then deactivate the other one:"] +
                      _key_hint(u, active) +
                      [f"aws iam get-access-key-last-used --access-key-id {q(k.ref)}"
                       for k in active]),
                  fix="Keep the key that's in use and deactivate the other one. Two keys only "
                      "make sense for a short time while rotating.")
        elif len(active) >= 2:
            def recency(k):
                return (k.last_used or datetime.min.replace(tzinfo=timezone.utc),
                        k.created or datetime.min.replace(tzinfo=timezone.utc))
            ranked = sorted(active, key=recency)
            keep, drop = ranked[-1], ranked[0]
            m.add("low", "two_keys", "Two active access keys",
                  f"{keep.masked} {keep.use_text(now)}. {drop.masked} {drop.use_text(now)}, "
                  "so that's the one to go.",
                  command=_retire_key(u, drop),
                  fix=f"Keep {keep.masked}, which was used most recently, and deactivate "
                      f"{drop.masked}. Two keys only make sense for a short time while "
                      "rotating.")
        old = u.inactive_keys
        if old:
            m.add("info", "inactive_keys", "Inactive access keys left behind",
                  "; ".join(f"{k.masked} inactive, created {when(k.created, now, 'at an unknown time')}"
                            for k in old) + ".",
                  command="\n".join(_key_hint(u, old) + [_key_cmd(u, k, "delete") for k in old]),
                  fix="Delete " + ("it." if len(old) == 1 else "them."))

    if u.admin == "yes":
        removal = [_remove_source_cmd(u, s) for s in u.admin_sources]
        boundary = " It has a permissions boundary, which may limit this." if u.boundary else ""
        if active:
            m.add("high", "admin_keys", "Admin user with access keys",
                  f"Has admin: {u.admin_why}. "
                  f"{plural(len(active), 'active access key')}: "
                  f"{', '.join(k.masked for k in active)}.{boundary}",
                  command="\n".join(
                      ["# Once you have another way in (Identity Center or a role):"] +
                      _key_hint(u, active) + [_key_cmd(u, k, "deactivate") for k in active] +
                      removal))
        else:
            m.add("medium", "admin_user", "Admin user",
                  f"Has admin: {u.admin_why}. No access keys.{boundary}",
                  command="\n".join(["# Once you have another way in (Identity Center or a "
                                     "role):"] + removal))
    elif u.admin == "can become":
        boundary = " It has a permissions boundary, which may limit this." if u.boundary else ""
        m.add("high", "can_escalate", "User can make itself admin", u.admin_why + "." + boundary,
              command="\n".join(["# Or narrow the policy to exact resources instead:"] +
                                [_remove_source_cmd(u, s) for s in u.admin_sources]))

    own_inline = [p for p, group in u.inline if not group]
    if own_inline:
        m.add("low", "inline_policy", "Inline policies on a user",
              f"{plural(len(own_inline), 'inline policy', 'inline policies')}: "
              f"{', '.join(own_inline)}.",
              command="\n".join(
                  [f"aws iam get-user-policy {n} --policy-name {q(own_inline[0])}",
                   "# After the same permissions are in a managed policy or group:"] +
                  [f"aws iam delete-user-policy {n} --policy-name {q(p)}" for p in own_inline]))

    ssh = [s for s in u.ssh_keys if s.get("status") == "Active"]
    if ssh:
        m.add("low", "ssh_keys", "Active SSH keys",
              "; ".join(f"{mask_key(s['id'])} uploaded {when(s.get('uploaded'), now, 'at an unknown time')}"
                        for s in ssh) + ". Used for CodeCommit over SSH.",
              command="\n".join(f"aws iam delete-ssh-public-key {n} --ssh-public-key-id {q(s['id'])}"
                                for s in ssh))
    creds = [c for c in u.service_creds if c.get("status") == "Active"]
    if creds:
        m.add("low", "service_creds", "Active service-specific credentials",
              "; ".join(f"{SERVICE_CRED_NAMES.get(c.get('service'), c.get('service') or 'unknown service')}"
                        f", created {when(c.get('created'), now, 'at an unknown time')}"
                        for c in creds) + ". IAM doesn't record when these are used.",
              command="\n".join(f"aws iam delete-service-specific-credential {n} "
                                f"--service-specific-credential-id {q(c['id'])}" for c in creds))
    certs = [c for c in u.certs if c.get("status") == "Active"]
    if certs:
        lines = [f"aws iam delete-signing-certificate {n} --certificate-id {q(c['id'])}"
                 for c in certs if c.get("id")]
        if any(not c.get("id") for c in certs):
            lines.insert(0, f"# Find the IDs with: aws iam list-signing-certificates {n}")
        m.add("low", "signing_certs", "Active signing certificates",
              f"{plural(len(certs), 'active X.509 signing certificate')}.",
              command="\n".join(lines))
    return m.out


def role_findings(r, now, unused) -> list:
    if r.aws_managed:
        return []  # AWS creates and removes these itself
    m = _Maker(r)
    powerful = r.admin in ("yes", "can become")
    sev = "medium" if powerful else "low"
    extra = ""
    if r.admin == "yes":
        extra = f" It has admin: {r.admin_why}."
    elif r.admin == "can become":
        extra = f" It can make itself admin: {r.admin_why}."
    if r.role_last_used:
        if days_since(r.role_last_used, now) >= unused:
            where = f" in {r.role_last_region}" if r.role_last_region else ""
            m.add(sev, "role_unused", f"Role not used in {unused}+ days",
                  f"Last used {when(r.role_last_used, now)}{where}.{extra}",
                  command=delete_role_commands(r))
    elif r.created and days_since(r.created, now) >= unused:
        m.add(sev, "role_never_used", "Role never used",
              f"Created {when(r.created, now)} and never used, as far as IAM can tell (it "
              f"tracks the last 400 days).{extra}",
              command=delete_role_commands(r), fix=FIX["role_unused"], why=WHY["role_unused"])
    return m.out


def password_policy_cmd(policy) -> str:
    """update-account-password-policy replaces the whole policy, so the command keeps what's
    already set and only fixes the weak parts."""
    p = policy or {}
    parts = ["aws iam update-account-password-policy",
             f"--minimum-password-length {max(14, int(p.get('MinimumPasswordLength') or 0))}"]
    for key, flag in (("RequireSymbols", "--require-symbols"),
                      ("RequireNumbers", "--require-numbers"),
                      ("RequireUppercaseCharacters", "--require-uppercase-characters"),
                      ("RequireLowercaseCharacters", "--require-lowercase-characters")):
        if p.get(key):
            parts.append(flag)
    parts.append("--allow-users-to-change-password")
    if p.get("MaxPasswordAge"):
        parts.append(f"--max-password-age {int(p['MaxPasswordAge'])}")
    parts.append(f"--password-reuse-prevention {int(p.get('PasswordReusePrevention') or 24)}")
    if p.get("HardExpiry"):
        parts.append("--hard-expiry")
    return " ".join(parts)


def password_policy_findings(data, identities) -> list:
    if not data.password_policy_read:
        return []
    console = [u for u in identities if u.kind == "user" and u.console]
    if not console:
        return []  # nobody signs in with an IAM password, so it doesn't matter yet
    holder = Identity(kind="account", name="password policy", profile=data.profile,
                      account=data.account)
    m = _Maker(holder)
    who = f"{plural(len(console), 'IAM user')} can sign in to the console"
    if data.password_policy is None:
        m.add("low", "no_password_policy", "No IAM password policy",
              f"{who}, and there's no password policy, so IAM's default of 8 characters applies.",
              command=password_policy_cmd({}))
        return m.out
    p = data.password_policy
    weak = []
    length = int(p.get("MinimumPasswordLength") or 0)
    if length < 14:
        weak.append(f"minimum length is {length}, 14 or more is better")
    if not p.get("PasswordReusePrevention"):
        weak.append("old passwords can be used again")
    if not p.get("AllowUsersToChangePassword"):
        weak.append("users can't change their own passwords")
    if weak:
        text = "; ".join(weak)
        m.add("low", "weak_password_policy", "Weak IAM password policy",
              f"{text[0].upper()}{text[1:]}. {who}.", command=password_policy_cmd(p))
    return m.out


def gap_findings(data) -> list:
    """Big gaps show up as info findings too, so the result never looks clean by mistake."""
    holder = Identity(kind="account", name="account", profile=data.profile, account=data.account)
    m = _Maker(holder)
    for what, title in (("report", "Couldn't read the credential report"),
                        ("auth", "Couldn't read users, roles and policies")):
        if what in data.denied or what in data.failed:
            m.add("info", f"{what}_missing", title, note_text(data, what, with_label=False),
                  fix=f"Allow {NOTES[what][0]}, or use a role with the SecurityAudit policy.",
                  why="Without it, part of this account wasn't checked.",
                  resource="account")
    return m.out


def note_text(data, what, with_label=True) -> str:
    action, consequence = NOTES[what]
    who = f"{data.label}: " if with_label else ""
    if what in data.denied:
        return f"{who}no permission for {action}, so {consequence}."
    reason = data.failed.get(what, "")
    if what == "report" and (reason in REPORT_STATES.values() or reason.startswith("There's no")):
        return f"{who}{reason}"
    return f"{who}couldn't read {THINGS[what]} ({reason}), so {consequence}."


def account_notes(data, identities) -> list:
    out = [note_text(data, what) for what in NOTES
           if what in data.denied or what in data.failed]
    if data.generate_denied and data.report is not None:
        made = (f" made {data.report_time.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC"
                if data.report_time else "")
        out.append(f"{data.label}: no permission for iam:GenerateCredentialReport, so this "
                   f"used the last credential report{made}.")
    if data.report_skipped:
        one = data.report_skipped == 1
        out.append(f"{data.label}: {plural(data.report_skipped, 'row')} of the credential "
                   "report didn't line up with its columns, so the passwords and MFA of "
                   f"{'that user' if one else 'those users'} weren't checked.")
    if data.report is not None and data.auth is not None:
        missing = [i.name for i in identities if i.kind == "user" and not i.in_report]
        if missing:
            out.append(f"{data.label}: {plural(len(missing), 'user')} ({', '.join(missing[:5])}"
                       f"{' and more' if len(missing) > 5 else ''}) aren't in the credential "
                       "report yet, since IAM makes a new one at most every 4 hours. Their "
                       "passwords and MFA weren't checked.")
    return out


def finding_order(f) -> tuple:
    rank = CODE_ORDER.index(f.code) if f.code in CODE_ORDER else len(CODE_ORDER)
    return (SEVERITY_ORDER.get(f.severity, 9), rank)


def analyze_account(data, key_age=DEFAULT_KEY_AGE, unused=DEFAULT_UNUSED, now=None) -> tuple:
    """(findings, identities, notes) for one account. Pure logic, no AWS calls."""
    now = now or datetime.now(timezone.utc)
    identities = build_identities(data)
    findings = []
    for i in identities:
        if i.kind == "root":
            found = root_findings(i, now, unused)
        elif i.kind == "user":
            found = user_findings(i, now, key_age, unused)
        else:
            found = role_findings(i, now, unused)
        found.sort(key=finding_order)
        i.findings = found
        findings += found
    findings += password_policy_findings(data, identities)
    findings += gap_findings(data)
    return findings, identities, account_notes(data, identities)


# =================================================================== totals

def account_stats(data, identities, key_age, unused, now) -> dict:
    users = [i for i in identities if i.kind == "user"]
    console = [u for u in users if u.console]
    roles = [i for i in identities if i.kind == "role"]
    keys = [k for u in users for k in u.active_keys]
    root = next((i for i in identities if i.kind == "root"), None)
    return {
        "accounts": 1,
        "users_known": data.auth is not None or data.report is not None,
        "users": len(users), "console": len(console),
        "console_no_mfa": sum(1 for u in console if u.mfa is False),
        "keys": len(keys),
        "keys_old": sum(1 for k in keys if k.created and days_since(k.created, now) > key_age),
        "keys_inactive": sum(len(u.inactive_keys) for u in users),
        "roles_known": data.auth is not None, "roles": len(roles),
        "roles_aws": sum(1 for r in roles if r.aws_managed),
        "roles_unused": sum(1 for r in roles if any(f.code in ("role_unused", "role_never_used")
                                                  for f in r.findings)),
        "root_known": root is not None,
        "root_no_mfa": 1 if root is not None and root.mfa is False else 0,
        "root_keys": 1 if root is not None and root.active_keys else 0,
    }


def add_stats(a, b) -> dict:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, bool):
            out[k] = out.get(k, False) or v
        else:
            out[k] = out.get(k, 0) + v
    return out


def summary_text(stats, key_age=DEFAULT_KEY_AGE, unused=DEFAULT_UNUSED) -> str:
    """12 users, 3 with console access, 1 without MFA. 9 active access keys, 4 older than 90
    days. 21 roles, 6 unused for 90 days or more. Root has MFA and no access keys."""
    if not stats or not stats.get("accounts"):
        return "Nothing checked yet."
    parts = []
    if stats["accounts"] > 1:
        parts.append(f"{stats['accounts']} accounts.")
    if stats.get("users_known"):
        if stats["users"]:
            s = plural(stats["users"], "user")
            if stats["console"]:
                s += f", {stats['console']} with console access"
                if stats["console_no_mfa"]:
                    s += f", {stats['console_no_mfa']} without MFA"
            else:
                s += ", none with console access"
            parts.append(s + ".")
            if stats["keys"]:
                s = plural(stats["keys"], "active access key")
                s += f", {stats['keys_old']} older than {key_age} days" if stats["keys_old"] \
                    else f", none older than {key_age} days"
                parts.append(s + ".")
            else:
                parts.append("No active access keys.")
        else:
            parts.append("No IAM users.")
    if stats.get("roles_known"):
        s = plural(stats["roles"], "role")
        if stats["roles_aws"]:
            s += f" ({stats['roles_aws']} managed by AWS)"
        if stats["roles"] > stats["roles_aws"]:
            s += f", {stats['roles_unused'] or 'none'} unused for {unused} days or more"
        parts.append(s + ".")
    if stats.get("root_known"):
        n = stats["accounts"]
        no_mfa, keys = stats["root_no_mfa"], stats["root_keys"]
        if n == 1:
            if no_mfa and keys:
                parts.append("Root has access keys and no MFA.")
            elif no_mfa:
                parts.append("Root has no MFA.")
            elif keys:
                parts.append("Root has MFA, but also access keys.")
            else:
                parts.append("Root has MFA and no access keys.")
        elif not no_mfa and not keys:
            parts.append("Root has MFA and no access keys in every account.")
        else:
            bits = []
            if no_mfa:
                bits.append(f"no MFA in {no_mfa} of {n} accounts")
            if keys:
                bits.append(f"access keys in {keys}")
            parts.append("Root: " + ", ".join(bits) + ".")
    return " ".join(parts) if parts else "Nothing could be read."


def counts(findings) -> dict:
    out = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def counts_text(findings) -> str:
    c = counts(findings)
    parts = [f"{n} {sev}" for sev, n in c.items() if n]
    return ", ".join(parts) if parts else "No findings."


# =================================================================== running

def analyze(accounts, key_age=DEFAULT_KEY_AGE, unused=DEFAULT_UNUSED, now=None,
            errors=None) -> Result:
    """Judge what was read. Cheap, so the window runs it again when a threshold changes."""
    now = now or datetime.now(timezone.utc)
    findings, identities, warnings = [], [], list(errors or [])
    stats = {}
    for data in accounts:
        f, ids, notes = analyze_account(data, key_age, unused, now)
        findings += f
        identities += ids
        warnings += notes
        stats = add_stats(stats, account_stats(data, ids, key_age, unused, now))
    findings.sort(key=lambda f: finding_order(f) + (f.profile, KIND_ORDER.get(f.kind, 9),
                                                    f.name.lower(), f.check))
    return Result(findings, identities, warnings, stats, list(accounts), key_age, unused,
                  list(errors or []), now)


def check(profiles, key_age=DEFAULT_KEY_AGE, unused=DEFAULT_UNUSED, progress=None,
          cancel=None, now=None, workers=4) -> Result:
    """Read and judge one or more profiles. progress(done, total, text) is called from
    worker threads."""
    profiles = list(profiles) or [None]
    total = len(profiles) * STEPS
    done = [0]
    lock = threading.Lock()
    cache, cache_lock = {}, threading.Lock()

    def stepper(label):
        taken = [0]

        def step(text, advance=1):
            with lock:
                done[0] += advance
                taken[0] += advance
                d = done[0]
            if progress:
                progress(d, total, f"{label}: {text}")

        def finish(text):
            left = STEPS - taken[0]
            if left > 0:
                step(text, left)
        return step, finish

    def run(p):
        label = p or "default"
        step, finish = stepper(label)
        try:
            ctx = AwsContext(p)
            ctx.account  # noqa: B018 - signs in, so a bad profile fails here
        except AuthError as exc:
            finish("couldn't sign in")
            return None, f"{label}: {exc}"
        try:
            data = read_account(ctx, step, cancel, cache, cache_lock)
        except Stopped:
            finish("stopped")
            return None, f"{label}: stopped before it finished."
        except Exception as exc:  # noqa: BLE001
            finish("failed")
            return None, f"{label}: {error_text(exc, p)}"
        finish("done")
        return data, None

    results = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(profiles)))) as pool:
        futures = {pool.submit(run, p): n for n, p in enumerate(profiles)}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    accounts = [results[n][0] for n in range(len(profiles)) if results[n][0] is not None]
    errors = [results[n][1] for n in range(len(profiles)) if results[n][1]]
    return analyze(accounts, key_age, unused, now, errors)


# =================================================================== text

def console_text(i) -> str:
    if i.kind == "role":
        return ""
    if i.console is None:
        return "?"
    if not i.console:
        return "no"
    if i.mfa is None:
        return "yes"
    return "yes, MFA" if i.mfa else "yes, no MFA"


def keys_text(i, now) -> str:
    """1 active, 120 days old, used 3 days ago"""
    if i.kind == "role":
        return ""
    active, inactive = i.active_keys, i.inactive_keys
    if not active and not inactive:
        return "none"
    parts = []
    if active:
        ages = [days_since(k.created, now) for k in active if k.created]
        used = [k.last_used for k in active if k.last_used]
        if len(active) == 1:
            s = "1 active"
            if ages:
                s += f", {ages[0]} days old"
        else:
            s = f"{len(active)} active"
            if ages:
                s += f", oldest {max(ages)} days"
        if used:
            s += (", used " if len(active) == 1 else ", last used ") + ago(max(used), now)
        elif any(not k.use_known for k in active):
            s += ", last use not known"
        else:
            s += ", never used"
        parts.append(s)
    if inactive:
        parts.append(f"{len(inactive)} inactive")
    return ", ".join(parts)


def identity_row(i, now) -> dict:
    """One row of the Identities table."""
    w = i.worst
    password = ""
    password_days = None
    if i.kind in ("root", "user") and (i.console or i.password_last_used):
        if i.kind == "root" and not i.in_report:
            password = "?"
        else:
            password = ago(i.password_last_used, now)
            password_days = days_since(i.password_last_used, now) \
                if i.password_last_used else 10 ** 6
    last = i.last_activity()
    if i.kind == "root" and not i.in_report:
        activity, activity_days = "?", None
    else:
        activity = ago(last, now)
        activity_days = days_since(last, now) if last else 10 ** 6
    admin = i.admin or ("" if i.aws_managed == "service-linked role" else "?")
    if w is not None:
        top = w.check
    elif i.aws_managed:
        top = f"{i.aws_managed[0].upper()}{i.aws_managed[1:]}, managed by AWS"
    else:
        top = ""
    return {"kind": i.kind, "profile": i.profile or "default", "account": i.account,
            "name": i.name, "console": console_text(i), "password": password,
            "_password_days": password_days, "keys": keys_text(i, now),
            "_keys_count": len(i.active_keys), "activity": activity,
            "_activity_days": activity_days, "admin": admin,
            "worst": w.severity if w else "",
            "_rank": SEVERITY_ORDER.get(w.severity, 9) if w else 9,
            "top": top, "findings": len(i.findings), "_dim": bool(i.aws_managed)}


def identity_json(i, now) -> dict:
    def d(dt):
        return dt.isoformat() if dt else None
    return {"kind": i.kind, "name": i.name, "arn": i.arn, "profile": i.profile or "default",
            "account": i.account, "path": i.path, "created": d(i.created),
            "console": i.console, "mfa": i.mfa, "password_last_used": d(i.password_last_used),
            "access_keys": [{"id": k.masked, "status": k.status, "created": d(k.created),
                             "last_used": d(k.last_used), "last_used_known": k.use_known,
                             "service": k.service, "region": k.region} for k in i.keys],
            "ssh_keys": len(i.ssh_keys), "service_specific_credentials": len(i.service_creds),
            "signing_certificates": len(i.certs), "groups": i.groups,
            "policies": [n for n, _, _ in i.attached] + [f"inline {n}" for n, _ in i.inline],
            "role_last_used": d(i.role_last_used), "trusted_by": i.trust,
            "managed_by_aws": i.aws_managed, "admin": i.admin, "admin_why": i.admin_why,
            "last_activity": d(i.last_activity()),
            "worst": i.worst.severity if i.worst else None,
            "findings": [f.code for f in i.findings]}


def finding_text(f, identity=None, now=None) -> str:
    """The details pane text for a finding: what, why it matters, and the fix."""
    now = now or datetime.now(timezone.utc)
    lines = [f"[{f.severity.upper()}] {f.check}"]
    what = {"root": "Root user", "user": "User", "role": "Role"}.get(f.kind, "Account")
    lines.append(f"{what}: {f.resource}")
    lines.append(f"Account: {f.profile or 'default'}" + (f" ({f.account})" if f.account else ""))
    if f.detail:
        lines += ["", f.detail]
    if f.why:
        lines += ["", "Why it matters: " + f.why]
    if f.fix:
        lines += ["", "How to fix: " + f.fix]
    if f.command:
        lines += ["", "Command:"] + ["  " + line for line in f.command.splitlines()]
    if identity is not None and f.kind in ("root", "user", "role"):
        lines += ["", "About this identity: " + identity_line(identity, now)]
    return "\n".join(lines)


def identity_line(i, now) -> str:
    bits = []
    if i.kind != "role":
        c = console_text(i)
        bits.append({"no": "no console access", "?": "console access unknown"}.get(
            c, f"console access ({c.replace('yes, ', '')})" if c != "yes" else "console access"))
        bits.append("keys: " + keys_text(i, now))
    else:
        bits.append("last used " + ago(i.role_last_used, now))
    if i.admin == "yes":
        bits.append("admin" if i.kind == "root" else f"admin ({i.admin_why})")
    elif i.admin == "can become":
        bits.append("can make itself admin")
    if len(i.findings) > 1:
        bits.append(plural(len(i.findings), "finding"))
    return ", ".join(bits) + "."


def identity_text(i, now=None) -> str:
    """Everything known about one identity, for the details pane. Keys are masked."""
    now = now or datetime.now(timezone.utc)
    title = {"root": "Root user", "user": f"User {i.name}", "role": f"Role {i.name}"}[i.kind]
    lines = [title]
    if i.arn:
        lines.append(f"ARN: {i.arn}")
    lines.append(f"Account: {i.profile or 'default'}" + (f" ({i.account})" if i.account else ""))
    if i.created:
        lines.append(f"Created: {when(i.created, now)}")
    if i.path and i.path != "/":
        lines.append(f"Path: {i.path}")
    if i.aws_managed:
        lines.append(f"Managed by AWS: {i.aws_managed}. It's counted here but not flagged as "
                     "unused.")
    lines.append("")
    if i.kind in ("root", "user"):
        if i.kind == "root":
            lines.append("Console: the root user can always sign in with its password." if
                         i.in_report else "Console: the root user can sign in with its password.")
            if i.in_report:
                lines.append(f"Password last used: {when(i.password_last_used, now)}")
        elif i.console is None:
            lines.append("Console: not in the credential report yet, so not known.")
        elif i.console:
            lines.append(f"Console: password set {when(i.password_changed, now, 'at an unknown time')}"
                         f", last used {when(i.password_last_used, now)}")
        else:
            lines.append("Console: no password" + (
                f" (one was last used {when(i.password_last_used, now)})"
                if i.password_last_used else ""))
        if i.mfa is None:
            lines.append("MFA: not known")
        elif i.mfa:
            lines.append("MFA: yes" + (f", {', '.join(i.mfa_devices)}" if i.mfa_devices else ""))
        else:
            lines.append("MFA: no")
        if i.keys:
            lines.append("Access keys:")
            for k in i.keys:
                lines.append(f"  {k.masked:<14} {k.status or '?':<9} created "
                             f"{when(k.created, now, 'at an unknown time')}, {k.use_text(now)}")
        else:
            lines.append("Access keys: none")
        for title2, items, fmt in (
                ("SSH keys", i.ssh_keys,
                 lambda s: f"{mask_key(s['id'])}  {s.get('status', '')}, uploaded "
                           f"{when(s.get('uploaded'), now, 'at an unknown time')}"),
                ("Service-specific credentials", i.service_creds,
                 lambda c: f"{SERVICE_CRED_NAMES.get(c.get('service'), c.get('service', ''))}  "
                           f"{c.get('status', '')}, created "
                           f"{when(c.get('created'), now, 'at an unknown time')}"),
                ("Signing certificates", i.certs,
                 lambda c: f"{mask_key(c['id']) or 'certificate ' + c.get('slot', '')}  "
                           f"{c.get('status', '')}, uploaded "
                           f"{when(c.get('uploaded'), now, 'at an unknown time')}")):
            if items:
                lines.append(f"{title2}:")
                lines += ["  " + fmt(x) for x in items]
    else:
        if i.role_last_used:
            where = f" in {i.role_last_region}" if i.role_last_region else ""
            lines.append(f"Last used: {when(i.role_last_used, now)}{where}")
        else:
            lines.append("Last used: never, as far as IAM can tell. It tracks role use for the "
                         "last 400 days, and not in every region.")
        if i.trust:
            lines.append("Trusted by: " + ", ".join(i.trust))
        if i.instance_profiles:
            lines.append("Instance profiles: " + ", ".join(i.instance_profiles))
    if i.kind != "root":
        if i.kind == "user":
            lines.append("Groups: " + (", ".join(i.groups) if i.groups else "none"))
        policies = [f"  {n}" + (f" (through group {g})" if g else "") for n, _, g in i.attached]
        policies += [f"  inline: {n}" + (f" (through group {g})" if g else "")
                     for n, g in i.inline]
        lines.append("Policies:" if policies else "Policies: none")
        lines += policies
        if i.boundary:
            lines.append(f"Permissions boundary: {i.boundary}")
    admin = {"yes": "yes", "can become": "can make itself admin", "no": "no"}.get(
        i.admin, "not known")
    if i.kind == "role" and i.aws_managed == "service-linked role":
        admin = "not checked, AWS manages this role"
    lines.append(f"Admin: {admin}" + (f". {i.admin_why}" if i.admin_why and i.kind != "root"
                                      else ""))
    lines.append("")
    if i.findings:
        lines.append("Findings:")
        lines += [f"  [{f.severity.upper()}] {f.check}" for f in i.findings]
    else:
        lines.append("No findings.")
    return "\n".join(lines)


FINDING_COLS = [("severity", "Severity"), ("profile", "Profile"), ("kind", "Type"),
                ("resource", "Identity"), ("check", "Finding"), ("detail", "Detail")]
IDENTITY_COLS = [("kind", "Type"), ("profile", "Profile"), ("name", "Name"),
                 ("console", "Console"), ("password", "Password used"), ("keys", "Access keys"),
                 ("activity", "Last activity"), ("admin", "Admin"), ("worst", "Worst"),
                 ("top", "Worst finding")]


def markdown_report(result, profiles=None) -> str:
    """A full report: summary, findings, identities, and every fix command."""
    now = result.now or datetime.now(timezone.utc)

    def cell(v):
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")

    def table(rows, cols):
        out = ["| " + " | ".join(t for _, t in cols) + " |",
               "|" + "|".join("---" for _ in cols) + "|"]
        out += ["| " + " | ".join(cell(r.get(k, "")) for k, _ in cols) + " |" for r in rows]
        return out

    lines = ["# Credentials", "", result.summary(), ""]
    if profiles:
        lines += ["Profiles: " + ", ".join(p or "default" for p in profiles), ""]
    lines += [
             f"Findings: {counts_text(result.findings)} Keys older than {result.key_age} days "
             f"and anything unused for {result.unused} days are flagged. "
             f"Checked {now.astimezone():%Y-%m-%d %H:%M}.", ""]
    lines += ["## Findings", ""]
    if result.findings:
        lines += table([f.row() for f in result.findings], FINDING_COLS + [("fix", "Fix")])
    else:
        lines.append("No findings.")
    lines += ["", "## Identities", ""]
    if result.identities:
        lines += table([identity_row(i, now) for i in result.identities], IDENTITY_COLS)
    else:
        lines.append("None could be read.")
    with_cmd = [f for f in result.findings if f.command]
    if with_cmd:
        lines += ["", "## Commands", "",
                  "Nothing here has been run. Read each one before you run it.", ""]
        for f in with_cmd:
            lines += [f"### {f.severity.capitalize()}: {f.check}, {f.resource} "
                      f"({f.profile or 'default'})", "", "```bash", f.command, "```", ""]
    if result.warnings:
        lines += ["", "## Notes", "", "What couldn't be checked:", ""]
        lines += [f"- {w}" for w in result.warnings]
    return "\n".join(lines).rstrip() + "\n"


# =================================================================== command line

DESCRIPTION = """\
Checks every IAM user, access key and role, and the root user, in each account:
how old the credentials are, when they were last used, who has admin, and what
should be cleaned up. Read-only. Each fix is an AWS CLI command for you to run."""
EPILOG = """examples:
  awskit creds                          findings for the current profile
  awskit creds -v                       also print the fix and command for each one
  awskit creds --identities             every user, role and root, one row each
  awskit creds --all-profiles --key-age 180 --unused 60
  awskit creds --markdown creds.md      full report with every command
  awskit creds --json
  awskit creds --fail-on high           exit code 2 if anything high or critical is found
"""


def days_arg(text):
    import argparse
    try:
        value = int(str(text).strip().rstrip("dD"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text} isn't a number of days.") from None
    if not 1 <= value <= MAX_DAYS:
        raise argparse.ArgumentTypeError(f"Use a number of days from 1 to {MAX_DAYS}.")
    return value


def register_cli(sub, add_profiles):
    import argparse
    p = sub.add_parser("creds", help="Check IAM users, access keys, roles and the root user "
                       "for old, unused and risky credentials",
                       description=DESCRIPTION, epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    add_profiles(p)
    p.add_argument("--identities", action="store_true",
                   help="Print every identity (root, users, roles) instead of the findings")
    p.add_argument("--key-age", type=days_arg, default=DEFAULT_KEY_AGE, metavar="DAYS",
                   help=f"Flag active keys older than this (default {DEFAULT_KEY_AGE})")
    p.add_argument("--unused", type=days_arg, default=DEFAULT_UNUSED, metavar="DAYS",
                   help="Flag passwords, keys, users and roles not used for this long "
                        f"(default {DEFAULT_UNUSED})")
    p.add_argument("--json", action="store_true", help="Print JSON")
    p.add_argument("--markdown", metavar="FILE",
                   help="Write a Markdown report with every fix command to FILE")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show the fix and the command for each finding")
    p.add_argument("-q", "--quiet", action="store_true", help="No progress line")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), metavar="SEVERITY",
                   help="Exit with code 2 if anything this bad or worse is found")
    p.set_defaults(func=cmd_creds)


def cmd_creds(args) -> int:
    from .cli import err, fail_exit, progress_printer, resolve_profiles, sev_colorizer
    profiles = resolve_profiles(args)
    show = progress_printer(sys.stderr.isatty() and not args.json and not args.quiet)
    result = check(profiles, args.key_age, args.unused, progress=show)
    several = len(profiles) > 1

    if args.json:
        print(json.dumps(result.as_json(), indent=2, default=str))
    elif args.markdown:
        try:
            write_atomic(Path(args.markdown), markdown_report(result, profiles))
        except OSError as exc:
            err(f"Couldn't write {args.markdown}: {exc}")
            return 1
        print(f"Wrote {args.markdown}")
        print(color(result.summary(), "bold"))
        for w in result.warnings:
            print(color("Note: " + w, "yellow"), file=sys.stderr)
    else:
        now = result.now
        if args.identities:
            cols = [c for c in IDENTITY_COLS if several or c[0] != "profile"]
            rows = [identity_row(i, now) for i in result.identities]
            if rows:
                print(table_text(rows, cols, max_width=44,
                                 colorize=lambda k, v: sev_colorizer("severity", v)
                                 if k == "worst" else None))
                print()
        else:
            cols = [c for c in FINDING_COLS if several or c[0] != "profile"]
            rows = [f.row() for f in result.findings]
            if rows:
                print(table_text(rows, cols, max_width=60, colorize=sev_colorizer))
                print()
        print(color(result.summary(), "bold"))
        print(color(counts_text(result.findings), "bold"))
        if args.verbose:
            for f in result.findings:
                print()
                print(color(f"[{f.severity.upper()}] {f.check}: {f.resource}"
                            + (f" ({f.profile or 'default'})" if several else ""),
                            "bold"))
                if f.fix:
                    print(f"  Fix: {f.fix}")
                if f.command:
                    for line in f.command.splitlines():
                        print("    " + (color(line, "dim") if line.startswith("#") else line))
        elif result.findings:
            print(color("Add -v to see the fix and the command for each one.", "dim"))
        for w in result.warnings:
            print(color("Note: " + w, "yellow"), file=sys.stderr)
    if not result.accounts:
        return 1
    code = fail_exit(result.findings, args.fail_on)
    if code == 0 and args.fail_on and result.errors:
        return 1  # a profile that couldn't be read at all mustn't pass the check
    return code
