"""PII Redact: strips account IDs, keys, ARNs, resource IDs, emails, public IPs and other
identifying info out of Terraform, AWS CLI, boto3 and general command output, so it can be
shared for troubleshooting.

This file has the redaction rules, the settings and the command line. The window is in
redact_page.py. Run `pii-redact --help` (same as `awskit redact --help`) for every option.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import math
import os
import re
import socket
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .common import (CONFIG_DIR, VERSION, ClipboardError, notify, read_clipboard,
                     write_clipboard)

CONFIG_FILE = CONFIG_DIR / "redact.json"
_CONFIG_HOME = CONFIG_DIR.parent

# Settings from when PII Redact was its own app, and from the even older pii-redactor
# name. Only used to carry settings over and to clean up old installs.
STANDALONE_CONFIG_FILE = _CONFIG_HOME / "pii-redact" / "config.json"
LEGACY_CONFIG_DIR = _CONFIG_HOME / "pii-redactor"
LEGACY_CONFIG_FILE = LEGACY_CONFIG_DIR / "config.json"
LEGACY_WORDS_FILE = LEGACY_CONFIG_DIR / "extra_words.txt"
LEGACY_BIN = Path.home() / ".local" / "bin" / "pii-redactor"
OLD_DESKTOP_FILES = ("local.PiiRedactor.desktop",
                     "io.github.Snowblind019.PiiRedactor.desktop",
                     "io.github.Snowblind019.PiiRedactor.Settings.desktop",
                     "io.github.Snowblind019.PiiRedact.desktop",
                     "io.github.Snowblind019.PiiRedact.Settings.desktop")


# =================================================================== categories

@dataclass
class Category:
    id: str
    section: str
    title: str
    desc: str
    default: bool = True


CATEGORIES = [
    Category("account_ids", "AWS", "Account IDs",
             "12-digit account numbers, including the ones inside ARNs and ECR URLs"),
    Category("aws_keys", "AWS", "Access keys and secret keys",
             "AKIA and ASIA access keys, secret access keys and session tokens"),
    Category("iam_ids", "AWS", "IAM unique IDs",
             "AIDA, AROA and similar IDs from get-caller-identity and IAM output"),
    Category("iam_names", "AWS", "IAM user and session names",
             "The user name in IAM user ARNs and the session name in assumed-role ARNs"),
    Category("sso_hash", "AWS", "Identity Center role suffix",
             "The random ending on AWSReservedSSO_ role names"),
    Category("org_ids", "AWS", "Organization IDs",
             "o-, ou- and r- IDs from AWS Organizations, plus Identity Center directory IDs"),
    Category("resource_ids", "AWS", "Resource IDs",
             "i-, vpc-, subnet-, sg-, ami-, vol-, tgw- and other EC2 and VPC IDs"),
    Category("uuids", "AWS", "UUIDs",
             "KMS key IDs, request IDs and anything else in UUID format"),
    Category("aws_hostnames", "AWS", "AWS endpoint hostnames and IDs",
             "The unique part of API Gateway, Lambda URL, CloudFront, RDS, ELB and access "
             "portal hostnames, plus Route 53 zone and CloudFront distribution IDs"),
    Category("buckets", "AWS", "S3 bucket names",
             "Bucket names in s3:// URLs, S3 ARNs, S3 hostnames and bucket settings"),
    Category("canonical_ids", "AWS", "S3 canonical user IDs",
             "The 64-character owner IDs in S3 output"),

    Category("private_keys", "Keys and tokens", "Private keys",
             "PEM and OpenSSH private key blocks"),
    Category("ssh_keys", "Keys and tokens", "SSH public keys",
             "The key and comment after ssh-ed25519, ssh-rsa and similar"),
    Category("tokens", "Keys and tokens", "API tokens",
             "GitHub, GitLab, Slack, Terraform Cloud, OpenAI, Anthropic, Google and Stripe "
             "tokens, JWTs, and long random strings"),
    Category("url_creds", "Keys and tokens", "Passwords in URLs",
             "The user:password part of URLs like https://user:pass@host"),
    Category("secret_values", "Keys and tokens", "Secret settings",
             "Values of password, secret, token, api_key and similar settings"),

    Category("emails", "Personal info", "Email addresses", ""),
    Category("phones", "Personal info", "Phone numbers", "US formats and +country numbers"),
    Category("names", "Personal info", "Names in owner and user fields",
             "Values of owner, user, username, display_name, first_name, organization "
             "and similar settings"),
    Category("home_paths", "Personal info", "Usernames in file paths",
             "The name in /home/name, /Users/name and C:\\Users\\name"),
    Category("gov_ids", "Personal info", "SSNs and birth dates", ""),
    Category("cards", "Personal info", "Card numbers",
             "Checked with the Luhn formula to avoid false hits"),
    Category("custom_words", "Personal info", "Your always-redact list",
             "The words you add further down"),

    Category("public_ips", "Network", "Public IP addresses", "IPv4 and IPv6"),
    Category("private_ips", "Network", "Private IP addresses",
             "10.x, 172.16-31.x, 192.168.x, fe80:: and fd00:: addresses and CIDR blocks. "
             "Off by default so VPC layouts still make sense", default=False),
    Category("macs", "Network", "MAC addresses", "Colon, dash and Cisco dotted formats"),
]
CATEGORY_IDS = [c.id for c in CATEGORIES]


# =================================================================== checks

def entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mixed_charset(s: str) -> bool:
    return (any(c.isupper() for c in s) and any(c.islower() for c in s)
            and any(c.isdigit() for c in s))


def secret_40_check(s):
    return mixed_charset(s) and entropy(s) >= 4.2  # AWS secret keys, not file paths


def long_token_check(s):
    return mixed_charset(s) and entropy(s) >= 4.8  # session tokens and similar blobs


def ipv4_check(s):
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return None
    if s.startswith(("0.", "255.")) or ip.is_loopback:
        return None  # 0.0.0.0, masks, wildcards, 127.x
    return "public_ips" if ip.is_global else "private_ips"


def ipv6_check(s):
    if s.count(":") < 2:
        return None
    try:
        ip = ipaddress.IPv6Address(s)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback:
        return None
    return "public_ips" if ip.is_global else "private_ips"


def luhn_check(s):
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def email_check(s):
    local, _, domain = s.partition("@")
    return local.lower() != "git" and not domain.lower().endswith("openssh.com")


# =================================================================== rules

@dataclass
class Rule:
    cat: Optional[str]        # None means the check decides the category
    label: str                # used for numbered placeholders
    regex: re.Pattern
    group: object = 0
    check: Optional[Callable] = None


def R(cat, label, pattern, group=0, check=None, flags=0):
    return Rule(cat, label, re.compile(pattern, flags), group, check)


B = r"(?<![\w-])"  # word start, counting - as part of the word
E = r"(?![\w-])"   # word end, same idea
REGION = r"[a-z]{2}(?:-gov)?-[a-z]+-\d"
EC2_PREFIXES = (
    "i|vpc|subnet|sg|sgr|igw|eigw|nat|rtb|rtbassoc|acl|aclassoc|eni|eni-attach|vol|snap|ami|"
    "eipalloc|eipassoc|vpce|vpce-svc|pcx|tgw|tgw-attach|tgw-rtb|lt|dopt|cgw|vgw|vpn|fs|fsap|"
    "fsmt|ipam|ipam-pool|ipam-scope|pl|sir|fleet|cr|key|fl|lgw|ssoins|ins|ps|cvpn-endpoint|"
    "vpc-flow-log"
)

# When two rules match the exact same text, the one higher up names it.
RULES = [
    R("private_keys", "PrivateKey",
      r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
      r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", flags=re.S),
    R("ssh_keys", "SSHKey",
      r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d{3}|sk-ssh-ed25519@openssh\.com)"
      r"[ \t]+(AAAA[A-Za-z0-9+/=]{20,}(?:[ \t]+[^\s\"',]+)?)", group=1),
    R("tokens", "JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    R("tokens", "Token",
      r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}"
      r"|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}"
      r"|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
      r"|AIza[0-9A-Za-z_-]{35}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})"),
    R("tokens", "Token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}"),

    R("aws_keys", "AccessKey", r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    R("iam_ids", "IAMUniqueID",
      r"(?<![A-Z0-9])(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16,}"
      r"(?![A-Z0-9])"),
    R("aws_keys", "SessionToken",
      r"(?<![A-Za-z0-9/+=])(?:IQoJb3JpZ2lu|FwoGZXIvYXdz|FQoGZXIvYXdz)[A-Za-z0-9/+=]{40,}"),
    R("tokens", "Token", r"(?<![A-Za-z0-9/+=_-])[A-Za-z0-9/+=_-]{100,}(?![A-Za-z0-9/+=_-])",
      check=long_token_check),
    R("aws_keys", "SecretKey", r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])",
      check=secret_40_check),
    R("url_creds", "Credentials", r"(?<=://)[^/\s:@\"']+:[^/\s@\"']+(?=@)"),

    R("iam_names", "IAMUser", r"\barn:aws[\w-]*:iam::[^:\s]*:user/([\w+=,.@/-]+)", group=1),
    R("iam_names", "SessionName", r":assumed-role/[\w+=,.@-]+/([\w+=,.@-]+)", group=1),
    R("iam_names", "SessionName", r"\bAROA[A-Z0-9]{16,}:([\w+=,.@-]+)", group=1),
    R("sso_hash", "SSOHash", r"\bAWSReservedSSO_[\w+=,.@-]+?_([0-9a-f]{16})(?![0-9a-f])", group=1),

    R("account_ids", "AccountID", r"(?<![\w.])\d{12}(?!\w|\.\d)"),
    R("account_ids", "AccountID", r"(?<![\w.-])\d{4}-\d{4}-\d{4}(?![\w-])"),
    R("org_ids", "OrgID", B + r"o-(?=[a-z0-9]*\d)[a-z0-9]{10,32}" + E),
    R("org_ids", "OrgUnitID", B + r"ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}" + E),
    R("org_ids", "OrgRootID", B + r"r-(?=[a-z0-9]*\d)[a-z0-9]{4,32}" + E),
    R("org_ids", "DirectoryID", B + r"d-(?=[0-9a-f]*\d)[0-9a-f]{10}" + E),
    R("resource_ids", "ResourceID",
      B + rf"(?:{EC2_PREFIXES})-(?=[0-9a-f]*\d)[0-9a-f]{{8,17}}" + E),
    R("resource_ids", "ResourceID", B + r"(?:db|cluster|prx)-[A-Z0-9]{20,30}" + E),
    R("uuids", "ID", B + r"(?:[0-9a-f]{10}-)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                         r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" + E),
    R("canonical_ids", "CanonicalID", r"(?<![\w:])[0-9a-f]{64}(?!\w)"),
    R("aws_hostnames", "HostedZoneID", r"(?<!\w)Z(?=[A-Z0-9]*\d)[A-Z0-9]{9,31}(?!\w)"),
    R("aws_hostnames", "CloudFrontID", r"(?<!\w)E(?=[A-Z0-9]*\d)[A-Z0-9]{12,13}(?!\w)"),

    R("aws_hostnames", "Hostname", r"\b([a-z0-9]{10})\.execute-api\.", group=1),
    R("aws_hostnames", "Hostname", r"\b([a-z0-9]{20,40})\.lambda-url\.", group=1),
    R("aws_hostnames", "Hostname", r"\b([a-z0-9]+)\.cloudfront\.net\b", group=1),
    R("aws_hostnames", "Hostname", r"\b([a-z0-9][a-z0-9-]*)\.awsapps\.com\b", group=1),
    R("aws_hostnames", "Hostname", rf"\.([a-z0-9]{{12}})\.{REGION}\.rds\.amazonaws\.com", group=1),
    R("aws_hostnames", "Hostname",
      rf"\b((?:internal-)?[\w-]+-\d+)\.{REGION}\.elb\.amazonaws\.com", group=1),
    R("buckets", "Bucket", r"(?<=s3://)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
    R("buckets", "Bucket", r"(?<=arn:aws:s3:::)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
    R("buckets", "Bucket",
      r"\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", group=1),

    R("emails", "Email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", check=email_check),
    R(None, "IPv6", r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])",
      check=ipv6_check),
    R(None, "IPv4", r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)", check=ipv4_check),
    R("macs", "MAC",
      r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])"),
    R("macs", "MAC", r"(?<![\w.])[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}(?![\w.])"),
    R("phones", "Phone",
      r"(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?![\w-])"),
    R("phones", "Phone", r"(?<![\w+])\+\d{10,15}(?!\w)"),
    R("gov_ids", "SSN", r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"),
    R("cards", "CardNumber",
      r"(?<![\w-])(?:[3-6]\d{3}(?:[ -]?\d{4}){3}|3[47]\d{2}[ -]?\d{6}[ -]?\d{5})(?![\w-])",
      check=luhn_check),
    R("home_paths", "Username", r"(?<=/home/)[^/\s\"':]+"),
    R("home_paths", "Username", r"(?<=/Users/)[^/\s\"':]+"),
    R("home_paths", "Username", r"(?<=[A-Za-z]:\\Users\\)[^\\\s\"':]+"),
]

# Settings whose values get redacted in HCL, JSON, YAML, .env, INI and boto3 output.
# Names are compared lowercased with _ and - removed, so AccountId, account_id and
# ACCOUNT-ID all match "accountid".
_KEY_GROUPS = {
    ("secret_values", "Secret"):
        "password passwd pwd pass passphrase secret secrets secretkey secretaccesskey "
        "awssecretaccesskey clientsecret accesskey accesskeyid awsaccesskeyid sessiontoken "
        "awssessiontoken securitytoken token accesstoken refreshtoken authtoken idtoken "
        "bearertoken apikey apitoken privatekey masterpassword adminpassword dbpassword "
        "rootpassword",
    ("account_ids", "AccountID"): "accountid account awsaccountid ownerid requesterid",
    ("names", "Owner"): "owner",
    ("names", "User"): "username user userid masterusername displayname principalid",
    ("names", "Org"): "organization organizationid orgid org",
    ("names", "Name"): "firstname lastname fullname givenname familyname",
    ("emails", "Email"): "email emailaddress mail",
    ("phones", "Phone"): "phone phonenumber mobile",
    ("buckets", "Bucket"): "bucket bucketname",
    ("canonical_ids", "CanonicalID"): "canonicaluserid",
    ("gov_ids", "SSN"): "ssn",
    ("gov_ids", "DOB"): "dob dateofbirth",
}
SENSITIVE_KEYS = {k: cat_label for cat_label, keys in _KEY_GROUPS.items() for k in keys.split()}

KV_RE = re.compile(
    r"""(?P<kq>["']?)(?P<key>[A-Za-z_][\w.-]*)(?P=kq)[ \t]*[=:][ \t]*"""
    r"""(?:(?P<q>["'])(?P<qval>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)"""
    r"""|(?P<val>[^\s,;{}\[\]()#"'][^\s,;{}\[\]()#"']*))"""
    r"""(?:[ \t]*->[ \t]*(?P<q2>["'])(?P<qval2>(?:\\.|(?!(?P=q2))[^\\\n])*)(?P=q2))?"""
)
# Terraform references like var.x or aws_s3_bucket.logs.id are names, not data
TF_REF = re.compile(r"^(?:var|local|data|module|each|count|self|path|terraform)\.[\w.\[\]\"*-]+$"
                    r"|^[a-z][a-z0-9_]*\.[a-z0-9_-]+\.[\w.\[\]\"*-]+$")
SKIP_VALUES = {"", "null", "none", "nil", "true", "false", "*", "undefined"}

# Terminal color codes would hide values from the patterns, so they get stripped first
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _kv_value_ok(value, quoted, placeholder):
    v = value.strip()
    if v.lower() in SKIP_VALUES or "${" in v or v.startswith("(") or f"[{placeholder}" in v:
        return False
    if v.startswith("arn:"):
        return False  # the ARN rules already strip the account, user and session parts
    if not quoted and TF_REF.match(v):
        return False
    return True


def kv_spans(text, prio, placeholder):
    spans = []
    for m in KV_RE.finditer(text):
        norm = m.group("key").split(".")[-1].lower().replace("_", "").replace("-", "")
        hit = SENSITIVE_KEYS.get(norm)
        if not hit:
            continue
        cat, label = hit
        if m.group("val") is not None:
            end = m.end("val")
            if end < len(text) and text[end] == "(":
                continue  # function call like jsonencode(...)
            if _kv_value_ok(m.group("val"), False, placeholder):
                spans.append((m.start("val"), end, prio, cat, label))
        elif m.group("qval") is not None and _kv_value_ok(m.group("qval"), True, placeholder):
            spans.append((m.start("qval"), m.end("qval"), prio, cat, label))
        if m.group("qval2") is not None and _kv_value_ok(m.group("qval2"), True, placeholder):
            spans.append((m.start("qval2"), m.end("qval2"), prio, cat, label))
    return spans


def word_regex(words):
    words = sorted({w.strip() for w in words if len(w.strip()) >= 2}, key=len, reverse=True)
    if not words:
        return None
    alt = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alt})(?![A-Za-z0-9])", re.I)


# =================================================================== core

@dataclass
class Options:
    enabled: set = field(default_factory=lambda: {c.id for c in CATEGORIES if c.default})
    numbered: bool = False
    placeholder: str = "Redacted"
    always: list = field(default_factory=list)
    never: list = field(default_factory=list)


def redact(text: str, opts: Options):
    """Return (redacted_text, Counter of labels, list of (start, end) placeholder offsets)."""
    text = ANSI_RE.sub("", text)
    rules = list(RULES)
    custom = word_regex(opts.always)
    if custom:
        rules.append(Rule("custom_words", "Custom", custom))

    spans = []
    for prio, rule in enumerate(rules):
        if rule.cat is not None and rule.cat not in opts.enabled:
            continue
        for m in rule.regex.finditer(text):
            s, e = m.span(rule.group)
            if s < 0 or s == e:
                continue
            cat = rule.cat
            if rule.check:
                result = rule.check(text[s:e])
                if not result:
                    continue
                if isinstance(result, str):
                    cat = result
            if cat in opts.enabled:
                spans.append((s, e, prio, cat, rule.label))
    spans.extend(sp for sp in kv_spans(text, len(rules), opts.placeholder) if sp[3] in opts.enabled)

    # Anything inside a never-redact match stays visible
    never = word_regex(opts.never)
    if never:
        protected = [m.span() for m in never.finditer(text)]
        spans = [sp for sp in spans
                 if not any(ps <= sp[0] and sp[1] <= pe for ps, pe in protected)]

    # Earliest start wins, then the longest match, then rule order
    spans.sort(key=lambda t: (t[0], -(t[1] - t[0]), t[2]))
    chosen, last_end = [], 0
    for s, e, _, _, label in spans:
        if s >= last_end:
            chosen.append((s, e, label))
            last_end = e

    out, ranges, counts = [], [], Counter()
    numbers, per_label = {}, Counter()
    pos = out_len = 0
    for s, e, label in chosen:
        out.append(text[pos:s])
        out_len += s - pos
        if opts.numbered:
            key = (label, text[s:e].lower())
            if key not in numbers:
                per_label[label] += 1
                numbers[key] = per_label[label]
            placeholder = f"[{opts.placeholder}-{label}-{numbers[key]}]"
        else:
            placeholder = f"[{opts.placeholder}]"
        out.append(placeholder)
        ranges.append((out_len, out_len + len(placeholder)))
        out_len += len(placeholder)
        counts[label] += 1
        pos = e
    out.append(text[pos:])
    return "".join(out), counts, ranges


def summarize(counts: Counter) -> str:
    total = sum(counts.values())
    if not total:
        return "Nothing found to redact"
    return f"Redacted {total}: " + ", ".join(f"{n} {label}" for label, n in counts.most_common())


# =================================================================== config

GENERIC_NAMES = {"root", "user", "admin", "fedora", "liveuser", "localhost", "localhost-live",
                 "ubuntu", "ec2-user", "toolbox"}


def default_words():
    words = []
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    host = socket.gethostname().split(".")[0]
    for w in (user, host):
        if len(w) >= 3 and w.lower() not in GENERIC_NAMES and w not in words:
            words.append(w)
    return words


def default_config():
    return {
        "categories": {c.id: c.default for c in CATEGORIES},
        "numbered": False,
        "placeholder": "Redacted",
        "copy_on_paste": False,
        "copy_in_terminal": False,
        "always_redact": [],
        "never_redact": [],
    }


def clean_placeholder(value):
    value = str(value).replace("\n", " ").strip().strip("[]").strip()
    return value or "Redacted"


def load_config():
    cfg = default_config()
    try:
        source = CONFIG_FILE
        if not CONFIG_FILE.exists():
            if STANDALONE_CONFIG_FILE.exists():
                source = STANDALONE_CONFIG_FILE  # from when PII Redact was its own app
            elif LEGACY_CONFIG_FILE.exists():
                source = LEGACY_CONFIG_FILE  # from the old pii-redactor name
        data = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # First run: pick up words from the older text file, or start with username and hostname
        try:
            cfg["always_redact"] = [w.strip() for w in
                                    LEGACY_WORDS_FILE.read_text(encoding="utf-8").splitlines()
                                    if w.strip()]
        except OSError:
            cfg["always_redact"] = default_words()
        return cfg
    except (OSError, ValueError):
        return cfg
    if not isinstance(data, dict):
        return cfg
    for cid, value in (data.get("categories") or {}).items():
        if cid in cfg["categories"] and isinstance(value, bool):
            cfg["categories"][cid] = value
    for key in ("numbered", "copy_on_paste", "copy_in_terminal"):
        if isinstance(data.get(key), bool):
            cfg[key] = data[key]
    if isinstance(data.get("placeholder"), str):
        cfg["placeholder"] = clean_placeholder(data["placeholder"])
    for key in ("always_redact", "never_redact"):
        if isinstance(data.get(key), list):
            cfg[key] = [str(w).strip() for w in data[key] if str(w).strip()]
    return cfg


def save_config(cfg) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, CONFIG_FILE)
        return True
    except OSError:
        return False


def split_cats(values):
    cats = []
    for v in values:
        cats.extend(c.strip() for c in v.split(",") if c.strip())
    unknown = [c for c in cats if c not in CATEGORY_IDS]
    if unknown:
        sys.exit(f"pii-redact: unknown category: {', '.join(unknown)}\n"
                 f"Run 'pii-redact categories' to see the names.")
    return set(cats)


def options_from(cfg, args=None) -> Options:
    opts = Options(
        enabled={cid for cid, on in cfg["categories"].items() if on},
        numbered=cfg["numbered"],
        placeholder=cfg["placeholder"],
        always=list(cfg["always_redact"]),
        never=list(cfg["never_redact"]),
    )
    if args is not None:
        if args.only:
            opts.enabled = split_cats([args.only])
        if args.skip:
            opts.enabled -= split_cats(args.skip)
        if args.private_ips:
            opts.enabled.add("private_ips")
        if args.numbered:
            opts.numbered = True
        opts.always += args.word
        opts.never += args.keep
    return opts


# =================================================================== clipboard


# =================================================================== commands

def tell(message, title="PII Redact"):
    """Print to the terminal, and pop a desktop notification when run from a keybind."""
    print(message, file=sys.stderr)
    if not sys.stderr.isatty():
        notify(title, message, icon="dialog-password")


def run_gui(initial_text=None, mode="main"):
    from .app import main as gui_main
    return gui_main("redact-settings" if mode == "settings" else "redact-window",
                    initial_text=initial_text)


def stdin_has_data():
    try:
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode)


def read_files(paths):
    if not paths or paths == ["-"]:
        return sys.stdin.read()
    parts = []
    for p in paths:
        try:
            parts.append(sys.stdin.read() if p == "-" else
                         Path(p).read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            sys.exit(f"pii-redact: {exc}")
    return "".join(parts)


def emit(text, cfg, args):
    """Redact text and send it where the options say: stdout, clipboard or the window."""
    if args.gui:
        return run_gui(initial_text=text)
    out, counts, _ = redact(text, options_from(cfg, args))
    if not args.quiet:
        sys.stdout.write(out)
        sys.stdout.flush()
    note = ""
    if args.copy or cfg["copy_in_terminal"]:
        try:
            write_clipboard(out)
            note = ". Copied to clipboard"
        except ClipboardError as exc:
            note = f". {exc}"
    print(summarize(counts) + note, file=sys.stderr)
    return 0


def cmd_clip(cfg, args):
    try:
        text = read_clipboard()
    except ClipboardError as exc:
        tell(f"{exc} Opening the paste window instead.")
        return run_gui()
    if not text.strip():
        tell("The clipboard is empty or doesn't hold text.")
        return 1
    if args.gui:
        return run_gui(initial_text=text)
    out, counts, _ = redact(text, options_from(cfg, args))
    try:
        write_clipboard(out)
    except ClipboardError as exc:
        tell(str(exc))
        return 1
    tell(summarize(counts) + ". Ready to paste.", title="Clipboard redacted")
    return 0


def cmd_run(command, cfg, args):
    if not command:
        sys.exit("pii-redact: run needs a command, like: pii-redact run terraform plan")
    if sys.stderr.isatty():
        print(f"Running {' '.join(command)} (output shows when it finishes)", file=sys.stderr)
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        print(f"pii-redact: command not found: {command[0]}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130
    emit(proc.stdout.decode("utf-8", errors="replace"), cfg, args)
    return proc.returncode


def cmd_categories():
    cfg = load_config()
    width = max(len(c.id) for c in CATEGORIES)
    section = None
    for c in CATEGORIES:
        if c.section != section:
            section = c.section
            print(f"\n{section}")
        state = "on " if cfg["categories"][c.id] else "off"
        print(f"  {c.id:<{width}}  {state}  {c.title}")
    print("\nChange the defaults with: pii-redact settings\n"
          "Change them for one run with: --skip NAME or --only NAME,NAME")
    return 0


def remove_old_install(apps_dir: Path) -> list:
    """Remove launcher entries and commands left from the standalone PII Redact.

    The pii-redact command itself is replaced by AWS Kit's own, so it isn't removed here.
    """
    removed = []
    for path in [LEGACY_BIN] + [apps_dir / n for n in OLD_DESKTOP_FILES]:
        if path.exists():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass
    return removed


# =================================================================== argument parsing

COMMANDS = ("gui", "clip", "run", "settings", "categories", "install", "uninstall")
VALUE_FLAGS = {"-w", "--word", "-k", "--keep", "--skip", "--only"}

DESCRIPTION = """\
Strip account IDs, keys, ARNs, resource IDs, emails, public IPs and other
identifying info out of Terraform, AWS CLI, boto3 and other output.
pii-redact and awskit redact are the same command.

commands:
  (none)                 open the paste window, or redact piped input and print it
  FILE...                redact files and print the result
  clip                   redact whatever is on the clipboard and put it back
  run COMMAND...         run a command and redact everything it prints
  gui [FILE]             open the paste window, optionally filled in with FILE
  settings               open the settings window with all the checkboxes
  categories             list the category names used by --skip and --only
"""

EPILOG = """\
examples:
  terraform plan 2>&1 | pii-redact -c         redact, print and copy
  pii-redact run -c terraform plan            same thing, shorter
  pii-redact run -g aws sts get-caller-identity
  python3 list_buckets.py | pii-redact -g     review it in the window first
  pii-redact clip                             fix up what you already copied
  pii-redact -n --skip buckets plan.log       numbered, keep bucket names

options for run go between "run" and the command.
"""


def build_parser(prog="pii-redact"):
    p = argparse.ArgumentParser(prog=prog, usage="%(prog)s [command] [options]",
                                description=DESCRIPTION, epilog=EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="*", help=argparse.SUPPRESS)
    p.add_argument("-c", "--copy", action="store_true",
                   help="copy the result to the clipboard")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="don't print the result, handy with -c")
    p.add_argument("-g", "--gui", action="store_true",
                   help="open the result in the window instead of printing it")
    p.add_argument("-n", "--numbered", action="store_true",
                   help="use numbered placeholders like [Redacted-AccountID-1]")
    p.add_argument("-p", "--private-ips", action="store_true",
                   help="also redact private IPs this time")
    p.add_argument("-w", "--word", action="append", default=[], metavar="WORD",
                   help="also redact WORD this time, can repeat")
    p.add_argument("-k", "--keep", action="append", default=[], metavar="WORD",
                   help="don't redact WORD this time, can repeat")
    p.add_argument("--skip", action="append", default=[], metavar="CATS",
                   help="turn categories off this time, comma separated")
    p.add_argument("--only", metavar="CATS",
                   help="use only these categories this time, comma separated")
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {VERSION} (part of AWS Kit)")
    return p


def split_run(argv):
    """Find a `run` subcommand and split our options from the command to run."""
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return argv, None
        if token.startswith("-"):
            i += 2 if token in VALUE_FLAGS else 1
            continue
        if token != "run":
            return argv, None
        ours, rest = argv[:i], argv[i + 1:]
        j = 0
        while j < len(rest) and rest[j].startswith("-") and rest[j] != "--":
            ours.append(rest[j])
            if rest[j] in VALUE_FLAGS and j + 1 < len(rest):
                j += 1
                ours.append(rest[j])
            j += 1
        if j < len(rest) and rest[j] == "--":
            j += 1
        return ours, rest[j:]
    return argv, None


def main(argv=None, prog="pii-redact"):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv, run_command = split_run(argv)
    args = build_parser(prog).parse_args(argv)

    target = args.target
    command = "run" if run_command is not None else (
        target[0] if target and target[0] in COMMANDS else None)
    files = target[1:] if command and command != "run" else target

    if command == "install":
        from .cli import cmd_install
        return cmd_install(args)
    if command == "uninstall":
        print("PII Redact is part of AWS Kit now. To remove it, run: awskit uninstall",
              file=sys.stderr)
        return 1
    if command == "categories":
        return cmd_categories()
    if command == "settings":
        return run_gui(mode="settings")

    cfg = load_config()
    options_from(cfg, args)  # check category names early

    if command == "run":
        return cmd_run(run_command, cfg, args)
    if command == "clip":
        return cmd_clip(cfg, args)
    if command == "gui":
        return run_gui(initial_text=read_files(files) if files else None)
    if files or stdin_has_data():
        return emit(read_files(files), cfg, args)
    return run_gui()
