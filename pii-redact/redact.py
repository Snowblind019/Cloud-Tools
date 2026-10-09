"""PII Redact: strips account IDs, keys, ARNs, resource IDs, emails, public IPs and other
identifying info out of Terraform, AWS CLI, boto3 and general command output, so it can be
shared for troubleshooting.

This file has the redaction rules, the settings and the command line. The window is in
redact_page.py. Run `pii-redact --help` (same as `awskit redact --help`) for every option.
"""
from __future__ import annotations

import argparse
import bisect
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

from .common import (CONFIG_DIR, VERSION, ClipboardError, keep_unreadable, notify,
                     read_clipboard, write_atomic, write_clipboard)

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
    if mixed_charset(s):
        return entropy(s) >= 4.2  # AWS secret keys, not file paths
    # About 1 real key in 900 has no digit at all. Without one, ask for a fair mix of both
    # cases with lots of switching between them, which camelCase names, long words and
    # paths don't have.
    letters = [c for c in s if c.isalpha()]
    upper = sum(c.isupper() for c in letters)
    if not letters or not 0.25 <= upper / len(letters) <= 0.75:
        return False
    flips = sum(1 for a, b in zip(s, s[1:])
                if a.isalpha() and b.isalpha() and a.isupper() != b.isupper())
    return flips >= 13 and entropy(s) >= 4.3


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


def url_creds_check(s):
    # https://host:8443/path@x is a host, port and path, not user:password
    return not re.match(r"\d{1,5}(?:[/?#]|$)", s.partition(":")[2])


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
# One or more line breaks, real ones or \n written inside a JSON string
GAP = r"(?:[ \t]*(?:\r?\n|\\r\\n|\\n))+[ \t]*"
# A whole line of base64, ending at a line break (real or written) or a closing quote
B64_LINE = r"[A-Za-z0-9+/=]+(?=[ \t]*(?:\r?\n|\\[rn]|[\"'](?=[\s,;)\]}]|\Z)|\Z))"
# A value after -p or --password: quoted, or up to the next space
FLAG_VALUE = r"'[^'\n]*'|\"[^\"\n]*\"|[^\s\"'-][^\s\"']*"
# A URL query string value, up to the next &
QUERY_VALUE = r"([^&\s\"'<>#\\,]+)"
EC2_PREFIXES = (
    "i|vpc|subnet|sg|sgr|igw|eigw|nat|rtb|rtbassoc|acl|aclassoc|eni|eni-attach|vol|snap|ami|"
    "eipalloc|eipassoc|vpce|vpce-svc|pcx|tgw|tgw-attach|tgw-rtb|lt|dopt|cgw|vgw|vpn|fs|fsap|"
    "fsmt|ipam|ipam-pool|ipam-scope|pl|sir|fleet|cr|key|fl|lgw|ssoins|ins|ps|cvpn-endpoint|"
    "vpc-flow-log"
)

# When two rules match the exact same text, the one higher up names it.
RULES = [
    # The body can't hold another BEGIN line and is at most 64 KB (a 16384-bit RSA key in
    # PEM is about 12 KB), so a BEGIN line without an END line only reads on to the next
    # BEGIN line. Reading to the end of the text for each one made a crafted text of
    # thousands of BEGIN lines take seconds to minutes.
    R("private_keys", "PrivateKey",
      r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN ).){0,65536}?"
      r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", flags=re.S),
    # A key pasted without its END line: the header lines and base64 lines after BEGIN,
    # up to the first line that isn't base64. Also catches a key flattened onto one line.
    R("private_keys", "PrivateKey",
      r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
      r"(?:" + GAP + r"[A-Za-z][\w-]*:[ \t][^\r\n\\]*)*"
      r"(?:" + GAP + B64_LINE + r"|[ \t]+[A-Za-z0-9+/=]{16,}(?![A-Za-z0-9+/=]))*"),
    # PuTTY .ppk files
    R("private_keys", "PrivateKey",
      r"\bPrivate-Lines:[ \t]*\d+" + GAP + "(" + B64_LINE + "(?:" + GAP + B64_LINE + ")*)",
      group=1),
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
    # Authorization: Bearer ... and Basic ... headers, JWT or not
    R("tokens", "Token",
      r"(?<![\w-])(?:Proxy-)?Authorization\\?[\"']?[ \t]*[:=][ \t]*\\?[\"']?[ \t]*"
      r"(?:Bearer|Basic|Token|Negotiate|NTLM|ApiKey|Api-Key|SSWS)[ \t]+([^\s\"'\\,;]+)",
      group=1, flags=re.I),

    R("aws_keys", "AccessKey", r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    R("iam_ids", "IAMUniqueID",
      r"(?<![A-Z0-9])(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16,}"
      r"(?![A-Z0-9])"),
    R("aws_keys", "SessionToken",
      r"(?<![A-Za-z0-9/+])(?:IQoJb3JpZ2lu|FwoGZXIvYXdz|FQoGZXIvYXdz)[A-Za-z0-9/+=]{40,}"),
    # Presigned URLs. %2F and %2B cut the session token into short pieces, so the whole
    # parameter goes.
    R("aws_keys", "SessionToken", r"(?<![\w-])X-Amz-Security-Token=" + QUERY_VALUE, group=1,
      flags=re.I),
    R("aws_keys", "AccessKey",
      r"(?<![\w-])X-Amz-Credential=([A-Za-z0-9]{16,128})(?=%2F|/|&|\s|$)", group=1, flags=re.I),
    R("aws_keys", "Signature", r"(?<![\w-])(?:X-Amz-)?Signature=" + QUERY_VALUE, group=1,
      flags=re.I),
    R("tokens", "Token", r"(?<![A-Za-z0-9/+=_-])[A-Za-z0-9/+=_-]{100,}(?![A-Za-z0-9/+=_-])",
      check=long_token_check),
    # A secret key can come right after = (MY_KEY=...) or after a \n written in JSON
    R("aws_keys", "SecretKey",
      r"(?:(?<=\\[nrt])|(?<![A-Za-z0-9/+]))[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])",
      check=secret_40_check),
    R("url_creds", "Credentials", r"(?<=://)[^/\s:@\"']{1,256}:[^\s@\"']{1,256}(?=@)",
      check=url_creds_check),
    # Passwords given on the command line: mysql -pSECRET, docker login -p SECRET and
    # mongosh -p SECRET. --password SECRET is handled with the other settings.
    R("secret_values", "Secret",
      r"\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlshow|mysqlpump|mariadb)"
      r"\b[^\n]{0,400}?[ \t]-p(" + FLAG_VALUE + ")", group=1),
    R("secret_values", "Secret",
      r"(?<![\w-])(?:login|mongo|mongosh|mongodump|mongorestore|mongoexport|mongoimport)"
      r"(?=[ \t])[^\n]{0,400}?[ \t]-p[ \t]+(" + FLAG_VALUE + ")", group=1),

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
    R("aws_hostnames", "Hostname", r"\b([a-z0-9][a-z0-9-]{0,62})\.awsapps\.com\b", group=1),
    R("aws_hostnames", "Hostname", rf"\.([a-z0-9]{{12}})\.{REGION}\.rds\.amazonaws\.com", group=1),
    R("aws_hostnames", "Hostname",
      rf"\b((?:internal-)?[\w-]{1,62}-\d{1,20})\.{REGION}\.elb\.amazonaws\.com", group=1),
    R("buckets", "Bucket", r"(?<=s3://)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
    R("buckets", "Bucket", r"(?<=arn:aws:s3:::)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
    R("buckets", "Bucket",
      r"\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", group=1),

    # Lengths are capped at what email allows, so long runs of dots or dashes stay fast
    R("emails", "Email", r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b",
      check=email_check),
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
        "rootpassword secretstring",
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
SECRET_HIT = ("secret_values", "Secret")

# Any other setting whose name ends like this holds a secret too, so DATABASE_PASSWORD,
# MasterUserPassword, PGPASSWORD, JWT_SECRET, DB_PASS and x-api-key all count.
SECRET_ENDINGS = ("password", "passwd", "passphrase", "pwd", "pass", "secret", "secretkey",
                  "secretaccesskey", "token", "apikey", "privatekey", "credential",
                  "credentials", "auth", "accesskey", "accesskeyid")
# Endings that don't change what the setting holds, like Terraform's write-only
# password_wo, or secret_value and private_key_pem
SECRET_QUALIFIERS = re.compile(r"(?:wo|value|string|b64|base64|pem|openssh|pkcs8|plaintext"
                               r"|raw|hash)+$")
# Names that end like a secret but aren't one: paging and request tokens, sudoers rules
NOT_SECRETS = {"nexttoken", "nextcontinuationtoken", "continuationtoken", "paginationtoken",
               "startingtoken", "nextpagetoken", "pagetoken", "clienttoken", "idempotencytoken",
               "bypass", "proxybypass", "compass", "nopasswd", "nopassword", "iamauth",
               "oldpwd"}


def key_norm(key):
    """A setting name compared without case, _ or -, and without a prefix like var.x."""
    return key.split(".")[-1].lower().replace("_", "").replace("-", "")


def secret_name(norm):
    if norm in NOT_SECRETS:
        return False
    base = SECRET_QUALIFIERS.sub("", norm) or norm
    return base not in NOT_SECRETS and base.endswith(SECRET_ENDINGS)


def key_hit(norm):
    return SENSITIVE_KEYS.get(norm) or (SECRET_HIT if secret_name(norm) else None)


KV_RE = re.compile(
    # A key starts a word, or a flag like --password=x or -Dpassword=x, or follows a \n
    # written inside a JSON string. Not after a colon, so the parts of an ARN aren't
    # keys. Keys can be quoted, also with escaped quotes like \"password\" inside a
    # JSON string that holds JSON.
    r"""(?:(?<=\\[nrt])|(?<=--)|(?<=[\s"'=(]-)|(?<![\w.\\:-]))"""
    r"""(?P<kq>\\?["']|)(?P<key>[A-Za-z_][\w.-]{0,199})(?P=kq)"""
    r"""[ \t]*(?P<sep>:=|=>|[=:])[ \t]*"""
    r"""(?:(?P<q>\\?["'])(?P<qval>(?:(?!(?P=q))(?:\\.|[^\\\n]))*)(?P=q)"""
    # An unquoted value is only measured (with VALUE_WORD) when the key matters, so a
    # long value isn't read again for every = or : inside it
    r"""|(?P<val>(?=[^\s,;{}\[\]"'\\]|\\(?![nrt"']))))"""
)
VALUE_WORD = re.compile(r"""(?:[^\s,;{}\[\]"'\\]|\\(?![nrt"']))"""
                        r"""(?:[^\s,;{}\[\]()#"'\\]|\\(?![nrt"']))*""")
# More words of a name after the first one, like Doe in Owner: Jane Doe. Only words that
# start with a capital and have a small letter count, so a log line like user: admin
# logged in keeps its words, and one that's the next key (Env=prod) ends it.
NAME_MORE = re.compile(r"[ \t]+(?=[^\W\d_])(?:[\w'\u2019-]*\w)(?![\w'\u2019-])(?![ \t]*[:=])")
# Terraform's "old" -> "new"
ARROW = re.compile(r"""[ \t]*->[ \t]*(?P<q>["'])(?P<qval>(?:(?!(?P=q))(?:\\.|[^\\\n]))*)(?P=q)""")
# --password SECRET and similar command line flags, with a space instead of =
FLAG_RE = re.compile(
    r"""(?<![\w-])--(?P<key>[A-Za-z][\w-]{0,63})[ \t]+"""
    r"""(?:(?P<q>["'])(?P<qval>(?:(?!(?P=q))(?:\\.|[^\\\n]))*)(?P=q)"""
    r"""|(?P<val>[^\s"'\\-][^\s"']*))"""
)
# Terraform references like var.x or aws_s3_bucket.logs.id are names, not data
TF_REF = re.compile(r"^(?:var|local|data|module|each|count|self|path|terraform)\.[\w.\[\]\"*-]+$"
                    r"|^[a-z][a-z0-9_]*\.[a-z0-9_-]+\.[\w.\[\]\"*-]+$")
SKIP_VALUES = {"", "null", "none", "nil", "true", "false", "*", "undefined"}
# Terraform progress lines like random_password.db: Creating...
TF_STATUS = re.compile(r"(?:Creating|Creation complete|Modifying|Modifications complete"
                       r"|Destroying|Destruction complete|Refreshing state|Reading|Read complete"
                       r"|Still \w+ing|Importing|Import (?:prepared|complete)|Preparing import)\b")
# Values that point at a secret instead of holding one: ${var.x} and {{ vault_pw }}
TEMPLATE = re.compile(r"\$\{[^}]*\}|^\{\{.*\}\}$")
# Unquoted values that are code: (sensitive value) and other Terraform placeholders,
# function calls like jsonencode({ or os.getenv("X") or file(var.path), $(command) and
# CloudFormation tags like !Ref. A password like Abc(123xyz isn't any of these.
CODE = re.compile(r"""^\([^()]*\)|^\$\(|^[A-Za-z_][\w.]*\((?:[{\["'$)]|$)"""
                  r"""|^[a-z_][\w.]*\(.*\)[,;]?$"""
                  r"""|^!(?:Ref|Sub|GetAtt|ImportValue|Join|If|Select|FindInMap|Base64|Split"""
                  r"""|GetAZs|Cidr|Transform)\b""")
# A SigV4 credential scope (AKIA.../20261004/us-east-1/s3/aws4_request): the access key
# rules take the key and leave the date, region and service readable
CRED_SCOPE = re.compile(r"[A-Z0-9]{16,128}(?:/|%2F)\d{8}(?:/|%2F)", re.I)
# What can come before KEY=value at the start of a line: indentation, export or set,
# a list dash, a comment mark, or Terraform's + ~ - markers
LINE_LEAD = re.compile(r"[ \t]*(?:(?:export|set|setx|readonly|local|declare[ \t]+-x)[ \t]+"
                       r"|\$env:|(?://|[-+~*#>;])[ \t]*)*", re.I)
# An inline secret runs to the next space, quote, comma or semicolon (connection strings
# put ; between settings), and in a URL query string to the next &
SECRET_WORD = re.compile(r"""(?:[^\s,;"'\\]|\\(?![nrt"']))+""")
QUERY_WORD = re.compile(r"""(?:[^\s,;"'\\&#]|\\(?![nrt"']))+""")
# The rest of a line written inside a JSON string, up to the next \n or closing quote
ESCAPED_REST = re.compile(r"""(?:[^\\"\r\n]|\\(?![nr"]))*""")

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


def _secret_value_ok(value, quoted, placeholder, first=None):
    """Like _kv_value_ok, for passwords and keys. first is the value's first word."""
    v = value.strip()
    first = (first or v).strip()
    if v.lower() in SKIP_VALUES or first.lower() in SKIP_VALUES or f"[{placeholder}" in v:
        return False
    if v.startswith("arn:") or CRED_SCOPE.match(v) or TEMPLATE.search(v):
        return False
    if not quoted and (TF_REF.match(first) or CODE.search(v)):
        return False
    return True


def _trim_closers(value):
    """Drop a ) ] or } at the end that closes something outside the value, like f(pw=x)."""
    while value and value[-1] in ")]}":
        opener = "([{"[")]}".index(value[-1])]
        if value.count(value[-1]) <= value.count(opener):
            break
        value = value[:-1]
    return value


def _secret_end(text, m):
    """Where an unquoted secret ends. On a KEY=value or key: value line it's the end of
    the line, so a space, # or ( in the password doesn't cut it short. Inline, it's the
    end of the word."""
    start, key_start = m.start("val"), m.start()
    if text.endswith("\\n", 0, key_start) or text.endswith("\\r", 0, key_start):
        rest = ESCAPED_REST.match(text, start).group()  # a line inside a JSON string
        return start + len(rest.rstrip(" \t"))
    # Only look back a little way for the line start, so long lines stay fast
    line_start = text.rfind("\n", max(0, key_start - 200), key_start) + 1
    if (line_start or key_start <= 200) and LINE_LEAD.fullmatch(text, line_start, key_start):
        end = text.find("\n", start)
        end = len(text) if end < 0 else end
        while end > start and text[end - 1] in " \t\r":
            end -= 1
        return end
    query = m.group("sep") == "=" and text[key_start - 1:key_start] in ("?", "&")
    # An empty query value (?token=&next=1) has no word at all
    word = (QUERY_WORD if query else SECRET_WORD).match(text, start)
    return start + len(_trim_closers(word.group() if word else ""))


def _name_end(text, end):
    """Where an unquoted name ends: Owner: Jane Doe takes Doe too, up to four more words."""
    for _ in range(4):
        m = NAME_MORE.match(text, end)
        word = m.group().lstrip(" \t") if m else ""
        if not (word[:1].isupper() and any(c.islower() for c in word)):
            break
        end = m.end()
    return end


def kv_spans(text, prio, placeholder):
    spans = []
    pos = 0
    while True:
        m = KV_RE.search(text, pos)
        if m is None:
            break
        key, quoted = m.group("key"), m.group("q") is not None
        value_start = m.start("qval") if quoted else m.start("val")
        hit = key_hit(key_norm(key))
        if (hit and "." in key and m.group("sep") == ":"
                and TF_STATUS.match(text, m.start("q" if quoted else "val"))):
            hit = None  # random_password.db: Creating... is a Terraform address
        found = []
        if hit:
            secret = hit == SECRET_HIT
            ok = _secret_value_ok if secret else _kv_value_ok
            if quoted:
                if ok(m.group("qval"), True, placeholder):
                    found.append((m.start("qval"), m.end("qval")))
                word_end = m.end()
            else:
                word_end = VALUE_WORD.match(text, value_start).end()
                word = text[value_start:word_end]
                if secret:
                    end = _secret_end(text, m)
                    if ok(text[value_start:end], False, placeholder, word):
                        found.append((value_start, end))
                # jsonencode(...) and other function calls aren't data
                elif text[word_end:word_end + 1] != "(" and ok(word, False, placeholder):
                    found.append((value_start, _name_end(text, word_end) if hit[0] == "names"
                                  else word_end))
            arrow = ARROW.match(text, word_end)
            if arrow and ok(arrow.group("qval"), True, placeholder):
                found.append(arrow.span("qval"))
        spans.extend((s, e, prio) + hit for s, e in found)
        # Carry on after a redacted value. Otherwise look inside the value too, since it
        # can hold more settings, like the JSON in a SecretString or an SSM parameter.
        pos = max(e for _, e in found) if found else value_start

    for m in FLAG_RE.finditer(text):
        norm = key_norm(m.group("key"))
        # curl --anyauth and similar take no value
        if norm.endswith("auth") or key_hit(norm) != SECRET_HIT:
            continue
        group = "qval" if m.group("q") is not None else "val"
        if _secret_value_ok(m.group(group), group == "qval", placeholder):
            spans.append((m.start(group), m.end(group), prio) + SECRET_HIT)
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


def find_spans(text: str, opts: Options) -> list:
    """Where redactions go in text, as (start, end, label), without changing anything.

    Image Redact uses this on text read from screenshots, so both tools find the same
    things with the same settings.
    """
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

    # Anything inside a never-redact match stays visible. The matches don't overlap and
    # come in order, so the only one that can hold a span is the last one starting
    # at or before it.
    never = word_regex(opts.never)
    if never:
        protected = [m.span() for m in never.finditer(text)]
        starts = [ps for ps, _ in protected]

        def visible(sp):
            i = bisect.bisect_right(starts, sp[0]) - 1
            return i < 0 or sp[1] > protected[i][1]
        spans = [sp for sp in spans if visible(sp)]

    # Earliest start wins, then the longest match, then rule order
    spans.sort(key=lambda t: (t[0], -(t[1] - t[0]), t[2]))
    chosen, last_end = [], 0
    for s, e, _, _, label in spans:
        if s >= last_end:
            chosen.append((s, e, label))
            last_end = e
    return chosen


def redact(text: str, opts: Options):
    """Return (redacted_text, Counter of labels, list of (start, end) placeholder offsets)."""
    text = ANSI_RE.sub("", text)
    chosen = find_spans(text, opts)

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
        # utf-8-sig: a file saved from Notepad or PowerShell can start with a byte order mark
        data = json.loads(source.read_text(encoding="utf-8-sig"))
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
    categories = data.get("categories")
    for cid, value in (categories.items() if isinstance(categories, dict) else ()):
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
        keep_unreadable(CONFIG_FILE)
        # The word lists can hold names and employers, so only the owner can read it
        write_atomic(CONFIG_FILE, json.dumps(cfg, indent=2) + "\n", mode=0o600)
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


def read_stdin():
    """Everything piped in. A byte that isn't valid text shows as the replacement
    character, the same as in files, instead of stopping with UnicodeDecodeError."""
    buf = getattr(sys.stdin, "buffer", None)
    if buf is None:
        return sys.stdin.read()
    return buf.read().decode(sys.stdin.encoding or "utf-8", errors="replace")


def read_files(paths):
    if not paths or paths == ["-"]:
        return read_stdin()
    parts = []
    for p in paths:
        try:
            parts.append(read_stdin() if p == "-" else
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
        # The command line can hold a password or key too, so it gets the same treatment
        shown, _, _ = redact(" ".join(command), options_from(cfg, args))
        print(f"Running {shown} (output shows when it finishes)", file=sys.stderr)
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        print(f"pii-redact: command not found: {command[0]}", file=sys.stderr)
        return 127
    except OSError as exc:
        # Not executable, a folder, or a file that isn't a program
        print(f"pii-redact: can't run {command[0]}: {exc.strerror or exc}", file=sys.stderr)
        return 126
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
