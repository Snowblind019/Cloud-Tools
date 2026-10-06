"""Policy evaluation: does a policy statement apply to a request, and why.

Org & SCPs uses this to answer "would an SCP or RCP block this", but it works on any IAM
policy statement: Action and NotAction, Resource and NotResource, Principal and
NotPrincipal, every condition operator, the ...IfExists forms, ForAllValues: and
ForAnyValue:, and policy variables like ${aws:PrincipalTag/team}.

It evaluates statements, it doesn't make a whole IAM decision. Combining identity policies,
permission boundaries, session policies and resource policies is left to the caller (Org &
SCPs only combines SCPs and RCPs).

Every result has three possible values: True (the statement applies), False (it doesn't),
or None (it depends on something that wasn't given, like a context key or the resource).
Each result also says what it would be if the missing context keys aren't set at all, using
AWS's documented rules for missing keys:

- a missing key makes a positive operator (StringEquals, ArnLike, Bool, IpAddress ...) false
- it makes a negated operator (StringNotEquals, ArnNotLike, NotIpAddress ...) true
- ...IfExists is true when the key is missing
- ForAllValues: is true when the key is missing or empty, ForAnyValue: is false
- Null checks whether the key is there

Keys that every real request has, like aws:RequestedRegion or aws:PrincipalArn, are never
"not set", so for those the "if not set" answer stays None.

Condition key names are case-insensitive. Values are case-sensitive, except with the
...IgnoreCase operators. Action names are case-insensitive. ARNs are case-sensitive.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache

from . import iampolicy

VERSION = "2012-10-17"
RESOURCE = "the resource"          # stands in for "the resource ARN" in depends_on lists

# Services whose resources resource control policies (RCPs) apply to, by their action
# prefix. This is the one place the list lives. RCPs launched in November 2024 with S3,
# STS, KMS, SQS and Secrets Manager, and AWS keeps adding services. This copy is from "List
# of AWS services that support RCPs" in the AWS Organizations user guide, as of October
# 2026. Check that page when this needs updating.
RCP_SERVICES = frozenset({
    "aoss", "appconfig", "appstream", "autoscaling", "autoscaling-plans", "budgets",
    "clouddirectory", "cloudfront", "cloudsearch", "cloudtrail-data", "codeartifact",
    "codebuild", "codecommit", "codepipeline", "cognito-identity", "cognito-idp",
    "comprehend", "comprehendmedical", "compute-optimizer", "cost-optimization-hub", "dax",
    "dsql", "dynamodb", "ecr", "ecr-public", "events", "firehose", "fis", "fms", "gamelift",
    "health", "inspector-scan", "kendra", "kinesisvideo", "kms", "logs", "memorydb",
    "networkmonitor", "notifications", "opensearch", "pca-connector-ad", "personalize",
    "polly", "pricing", "resource-groups", "rolesanywhere", "s3", "secretsmanager",
    "servicediscovery", "signin", "sqs", "sts", "support", "swf", "textract",
    "timestream-influxdb", "transcribe", "transfer", "translate", "wafv2", "workspaces",
    "xray",
})

# Keys every real request carries. A missing one means "not given", never "not set".
ALWAYS_PRESENT = frozenset({
    "aws:requestedregion", "aws:principalarn", "aws:principalaccount", "aws:principaltype",
    "aws:principalorgid", "aws:principalorgpaths", "aws:userid", "aws:securetransport",
    "aws:currenttime", "aws:epochtime", "aws:principalisawsservice", "aws:viaawsservice",
})


class _Absent:
    """Marks a context key that's known not to be set."""

    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()


# =================================================================== three-valued logic

def all_of(values) -> object:
    """True if every value is True, False if any is False, else None."""
    values = list(values)
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def any_of(values) -> object:
    """True if any value is True, False if every one is False, else None."""
    values = list(values)
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


def negate(value) -> object:
    return None if value is None else not value


# =================================================================== context

def text_value(value) -> str:
    """A policy or context value as IAM sees it: JSON true is "true", 5 is "5"."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def make_context(context) -> dict:
    """Keys lowercased, values as lists of strings. ABSENT (or None) means not set."""
    out = {}
    for key, value in dict(context or {}).items():
        k = str(key).strip().lower()
        if not k:
            continue
        if value is None or value is ABSENT:
            out[k] = ABSENT
        elif isinstance(value, (list, tuple, set)):
            out[k] = [text_value(v) for v in value]
        else:
            out[k] = [text_value(value)]
    return out


@dataclass
class Request:
    """What's being asked: one action, on a resource (empty or * when it isn't known),
    with a context of condition keys."""
    action: str
    resource: str = ""
    context: dict = field(default_factory=dict)

    def __post_init__(self):
        self.action = str(self.action or "").strip()
        self.resource = str(self.resource or "").strip()
        self.context = make_context(self.context)

    @property
    def service(self) -> str:
        return self.action.split(":", 1)[0].lower()

    @property
    def resource_known(self) -> bool:
        return bool(self.resource) and self.resource != "*"


# =================================================================== wildcards

STAR, QMARK = "\ue000", "\ue001"   # a literal * or ? that came out of ${*} or a variable

# Wildcard patterns are matched with a small state machine instead of a regular expression:
# a regex like .*a.*a.*a... backtracks for minutes on a crafted policy, while this takes
# time in proportion to the text times the number of wildcards. A pattern is a tuple of
# tokens: ("c", char) is one literal character, ("?", colons) one character and ("*",
# colons) any run of characters, where colons says whether they may include a colon.


def _tokens(chars) -> tuple:
    """Tokens from (char, colons) pairs, with runs of * merged into one."""
    out = []
    for ch, colons in chars:
        if ch == "*":
            if out and out[-1][0] == "*":
                out[-1] = ("*", out[-1][1] or colons)
            else:
                out.append(("*", colons))
        elif ch == "?":
            out.append(("?", colons))
        else:
            out.append(("c", "*" if ch == STAR else "?" if ch == QMARK else ch))
    return tuple(out)


@lru_cache(maxsize=4096)
def _glob_tokens(pattern: str, ignorecase: bool) -> tuple:
    """Only * and ? are special in IAM. Square brackets are plain characters, which is why
    this doesn't use fnmatch."""
    text = pattern.lower() if ignorecase else pattern
    return _tokens((ch, True) for ch in text)


@lru_cache(maxsize=4096)
def _arn_tokens(pattern: str, expand: bool) -> tuple:
    """An ARN pattern's tokens. In the first five colon-separated parts, ? and * stay
    inside their part. With expand (the Resource element), a * that ends a part may run on
    past the colon: AWS documents that "If the * wildcard is the last character of a
    resource ARN segment, it can expand to match beyond the colon boundaries". ArnLike
    checks the parts one by one. Either way a * that ends the whole pattern (like
    arn:aws:s3:*) covers the rest, and in the resource part (after the fifth colon) * and ?
    match colons like any other character."""
    chars, colons = [], 0
    for i, ch in enumerate(pattern):
        if colons >= 5:
            chars.append((ch, True))
            continue
        if ch == ":":
            colons += 1
            chars.append((ch, False))
        elif ch == "*":
            last = i + 1 == len(pattern)
            chars.append((ch, last or (expand and pattern[i + 1] == ":")))
        else:
            chars.append((ch, False))
    return _tokens(chars)


def _takes(tok, ch) -> bool:
    """Can a ? or literal token take the character ch."""
    if tok[0] == "c":
        return tok[1] == ch
    return tok[1] or ch != ":"


def _closure(tokens, states) -> set:
    """States plus every state reachable by letting a * match nothing."""
    out, todo = set(), list(states)
    while todo:
        i = todo.pop()
        if i in out:
            continue
        out.add(i)
        if i < len(tokens) and tokens[i][0] == "*":
            todo.append(i + 1)
    return out


def _run(tokens, text) -> bool:
    end = len(tokens)
    cur = _closure(tokens, {0})
    for ch in text:
        nxt = set()
        for i in cur:
            if i == end:
                continue
            tok = tokens[i]
            if tok[0] == "*":
                if tok[1] or ch != ":":
                    nxt.add(i)
            elif _takes(tok, ch):
                nxt.add(i + 1)
        if not nxt:
            return False
        cur = _closure(tokens, nxt)
    return end in cur


def glob_match(pattern: str, text: str, ignorecase=False) -> bool:
    return _run(_glob_tokens(pattern, ignorecase), text.lower() if ignorecase else text)


def literal(text: str) -> str:
    return text.replace(STAR, "*").replace(QMARK, "?")


def action_matches(pattern, action: str) -> bool:
    """Action names and service prefixes are case-insensitive."""
    pattern = str(pattern).strip()
    if pattern == "*":
        return True
    return glob_match(pattern, action, ignorecase=True)


def _pattern_tokens(pattern: str, expand: bool) -> tuple:
    if pattern.startswith("arn:"):
        return _arn_tokens(pattern, expand)
    return _glob_tokens(pattern, False)


def arn_match(pattern: str, value: str, expand=True) -> bool:
    """An ARN pattern against an ARN. expand is True for the Resource element and False
    for ArnLike and ArnEquals, which AWS documents as checking "each of the six
    colon-delimited components of the ARN separately". See _arn_tokens."""
    if not pattern.strip("*"):
        return True                                   # "*" matches anything
    return _run(_pattern_tokens(pattern, expand), value)


# Comparing a policy's pattern with a request resource that has wildcards in it, like
# arn:aws:s3:::prod-*: the statement covers the request only if it covers every resource
# the request's pattern could stand for.

MAX_PAIR_STATES = 2_000_000


def _covers(big, small) -> bool:
    """True when every text the tokens small match is also matched by the tokens big. A
    * or ? in small has to be taken by a * or ? in big that's at least as wide."""
    def takes(tok, sym):
        if sym[0] == "c":
            return _takes(tok, sym[1])
        if tok[0] == "c" or (tok[0] == "?" and sym[0] == "*"):
            return False
        return tok[1] or not sym[1]
    end = len(big)
    cur = _closure(big, {0})
    for sym in small:
        nxt = set()
        for i in cur:
            if i == end:
                continue
            tok = big[i]
            if takes(tok, sym):
                nxt.add(i if tok[0] == "*" else i + 1)
        if not nxt:
            return False
        cur = _closure(big, nxt)
    return end in cur


def _overlap(a, b) -> object:
    """True if some text matches both token lists, False if none can, None if that's too
    much work to tell."""
    if (len(a) + 1) * (len(b) + 1) > MAX_PAIR_STATES:
        return None

    def common(x, y):          # is there a character both tokens take
        if x[0] == "c" and y[0] == "c":
            return x[1] == y[1]
        if x[0] == "c":
            return _takes(y, x[1])
        if y[0] == "c":
            return _takes(x, y[1])
        return True
    seen, todo = set(), [(0, 0)]
    while todo:
        i, j = todo.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i][0] == "*":
            todo.append((i + 1, j))
        if j < len(b) and b[j][0] == "*":
            todo.append((i, j + 1))
        if i < len(a) and j < len(b) and common(a[i], b[j]):
            todo.append((i if a[i][0] == "*" else i + 1, j if b[j][0] == "*" else j + 1))
    return False


def has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def arn_match_pattern(pattern: str, request: str) -> object:
    """A policy's ARN pattern against a request resource with * or ? in it: True if the
    pattern covers everything the request could mean, False if it covers none of it, None
    if it covers some (the answer depends on which resource)."""
    if not pattern.strip("*"):
        return True
    big = _pattern_tokens(pattern, True)
    small = _arn_tokens(request, False) if request.startswith("arn:") else \
        _glob_tokens(request, False)
    if _covers(big, small):
        return True
    return None if _overlap(big, small) is not False else False


# =================================================================== policy variables

_VAR = re.compile(r"\$\{([^}]*)\}")


class Unresolved:
    """A value that holds a policy variable whose key wasn't in the context."""

    def __init__(self, key: str, known_absent=False):
        self.key = key
        self.known_absent = known_absent


def substitute(text: str, context: dict, version=VERSION):
    """Fill in ${...} policy variables. Returns the filled-in text (with any * or ? that
    came from a variable or from ${*} marked as literal), or an Unresolved when a key it
    needs isn't in the context and has no default. Policies without Version 2012-10-17
    take ${...} as plain text."""
    text = str(text)
    if version != VERSION or "${" not in text:
        return text
    missing = []

    def fill(m):
        inner = m.group(1).strip()
        if inner == "*":
            return STAR
        if inner == "?":
            return QMARK
        if inner == "$":
            return "$"
        key, default = inner, None
        if "," in inner:
            key, default = inner.split(",", 1)
            key = key.strip()
            default = default.strip().strip("'\"")
        got = context.get(key.lower())
        if isinstance(got, list) and got:
            return got[0].replace("*", STAR).replace("?", QMARK)
        if default is not None:
            return default
        missing.append((key, got is ABSENT))
        return ""
    out = _VAR.sub(fill, text)
    if missing:
        key, absent = missing[0]
        return Unresolved(key, known_absent=absent)
    return out


# =================================================================== condition operators

# base operator -> (kind, negated, ignore case)
OPERATORS = {
    "stringequals": ("string", False, False),
    "stringnotequals": ("string", True, False),
    "stringequalsignorecase": ("string", False, True),
    "stringnotequalsignorecase": ("string", True, True),
    "stringlike": ("like", False, False),
    "stringnotlike": ("like", True, False),
    "numericequals": ("num_eq", False, False),
    "numericnotequals": ("num_eq", True, False),
    "numericlessthan": ("num_lt", False, False),
    "numericlessthanequals": ("num_le", False, False),
    "numericgreaterthan": ("num_gt", False, False),
    "numericgreaterthanequals": ("num_ge", False, False),
    "dateequals": ("date_eq", False, False),
    "datenotequals": ("date_eq", True, False),
    "datelessthan": ("date_lt", False, False),
    "datelessthanequals": ("date_le", False, False),
    "dategreaterthan": ("date_gt", False, False),
    "dategreaterthanequals": ("date_ge", False, False),
    "bool": ("bool", False, False),
    "binaryequals": ("binary", False, False),
    "ipaddress": ("ip", False, False),
    "notipaddress": ("ip", True, False),
    "arnequals": ("arn", False, False),
    "arnlike": ("arn", False, False),
    "arnnotequals": ("arn", True, False),
    "arnnotlike": ("arn", True, False),
    "null": ("null", False, False),
}
# Kinds whose policy values can hold policy variables.
VARIABLE_KINDS = {"string", "like", "arn"}


def split_operator(operator: str):
    """'ForAnyValue:StringNotLikeIfExists' -> ('any', 'stringnotlike', True).
    The set operator is 'all', 'any' or ''."""
    low = str(operator).strip().lower()
    setop = ""
    if low.startswith("forallvalues:"):
        setop, low = "all", low[len("forallvalues:"):]
    elif low.startswith("foranyvalue:"):
        setop, low = "any", low[len("foranyvalue:"):]
    ifexists = low.endswith("ifexists") and low != "ifexists"
    if ifexists:
        low = low[:-len("ifexists")]
    return setop, low, ifexists


def known_operator(operator: str) -> bool:
    setop, base, ifexists = split_operator(operator)
    if base not in OPERATORS:
        return False
    return not (base == "null" and (ifexists or setop))


def _number(text):
    return float(str(text).strip())


def _date(text):
    s = str(text).strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    s = s.replace("Z", "+00:00").replace("z", "+00:00")
    m = re.match(r"(.*T\d\d:\d\d:\d\d)\.(\d+)(.*)$", s)
    if m:  # Python 3.9 only takes 3 or 6 digits of fractions
        s = m.group(1) + "." + (m.group(2) + "000000")[:6] + m.group(3)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _binary(text):
    s = str(text).strip()
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return s.encode("utf-8", "replace")


def _compare(kind, given, wanted, ignorecase) -> bool:
    """One context value against one policy value."""
    try:
        if kind == "string":
            w = literal(wanted)
            return given.casefold() == w.casefold() if ignorecase else given == w
        if kind == "like":
            return glob_match(wanted, given)
        if kind == "arn":
            return arn_match(wanted, given, expand=False)
        if kind.startswith("num_"):
            a, b = _number(given), _number(wanted)
        elif kind.startswith("date_"):
            a, b = _date(given), _date(wanted)
        elif kind == "bool":
            return given.strip().lower() == wanted.strip().lower()
        elif kind == "binary":
            return _binary(given) == _binary(wanted)
        elif kind == "ip":
            net = ipaddress.ip_network(wanted.strip(), strict=False)
            addr = ipaddress.ip_address(given.strip().split("/")[0])
            return addr.version == net.version and addr in net
        else:
            return False
    except (ValueError, TypeError, OverflowError, OSError):
        # OSError: on Windows, datetime.fromtimestamp raises it for a negative epoch time
        return False   # a value of the wrong type never matches
    op = kind.split("_", 1)[1]
    return {"eq": a == b, "lt": a < b, "le": a <= b, "gt": a > b, "ge": a >= b}[op]


@dataclass
class ConditionResult:
    operator: str
    key: str
    values: list
    result: object             # True, False, or None when it depends on a missing key
    if_unset: object           # the result if missing keys aren't set (None: always set)
    missing: bool = False      # the key wasn't given
    given: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)   # keys, as written in the policy
    error: str = ""


def _absent_result(kind, negated, ifexists, setop, values) -> bool:
    """What a condition is when its key isn't in the request at all."""
    if kind == "null":
        return any(v.strip().lower() == "true" for v in values)
    if ifexists:
        return True
    if setop == "all":
        return True
    if setop == "any":
        return False
    return negated


def evaluate_condition(operator, key, values, context, version=VERSION) -> ConditionResult:
    """One operator, one key, its list of values, against a context from make_context."""
    op = str(operator)
    key = str(key)
    values = [text_value(v) for v in iampolicy.as_list(values)]
    out = ConditionResult(op, key, values, False, False)
    setop, base, ifexists = split_operator(op)
    spec = OPERATORS.get(base)
    if spec is None or not known_operator(op):
        out.error = f"unknown condition operator {op}"
        return out
    kind, negated, ignorecase = spec
    k = key.lower()
    given = context.get(k)

    if given is None or given is ABSENT or given == []:
        out.missing = True
        absent = _absent_result(kind, negated, ifexists, setop, values)
        if given is ABSENT or given == []:
            out.result = out.if_unset = absent
        else:
            out.result = None
            out.if_unset = None if k in ALWAYS_PRESENT else absent
            out.depends_on = [key]
        return out
    out.given = list(given)

    if kind == "null":   # the key is there
        out.result = out.if_unset = any(v.strip().lower() == "false" for v in values)
        return out

    wanted = []
    for v in values:
        wanted.append(substitute(v, context, version) if kind in VARIABLE_KINDS else v)
    var_keys = [w.key for w in wanted if isinstance(w, Unresolved) and not w.known_absent]

    def run(unresolved_as):
        def one(g):   # does one context value match any policy value
            outs = []
            for w in wanted:
                if isinstance(w, Unresolved):
                    outs.append(False if w.known_absent else unresolved_as(w.key))
                else:
                    outs.append(_compare(kind, g, w, ignorecase))
            return any_of(outs)

        def single(g):
            hit = one(g)
            return negate(hit) if negated else hit
        if setop == "all":
            return all_of(single(g) for g in given)
        if setop == "any":
            return any_of(single(g) for g in given)
        hit = any_of(one(g) for g in given)
        return negate(hit) if negated else hit

    out.result = run(lambda _k: None)
    out.if_unset = run(lambda vk: None if vk.lower() in ALWAYS_PRESENT else False)
    if out.result is None:
        out.depends_on = sorted(set(var_keys))
    return out


# =================================================================== statements

@dataclass
class StatementResult:
    index: int
    sid: str
    effect: str                # "Allow" or "Deny"
    result: object             # True, False or None
    if_unset: object
    action_match: bool = False
    resource_match: object = False
    principal_match: object = True
    conditions: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)
    error: str = ""
    statement: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"statement {self.index + 1}" + (f" ({self.sid})" if self.sid else "")

    @property
    def why_not(self) -> str:
        """Why a statement that doesn't apply doesn't, in a few words."""
        if self.error:
            return self.error
        if not self.action_match:
            return "it doesn't cover this action"
        if self.resource_match is False:
            return "it doesn't cover this resource"
        if self.principal_match is False:
            return "it doesn't cover this caller"
        failed = [c for c in self.conditions if c.result is False]
        if failed:
            return "its conditions don't match"
        return ""


def _resource_match(stmt, req, version):
    """(result, if_unset, depends_on) for the Resource or NotResource element."""
    if "Resource" in stmt:
        patterns, negated = iampolicy.as_list(stmt.get("Resource")), False
    elif "NotResource" in stmt:
        patterns, negated = iampolicy.as_list(stmt.get("NotResource")), True
    else:
        return True, True, []        # SCPs and trust policies can leave it out
    outs, unset_outs, deps = [], [], []
    for p in patterns:
        p = substitute(str(p).strip(), req.context, version)
        if isinstance(p, Unresolved):
            if p.known_absent:
                outs.append(False)
                unset_outs.append(False)
            else:
                outs.append(None)
                unset_outs.append(None if p.key.lower() in ALWAYS_PRESENT else False)
                deps.append(p.key)
            continue
        if not p.strip("*"):
            outs.append(True)
            unset_outs.append(True)
        elif not req.resource_known:
            outs.append(None)
            unset_outs.append(None)
            deps.append(RESOURCE)
        elif has_wildcard(req.resource):
            # The request names a pattern, not one resource: it's only a match when the
            # statement covers all of it, and only a miss when it covers none of it.
            hit = arn_match_pattern(p, req.resource)
            outs.append(hit)
            unset_outs.append(hit)
            if hit is None:
                deps.append(RESOURCE)
        else:
            hit = arn_match(p, req.resource)
            outs.append(hit)
            unset_outs.append(hit)
    hit, unset = any_of(outs), any_of(unset_outs)
    if negated:
        hit, unset = negate(hit), negate(unset)
    return hit, unset, (deps if hit is None else [])


def _principal_match(stmt, req):
    """(result, depends_on) for Principal or NotPrincipal. RCPs always use "*"."""
    if "Principal" in stmt:
        value, negated = stmt.get("Principal"), False
    elif "NotPrincipal" in stmt:
        value, negated = stmt.get("NotPrincipal"), True
    else:
        return True, []
    parts = iampolicy.principal_parts(value)
    if "*" in parts.get("AWS", []):
        return (not negated), []
    arn = (req.context.get("aws:principalarn") or [""])
    account = (req.context.get("aws:principalaccount") or [""])
    arn = arn[0] if isinstance(arn, list) and arn else ""
    account = account[0] if isinstance(account, list) and account else ""
    service = req.context.get("aws:principalservicename")
    service = service[0] if isinstance(service, list) and service else ""
    outs = []
    for p in parts.get("AWS", []):
        if re.fullmatch(r"\d{12}", p) or p.endswith(":root"):
            acct = p if p.isdigit() else iampolicy.account_of(p)
            outs.append(acct == account if account else None)
        else:
            outs.append(p == arn if arn else None)
    for p in parts.get("Service", []):
        outs.append(p == service if service else (False if arn else None))
    for kind in ("Federated", "CanonicalUser"):
        for p in parts.get(kind, []):
            outs.append(p == arn if arn else None)
    hit = any_of(outs)
    if negated:
        hit = negate(hit)
    return hit, (["aws:PrincipalArn"] if hit is None else [])


def evaluate_statement(stmt, req: Request, index=0, version=VERSION) -> StatementResult:
    sid = str(stmt.get("Sid", "") or "") if isinstance(stmt, dict) else ""
    effect = str(stmt.get("Effect", "")).strip().capitalize() if isinstance(stmt, dict) else ""
    out = StatementResult(index, sid, effect, False, False,
                          statement=stmt if isinstance(stmt, dict) else {})
    if not isinstance(stmt, dict):
        out.error = "a statement has to be a JSON object"
        return out
    if effect not in ("Allow", "Deny"):
        out.error = f"Effect has to be Allow or Deny, not {stmt.get('Effect')!r}"
        return out
    if "Action" in stmt:
        out.action_match = any(action_matches(p, req.action)
                               for p in iampolicy.as_list(stmt.get("Action")))
    elif "NotAction" in stmt:
        out.action_match = not any(action_matches(p, req.action)
                                   for p in iampolicy.as_list(stmt.get("NotAction")))
    else:
        out.error = "it has no Action or NotAction"
        return out
    res, res_unset, res_deps = _resource_match(stmt, req, version)
    out.resource_match = res
    out.principal_match, pr_deps = _principal_match(stmt, req)
    cond = stmt.get("Condition") or {}
    if not isinstance(cond, dict):
        out.error = "Condition has to be a JSON object"
        return out
    for op, block in cond.items():
        if not isinstance(block, dict):
            out.error = f"the {op} condition has to be a JSON object of keys and values"
            return out
        for key, values in block.items():
            out.conditions.append(evaluate_condition(op, key, values, req.context, version))
    bad = [c.error for c in out.conditions if c.error]
    if bad:
        out.error = bad[0]
        return out
    out.result = all_of([out.action_match, res, out.principal_match] +
                        [c.result for c in out.conditions])
    out.if_unset = all_of([out.action_match, res_unset, out.principal_match] +
                          [c.if_unset for c in out.conditions])
    if out.result is None:
        deps = list(res_deps) + list(pr_deps)
        for c in out.conditions:
            if c.result is None:
                deps += c.depends_on
        out.depends_on = _unique(deps)
    return out


def evaluate_policy(doc, req: Request) -> list:
    """Every statement of a policy against one request."""
    version = str(doc.get("Version", "")) if isinstance(doc, dict) else ""
    return [evaluate_statement(s, req, i, version)
            for i, s in enumerate(iampolicy.statements(doc) if isinstance(doc, dict) else [])]


def _unique(items) -> list:
    seen, out = set(), []
    for i in items:
        k = str(i).lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


# =================================================================== checking a policy

def problems(doc, kind="scp") -> list:
    """Things that would make AWS reject the policy, in plain words. kind is "scp" or
    "rcp". An empty list means it looks fine."""
    out = []
    if not isinstance(doc, dict):
        return ["A policy has to be a JSON object with a Statement list."]
    raw = doc.get("Statement")
    if raw is None:
        return ["There's no Statement."]
    sts = iampolicy.as_list(raw) if not isinstance(raw, dict) else [raw]
    if not sts:
        out.append("The Statement list is empty.")
    for i, stmt in enumerate(sts):
        where = f"Statement {i + 1}"
        if not isinstance(stmt, dict):
            out.append(f"{where} isn't a JSON object.")
            continue
        if stmt.get("Sid"):
            where += f" ({stmt['Sid']})"
        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            out.append(f"{where}: Effect has to be \"Allow\" or \"Deny\".")
        if kind == "rcp" and effect == "Allow":
            out.append(f"{where}: resource control policies can only deny.")
        if ("Action" in stmt) == ("NotAction" in stmt):
            out.append(f"{where}: give Action or NotAction (one of them).")
        for a in iampolicy.as_list(stmt.get("Action")) + iampolicy.as_list(stmt.get("NotAction")):
            a = str(a)
            if a != "*" and not re.fullmatch(r"[A-Za-z0-9-]+:[A-Za-z0-9*?]+", a):
                out.append(f"{where}: {a!r} isn't an action. Write it like s3:GetObject.")
        if "Resource" in stmt and "NotResource" in stmt:
            out.append(f"{where}: use Resource or NotResource, not both.")
        if kind == "scp" and ("Principal" in stmt or "NotPrincipal" in stmt):
            out.append(f"{where}: SCPs can't name a Principal. They apply to every principal "
                       "in the accounts they're attached to.")
        if kind == "rcp" and stmt.get("Principal") not in ("*", {"AWS": "*"}):
            out.append(f"{where}: in a resource control policy, Principal has to be \"*\".")
        cond = stmt.get("Condition")
        if cond is not None:
            if not isinstance(cond, dict):
                out.append(f"{where}: Condition has to be a JSON object.")
            else:
                for op, block in cond.items():
                    if not known_operator(op):
                        out.append(f"{where}: {op} isn't a condition operator AWS knows.")
                    if not isinstance(block, dict):
                        out.append(f"{where}: the {op} condition has to map keys to values.")
    return out


# =================================================================== plain words

KEY_SUBJECTS = {
    "aws:requestedregion": "the region",
    "aws:principalarn": "the caller",
    "aws:principalaccount": "the caller's account",
    "aws:principalorgid": "the caller's organization",
    "aws:principalorgpaths": "the caller's place in the organization",
    "aws:principaltype": "the caller type",
    "aws:principalservicename": "the calling service",
    "aws:principalisawsservice": "the caller is an AWS service",
    "aws:userid": "the caller's user ID",
    "aws:username": "the user name",
    "aws:sourceip": "the source IP",
    "aws:sourcevpc": "the VPC",
    "aws:sourcevpce": "the VPC endpoint",
    "aws:sourcearn": "the source ARN",
    "aws:sourceaccount": "the source account",
    "aws:sourceorgid": "the source organization",
    "aws:resourceaccount": "the resource's account",
    "aws:resourceorgid": "the resource's organization",
    "aws:resourceorgpaths": "the resource's place in the organization",
    "aws:currenttime": "the time",
    "aws:epochtime": "the time",
    "aws:tagkeys": "the tag keys in the request",
    "aws:calledvia": "the services the call came through",
    "aws:calledviafirst": "the first service the call came through",
    "aws:calledvialast": "the last service the call came through",
    "aws:federatedprovider": "the identity provider",
    "aws:multifactorauthage": "the seconds since the caller's MFA sign-in",
    "aws:tokenissuetime": "the time the credentials were issued",
    "ec2:instancetype": "the instance type",
}
BOOL_PHRASES = {
    "aws:securetransport": ("the request uses HTTPS", "the request doesn't use HTTPS"),
    "aws:multifactorauthpresent": ("the caller signed in with MFA",
                                   "the caller didn't sign in with MFA"),
    "aws:viaawsservice": ("an AWS service makes the call for the caller",
                          "the caller makes the call directly"),
    "aws:principalisawsservice": ("the caller is an AWS service",
                                  "the caller isn't an AWS service"),
}
PRINCIPAL_KEYS = {"aws:principalarn", "aws:sourcearn"}


def join_words(items, word="and", limit=6) -> str:
    """'a', 'a and b', 'a, b and c', or 'a, b, c, d, e and 3 more'."""
    items = [str(i) for i in items if str(i)]
    if not items:
        return ""
    if len(items) > limit:
        shown = items[:limit - 1]
        return ", ".join(shown) + f" {word} {len(items) - len(shown)} more"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" {word} " + items[-1]


def subject(key: str) -> str:
    k = key.lower()
    if k in KEY_SUBJECTS:
        return KEY_SUBJECTS[k]
    for prefix, text in (("aws:principaltag/", "the caller's tag "),
                         ("aws:resourcetag/", "the resource's tag "),
                         ("aws:requesttag/", "the tag in the request, ")):
        if k.startswith(prefix):
            return text + key[len(prefix):]
    return key


def principal_label(value: str) -> str:
    """arn:aws:iam::*:role/OrganizationAccountAccessRole -> OrganizationAccountAccessRole."""
    v = str(value)
    m = re.fullmatch(r"arn:aws[\w-]*:iam::([^:]*):role/(?:.*/)?([^/]+)", v)
    if m:
        return m.group(2) if m.group(1) in ("*", "") else f"{m.group(2)} in {m.group(1)}"
    m = re.fullmatch(r"arn:aws[\w-]*:sts::([^:]*):assumed-role/([^/]+)/.*", v)
    if m:
        return m.group(2) if m.group(1) in ("*", "") else f"{m.group(2)} in {m.group(1)}"
    m = re.fullmatch(r"arn:aws[\w-]*:iam::([^:]*):user/(?:.*/)?([^/]+)", v)
    if m:
        return f"user {m.group(2)}" if m.group(1) in ("*", "") else \
            f"user {m.group(2)} in {m.group(1)}"
    m = re.fullmatch(r"arn:aws[\w-]*:iam::([^:]*):root", v)
    if m:
        return "the root user" if m.group(1) in ("*", "") else f"the root user of {m.group(1)}"
    return v


def _values_text(key, values) -> str:
    vals = [principal_label(v) if key.lower() in PRINCIPAL_KEYS else literal(str(v))
            for v in values]
    return join_words(vals, "or", limit=5)


def condition_phrase(operator, key, values) -> tuple:
    """(phrase, negated, ifexists) for one condition, with the phrase in its positive
    form: StringNotEquals on aws:RequestedRegion gives ("the region is us-east-1", True,
    False). Null and Bool come out ready to use, with negated False."""
    setop, base, ifexists = split_operator(operator)
    spec = OPERATORS.get(base)
    values = [text_value(v) for v in iampolicy.as_list(values)]
    k = key.lower()
    if spec is None:
        return f"{operator} on {key} matches {join_words(values, 'or')}", False, ifexists
    kind, negated, _ = spec
    subj = subject(key)
    if setop == "all":
        subj = f"each of {subj}"
    elif setop == "any":
        subj = f"one of {subj}"
    vals = _values_text(key, values)
    if kind == "null":
        on = any(v.lower() == "true" for v in values)
        off = any(v.lower() == "false" for v in values)
        if on and off:
            return f"{subj} is set or not", False, False
        return (f"{subj} isn't set" if on else f"{subj} is set"), False, False
    if kind == "bool":
        true_text, false_text = BOOL_PHRASES.get(k, (f"{key} is true", f"{key} is false"))
        want = values[0].lower() if values else "true"
        return (true_text if want == "true" else false_text), False, ifexists
    if kind in ("string", "arn"):
        text = f"{subj} is {vals}"
    elif kind == "like":
        verb = "is" if k in PRINCIPAL_KEYS else "matches"
        text = f"{subj} {verb} {vals}"
    elif kind == "ip":
        text = f"{subj} is in {vals}"
    elif kind == "binary":
        text = f"{subj} is the given binary value"
    else:
        op = kind.split("_", 1)[1]
        date = kind.startswith("date_")
        words = {"eq": "is {}", "lt": "is before {}" if date else "is under {}",
                 "le": "is {} or earlier" if date else "is {} or less",
                 "gt": "is after {}" if date else "is over {}",
                 "ge": "is {} or later" if date else "is {} or more"}
        text = f"{subj} " + words[op].format(vals)
    return text, negated, ifexists


def _negative(text: str) -> str:
    """'the region is x' -> 'the region isn't x'."""
    for a, b in ((" is in ", " isn't in "), (" matches ", " doesn't match "), (" is ", " isn't ")):
        if a in text:
            return text.replace(a, b, 1)
    return "not: " + text


def condition_clauses(stmt) -> tuple:
    """(when, unless) phrases for a statement's conditions. A statement applies when every
    "when" phrase is true and no "unless" phrase is."""
    when, unless = [], []
    for op, key, values in _entries(stmt):
        text, negated, ifexists = condition_phrase(op, key, values)
        if negated:
            unless.append(text)
        else:
            when.append(text + (" (or that isn't known)" if ifexists else ""))
    return when, unless


def _entries(stmt) -> list:
    out = []
    cond = stmt.get("Condition") if isinstance(stmt, dict) else None
    if isinstance(cond, dict):
        for op, block in cond.items():
            if isinstance(block, dict):
                for key, values in block.items():
                    out.append((str(op), str(key), iampolicy.as_list(values)))
    return out


def actions_text(stmt, limit=6) -> str:
    if "NotAction" in stmt:
        acts = [str(a) for a in iampolicy.as_list(stmt.get("NotAction"))]
        return "everything except " + join_words(acts, "and", limit=max(limit, 8))
    acts = [str(a) for a in iampolicy.as_list(stmt.get("Action"))]
    if any(a.strip() in ("*", "*:*") for a in acts):
        return "everything"
    return join_words(acts, "and", limit=limit) or "nothing"


def resources_text(stmt) -> str:
    if "NotResource" in stmt:
        return " on anything except " + join_words(
            [str(r) for r in iampolicy.as_list(stmt.get("NotResource"))], "and", 4)
    res = [str(r) for r in iampolicy.as_list(stmt.get("Resource"))]
    if not res or any(not r.strip("*") for r in res):
        return ""
    return " on " + join_words(res, "and", 4)


def principals_text(stmt) -> str:
    if "NotPrincipal" in stmt:
        parts = iampolicy.principal_parts(stmt.get("NotPrincipal"))
        names = [principal_label(p) for vals in parts.values() for p in vals]
        return " for everyone except " + join_words(names, "and", 4)
    if "Principal" in stmt:
        parts = iampolicy.principal_parts(stmt.get("Principal"))
        if "*" in parts.get("AWS", []):
            return ""
        names = [principal_label(p) for vals in parts.values() for p in vals]
        return " for " + join_words(names, "and", 4)
    return ""


def describe_statement(stmt, limit=6) -> str:
    """A statement in plain words, starting with a verb: 'denies
    organizations:LeaveOrganization for everyone', 'denies everything except iam:* and
    sts:* unless the region is us-east-1 or us-west-2', 'allows everything'."""
    if not isinstance(stmt, dict):
        return "isn't a valid statement"
    effect = str(stmt.get("Effect", "")).strip().capitalize()
    deny = effect == "Deny"
    text = ("denies " if deny else "allows ") + actions_text(stmt, limit) + resources_text(stmt)
    who = principals_text(stmt)
    text += who
    when, unless = condition_clauses(stmt)
    if deny:
        if not when and not unless and not who:
            text += " for everyone"
        if when:
            text += " when " + " and ".join(when)
        if unless:
            text += (", unless " if when else " unless ") + ", or ".join(unless)
    else:
        parts = when + [_negative(u) for u in unless]
        if parts:
            text += " only when " + " and ".join(parts)
    return text


def describe_policy(doc, effect=None) -> list:
    """describe_statement for each statement, optionally only Allow or Deny ones."""
    out = []
    for stmt in iampolicy.statements(doc) if isinstance(doc, dict) else []:
        if effect and str(stmt.get("Effect", "")).capitalize() != effect:
            continue
        out.append(describe_statement(stmt))
    return out


def given_text(stmt, context) -> str:
    """What the request had for the keys a statement's conditions check, like 'the
    region is eu-west-1 and the caller is dev-admin'. Empty when none were given."""
    parts, seen = [], set()
    for _op, key, _values in _entries(stmt):
        k = key.lower()
        if k in seen:
            continue
        seen.add(k)
        got = context.get(k)
        if not isinstance(got, list) or not got:
            continue
        if k in BOOL_PHRASES:
            true_text, false_text = BOOL_PHRASES[k]
            parts.append(true_text if got[0].lower() == "true" else false_text)
            continue
        vals = [principal_label(v) if k in PRINCIPAL_KEYS else v for v in got]
        parts.append(f"{subject(key)} is {join_words(vals, 'and', 4)}")
    return join_words(parts, "and", 4)


def unconditional_allow_all(stmt) -> bool:
    """True for a statement like FullAWSAccess: Allow every action on every resource, with
    no conditions."""
    if not isinstance(stmt, dict) or str(stmt.get("Effect", "")).capitalize() != "Allow":
        return False
    if "Action" not in stmt or stmt.get("Condition") or "NotResource" in stmt:
        return False
    if "NotPrincipal" in stmt:
        return False
    if "Principal" in stmt and "*" not in iampolicy.principal_parts(
            stmt.get("Principal")).get("AWS", []):
        return False
    acts = [str(a).strip() for a in iampolicy.as_list(stmt.get("Action"))]
    res = [str(r).strip() for r in iampolicy.as_list(stmt.get("Resource", "*"))]
    return any(a in ("*", "*:*") for a in acts) and any(not r.strip("*") for r in res)
