"""Policy Check: reads an IAM policy and flags what's risky about it.

Works offline. Optionally also asks IAM Access Analyzer's ValidatePolicy (free) for
AWS's own findings.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from urllib.parse import unquote

from .common import SEVERITY_ORDER, error_text


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    where: str = ""
    fix: str = ""
    source: str = "awskit"
    link: str = ""

    def as_dict(self):
        return asdict(self)


KINDS = ("identity", "resource", "trust", "scp")
KIND_NAMES = {"identity": "Identity policy", "resource": "Resource policy",
              "trust": "Role trust policy", "scp": "Service control policy"}

# ------------------------------------------------------------------ catalogs

PRIV_ESC = {
    "iam:CreatePolicyVersion": "can write a new version of a policy and make it the default",
    "iam:SetDefaultPolicyVersion": "can switch a policy back to an older, broader version",
    "iam:CreateAccessKey": "can create access keys for other users",
    "iam:CreateLoginProfile": "can give other users a console password",
    "iam:UpdateLoginProfile": "can change other users' console passwords",
    "iam:AttachUserPolicy": "can attach any managed policy, AdministratorAccess included",
    "iam:AttachGroupPolicy": "can attach any managed policy to a group",
    "iam:AttachRolePolicy": "can attach any managed policy to a role",
    "iam:PutUserPolicy": "can write inline policies with any permissions",
    "iam:PutGroupPolicy": "can write inline group policies with any permissions",
    "iam:PutRolePolicy": "can write inline role policies with any permissions",
    "iam:AddUserToGroup": "can join groups that have more permissions",
    "iam:UpdateAssumeRolePolicy": "can change who is allowed to assume a role",
    "iam:DeleteUserPermissionsBoundary": "can remove a user's permissions boundary",
    "iam:DeleteRolePermissionsBoundary": "can remove a role's permissions boundary",
    "iam:PutUserPermissionsBoundary": "can swap a user's boundary for a looser one",
    "iam:PutRolePermissionsBoundary": "can swap a role's boundary for a looser one",
    "lambda:UpdateFunctionCode": "can replace the code of functions that run with their own role",
    "ssm:SendCommand": "can run commands on instances and use their roles",
    "ssm:StartSession": "can open a shell on instances and use their roles",
    "ec2-instance-connect:SendSSHPublicKey": "can push an SSH key and log in to instances",
    "glue:UpdateDevEndpoint": "can add an SSH key to a Glue endpoint that has a role",
}

# Actions that become a path to admin when paired with iam:PassRole on a broad resource.
PASSROLE_PAIRS = {
    "ec2:RunInstances": "launch an instance with any role",
    "lambda:CreateFunction": "create a function that runs as any role",
    "cloudformation:CreateStack": "create a stack that runs as any role",
    "glue:CreateDevEndpoint": "create a Glue endpoint with any role",
    "glue:CreateJob": "create a Glue job with any role",
    "ecs:RunTask": "run a task with any role",
    "ecs:RegisterTaskDefinition": "register a task that runs as any role",
    "sagemaker:CreateNotebookInstance": "create a notebook with any role",
    "codebuild:CreateProject": "create a build project with any role",
    "datapipeline:CreatePipeline": "create a pipeline with any role",
    "states:CreateStateMachine": "create a state machine with any role",
    "ec2:AssociateIamInstanceProfile": "attach any role to a running instance",
    "ec2:ReplaceIamInstanceProfileAssociation": "swap the role on a running instance",
    "lambda:UpdateFunctionConfiguration": "switch a function to run as any role",
}

DEFENSE_EVASION = {
    "cloudtrail:StopLogging": "turn off CloudTrail",
    "cloudtrail:DeleteTrail": "delete a CloudTrail trail",
    "cloudtrail:UpdateTrail": "point a trail somewhere else",
    "cloudtrail:PutEventSelectors": "change what a trail records",
    "guardduty:DeleteDetector": "turn off GuardDuty",
    "guardduty:UpdateDetector": "suspend GuardDuty",
    "guardduty:CreateIPSet": "add trusted IPs that GuardDuty ignores",
    "config:StopConfigurationRecorder": "stop AWS Config recording",
    "config:DeleteConfigurationRecorder": "delete the AWS Config recorder",
    "config:DeleteDeliveryChannel": "stop AWS Config from saving history",
    "securityhub:DisableSecurityHub": "turn off Security Hub",
    "access-analyzer:DeleteAnalyzer": "delete IAM Access Analyzer",
    "ec2:DeleteFlowLogs": "delete VPC flow logs",
    "logs:DeleteLogGroup": "delete CloudWatch log groups",
    "organizations:LeaveOrganization": "leave the organization and its SCPs",
}

DATA_READ = {
    "s3:GetObject": "read objects in every bucket",
    "kms:Decrypt": "decrypt with every KMS key",
    "secretsmanager:GetSecretValue": "read every secret",
    "ssm:GetParameter": "read every SSM parameter",
    "ssm:GetParameters": "read every SSM parameter",
    "ssm:GetParametersByPath": "read every SSM parameter",
    "dynamodb:Scan": "read every DynamoDB table",
    "dynamodb:GetItem": "read every DynamoDB table",
    "ec2:GetPasswordData": "read Windows admin passwords",
}

DESTRUCTIVE = {
    "s3:DeleteBucket": "delete any bucket",
    "s3:DeleteObject": "delete objects in any bucket",
    "s3:PutBucketPolicy": "rewrite any bucket policy",
    "kms:ScheduleKeyDeletion": "schedule any KMS key for deletion",
    "kms:PutKeyPolicy": "rewrite any key policy",
    "ec2:TerminateInstances": "terminate any instance",
    "rds:DeleteDBInstance": "delete any database",
    "rds:DeleteDBCluster": "delete any Aurora cluster",
    "dynamodb:DeleteTable": "delete any table",
    "iam:DeleteRole": "delete any role",
    "iam:DeleteUser": "delete any user",
}

SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations", "cloudtrail", "guardduty",
                      "config", "securityhub", "secretsmanager", "ssm", "lambda", "ec2",
                      "s3", "account", "sso", "identitystore"}

# Condition keys that genuinely narrow who a public principal can be.
LIMITING_KEYS = {
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid",
    "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn", "aws:sourcevpce",
    "aws:sourcevpc", "aws:sourceip", "aws:sourceorgid", "aws:sourceorgpaths",
    "aws:userid", "aws:username", "aws:resourceorgid", "s3:dataaccesspointaccount",
    "kms:calleraccount", "kms:viaservice", "sts:externalid", "aws:principalservicename",
    "lambda:functionurlauthtype", "sns:endpoint", "elasticfilesystem:accesspointarn",
}

# Condition operators that only let in requests whose value matches. Not* operators let in
# everyone else, Null only checks whether the key is there, and ...IfExists and
# ForAllValues: also pass when the key is missing, which it is for anonymous callers.
POSITIVE_OPERATORS = {"stringequals", "stringequalsignorecase", "stringlike", "arnequals",
                      "arnlike", "ipaddress"}
WILDCARD_OPERATORS = {"stringlike", "arnequals", "arnlike"}  # these treat * and ? as wildcards

# Services whose ARNs end in the resource's name, with no resource type in front.
NAME_ONLY_SERVICES = {"s3", "sqs", "sns", "codecommit"}

GITHUB_SUB = "token.actions.githubusercontent.com:sub"

MAX_POLICY_TEXT = 1024 * 1024  # IAM policies are a few KB at most
MAX_POLICY_DEPTH = 32          # a real policy is about 6 levels deep
TOO_DEEP = "That's nested too deeply to be a policy."


# ------------------------------------------------------------------ loading

class PolicyError(ValueError):
    pass


def _unwrap(obj):
    """Accept full CLI/boto3 output, not just the bare document."""
    if not isinstance(obj, dict):
        return obj, ""
    for path, note in (
        (("PolicyVersion", "Document"), "get-policy-version output"),
        (("Role", "AssumeRolePolicyDocument"), "get-role output, trust policy"),
        (("PolicyDocument",), "inline policy output"),
        (("Policy",), "resource policy output"),
        (("AssumeRolePolicyDocument",), "trust policy"),
        (("Document",), "policy version"),
    ):
        cur = obj
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                cur = None
                break
        if cur is not None and "Statement" not in obj:
            if isinstance(cur, str):
                try:
                    cur = json.loads(unquote(cur) if cur.lstrip().startswith("%") else cur)
                except (ValueError, RecursionError):
                    continue
            if isinstance(cur, dict):
                return cur, f"Read the policy out of {note}."
    return obj, ""


def _too_deep(obj, limit=MAX_POLICY_DEPTH) -> bool:
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(cur, dict):
            stack += [(v, depth + 1) for v in cur.values()]
        elif isinstance(cur, (list, tuple)):
            stack += [(v, depth + 1) for v in cur]
    return False


def load_policy(text: str) -> tuple:
    """Parse JSON, URL-encoded JSON, or a printed boto3 dict. Returns (doc, note)."""
    raw = (text or "").strip()
    if not raw:
        raise PolicyError("Paste a policy first.")
    if len(raw) > MAX_POLICY_TEXT:
        raise PolicyError("That's over 1 MB. IAM policies are a few KB at most, so this "
                          "isn't one.")
    if raw.startswith("%7B") or raw.startswith("%7b"):
        raw = unquote(raw)
    doc = None
    try:
        doc = json.loads(raw)
    except RecursionError:
        raise PolicyError(TOO_DEEP) from None
    except ValueError as json_err:
        try:
            doc = ast.literal_eval(raw)
        except RecursionError:
            raise PolicyError(TOO_DEEP) from None
        except (ValueError, TypeError, SyntaxError, MemoryError):
            # TypeError: a printed dict with a list as a key, like {[1]: 2}
            line = getattr(json_err, "lineno", None)
            where = f" (line {line})" if line else ""
            msg = getattr(json_err, "msg", str(json_err))
            raise PolicyError(f"That isn't valid JSON{where}: {msg}") from None
    if isinstance(doc, str):  # JSON string holding JSON
        try:
            doc = json.loads(doc)
        except RecursionError:
            raise PolicyError(TOO_DEEP) from None
        except ValueError:
            raise PolicyError("That's a plain string, not a policy.") from None
    doc, note = _unwrap(doc)
    if not isinstance(doc, dict):
        raise PolicyError("A policy should be a JSON object with a Statement list.")
    if "Statement" not in doc:
        raise PolicyError("No Statement found. Is this the whole policy?")
    if _too_deep(doc):
        raise PolicyError(TOO_DEEP)
    return doc, note


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def statements(doc) -> list:
    st = doc.get("Statement")
    if isinstance(st, dict):
        return [st]
    return [s for s in as_list(st) if isinstance(s, dict)]


def detect_kind(doc) -> str:
    sts = statements(doc)
    has_principal = any("Principal" in s or "NotPrincipal" in s for s in sts)
    if not has_principal:
        return "identity"
    actions = [a.lower() for s in sts for a in as_list(s.get("Action"))]
    has_resource = any("Resource" in s or "NotResource" in s for s in sts)
    if actions and all(a.startswith("sts:assumerole") or a.startswith("sts:tagsession")
                       or a.startswith("sts:setsourceidentity") or a.startswith("sts:setcontext")
                       for a in actions) and not has_resource:
        return "trust"
    return "resource"


# ------------------------------------------------------------------ matching

def grants(patterns, action: str) -> bool:
    action = action.lower()
    return any(fnmatchcase(action, str(p).lower()) for p in patterns)


def matched(patterns, catalog: dict) -> dict:
    return {a: why for a, why in catalog.items() if grants(patterns, a)}


def listing(hits: dict, limit=5) -> str:
    """'a (why); b (why)', cut short with 'and N more' so long lists stay readable."""
    items = sorted(hits.items())
    text = "; ".join(f"{a} ({why})" for a, why in items[:limit])
    if len(items) > limit:
        text += f"; and {len(items) - limit} more: " + ", ".join(a for a, _ in items[limit:])
    return text


def has_wildcard(text) -> bool:
    return "*" in text or "?" in text


def is_broad_resource(resources) -> bool:
    for r in resources:
        r = str(r).strip()
        if r and not r.strip("*?"):
            return True                                  # "*"
        parts = r.split(":", 5)
        if parts[0] != "arn":
            continue
        if len(parts) < 6:
            if has_wildcard(parts[-1]):
                return True                              # arn:*, arn:aws:*, arn:aws:ec2:*:*
            continue
        _, partition, service, _region, account, res = parts
        # Any partition, service or account. The region doesn't matter much.
        if has_wildcard(partition) or has_wildcard(service) or has_wildcard(account):
            return True
        if res and not res.strip("*?"):
            return True                                  # arn:aws:iam::111111111111:*
        if service == "s3":
            # A wildcard first is any bucket, in any account. arn:aws:s3:::bucket/* is just
            # one bucket's objects.
            if res[:1] in ("*", "?"):
                return True
            continue
        if service in NAME_ONLY_SERVICES:
            continue
        # Every resource of one type, like user/*, function:*, or role* with no slash.
        if re.fullmatch(r"[\w-]+[/:]\*", res) or re.fullmatch(r"[a-z][a-z-]*\*", res):
            return True
    return False


def condition_keys(stmt) -> set:
    keys = set()
    cond = stmt.get("Condition") or {}
    if isinstance(cond, dict):
        for block in cond.values():
            if isinstance(block, dict):
                keys.update(k.lower() for k in block)
    return keys


def condition_values(stmt, key: str) -> list:
    out = []
    cond = stmt.get("Condition") or {}
    if isinstance(cond, dict):
        for block in cond.values():
            if isinstance(block, dict):
                for k, v in block.items():
                    if k.lower() == key.lower():
                        out += [str(x) for x in as_list(v)]
    return out


def condition_entries(stmt) -> list:
    """[(operator, key, values)] for every condition in a statement, as written."""
    out = []
    cond = stmt.get("Condition") or {}
    if isinstance(cond, dict):
        for op, block in cond.items():
            if isinstance(block, dict):
                for key, values in block.items():
                    out.append((str(op), str(key), [str(v) for v in as_list(values)]))
    return out


def wide_value(base_op, value) -> bool:
    """True when a condition value lets about anyone through: a bare wildcard, an ARN with a
    wildcard for the partition, service or account, or a public IP range of /8 or wider
    (/16 for IPv6), 0.0.0.0/0 and ::/0 included."""
    v = str(value).strip()
    if base_op == "ipaddress":
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return False
        return net.prefixlen <= (8 if net.version == 4 else 16) and not net.is_private
    if base_op not in WILDCARD_OPERATORS:
        return False  # StringEquals takes * as a plain character
    if not v.strip("*?"):
        return True
    parts = v.split(":", 5)
    if parts[0] != "arn":
        return False
    if len(parts) < 6:
        return has_wildcard(parts[-1])
    _, partition, service, _region, account, res = parts
    if has_wildcard(partition) or has_wildcard(service) or has_wildcard(account):
        return True
    if res and not res.strip("*?"):
        return True
    return service == "s3" and res[:1] in ("*", "?")  # any bucket, in any account


def weak_condition(op, key, values) -> str:
    """Why a condition doesn't narrow who gets in, or "" when it does."""
    low = op.lower()
    if low.startswith("forallvalues:") or low.endswith("ifexists"):
        return f"{op} on {key} passes when the key is missing"
    base = low.split(":", 1)[-1]  # drop ForAnyValue:
    if "not" in base:
        return f"{op} on {key} lets in everyone who doesn't match"
    if base == "null":
        return f"Null on {key} only checks whether the key is there"
    if base not in POSITIVE_OPERATORS:
        return f"{op} on {key} doesn't say who"
    if not values:
        return f"{op} on {key} has no value"
    wide = [v for v in values if wide_value(base, v)]
    if wide:
        return f"{op} on {key} allows {', '.join(wide)}"
    return ""


def limiting_conditions(stmt) -> tuple:
    """(keys that really narrow who gets in, reasons the other who-keys don't). Conditions
    all have to match, so one narrowing condition is enough."""
    strong, weak = set(), []
    for op, key, values in condition_entries(stmt):
        if key.lower() not in LIMITING_KEYS:
            continue
        why = weak_condition(op, key, values)
        if why:
            weak.append(why)
        else:
            strong.add(key.lower())
    return sorted(strong), weak


def principal_parts(principal) -> dict:
    """Normalize Principal into {'AWS': [...], 'Service': [...], ...}. '*' becomes AWS ['*']."""
    if principal == "*" or principal == ["*"]:
        return {"AWS": ["*"]}
    if isinstance(principal, dict):
        return {k: [str(x) for x in as_list(v)] for k, v in principal.items()}
    return {}


def account_of(principal: str) -> str:
    m = re.match(r"arn:aws[\w-]*:(?:iam|sts)::(\d{12}):", principal)
    if m:
        return m.group(1)
    if re.fullmatch(r"\d{12}", principal):
        return principal
    return ""


# ------------------------------------------------------------------ analysis

def stmt_label(i, stmt) -> str:
    sid = stmt.get("Sid")
    return f"Statement {i + 1}" + (f" ({sid})" if sid else "")


def analyze(doc, kind: str | None = None) -> list:
    kind = kind or detect_kind(doc)
    out = []

    version = doc.get("Version")
    if version is None:
        out.append(Finding("low", "No Version set",
                           "Without \"Version\": \"2012-10-17\", policy variables like "
                           "${aws:username} are treated as plain text.",
                           fix="Add \"Version\": \"2012-10-17\" at the top."))
    elif version == "2008-10-17":
        out.append(Finding("low", "Old policy language version",
                           "2008-10-17 doesn't support policy variables.",
                           fix="Use \"Version\": \"2012-10-17\"."))

    sts = statements(doc)
    if not sts:
        out.append(Finding("high", "No statements", "The Statement list is empty."))
        return out

    sids = [s.get("Sid") for s in sts if s.get("Sid")]
    dupes = sorted({s for s in sids if sids.count(s) > 1})
    if dupes:
        out.append(Finding("low", "Duplicate Sid", ", ".join(dupes),
                           fix="Give each statement its own Sid. IAM rejects duplicates."))

    passrole_broad_where = []
    passrole_pair_hits = {}

    for i, stmt in enumerate(sts):
        where = stmt_label(i, stmt)
        effect = str(stmt.get("Effect", "")).capitalize()
        if effect not in ("Allow", "Deny"):
            out.append(Finding("high", "Effect must be Allow or Deny",
                               f"Got {stmt.get('Effect')!r}.", where))
            continue
        if effect == "Deny":
            continue

        actions = as_list(stmt.get("Action"))
        not_actions = as_list(stmt.get("NotAction"))
        resources = as_list(stmt.get("Resource"))
        has_not_resource = "NotResource" in stmt
        conds = condition_keys(stmt)
        broad = is_broad_resource(resources) or has_not_resource or (
            kind in ("resource", "trust") and not resources)
        cond_note = " It has a Condition, so check that it narrows this." if conds else ""
        star_services = sorted({str(a).split(":")[0].lower() for a in actions
                                if re.fullmatch(r"[\w-]+:\*", str(a))})

        def not_covered(found):
            # Skip actions already explained by a "Full <service> access" finding.
            return {a: w for a, w in found.items() if a.split(":")[0].lower() not in star_services}

        if not_actions:
            out.append(Finding("high", "Allow with NotAction",
                               "This allows every action except the listed ones, including any "
                               "new actions AWS adds later." + cond_note, where,
                               "List the actions you want with Action instead."))
        if has_not_resource:
            out.append(Finding("medium", "Allow with NotResource",
                               "This applies to every resource except the listed ones." + cond_note,
                               where, "List the resources you want with Resource instead."))

        if any(str(a) in ("*", "*:*") for a in actions):
            if broad and kind in ("identity", "scp"):
                out.append(Finding("critical", "Full admin access",
                                   "Action \"*\" on Resource \"*\" can do anything in the account."
                                   + cond_note, where,
                                   "Only list the actions this role needs. If it really needs "
                                   "admin, use the AWS managed AdministratorAccess policy so "
                                   "it's obvious."))
            else:
                out.append(Finding("high", "Every action allowed",
                                   "Action \"*\" allows all actions on the listed resources."
                                   + cond_note, where, "List only the actions needed."))
        else:
            for svc in star_services:
                sev = "high" if svc in SENSITIVE_SERVICES else "medium"
                scope = "every resource" if broad else "the listed resources"
                out.append(Finding(sev, f"Full {svc} access",
                                   f"{svc}:* allows every {svc} action on {scope}." + cond_note,
                                   where, f"List the specific {svc} actions needed."))

        patterns = actions
        if not_actions:  # NotAction grants everything not listed
            patterns = [a for a in PRIV_ESC] + list(PASSROLE_PAIRS) + list(DEFENSE_EVASION)
            patterns = [a for a in patterns if not grants(not_actions, a)]

        esc = matched(patterns, PRIV_ESC)
        if esc and kind in ("identity", "scp"):
            if not any(str(a) in ("*", "*:*") for a in actions):
                detail = listing(esc)
                sev = "high" if broad else "medium"
                out.append(Finding(sev, "Privilege escalation actions",
                                   detail + ("" if broad else
                                             ". Resource is limited, which helps."),
                                   where, "Remove these or limit Resource to exact ARNs."))

        star = any(str(a) in ("*", "*:*") for a in actions)
        if grants(patterns, "iam:PassRole") and kind in ("identity", "scp") and not star:
            role_broad = is_broad_resource(resources) or has_not_resource
            if role_broad:
                passrole_broad_where.append(where)
                if "iam:passedtoservice" not in conds:
                    out.append(Finding("high", "iam:PassRole on any role",
                                       "Can hand any role, including admin roles, to a service.",
                                       where, "Limit Resource to the role ARNs needed and add "
                                       "a iam:PassedToService condition."))
                else:
                    # The condition picks the service, not the role, so any role, admin
                    # ones included, can still be handed to that service.
                    out.append(Finding("medium", "iam:PassRole on any role, for some services",
                                       "iam:PassedToService limits which services get a role, "
                                       "but any role, including admin roles, can still be "
                                       "handed to them.",
                                       where, "Limit Resource to the role ARNs needed."))
        if not star:
            for action, why in matched(patterns, PASSROLE_PAIRS).items():
                passrole_pair_hits.setdefault(action, (why, where))

        if kind in ("identity", "scp") and not any(str(a) in ("*", "*:*") for a in actions):
            evasion = matched(patterns, DEFENSE_EVASION)
            if evasion:
                out.append(Finding("high", "Can turn off security logging",
                                   listing(evasion),
                                   where, "Keep these for a break-glass role only, or deny "
                                   "them with an SCP."))
            if broad:
                reads = not_covered(matched(patterns, DATA_READ))
                if reads:
                    out.append(Finding("medium", "Reads sensitive data everywhere",
                                       listing(reads),
                                       where, "Limit Resource to the buckets, keys, secrets or "
                                       "tables needed."))
                destroys = not_covered(matched(patterns, DESTRUCTIVE))
                if destroys:
                    out.append(Finding("medium", "Destructive actions on any resource",
                                       listing(destroys),
                                       where, "Limit Resource, or add a Condition such as a "
                                       "required tag."))

        if "Principal" in stmt or "NotPrincipal" in stmt:
            out += principal_findings(stmt, where, kind, conds)

    if passrole_broad_where and passrole_pair_hits and kind in ("identity", "scp"):
        pairs = listing({a: why for a, (why, _) in passrole_pair_hits.items()})
        out.append(Finding("high", "PassRole plus a service that runs as a role",
                           "With iam:PassRole on any role, these let someone run code as a more "
                           "powerful role: " + pairs,
                           ", ".join(sorted(set(passrole_broad_where))),
                           "Limit iam:PassRole to the specific roles this service should use."))

    minified = json.dumps(doc, separators=(",", ":"))
    if kind == "identity" and len(minified) > 6144:
        out.append(Finding("low", "Over the managed policy size limit",
                           f"{len(minified):,} characters without spaces. Managed policies max out "
                           f"at 6,144.", fix="Split it into two policies or tighten wildcards."))
    if kind == "scp" and len(minified) > 5120:
        out.append(Finding("low", "Over the SCP size limit",
                           f"{len(minified):,} characters. SCPs max out at 5,120."))

    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return out


def principal_findings(stmt, where, kind, conds) -> list:
    out = []
    if "NotPrincipal" in stmt:
        out.append(Finding("high", "Allow with NotPrincipal",
                           "This grants access to everyone except the listed principals.",
                           where, "Use Principal with the exact principals instead."))
        return out
    parts = principal_parts(stmt.get("Principal"))
    actions = [str(a).lower() for a in as_list(stmt.get("Action"))]
    limiting, weak = limiting_conditions(stmt)

    if "*" in parts.get("AWS", []):
        who = "any AWS account in the world can assume this role" if kind == "trust" \
            else "anyone, including anonymous users, gets this access"
        if not conds:
            out.append(Finding("critical", "Open to everyone", f"Principal \"*\" means {who}.",
                               where, "Name the exact accounts or roles, or add a Condition "
                               "like aws:PrincipalOrgID."))
        elif limiting:
            out.append(Finding("info", "Public principal narrowed by a condition",
                               f"Principal is \"*\" but limited by {', '.join(limiting)}. Check "
                               "the values are yours.", where))
        else:
            if weak:
                detail = ("Principal is \"*\" and the Condition doesn't limit who can call it: "
                          + "; ".join(weak) + ".")
            else:
                detail = ("Principal is \"*\" and the Condition doesn't use a key that limits "
                          "who can call it (" + ", ".join(sorted(conds)) + ").")
            out.append(Finding("high", "Public principal with a weak condition", detail, where,
                               "Add StringEquals on aws:PrincipalOrgID, aws:SourceAccount or "
                               "aws:SourceArn (or ArnLike for ARNs) with your own values."))

    accounts = sorted({account_of(p) for p in parts.get("AWS", []) if account_of(p)})
    if accounts:
        msg = "Grants access to account " + ", ".join(accounts) + "."
        fix = ""
        if kind == "trust" and "sts:externalid" not in limiting and any(
                re.search(r":root$", p) or re.fullmatch(r"\d{12}", p)
                for p in parts.get("AWS", [])):
            msg += " Anyone in that account with sts:AssumeRole can assume this role."
            fix = "Name a specific role ARN. For third parties, require sts:ExternalId."
        out.append(Finding("info", "Cross-account access", msg, where, fix))

    for fed in parts.get("Federated", []):
        if "token.actions.githubusercontent.com" in fed:
            out += github_sub_findings(stmt, where)
            if not condition_values(stmt, "token.actions.githubusercontent.com:aud"):
                out.append(Finding("low", "GitHub OIDC trust without an audience check",
                                   "There's no token.actions.githubusercontent.com:aud condition.",
                                   where, "Add StringEquals ...:aud = sts.amazonaws.com."))
        elif not conds:
            out.append(Finding("medium", "Federated trust without conditions",
                               f"{fed} can assume this role with no Condition, so any identity "
                               "from that provider may get in.", where,
                               "Add conditions on the provider's sub or aud claims."))

    services = parts.get("Service", [])
    if services and kind == "resource":
        if not ({"aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid"} & set(limiting)):
            out.append(Finding("low", "Service principal without a source check",
                               ", ".join(services) + " can use this for any customer's "
                               "resources (the confused deputy problem).", where,
                               "Add aws:SourceArn or aws:SourceAccount."))
    if kind == "trust" and any(a.startswith("sts:assumerolewithwebidentity") for a in actions) \
            and not parts.get("Federated"):
        out.append(Finding("medium", "Web identity trust with no Federated principal",
                           "sts:AssumeRoleWithWebIdentity is allowed but no identity provider "
                           "is named.", where))
    return out


def sub_looseness(base_op, value) -> int:
    """2 when a GitHub sub pattern matches repos of any owner (repo:*, repo:*:*,
    repo:*/app:*), 1 when it matches any repo of one owner (repo:my-org/*), else 0."""
    if base_op != "stringlike":
        return 0  # StringEquals takes * as a plain character
    prefix = re.split(r"[*?]", value, maxsplit=1)[0]
    if prefix == value:
        return 0  # no wildcard
    if "/" not in prefix:
        return 2  # the wildcard comes before the owner is spelled out
    if re.fullmatch(r"repo:[^/]+/", prefix):
        return 1
    return 0


def github_sub_findings(stmt, where) -> list:
    positive, negative = [], []
    for op, key, values in condition_entries(stmt):
        if key.lower() != GITHUB_SUB:
            continue
        # GitHub always sends sub, so ...IfExists and ForAllValues: work like the plain one.
        base = op.lower().split(":", 1)[-1].removesuffix("ifexists")
        if "not" in base:
            negative.append(op)
        elif base in ("stringequals", "stringequalsignorecase", "stringlike"):
            positive.append((base, values))
    if not positive:
        if negative:
            detail = (f"The only sub condition uses {', '.join(sorted(set(negative)))}, which "
                      "lets in every repo except the ones listed, so any GitHub Actions "
                      "workflow can assume this role.")
        else:
            detail = ("Any GitHub Actions workflow in any repo can assume this role, because "
                      "there's no token.actions.githubusercontent.com:sub condition.")
        return [Finding("critical", "GitHub OIDC trust without a repo check", detail, where,
                        "Add StringLike token.actions.githubusercontent.com:sub = "
                        "repo:OWNER/REPO:ref:refs/heads/main (or :environment:NAME).")]
    # Every condition has to match, so the tightest one decides. A Not* condition next to
    # a positive one only takes more away.
    worst = min(max((sub_looseness(b, v) for v in values), default=0) for b, values in positive)
    if not worst:
        return []
    loose = sorted({v for b, values in positive for v in values if sub_looseness(b, v) >= worst})
    detail = "The sub condition allows " + ", ".join(loose)
    detail += ", which matches repos owned by anyone." if worst == 2 else "."
    return [Finding("high" if worst == 2 else "medium", "GitHub OIDC repo check is loose",
                    detail, where, "Pin it to one repo and branch or environment.")]


# ------------------------------------------------------------------ AWS checks

AA_TYPES = {"identity": "IDENTITY_POLICY", "resource": "RESOURCE_POLICY",
            "trust": "RESOURCE_POLICY", "scp": "SERVICE_CONTROL_POLICY"}
AA_SEVERITY = {"ERROR": "high", "SECURITY_WARNING": "high", "WARNING": "medium",
               "SUGGESTION": "low"}


def guess_resource_type(doc, kind):
    if kind == "trust":
        return "AWS::IAM::AssumeRolePolicyDocument"
    text = json.dumps(doc)
    if "arn:aws:s3:" in text or '"s3:' in text:
        return "AWS::S3::Bucket"
    if '"dynamodb:' in text:
        return "AWS::DynamoDB::Table"
    return None


def _location_text(locations) -> str:
    parts = []
    for loc in locations or []:
        path = []
        for step in loc.get("path", []):
            if "value" in step:
                path.append(str(step["value"]))
            elif "index" in step:
                path.append(f"[{step['index'] + 1}]")
            elif "key" in step:
                path.append(str(step["key"]))
        if path:
            parts.append(".".join(path).replace(".[", "["))
    return ", ".join(parts)


def validate_with_aws(ctx, doc, kind) -> list:
    """IAM Access Analyzer ValidatePolicy. Free to call. ctx is an AwsContext."""
    kwargs = {"policyDocument": json.dumps(doc), "policyType": AA_TYPES[kind]}
    rtype = guess_resource_type(doc, kind) if kind in ("resource", "trust") else None
    if rtype:
        kwargs["validatePolicyResourceType"] = rtype
    client = ctx.client("accessanalyzer")
    out = []
    try:
        for f in _paginate_validate(client, kwargs):
            sev = AA_SEVERITY.get(f.get("findingType", ""), "info")
            out.append(Finding(sev, f.get("issueCode", "Finding").replace("_", " ").capitalize(),
                               f.get("findingDetails", ""), _location_text(f.get("locations")),
                               source="Access Analyzer", link=f.get("learnMoreLink", "")))
    except Exception as exc:  # noqa: BLE001
        out.append(Finding("info", "Couldn't reach Access Analyzer", error_text(exc, ctx.profile),
                           source="Access Analyzer"))
    return out


def _paginate_validate(client, kwargs):
    token = None
    while True:
        args = dict(kwargs)
        if token:
            args["nextToken"] = token
        resp = client.validate_policy(**args)
        yield from resp.get("findings", [])
        token = resp.get("nextToken")
        if not token:
            break


def fetch_policy(ctx, ref: str) -> tuple:
    """Load a policy from AWS. ref is a managed policy ARN, a role ARN, or role/NAME.

    Returns (doc, kind, label).
    """
    ref = ref.strip()
    iam = ctx.client("iam")
    m = re.match(r"arn:aws[\w-]*:iam::(\d{12}|aws):policy/(.+)", ref)
    if m:
        pol = iam.get_policy(PolicyArn=ref)["Policy"]
        ver = iam.get_policy_version(PolicyArn=ref, VersionId=pol["DefaultVersionId"])
        return _decode(ver["PolicyVersion"]["Document"]), "identity", pol["PolicyName"]
    m = re.match(r"(?:arn:aws[\w-]*:iam::(\d{12}):)?role/(?:.*/)?([\w+=,.@-]+)$", ref)
    if m:
        # get_role only takes a name, so a role ARN from another account would quietly load
        # the role with the same name in this one.
        account = m.group(1)
        if account and account != ctx.account:
            raise PolicyError(f"That role is in account {account}, but this profile is signed "
                              f"in to account {ctx.account}. Use a profile for {account}, or "
                              "paste the trust policy instead.")
        role = iam.get_role(RoleName=m.group(2))["Role"]
        return _decode(role["AssumeRolePolicyDocument"]), "trust", role["RoleName"] + " trust policy"
    raise PolicyError("Use a managed policy ARN, a role ARN, or role/NAME for a trust policy.")


def _decode(doc):
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    return doc


def report_text(findings, kind, note="") -> str:
    lines = [f"Policy type: {KIND_NAMES.get(kind, kind)}"]
    if note:
        lines.append(note)
    if not findings:
        lines.append("No problems found.")
    for f in findings:
        lines.append("")
        head = f"[{f.severity.upper()}] {f.title}"
        if f.where:
            head += f"  ({f.where})"
        if f.source != "awskit":
            head += f"  [{f.source}]"
        lines.append(head)
        if f.detail:
            lines.append(f"  {f.detail}")
        if f.fix:
            lines.append(f"  Fix: {f.fix}")
        if f.link:
            lines.append(f"  More: {f.link}")
    return "\n".join(lines) + "\n"
