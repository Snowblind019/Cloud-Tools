"""Policy Check: reads an IAM policy and flags what's risky about it.

Works offline. Optionally also asks IAM Access Analyzer's ValidatePolicy (free) for
AWS's own findings.
"""
from __future__ import annotations

import ast
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
                except ValueError:
                    continue
            if isinstance(cur, dict):
                return cur, f"Read the policy out of {note}."
    return obj, ""


def load_policy(text: str) -> tuple:
    """Parse JSON, URL-encoded JSON, or a printed boto3 dict. Returns (doc, note)."""
    raw = (text or "").strip()
    if not raw:
        raise PolicyError("Paste a policy first.")
    if raw.startswith("%7B") or raw.startswith("%7b"):
        raw = unquote(raw)
    doc = None
    try:
        doc = json.loads(raw)
    except ValueError as json_err:
        try:
            doc = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            line = getattr(json_err, "lineno", None)
            where = f" (line {line})" if line else ""
            raise PolicyError(f"That isn't valid JSON{where}: {json_err.msg}") from None
    if isinstance(doc, str):  # JSON string holding JSON
        try:
            doc = json.loads(doc)
        except ValueError:
            raise PolicyError("That's a plain string, not a policy.") from None
    doc, note = _unwrap(doc)
    if not isinstance(doc, dict):
        raise PolicyError("A policy should be a JSON object with a Statement list.")
    if "Statement" not in doc:
        raise PolicyError("No Statement found. Is this the whole policy?")
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


def is_broad_resource(resources) -> bool:
    for r in resources:
        r = str(r)
        if r == "*":
            return True
        if re.fullmatch(r"arn:aws[\w-]*:[^:]*:[^:]*:[^:]*:\*", r):
            return True
        if re.fullmatch(r"arn:aws[\w-]*:[^:]+:\*(:\*)*", r):
            return True
        if r in ("arn:aws:s3:::*", "arn:aws:s3:::*/*"):
            return True
        if re.fullmatch(r"arn:aws[\w-]*:iam::\d{12}:role/\*", r):
            return True
        # Every resource of one type, like user/* or function:*. A bucket's objects
        # (arn:aws:s3:::bucket/*) don't count, that's one bucket.
        if not r.startswith("arn:aws:s3:") and re.fullmatch(
                r"arn:aws[\w-]*:[^:]+:[^:]*:[^:]*:[\w-]+[/:]\*", r):
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
                if "iam:passedtoservice" not in conds and not any(
                        str(a) in ("*", "*:*") for a in actions):
                    out.append(Finding("high", "iam:PassRole on any role",
                                       "Can hand any role, including admin roles, to a service.",
                                       where, "Limit Resource to the role ARNs needed and add "
                                       "a iam:PassedToService condition."))
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
    limiting = sorted(k for k in conds if k in LIMITING_KEYS)

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
            out.append(Finding("high", "Public principal with a weak condition",
                               "Principal is \"*\" and the Condition doesn't use a key that "
                               "limits who can call it (" + ", ".join(sorted(conds)) + ").", where,
                               "Add aws:PrincipalOrgID, aws:SourceAccount or aws:SourceArn."))

    accounts = sorted({account_of(p) for p in parts.get("AWS", []) if account_of(p)})
    if accounts:
        msg = "Grants access to account " + ", ".join(accounts) + "."
        fix = ""
        if kind == "trust" and "sts:externalid" not in conds and any(
                re.search(r":root$", p) or re.fullmatch(r"\d{12}", p)
                for p in parts.get("AWS", [])):
            msg += " Anyone in that account with sts:AssumeRole can assume this role."
            fix = "Name a specific role ARN. For third parties, require sts:ExternalId."
        out.append(Finding("info", "Cross-account access", msg, where, fix))

    for fed in parts.get("Federated", []):
        if "token.actions.githubusercontent.com" in fed:
            subs = condition_values(stmt, "token.actions.githubusercontent.com:sub")
            if not subs:
                out.append(Finding("critical", "GitHub OIDC trust without a repo check",
                                   "Any GitHub Actions workflow in any repo can assume this role, "
                                   "because there's no token.actions.githubusercontent.com:sub "
                                   "condition.", where,
                                   "Add StringLike token.actions.githubusercontent.com:sub = "
                                   "repo:OWNER/REPO:ref:refs/heads/main (or :environment:NAME)."))
            else:
                loose = [s for s in subs if s in ("*", "repo:*") or re.fullmatch(r"repo:[^/]+/\*.*", s)
                         or s.startswith("*")]
                if loose:
                    out.append(Finding("high" if any(s in ("*", "repo:*") or s.startswith("*")
                                                     for s in loose) else "medium",
                                       "GitHub OIDC repo check is loose",
                                       "The sub condition allows " + ", ".join(loose) + ".",
                                       where, "Pin it to one repo and branch or environment."))
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
        if not ({"aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid"} & conds):
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
    m = re.match(r"(?:arn:aws[\w-]*:iam::\d{12}:)?role/(?:.*/)?([\w+=,.@-]+)$", ref)
    if m:
        role = iam.get_role(RoleName=m.group(1))["Role"]
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
