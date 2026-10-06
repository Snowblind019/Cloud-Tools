"""CloudTrail timeline: who did what, when, and whether it failed.

Uses CloudTrail Event history (LookupEvents). It's free, covers management events
for the last 90 days, and needs no trail set up. It allows one filter at a time,
so extra filters like "errors only" are applied after the events come back.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .common import AuthError, AwsContext, error_text, local_time

LOOKUP_KEYS = {
    "user": ("Username", "User or role session name"),
    "resource": ("ResourceName", "Resource name or ID"),
    "event": ("EventName", "Event name, like PutBucketPolicy"),
    "source": ("EventSource", "Service, like s3.amazonaws.com"),
    "key": ("AccessKeyId", "Access key ID"),
    "type": ("ResourceType", "Resource type, like AWS::S3::Bucket"),
}

GLOBAL_HINT = ("IAM, STS, Organizations and console sign-in events are recorded in "
               "us-east-1, so include it when looking for those.")


@dataclass
class Event:
    time: datetime
    name: str
    service: str
    who: str
    who_type: str
    ip: str
    region: str
    error: str = ""
    error_message: str = ""
    resources: str = ""
    read_only: bool | None = None
    agent: str = ""
    event_id: str = ""
    raw: dict = field(default_factory=dict)
    # (severity, title, why) when it's a security event worth a look, see SECURITY_RULES
    alert: tuple = ()

    @property
    def action(self) -> str:
        return f"{self.service}:{self.name}"

    @property
    def result(self) -> str:
        return self.error or "OK"

    def row(self) -> dict:
        return {"flag": self.alert[0] if self.alert else "",
                "time": local_time(self.time), "who": self.who, "action": self.action,
                "resources": self.resources, "result": self.result, "ip": self.ip,
                "region": self.region, "who_type": self.who_type,
                "read_only": "" if self.read_only is None else ("read" if self.read_only else "write")}

    def detail_text(self) -> str:
        lines = []
        if self.alert:
            sev, title, why = self.alert
            lines += [f"[{sev.upper()}] {title}", f"Why it's worth a look: {why}", ""]
        lines += [f"{local_time(self.time)}  {self.action}", f"Who: {self.who} ({self.who_type})"]
        ident = self.raw.get("userIdentity")
        arn = ident.get("arn") if isinstance(ident, dict) else None
        if arn:
            lines.append(f"ARN: {arn}")
        lines.append(f"From: {self.ip}  in {self.region}")
        if self.agent:
            lines.append(f"Client: {self.agent[:160]}")
        if self.error:
            lines.append(f"Result: FAILED, {self.error}")
            if self.error_message:
                lines.append(f"Message: {self.error_message}")
        else:
            lines.append("Result: OK")
        lines += ["", json.dumps(self.raw, indent=2, default=str)]
        return "\n".join(lines)


def short_who(identity: dict) -> tuple:
    if not isinstance(identity, dict):
        identity = {}
    itype = str(identity.get("type") or "")
    arn = str(identity.get("arn") or "")
    if itype == "Root":
        return "root", itype
    if itype == "IAMUser":
        return identity.get("userName") or arn.rsplit("/", 1)[-1], itype
    if itype == "AssumedRole":
        m = re.match(r"arn:aws[\w-]*:sts::\d{12}:assumed-role/([^/]+)/(.+)", arn)
        if m:
            role, session = m.group(1), m.group(2)
            if role.startswith("AWSReservedSSO_"):
                role = role[len("AWSReservedSSO_"):].rsplit("_", 1)[0] + " (SSO)"
            return f"{role}/{session}", itype
        ctx = identity.get("sessionContext")
        issuer = ctx.get("sessionIssuer") if isinstance(ctx, dict) else None
        name = issuer.get("userName", "") if isinstance(issuer, dict) else ""
        return str(name or arn), itype
    if itype == "AWSService":
        return identity.get("invokedBy", "AWS service"), itype
    if itype == "AWSAccount":
        return "account " + identity.get("accountId", ""), itype
    if itype == "FederatedUser":
        return arn.rsplit("/", 1)[-1] or identity.get("principalId", ""), itype
    behalf = identity.get("onBehalfOf")
    name = identity.get("userName") or (behalf.get("userId") if isinstance(behalf, dict) else "") \
        or identity.get("principalId") or itype or "unknown"
    return str(name), itype or "unknown"


INTERESTING_PARAM = re.compile(r"(name|id|ids|arn|bucket|key)$", re.I)


def resources_text(lookup_event: dict, detail: dict) -> str:
    listed = lookup_event.get("Resources")
    names = [str(r.get("ResourceName")) for r in (listed if isinstance(listed, list) else [])
             if isinstance(r, dict) and r.get("ResourceName")]
    if not names:
        params = detail.get("requestParameters") or {}
        if isinstance(params, dict):
            for k, v in params.items():
                if INTERESTING_PARAM.search(k) and isinstance(v, (str, int)) and str(v):
                    names.append(str(v))
                if len(names) >= 2:
                    break
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return ", ".join(seen[:3]) + (" ..." if len(seen) > 3 else "")


# =================================================================== security events

# Calls worth a second look, after the CIS AWS Foundations Benchmark's monitoring list
# (section 4: the metric filters and alarms it asks for), plus a few more that undo a
# protection: GuardDuty switched off, a snapshot or image shared with everyone, new access
# keys. Each rule: (key, severity, title, why, test). test gets the event's own record.

def _names(*names):
    wanted = set(names)
    return lambda d: d.get("eventName") in wanted


def _source(source, *names):
    wanted = set(names)
    return lambda d: d.get("eventSource") == source and d.get("eventName") in wanted


DENIED_CODES = re.compile(r"(AccessDenied|UnauthorizedOperation|Unauthorized|Forbidden)", re.I)


def _denied(d):
    return bool(DENIED_CODES.search(str(d.get("errorCode") or "")))


def _console_login(d):
    return d.get("eventName") == "ConsoleLogin" and d.get("eventSource", "signin.amazonaws.com") \
        == "signin.amazonaws.com"


def _login_ok(d):
    return str(((d.get("responseElements") or {}).get("ConsoleLogin") or "")).lower() == "success"


def _login_without_mfa(d):
    # IAM users and root only. Identity Center sign-ins do their MFA outside AWS's sign-in
    # page, so their MFAUsed is always No and would only be noise.
    who = (d.get("userIdentity") or {}).get("type")
    mfa = str((d.get("additionalEventData") or {}).get("MFAUsed", "")).lower()
    return _console_login(d) and _login_ok(d) and who in ("IAMUser", "Root") and mfa != "yes"


def _login_failed(d):
    return _console_login(d) and not _login_ok(d) and bool(
        d.get("errorMessage") or (d.get("responseElements") or {}).get("ConsoleLogin"))


def _root_used(d):
    ident = d.get("userIdentity") or {}
    return ident.get("type") == "Root" and not ident.get("invokedBy") and \
        d.get("eventType") != "AwsServiceEvent"


def _shared_with_everyone(d):
    """A snapshot or AMI made public: createVolumePermission / launchPermission with group all."""
    if d.get("eventName") not in ("ModifySnapshotAttribute", "ModifyImageAttribute"):
        return False
    text = json.dumps(d.get("requestParameters") or {})
    return '"group": "all"' in text and ('"add"' in text or "Add" in text)


def _public_access_block_loosened(d):
    if d.get("eventSource") != "s3.amazonaws.com":
        return False
    if d.get("eventName") == "DeletePublicAccessBlock":
        return True
    if d.get("eventName") != "PutPublicAccessBlock":
        return False
    conf = json.dumps((d.get("requestParameters") or {}).get("PublicAccessBlockConfiguration") or {})
    return "false" in conf.lower()


def _guardduty_off(d):
    if d.get("eventSource") != "guardduty.amazonaws.com":
        return False
    if d.get("eventName") in ("DeleteDetector", "DisassociateFromMasterAccount",
                              "DisassociateFromAdministratorAccount", "StopMonitoringMembers"):
        return True
    params = d.get("requestParameters") or {}
    return d.get("eventName") == "UpdateDetector" and params.get("enable") is False


SECURITY_RULES = (
    ("root", "high", "Root user used",
     "The root user can do anything and can't be limited. Outside a few account settings "
     "tasks, it shouldn't be used at all.", _root_used),
    ("login-no-mfa", "high", "Console sign-in without MFA",
     "Someone signed in with just a password.", _login_without_mfa),
    ("trail-change", "high", "CloudTrail changed",
     "Stopping or changing a trail is how someone hides what they do next.",
     _source("cloudtrail.amazonaws.com", "CreateTrail", "UpdateTrail", "DeleteTrail",
             "StartLogging", "StopLogging", "PutEventSelectors")),
    ("config-change", "high", "AWS Config recording changed",
     "Turning off Config recording hides configuration changes from now on.",
     _source("config.amazonaws.com", "StopConfigurationRecorder", "DeleteDeliveryChannel",
             "PutDeliveryChannel", "PutConfigurationRecorder")),
    ("kms-delete", "high", "KMS key disabled or set to be deleted",
     "Data encrypted with a deleted key can't be read again.",
     _source("kms.amazonaws.com", "DisableKey", "ScheduleKeyDeletion")),
    ("guardduty-off", "high", "GuardDuty turned off",
     "GuardDuty is the alarm system. Turning it off is a common first step in an attack.",
     _guardduty_off),
    ("made-public", "critical", "Snapshot or image shared with everyone",
     "Anyone with an AWS account can now copy it, with whatever data is on it.",
     _shared_with_everyone),
    ("s3-block-public", "high", "S3 Block Public Access loosened",
     "Block Public Access is the safety net that stops buckets being made public by mistake.",
     _public_access_block_loosened),
    ("iam-policy", "medium", "IAM policy changed",
     "Changes to who can do what. Worth checking they were meant.",
     _source("iam.amazonaws.com", "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy",
             "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
             "CreatePolicyVersion", "DeletePolicyVersion", "SetDefaultPolicyVersion",
             "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
             "AttachGroupPolicy", "DetachGroupPolicy", "UpdateAssumeRolePolicy",
             "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary")),
    ("iam-credentials", "medium", "New IAM user or credentials",
     "New long-lived credentials are the usual way someone keeps access.",
     _source("iam.amazonaws.com", "CreateUser", "CreateAccessKey", "CreateLoginProfile",
             "UpdateLoginProfile", "DeactivateMFADevice", "DeleteVirtualMFADevice")),
    ("org-change", "medium", "Organizations changed",
     "Accounts, OUs and SCPs decide what every account can do.",
     lambda d: d.get("eventSource") == "organizations.amazonaws.com" and d.get("eventName") in {
         "AcceptHandshake", "AttachPolicy", "CreateAccount", "CreateOrganizationalUnit",
         "CreatePolicy", "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit",
         "DeletePolicy", "DetachPolicy", "DisablePolicyType", "EnablePolicyType",
         "InviteAccountToOrganization", "LeaveOrganization", "MoveAccount",
         "RemoveAccountFromOrganization", "UpdatePolicy", "UpdateOrganizationalUnit"}),
    ("login-failed", "medium", "Failed console sign-in",
     "A few are typos. Many in a row can be someone guessing passwords.", _login_failed),
    ("s3-policy", "medium", "S3 bucket policy or ACL changed",
     "Bucket policies and ACLs decide who outside the account can read the data.",
     _source("s3.amazonaws.com", "PutBucketAcl", "PutBucketPolicy", "PutBucketCors",
             "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy",
             "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication")),
    ("denied", "medium", "Call denied",
     "Usually a missing permission in your own work. A burst of them from one identity can "
     "be someone testing what a stolen key can do.", _denied),
    ("sg-change", "low", "Security group changed",
     "Security groups decide what can reach your instances.",
     _source("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
             "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup",
             "DeleteSecurityGroup", "ModifySecurityGroupRules")),
    ("nacl-change", "low", "Network ACL changed", "Network ACLs filter traffic for whole subnets.",
     _source("ec2.amazonaws.com", "CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl",
             "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation")),
    ("gateway-change", "low", "Network gateway changed",
     "Gateways are the ways in and out of a VPC.",
     _source("ec2.amazonaws.com", "CreateCustomerGateway", "DeleteCustomerGateway",
             "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway",
             "DetachInternetGateway")),
    ("route-change", "low", "Route table changed", "Routes decide where traffic goes.",
     _source("ec2.amazonaws.com", "CreateRoute", "CreateRouteTable", "ReplaceRoute",
             "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute",
             "DisassociateRouteTable")),
    ("vpc-change", "low", "VPC changed", "New or changed VPCs and peering connections.",
     _source("ec2.amazonaws.com", "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
             "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection",
             "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection")),
)


def security_alert(detail: dict) -> tuple:
    """(severity, title, why) for the first rule an event's record matches, or ()."""
    if not isinstance(detail, dict):
        return ()
    for _key, sev, title, why, test in SECURITY_RULES:
        try:
            if test(detail):
                return (sev, title, why)
        except (AttributeError, TypeError, ValueError):
            continue
    return ()


def _text(value) -> str:
    """A field of an event record as text. Records come from AWS, but trail files can be
    anything, so a list or a number where text should be doesn't stop the whole search."""
    return value if isinstance(value, str) else ("" if value is None else str(value))


def parse_event(ev: dict, region: str) -> Event:
    try:
        detail = json.loads(ev.get("CloudTrailEvent") or "{}")
    except (TypeError, ValueError, RecursionError):
        detail = {}
    if not isinstance(detail, dict):
        detail = {}
    who, wtype = short_who(detail.get("userIdentity") or {})
    t = ev.get("EventTime")
    if not isinstance(t, datetime):
        try:
            t = datetime.fromisoformat(str(detail.get("eventTime", "")).replace("Z", "+00:00"))
        except ValueError:
            t = datetime.now(timezone.utc)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    source = _text(ev.get("EventSource") or detail.get("eventSource", ""))
    return Event(
        time=t, name=_text(ev.get("EventName") or detail.get("eventName", "")),
        service=source.replace(".amazonaws.com", ""), who=who, who_type=wtype,
        ip=_text(detail.get("sourceIPAddress", "")), region=_text(detail.get("awsRegion") or region),
        error=_text(detail.get("errorCode")), error_message=_text(detail.get("errorMessage")),
        resources=resources_text(ev, detail),
        read_only=detail.get("readOnly") if isinstance(detail.get("readOnly"), bool) else (
            None if ev.get("ReadOnly") is None else str(ev.get("ReadOnly")).lower() == "true"),
        agent=_text(detail.get("userAgent")), event_id=_text(detail.get("eventID", ev.get("EventId", ""))),
        raw=detail, alert=security_alert(detail))


def my_session_name(ctx) -> str:
    """The Username CloudTrail records for the current credentials."""
    arn = ctx.identity().get("Arn", "")
    if ":assumed-role/" in arn:
        return arn.rsplit("/", 1)[-1]
    if ":user/" in arn:
        return arn.rsplit("/", 1)[-1]
    if arn.endswith(":root"):
        return "root"
    return ""


def lookup(profile, regions, start, end, attr=None, value=None, errors_only=False,
           writes_only=False, limit=500, progress=None, cancel=None, security_only=False):
    """Returns (events, warnings). attr is a key of LOOKUP_KEYS or None for no filter.
    security_only keeps just the events SECURITY_RULES flags."""
    ctx = AwsContext(profile)
    regions = list(regions) or [ctx.default_region]
    kwargs = {"StartTime": start, "EndTime": end}
    if attr and value:
        kwargs["LookupAttributes"] = [{"AttributeKey": LOOKUP_KEYS[attr][0],
                                       "AttributeValue": value.strip()}]
    if writes_only and not kwargs.get("LookupAttributes"):
        kwargs["LookupAttributes"] = [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]
    # When filtering afterwards, read further so the filtered list still has enough.
    scan_limit = limit * 4 if (errors_only or (writes_only and attr)) else limit
    if security_only:
        # Most events aren't security events, so read a good deal further.
        scan_limit = max(scan_limit, min(limit * 10, 5000))

    events, warnings = [], []

    def run(region):
        ct = ctx.client("cloudtrail", region)
        found = []
        pages = ct.get_paginator("lookup_events").paginate(
            **kwargs, PaginationConfig={"MaxItems": scan_limit, "PageSize": 50})
        for page in pages:
            if cancel is not None and cancel.is_set():
                break
            for ev in page.get("Events", []):
                found.append(parse_event(ev, region))
        return found

    done = 0
    with ThreadPoolExecutor(max_workers=min(4, len(regions))) as pool:
        futures = {pool.submit(run, r): r for r in regions}
        for fut in as_completed(futures):
            region = futures[fut]
            done += 1
            try:
                events += fut.result()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{region}: {error_text(exc, profile)}")
            if progress:
                progress(done, len(regions), f"Read {region}")

    if errors_only:
        events = [e for e in events if e.error]
    if writes_only:
        events = [e for e in events if e.read_only is not True]
    if security_only:
        events = [e for e in events if e.alert]
    events.sort(key=lambda e: e.time, reverse=True)
    return events[:limit], warnings


def explain_denied(event: Event) -> str:
    """Pull the useful part out of an AccessDenied message."""
    msg = event.error_message
    if not msg:
        return ""
    m = re.search(r"not authorized to perform: (\S+)(?: on resource: (\S+))?", msg)
    reason = re.search(r"because (.+)$", msg)
    parts = []
    if m:
        target = (m.group(2) or "").strip('"')
        parts.append(f"Missing permission: {m.group(1)}" + (f" on {target}" if target else ""))
    if reason:
        parts.append("Why: " + reason.group(1).rstrip("."))
    return "\n".join(parts)


__all__ = ["lookup", "LOOKUP_KEYS", "GLOBAL_HINT", "Event", "my_session_name", "explain_denied",
           "AuthError", "SECURITY_RULES", "security_alert"]
