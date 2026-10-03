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

    @property
    def action(self) -> str:
        return f"{self.service}:{self.name}"

    @property
    def result(self) -> str:
        return self.error or "OK"

    def row(self) -> dict:
        return {"time": local_time(self.time), "who": self.who, "action": self.action,
                "resources": self.resources, "result": self.result, "ip": self.ip,
                "region": self.region, "who_type": self.who_type,
                "read_only": "" if self.read_only is None else ("read" if self.read_only else "write")}

    def detail_text(self) -> str:
        lines = [f"{local_time(self.time)}  {self.action}", f"Who: {self.who} ({self.who_type})"]
        arn = self.raw.get("userIdentity", {}).get("arn")
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
    itype = identity.get("type", "")
    arn = identity.get("arn", "")
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
        issuer = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName", "")
        return issuer or arn, itype
    if itype == "AWSService":
        return identity.get("invokedBy", "AWS service"), itype
    if itype == "AWSAccount":
        return "account " + identity.get("accountId", ""), itype
    if itype == "FederatedUser":
        return arn.rsplit("/", 1)[-1] or identity.get("principalId", ""), itype
    name = identity.get("userName") or identity.get("onBehalfOf", {}).get("userId") \
        or identity.get("principalId") or itype or "unknown"
    return name, itype or "unknown"


INTERESTING_PARAM = re.compile(r"(name|id|ids|arn|bucket|key)$", re.I)


def resources_text(lookup_event: dict, detail: dict) -> str:
    names = [r.get("ResourceName", "") for r in lookup_event.get("Resources") or []
             if r.get("ResourceName")]
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


def parse_event(ev: dict, region: str) -> Event:
    try:
        detail = json.loads(ev.get("CloudTrailEvent") or "{}")
    except ValueError:
        detail = {}
    who, wtype = short_who(detail.get("userIdentity") or {})
    t = ev.get("EventTime")
    if not isinstance(t, datetime):
        try:
            t = datetime.fromisoformat(str(detail.get("eventTime", "")).replace("Z", "+00:00"))
        except ValueError:
            t = datetime.now(timezone.utc)
    source = ev.get("EventSource") or detail.get("eventSource", "")
    return Event(
        time=t, name=ev.get("EventName") or detail.get("eventName", ""),
        service=source.replace(".amazonaws.com", ""), who=who, who_type=wtype,
        ip=detail.get("sourceIPAddress", ""), region=detail.get("awsRegion", region),
        error=detail.get("errorCode", "") or "", error_message=detail.get("errorMessage", "") or "",
        resources=resources_text(ev, detail),
        read_only=detail.get("readOnly") if isinstance(detail.get("readOnly"), bool) else (
            None if ev.get("ReadOnly") is None else str(ev.get("ReadOnly")).lower() == "true"),
        agent=detail.get("userAgent", ""), event_id=detail.get("eventID", ev.get("EventId", "")),
        raw=detail)


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
           writes_only=False, limit=500, progress=None, cancel=None):
    """Returns (events, warnings). attr is a key of LOOKUP_KEYS or None for no filter."""
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
           "AuthError"]
