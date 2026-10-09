"""Exposure Audit: looks for things open to the internet or missing basic protection.

Read-only. The checks use describe, list and get calls, plus iam:GenerateCredentialReport,
which only asks IAM to build the credential report so it can be read. Nothing is changed.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from . import iampolicy
from .common import (SEVERITY_ORDER, AuthError, AwsContext, error_code, error_text,
                     is_access_denied, name_tag, open_port_risk, paginate)


@dataclass
class Finding:
    severity: str
    check: str
    resource: str
    detail: str = ""
    fix: str = ""
    region: str = ""
    profile: str = ""
    account: str = ""
    name: str = ""

    def row(self) -> dict:
        d = asdict(self)
        d["profile"] = self.profile or "default"
        return d


CHECKS: dict = {}


def check(key, title, service, scope="region"):
    def wrap(fn):
        CHECKS[key] = {"key": key, "title": title, "service": service, "scope": scope, "fn": fn}
        return fn
    return wrap


# =================================================================== network

ONE_STEP_LOWER = {"critical": "high", "high": "medium", "medium": "low"}


def wide_sources(perm) -> tuple:
    """(open, broad) sources of one security group rule. open is the whole internet:
    0.0.0.0/0, ::/0, or ranges that add up to it like 0.0.0.0/1 plus 128.0.0.0/1. broad is a
    public range of /8 or wider in IPv4, or /16 or wider in IPv6, that doesn't."""
    open_, broad = [], []
    for key, field, widest in (("IpRanges", "CidrIp", 8), ("Ipv6Ranges", "CidrIpv6", 16)):
        nets = []
        for r in perm.get(key) or []:
            try:
                nets.append((r[field], ipaddress.ip_network(r[field], strict=False)))
            except (KeyError, TypeError, ValueError):
                continue
        wide = [(text, net) for text, net in nets if net.prefixlen <= widest]
        if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(n for _, n in nets)):
            open_ += [text for text, _ in wide] or [text for text, _ in nets]
        else:
            broad += [text for text, net in wide if not net.is_private]
    return open_, broad


@check("open_sg", "Security groups open to the internet", "ec2")
def check_security_groups(ctx, region):
    ec2 = ctx.client("ec2", region)
    used = set()
    for eni in paginate(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        for g in eni.get("Groups", []):
            used.add(g.get("GroupId"))
    out = []
    for sg in paginate(ec2, "describe_security_groups", "SecurityGroups"):
        gid = sg["GroupId"]
        for perm in sg.get("IpPermissions", []):
            open_, broad = wide_sources(perm)
            if not open_ and not broad:
                continue
            sev, label = open_port_risk(perm.get("IpProtocol"), perm.get("FromPort"),
                                        perm.get("ToPort"))
            title = "Open to the internet"
            if not open_:  # a huge range, but not everyone
                title = "Open to a very broad range"
                sev = ONE_STEP_LOWER.get(sev, sev)
            in_use = gid in used
            if not in_use:  # nothing uses it yet, so one step lower
                sev = {"critical": "medium", "high": "medium", "medium": "low"}.get(sev, sev)
            detail = f"{label} from {', '.join(open_ + broad)}"
            if open_ and not {"0.0.0.0/0", "::/0"} & set(open_):
                detail += " (together that's the whole internet)"
            detail += ", attached to something" if in_use else ", not attached to anything right now"
            fix = ("Normal for a public website." if sev == "info" else
                   "Limit the source to your IP, a VPN range, or another security group. Use "
                   "SSM Session Manager instead of open SSH or RDP.")
            out.append(Finding(sev, title, gid, detail, fix, name=sg.get("GroupName", "")))
        if sg.get("GroupName") == "default" and (sg.get("IpPermissions") or []) and gid in used:
            out.append(Finding("low", "Default security group allows traffic", gid,
                               "Things that fall back to the default group get these rules.",
                               "Remove all rules from default groups and use your own.",
                               name=f"default in {sg.get('VpcId', '')}"))
    return out


@check("imds", "EC2 instances allowing IMDSv1", "ec2")
def check_instances(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    flt = [{"Name": "instance-state-name", "Values": ["pending", "running", "stopped", "stopping"]}]
    for res in paginate(ec2, "describe_instances", "Reservations", Filters=flt):
        for i in res.get("Instances", []):
            iid = i["InstanceId"]
            name = name_tag(i.get("Tags"))
            public = bool(i.get("PublicIpAddress"))
            if i.get("MetadataOptions", {}).get("HttpTokens") == "optional" and \
                    i.get("MetadataOptions", {}).get("HttpEndpoint") != "disabled":
                out.append(Finding("high" if public else "medium", "IMDSv1 allowed", iid,
                                   "Instance metadata answers without a token" +
                                   (", and the instance has a public IP." if public else "."),
                                   "Set HttpTokens to required (aws ec2 modify-instance-metadata-options "
                                   f"--instance-id {iid} --http-tokens required).", name=name))
    return out


# =================================================================== storage

@check("public_snapshots", "Public EBS snapshots and AMIs", "ec2")
def check_public_snapshots(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    for s in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"],
                      RestorableByUserIds=["all"]):
        out.append(Finding("critical", "Public EBS snapshot", s["SnapshotId"],
                           f"Anyone can copy this {s.get('VolumeSize', '?')} GB snapshot.",
                           "Remove the 'all' create-volume permission.",
                           name=name_tag(s.get("Tags"))))
    imgs = ec2.describe_images(Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}])
    for img in imgs.get("Images", []):
        out.append(Finding("high", "Public AMI", img["ImageId"],
                           "Anyone can launch this image and read its disks.",
                           "Make the AMI private.", name=img.get("Name", "")))
    try:
        state = ec2.get_snapshot_block_public_access_state().get("State", "")
        if state == "unblocked":
            out.append(Finding("low", "Snapshot public sharing not blocked", "account setting",
                               "Snapshots can be made public in this region.",
                               "Turn on Block public access for snapshots in the EC2 settings."))
    except Exception as exc:  # noqa: BLE001
        if is_access_denied(exc):
            raise
    return out


@check("ebs_encryption", "Unencrypted EBS volumes", "ec2")
def check_ebs(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    count = 0
    for v in paginate(ec2, "describe_volumes", "Volumes",
                      Filters=[{"Name": "encrypted", "Values": ["false"]}]):
        count += 1
        out.append(Finding("medium", "Unencrypted EBS volume", v["VolumeId"],
                           f"{v.get('Size', '?')} GB, {v.get('State', '')}",
                           "Snapshot it, copy the snapshot with encryption, and swap the volume.",
                           name=name_tag(v.get("Tags"))))
    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
        out.append(Finding("low", "EBS encryption by default is off", "account setting",
                           "New volumes in this region won't be encrypted unless asked.",
                           "aws ec2 enable-ebs-encryption-by-default --region " + region))
    return out


@check("s3", "S3 public access", "s3", scope="global")
def check_s3(ctx, region):
    out = []
    account = ctx.account
    try:
        pab = ctx.client("s3control", "us-east-1").get_public_access_block(
            AccountId=account)["PublicAccessBlockConfiguration"]
        off = [k for k, v in pab.items() if not v]
        if off:
            out.append(Finding("medium", "Account S3 public access block is partly off",
                               "account setting", "Off: " + ", ".join(off),
                               "Turn on all four settings unless a bucket must be public."))
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            out.append(Finding("medium", "No account-level S3 public access block",
                               "account setting", "Each bucket decides for itself.",
                               "Turn on Block Public Access for the whole account in S3 settings."))
        elif is_access_denied(exc):  # say so, rather than look like it's on
            out.append(Finding("info", "Couldn't check the account's S3 public access block",
                               "account setting", error_text(exc, ctx.profile) +
                               ". The buckets were still checked one by one.",
                               "Allow s3:GetAccountPublicAccessBlock to check it."))
        else:
            raise
    s3 = ctx.client("s3", "us-east-1")
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        loc = b.get("BucketRegion")
        try:
            if not loc:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            rs3 = ctx.client("s3", loc)
            out += _bucket_findings(rs3, name, loc)
        except Exception as exc:  # noqa: BLE001
            out.append(Finding("info", "Couldn't check bucket", name, error_text(exc, ctx.profile),
                               region=loc or ""))
    return out


def _bucket_findings(s3, name, region):
    out = []
    blocked = False
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        blocked = all(cfg.values())
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
    try:
        status = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
        if status.get("IsPublic"):
            out.append(Finding("critical", "Bucket policy makes it public", name,
                               "The bucket policy allows anonymous access.",
                               "Remove Principal \"*\" statements or add a narrowing Condition. "
                               "Serve public sites through CloudFront with OAC.", region=region))
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) not in ("NoSuchBucketPolicy",):
            raise
    acl = s3.get_bucket_acl(Bucket=name)
    for g in acl.get("Grants", []):
        uri = g.get("Grantee", {}).get("URI", "")
        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
            who = "everyone" if uri.endswith("/AllUsers") else "any AWS account"
            out.append(Finding("high" if not blocked else "low", f"Bucket ACL grants {who}", name,
                               f"{g.get('Permission')} for {who}." +
                               (" Public access block overrides it for now." if blocked else ""),
                               "Set Object Ownership to Bucket owner enforced to turn ACLs off.",
                               region=region))
    return out


# =================================================================== databases

@check("rds", "RDS public access and encryption", "rds")
def check_rds(ctx, region):
    rds = ctx.client("rds", region)
    out = []
    for db in paginate(rds, "describe_db_instances", "DBInstances"):
        dbid = db["DBInstanceIdentifier"]
        if db.get("PubliclyAccessible"):
            out.append(Finding("high", "Database publicly accessible", dbid,
                               f"{db.get('Engine', '')} has a public endpoint. Only its security "
                               "group protects it.", "Turn off public access, or at least limit "
                               "its security group to your IP."))
        if not db.get("StorageEncrypted"):
            out.append(Finding("medium", "Database storage not encrypted", dbid,
                               db.get("Engine", ""), "Restore an encrypted copy from a snapshot."))
    for s in paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=s["DBSnapshotIdentifier"])
        for a in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
            if a.get("AttributeName") == "restore" and "all" in (a.get("AttributeValues") or []):
                out.append(Finding("critical", "Public RDS snapshot", s["DBSnapshotIdentifier"],
                                   "Anyone can restore this database snapshot.",
                                   "Remove 'all' from the snapshot's restore permission."))
    try:
        for s in paginate(rds, "describe_db_cluster_snapshots", "DBClusterSnapshots",
                          SnapshotType="manual"):
            sid = s["DBClusterSnapshotIdentifier"]
            attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=sid)
            for a in attrs.get("DBClusterSnapshotAttributesResult", {}).get(
                    "DBClusterSnapshotAttributes", []):
                if a.get("AttributeName") == "restore" and "all" in (a.get("AttributeValues") or []):
                    out.append(Finding("critical", "Public Aurora cluster snapshot", sid,
                                       "Anyone can restore this cluster snapshot.",
                                       "Remove 'all' from the snapshot's restore permission."))
    except Exception as exc:  # noqa: BLE001
        if not is_access_denied(exc):
            raise
        out.append(Finding("info", "Couldn't check Aurora cluster snapshots", "cluster snapshots",
                           error_text(exc, ctx.profile)))
    return out


# =================================================================== serverless

@check("lambda", "Public Lambda functions", "lambda")
def check_lambda(ctx, region):
    lam = ctx.client("lambda", region)
    out = []
    denied = {}  # what couldn't be read -> the first error, reported once below
    for fn in paginate(lam, "list_functions", "Functions"):
        name = fn["FunctionName"]
        try:
            for url in lam.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", []):
                if url.get("AuthType") == "NONE":
                    out.append(Finding("high", "Function URL with no auth", name,
                                       f"Anyone can call {url.get('FunctionUrl', '')}",
                                       "Use AuthType AWS_IAM, or check the function handles auth."))
        except Exception as exc:  # noqa: BLE001
            if not is_access_denied(exc):
                raise
            denied.setdefault("function URLs", exc)
        try:
            pol = json.loads(lam.get_policy(FunctionName=name)["Policy"])
            # Critical is Principal "*" with no condition. High covers a condition that
            # doesn't narrow who (like StringNotEquals) and NotPrincipal.
            for f in iampolicy.analyze(pol, "resource"):
                if f.severity in ("critical", "high"):
                    title = "Function policy allows anyone" if f.severity == "critical" \
                        else f"Function policy: {f.title}"
                    out.append(Finding("high", title, name, f.detail,
                                       "Set the principal to a service and add SourceArn."))
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) == "ResourceNotFoundException":
                continue
            if not is_access_denied(exc):
                raise
            denied.setdefault("function policies", exc)
    for what, exc in denied.items():
        out.append(Finding("info", f"Couldn't check {what}", "Lambda", error_text(exc, ctx.profile)))
    return out


# =================================================================== account wide

@check("iam", "IAM users, keys and root account", "iam", scope="global")
def check_iam(ctx, region):
    iam = ctx.client("iam")
    out = []
    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountAccessKeysPresent"):
        out.append(Finding("critical", "Root user has access keys", "root",
                           "Root keys can do anything and can't be limited.",
                           "Delete them in the root user's Security credentials page."))
    if not summary.get("AccountMFAEnabled"):
        out.append(Finding("high", "Root user has no MFA", "root",
                           "Anyone with the root password can sign in.",
                           "Add MFA to the root user. In an organization, consider centralized "
                           "root access so member accounts have no root password."))
    try:
        iam.get_account_password_policy()
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchEntity" and summary.get("Users", 0):
            out.append(Finding("low", "No IAM password policy", "account setting",
                               "IAM users can set short passwords.",
                               "Set a password policy, or move people to IAM Identity Center."))
    try:
        out += _credential_report(iam)
    except Exception as exc:  # noqa: BLE001
        if not is_access_denied(exc):
            raise
        # Keep the root findings above, and say what wasn't checked
        out.append(Finding("info", "Couldn't read the credential report", "credential report",
                           error_text(exc, ctx.profile) + ". Console users without MFA and "
                           "old or unused access keys weren't checked.",
                           "Allow iam:GenerateCredentialReport and iam:GetCredentialReport."))
    return out


def _credential_report(iam):
    deadline = time.time() + 30
    while True:
        state = iam.generate_credential_report().get("State")
        if state == "COMPLETE" or time.time() > deadline:
            break
        time.sleep(2)
    try:
        content = iam.get_credential_report()["Content"].decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) in ("ReportNotPresent", "ReportInProgress", "ReportExpired"):
            return [Finding("info", "Credential report not ready", "iam",
                            "Run the audit again in a minute.")]
        raise
    out = []
    now = datetime.now(timezone.utc)

    def parse(value):
        if not value or value in ("N/A", "no_information", "not_supported"):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    for row in csv.DictReader(io.StringIO(content)):
        user = row.get("user", "")
        if user == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            out.append(Finding("high", "Console user without MFA", user,
                               "This user can sign in with just a password.",
                               "Add MFA, or move the person to IAM Identity Center."))
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            rotated = parse(row.get(f"access_key_{n}_last_rotated"))
            used = parse(row.get(f"access_key_{n}_last_used_date"))
            age = (now - rotated).days if rotated else None
            if used is None:
                out.append(Finding("medium", "Access key never used", f"{user} (key {n})",
                                   f"Active for {age} days and never used." if age is not None else
                                   "Active and never used.", "Deactivate and delete it."))
            elif (now - used).days > 90:
                out.append(Finding("medium", "Access key unused for 90+ days", f"{user} (key {n})",
                                   f"Last used {(now - used).days} days ago.",
                                   "Deactivate and delete it."))
            elif age is not None and age > 90:
                out.append(Finding("low", "Access key older than 90 days", f"{user} (key {n})",
                                   f"Created {age} days ago.",
                                   "Rotate it, or switch to roles or Identity Center."))
    return out


@check("cloudtrail", "CloudTrail coverage", "cloudtrail", scope="global")
def check_cloudtrail(ctx, region):
    ct = ctx.client("cloudtrail", ctx.default_region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    good = False
    out = []
    for t in trails:
        if not t.get("IsMultiRegionTrail"):
            continue
        try:
            status = ctx.client("cloudtrail", t.get("HomeRegion") or ctx.default_region) \
                .get_trail_status(Name=t["TrailARN"])
        except Exception:  # noqa: BLE001
            continue
        if status.get("IsLogging"):
            good = True
            if not t.get("LogFileValidationEnabled"):
                out.append(Finding("low", "Trail log file validation is off", t.get("Name", ""),
                                   "You can't prove the logs weren't changed.",
                                   "Turn on log file validation."))
    if not good:
        out.append(Finding("medium", "No multi-region trail logging", "account setting",
                           "Without a trail, API history only lasts 90 days in Event history and "
                           "can't be sent anywhere.",
                           "Create one multi-region trail (or an organization trail) to S3."))
    return out


@check("access_analyzer", "IAM Access Analyzer findings", "accessanalyzer")
def check_access_analyzer(ctx, region):
    aa = ctx.client("accessanalyzer", region)
    analyzers = [a for a in paginate(aa, "list_analyzers", "analyzers")
                 if a.get("type") in ("ACCOUNT", "ORGANIZATION") and a.get("status") == "ACTIVE"]
    if not analyzers:
        if region == ctx.default_region:
            return [Finding("low", "No IAM Access Analyzer in your home region", "account setting",
                            "Access Analyzer is free and finds resources shared outside the "
                            "account.", f"aws accessanalyzer create-analyzer --analyzer-name "
                            f"account --type ACCOUNT --region {region}")]
        return []
    out = []
    arn = analyzers[0]["arn"]
    for f in paginate(aa, "list_findings_v2", "findings", analyzerArn=arn,
                      filter={"status": {"eq": ["ACTIVE"]}}):
        if f.get("findingType") not in (None, "ExternalAccess"):
            continue
        out.append(Finding("high", "Shared outside the account",
                           f.get("resource", "").split(":")[-1] or f.get("resource", ""),
                           f"{f.get('resourceType', '')} reported by Access Analyzer.",
                           "Review it in IAM, Access Analyzer. Archive it if it's on purpose."))
    return out


# =================================================================== running

def check_choices() -> list:
    return sorted(CHECKS)


def audit(profiles, regions=None, checks=None, progress=None, cancel=None, workers=12):
    """Run checks for one or more profiles. Returns (findings, warnings)."""
    profiles = list(profiles) or [None]
    wanted = [CHECKS[c] for c in (checks or CHECKS) if c in CHECKS]
    findings, warnings = [], []
    denied = {}
    unreachable = {}
    contexts = []
    for p in profiles:
        try:
            ctx = AwsContext(p)
            ctx.account  # noqa: B018
            contexts.append(ctx)
        except AuthError as exc:
            warnings.append(f"{p or 'default'}: {exc}")

    tasks = []
    for ctx in contexts:
        regs = list(regions) if regions else ctx.enabled_regions()
        for c in wanted:
            if c["scope"] == "global":
                tasks.append((ctx, c, "global"))
            else:
                for r in ctx.regions_for(c["service"], regs):
                    tasks.append((ctx, c, r))

    def run(task):
        ctx, c, region = task
        if cancel is not None and cancel.is_set():
            return task, [], None
        try:
            return task, c["fn"](ctx, region), None
        except Exception as exc:  # noqa: BLE001
            return task, [], exc

    total, done = len(tasks), 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(run, t) for t in tasks]):
            (ctx, c, region), found, exc = fut.result()
            done += 1
            if progress:
                progress(done, total, f"{c['title']} in {region}")
            if exc is not None:
                if error_code(exc) == "OptInRequired":
                    continue  # the region isn't turned on, so nothing can be in it
                if is_access_denied(exc):
                    denied.setdefault((ctx.label, c["title"]), []).append(region)
                elif type(exc).__name__ == "EndpointConnectionError" or error_code(exc) in (
                        "UnrecognizedClientException", "AuthFailure"):
                    # Not checked, so say so instead of looking clean. Grouped, since these
                    # tend to hit every region at once.
                    why = error_text(exc, ctx.profile)
                    unreachable.setdefault((ctx.label, c["title"], why), []).append(region)
                else:
                    warnings.append(f"{ctx.label}: {c['title']} in {region}: "
                                    f"{error_text(exc, ctx.profile)}")
                continue
            for f in found:
                f.profile = ctx.profile or ""
                f.account = ctx.account
                if not f.region:
                    f.region = region
                findings.append(f)

    for (label, title), regs in sorted(denied.items()):
        where = regs[0] if len(regs) == 1 else f"{len(regs)} regions"
        warnings.append(f"{label}: no permission for {title} ({where})")
    for (label, title, why), regs in sorted(unreachable.items()):
        where = regs[0] if len(regs) == 1 else f"{len(regs)} regions"
        warnings.append(f"{label}: couldn't check {title} ({where}): {why}")
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.profile, f.region, f.check))
    return findings, warnings


def counts(findings) -> dict:
    out = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def counts_text(findings) -> str:
    c = counts(findings)
    parts = [f"{n} {sev}" for sev, n in c.items() if n]
    return ", ".join(parts) if parts else "No findings."
