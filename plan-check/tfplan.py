"""Plan Check: turns `terraform show -json` into a short summary and flags risky changes."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import iampolicy
from .common import SEVERITY_ORDER, open_port_risk


@dataclass
class Change:
    address: str
    type: str
    action: str
    changed: list = field(default_factory=list)
    forces: list = field(default_factory=list)
    module: str = ""

    def as_dict(self):
        return asdict(self)


@dataclass
class Risk:
    severity: str
    address: str
    title: str
    detail: str = ""
    fix: str = ""

    def as_dict(self):
        return asdict(self)


@dataclass
class PlanSummary:
    changes: list
    risks: list
    outputs: list
    drift: list
    tf_version: str = ""
    errored: bool = False

    def counts(self) -> dict:
        c = {"create": 0, "update": 0, "replace": 0, "delete": 0, "forget": 0}
        for ch in self.changes:
            if ch.action in c:
                c[ch.action] += 1
        return c

    def headline(self) -> str:
        c = self.counts()
        if not any(c.values()):
            return "No changes. Your infrastructure matches the configuration."
        parts = [f"{c['create']} to add", f"{c['update']} to change",
                 f"{c['replace']} to replace", f"{c['delete']} to destroy"]
        if c["forget"]:
            parts.append(f"{c['forget']} to forget")
        return "Plan: " + ", ".join(parts) + "."


class PlanError(Exception):
    pass


# ------------------------------------------------------------------ loading

def terraform_bin():
    for name in ("terraform", "tofu"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run(cmd, cwd, timeout=900):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "TF_IN_AUTOMATION": "1"})
    except subprocess.TimeoutExpired as exc:
        raise PlanError(f"{Path(cmd[0]).name} timed out.") from exc
    except OSError as exc:
        raise PlanError(str(exc)) from exc


def _tail(text, lines=25):
    rows = [r for r in (text or "").strip().splitlines() if r.strip()]
    return "\n".join(rows[-lines:])


def show_json(plan_file: str) -> dict:
    tf = terraform_bin()
    if not tf:
        raise PlanError("Terraform isn't installed or isn't in PATH.")
    path = Path(plan_file).resolve()
    r = _run([tf, "show", "-json", "-no-color", str(path)], cwd=str(path.parent))
    if r.returncode != 0:
        raise PlanError("terraform show failed:\n" + _tail(r.stderr or r.stdout))
    return json.loads(r.stdout)


def plan_directory(directory: str, extra_args=None, log=None) -> dict:
    """Run terraform plan in a directory and return the JSON plan."""
    tf = terraform_bin()
    if not tf:
        raise PlanError("Terraform isn't installed or isn't in PATH.")
    directory = str(Path(directory).resolve())
    fd, tmp = tempfile.mkstemp(prefix="awskit-", suffix=".tfplan", dir=directory)
    os.close(fd)
    try:
        cmd = [tf, "plan", "-input=false", "-no-color", f"-out={tmp}"] + list(extra_args or [])
        if log:
            log("Running " + " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd)))
        r = _run(cmd, cwd=directory)
        if r.returncode != 0:
            raise PlanError("terraform plan failed:\n" + _tail(r.stderr or r.stdout))
        if log:
            log("Reading the plan")
        return show_json(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def load_plan(source: str) -> dict:
    """source can be JSON text, a .json file, a saved binary plan, or a Terraform folder."""
    text = (source or "").strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise PlanError(f"That isn't valid plan JSON: {exc}") from exc
    path = Path(os.path.expanduser(text))
    if path.is_dir():
        return plan_directory(str(path))
    if path.is_file():
        data = path.read_bytes()
        if data.lstrip()[:1] == b"{":
            try:
                return json.loads(data.decode("utf-8"))
            except ValueError as exc:
                raise PlanError(f"{path.name} isn't valid JSON: {exc}") from exc
        return show_json(str(path))
    raise PlanError("Give a plan JSON file, a saved plan file, or a Terraform folder.")


# ------------------------------------------------------------------ summary

def action_of(actions) -> str:
    actions = list(actions or [])
    if actions in (["delete", "create"], ["create", "delete"]):
        return "replace"
    if actions == ["create"]:
        return "create"
    if actions == ["update"]:
        return "update"
    if actions == ["delete"]:
        return "delete"
    if actions == ["forget"]:
        return "forget"
    if actions == ["read"]:
        return "read"
    return "no-op"


def changed_attrs(change: dict) -> list:
    before = change.get("before") or {}
    after = change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    keys = set(before) | set(after) | (set(unknown) if isinstance(unknown, dict) else set())
    out = []
    for k in sorted(keys):
        if k in ("tags_all",) and "tags" in keys:
            continue
        if isinstance(unknown, dict) and unknown.get(k) is True and before.get(k) is not None:
            out.append(k + " (known after apply)")
        elif before.get(k) != after.get(k) and not (isinstance(unknown, dict) and unknown.get(k) is True):
            out.append(k)
    return out


def path_text(path) -> str:
    out = ""
    for step in path or []:
        out += f"[{step}]" if isinstance(step, int) else (("." if out else "") + str(step))
    return out


def summarize(plan: dict) -> PlanSummary:
    if not isinstance(plan, dict) or ("resource_changes" not in plan and "format_version" not in plan):
        raise PlanError("This doesn't look like `terraform show -json` output.")
    changes, risks = [], []
    for rc in plan.get("resource_changes", []) or []:
        if rc.get("mode") == "data":
            continue
        ch = rc.get("change") or {}
        action = action_of(ch.get("actions"))
        if action in ("no-op", "read"):
            continue
        c = Change(address=rc.get("address", ""), type=rc.get("type", ""), action=action,
                   module=rc.get("module_address", ""))
        if action in ("update", "replace"):
            c.changed = changed_attrs(ch)
        if action == "replace":
            c.forces = [path_text(p) for p in ch.get("replace_paths") or []]
        changes.append(c)
        risks += check_resource(rc, action, ch)

    outputs = []
    for name, oc in (plan.get("output_changes") or {}).items():
        action = action_of(oc.get("actions"))
        if action == "no-op":
            continue
        outputs.append({"name": name, "action": action,
                        "sensitive": bool(oc.get("after_sensitive"))})
        lowered = name.lower()
        if not oc.get("after_sensitive") and action in ("create", "update") and any(
                w in lowered for w in ("password", "secret", "token", "private_key", "access_key")):
            risks.append(Risk("low", f"output.{name}", "Output looks secret but isn't sensitive",
                              "It will print in plain text after apply.",
                              "Add sensitive = true to the output block."))

    drift = []
    for rd in plan.get("resource_drift", []) or []:
        action = action_of((rd.get("change") or {}).get("actions"))
        if action != "no-op":
            drift.append({"address": rd.get("address", ""), "action": action,
                          "changed": changed_attrs(rd.get("change") or {})})

    risks.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.address))
    order = {"delete": 0, "replace": 1, "update": 2, "create": 3, "forget": 4}
    changes.sort(key=lambda c: (order.get(c.action, 9), c.address))
    return PlanSummary(changes, risks, outputs, drift, plan.get("terraform_version", ""),
                       bool(plan.get("errored")))


# ------------------------------------------------------------------ risk rules

STATEFUL = {
    "aws_s3_bucket": "the bucket and every object in it",
    "aws_db_instance": "the database and its data",
    "aws_rds_cluster": "the Aurora cluster and its data",
    "aws_dynamodb_table": "the table and its items",
    "aws_kms_key": "the key, and anything encrypted with it becomes unreadable",
    "aws_efs_file_system": "the file system and its files",
    "aws_ebs_volume": "the volume and its data",
    "aws_secretsmanager_secret": "the secret",
    "aws_elasticache_cluster": "the cache cluster",
    "aws_elasticache_replication_group": "the cache cluster",
    "aws_opensearch_domain": "the search domain and its data",
    "aws_ecr_repository": "the repository and its images",
    "aws_backup_vault": "the backup vault",
    "aws_cloudwatch_log_group": "the log group and its logs",
    "aws_cognito_user_pool": "the user pool and its users",
}

SECURITY_SERVICES = {
    "aws_cloudtrail": "CloudTrail logging",
    "aws_guardduty_detector": "GuardDuty",
    "aws_securityhub_account": "Security Hub",
    "aws_config_configuration_recorder": "AWS Config recording",
    "aws_accessanalyzer_analyzer": "IAM Access Analyzer",
    "aws_flow_log": "VPC flow logs",
    "aws_macie2_account": "Macie",
    "aws_inspector2_enabler": "Inspector",
}

ADMIN_POLICIES = {
    "AdministratorAccess": "high",
    "IAMFullAccess": "high",
    "PowerUserAccess": "medium",
    "AWSOrganizationsFullAccess": "high",
}

POLICY_ATTRS = {
    "aws_iam_policy": ("policy", "identity"),
    "aws_iam_role_policy": ("policy", "identity"),
    "aws_iam_user_policy": ("policy", "identity"),
    "aws_iam_group_policy": ("policy", "identity"),
    "aws_iam_role": ("assume_role_policy", "trust"),
    "aws_s3_bucket_policy": ("policy", "resource"),
    "aws_sqs_queue_policy": ("policy", "resource"),
    "aws_sns_topic_policy": ("policy", "resource"),
    "aws_kms_key": ("policy", "resource"),
    "aws_ecr_repository_policy": ("policy", "resource"),
    "aws_secretsmanager_secret_policy": ("policy", "resource"),
    "aws_glacier_vault": ("access_policy", "resource"),
    "aws_organizations_policy": ("content", "scp"),
}


def first(value):
    if isinstance(value, list):
        return value[0] if value else {}
    return value or {}


def is_unknown(ch, key) -> bool:
    unk = ch.get("after_unknown") or {}
    return isinstance(unk, dict) and unk.get(key) is True


def world(cidrs) -> list:
    return [c for c in cidrs or [] if c in ("0.0.0.0/0", "::/0")]


def open_risk(sev, addr, label, cidrs) -> Risk:
    if sev == "info":
        return Risk(sev, addr, f"Open to the internet: {label}",
                    f"Ingress from {', '.join(cidrs)}. Normal for a public website.")
    return Risk(sev, addr, f"Open to the internet: {label}", f"Ingress from {', '.join(cidrs)}.",
                "Limit the source to your IP, a VPN range, or another security group. "
                "For admin access, SSM Session Manager needs no open ports at all.")


def check_resource(rc, action, ch) -> list:
    rtype = rc.get("type", "")
    addr = rc.get("address", "")
    after = ch.get("after") or {}
    before = ch.get("before") or {}
    out = []

    if action in ("delete", "replace"):
        if rtype in STATEFUL:
            verb = "destroys" if action == "delete" else "destroys and recreates"
            out.append(Risk("high", addr, f"Plan {verb} {STATEFUL[rtype]}",
                            "Data can't be recovered unless you have a backup.",
                            "If this isn't intended, check for a renamed resource (use a moved "
                            "block) or a changed argument that forces replacement."))
        elif rtype in SECURITY_SERVICES:
            out.append(Risk("high", addr, f"Plan removes {SECURITY_SERVICES[rtype]}",
                            "Security logging or detection goes away while this applies."))
        elif action == "replace":
            out.append(Risk("info", addr, "Resource gets destroyed and recreated",
                            "Expect downtime and a new ID for this resource."))
    if action == "delete" or not isinstance(after, dict):
        return out

    # ---- network exposure
    if rtype == "aws_security_group" and not is_unknown(ch, "ingress"):
        for rule in after.get("ingress") or []:
            cidrs = world((rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or []))
            if cidrs:
                sev, label = open_port_risk(rule.get("protocol"), rule.get("from_port"),
                                            rule.get("to_port"))
                out.append(open_risk(sev, addr, label, cidrs))
    elif rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        cidrs = world((after.get("cidr_blocks") or []) + (after.get("ipv6_cidr_blocks") or []))
        if cidrs:
            sev, label = open_port_risk(after.get("protocol"), after.get("from_port"),
                                        after.get("to_port"))
            out.append(open_risk(sev, addr, label, cidrs))
    elif rtype == "aws_vpc_security_group_ingress_rule":
        cidrs = world([after.get("cidr_ipv4"), after.get("cidr_ipv6")])
        if cidrs:
            sev, label = open_port_risk(after.get("ip_protocol"), after.get("from_port"),
                                        after.get("to_port"))
            out.append(open_risk(sev, addr, label, cidrs))

    # ---- S3
    elif rtype in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"):
        off = [k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                           "restrict_public_buckets") if after.get(k) is False]
        if off:
            scope = "account" if rtype.startswith("aws_s3_account") else "bucket"
            out.append(Risk("high", addr, f"S3 public access block turned off for the {scope}",
                            "Off: " + ", ".join(off) + ".",
                            "Set all four to true unless this bucket is meant to be public."))
    elif rtype == "aws_s3_bucket_acl":
        acl = after.get("acl")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            out.append(Risk("high", addr, f"Bucket ACL is {acl}",
                            "Objects can be read by anyone" +
                            (" and written by anyone." if acl == "public-read-write" else "."),
                            "Use private and serve public files through CloudFront with OAC."))
        for grant in (first(after.get("access_control_policy")).get("grant") or []):
            uri = str(first(grant.get("grantee")).get("uri", ""))
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                out.append(Risk("high", addr, "Bucket ACL grants access to everyone",
                                f"Grantee {uri.rsplit('/', 1)[-1]} gets {grant.get('permission')}."))
    elif rtype == "aws_s3_bucket" and after.get("force_destroy") is True:
        out.append(Risk("low", addr, "force_destroy is on",
                        "terraform destroy will delete this bucket even with objects in it."))

    # ---- IAM attachments and keys
    elif rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
                   "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"):
        arn = str(after.get("policy_arn") or "")
        name = arn.rsplit("/", 1)[-1]
        if name in ADMIN_POLICIES and ":aws:policy/" in arn:
            out.append(Risk(ADMIN_POLICIES[name], addr, f"Attaches {name}",
                            "This gives broad or full control of the account.",
                            "Use a policy with only the actions this needs."))
    elif rtype == "aws_iam_access_key" and action == "create":
        out.append(Risk("medium", addr, "Creates a long-lived access key",
                        "Access keys don't expire and are the most common thing to leak.",
                        "Use IAM Identity Center or an assumed role instead where you can."))
    elif rtype == "aws_iam_user_login_profile" and action == "create":
        out.append(Risk("low", addr, "Gives an IAM user a console password",
                        "Make sure the user has MFA. Identity Center users are easier to manage."))

    # ---- compute and data
    elif rtype in ("aws_instance", "aws_launch_template"):
        meta = first(after.get("metadata_options"))
        if not is_unknown(ch, "metadata_options"):
            tokens = meta.get("http_tokens") if isinstance(meta, dict) else None
            if tokens == "optional":
                out.append(Risk("medium", addr, "IMDSv1 is allowed",
                                "Without required tokens, SSRF bugs can steal the instance role's "
                                "credentials.", "Set metadata_options { http_tokens = \"required\" }."))
            elif tokens is None and rtype == "aws_instance" and action == "create":
                out.append(Risk("low", addr, "IMDSv2 isn't required in the config",
                                "Whether IMDSv1 works depends on the AMI and account defaults.",
                                "Set metadata_options { http_tokens = \"required\" }."))
        root = first(after.get("root_block_device"))
        if isinstance(root, dict) and root.get("encrypted") is False:
            out.append(Risk("low", addr, "Root volume not encrypted",
                            "Unless EBS encryption by default is on in this region.",
                            "Set encrypted = true on root_block_device."))
        if rtype == "aws_instance" and after.get("associate_public_ip_address") is True:
            out.append(Risk("info", addr, "Instance gets a public IP",
                            "Check its security groups. Public IPv4 also costs $0.005 an hour."))
    elif rtype == "aws_ebs_volume" and after.get("encrypted") is False:
        out.append(Risk("medium", addr, "EBS volume not encrypted",
                        fix="Set encrypted = true, or turn on aws_ebs_encryption_by_default."))
    elif rtype == "aws_ebs_encryption_by_default" and after.get("enabled") is False:
        out.append(Risk("medium", addr, "Turns off EBS encryption by default"))
    elif rtype == "aws_db_instance":
        if after.get("publicly_accessible") is True:
            out.append(Risk("high", addr, "Database is publicly accessible",
                            "It gets a public endpoint. Only its security group stands between "
                            "it and the internet.", "Set publicly_accessible = false."))
        if after.get("storage_encrypted") is False:
            out.append(Risk("medium", addr, "Database storage not encrypted",
                            "Encryption can't be turned on later without a rebuild.",
                            "Set storage_encrypted = true."))
    elif rtype == "aws_rds_cluster" and after.get("storage_encrypted") is False:
        out.append(Risk("medium", addr, "Aurora storage not encrypted",
                        fix="Set storage_encrypted = true."))
    elif rtype == "aws_kms_key":
        if after.get("enable_key_rotation") is False and \
                str(after.get("customer_master_key_spec") or "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
            out.append(Risk("low", addr, "KMS key rotation is off",
                            fix="Set enable_key_rotation = true."))
    elif rtype == "aws_lambda_function_url" and after.get("authorization_type") == "NONE":
        out.append(Risk("high", addr, "Lambda function URL has no auth",
                        "Anyone with the URL can invoke the function.",
                        "Use authorization_type = \"AWS_IAM\" or put API Gateway in front."))
    elif rtype == "aws_lambda_permission":
        if str(after.get("principal")) == "*" and not after.get("source_arn") and \
                not after.get("source_account"):
            out.append(Risk("high", addr, "Lambda can be invoked by anyone",
                            "principal = \"*\" with no source_arn or source_account.",
                            "Set principal to the service and add source_arn."))
    elif rtype == "aws_eks_cluster":
        vpc = first(after.get("vpc_config"))
        if isinstance(vpc, dict) and vpc.get("endpoint_public_access") is not False and \
                (not vpc.get("public_access_cidrs") or "0.0.0.0/0" in vpc.get("public_access_cidrs")):
            out.append(Risk("medium", addr, "EKS API endpoint is open to the internet",
                            fix="Set public_access_cidrs to your IP, or turn off public access."))
    elif rtype == "aws_lb_listener" and after.get("protocol") == "HTTP":
        acts = after.get("default_action") or []
        if not any(a.get("type") == "redirect" for a in acts if isinstance(a, dict)):
            out.append(Risk("low", addr, "Load balancer listener uses plain HTTP",
                            fix="Redirect port 80 to HTTPS."))

    # ---- security services switched off
    elif rtype == "aws_cloudtrail":
        if after.get("enable_logging") is False:
            out.append(Risk("high", addr, "CloudTrail logging turned off"))
        if after.get("is_multi_region_trail") is False:
            out.append(Risk("low", addr, "Trail only covers one region",
                            fix="Set is_multi_region_trail = true."))
        if after.get("enable_log_file_validation") is False:
            out.append(Risk("low", addr, "Log file validation is off",
                            fix="Set enable_log_file_validation = true."))
    elif rtype == "aws_guardduty_detector" and after.get("enable") is False:
        out.append(Risk("high", addr, "GuardDuty detector suspended"))
    elif rtype == "aws_config_configuration_recorder_status" and after.get("is_enabled") is False:
        out.append(Risk("high", addr, "AWS Config recording turned off"))

    # ---- policy documents, checked with the Policy Check rules
    if rtype in POLICY_ATTRS:
        attr, kind = POLICY_ATTRS[rtype]
        out += check_policy_attr(addr, after, before, attr, kind, ch)
    return out


def check_policy_attr(addr, after, before, attr, kind, ch) -> list:
    text = after.get(attr)
    if not text or is_unknown(ch, attr) or not isinstance(text, str):
        return []
    if text == (before or {}).get(attr):
        return []  # unchanged policy, don't re-flag it on every plan
    try:
        doc, _ = iampolicy.load_policy(text)
    except iampolicy.PolicyError:
        return []
    out = []
    for f in iampolicy.analyze(doc, kind):
        if f.severity in ("critical", "high", "medium"):
            detail = f.detail + (f" ({f.where})" if f.where else "")
            out.append(Risk(f.severity, addr, f.title, detail, f.fix))
    return out


# ------------------------------------------------------------------ output

ACTION_WORD = {"create": "create", "update": "update", "replace": "replace",
               "delete": "destroy", "forget": "forget"}
ACTION_MARK = {"create": "+", "update": "~", "replace": "-/+", "delete": "-", "forget": "."}


def report_text(s: PlanSummary, markdown=False) -> str:
    lines = []
    h = "## " if markdown else ""
    lines.append(f"{h}{s.headline()}")
    if s.errored:
        lines.append("Warning: Terraform marked this plan as errored. It may be incomplete.")
    if s.risks:
        lines += ["", f"{h}Things to look at ({len(s.risks)})"]
        for r in s.risks:
            row = f"[{r.severity.upper()}] {r.address}: {r.title}"
            lines.append(("- " if markdown else "") + row)
            if r.detail:
                lines.append(f"    {r.detail}")
            if r.fix:
                lines.append(f"    Fix: {r.fix}")
    for action in ("delete", "replace", "update", "create", "forget"):
        group = [c for c in s.changes if c.action == action]
        if not group:
            continue
        lines += ["", f"{h}{ACTION_WORD[action].capitalize()} ({len(group)})"]
        for c in group:
            mark = ACTION_MARK[action]
            row = f"{mark} {c.address}"
            if markdown:
                row = f"- `{mark}` {c.address}"
            if c.forces:
                row += "  (forced by: " + ", ".join(c.forces) + ")"
            elif c.changed and action == "update":
                row += "  (" + ", ".join(c.changed[:8]) + (", ..." if len(c.changed) > 8 else "") + ")"
            lines.append(row)
    if s.outputs:
        lines += ["", f"{h}Outputs"]
        for o in s.outputs:
            lines.append(("- " if markdown else "  ") + f"{o['name']}: {o['action']}" +
                         (" (sensitive)" if o["sensitive"] else ""))
    if s.drift:
        lines += ["", f"{h}Changed outside Terraform ({len(s.drift)})"]
        for d in s.drift:
            extra = f" ({', '.join(d['changed'][:6])})" if d["changed"] else ""
            lines.append(("- " if markdown else "  ") + f"{d['address']}: {d['action']}{extra}")
    return "\n".join(lines) + "\n"


def worst(risks) -> str:
    if not risks:
        return ""
    return min(risks, key=lambda r: SEVERITY_ORDER.get(r.severity, 9)).severity
