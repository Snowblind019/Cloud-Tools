"""Plan Check: turns `terraform show -json` into a short summary and flags risky changes."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
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


class NeedsTerraform(PlanError):
    """Reading this means running Terraform, and the caller said not to."""


# ------------------------------------------------------------------ loading

TF_NAMES = ("terraform", "tofu")


def terraform_bin():
    """The terraform (or tofu) program to run, or None if neither is installed.

    On Windows, shutil.which looks in the current folder first and also takes .bat and .cmd
    files. Those run through cmd.exe, which reads the arguments again, so a path with & in
    it could run something else. So there it only takes terraform.exe or tofu.exe from a
    folder in PATH."""
    if os.name == "nt":
        folders = [d.strip().strip('"') for d in os.environ.get("PATH", "").split(os.pathsep)]
        for name in TF_NAMES:
            for folder in folders:
                if not folder or not os.path.isabs(folder):
                    continue
                path = os.path.join(folder, name + ".exe")
                if os.path.isfile(path):
                    return path
        return None
    for name in TF_NAMES:
        # Only from a folder in PATH given as a full path. With "." or an empty entry in
        # PATH, which would hand back a relative path, Terraform would run from the folder
        # being planned, so a repo could ship its own "terraform".
        folders = [d for d in os.environ.get("PATH", "").split(os.pathsep) if os.path.isabs(d)]
        path = shutil.which(name, path=os.pathsep.join(folders))
        if path:
            return os.path.abspath(path)
    return None


def _env(profile=None) -> dict:
    """The environment Terraform runs with. With a profile (the one picked in AWS Kit), the
    AWS provider uses it instead of whatever profile the app was started with."""
    env = {**os.environ, "TF_IN_AUTOMATION": "1"}
    if profile:
        env["AWS_PROFILE"] = profile
        env.pop("AWS_DEFAULT_PROFILE", None)
    return env


def _run(cmd, cwd, timeout=900, profile=None):
    """Run cmd and return a CompletedProcess. On Linux and macOS it runs in its own process
    group, so if it times out the provider plugins Terraform started are stopped with it."""
    group = os.name != "nt"
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=_env(profile),
                                start_new_session=group)
    except OSError as exc:
        raise PlanError(str(exc)) from exc
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _stop(proc, group)
        raise PlanError(f"{Path(cmd[0]).name} timed out.") from exc
    except BaseException:
        _stop(proc, group)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _stop(proc, group):
    if not group:  # Windows: the same as subprocess.run does
        proc.kill()
        proc.communicate()
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    proc.wait()
    for pipe in (proc.stdout, proc.stderr):
        if pipe:
            pipe.close()


def _tail(text, lines=25):
    rows = [r for r in (text or "").strip().splitlines() if r.strip()]
    return "\n".join(rows[-lines:])


def _json_out(text) -> dict:
    """Terraform's JSON output, read safely: a folder's code decides what's in it."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise PlanError(f"terraform show didn't print JSON Plan Check can read: "
                        f"{type(exc).__name__}") from exc


def show_json(plan_file: str, profile=None, cwd=None) -> dict:
    """terraform show -json on a saved plan. It runs in cwd (the plan's folder unless
    given), which needs the .terraform folder the plan was made with."""
    tf = terraform_bin()
    if not tf:
        raise PlanError("Terraform isn't installed or isn't in PATH.")
    path = Path(plan_file).resolve()
    r = _run([tf, "show", "-json", "-no-color", str(path)], cwd=str(cwd or path.parent),
             profile=profile)
    if r.returncode != 0:
        raise PlanError("terraform show failed:\n" + _tail(r.stderr or r.stdout))
    return _json_out(r.stdout)


def show_state(directory: str, profile=None) -> dict:
    """terraform show -json in a folder: its current state, without planning anything.
    Cloud Map uses this to draw what a folder has already built."""
    tf = terraform_bin()
    if not tf:
        raise PlanError("Terraform isn't installed or isn't in PATH.")
    directory = str(Path(directory).resolve())
    r = _run([tf, "show", "-json", "-no-color"], cwd=directory, profile=profile)
    if r.returncode != 0:
        raise PlanError("terraform show failed:\n" + _tail(r.stderr or r.stdout))
    return _json_out(r.stdout or "{}")


def plan_directory(directory: str, extra_args=None, log=None, profile=None) -> dict:
    """Run terraform plan in a directory and return the JSON plan."""
    tf = terraform_bin()
    if not tf:
        raise PlanError("Terraform isn't installed or isn't in PATH.")
    directory = str(Path(directory).resolve())
    # A saved plan holds variable values and often secrets, so it goes in a private temp
    # folder, not in the Terraform folder where it could be left behind or committed.
    tmpdir = tempfile.mkdtemp(prefix="awskit-plan-")
    tmp = os.path.join(tmpdir, "plan.tfplan")
    try:
        cmd = [tf, "plan", "-input=false", "-no-color", f"-out={tmp}"] + list(extra_args or [])
        if log:
            log("Running " + " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd)))
        r = _run(cmd, cwd=directory, profile=profile)
        if r.returncode != 0:
            raise PlanError("terraform plan failed:\n" + _tail(r.stderr or r.stdout))
        if log:
            log("Reading the plan")
        return show_json(tmp, profile=profile, cwd=directory)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def load_plan(source: str, profile=None, run_terraform=True) -> dict:
    """source can be JSON text, a .json file, a saved binary plan, or a Terraform folder.
    With run_terraform=False, a saved plan or a folder raises NeedsTerraform instead."""
    text = (source or "").strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise PlanError(f"That isn't valid plan JSON: {exc}") from exc
    path = Path(os.path.expanduser(text))
    try:
        is_dir = path.is_dir()
        data = None if is_dir or not path.is_file() else path.read_bytes()
    except OSError as exc:
        raise PlanError(f"Couldn't read {path}: {exc}") from exc
    if is_dir:
        if not run_terraform:
            raise NeedsTerraform(f"{path} is a folder. Reading it means running terraform "
                                 "plan there.")
        return plan_directory(str(path), profile=profile)
    if data is not None:
        if data.lstrip()[:1] == b"{":
            try:
                return json.loads(data.decode("utf-8"))
            except (ValueError, RecursionError) as exc:
                raise PlanError(f"{path.name} isn't valid JSON: {exc}") from exc
        if not run_terraform:
            raise NeedsTerraform(f"{path.name} is a saved plan. Reading it means running "
                                 "terraform show in its folder.")
        return show_json(str(path), profile=profile)
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


def _module_path(module_address) -> tuple:
    """module.net[0].module.sg["a"] -> ('net', 'sg'), the names the configuration uses."""
    return tuple(re.findall(r'module\.([\w-]+)(?:\[(?:\d+|"(?:[^"\\]|\\.)*")\])?',
                            module_address or ""))


def configured_args(plan) -> dict | None:
    """{(module path, type, name): names of the arguments set in the code}, from the plan's
    configuration section, or None when the plan doesn't have one. dynamic blocks don't
    show up there."""
    root = (plan.get("configuration") or {}).get("root_module")
    if not isinstance(root, dict):
        return None
    out = {}

    def walk(module, path):
        if not isinstance(module, dict):
            return
        for res in module.get("resources") or []:
            if isinstance(res, dict) and res.get("mode", "managed") == "managed":
                out[(path, res.get("type"), res.get("name"))] = set(res.get("expressions") or {})
        for name, call in (module.get("module_calls") or {}).items():
            if isinstance(call, dict):
                walk(call.get("module"), path + (name,))
    walk(root, ())
    return out


def summarize(plan: dict) -> PlanSummary:
    # A plan always has planned_values (and resource_changes when anything changes). The
    # state's terraform show -json has neither, and reading it as a plan would say
    # "No changes" and "Nothing risky found".
    if not isinstance(plan, dict) or ("resource_changes" not in plan and "planned_values" not in plan):
        raise PlanError("That JSON isn't a Terraform plan. Give the output of terraform show "
                        "-json on a saved plan (terraform plan -out), not on the state.")
    rcs = plan.get("resource_changes") or []
    if not isinstance(rcs, list):
        raise PlanError("That JSON isn't a Terraform plan: resource_changes isn't a list.")
    config = configured_args(plan)
    changes, risks = [], []
    for rc in rcs:
        if not isinstance(rc, dict) or rc.get("mode") == "data":
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
        configured = None if config is None else config.get(
            (_module_path(rc.get("module_address")), rc.get("type"), rc.get("name")))
        risks += check_resource(rc, action, ch, configured)

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
    "aws_s3_bucket": ("policy", "resource"),
    "aws_sqs_queue": ("policy", "resource"),
    "aws_sns_topic": ("policy", "resource"),
}

# Arguments Terraform fills in by itself when the code doesn't set them, so a plan shows
# them as "known after apply" whenever they're left out. They only get the "couldn't check"
# note when the plan's configuration shows the code really sets them.
SELF_FILLED = {
    "aws_security_group": {"ingress"},
    "aws_kms_key": {"policy"},
    "aws_s3_bucket": {"policy", "acl"},
    "aws_sqs_queue": {"policy"},
    "aws_sns_topic": {"policy"},
    "aws_iam_role": {"inline_policy", "managed_policy_arns"},
}

PUBLIC_ACLS = ("public-read", "public-read-write", "authenticated-read")


def first(value):
    if isinstance(value, list):
        return value[0] if value else {}
    return value or {}


def is_unknown(ch, key) -> bool:
    unk = ch.get("after_unknown") or {}
    return isinstance(unk, dict) and unk.get(key) is True


def has_unknown(value) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(has_unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(has_unknown(v) for v in value)
    return False


def unknown_risk(rtype, addr, ch, attr, configured=None, fields=()) -> list:
    """An info risk when attr is only known after apply, so it doesn't look checked and fine.
    fields: for a list of blocks, only these keys inside the blocks matter."""
    unk = ch.get("after_unknown")
    value = unk.get(attr) if isinstance(unk, dict) else None
    if value is True:
        if attr in SELF_FILLED.get(rtype, ()) and (configured is None or attr not in configured):
            return []  # not set in the code, AWS fills it in
    elif fields:
        blocks = value if isinstance(value, list) else [value]
        if not any(isinstance(b, dict) and has_unknown(b.get(f)) for b in blocks for f in fields):
            return []
    elif not has_unknown(value):
        return []
    return [Risk("info", addr, f"Couldn't check {attr}, it's only known after apply",
                 "Terraform only works this value out while it applies, so the plan can't show "
                 "what it allows.", "Check it after apply, for example with Exposure Audit or "
                 "Policy Check.")]


def world(cidrs) -> list:
    return [c for c in cidrs or [] if c in ("0.0.0.0/0", "::/0")]


def acl_risks(addr, acl) -> list:
    if acl not in PUBLIC_ACLS:
        return []
    return [Risk("high", addr, f"Bucket ACL is {acl}",
                 "Objects can be read by anyone" +
                 (" and written by anyone." if acl == "public-read-write" else "."),
                 "Use private and serve public files through CloudFront with OAC.")]


def admin_policy_risks(addr, arn) -> list:
    arn = str(arn or "")
    name = arn.rsplit("/", 1)[-1]
    if name in ADMIN_POLICIES and ":aws:policy/" in arn:
        return [Risk(ADMIN_POLICIES[name], addr, f"Attaches {name}",
                     "This gives broad or full control of the account.",
                     "Use a policy with only the actions this needs.")]
    return []


def public_db_risk(addr) -> Risk:
    return Risk("high", addr, "Database is publicly accessible",
                "It gets a public endpoint. Only its security group stands between it and the "
                "internet.", "Set publicly_accessible = false.")


def open_risk(sev, addr, label, cidrs) -> Risk:
    if sev == "info":
        return Risk(sev, addr, f"Open to the internet: {label}",
                    f"Ingress from {', '.join(cidrs)}. Normal for a public website.")
    return Risk(sev, addr, f"Open to the internet: {label}", f"Ingress from {', '.join(cidrs)}.",
                "Limit the source to your IP, a VPN range, or another security group. "
                "For admin access, SSM Session Manager needs no open ports at all.")


def check_resource(rc, action, ch, configured=None) -> list:
    """Risks for one resource change. configured is the set of arguments the code sets for
    it (see configured_args), or None when the plan doesn't say."""
    rtype = rc.get("type", "")
    addr = rc.get("address", "")
    after = ch.get("after") or {}
    before = ch.get("before") or {}
    if not isinstance(before, dict):
        before = {}
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
    if rtype == "aws_security_group":
        for rule in after.get("ingress") or []:
            cidrs = world((rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or []))
            if cidrs:
                sev, label = open_port_risk(rule.get("protocol"), rule.get("from_port"),
                                            rule.get("to_port"))
                out.append(open_risk(sev, addr, label, cidrs))
        out += unknown_risk(rtype, addr, ch, "ingress", configured,
                            fields=("cidr_blocks", "ipv6_cidr_blocks"))
    elif rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        cidrs = world((after.get("cidr_blocks") or []) + (after.get("ipv6_cidr_blocks") or []))
        if cidrs:
            sev, label = open_port_risk(after.get("protocol"), after.get("from_port"),
                                        after.get("to_port"))
            out.append(open_risk(sev, addr, label, cidrs))
        for attr in ("cidr_blocks", "ipv6_cidr_blocks"):
            out += unknown_risk(rtype, addr, ch, attr, configured)
    elif rtype == "aws_vpc_security_group_ingress_rule":
        cidrs = world([after.get("cidr_ipv4"), after.get("cidr_ipv6")])
        if cidrs:
            sev, label = open_port_risk(after.get("ip_protocol"), after.get("from_port"),
                                        after.get("to_port"))
            out.append(open_risk(sev, addr, label, cidrs))
        for attr in ("cidr_ipv4", "cidr_ipv6"):
            out += unknown_risk(rtype, addr, ch, attr, configured)

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
        out += acl_risks(addr, after.get("acl"))
        for grant in (first(after.get("access_control_policy")).get("grant") or []):
            uri = str(first(grant.get("grantee")).get("uri", ""))
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                out.append(Risk("high", addr, "Bucket ACL grants access to everyone",
                                f"Grantee {uri.rsplit('/', 1)[-1]} gets {grant.get('permission')}."))
    elif rtype == "aws_s3_bucket":
        out += acl_risks(addr, after.get("acl"))  # the older inline acl argument
        out += unknown_risk(rtype, addr, ch, "acl", configured)
        if after.get("force_destroy") is True:
            out.append(Risk("low", addr, "force_destroy is on",
                            "terraform destroy will delete this bucket even with objects in it."))

    # ---- IAM attachments and keys
    elif rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
                   "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"):
        out += admin_policy_risks(addr, after.get("policy_arn"))
    elif rtype == "aws_iam_role":
        # managed_policy_arns and inline_policy, both deprecated but still used. Only what's
        # new in this plan gets flagged, like the policy checks below.
        had = set(before.get("managed_policy_arns") or [])
        for arn in after.get("managed_policy_arns") or []:
            if arn not in had:
                out += admin_policy_risks(addr, arn)
        out += unknown_risk(rtype, addr, ch, "managed_policy_arns", configured)
        had = {b.get("policy") for b in before.get("inline_policy") or [] if isinstance(b, dict)}
        for block in after.get("inline_policy") or []:
            if isinstance(block, dict) and block.get("policy") not in had:
                where = f"inline policy {block['name']}" if block.get("name") else "inline policy"
                out += check_policy_text(addr, block.get("policy"), "identity", where)
        out += unknown_risk(rtype, addr, ch, "inline_policy", configured, fields=("policy",))
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
            out.append(public_db_risk(addr))
        if after.get("storage_encrypted") is False:
            out.append(Risk("medium", addr, "Database storage not encrypted",
                            "Encryption can't be turned on later without a rebuild.",
                            "Set storage_encrypted = true."))
    elif rtype == "aws_rds_cluster" and after.get("storage_encrypted") is False:
        out.append(Risk("medium", addr, "Aurora storage not encrypted",
                        fix="Set storage_encrypted = true."))
    elif rtype == "aws_rds_cluster_instance" and after.get("publicly_accessible") is True:
        out.append(public_db_risk(addr))
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
        out += unknown_risk(rtype, addr, ch, attr, configured)
        text = after.get(attr)
        if text != before.get(attr):  # unchanged policy, don't re-flag it on every plan
            out += check_policy_text(addr, text, kind)
    return out


def check_policy_text(addr, text, kind, where="") -> list:
    """Policy Check's medium and worse findings for one policy document, as risks."""
    if not text or not isinstance(text, str):
        return []
    try:
        doc, _ = iampolicy.load_policy(text)
    except iampolicy.PolicyError:
        return []
    out = []
    for f in iampolicy.analyze(doc, kind):
        if f.severity in ("critical", "high", "medium"):
            places = ", ".join(p for p in (where, f.where) if p)
            detail = f.detail + (f" ({places})" if places else "")
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
