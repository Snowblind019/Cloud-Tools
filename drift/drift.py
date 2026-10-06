"""Drift: compares Terraform state with what's really in the AWS account.

It lists three things:

- Not in Terraform: in the account, but none of the states you gave know about it, like
  something made by hand in the console.
- Gone: in a state, but not in the account any more. The next apply makes it again.
- Changed: in both, but a setting that matters is different now.

Read-only. It reads state files (or runs terraform show -json in a folder you pick) and
makes describe, list and get calls. State files hold secrets like database passwords and
private keys, so only the few settings it compares are read out of them, and a value
Terraform marks as sensitive is never shown.

tfplan, maptf and sweep are imported inside the functions that use them, because the
awskit command line imports this module for every command.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from .common import (AuthError, AwsContext, error_code, error_text, is_access_denied,
                     load_config, paginate, save_config, tags_dict, write_atomic)

MAX_INPUT_BYTES = 200 * 1024 * 1024
MAX_TAG_CALLS = 400        # per type and region, for types whose listing has no tags
CONFIG_KEY = "drift"
DEFAULT_SETTINGS = {"ignore": ["tag:awskit:drift-ignore"]}
NOT_SET = "(not set)"
NOT_THERE = "(not there)"
HIDDEN = "(sensitive, not shown)"


class DriftError(Exception):
    """A source couldn't be read. The message says why, in plain words."""


class NeedsTerraform(DriftError):
    """Reading this source means running Terraform, and the caller said not to."""


# =================================================================== types

# What Drift reads from the account, by the Terraform type it matches. Other Terraform
# types are counted but not read on their own (see CHILD_TYPES for the ones that are
# compared as part of their parent).
TYPE_LABELS = {
    "aws_vpc": "VPC", "aws_subnet": "Subnet", "aws_route_table": "Route table",
    "aws_internet_gateway": "Internet gateway", "aws_nat_gateway": "NAT gateway",
    "aws_eip": "Elastic IP", "aws_security_group": "Security group",
    "aws_network_acl": "Network ACL", "aws_vpc_endpoint": "VPC endpoint",
    "aws_instance": "EC2 instance", "aws_ebs_volume": "EBS volume", "aws_lb": "Load balancer",
    "aws_db_instance": "RDS instance", "aws_rds_cluster_instance": "RDS cluster instance",
    "aws_s3_bucket": "S3 bucket", "aws_iam_role": "IAM role", "aws_iam_user": "IAM user",
    "aws_iam_policy": "IAM policy", "aws_lambda_function": "Lambda function",
    "aws_dynamodb_table": "DynamoDB table", "aws_sns_topic": "SNS topic",
    "aws_sqs_queue": "SQS queue", "aws_kms_key": "KMS key",
    "aws_secretsmanager_secret": "Secrets Manager secret",
    "aws_cloudwatch_log_group": "CloudWatch log group", "aws_ecr_repository": "ECR repository",
}

# Terraform types that manage the same thing as another type.
FAMILY = {
    "aws_default_vpc": "aws_vpc", "aws_default_subnet": "aws_subnet",
    "aws_default_security_group": "aws_security_group",
    "aws_default_network_acl": "aws_network_acl", "aws_default_route_table": "aws_route_table",
    "aws_alb": "aws_lb",
}

# Types that aren't read on their own but fill in their parent: routes, security group
# rules, role policy attachments and bucket versioning.
CHILD_TYPES = {
    "aws_route": "aws_route_table", "aws_security_group_rule": "aws_security_group",
    "aws_vpc_security_group_ingress_rule": "aws_security_group",
    "aws_vpc_security_group_egress_rule": "aws_security_group",
    "aws_iam_role_policy_attachment": "aws_iam_role",
    "aws_iam_policy_attachment": "aws_iam_role",
    "aws_s3_bucket_versioning": "aws_s3_bucket",
}

# Types that count toward "a type my Terraform manages" for their parent's type.
SCOPE_PARENT = dict(CHILD_TYPES, aws_route_table_association="aws_route_table",
                    aws_main_route_table_association="aws_route_table",
                    aws_network_acl_rule="aws_network_acl",
                    aws_network_acl_association="aws_network_acl",
                    aws_volume_attachment="aws_ebs_volume",
                    aws_internet_gateway_attachment="aws_internet_gateway",
                    aws_eip_association="aws_eip", aws_iam_role_policy="aws_iam_role",
                    aws_iam_user_policy_attachment="aws_iam_user",
                    aws_iam_user_policy="aws_iam_user", aws_sqs_queue_policy="aws_sqs_queue",
                    aws_sns_topic_policy="aws_sns_topic", aws_kms_alias="aws_kms_key",
                    aws_secretsmanager_secret_version="aws_secretsmanager_secret",
                    aws_lambda_permission="aws_lambda_function",
                    aws_ecr_lifecycle_policy="aws_ecr_repository",
                    aws_ecr_repository_policy="aws_ecr_repository",
                    aws_lb_listener="aws_lb", aws_alb_listener="aws_lb")

GLOBAL_FAMILIES = {"aws_iam_role", "aws_iam_user", "aws_iam_policy"}

# The attribute in the state that holds the ID the live side uses (and that terraform
# import takes). Anything not listed uses "id".
ID_ATTR = {
    "aws_db_instance": "identifier", "aws_rds_cluster_instance": "identifier",
    "aws_s3_bucket": "bucket", "aws_iam_role": "name", "aws_iam_user": "name",
    "aws_iam_policy": "arn", "aws_lambda_function": "function_name",
    "aws_dynamodb_table": "name", "aws_sns_topic": "arn", "aws_kms_key": "key_id",
    "aws_secretsmanager_secret": "arn", "aws_cloudwatch_log_group": "name",
    "aws_ecr_repository": "name", "aws_lb": "arn",
}
# Where a readable name comes from when there's no Name tag.
NAME_ATTR = {
    "aws_security_group": "name", "aws_lb": "name", "aws_db_instance": "identifier",
    "aws_rds_cluster_instance": "identifier", "aws_s3_bucket": "bucket",
    "aws_iam_role": "name", "aws_iam_user": "name", "aws_iam_policy": "name",
    "aws_lambda_function": "function_name", "aws_dynamodb_table": "name",
    "aws_sns_topic": "name", "aws_sqs_queue": "name", "aws_kms_key": "description",
    "aws_secretsmanager_secret": "name", "aws_cloudwatch_log_group": "name",
    "aws_ecr_repository": "name",
}

# Tags other tools and services put on what they make. First match wins, so the more
# specific ones come first (an EKS node is also in an Auto Scaling group, and Elastic
# Beanstalk builds its environments with CloudFormation).
OWNER_TAGS = (
    ("eks:nodegroup-name", "EKS", "node group {}"),
    ("eks:cluster-name", "EKS", "cluster {}"),
    ("aws:eks:cluster-name", "EKS", "cluster {}"),
    ("karpenter.sh/nodepool", "Karpenter", "node pool {}"),
    ("karpenter.sh/provisioner-name", "Karpenter", "provisioner {}"),
    ("elbv2.k8s.aws/cluster", "EKS (load balancer controller)", "cluster {}"),
    ("elasticbeanstalk:environment-name", "Elastic Beanstalk", "environment {}"),
    ("aws:autoscaling:groupName", "Auto Scaling", "group {}"),
    ("aws:elasticmapreduce:job-flow-id", "EMR", "cluster {}"),
    ("aws:ec2spot:fleet-request-id", "Spot Fleet", "request {}"),
    ("aws:ec2:fleet-id", "EC2 Fleet", "fleet {}"),
    ("aws:cloud9:environment", "Cloud9", "environment {}"),
    ("opsworks:stack", "OpsWorks", "stack {}"),
    ("AmazonECSManaged", "ECS", "capacity provider"),
    ("aws:servicecatalog:provisionedProductArn", "Service Catalog", "product {}"),
    ("aws:cloudformation:stack-name", "CloudFormation", "stack {}"),
)
OWNER_SERVICES = {"rds": "RDS", "redshift": "Redshift", "appflow": "AppFlow",
                  "alb": "Elastic Load Balancing", "nlb": "Elastic Load Balancing",
                  "rnat": "NAT gateway", "ecs-sc": "ECS", "events": "EventBridge"}
TERRAFORM_TAG = re.compile(r"^(managed[-_ ]?by|terraform|iac|provisioner|tool)$", re.I)

# Attribute names whose values are never shown, whether or not the state marks them.
SECRET_NAME = re.compile(r"password|passwd|secret|private_key|privatekey|token|credential|"
                         r"passphrase|key_material|user_data|auth_key", re.I)

STATUS_LABEL = {"unmanaged": "Not in Terraform", "gone": "Gone", "changed": "Changed"}
STATUS_SEVERITY = {"gone": "high", "changed": "medium", "unmanaged": "low", "other": "info"}
STATUS_ORDER = {"gone": 0, "changed": 1, "unmanaged": 2, "other": 3}


def type_label(family) -> str:
    return TYPE_LABELS.get(FAMILY.get(family, family), family)


def type_words(family) -> str:
    """The type's name for the middle of a sentence: "security group", but "EC2 instance"."""
    text = type_label(family)
    first = text.split(" ", 1)[0]
    return text if first.isupper() or first in ("Elastic", "Lambda", "DynamoDB", "Secrets",
                                                "CloudWatch") else text[:1].lower() + text[1:]


# =================================================================== settings

def load_settings() -> dict:
    """This tool's settings from the awskit config, under its own key."""
    out = json.loads(json.dumps(DEFAULT_SETTINGS))
    mine = load_config().get(CONFIG_KEY)
    if isinstance(mine, dict) and isinstance(mine.get("ignore"), list):
        out["ignore"] = [str(x).strip() for x in mine["ignore"]
                         if isinstance(x, (str, int)) and str(x).strip()][:2000]
    return out


def save_settings(values: dict) -> bool:
    """Save this tool's settings, keeping every other key in the config file as it is."""
    cfg = load_config()
    current = load_settings()
    if isinstance(values.get("ignore"), list):
        current["ignore"] = [str(x).strip() for x in values["ignore"] if str(x).strip()]
    cfg[CONFIG_KEY] = current
    return save_config(cfg)


class IgnoreList:
    """Entries are IDs, ARNs, names or Terraform addresses, or tag:KEY and tag:KEY=VALUE."""

    def __init__(self, entries=()):
        self.ids = set()
        self.tags = []
        for e in entries or []:
            e = str(e).strip()
            if not e or e.startswith("#"):
                continue
            if e.lower().startswith("tag:"):
                key, sep, value = e[4:].partition("=")
                if key.strip():
                    self.tags.append((key.strip(), value.strip() if sep else None))
            else:
                self.ids.add(e)

    def matches(self, ids=(), tags=None) -> bool:
        if any(i and i in self.ids for i in ids):
            return True
        if tags:
            for key, value in self.tags:
                if key in tags and (value is None or tags[key] == value):
                    return True
        return False


# =================================================================== reading Terraform

@dataclass
class Managed:
    """One managed resource from a state, cut down to what Drift compares. It never holds
    attributes it doesn't compare, so it can't leak them."""
    stack: str
    address: str
    type: str
    family: str
    id: str
    name: str = ""
    region: str = ""
    account: str = ""
    module: str = ""
    tags: dict | None = None
    secret_tags: set = field(default_factory=set)   # "*" means every tag value
    settings: dict = field(default_factory=dict)
    hidden: list = field(default_factory=list)      # settings not compared, marked sensitive
    group: str = ""                                 # provider and module, for region guesses

    @property
    def key(self) -> str:
        return match_key(self.family, self.id)


@dataclass
class Stack:
    label: str
    path: str
    kind: str                                       # state, plan or folder
    resources: list = field(default_factory=list)   # Managed
    children: list = field(default_factory=list)    # (kind, parent id, payload)
    covered: set = field(default_factory=set)       # (family, id) a managed thing implies
    names: set = field(default_factory=set)         # (type, name) in the root module
    total: int = 0
    unread: Counter = field(default_factory=Counter)
    plan_drift: list = field(default_factory=list)  # resource drift a plan file carried
    tf_version: str = ""
    child_account: str = ""                         # the account children belong to

    @property
    def is_folder(self) -> bool:
        return self.kind == "folder"

    @property
    def regions(self) -> set:
        return {m.region for m in self.resources if m.region and m.region != "global"}

    @property
    def accounts(self) -> set:
        return {m.account for m in self.resources if m.account}


def _read_input(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DriftError(f"Couldn't read {path}: {exc.strerror or exc}") from exc
    if size > MAX_INPUT_BYTES:
        raise DriftError(f"{path.name} is bigger than {MAX_INPUT_BYTES // (1024 * 1024)} MB, "
                         "which is too big to be a state file.")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DriftError(f"Couldn't read {path}: {exc.strerror or exc}") from exc


def parse_json(data, name="input") -> dict:
    if isinstance(data, bytes):
        if len(data) > MAX_INPUT_BYTES:
            raise DriftError(f"{name} is too big to be a state file.")
        data = data.decode("utf-8-sig", errors="replace")
    text = (data or "").strip()
    if text.startswith("["):
        raise DriftError(f"{name} isn't a Terraform state or plan.")
    if not text.startswith("{"):
        raise DriftError(f"{name} isn't JSON. Give a terraform.tfstate file, the output of "
                         "terraform show -json, plan JSON, or a Terraform folder. For a saved "
                         "binary plan, run terraform show -json on it first.")
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise DriftError(f"{name} isn't valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise DriftError(f"{name} isn't a Terraform state or plan.")
    return doc


def load_source(source, profile=None, run_terraform=True, log=None, label=None) -> Stack:
    """A state file (raw or terraform show -json), plan JSON, or a Terraform folder.
    A folder runs terraform show -json there, which runs that folder's code, so with
    run_terraform=False a folder raises NeedsTerraform instead."""
    if source == "-":
        data = parse_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1), "stdin")
        return build_stack(data, label or "stdin", "-", "state")
    path = Path(os.path.expanduser(str(source)))
    if path.is_dir():
        from . import tfplan
        if not run_terraform:
            raise NeedsTerraform(f"{path} is a folder. Reading it means running terraform show "
                                 "-json there.")
        if not tfplan.terraform_bin():
            raise DriftError("Terraform isn't installed or isn't in PATH, so the folder can't be "
                             "read. Give its state file instead (terraform state pull > "
                             "state.json).")
        if log:
            log(f"Running terraform show in {path.name}")
        try:
            data = tfplan.show_state(str(path), profile=profile)
        except tfplan.PlanError as exc:
            raise DriftError(str(exc)) from exc
        except RecursionError as exc:
            raise DriftError("terraform show printed JSON nested too deep to read.") from exc
        if not isinstance(data, dict):
            raise DriftError("terraform show didn't print a state.")
        return build_stack(data, label or path.resolve().name or str(path), str(path.resolve()),
                           "folder")
    if not path.is_file():
        raise DriftError(f"{source} doesn't exist. Give a state file, plan JSON, or a "
                         "Terraform folder.")
    data = parse_json(_read_input(path), path.name)
    return build_stack(data, label or path.name, str(path.resolve()), "state")


def source_kind(data) -> str:
    if "planned_values" in data or "resource_changes" in data or "prior_state" in data:
        return "plan"
    if "resources" in data and "version" in data:
        return "raw"
    if "values" in data or "format_version" in data:
        return "show"
    raise DriftError("That JSON isn't a Terraform state or plan. Give a terraform.tfstate "
                     "file, the output of terraform show -json, or plan JSON.")


def _raw_address(r, inst) -> str:
    """The same address maptf.flatten builds for a raw state instance."""
    prefix = "data." if r.get("mode") == "data" else ""
    addr = f"{prefix}{r['type']}.{r['name']}"
    idx = inst.get("index_key")
    if idx is not None:
        addr += f"[{json.dumps(idx)}]"
    if r.get("module"):
        addr = f"{r['module']}.{addr}"
    return addr


def _path_marks(paths) -> dict:
    """A raw state's sensitive_attributes (a list of paths) as nested marks like the ones
    terraform show -json uses: {"password": true}, or {"tags": {"Owner": true}} for one
    tag. Anything deeper than that marks the whole attribute. Marks in a shape Terraform
    doesn't write mark everything."""
    if paths is not None and not isinstance(paths, list):
        return True
    out = {}
    for p in paths or []:
        steps = p if isinstance(p, list) else [p]
        if not steps:
            continue
        first = steps[0]
        if isinstance(first, dict) and first.get("type", "get_attr") == "get_attr":
            name = first.get("value")
        else:
            name = first if isinstance(first, str) else None
        if not isinstance(name, str) or not name:
            continue
        if name in ("tags", "tags_all") and len(steps) > 1 and out.get(name) is not True:
            second = steps[1]
            key = second.get("value") if isinstance(second, dict) else None
            if isinstance(key, dict):  # {"value": "Owner", "type": "string"}
                key = key.get("value")
            if isinstance(key, str):
                out.setdefault(name, {})[key] = True
                continue
        out[name] = True
    return out


def sensitive_marks(data, kind) -> dict:
    """{address: marks} for every resource, from sensitive_values (terraform show -json)
    or sensitive_attributes (raw state)."""
    out = {}
    if kind == "raw":
        for r in data.get("resources") or []:
            if not isinstance(r, dict) or "type" not in r or "name" not in r:
                continue
            for inst in r.get("instances") or []:
                if isinstance(inst, dict):
                    out[_raw_address(r, inst)] = _path_marks(inst.get("sensitive_attributes"))
        return out

    # Terraform before 0.15 (format 0.1) didn't write sensitive_values at all. Since then
    # it's always there, so a missing or odd one means the marks can't be trusted.
    old_format = str(data.get("format_version", "")) in ("", "0.1")

    def walk(module):
        if not isinstance(module, dict):
            return
        for r in module.get("resources") or []:
            if isinstance(r, dict) and r.get("address"):
                marks = r.get("sensitive_values")
                if marks is None and old_format:
                    marks = {}
                out[r["address"]] = marks if isinstance(marks, (dict, bool)) else True
        for child in module.get("child_modules") or []:
            walk(child)
    if kind == "show":
        root = data.get("values")
    else:
        prior = data.get("prior_state")
        root = prior.get("values") if isinstance(prior, dict) else None
    walk(root.get("root_module") if isinstance(root, dict) else None)
    return out


def _has_true(marks) -> bool:
    """True when anything in marks is marked. A mark Terraform wouldn't write (a string or
    a number) counts as marked, so odd input hides values instead of showing them."""
    if isinstance(marks, dict):
        return any(_has_true(v) for v in marks.values())
    if isinstance(marks, list):
        return any(_has_true(v) for v in marks)
    if isinstance(marks, bool) or marks is None:
        return bool(marks)
    return True


class _Values:
    """Reads one resource's attributes, refusing the ones marked sensitive."""

    def __init__(self, values, marks):
        self.values = values if isinstance(values, dict) else {}
        self.all_secret = marks is True
        self.marks = marks if isinstance(marks, dict) else {}

    def secret(self, attr) -> bool:
        return self.all_secret or _has_true(self.marks.get(attr)) or bool(SECRET_NAME.search(attr))

    def get(self, attr, default=None):
        if self.secret(attr):
            return default
        v = self.values.get(attr)
        return default if v is None else v

    def text(self, attr) -> str:
        v = self.get(attr)
        if isinstance(v, str):
            return v
        return "" if v is None or isinstance(v, (dict, list)) else str(v)

    def blocks(self, attr) -> list:
        v = self.get(attr)
        if isinstance(v, dict):
            return [v]
        return [b for b in v if isinstance(b, dict)] if isinstance(v, list) else []

    def strings(self, attr) -> list:
        v = self.get(attr)
        if isinstance(v, str):
            return [v] if v else []
        if not isinstance(v, list):
            return []
        return [str(x) for x in v if isinstance(x, (str, int)) and str(x)]


def arn_parts(arn) -> tuple:
    """(region, account) from an ARN, or ("", "")."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return "", ""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "", ""
    return parts[3], parts[4]


def _cidr(text) -> str:
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False).compressed
    except ValueError:
        return str(text).strip().lower()


def match_key(family, ident) -> str:
    """The form an ID is matched in. SQS queues go by account and name, since a queue URL
    can be written with more than one host name. KMS keys go by key ID."""
    ident = str(ident or "")
    if family == "aws_sqs_queue":
        if ident.startswith("arn:"):
            parts = ident.split(":")
            return f"{parts[4]}/{parts[5]}" if len(parts) >= 6 else ident
        path = urlparse(ident).path.strip("/") if "://" in ident else ident
        bits = path.split("/")
        return "/".join(bits[-2:]) if len(bits) >= 2 else path
    if family == "aws_kms_key" and ident.startswith("arn:"):
        return ident.rsplit("/", 1)[-1]
    return ident


def build_stack(data, label, path, kind) -> Stack:
    """Reduce a state or plan to the managed AWS resources and the settings Drift compares.
    Values of other attributes are dropped here and never kept."""
    from . import maptf
    shape = source_kind(data)
    stack = Stack(label, path, "plan" if shape == "plan" and kind == "state" else kind,
                  tf_version=str(data.get("terraform_version", ""))[:40])
    if shape == "plan":
        prior = data.get("prior_state") if isinstance(data.get("prior_state"), dict) else {}
        flat_input = {"values": prior.get("values") or {}}
    elif shape == "show" and "values" not in data:
        flat_input = {"values": {}}  # terraform show -json of an empty state
    else:
        flat_input = data
    # A state can be hand-made or damaged: values of the wrong type, or nested very deep.
    # That's a plain "can't read it", never a crash.
    try:
        if shape == "plan":
            stack.plan_drift = parse_drift(data)
        resources, _, _ = maptf.flatten(flat_input)
        _reduce(stack, data, shape, resources, label)
    except maptf.TfError as exc:
        raise DriftError(str(exc)) from exc
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError) as exc:
        raise DriftError(f"{label} doesn't look like a Terraform state Drift can read "
                         f"({type(exc).__name__}).") from exc
    return stack


def _reduce(stack, data, shape, resources, label):
    marks = sensitive_marks(data, shape)

    managed = [r for r in resources if r.mode == "managed" and str(r.type).startswith("aws_")]
    stack.total = len(managed)
    readers = []
    for r in managed:
        # An address missing from the marks means they couldn't be read: treat every value
        # as sensitive, so only IDs and names that aren't marked get used.
        vals = _Values(r.values, marks.get(r.address, True))
        readers.append((r, vals))
        if not r.module:
            stack.names.add((r.type, r.name))

    for r, v in readers:
        rtype = r.type
        family = FAMILY.get(rtype, rtype)
        if rtype in CHILD_TYPES:
            stack.children += _child(rtype, v)
            continue
        if family not in TYPE_LABELS:
            stack.unread[rtype] += 1
            continue
        ident = v.text(ID_ATTR.get(family, "id")) or v.text("id")
        if family == "aws_sqs_queue":
            ident = v.text("url") or v.text("id")
        if family == "aws_eip":
            ident = v.text("allocation_id") or v.text("id")
        if not ident:
            stack.unread[rtype] += 1
            continue
        m = Managed(label, r.address, rtype, family, ident, module=r.module)
        _place(m, v, family)
        m.name = _name(v, family)
        _tags(m, v)
        m.settings, m.hidden = _settings(family, v, ident)
        for fam, cid in _covers(family, v):
            stack.covered.add((fam, cid))
        m.group = f"{r.provider}|{r.module}"
        stack.resources.append(m)

    _guess_places(stack, readers)


def _child(rtype, v) -> list:
    """Routes, rules, attachments and versioning, as (kind, parent id, payload)."""
    if rtype == "aws_route":
        dest = _route_dest(v, ("destination_cidr_block", "destination_ipv6_cidr_block",
                               "destination_prefix_list_id"))
        target = _route_target(v)
        rt = v.text("route_table_id")
        return [("route", rt, (dest, target))] if rt and dest else []
    if rtype == "aws_security_group_rule":
        sg = v.text("security_group_id")
        groups = [v.text("source_security_group_id")] if v.text("source_security_group_id") else []
        if v.get("self") is True:
            groups.append(sg)
        cidrs = v.strings("cidr_blocks") + v.strings("ipv6_cidr_blocks")
        atoms = rule_atoms(v.text("type") or "ingress", v.get("protocol"), v.get("from_port"),
                           v.get("to_port"), cidrs, v.strings("prefix_list_ids"), groups)
        return [("rule", sg, a) for a in atoms] if sg else []
    if rtype in ("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"):
        sg = v.text("security_group_id")
        direction = "ingress" if rtype.endswith("ingress_rule") else "egress"
        atoms = rule_atoms(direction, v.get("ip_protocol"), v.get("from_port"), v.get("to_port"),
                           [c for c in (v.text("cidr_ipv4"), v.text("cidr_ipv6")) if c],
                           [v.text("prefix_list_id")] if v.text("prefix_list_id") else [],
                           [v.text("referenced_security_group_id")]
                           if v.text("referenced_security_group_id") else [])
        return [("rule", sg, a) for a in atoms] if sg else []
    if rtype == "aws_iam_role_policy_attachment":
        role, arn = v.text("role"), v.text("policy_arn")
        return [("policy", role, arn)] if role and arn else []
    if rtype == "aws_iam_policy_attachment":
        arn = v.text("policy_arn")
        return [("policy", role, arn) for role in v.strings("roles")] if arn else []
    if rtype == "aws_s3_bucket_versioning":
        conf = v.blocks("versioning_configuration")
        status = conf[0].get("status") if conf else None
        bucket = v.text("bucket")
        if bucket and isinstance(status, str):
            return [("versioning", bucket, status == "Enabled")]
    return []


def _place(m, v, family):
    region = v.text("region")
    arn = v.text("arn")
    a_region, a_account = arn_parts(arn)
    if family in GLOBAL_FAMILIES:
        m.region = "global"
    elif region and re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d+", region):
        m.region = region
    elif a_region:
        m.region = a_region
    elif family == "aws_sqs_queue":
        host = urlparse(m.id).hostname or ""
        hit = re.match(r"sqs\.([a-z0-9-]+)\.amazonaws", host)
        m.region = hit.group(1) if hit else ""
    if not m.region:
        az = v.text("availability_zone")
        if re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d+[a-z]", az or ""):
            m.region = az[:-1]
    owner = v.text("owner_id")
    m.account = a_account or (owner if re.fullmatch(r"\d{12}", owner or "") else "")
    if not m.account and family == "aws_sqs_queue":
        key = match_key(family, m.id)
        if re.fullmatch(r"\d{12}", key.split("/")[0]):
            m.account = key.split("/")[0]


def _guess_places(stack, readers):
    """Fill in regions and accounts that the resource itself doesn't say, from what it
    points at (a NAT gateway's subnet), then from its provider, then from the stack."""
    by_id = {}
    for m in stack.resources:
        if m.region:
            by_id[m.id] = (m.region, m.account)
    refs = ("subnet_id", "vpc_id", "instance_id", "allocation_id", "network_interface_id",
            "security_group_id", "route_table_id")
    reader_of = {r.address: v for r, v in readers}
    for m in stack.resources:
        if m.region and m.account:
            continue
        v = reader_of.get(m.address)
        for attr in refs:
            ref = v.text(attr) if v else ""
            if ref in by_id:
                reg, acct = by_id[ref]
                m.region = m.region or (reg if reg != "global" else "")
                m.account = m.account or acct
                if m.region and m.account:
                    break
    groups = {}
    for m in stack.resources:
        if m.region and m.region != "global":
            groups.setdefault(m.group, Counter())[m.region] += 1
    regions = Counter(m.region for m in stack.resources if m.region and m.region != "global")
    accounts = Counter(m.account for m in stack.resources if m.account)
    for m in stack.resources:
        if not m.region:
            group = groups.get(m.group)
            if group and len(group) == 1:
                m.region = next(iter(group))
            elif len(regions) == 1:
                m.region = next(iter(regions))
        if not m.account and len(accounts) == 1:
            m.account = next(iter(accounts))
    stack.child_account = next(iter(accounts)) if len(accounts) == 1 else ""


def _name(v, family) -> str:
    if not v.all_secret and not _tag_secret(v, "Name"):
        for attr in ("tags_all", "tags"):
            tags = v.values.get(attr)
            if isinstance(tags, dict) and isinstance(tags.get("Name"), str) and tags["Name"]:
                return tags["Name"][:120]
    attr = NAME_ATTR.get(family)
    return v.text(attr)[:120] if attr else ""


def _tag_secret(v, key) -> bool:
    if v.all_secret:
        return True
    for attr in ("tags", "tags_all"):
        mk = v.marks.get(attr)
        if _has_true(mk.get(key)) if isinstance(mk, dict) else _has_true(mk):
            return True
    return False


def _tags(m, v):
    if v.all_secret:
        return
    tags_all, tags = v.values.get("tags_all"), v.values.get("tags")
    chosen = tags_all if isinstance(tags_all, dict) and (tags_all or not isinstance(tags, dict)) \
        else tags
    if not isinstance(chosen, dict):
        return
    m.tags = {str(k): "" if val is None else str(val) for k, val in chosen.items()}
    for attr in ("tags", "tags_all"):
        mk = v.marks.get(attr)
        if isinstance(mk, dict):
            m.secret_tags |= {k for k, x in mk.items() if _has_true(x)}
        elif _has_true(mk):
            m.secret_tags.add("*")


def _settings(family, v, ident) -> tuple:
    """(settings, hidden): the settings Drift compares for this type, and the ones it
    can't compare because the state marks them sensitive."""
    out, hidden = {}, []

    def want(attr, label):
        if attr in v.values and v.secret(attr):
            hidden.append(label)
            return False
        return attr in v.values

    if family == "aws_subnet" and want("map_public_ip_on_launch", "map_public_ip_on_launch"):
        if isinstance(v.get("map_public_ip_on_launch"), bool):
            out["public_ip"] = v.get("map_public_ip_on_launch")
    elif family == "aws_instance":
        if want("instance_type", "instance type") and v.text("instance_type"):
            out["instance_type"] = v.text("instance_type")
        groups = v.strings("vpc_security_group_ids")
        if want("vpc_security_group_ids", "security groups") and groups:
            out["security_groups"] = sorted(set(groups))
    elif family == "aws_security_group":
        has_in, has_out = want("ingress", "ingress rules"), want("egress", "egress rules")
        if (has_in or has_out) and not (v.secret("ingress") or v.secret("egress")):
            atoms = set()
            for direction in ("ingress", "egress"):
                for b in v.blocks(direction):
                    groups = [g for g in (b.get("security_groups") or []) if isinstance(g, str)]
                    if b.get("self") is True:
                        groups.append(ident)
                    atoms |= rule_atoms(direction, b.get("protocol"), b.get("from_port"),
                                        b.get("to_port"), _block_cidrs(b),
                                        list(b.get("prefix_list_ids") or []), groups)
            out["rules"] = atoms
    elif family == "aws_route_table" and want("route", "routes"):
        routes = {}
        for b in v.blocks("route"):
            vb = _Values(b, {})
            dest = _route_dest(vb, ("cidr_block", "ipv6_cidr_block", "destination_prefix_list_id"))
            target = _route_target(vb)
            if dest and target != "local":
                routes[dest] = target
        out["routes"] = routes
    elif family == "aws_iam_role":
        if want("assume_role_policy", "trust policy") and v.text("assume_role_policy"):
            doc = norm_policy(v.text("assume_role_policy"))
            if doc is not None:
                out["trust"] = doc
        if want("managed_policy_arns", "attached policies") and \
                isinstance(v.get("managed_policy_arns"), list):
            out["policies"] = set(v.strings("managed_policy_arns"))
    elif family == "aws_s3_bucket" and want("versioning", "versioning"):
        blocks = v.blocks("versioning")
        if blocks and isinstance(blocks[0].get("enabled"), bool):
            out["versioning"] = blocks[0]["enabled"]
    return out, hidden


def _block_cidrs(b) -> list:
    return list(b.get("cidr_blocks") or []) + list(b.get("ipv6_cidr_blocks") or [])


def _covers(family, v) -> list:
    """What a managed resource brings with it, so those don't show as made outside
    Terraform: a VPC's default security group, network ACL and main route table, and an
    instance's volumes."""
    out = []
    if family == "aws_vpc":
        for attr, fam in (("default_security_group_id", "aws_security_group"),
                          ("default_network_acl_id", "aws_network_acl"),
                          ("main_route_table_id", "aws_route_table"),
                          ("default_route_table_id", "aws_route_table")):
            if v.text(attr):
                out.append((fam, v.text(attr)))
    elif family == "aws_instance":
        for attr in ("root_block_device", "ebs_block_device"):
            for b in v.blocks(attr):
                if isinstance(b.get("volume_id"), str) and b["volume_id"]:
                    out.append(("aws_ebs_volume", b["volume_id"]))
    return out


# =================================================================== normalizing

ROUTE_TARGETS = ("gateway_id", "nat_gateway_id", "transit_gateway_id",
                 "vpc_peering_connection_id", "egress_only_gateway_id", "vpc_endpoint_id",
                 "network_interface_id", "local_gateway_id", "carrier_gateway_id",
                 "core_network_arn", "instance_id")
LIVE_ROUTE_TARGETS = ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
                      "EgressOnlyInternetGatewayId", "NetworkInterfaceId", "LocalGatewayId",
                      "CarrierGatewayId", "CoreNetworkArn", "InstanceId")


def _route_dest(v, keys) -> str:
    for k in keys:
        val = v.text(k)
        if val:
            return val if val.startswith("pl-") else _cidr(val)
    return ""


def _route_target(v) -> str:
    for k in ROUTE_TARGETS:
        val = v.text(k)
        if val:
            return val
    return ""


def _proto(p) -> str:
    s = str(p if p not in (None, "") else "-1").strip().lower()
    return {"all": "-1", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(s, s)


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def rule_atoms(direction, proto, fp, tp, cidrs=(), prefix_lists=(), groups=()) -> set:
    """One security group rule split into (direction, protocol, from, to, kind, source)
    pieces, one per source. Descriptions are left out on purpose."""
    proto = _proto(proto)
    if proto == "-1":
        fp = tp = None
    else:
        fp, tp = _num(fp), _num(tp)
    direction = "egress" if str(direction).lower() == "egress" else "ingress"
    out = set()
    for c in cidrs or []:
        if c:
            out.add((direction, proto, fp, tp, "cidr", _cidr(c)))
    for pl in prefix_lists or []:
        if pl:
            out.add((direction, proto, fp, tp, "pl", str(pl)))
    for g in groups or []:
        if g:
            out.add((direction, proto, fp, tp, "sg", str(g).split("/")[-1]))
    return out


def live_rule_atoms(perms, direction) -> set:
    out = set()
    for p in perms or []:
        out |= rule_atoms(direction, p.get("IpProtocol"), p.get("FromPort"), p.get("ToPort"),
                          [r.get("CidrIp") for r in p.get("IpRanges") or []] +
                          [r.get("CidrIpv6") for r in p.get("Ipv6Ranges") or []],
                          [r.get("PrefixListId") for r in p.get("PrefixListIds") or []],
                          [r.get("GroupId") for r in p.get("UserIdGroupPairs") or []])
    return out


def atom_text(a) -> str:
    direction, proto, fp, tp, _, src = a
    if proto == "-1":
        what = "all traffic"
    elif proto in ("icmp", "icmpv6"):
        what = proto.upper() + ("" if fp in (None, -1) else f" type {fp}")
    elif fp is None:
        what = proto
    elif fp == tp:
        what = f"{proto} {fp}"
    elif (fp, tp) == (0, 65535):
        what = f"{proto} all ports"
    else:
        what = f"{proto} {fp}-{tp}"
    return f"{what} {'from' if direction == 'ingress' else 'to'} {src}"


def _atom_sort(a):
    """Ingress first, then by protocol, ports and source."""
    def part(x):
        if x is None:
            return ""
        return f"{x:08d}" if isinstance(x, int) and x >= 0 else str(x)
    return (a[0] != "ingress",) + tuple(part(x) for x in a[1:])


def norm_policy(doc):
    """A policy document in a form where two that mean the same compare equal: keys
    sorted, one-item lists as plain values, lists in order, and account IDs in principals
    written the way IAM stores them. None when it can't be read."""
    if isinstance(doc, str):
        text = doc.strip()
        if text.startswith("%7B") or text.startswith("%7b"):
            text = unquote(text)
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            return None
    if not isinstance(doc, dict):
        return None
    try:
        return _canon(doc)
    except RecursionError:
        return None


def _canon(v, key=""):
    if isinstance(v, dict):
        return {k: _canon(x, k) for k, x in v.items()}
    if isinstance(v, list):
        items = [_canon(x, key) for x in v]
        if len(items) == 1:
            return items[0]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
    if key == "AWS" and isinstance(v, str) and re.fullmatch(r"\d{12}", v):
        return f"arn:aws:iam::{v}:root"
    return v


def policy_text(doc) -> str:
    return json.dumps(doc, sort_keys=True, separators=(", ", ": "), default=str)


# =================================================================== reading AWS

@dataclass
class Live:
    """One thing found in the account."""
    family: str
    id: str
    name: str = ""
    region: str = ""
    account: str = ""
    profile: str = ""
    tags: dict | None = None        # None: couldn't read them
    settings: dict = field(default_factory=dict)
    summary: str = ""
    aws_made: str = ""              # why it's left out, like "default VPC"
    owner: str = ""                 # another tool or service that manages it
    owner_detail: str = ""
    part_of: str = ""               # an instance it's deleted with
    pending_delete: str = ""        # KMS keys waiting to be deleted
    hint: str = ""

    @property
    def key(self) -> str:
        return match_key(self.family, self.id)


@dataclass
class LiveType:
    family: str
    label: str
    service: str
    scope: str
    scan: object


LIVE_TYPES: dict = {}


def live_type(family, service, scope="region"):
    def wrap(fn):
        LIVE_TYPES[family] = LiveType(family, TYPE_LABELS[family], service, scope, fn)
        return fn
    return wrap


class Scan:
    """Shared state for one read of the account: what's in a state (so extra calls are only
    made for those), notes about partial reads, and the stop flag."""

    def __init__(self, managed=None, cancel=None):
        self.managed = managed or {}
        self.cancel = cancel
        self.lock = threading.Lock()
        self.partial = {}
        self.skipped = Counter()
        self.unreadable = Counter()
        self._default_vpcs = {}

    def stopped(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def is_managed(self, family, ident) -> bool:
        return match_key(family, ident) in self.managed.get(family, ())

    def note(self, ctx, what, region, exc):
        with self.lock:
            key = (ctx.label, what, "denied" if is_access_denied(exc) else
                   error_text(exc, ctx.profile))
            self.partial.setdefault(key, set()).add(region)

    def default_vpcs(self, ctx, region) -> set:
        key = (ctx.label, region)
        with self.lock:
            if key in self._default_vpcs:
                return self._default_vpcs[key]
        try:
            found = {v["VpcId"] for v in ctx.client("ec2", region).describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])}
        except Exception:  # noqa: BLE001 - the VPC listing reports the problem itself
            found = set()
        with self.lock:
            self._default_vpcs[key] = found
        return found

    def fill_tags(self, ctx, region, label, lives, fetch):
        """One tag call per item, for types whose listing has no tags. Capped, so a region
        with thousands of log groups doesn't take forever."""
        budget = MAX_TAG_CALLS
        for lv in lives:
            if self.stopped():
                return
            if lv.aws_made:
                continue
            if budget <= 0 and not self.is_managed(lv.family, lv.id):
                with self.lock:
                    self.skipped[(ctx.label, label, region)] += 1
                continue
            budget -= 1
            try:
                lv.tags = fetch(lv)
            except Exception as exc:  # noqa: BLE001
                code = error_code(exc)
                if code in ("NoSuchTagSet", "NoSuchTagSetError", "ResourceNotFoundException",
                            "NoSuchEntity", "NotFoundException", "RepositoryNotFoundException"):
                    lv.tags = {}
                    continue
                self.note(ctx, f"tags of {label}s", region, exc)
                if is_access_denied(exc):
                    return  # the rest would be turned away too


def owner_of(tags) -> tuple:
    """(tool, detail) when tags say another tool or service made and manages this."""
    if not tags:
        return "", ""
    for key, owner, detail in OWNER_TAGS:
        if key in tags:
            return owner, detail.format(tags[key]) if "{}" in detail else detail
    for key in tags:
        if key.startswith("kubernetes.io/cluster/"):
            return "Kubernetes", "cluster " + key.split("/", 2)[-1]
    return "", ""


def terraform_tagged(tags) -> bool:
    for key, value in (tags or {}).items():
        if TERRAFORM_TAG.match(key) and re.search(r"terraform|opentofu|true", str(value), re.I):
            return True
    return False


def _tag_map(items, key="Key", value="Value") -> dict:
    out = {}
    for t in items or []:
        if isinstance(t, dict) and t.get(key) is not None:
            out[str(t[key])] = "" if t.get(value) is None else str(t[value])
    return out


# ---- network

@live_type("aws_vpc", "ec2")
def scan_vpcs(scan, ctx, region):
    out = []
    for v in paginate(ctx.client("ec2", region), "describe_vpcs", "Vpcs"):
        tags = tags_dict(v.get("Tags"))
        out.append(Live("aws_vpc", v["VpcId"], tags.get("Name", ""), tags=tags,
                        summary=v.get("CidrBlock", ""),
                        aws_made="the default VPC" if v.get("IsDefault") else ""))
    return out


@live_type("aws_subnet", "ec2")
def scan_subnets(scan, ctx, region):
    out = []
    for s in paginate(ctx.client("ec2", region), "describe_subnets", "Subnets"):
        tags = tags_dict(s.get("Tags"))
        out.append(Live("aws_subnet", s["SubnetId"], tags.get("Name", ""), tags=tags,
                        settings={"public_ip": bool(s.get("MapPublicIpOnLaunch"))},
                        summary=f"{s.get('CidrBlock', '')} in {s.get('AvailabilityZone', '')}",
                        aws_made="a default subnet" if s.get("DefaultForAz") else ""))
    return out


@live_type("aws_route_table", "ec2")
def scan_route_tables(scan, ctx, region):
    out = []
    for rt in paginate(ctx.client("ec2", region), "describe_route_tables", "RouteTables"):
        tags = tags_dict(rt.get("Tags"))
        routes = {}
        for r in rt.get("Routes") or []:
            if r.get("Origin") in ("CreateRouteTable", "EnableVgwRoutePropagation") or \
                    r.get("GatewayId") == "local":
                continue
            dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or \
                r.get("DestinationPrefixListId") or ""
            if not dest:
                continue
            if str(r.get("GatewayId", "")).startswith("vpce-") and r.get("DestinationPrefixListId"):
                continue  # a gateway endpoint's route, managed through the endpoint
            routes[dest if dest.startswith("pl-") else _cidr(dest)] = \
                {r[k] for k in LIVE_ROUTE_TARGETS if r.get(k)}
        main = any(a.get("Main") for a in rt.get("Associations") or [])
        out.append(Live("aws_route_table", rt["RouteTableId"], tags.get("Name", ""), tags=tags,
                        settings={"routes": routes},
                        summary=f"{len(routes)} route(s) in {rt.get('VpcId', '')}",
                        aws_made="a main route table" if main else ""))
    return out


@live_type("aws_internet_gateway", "ec2")
def scan_igws(scan, ctx, region):
    out = []
    defaults = None
    for g in paginate(ctx.client("ec2", region), "describe_internet_gateways", "InternetGateways"):
        tags = tags_dict(g.get("Tags"))
        vpcs = [a.get("VpcId") for a in g.get("Attachments") or [] if a.get("VpcId")]
        if vpcs and defaults is None:
            defaults = scan.default_vpcs(ctx, region)
        made = any(v in (defaults or ()) for v in vpcs)
        out.append(Live("aws_internet_gateway", g["InternetGatewayId"], tags.get("Name", ""),
                        tags=tags,
                        summary=("attached to " + ", ".join(vpcs)) if vpcs else "not attached",
                        aws_made="the default VPC's internet gateway" if made else ""))
    return out


@live_type("aws_nat_gateway", "ec2")
def scan_nats(scan, ctx, region):
    out = []
    flt = [{"Name": "state", "Values": ["pending", "available"]}]
    ec2 = ctx.client("ec2", region)
    for n in paginate(ec2, "describe_nat_gateways", "NatGateways", Filter=flt):
        tags = tags_dict(n.get("Tags"))
        kind = n.get("ConnectivityType", "public")
        out.append(Live("aws_nat_gateway", n["NatGatewayId"], tags.get("Name", ""), tags=tags,
                        summary=f"{kind} in {n.get('SubnetId', '')}"))
    return out


@live_type("aws_eip", "ec2")
def scan_eips(scan, ctx, region):
    out = []
    for a in ctx.client("ec2", region).describe_addresses().get("Addresses", []):
        if not a.get("AllocationId"):
            continue
        tags = tags_dict(a.get("Tags"))
        owner = OWNER_SERVICES.get(str(a.get("ServiceManaged", "")).lower(),
                                   str(a.get("ServiceManaged", "")))
        attached = a.get("InstanceId") or a.get("NetworkInterfaceId") or ""
        where = f", on {attached}" if attached else ", not attached"
        out.append(Live("aws_eip", a["AllocationId"], tags.get("Name", ""), tags=tags,
                        summary=a.get("PublicIp", "") + where,
                        owner=owner, owner_detail="manages this address" if owner else ""))
    return out


@live_type("aws_security_group", "ec2")
def scan_sgs(scan, ctx, region):
    out = []
    for g in paginate(ctx.client("ec2", region), "describe_security_groups", "SecurityGroups"):
        tags = tags_dict(g.get("Tags"))
        atoms = live_rule_atoms(g.get("IpPermissions"), "ingress") | \
            live_rule_atoms(g.get("IpPermissionsEgress"), "egress")
        default = g.get("GroupName") == "default"
        out.append(Live("aws_security_group", g["GroupId"],
                        tags.get("Name") or g.get("GroupName", ""),
                        tags=tags, settings={"rules": atoms},
                        summary=f"{g.get('GroupName', '')} in {g.get('VpcId', '')}",
                        aws_made="a default security group" if default else ""))
    return out


@live_type("aws_network_acl", "ec2")
def scan_nacls(scan, ctx, region):
    out = []
    for n in paginate(ctx.client("ec2", region), "describe_network_acls", "NetworkAcls"):
        tags = tags_dict(n.get("Tags"))
        out.append(Live("aws_network_acl", n["NetworkAclId"], tags.get("Name", ""), tags=tags,
                        summary=f"in {n.get('VpcId', '')}",
                        aws_made="a default network ACL" if n.get("IsDefault") else ""))
    return out


@live_type("aws_vpc_endpoint", "ec2")
def scan_endpoints(scan, ctx, region):
    out = []
    for e in paginate(ctx.client("ec2", region), "describe_vpc_endpoints", "VpcEndpoints"):
        if str(e.get("State", "")).lower() in ("deleted", "deleting", "failed"):
            continue
        tags = tags_dict(e.get("Tags"))
        out.append(Live("aws_vpc_endpoint", e["VpcEndpointId"], tags.get("Name", ""), tags=tags,
                        summary=f"{e.get('ServiceName', '').split('.')[-1]}, "
                                f"{e.get('VpcEndpointType', '')} in {e.get('VpcId', '')}"))
    return out


# ---- compute and storage

@live_type("aws_instance", "ec2")
def scan_instances(scan, ctx, region):
    out = []
    flt = [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
    ec2 = ctx.client("ec2", region)
    for res in paginate(ec2, "describe_instances", "Reservations", Filters=flt):
        for i in res.get("Instances", []):
            tags = tags_dict(i.get("Tags"))
            groups = sorted({g["GroupId"] for g in i.get("SecurityGroups") or []
                             if g.get("GroupId")})
            # Volumes deleted with the instance belong to it, not to anything on their own.
            volumes = []
            for b in i.get("BlockDeviceMappings") or []:
                ebs = b.get("Ebs") or {}
                if ebs.get("VolumeId") and ebs.get("DeleteOnTermination"):
                    volumes.append(ebs["VolumeId"])
            state = i.get("State", {}).get("Name", "")
            out.append(Live("aws_instance", i["InstanceId"], tags.get("Name", ""), tags=tags,
                            settings={"instance_type": i.get("InstanceType", ""),
                                      "security_groups": groups, "volumes": volumes},
                            summary=f"{i.get('InstanceType', '')}, {state}"))
    return out


@live_type("aws_ebs_volume", "ec2")
def scan_volumes(scan, ctx, region):
    out = []
    for v in paginate(ctx.client("ec2", region), "describe_volumes", "Volumes"):
        tags = tags_dict(v.get("Tags"))
        part_of = ""
        for a in v.get("Attachments") or []:
            if a.get("DeleteOnTermination") and a.get("InstanceId"):
                part_of = a["InstanceId"]
        attached = [a.get("InstanceId") for a in v.get("Attachments") or [] if a.get("InstanceId")]
        out.append(Live("aws_ebs_volume", v["VolumeId"], tags.get("Name", ""), tags=tags,
                        summary=f"{v.get('Size', '?')} GB {v.get('VolumeType', '')}" +
                                (f", on {', '.join(attached)}" if attached else ", not attached"),
                        part_of=part_of))
    return out


@live_type("aws_lb", "elbv2")
def scan_lbs(scan, ctx, region):
    elb = ctx.client("elbv2", region)
    out = []
    for lb in paginate(elb, "describe_load_balancers", "LoadBalancers"):
        out.append(Live("aws_lb", lb["LoadBalancerArn"], lb.get("LoadBalancerName", ""),
                        summary=f"{lb.get('Type', '')}, {lb.get('Scheme', '')}"))
    try:
        for i in range(0, len(out), 20):
            if scan.stopped():
                break
            batch = out[i:i + 20]
            found = elb.describe_tags(ResourceArns=[lv.id for lv in batch]).get(
                "TagDescriptions", [])
            tags = {d.get("ResourceArn"): _tag_map(d.get("Tags")) for d in found}
            for lv in batch:
                lv.tags = tags.get(lv.id, {})
    except Exception as exc:  # noqa: BLE001
        scan.note(ctx, "tags of load balancers", region, exc)
    return out


@live_type("aws_db_instance", "rds")
def scan_rds(scan, ctx, region):
    out = []
    for db in paginate(ctx.client("rds", region), "describe_db_instances", "DBInstances"):
        family = "aws_rds_cluster_instance" if db.get("DBClusterIdentifier") else "aws_db_instance"
        dbid = db["DBInstanceIdentifier"]
        out.append(Live(family, dbid, dbid, tags=_tag_map(db.get("TagList")),
                        summary=f"{db.get('Engine', '')} {db.get('DBInstanceClass', '')}, "
                                f"{db.get('DBInstanceStatus', '')}"))
    return out


@live_type("aws_s3_bucket", "s3", scope="global")
def scan_buckets(scan, ctx, region):
    s3 = ctx.client("s3", "us-east-1")
    out = []
    for b in s3.list_buckets().get("Buckets", []):
        if scan.stopped():
            break
        name = b["Name"]
        loc = b.get("BucketRegion")
        try:
            if not loc:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
                loc = {"EU": "eu-west-1"}.get(loc, loc)
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) == "NoSuchBucket":
                continue
            scan.note(ctx, "S3 bucket locations", "global", exc)
            loc = ""
        lv = Live("aws_s3_bucket", name, name, region=loc or "us-east-1", summary="")
        rs3 = ctx.client("s3", loc or "us-east-1")
        try:
            lv.tags = _tag_map(rs3.get_bucket_tagging(Bucket=name).get("TagSet"))
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) in ("NoSuchTagSet", "NoSuchTagSetError"):
                lv.tags = {}
            elif error_code(exc) == "NoSuchBucket":
                continue
            else:
                scan.note(ctx, "tags of S3 buckets", "global", exc)
        if scan.is_managed("aws_s3_bucket", name):
            try:
                status = rs3.get_bucket_versioning(Bucket=name).get("Status")
                lv.settings["versioning"] = status == "Enabled"
            except Exception as exc:  # noqa: BLE001
                scan.note(ctx, "S3 bucket versioning", "global", exc)
        made = b.get("CreationDate")
        lv.summary = f"created {made:%Y-%m-%d}" if hasattr(made, "strftime") else ""
        out.append(lv)
    return out


# ---- IAM

def _role_owner(name, path) -> tuple:
    if name == "OrganizationAccountAccessRole":
        return "AWS Organizations", "made when the account was created"
    if name.startswith("stacksets-exec-") or name == "AWSCloudFormationStackSetExecutionRole":
        return "CloudFormation StackSets", "StackSets runs as this role"
    if path.startswith("/aws-controltower/") or name.startswith("AWSControlTower"):
        return "Control Tower", "made by Control Tower"
    return "", ""


@live_type("aws_iam_role", "iam", scope="global")
def scan_roles(scan, ctx, region):
    iam = ctx.client("iam")
    out = []
    for r in paginate(iam, "list_roles", "Roles"):
        name, path = r["RoleName"], r.get("Path", "/")
        made = ""
        if path.startswith("/aws-service-role/"):
            made = "a service-linked role"
        elif path.startswith("/aws-reserved/"):
            made = "an IAM Identity Center role"
        owner, detail = _role_owner(name, path)
        doc = r.get("AssumeRolePolicyDocument")
        trust = norm_policy(doc if isinstance(doc, (dict, str)) else "")
        lv = Live("aws_iam_role", name, name, region="global", aws_made=made, owner=owner,
                  owner_detail=detail, summary=f"path {path}")
        if trust is not None:
            lv.settings["trust"] = trust
        out.append(lv)
    scan.fill_tags(ctx, "global", "IAM role", out, lambda lv: _tag_map(
        list(paginate(iam, "list_role_tags", "Tags", RoleName=lv.id))))
    for lv in out:
        if scan.stopped():
            break
        if not scan.is_managed("aws_iam_role", lv.id):
            continue
        try:
            lv.settings["policies"] = {p["PolicyArn"] for p in paginate(
                iam, "list_attached_role_policies", "AttachedPolicies", RoleName=lv.id)}
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) == "NoSuchEntity":
                continue
            scan.note(ctx, "attached policies of IAM roles", "global", exc)
            if is_access_denied(exc):
                break
    return out


@live_type("aws_iam_user", "iam", scope="global")
def scan_users(scan, ctx, region):
    iam = ctx.client("iam")
    out = [Live("aws_iam_user", u["UserName"], u["UserName"], region="global",
                summary=f"path {u.get('Path', '/')}")
           for u in paginate(iam, "list_users", "Users")]
    scan.fill_tags(ctx, "global", "IAM user", out, lambda lv: _tag_map(
        list(paginate(iam, "list_user_tags", "Tags", UserName=lv.id))))
    return out


def _attached(n) -> str:
    return "not attached" if not n else f"attached to {n} identit{'y' if n == 1 else 'ies'}"


@live_type("aws_iam_policy", "iam", scope="global")
def scan_policies(scan, ctx, region):
    iam = ctx.client("iam")
    out = [Live("aws_iam_policy", p["Arn"], p.get("PolicyName", ""), region="global",
                summary=_attached(p.get("AttachmentCount", 0)))
           for p in paginate(iam, "list_policies", "Policies", Scope="Local")]
    scan.fill_tags(ctx, "global", "IAM policy", out, lambda lv: _tag_map(
        list(paginate(iam, "list_policy_tags", "Tags", PolicyArn=lv.id))))
    return out


# ---- serverless, data and messaging

@live_type("aws_lambda_function", "lambda")
def scan_lambdas(scan, ctx, region):
    lam = ctx.client("lambda", region)
    out, arns = [], {}
    for f in paginate(lam, "list_functions", "Functions"):
        lv = Live("aws_lambda_function", f["FunctionName"], f["FunctionName"],
                  summary=f.get("Runtime") or f.get("PackageType", ""))
        arns[lv.id] = f.get("FunctionArn", "")
        out.append(lv)
    scan.fill_tags(ctx, region, "Lambda function", out,
                   lambda lv: dict(lam.list_tags(Resource=arns[lv.id]).get("Tags") or {}))
    return out


@live_type("aws_dynamodb_table", "dynamodb")
def scan_tables(scan, ctx, region):
    ddb = ctx.client("dynamodb", region)
    partition = _partition(ctx)
    out = [Live("aws_dynamodb_table", name, name, summary="table")
           for name in paginate(ddb, "list_tables", "TableNames")]
    prefix = f"arn:{partition}:dynamodb:{region}:{ctx.account}:table/"
    scan.fill_tags(ctx, region, "DynamoDB table", out, lambda lv: _tag_map(
        ddb.list_tags_of_resource(ResourceArn=prefix + lv.id).get("Tags")))
    return out


@live_type("aws_sns_topic", "sns")
def scan_topics(scan, ctx, region):
    sns = ctx.client("sns", region)
    out = [Live("aws_sns_topic", t["TopicArn"], t["TopicArn"].rsplit(":", 1)[-1],
                summary="FIFO topic" if t["TopicArn"].endswith(".fifo") else "standard topic")
           for t in paginate(sns, "list_topics", "Topics")]
    scan.fill_tags(ctx, region, "SNS topic", out,
                   lambda lv: _tag_map(sns.list_tags_for_resource(ResourceArn=lv.id).get("Tags")))
    return out


@live_type("aws_sqs_queue", "sqs")
def scan_queues(scan, ctx, region):
    sqs = ctx.client("sqs", region)
    out = [Live("aws_sqs_queue", url, url.rstrip("/").rsplit("/", 1)[-1],
                summary="FIFO queue" if url.endswith(".fifo") else "standard queue")
           for url in paginate(sqs, "list_queues", "QueueUrls")]
    scan.fill_tags(ctx, region, "SQS queue", out,
                   lambda lv: dict(sqs.list_queue_tags(QueueUrl=lv.id).get("Tags") or {}))
    return out


@live_type("aws_kms_key", "kms")
def scan_keys(scan, ctx, region):
    kms = ctx.client("kms", region)
    aliases = {}
    try:
        for a in paginate(kms, "list_aliases", "Aliases"):
            if a.get("TargetKeyId"):
                aliases.setdefault(a["TargetKeyId"], a.get("AliasName", "").replace("alias/", ""))
    except Exception as exc:  # noqa: BLE001
        scan.note(ctx, "KMS aliases", region, exc)
    out = []
    unreadable = 0
    for k in paginate(kms, "list_keys", "Keys"):
        if scan.stopped():
            break
        lv = Live("aws_kms_key", k["KeyId"], aliases.get(k["KeyId"], ""))
        try:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        except Exception as exc:  # noqa: BLE001
            if not is_access_denied(exc):
                raise
            # The key policy keeps us out, so it's most likely not ours. It still counts as
            # there, so a key in a state isn't called gone.
            lv.aws_made = "a key whose policy doesn't let this profile read it"
            unreadable += 1
            out.append(lv)
            continue
        if meta.get("KeyManager") == "AWS":
            lv.aws_made = "an AWS managed key"
        state = meta.get("KeyState", "")
        if state in ("PendingDeletion", "PendingReplicaDeletion"):
            when = meta.get("DeletionDate")
            lv.pending_delete = f"scheduled for deletion on {when:%Y-%m-%d}" \
                if hasattr(when, "strftime") else "scheduled for deletion"
        lv.name = lv.name or str(meta.get("Description", ""))[:60]
        lv.summary = f"{meta.get('KeySpec', '')}, {state.lower()}"
        out.append(lv)
    scan.fill_tags(ctx, region, "KMS key", [lv for lv in out if not lv.pending_delete],
                   lambda lv: _tag_map(kms.list_resource_tags(KeyId=lv.id).get("Tags"),
                                       "TagKey", "TagValue"))
    if unreadable:
        with scan.lock:
            scan.unreadable[(ctx.label, region)] += unreadable
    return out


@live_type("aws_secretsmanager_secret", "secretsmanager")
def scan_secrets(scan, ctx, region):
    out = []
    for s in paginate(ctx.client("secretsmanager", region), "list_secrets", "SecretList"):
        tags = _tag_map(s.get("Tags"))
        owning = str(s.get("OwningService") or "")
        owner = OWNER_SERVICES.get(owning.lower(), owning)
        out.append(Live("aws_secretsmanager_secret", s["ARN"], s.get("Name", ""), tags=tags,
                        summary="rotation on" if s.get("RotationEnabled") else "secret",
                        owner=owner, owner_detail="manages this secret" if owner else ""))
    return out


@live_type("aws_cloudwatch_log_group", "logs")
def scan_log_groups(scan, ctx, region):
    logs = ctx.client("logs", region)
    out, arns = [], {}
    for g in paginate(logs, "describe_log_groups", "logGroups"):
        name = g["logGroupName"]
        days = g.get("retentionInDays")
        lv = Live("aws_cloudwatch_log_group", name, name,
                  summary=f"logs kept {days} days" if days else "logs kept forever")
        if name.startswith("/aws/lambda/"):
            lv.hint = ("Lambda makes this log group the first time the function runs. An "
                       "aws_cloudwatch_log_group for it in Terraform lets you set how long logs "
                       "are kept.")
        arns[name] = g.get("logGroupArn") or re.sub(r":\*$", "", str(g.get("arn") or ""))
        out.append(lv)

    def fetch(lv):
        try:
            return dict(logs.list_tags_for_resource(resourceArn=arns[lv.id]).get("tags") or {})
        except Exception as exc:  # noqa: BLE001 - older SDKs only have the log group call
            if is_access_denied(exc) or not arns[lv.id]:
                raise
            return dict(logs.list_tags_log_group(logGroupName=lv.id).get("tags") or {})
    scan.fill_tags(ctx, region, "log group", out, fetch)
    return out


@live_type("aws_ecr_repository", "ecr")
def scan_repos(scan, ctx, region):
    ecr = ctx.client("ecr", region)
    out, arns = [], {}
    for r in paginate(ecr, "describe_repositories", "repositories"):
        made = r.get("createdAt")
        lv = Live("aws_ecr_repository", r["repositoryName"], r["repositoryName"],
                  summary=f"created {made:%Y-%m-%d}" if hasattr(made, "strftime") else "")
        arns[lv.id] = r.get("repositoryArn", "")
        out.append(lv)
    scan.fill_tags(ctx, region, "ECR repository", out, lambda lv: _tag_map(
        ecr.list_tags_for_resource(resourceArn=arns[lv.id]).get("tags"), "Key", "Value"))
    return out


def _partition(ctx) -> str:
    arn = ctx.identity().get("Arn", "")
    return arn.split(":")[1] if arn.startswith("arn:") and arn.count(":") >= 2 else "aws"


# =================================================================== the live read

@dataclass
class Inventory:
    lives: list = field(default_factory=list)
    done: set = field(default_factory=set)        # (account, region or "global", family)
    notes: list = field(default_factory=list)
    accounts: dict = field(default_factory=dict)  # account -> profile label
    regions: dict = field(default_factory=dict)   # account -> regions read
    stopped: bool = False


def managed_keys(stacks) -> dict:
    out = {}
    for st in stacks:
        for m in st.resources:
            out.setdefault(m.family, set()).add(m.key)
    return out


def regions_to_read(stacks, account, default_region) -> list:
    regs = set()
    unknown = False
    for st in stacks:
        for m in st.resources:
            if m.account not in ("", account):
                continue
            if m.region and m.region != "global":
                regs.add(m.region)
            elif not m.region:
                unknown = True
    if unknown or not regs:
        regs.add(default_region)
    return sorted(regs)


def read_account(stacks, profiles, regions=None, progress=None, cancel=None,
                 workers=12) -> Inventory:
    """Read the live side for each profile. regions: the ones to read, or None for the
    regions the states use. Returns an Inventory with notes on what couldn't be read."""
    from .sweep import NOT_OFFERED_CODES, NOT_OFFERED_NAMES, UNREACHABLE_CODES, UNREACHABLE_NAMES
    inv = Inventory()
    scan = Scan(managed_keys(stacks), cancel)
    contexts = []
    for p in list(profiles) or [None]:
        try:
            ctx = AwsContext(p)
            acct = ctx.account
        except AuthError as exc:
            inv.notes.append(f"{p or 'default'}: {exc}")
            continue
        if acct in inv.accounts:
            inv.notes.append(f"{ctx.label} is the same account as {inv.accounts[acct]} "
                             f"({acct}), so it was read once.")
            continue
        inv.accounts[acct] = ctx.label
        contexts.append(ctx)

    tasks = []
    for ctx in contexts:
        regs = list(regions) if regions else \
            regions_to_read(stacks, ctx.account, ctx.default_region)
        inv.regions[ctx.account] = regs
        for lt in LIVE_TYPES.values():
            if lt.scope == "global":
                tasks.append((ctx, lt, "global"))
            else:
                for r in ctx.regions_for(lt.service, regs):
                    tasks.append((ctx, lt, r))

    denied, unreachable = {}, {}

    def run(task):
        ctx, lt, region = task
        if scan.stopped():
            return task, None, None
        try:
            return task, lt.scan(scan, ctx, region), None
        except Exception as exc:  # noqa: BLE001
            return task, None, exc

    total, done = len(tasks), 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for fut in as_completed([pool.submit(run, t) for t in tasks]):
            (ctx, lt, region), found, exc = fut.result()
            done += 1
            if progress:
                where = f" in {region}" if region != "global" else ""
                progress(done, total, f"{lt.label}s{where}")
            if exc is not None:
                name, code = type(exc).__name__, error_code(exc)
                if name in NOT_OFFERED_NAMES or code in NOT_OFFERED_CODES:
                    inv.done.add((ctx.account, region, lt.family))
                    continue
                if is_access_denied(exc):
                    denied.setdefault((ctx.label, lt.label), []).append(region)
                elif name in UNREACHABLE_NAMES or code in UNREACHABLE_CODES:
                    _, kinds, regs = unreachable.setdefault(
                        (ctx.label, code or name), (error_text(exc, ctx.profile), set(), set()))
                    kinds.add(lt.label)
                    regs.add(region)
                else:
                    inv.notes.append(f"{ctx.label}: {lt.label}s in {region}: "
                                     f"{error_text(exc, ctx.profile)}")
                continue
            if found is None:
                continue  # stopped before it ran
            if not scan.stopped():
                inv.done.add((ctx.account, region, lt.family))
            for lv in found:
                lv.account = ctx.account
                lv.profile = ctx.label
                if not lv.region:
                    lv.region = region
                if not lv.owner:
                    lv.owner, lv.owner_detail = owner_of(lv.tags)
                inv.lives.append(lv)

    inv.stopped = scan.stopped()
    if inv.stopped:
        inv.notes.append("Stopped before everything was read, so some things weren't checked.")
    for (label, code), (reason, kinds, regs) in sorted(unreachable.items()):
        what = f"{next(iter(kinds))}s" if len(kinds) == 1 else f"{len(kinds)} types"
        where = ", ".join(sorted(regs)) if len(regs) <= 3 else f"{len(regs)} regions"
        text = f"{label}: couldn't read {what} in {where}. {reason}"
        if code in UNREACHABLE_CODES:
            text += " If a region isn't turned on for this account, leave it out."
        inv.notes.append(text)
    for (label, what), regs in sorted(denied.items()):
        where = regs[0] if len(regs) == 1 else f"{len(regs)} regions"
        inv.notes.append(f"{label}: no permission to list {what}s ({where}), so they weren't "
                         "checked.")
    for (label, what, why), regs in sorted(scan.partial.items()):
        regs = sorted(regs)
        where = regs[0] if len(regs) == 1 else f"{len(regs)} regions"
        if why == "denied":
            inv.notes.append(f"{label}: no permission to read {what} ({where}), so those "
                             "weren't compared.")
        else:
            inv.notes.append(f"{label}: couldn't read {what} ({where}): {why}")
    for (label, what, region), n in sorted(scan.skipped.items()):
        inv.notes.append(f"{label}: tags weren't read for {n} more {what}s in {region} "
                         f"(more than {MAX_TAG_CALLS}), so tag marks don't apply to them.")
    for (label, region), n in sorted(scan.unreadable.items()):
        inv.notes.append(f"{label}: {n} KMS key{'s' if n > 1 else ''} in {region} couldn't be "
                         "read, since the key policy doesn't allow it. They're left out of the "
                         "list, but still count as there for keys in a state.")
    return inv


# =================================================================== comparing

@dataclass
class Change:
    setting: str
    state: str
    aws: str

    def as_dict(self):
        return {"setting": self.setting, "state": self.state, "aws": self.aws}


@dataclass
class Finding:
    status: str                 # unmanaged, gone, changed, other
    type: str
    id: str
    name: str = ""
    region: str = ""
    account: str = ""
    profile: str = ""
    address: str = ""
    stack: str = ""
    detail: str = ""
    changes: list = field(default_factory=list)
    source: str = "drift"       # or terraform, for Terraform's own refresh
    owner: str = ""
    in_scope: bool = True
    hint: str = ""
    tags: dict = field(default_factory=dict)
    import_name: str = ""
    hidden: list = field(default_factory=list)
    why: str = ""               # the longer explanation, for the details

    @property
    def label(self) -> str:
        if self.status == "other":
            return f"Managed by {self.owner}"
        text = STATUS_LABEL[self.status]
        if self.source == "terraform":
            text += " (from Terraform's refresh)"
        return text

    @property
    def badge(self) -> str:
        if self.status == "other":
            return self.owner
        return STATUS_LABEL[self.status]

    @property
    def severity(self) -> str:
        return STATUS_SEVERITY[self.status]

    @property
    def import_block(self) -> str:
        if self.status != "unmanaged" or not self.import_name:
            return ""
        return import_block(self.type, self.import_name, self.id)

    @property
    def state_rm(self) -> str:
        if self.status != "gone" or not self.address:
            return ""
        return "terraform state rm " + _shell_quote(plain(self.address))

    def fix(self) -> str:
        if self.status == "unmanaged":
            return ("Bring it under Terraform with the import block (Terraform 1.5 or newer), "
                    "then terraform plan -generate-config-out=generated.tf writes the resource "
                    "code for you. Or delete it if it's a leftover.")
        if self.status == "gone":
            return ("The next terraform apply makes it again. If it was deleted on purpose, take "
                    "it out of the code. To drop it from the state right away: " + self.state_rm)
        if self.status == "changed":
            return ("Run terraform apply to put it back the way the code says, or change the code "
                    "to match what's there now.")
        return f"{self.owner} manages it. Change it there, not in Terraform."

    def row(self) -> dict:
        row = {"status": self.label, "badge": self.badge, "severity": self.severity,
               "type": self.type, "id": self.id,
               "name": self.name if self.name != self.id else "", "region": self.region,
               "account": self.account, "profile": self.profile, "address": self.address,
               "stack": self.stack, "detail": self.detail, "fix": self.fix()}
        row = {k: plain(v) for k, v in row.items()}
        row["rank"] = STATUS_ORDER[self.status]
        return row

    def as_dict(self) -> dict:
        d = self.row()
        d.update({"state": self.status, "source": self.source, "owner": self.owner,
                  "in_scope": self.in_scope, "hint": self.hint,
                  "why": self.why, "changes": [c.as_dict() for c in self.changes],
                  "import": self.import_block, "state_rm": self.state_rm,
                  "not_compared": list(self.hidden),
                  "tags": dict(self.tags) if self.status in ("unmanaged", "other") else {}})
        d.pop("rank", None)
        d.pop("badge", None)
        return d

    def detail_text(self) -> str:
        what = type_label(self.type)
        head = f"{self.label.upper()}   {self.address or self.type}"
        lines = [head]
        ident = f"{what} {self.id}"
        if self.name and self.name != self.id:
            ident += f" ({self.name})"
        place = ", ".join(p for p in (self.region if self.region != "global" else "",
                                      f"account {self.account}" if self.account else "",
                                      f"profile {self.profile}" if self.profile else "") if p)
        lines.append(ident + (f", {place}" if place else ""))
        if self.stack:
            lines.append(f"In the state from {self.stack}.")
        if self.status == "unmanaged":
            lines.append("None of the states you added know about it, so it was probably made in "
                         "the console, the CLI, or another tool.")
        elif self.status == "gone":
            lines.append(self.why or self.detail)
        elif self.status == "other":
            lines.append(f"Managed by {self.owner}" + (f", {self.detail}." if self.detail else "."))
        if self.hint:
            lines += ["", self.hint]
        if self.changes:
            lines += ["", "What Terraform's refresh found" if self.source == "terraform"
                      else "What's different"]
            for c in self.changes:
                lines += [f"  {c.setting}", f"    in the state:  {c.state}",
                          f"    in AWS:        {c.aws}"]
        if self.hidden:
            lines += ["", "Not compared, because the state marks them sensitive: " +
                      ", ".join(self.hidden) + "."]
        if self.tags and self.status in ("unmanaged", "other"):
            shown = [(k, v) for k, v in sorted(self.tags.items()) if not k.startswith("aws:")][:12]
            if shown:
                lines += ["", "Tags"] + [f"  {k} = {v}" for k, v in shown]
        lines += ["", "What to do"]
        if self.status == "unmanaged":
            lines += ["  Bring it under Terraform with this import block (Terraform 1.5 or newer):",
                      ""] + self.import_block.split("\n") + ["",
                      "  Then terraform plan -generate-config-out=generated.tf writes the resource",
                      "  code for you. Or delete it, if it's a leftover."]
        elif self.status == "gone":
            lines += ["  The next terraform apply makes it again. If that's what you want, run",
                      "  terraform apply. If it was deleted on purpose, take it out of the code.",
                      "  To drop it from the state right away:", "", "    " + self.state_rm]
        elif self.status == "changed":
            lines += ["  Run terraform apply to put it back the way the code says, or change the",
                      "  code to match what's there now. terraform plan shows what apply would do."]
        else:
            lines += [f"  Change it in {self.owner}, not in Terraform. If you'd rather manage it",
                      "  with Terraform, move it out of there first."]
        # Each line is one piece of text, so a newline or escape code inside a name, tag or
        # address becomes a ? instead of a new line or a terminal command.
        return "\n".join(plain(line) for line in lines)


def _shell_quote(text) -> str:
    """Single quotes for bash and zsh. A ' inside is written as '"'"'."""
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


# Characters that could move the cursor, rewrite a terminal line, or flip text direction.
UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def plain(text) -> str:
    """Text from AWS or a state, safe to show on one line: names and tags can hold any
    character, and a newline or escape code must not start a new line or reach a terminal."""
    return UNSAFE_CHARS.sub("?", str(text if text is not None else ""))


_HCL_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def hcl_string(text) -> str:
    """A quoted HCL string. ${ and %{ are doubled, so an ID is never read as a template."""
    out = []
    for ch in str(text):
        if ch in _HCL_ESCAPES:
            out.append(_HCL_ESCAPES[ch])
        elif UNSAFE_CHARS.match(ch):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return ('"' + "".join(out) + '"').replace("${", "$${").replace("%{", "%%{")


def import_block(rtype, name, ident) -> str:
    return "import {\n  to = %s.%s\n  id = %s\n}" % (rtype, name, hcl_string(ident))


TF_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def tf_name(text, fallback="resource") -> str:
    """A Terraform resource name from free text: lower case, underscores, starting with a
    letter."""
    s = re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
    if not s:
        s = re.sub(r"[^a-z0-9]+", "_", str(fallback).lower()).strip("_") or "resource"
    if not re.match(r"[a-z_]", s):
        s = "r_" + s
    return s[:60].rstrip("_") or "resource"


def _short_id(ident) -> str:
    """The distinctive part of an ID: 0abc123 from i-0abc123, the name from an ARN or URL."""
    tail = str(ident).rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    tail = re.sub(r"^[a-z]{1,10}-(?=[0-9a-f]{8,}$)", "", tail)
    return tail[:12]


def assign_import_names(findings, taken=()):
    """Give each unmanaged finding a resource name that's valid and unique per type,
    and doesn't clash with names the states already use."""
    used = {(t, n) for t, n in taken}
    for f in sorted((f for f in findings if f.status == "unmanaged"),
                    key=lambda f: (f.type, f.region, f.name, f.id)):
        short = f.type[4:] if f.type.startswith("aws_") else f.type
        base = tf_name(f.name, f"{short}_{_short_id(f.id)}")
        name, n = base, 2
        while (f.type, name) in used:
            name = f"{base}_{n}"
            n += 1
        used.add((f.type, name))
        f.import_name = name


def tag_changes(state_tags, live_tags, secret) -> list:
    out = []
    s = {k: v for k, v in (state_tags or {}).items() if not k.startswith("aws:")}
    live = {k: v for k, v in (live_tags or {}).items() if not k.startswith("aws:")}

    def show(key, value):
        if "*" in secret or key in secret:
            return HIDDEN
        return value if value.strip() else json.dumps(value)
    for k in sorted(set(s) | set(live)):
        if k not in s:
            out.append(Change(f"tag {k}", NOT_SET, show(k, live[k])))
        elif k not in live:
            out.append(Change(f"tag {k}", show(k, s[k]), NOT_SET))
        elif s[k] != live[k]:
            out.append(Change(f"tag {k}", show(k, s[k]), show(k, live[k])))
    return out


def compare_settings(m, lv, extra) -> list:
    """What differs between a managed resource and the live one. extra holds what child
    resources add: routes, rules, policy attachments, versioning."""
    out = []
    if m.tags is not None and lv.tags is not None:
        out += tag_changes(m.tags, lv.tags, m.secret_tags)
    ms, ls = m.settings, lv.settings
    fam = m.family
    if fam == "aws_instance":
        want, have = ms.get("instance_type"), ls.get("instance_type")
        if want and have and want != have:
            out.append(Change("instance type", want, have))
        if ms.get("security_groups") and "security_groups" in ls and \
                set(ms["security_groups"]) != set(ls["security_groups"]):
            out.append(Change("security groups", ", ".join(sorted(ms["security_groups"])),
                              ", ".join(sorted(ls["security_groups"])) or "none"))
    elif fam == "aws_subnet":
        if "public_ip" in ms and "public_ip" in ls and ms["public_ip"] != ls["public_ip"]:
            out.append(Change("map_public_ip_on_launch", str(ms["public_ip"]).lower(),
                              str(ls["public_ip"]).lower()))
    elif fam == "aws_security_group":
        managed = set(ms.get("rules") or set()) | extra.get("rule", set())
        if ("rules" in ms or extra.get("rule")) and "rules" in ls:
            live = ls["rules"]
            for a in sorted(live - managed, key=_atom_sort):
                out.append(Change(f"{a[0]} rule", NOT_THERE, atom_text(a)))
            for a in sorted(managed - live, key=_atom_sort):
                out.append(Change(f"{a[0]} rule", atom_text(a), NOT_THERE))
    elif fam == "aws_route_table":
        if ("routes" in ms or extra.get("route")) and "routes" in ls:
            managed = dict(ms.get("routes") or {})
            for dest, target in extra.get("route", set()):
                if target != "local":
                    managed[dest] = target
            live = ls["routes"]
            for dest in sorted(set(live) - set(managed)):
                out.append(Change(f"route {dest}", NOT_THERE, ", ".join(sorted(live[dest]))))
            for dest in sorted(set(managed) - set(live)):
                out.append(Change(f"route {dest}", managed[dest] or "?", NOT_THERE))
            for dest in sorted(set(managed) & set(live)):
                if managed[dest] and managed[dest] not in live[dest]:
                    out.append(Change(f"route {dest}", managed[dest],
                                      ", ".join(sorted(live[dest]))))
    elif fam == "aws_iam_role":
        if ms.get("trust") is not None and ls.get("trust") is not None and \
                policy_text(ms["trust"]) != policy_text(ls["trust"]):
            out.append(Change("trust policy", policy_text(ms["trust"]), policy_text(ls["trust"])))
        if ("policies" in ms or extra.get("policy")) and "policies" in ls:
            managed = set(ms.get("policies") or set()) | extra.get("policy", set())
            for arn in sorted(ls["policies"] - managed):
                out.append(Change("attached policy", NOT_THERE, arn))
            for arn in sorted(managed - ls["policies"]):
                out.append(Change("attached policy", arn, NOT_THERE))
    elif fam == "aws_s3_bucket":
        want = extra.get("versioning", ms.get("versioning"))
        if isinstance(want, bool) and "versioning" in ls and want != ls["versioning"]:
            out.append(Change("versioning", "enabled" if want else "off or suspended",
                              "enabled" if ls["versioning"] else "off or suspended"))
    return out


def _change_summary(changes) -> str:
    """'tags, rules' style list of what changed, for the one-line Detail column."""
    names = []
    for c in changes:
        if c.setting.endswith(" rule"):
            name = "rules"
        elif c.setting.startswith("route "):
            name = "routes"
        elif c.setting == "attached policy":
            name = "attached policies"
        elif c.setting.startswith("tag "):
            name = "tags"
        else:
            name = c.setting
        if name not in names:
            names.append(name)
    return ", ".join(names[:4]) + (", ..." if len(names) > 4 else "")


@dataclass
class Report:
    findings: list
    notes: list
    managed: int = 0
    stacks: int = 0
    checked: int = 0
    hidden: int = 0
    readable: int = 0
    accounts: dict = field(default_factory=dict)
    regions: dict = field(default_factory=dict)
    exact: dict = field(default_factory=dict)   # stack label -> "ok" or the error

    def visible(self, show_all=False) -> list:
        """Gone and changed always show. The rest only when they're in the types and
        regions the states manage, unless show_all."""
        return [f for f in self.findings
                if show_all or f.in_scope or f.status in ("gone", "changed")]

    def elsewhere(self) -> int:
        return sum(1 for f in self.findings
                   if not f.in_scope and f.status in ("unmanaged", "other"))

    def counts(self, show_all=False) -> dict:
        c = {"unmanaged": 0, "gone": 0, "changed": 0, "other": 0}
        for f in self.visible(show_all):
            c[f.status] += 1
        return c

    def drift_found(self, show_all=False) -> bool:
        c = self.counts(show_all)
        return bool(c["unmanaged"] or c["gone"] or c["changed"])

    def headline(self, show_all=False) -> str:
        c = self.counts(show_all)
        stacks = f"{self.stacks} stack" + ("" if self.stacks == 1 else "s")
        res = f"{self.managed} resource" + ("" if self.managed == 1 else "s")
        text = f"Terraform manages {res} in {stacks}."
        if not (c["unmanaged"] or c["gone"] or c["changed"]):
            return text + " No drift found."
        return (text + f" {c['unmanaged']} not in Terraform, {c['gone']} gone, "
                f"{c['changed']} changed.")

    def subline(self, show_all=False) -> str:
        parts = []
        accts = ", ".join(f"{a} ({p})" for a, p in self.accounts.items())
        regs = sorted({r for rs in self.regions.values() for r in rs})
        if accts:
            parts.append(f"Account{'s' if len(self.accounts) > 1 else ''} {accts}, "
                         f"{', '.join(regs) or 'no regions'} and global services.")
        other = self.counts(show_all)["other"]
        if other:
            parts.append(f"{other} managed by another tool or service.")
        if not show_all and self.elsewhere():
            parts.append(f"{self.elsewhere()} more in types or regions your Terraform doesn't "
                         "manage.")
        if self.hidden:
            parts.append(f"{self.hidden} hidden by your ignore list.")
        missed = self.readable - self.checked
        if missed > 0:
            parts.append(f"{missed} of the managed resources couldn't be checked, see the notes.")
        return " ".join(parts)


def _account_ok(m_account, account) -> bool:
    return not m_account or m_account == account


def evaluate(stacks, inv, ignore=None, exact=None) -> Report:
    """Match the states against the live read. exact: {stack label: list of drift entries
    from terraform plan -refresh-only, or an error text}."""
    ignore = ignore if isinstance(ignore, IgnoreList) else IgnoreList(
        ignore if ignore is not None else load_settings()["ignore"])
    exact = exact or {}
    findings, notes = [], []
    scanned = set(inv.accounts)

    # Regional things are matched in their own region, since names (log groups, functions,
    # tables, queues, databases) can repeat from one region to the next.
    by_region, by_key = {}, {}
    for lv in inv.lives:
        by_region.setdefault((lv.account, lv.family, lv.key, lv.region), lv)
        by_key.setdefault((lv.account, lv.family, lv.key), lv)

    def find(m, account):
        if LIVE_TYPES[_scan_family(m.family)].scope == "global" or not m.region:
            return by_key.get((account, m.family, m.key))
        return by_region.get((account, m.family, m.key, m.region))

    # What child resources add to their parents, per account.
    extra = {}
    for st in stacks:
        acct = getattr(st, "child_account", "")
        for kind, parent, payload in st.children:
            bucket = extra.setdefault((acct, parent), {})
            if kind == "versioning":
                bucket["versioning"] = payload
            else:
                bucket.setdefault(kind, set()).add(payload)

    def extra_for(m, account):
        out = {}
        for key in ((account, m.id), ("", m.id)):
            for k, v in extra.get(key, {}).items():
                if isinstance(v, set):
                    out.setdefault(k, set()).update(v)
                else:
                    out[k] = v
        return out

    covered = set()
    for st in stacks:
        covered |= st.covered

    tf_entries, authoritative = {}, set()
    for st in stacks:
        result = exact.get(st.label)
        if isinstance(result, list):
            authoritative.add(st.label)
            for e in result:
                tf_entries[(st.label, e["address"])] = e
        for e in st.plan_drift:
            tf_entries.setdefault((st.label, e["address"]), e)

    matched = set()
    not_checked = Counter()
    other_account = Counter()
    unknown_region = 0
    checked = 0
    used_entries = set()
    for st in stacks:
        for m in st.resources:
            accounts = [a for a in scanned if _account_ok(m.account, a)]
            lv, where = None, None
            for a in accounts:
                lv = find(m, a)
                if lv is not None:
                    where = a
                    break
            if lv is not None:
                matched.add(id(lv))
            entry = tf_entries.get((st.label, m.address))
            if entry is not None:
                used_entries.add((st.label, m.address))
                findings.append(_from_entry(entry, st, m, lv, inv))
                checked += 1
                continue
            if st.label in authoritative:
                checked += 1
                continue  # Terraform's refresh found it as it should be
            if m.account and m.account not in scanned:
                other_account[m.account] += 1
                continue
            if lv is not None:
                checked += 1
                if lv.pending_delete:
                    f = _gone(m, st, where, inv, f"{m.address}: {lv.pending_delete}",
                              f"The key is {lv.pending_delete}, and AWS no longer lets it be used.")
                    f.hint = ("Until then you can cancel the deletion in the KMS console (or aws "
                              f"kms cancel-key-deletion --key-id {lv.id} --region {lv.region}), "
                              "which keeps the key and everything encrypted with it.")
                    findings.append(f)
                    continue
                changes = compare_settings(m, lv, extra_for(m, where))
                if changes:
                    # Live tags only go along for the ignore list, never for display, and
                    # without the ones the state marks sensitive.
                    tags = {k: v for k, v in (lv.tags or {}).items()
                            if "*" not in m.secret_tags and k not in m.secret_tags}
                    findings.append(Finding(
                        "changed", m.type, m.id, m.name or lv.name, lv.region, where,
                        inv.accounts.get(where, ""), m.address, st.label,
                        f"{m.address}: {_change_summary(changes)} changed",
                        changes, tags=tags, hidden=list(m.hidden)))
                continue
            # Not found. It's only gone if every account and region it could be in was read.
            is_global = LIVE_TYPES[_scan_family(m.family)].scope == "global"
            fam_scope = "global" if is_global else m.region
            if not fam_scope:
                unknown_region += 1
                continue
            complete = accounts and all((a, fam_scope, _scan_family(m.family)) in inv.done
                                        for a in accounts)
            if not complete:
                regs_read = {r for a in accounts for r in inv.regions.get(a, [])}
                if fam_scope != "global" and fam_scope not in regs_read:
                    not_checked[f"in {fam_scope}, which wasn't picked"] += 1
                else:
                    not_checked[f"{type_label(m.family)}s couldn't be listed"] += 1
                continue
            checked += 1
            acct = m.account or (accounts[0] if len(accounts) == 1 else "")
            findings.append(_gone(m, st, acct, inv, f"{m.address}: not in AWS any more",
                                  f"{m.address} is in the state, but AWS has no "
                                  f"{type_words(m.family)} {m.id}" +
                                  (f" in {m.region}" if m.region and m.region != "global" else "") +
                                  "."))

    # Drift Terraform reported on types Drift doesn't read itself.
    for (label, address), e in tf_entries.items():
        if (label, address) in used_entries:
            continue
        st = next((s for s in stacks if s.label == label), None)
        findings.append(_from_entry(e, st, None, None, inv))

    # Live things no state knows about.
    scope = _scope(stacks, scanned)
    for lv in inv.lives:
        if lv.family == "aws_instance":
            covered.update(("aws_ebs_volume", vol) for vol in lv.settings.get("volumes") or ())
    for lv in inv.lives:
        if id(lv) in matched or lv.aws_made or lv.pending_delete:
            continue
        if (lv.family, lv.id) in covered or (lv.family == "aws_ebs_volume" and lv.part_of):
            continue
        status = "other" if lv.owner else "unmanaged"
        if lv.owner:
            detail = lv.owner_detail or f"made by {lv.owner}"
        else:
            detail = lv.summary
            if terraform_tagged(lv.tags):
                detail = (detail + ". " if detail else "") + \
                    "Tags say Terraform manages it: a stack you didn't add?"
        families, regions = scope.get(lv.account, (set(), set()))
        in_scope = lv.family in families and (lv.family in GLOBAL_FAMILIES or lv.region in regions)
        findings.append(Finding(status, lv.family, lv.id, lv.name, lv.region, lv.account,
                                lv.profile, detail=detail, owner=lv.owner, in_scope=in_scope,
                                hint=lv.hint, tags=dict(lv.tags or {})))

    # The ignore list.
    kept, hidden = [], 0
    for f in findings:
        if ignore.matches((f.id, f.name, f.address, match_key(f.type, f.id)), f.tags):
            hidden += 1
            continue
        kept.append(f)
    findings = kept

    taken = set()
    for st in stacks:
        taken |= st.names
    assign_import_names(findings, taken)
    findings.sort(key=lambda f: (STATUS_ORDER[f.status], not f.in_scope, f.type, f.region,
                                 f.name, f.id))

    managed_total = sum(st.total for st in stacks)
    unread = Counter()
    for st in stacks:
        unread.update(st.unread)
    if unread:
        parts = [f"{n} {t}" for t, n in sorted(unread.items(), key=lambda x: (-x[1], x[0]))]
        shown = ", ".join(parts[:6])
        if len(parts) > 6:
            shown += f" and {len(parts) - 6} more types"
        notes.append(f"Drift doesn't read these types on their own, so they weren't checked: "
                     f"{shown}. Routes, security group rules, role policy attachments and bucket "
                     "versioning are still compared as part of their parent.")
    for acct, n in sorted(other_account.items()):
        notes.append(f"{n} resource{'s are' if n > 1 else ' is'} in account {acct}, which no "
                     "picked profile reaches, so they weren't checked.")
    for why, n in sorted(not_checked.items()):
        notes.append(f"{n} resource{'s' if n > 1 else ''} weren't checked: {why}.")
    if unknown_region:
        notes.append(f"{unknown_region} resource{'s' if unknown_region > 1 else ''} weren't "
                     "checked, because their region couldn't be worked out from the state.")
    for label, result in exact.items():
        if isinstance(result, str):
            notes.append(f"Exact check in {label} didn't work, so Drift's own comparison is "
                         f"shown: {result}")
    readable = sum(len(st.resources) for st in stacks)
    return Report(findings, list(inv.notes) + notes, managed_total, len(stacks), checked,
                  hidden, readable, dict(inv.accounts), dict(inv.regions),
                  {k: ("ok" if isinstance(v, list) else v) for k, v in exact.items()})


def _scan_family(family) -> str:
    return "aws_db_instance" if family == "aws_rds_cluster_instance" else family


def _scope(stacks, accounts) -> dict:
    """account -> (types, regions) the states manage there. Types the states only use as
    children or don't read (like aws_security_group_rule) count for their parent type."""
    out = {a: (set(), set()) for a in accounts}
    for st in stacks:
        extra = {FAMILY.get(SCOPE_PARENT.get(t, t), SCOPE_PARENT.get(t, t)) for t in _all_types(st)}
        for a in accounts:
            mine = [m for m in st.resources if _account_ok(m.account, a)]
            if st.resources and not mine:
                continue  # this stack is about other accounts
            types, regions = out[a]
            types.update(m.family for m in mine)
            types.update(extra)
            regions.update(m.region for m in mine if m.region and m.region != "global")
    return out


def _all_types(st) -> set:
    types = set(st.unread)
    kinds = {"route": "aws_route", "rule": "aws_security_group_rule",
             "policy": "aws_iam_role_policy_attachment", "versioning": "aws_s3_bucket_versioning"}
    types |= {kinds[k] for k, _, _ in st.children}
    return types


def _gone(m, st, account, inv, detail, why="") -> Finding:
    # The state's tags go along for the ignore list only, without sensitive ones.
    tags = {k: v for k, v in (m.tags or {}).items()
            if "*" not in m.secret_tags and k not in m.secret_tags}
    return Finding("gone", m.type, m.id, m.name, m.region, account, inv.accounts.get(account, ""),
                   m.address, st.label, detail, why=why, tags=tags)


def _from_entry(e, st, m, lv, inv) -> Finding:
    region = (m.region if m else "") or e.get("region", "")
    account = (m.account if m else "") or e.get("account", "") or \
        (next(iter(inv.accounts)) if len(inv.accounts) == 1 else "")
    ident = (m.id if m else "") or e.get("id", "")
    name = (m.name if m else "") or e.get("name", "")
    if e["action"] == "delete":
        return Finding("gone", e["type"], ident, name, region, account,
                       inv.accounts.get(account, ""), e["address"], st.label if st else "",
                       f"{e['address']}: gone, from Terraform's refresh", source="terraform",
                       why=f"Terraform's refresh found {e['address']} is no longer in AWS.")
    changes = [Change(c["setting"], c["state"], c["aws"]) for c in e["changes"]]
    return Finding("changed", e["type"], ident, name, region, account,
                   inv.accounts.get(account, ""), e["address"], st.label if st else "",
                   f"{e['address']}: {_change_summary(changes) or 'settings'} changed, from "
                   "Terraform's refresh", changes, source="terraform")


# =================================================================== Terraform's own view

def _mask(value, marks, attr=""):
    """value with anything marks flags (or any attribute named like a secret) hidden."""
    if (attr and SECRET_NAME.search(attr)) or \
            (not isinstance(marks, (dict, list)) and _has_true(marks)):
        return HIDDEN
    if isinstance(value, dict):
        sub = marks if isinstance(marks, dict) else {}
        return {k: _mask(v, sub.get(k), k) for k, v in value.items()}
    if isinstance(value, list):
        sub = marks if isinstance(marks, list) else []
        return [_mask(v, sub[i] if i < len(sub) else None, attr) for i, v in enumerate(value)]
    return value


# Attributes whose values often hold secrets without being marked sensitive, like Lambda
# environment variables. A change to them is reported, but not the values.
NEVER_SHOW = {"environment", "variables", "user_data", "user_data_base64", "content",
              "content_base64", "secret_string", "secret_binary", "plaintext", "value",
              "insecure_value", "container_definitions", "body", "template_body",
              "connection_string", "parameter", "parameters"}
NOT_SHOWN = "(changed, value not shown)"


def _show(attr, value, limit=300) -> str:
    """A changed attribute's value as text, when it's safe to show: plain values and lists
    of them. Objects and nested blocks only say they changed."""
    if value is None:
        return NOT_SET
    if value == HIDDEN:
        return HIDDEN
    if attr in NEVER_SHOW:
        return NOT_SHOWN
    if isinstance(value, dict) or (isinstance(value, list) and
                                   any(isinstance(x, (dict, list)) for x in value)):
        return NOT_SHOWN
    if isinstance(value, list):
        text = ", ".join(HIDDEN if x == HIDDEN else str(x) for x in value) or "(empty)"
    elif isinstance(value, bool):
        text = str(value).lower()
    else:
        text = str(value)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _attr_changes(rtype, attr, before, after, bmarks, amarks) -> list:
    if attr in ("tags", "tags_all"):
        b = before if isinstance(before, dict) else {}
        a = after if isinstance(after, dict) else {}
        secret = set()
        for mk in (bmarks, amarks):
            if isinstance(mk, dict):
                secret |= {k for k, x in mk.items() if _has_true(x)}
            elif _has_true(mk):
                secret.add("*")
        return tag_changes({str(k): str(v) for k, v in b.items()},
                           {str(k): str(v) for k, v in a.items()}, secret)
    if FAMILY.get(rtype, rtype) == "aws_security_group" and attr in ("ingress", "egress") \
            and not _has_true(bmarks) and not _has_true(amarks):
        def atoms(blocks):
            out = set()
            for b in blocks if isinstance(blocks, list) else []:
                if isinstance(b, dict):
                    groups = [g for g in (b.get("security_groups") or []) if isinstance(g, str)]
                    if b.get("self"):
                        groups.append("self")
                    out |= rule_atoms(attr, b.get("protocol"), b.get("from_port"), b.get("to_port"),
                                      _block_cidrs(b), list(b.get("prefix_list_ids") or []), groups)
            return out
        old, new = atoms(before), atoms(after)
        return [Change(f"{attr} rule", NOT_THERE, atom_text(x))
                for x in sorted(new - old, key=_atom_sort)] + \
            [Change(f"{attr} rule", atom_text(x), NOT_THERE)
             for x in sorted(old - new, key=_atom_sort)]
    if attr == "assume_role_policy" and not _has_true(bmarks) and not _has_true(amarks):
        b, a = norm_policy(before or ""), norm_policy(after or "")
        if b is not None and a is not None:
            if policy_text(b) == policy_text(a):
                return []
            return [Change("trust policy", policy_text(b), policy_text(a))]
    old, new = _show(attr, _mask(before, bmarks, attr)), _show(attr, _mask(after, amarks, attr))
    if old == new == NOT_SHOWN:
        return [Change(attr, "(not shown)", NOT_SHOWN)]
    return [Change(attr, old, new)]


def _marks_of(marks):
    """A change's before_sensitive or after_sensitive. Terraform always writes them, so
    when one is missing or odd every value is treated as sensitive."""
    return marks if isinstance(marks, (dict, bool)) else True


def _marks_for(marks, attr):
    """One attribute's marks: True when the whole object is sensitive."""
    if marks is True:
        return True
    return marks.get(attr) if isinstance(marks, dict) else None


def parse_drift(plan) -> list:
    """The resource_drift of a plan (terraform plan -refresh-only, or a normal plan) as
    plain entries with old and new values. Values marked sensitive, or named like a
    secret, are replaced before anything else sees them."""
    from . import tfplan
    out = []
    entries = plan.get("resource_drift") if isinstance(plan, dict) else None
    for rd in entries if isinstance(entries, list) else []:
        if not isinstance(rd, dict) or rd.get("mode", "managed") != "managed":
            continue
        rtype = str(rd.get("type") or "")
        if not rtype.startswith("aws_") or not rd.get("address"):
            continue
        ch = rd.get("change") if isinstance(rd.get("change"), dict) else {}
        action = tfplan.action_of(ch.get("actions"))
        if action not in ("update", "delete"):
            continue
        before = ch.get("before") if isinstance(ch.get("before"), dict) else {}
        after = ch.get("after") if isinstance(ch.get("after"), dict) else {}
        bs, as_ = _marks_of(ch.get("before_sensitive")), _marks_of(ch.get("after_sensitive"))
        changes = []
        if action == "update":
            for attr in tfplan.changed_attrs(ch):
                attr = attr.split(" ")[0]
                if attr == "tags_all" and "tags" in before:
                    continue
                changes += _attr_changes(rtype, attr, before.get(attr), after.get(attr),
                                         _marks_for(bs, attr), _marks_for(as_, attr))
            if not changes:
                continue
        vals = _Values(before, bs)
        family = FAMILY.get(rtype, rtype)
        ident = vals.text(ID_ATTR.get(family, "id")) or vals.text("id")
        region, account = arn_parts(vals.text("arn"))
        name = _name(vals, family)
        out.append({"address": rd["address"], "type": rtype, "action": action, "id": ident,
                    "name": name, "region": vals.text("region") or region, "account": account,
                    "changes": [c.as_dict() for c in changes]})
    return out


def exact_check(folder, profile=None, log=None) -> list:
    """terraform plan -refresh-only in a folder: Terraform's own view of what changed on
    the resources it manages. The plan isn't applied, so the state isn't touched."""
    from . import tfplan
    try:
        plan = tfplan.plan_directory(str(folder), extra_args=["-refresh-only"], log=log,
                                     profile=profile)
    except tfplan.PlanError as exc:
        raise DriftError(str(exc)) from exc
    except RecursionError as exc:
        raise DriftError("terraform show printed JSON nested too deep to read.") from exc
    try:
        return parse_drift(plan)
    except (TypeError, AttributeError, ValueError, RecursionError) as exc:
        raise DriftError(f"Couldn't read the plan's resource_drift ({type(exc).__name__}).") \
            from exc


# =================================================================== all together

def compare(stacks, profiles, regions=None, progress=None, cancel=None, exact=None,
            ignore=None):
    """Read the account and match it against the stacks. Returns (report, inventory)."""
    inv = read_account(stacks, profiles, regions, progress=progress, cancel=cancel)
    return evaluate(stacks, inv, ignore, exact), inv


def import_text(findings) -> str:
    blocks = []
    for f in findings:
        if f.import_block:
            where = ", ".join(p for p in (f.region if f.region != "global" else "",
                                          f"account {f.account}" if f.account else "") if p)
            comment = f"{type_label(f.type)}" + (f" {f.name}" if f.name else "") + \
                (f" ({where})" if where else "")
            blocks.append("# " + plain(comment) + "\n" + f.import_block)
    if not blocks:
        return ""
    head = ("# Import blocks from AWS Kit Drift. Needs Terraform 1.5 or newer. Run\n"
            "# terraform plan -generate-config-out=generated.tf to have Terraform write the\n"
            "# resource code, check it, then terraform apply.\n")
    return head + "\n" + "\n\n".join(blocks) + "\n"


EXPORT_COLS = [("status", "Status"), ("type", "Type"), ("id", "ID"), ("name", "Name"),
               ("region", "Region"), ("account", "Account"), ("address", "Address"),
               ("detail", "Detail"), ("fix", "What to do")]


def markdown_report(report, findings, show_all=False) -> str:
    from .common import to_markdown
    rows = [f.row() for f in findings]
    text = to_markdown(rows, [c for c in EXPORT_COLS if c[0] != "fix"], title="Drift",
                       intro=report.headline(show_all) + " " + report.subline(show_all))
    changed = [f for f in findings if f.changes]
    if changed:
        text += "\n## What changed\n"
        for f in changed:
            text += (f"\n### {plain(f.address or f.id)}\n\n"
                     "| Setting | In the state | In AWS |\n|---|---|---|\n")
            for c in f.changes:
                cells = [plain(x).replace("|", "\\|") for x in (c.setting, c.state, c.aws)]
                text += "| " + " | ".join(cells) + " |\n"
    imports = import_text(findings)
    if imports:
        text += "\n## Import blocks\n\n```hcl\n" + imports + "```\n"
    if report.notes:
        text += "\n## Notes\n\n" + "\n".join(f"- {plain(n)}" for n in report.notes) + "\n"
    return text


# =================================================================== command line

DESCRIPTION = ("Compares Terraform state with what's in the AWS account. Lists what's in the "
               "account but not in Terraform, what's in the state but gone from AWS, and "
               "settings changed outside Terraform. Read-only.")
EPILOG = """examples:
  awskit drift terraform.tfstate
  awskit drift state.json other-stack.json -p lab-admin
  terraform show -json | awskit drift -
  awskit drift ~/code/network             runs terraform show -json in that folder
  awskit drift ~/code/network --exact     also runs terraform plan -refresh-only there
  awskit drift state.json --imports imports.tf
  awskit drift state.json --fail-on-drift   exit code 2 when anything is found (for CI)
"""


def register_cli(sub, add_profiles):
    import argparse
    p = sub.add_parser("drift", help="Compare Terraform state with what's in the AWS account",
                       description=DESCRIPTION, epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("source", nargs="*", metavar="SOURCE",
                   help="State file, terraform show -json output, plan JSON, a Terraform folder, "
                        "or - for stdin. Several stacks can be given.")
    add_profiles(p)
    p.add_argument("-r", "--region", action="append",
                   help="Region to read (repeatable). Default: the regions the states use.")
    p.add_argument("--all", action="store_true",
                   help="Also list what's not in Terraform in types and regions your Terraform "
                        "doesn't manage")
    p.add_argument("--exact", action="store_true",
                   help="For folders, also run terraform plan -refresh-only and use Terraform's "
                        "own view of what changed")
    p.add_argument("--json", action="store_true", help="Print JSON")
    p.add_argument("--markdown", metavar="FILE", help="Write a Markdown report to FILE")
    p.add_argument("--imports", metavar="FILE",
                   help="Write import blocks for everything not in Terraform to FILE")
    p.add_argument("--fail-on-drift", action="store_true",
                   help="Exit with code 2 if anything is found")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show what changed and what to do for each one")
    p.add_argument("-q", "--quiet", action="store_true", help="No progress line")
    p.set_defaults(func=cmd_drift)


def _colorize(key, value):
    if key != "status":
        return None
    text = str(value)
    if text.startswith("Gone"):
        return "red"
    if text.startswith("Changed"):
        return "yellow"
    if text.startswith("Not in"):
        return "blue"
    return "dim"


TABLE_COLS = [("status", "Status"), ("type", "Type"), ("id", "ID"), ("name", "Name"),
              ("region", "Region"), ("detail", "Detail")]


def cmd_drift(args) -> int:
    from .cli import err, progress_printer, resolve_profiles, stdin_has_data
    from .common import color, table_text
    sources = list(args.source or [])
    if not sources:
        if stdin_has_data():
            sources = ["-"]
        else:
            err("Give a state file, plan JSON, or a Terraform folder, like: awskit drift "
                "terraform.tfstate (or awskit drift . for this folder).")
            return 1
    profiles = resolve_profiles(args)
    tf_profile = profiles[0] if profiles else None
    show = progress_printer(sys.stderr.isatty() and not args.json and not args.quiet)
    say = (lambda text: print(color(text, "dim"), file=sys.stderr)) \
        if not args.json and not args.quiet else (lambda text: None)

    stacks, labels = [], set()
    try:
        for src in sources:
            st = load_source(src, profile=tf_profile, run_terraform=True, log=say)
            if st.label in labels:
                st.label = f"{st.label} ({len(stacks) + 1})"
            labels.add(st.label)
            stacks.append(st)
    except DriftError as exc:
        err(str(exc))
        return 1

    exact = {}
    if args.exact:
        folders = [st for st in stacks if st.is_folder]
        if not folders:
            err("--exact only works for Terraform folders. Give the folder instead of its state "
                "file.")
            return 1
        for st in folders:
            say(f"Running terraform plan -refresh-only in {st.label}...")
            try:
                exact[st.label] = exact_check(st.path, profile=tf_profile, log=None)
            except DriftError as exc:
                exact[st.label] = str(exc).replace("\n", " ")[:600]

    try:
        report, inv = compare(stacks, profiles, args.region, progress=show, exact=exact)
    except AuthError as exc:
        err(str(exc))
        return 1
    if not inv.accounts:
        for n in report.notes:
            err(plain(n))
        err("No profile could be read, so nothing was compared.")
        return 1

    findings = report.visible(args.all)
    code = 2 if args.fail_on_drift and report.drift_found(args.all) else 0

    if args.imports:
        text = import_text(findings)
        if text:
            try:
                write_atomic(Path(args.imports), text)
            except OSError as exc:
                err(f"Couldn't write {args.imports}: {exc.strerror or exc}")
                return 1
            if not args.json:
                n = sum(1 for f in findings if f.import_block)
                print(f"Wrote {n} import block{'s' if n != 1 else ''} to {args.imports}",
                      file=sys.stderr)
        elif not args.json:
            print("Nothing outside Terraform, so no import blocks were written.", file=sys.stderr)

    if args.json:
        print(json.dumps({"headline": report.headline(args.all), "counts": report.counts(args.all),
                          "managed": report.managed, "stacks": report.stacks,
                          "elsewhere": 0 if args.all else report.elsewhere(),
                          "hidden_by_ignore_list": report.hidden,
                          "findings": [f.as_dict() for f in findings], "notes": report.notes},
                         indent=2, default=str))
        return code
    if args.markdown:
        try:
            write_atomic(Path(args.markdown), markdown_report(report, findings, args.all))
        except OSError as exc:
            err(f"Couldn't write {args.markdown}: {exc.strerror or exc}")
            return 1
        print(f"Wrote {args.markdown}")
        return code

    rows = [f.row() for f in findings]
    cols = TABLE_COLS
    if len(inv.accounts) > 1:
        cols = TABLE_COLS[:5] + [("profile", "Profile")] + TABLE_COLS[5:]
    if rows:
        print(table_text(rows, cols, max_width=48, colorize=_colorize))
        print()
    print(color(report.headline(args.all), "bold"))
    sub = report.subline(args.all)
    if sub:
        print(sub)
    if not args.all and report.elsewhere():
        print(color("Add --all to list the ones in types or regions your Terraform doesn't manage.",
                    "dim"))
    if args.verbose:
        for f in findings:
            print("\n" + f.detail_text())
    elif findings:
        print(color("Add -v to see what changed and what to do about each one.", "dim"))
    for n in report.notes:
        print(color("Note: " + plain(n), "yellow"), file=sys.stderr)
    return code
