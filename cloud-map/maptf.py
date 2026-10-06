"""Cloud Map's Terraform input. Reads a state or plan and builds the same model a live
scan does.

Accepts `terraform show -json` output (state or plan), a raw .tfstate file (like one
from `terraform state pull`), a saved binary plan, or a folder. For a folder it runs
`terraform show -json` to read the current state, or `terraform plan` with --plan.
It never runs apply.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import mapmodel as mm
from . import tfplan

KAA = "(known after apply)"

# One table for every Terraform type Cloud Map reads, and the kind of node it becomes.
# "detail" types are read to fill in another node (routes, rules, attachments) and
# aren't drawn on their own.
TYPE_KINDS = {
    "aws_vpc": "vpc", "aws_default_vpc": "vpc",
    "aws_vpc_ipv4_cidr_block_association": "detail",
    "aws_subnet": "subnet", "aws_default_subnet": "subnet",
    "aws_internet_gateway": "igw", "aws_internet_gateway_attachment": "detail",
    "aws_egress_only_internet_gateway": "eigw",
    "aws_nat_gateway": "nat",
    "aws_route_table": "route-table", "aws_default_route_table": "route-table",
    "aws_route": "detail", "aws_route_table_association": "detail",
    "aws_main_route_table_association": "detail",
    "aws_ec2_transit_gateway": "tgw", "aws_ec2_transit_gateway_vpc_attachment": "tgw-attachment",
    "aws_vpc_peering_connection": "peering", "aws_vpc_peering_connection_accepter": "detail",
    "aws_vpc_endpoint": "endpoint",
    "aws_security_group": "sg", "aws_default_security_group": "sg",
    "aws_vpc_security_group_ingress_rule": "detail", "aws_vpc_security_group_egress_rule": "detail",
    "aws_security_group_rule": "detail",
    "aws_network_acl": "nacl", "aws_default_network_acl": "detail",
    "aws_network_acl_association": "detail", "aws_network_acl_rule": "detail",
    "aws_instance": "instance", "aws_lb": "lb", "aws_alb": "lb",
    "aws_lb_listener": "detail", "aws_alb_listener": "detail",
    "aws_db_instance": "rds", "aws_db_subnet_group": "detail",
    "aws_vpn_gateway": "vgw", "aws_vpn_gateway_attachment": "detail",
    "aws_customer_gateway": "cgw", "aws_vpn_connection": "vpn",
    "aws_organizations_organization": "org", "aws_organizations_organizational_unit": "ou",
    "aws_organizations_account": "account", "aws_organizations_policy": "detail",
    "aws_organizations_policy_attachment": "detail",
    "aws_iam_role": "role", "aws_iam_role_policy_attachment": "detail",
    "aws_iam_openid_connect_provider": "oidc-provider", "aws_iam_saml_provider": "saml-provider",
    "aws_ssoadmin_permission_set": "permission-set",
    "aws_ssoadmin_managed_policy_attachment": "detail",
    "aws_ssoadmin_account_assignment": "sso-assignment",
    "aws_identitystore_user": "user", "aws_identitystore_group": "group",
    "aws_cloudtrail": "trail", "aws_s3_bucket": "bucket",
    "aws_budgets_budget": "cost", "aws_ce_anomaly_monitor": "cost",
    "aws_ce_anomaly_subscription": "detail",
}

# Data sources that help place resources and name principals.
DATA_TYPES = {"aws_caller_identity", "aws_region", "aws_identitystore_user",
              "aws_identitystore_group", "aws_ssoadmin_instances"}

# Types whose node ID comes from their ARN instead of their id attribute, so they match
# what a live scan uses.
ARN_IDS = {"aws_iam_role", "aws_iam_openid_connect_provider", "aws_iam_saml_provider",
           "aws_ssoadmin_permission_set", "aws_cloudtrail", "aws_lb", "aws_alb",
           "aws_db_instance"}


class TfError(Exception):
    pass


@dataclass
class Res:
    address: str
    type: str
    name: str
    index: object
    module: str
    provider: str
    values: dict
    mode: str = "managed"
    unknown: set = field(default_factory=set)
    refs: dict = field(default_factory=dict)
    each_value: object = None        # this instance's for_each value, when it can be worked out
    provider_key: str = ""
    node: str = ""
    account: str = ""
    region: str = ""

    @property
    def base(self) -> str:
        return re.sub(r"\[[^\]]*\]", "", self.address)


# =================================================================== loading

def load(path, plan=False, log=None) -> tuple:
    """Returns (data, label). Folders run terraform show (or plan with plan=True)."""
    p = Path(os.path.expanduser(str(path)))
    try:
        if p.is_dir():
            if plan:
                if log:
                    log(f"Running terraform plan in {p.name}")
                return tfplan.plan_directory(str(p), log=log), p.name
            if log:
                log(f"Reading the current state in {p.name}")
            return tfplan.show_state(str(p)), p.name
        if not p.is_file():
            raise TfError(f"{path} doesn't exist. Give a state or plan JSON file, a saved plan, "
                          "or a Terraform folder.")
        data = p.read_bytes()
        if data.lstrip()[:1] == b"{":
            try:
                return json.loads(data.decode("utf-8")), p.name
            except ValueError as exc:
                raise TfError(f"{p.name} isn't valid JSON: {exc}") from exc
        return tfplan.show_json(str(p)), p.name
    except tfplan.PlanError as exc:
        raise TfError(str(exc)) from exc


def read(paths, plan=False, log=None, known_accounts=()) -> mm.Snapshot:
    """One or more states, plans or folders, drawn as one map."""
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    parts, labels, kinds, versions, stamps = [], [], [], set(), set()
    for path in paths:
        data, label = load(path, plan=plan, log=log)
        snap, kind = build_unfinished(data, label)
        parts.append(snap)
        labels.append(label)
        kinds.append(kind)
        versions.add(str(data.get("terraform_version", "")))
        if kind == "plan" and data.get("timestamp"):
            stamps.add(str(data["timestamp"]))
    snap = parts[0] if len(parts) == 1 else mm.merge(parts)
    snap.source = "terraform"
    snap.scanned_at = max(stamps) if stamps else ""
    snap.scope = {"inputs": labels, "kind": sorted(set(kinds)),
                  "terraform_version": sorted(v for v in versions if v)}
    return mm.finish(snap, known_accounts)


# =================================================================== flattening

def _walk(module, out, mode_filter=None):
    if not isinstance(module, dict):
        return
    for r in module.get("resources", []) or []:
        out.append((module.get("address", ""), r))
    for child in module.get("child_modules", []) or []:
        _walk(child, out)


def _unknown_keys(after_unknown) -> set:
    if not isinstance(after_unknown, dict):
        return set()
    out = set()
    for k, v in after_unknown.items():
        if v is True or (isinstance(v, list) and any(x is True for x in v)):
            out.add(k)
    return out


def _config_index(module, prefix, out, for_each=None, inputs=None, parent_inputs=None):
    """address without instance keys -> (expressions, provider_config_key). With for_each
    and inputs, also each resource's for_each expression, and each module's input
    values where they're constants (or the root's variables passed straight through)."""
    if not isinstance(module, dict):
        return
    for r in module.get("resources", []) or []:
        out[prefix + r.get("address", "")] = (r.get("expressions") or {},
                                              r.get("provider_config_key", ""))
        if for_each is not None and r.get("for_each_expression") is not None:
            for_each[prefix + r.get("address", "")] = r["for_each_expression"]
    for name, call in (module.get("module_calls") or {}).items():
        child = f"{prefix}module.{name}."
        if inputs is not None:
            values = {}
            for var, expr in (call.get("expressions") or {}).items():
                got = _expr_value(expr, parent_inputs or {})
                if got is not None:
                    values[var] = got
            inputs[child] = values
        _config_index(call.get("module") or {}, child, out, for_each, inputs,
                      inputs.get(child) if inputs is not None else None)


def _expr_value(expr, variables):
    """A constant expression's value, or a variable passed straight through."""
    if not isinstance(expr, dict):
        return None
    if "constant_value" in expr:
        return expr["constant_value"]
    refs = [r for r in expr.get("references") or [] if str(r).startswith("var.")]
    if len(refs) == 1:
        return variables.get(str(refs[0])[4:])
    return None


def _each_values(resources, for_each, inputs, root_vars):
    """Set each instance's each.value from its for_each expression, when it's a constant
    or a variable whose value is known. Generated modules (like the designer's) are
    written this way, so their references can be followed per instance."""
    for res in resources:
        if res.index is None or not isinstance(res.index, str):
            continue
        expr = for_each.get(res.base)
        if expr is None:
            continue
        variables = root_vars if not res.module else inputs.get(res.module + ".", {})
        collection = _expr_value(expr, variables)
        if collection is None:
            # A for expression over a variable, like { for k, v in var.x : k => v if ... }
            refs = [r for r in expr.get("references") or [] if str(r).startswith("var.")]
            if refs:
                collection = variables.get(str(refs[0])[4:])
        if isinstance(collection, dict) and res.index in collection:
            res.each_value = collection[res.index]


def _refs(expressions) -> dict:
    out = {}
    for attr, expr in (expressions or {}).items():
        refs = []
        stack = [expr]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                if isinstance(cur.get("references"), list):
                    refs += [str(x) for x in cur["references"]]
                stack += [v for k, v in cur.items() if k != "references"]
            elif isinstance(cur, list):
                stack += cur
        if refs:
            out[attr] = refs
    return out


def flatten(data) -> tuple:
    """(list of Res, kind, provider settings) from show -json state, plan, or raw state."""
    if not isinstance(data, dict):
        raise TfError("That doesn't look like Terraform state or plan JSON.")
    resources, kind = [], "state"
    providers = {}
    if "planned_values" in data or "resource_changes" in data:
        kind = "plan"
        flat = []
        _walk((data.get("planned_values") or {}).get("root_module"), flat)
        prior = []
        _walk(((data.get("prior_state") or {}).get("values") or {}).get("root_module"), prior)
        seen = {r.get("address") for _, r in flat}
        flat += [(m, r) for m, r in prior if r.get("mode") == "data" and r.get("address") not in seen]
        unknown = {}
        for rc in data.get("resource_changes", []) or []:
            unknown[rc.get("address")] = _unknown_keys((rc.get("change") or {}).get("after_unknown"))
        config, for_each, inputs = {}, {}, {}
        root_vars = {k: (v or {}).get("value") for k, v in (data.get("variables") or {}).items()}
        _config_index((data.get("configuration") or {}).get("root_module"), "", config,
                      for_each, inputs, root_vars)
        for key, prov in ((data.get("configuration") or {}).get("provider_config") or {}).items():
            providers[key] = _provider_settings(prov)
        for module, r in flat:
            res = _res(module, r)
            res.unknown = unknown.get(res.address, set())
            expr, pkey = config.get(res.base, ({}, ""))
            res.refs = _refs(expr)
            res.provider_key = pkey
            resources.append(res)
        _each_values(resources, for_each, inputs, root_vars)
    elif "values" in data:
        flat = []
        _walk((data.get("values") or {}).get("root_module"), flat)
        resources = [_res(m, r) for m, r in flat]
    elif "resources" in data and "version" in data:
        kind = "raw state"
        for r in data.get("resources", []) or []:
            module = r.get("module", "")
            prefix = "data." if r.get("mode") == "data" else ""
            for inst in r.get("instances", []) or []:
                idx = inst.get("index_key")
                addr = f"{prefix}{r['type']}.{r['name']}"
                if idx is not None:
                    addr += f"[{json.dumps(idx)}]"
                if module:
                    addr = f"{module}.{addr}"
                resources.append(Res(addr, r["type"], r["name"], idx, module,
                                     str(r.get("provider", "")), inst.get("attributes") or {},
                                     r.get("mode", "managed")))
    else:
        raise TfError("That doesn't look like Terraform state or plan JSON. Use the output of "
                      "terraform show -json, or a .tfstate file.")
    return resources, kind, providers


def _res(module, r) -> Res:
    return Res(r.get("address", ""), r.get("type", ""), r.get("name", ""), r.get("index"),
               module or "", str(r.get("provider_name", "")), r.get("values") or {},
               r.get("mode", "managed"))


def _constant(expr):
    if isinstance(expr, dict):
        return expr.get("constant_value")
    return None


def _provider_settings(prov) -> dict:
    expr = (prov or {}).get("expressions") or {}
    out = {"region": _constant(expr.get("region")) or ""}
    allowed = _constant(expr.get("allowed_account_ids"))
    if isinstance(allowed, list) and len(allowed) == 1:
        out["account"] = str(allowed[0])
    for block in expr.get("assume_role") or []:
        arn = _constant((block or {}).get("role_arn"))
        if arn and not out.get("account"):
            out["account"] = mm.account_of_arn(arn)
    return out


# =================================================================== building

class Builder:
    def __init__(self, resources, providers, label="", kind="state"):
        self.all = resources
        self.res = [r for r in resources if r.mode != "data"]
        self.data = [r for r in resources if r.mode == "data"]
        self.providers = providers
        self.snap = mm.Snapshot("terraform")
        self.by_address = {r.address: r for r in self.res}
        self.by_base = {}
        for r in self.res:
            self.by_base.setdefault(r.base, []).append(r)
        self.skipped = Counter()

    # ---- values
    def val(self, r, attr, default=None):
        if attr in r.unknown:
            return KAA
        v = r.values.get(attr)
        return default if v is None else v

    def known(self, r, attr):
        """The value only if it's known, else None."""
        if attr in r.unknown:
            return None
        v = r.values.get(attr)
        return None if v in (None, "") else v

    def first(self, r, attr) -> dict:
        v = r.values.get(attr)
        if isinstance(v, list):
            return v[0] if v and isinstance(v[0], dict) else {}
        return v if isinstance(v, dict) else {}

    def tags(self, r) -> dict:
        t = r.values.get("tags") or r.values.get("tags_all") or {}
        return {str(k): str(v) for k, v in t.items()} if isinstance(t, dict) else {}

    def name_tag(self, r) -> str:
        return self.tags(r).get("Name", "")

    def _each_keys(self, r, refs) -> list:
        """Instance keys from each.key and each.value.x references, like the "public-a" in
        aws_subnet.this[each.value.subnet]."""
        keys = []
        for ref in refs:
            if ref == "each.key" and r.index is not None:
                keys.append(r.index)
            elif ref.startswith("each.value.") and isinstance(r.each_value, dict):
                v = r.each_value
                for part in ref[len("each.value."):].split("."):
                    v = v.get(part) if isinstance(v, dict) else None
                if isinstance(v, (str, int)):
                    keys.append(v)
                elif isinstance(v, list):
                    keys += [x for x in v if isinstance(x, (str, int))]
        return keys

    def _from_config(self, r, attr) -> list:
        out = []
        refs = r.refs.get(attr, [])
        keys = self._each_keys(r, refs)
        # each.value.x that's known and null (like an optional reference left out) means
        # nothing is referenced, not every instance.
        dynamic = r.each_value is not None and any(
            x == "each.key" or x.startswith("each.value.") for x in refs)
        for ref in refs:
            m = re.match(r"((?:data\.)?aws_[a-z0-9_]+\.[A-Za-z0-9_-]+)(\[[^\]]+\])?", ref)
            if not m:
                continue
            prefix = (r.module + ".") if r.module else ""
            if m.group(2):
                hit = self.by_address.get(prefix + m.group(1) + m.group(2))
                cands = [hit] if hit else []
            else:
                keyed = [self.by_address.get(f"{prefix}{m.group(1)}[{json.dumps(k)}]") for k in keys]
                keyed = [c for c in keyed if c is not None]
                cands = self.by_base.get(prefix + m.group(1), [])
                same = [c for c in cands if c.index == r.index and r.index is not None]
                cands = keyed if (keyed or dynamic) else (same or cands)
            for c in cands:
                if c.node and c.node not in out:
                    out.append(c.node)
        return out

    def ref(self, r, attr) -> str:
        v = self.known(r, attr)
        if isinstance(v, str):
            return v
        got = self._from_config(r, attr)
        return got[0] if got else ""

    def refs(self, r, attr) -> list:
        v = r.values.get(attr) if attr not in r.unknown else None
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            return sorted(set(v))
        return sorted(set(self._from_config(r, attr)))

    # ---- placement
    def place(self):
        """Work out each resource's account and region, then its node ID."""
        identities = {}
        regions = {}
        for d in self.data:
            if d.type == "aws_caller_identity" and d.values.get("account_id"):
                identities[d.provider_key or d.provider or d.module] = str(d.values["account_id"])
            if d.type == "aws_region" and (d.values.get("name") or d.values.get("region")):
                regions[d.provider_key or d.provider or d.module] = str(
                    d.values.get("name") or d.values.get("region"))
        for r in self.res:
            arn = r.values.get("arn") if "arn" not in r.unknown else None
            r.account = mm.account_of_arn(arn) if isinstance(arn, str) else ""
            r.region = mm.region_of_arn(arn) if isinstance(arn, str) else ""
            prov = self.providers.get(r.provider_key) or self.providers.get(
                r.provider_key.split(":")[-1], {}) if r.provider_key else {}
            key = r.provider_key or r.provider or r.module
            r.account = r.account or prov.get("account", "") or identities.get(key, "")
            r.region = r.region or prov.get("region", "") or regions.get(key, "")
            az = self.known(r, "availability_zone")
            if not r.region and isinstance(az, str):
                r.region = mm.region_of_az(az)
            if r.type == "aws_budgets_budget" and self.known(r, "account_id"):
                r.account = str(r.values["account_id"])
        # A module's other resources usually share its account and region.
        mod_acct, mod_region = {}, {}
        for r in self.res:
            if r.account and not r.type.startswith("aws_organizations_"):
                mod_acct.setdefault(r.module, set()).add(r.account)
            if r.region:
                mod_region.setdefault(r.module, set()).add(r.region)
        single_identity = sorted(set(identities.values()))
        single_region = sorted(set(regions.values()))
        for r in self.res:
            if not r.account:
                accts = mod_acct.get(r.module, set())
                if len(accts) == 1:
                    r.account = next(iter(accts))
                elif len(single_identity) == 1:
                    r.account = single_identity[0]
            if not r.region:
                regs = mod_region.get(r.module, set())
                if len(regs) == 1:
                    r.region = next(iter(regs))
                elif len(single_region) == 1:
                    r.region = single_region[0]
        for r in self.res:
            r.node = self.node_id(r)

    def node_id(self, r) -> str:
        v = r.values
        if r.type == "aws_s3_bucket":
            name = self.known(r, "bucket")
            return f"arn:aws:s3:::{name}" if name else r.address
        if r.type in ARN_IDS:
            arn = self.known(r, "arn")
            if arn:
                return arn
            name = self.known(r, "name")
            if r.account and name:
                if r.type == "aws_iam_role":
                    path = self.known(r, "path") or "/"
                    return f"arn:aws:iam::{r.account}:role{path}{name}"
                if r.type == "aws_cloudtrail" and r.region:
                    return f"arn:aws:cloudtrail:{r.region}:{r.account}:trail/{name}"
            if r.type == "aws_iam_openid_connect_provider" and r.account:
                url = self.known(r, "url")
                if url:
                    return f"arn:aws:iam::{r.account}:oidc-provider/{re.sub(r'^https://', '', url)}"
            return r.address
        rid = self.known(r, "id")
        if r.type in ("aws_organizations_policy_attachment", "aws_route",
                      "aws_route_table_association", "aws_security_group_rule"):
            return r.address
        return str(rid) if rid else (str(v.get("id")) if v.get("id") and "id" not in r.unknown
                                    else r.address)

    # ---- the build
    ORDER = ("aws_organizations_organization", "aws_organizations_policy",
             "aws_organizations_organizational_unit", "aws_organizations_account",
             "aws_organizations_policy_attachment",
             "aws_vpc", "aws_default_vpc", "aws_vpc_ipv4_cidr_block_association",
             "aws_subnet", "aws_default_subnet", "aws_internet_gateway",
             "aws_internet_gateway_attachment", "aws_egress_only_internet_gateway",
             "aws_vpn_gateway", "aws_vpn_gateway_attachment", "aws_customer_gateway",
             "aws_nat_gateway", "aws_ec2_transit_gateway", "aws_ec2_transit_gateway_vpc_attachment",
             "aws_vpc_peering_connection", "aws_route_table", "aws_default_route_table",
             "aws_route", "aws_route_table_association", "aws_main_route_table_association",
             "aws_vpc_endpoint", "aws_security_group", "aws_default_security_group",
             "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
             "aws_security_group_rule", "aws_network_acl", "aws_default_network_acl",
             "aws_network_acl_rule", "aws_network_acl_association", "aws_db_subnet_group",
             "aws_instance", "aws_lb", "aws_alb", "aws_lb_listener", "aws_alb_listener",
             "aws_db_instance", "aws_vpn_connection",
             "aws_iam_openid_connect_provider", "aws_iam_saml_provider", "aws_iam_role",
             "aws_iam_role_policy_attachment", "aws_identitystore_user",
             "aws_identitystore_group", "aws_ssoadmin_permission_set",
             "aws_ssoadmin_managed_policy_attachment", "aws_ssoadmin_account_assignment",
             "aws_s3_bucket", "aws_cloudtrail", "aws_budgets_budget", "aws_ce_anomaly_monitor")

    def build(self) -> mm.Snapshot:
        self.place()
        self.policies = {}
        self.scp_targets = {}
        self.subnet_groups = {}
        self.default_acls = {}          # a VPC's default network ACL ID -> the VPC
        self.org = None
        self.principal_names = {}
        for d in self.data:
            self._principal_from(d)
        order = {t: i for i, t in enumerate(self.ORDER)}
        for r in sorted(self.res, key=lambda r: (order.get(r.type, 999), r.address)):
            handler = getattr(self, "t_" + r.type, None)
            if handler is None:
                if r.type not in TYPE_KINDS:
                    self.skipped[r.type] += 1
                continue
            handler(r)
        self._attach_scps()
        if self.skipped:
            parts = [f"{n} {t}" for t, n in sorted(self.skipped.items())]
            self.snap.warn("Not drawn from Terraform: " + ", ".join(parts))
        return self.snap

    def _principal_from(self, r):
        if r.type == "aws_identitystore_user":
            uid = self.known(r, "user_id") or self.known(r, "id")
            if uid:
                name = self.known(r, "display_name") or self.known(r, "user_name") or uid
                self.principal_names[str(uid).split("/")[-1]] = ("user", name)
        elif r.type == "aws_identitystore_group":
            gid = self.known(r, "group_id") or self.known(r, "id")
            if gid:
                name = self.known(r, "display_name") or gid
                self.principal_names[str(gid).split("/")[-1]] = ("group", name)

    # ---- organizations
    def t_aws_organizations_organization(self, r):
        roots = r.values.get("roots") or []
        root = roots[0] if roots and isinstance(roots[0], dict) else {}
        enabled = r.values.get("enabled_policy_types") or []
        root_scps = ["FullAWSAccess"] if "SERVICE_CONTROL_POLICY" in enabled else []
        accounts = [{"id": str(a.get("id")), "name": a.get("name", ""), "email": a.get("email", ""),
                     "status": a.get("status", "")}
                    for a in (r.values.get("accounts") or []) if isinstance(a, dict) and a.get("id")]
        self.org = mm.add_org(self.snap, r.node, self.known(r, "arn") or "",
                              str(self.known(r, "master_account_id") or r.account or ""),
                              root.get("id", ""), root_scps, accounts, source="terraform")

    def t_aws_organizations_policy(self, r):
        self.policies[r.node] = {"name": self.val(r, "name", r.name),
                                 "type": self.val(r, "type", "SERVICE_CONTROL_POLICY"),
                                 "content": self.known(r, "content") or ""}

    def t_aws_organizations_organizational_unit(self, r):
        mm.add_ou(self.snap, r.node, self.val(r, "name", r.name), self.ref(r, "parent_id"),
                  self.known(r, "arn") or "", tags=self.tags(r), source="terraform")

    def t_aws_organizations_account(self, r):
        acct = mm.add_org_account(self.snap, r.node, self.val(r, "name", r.name),
                                  self.ref(r, "parent_id"), self.known(r, "arn") or "",
                                  self.known(r, "email") or "", self.known(r, "status") or "",
                                  tags=self.tags(r), source="terraform")
        role_name = self.known(r, "role_name")
        master = (self.org.props.get("master_account") if self.org is not None else "") or r.account
        if role_name and re.fullmatch(r"\d{12}", acct.id) and master:
            trust = {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{master}:root"},
                "Action": "sts:AssumeRole"}]}
            mm.add_role(self.snap, f"arn:aws:iam::{acct.id}:role/{role_name}", role_name,
                        trust=trust, source="terraform").props["created_by"] = \
                "Organizations, from role_name on " + r.address

    def t_aws_organizations_policy_attachment(self, r):
        pid = self.ref(r, "policy_id")
        target = self.ref(r, "target_id")
        if pid and target:
            self.scp_targets.setdefault(target, set()).add(pid)

    def _attach_scps(self):
        roots = set()
        for org in self.snap.of_kind("org"):
            if org.props.get("root_id"):
                roots.add(org.props["root_id"])
        summaries = {}
        for target, pids in sorted(self.scp_targets.items()):
            names = []
            for pid in sorted(pids):
                pol = self.policies.get(pid, {"name": pid, "type": "SERVICE_CONTROL_POLICY"})
                if pol.get("type", "SERVICE_CONTROL_POLICY") != "SERVICE_CONTROL_POLICY":
                    continue
                names.append(pol["name"])
                summaries[pol["name"]] = scp_summary(pol.get("content", ""))
            node = self.snap.get(target)
            if target in roots:
                for org in self.snap.of_kind("org"):
                    org.props["scps"] = sorted(set(org.props.get("scps", [])) | set(names))
            elif node is not None:
                node.props["scps"] = sorted(set(node.props.get("scps", [])) | set(names))
        for org in self.snap.of_kind("org"):
            org.props["scp_summaries"] = dict(org.props.get("scp_summaries", {}), **summaries)

    # ---- network
    def t_aws_vpc(self, r, default=False):
        mm.add_vpc(self.snap, r.node, r.account, r.region, [self.val(r, "cidr_block", "")],
                   self.name_tag(r), default, self.tags(r), "terraform")
        acl = self.known(r, "default_network_acl_id")
        if isinstance(acl, str):
            self.default_acls[acl] = r.node

    def t_aws_default_vpc(self, r):
        self.t_aws_vpc(r, default=True)

    def t_aws_vpc_ipv4_cidr_block_association(self, r):
        vpc = self.snap.get(self.ref(r, "vpc_id"))
        if vpc is not None:
            vpc.props["cidrs"] = sorted(set(vpc.props.get("cidrs", [])) |
                                        {self.val(r, "cidr_block", "")} - {""})

    def t_aws_subnet(self, r):
        mm.add_subnet(self.snap, r.node, self.ref(r, "vpc_id"),
                      self.val(r, "availability_zone", ""), self.val(r, "cidr_block", ""),
                      self.name_tag(r), self.known(r, "ipv6_cidr_block") or "",
                      self.known(r, "map_public_ip_on_launch"), r.account, r.region,
                      self.tags(r), "terraform")

    t_aws_default_subnet = t_aws_subnet

    def t_aws_internet_gateway(self, r):
        mm.add_gateway(self.snap, "igw", r.node, self.ref(r, "vpc_id"), r.account, r.region,
                       self.name_tag(r), self.tags(r), "terraform")

    def t_aws_internet_gateway_attachment(self, r):
        igw, vpc = self.ref(r, "internet_gateway_id"), self.ref(r, "vpc_id")
        node = self.snap.get(igw)
        if node is not None and vpc:
            node.parent = vpc
            node.props["vpc"] = vpc

    def t_aws_egress_only_internet_gateway(self, r):
        mm.add_gateway(self.snap, "eigw", r.node, self.ref(r, "vpc_id"), r.account, r.region,
                       self.name_tag(r), self.tags(r), "terraform")

    def t_aws_vpn_gateway(self, r):
        mm.add_gateway(self.snap, "vgw", r.node, self.ref(r, "vpc_id"), r.account, r.region,
                       self.name_tag(r), self.tags(r), "terraform",
                       asn=str(self.known(r, "amazon_side_asn") or ""))

    def t_aws_vpn_gateway_attachment(self, r):
        vgw, vpc = self.ref(r, "vpn_gateway_id"), self.ref(r, "vpc_id")
        node = self.snap.get(vgw)
        if node is not None and vpc:
            node.parent = vpc
            node.props["vpc"] = vpc

    def t_aws_customer_gateway(self, r):
        mm.add_cgw(self.snap, r.node, r.account, r.region, self.val(r, "ip_address", ""),
                   self.known(r, "bgp_asn") or "", self.name_tag(r), self.tags(r), "terraform")

    def _vpc_of_subnet(self, subnet_id) -> str:
        sn = self.snap.get(subnet_id)
        return sn.props.get("vpc", "") if sn is not None else ""

    def t_aws_nat_gateway(self, r):
        subnet = self.ref(r, "subnet_id")
        mm.add_nat(self.snap, r.node, subnet, self._vpc_of_subnet(subnet),
                   self.known(r, "connectivity_type") or "public",
                   self.val(r, "public_ip", "") if self.known(r, "connectivity_type") != "private" else "",
                   name=self.name_tag(r), tags=self.tags(r), source="terraform")

    def t_aws_ec2_transit_gateway(self, r):
        mm.add_tgw(self.snap, r.node, r.account, r.region, self.known(r, "amazon_side_asn") or "",
                   self.name_tag(r), str(self.known(r, "owner_id") or ""), self.tags(r),
                   "terraform")

    def t_aws_ec2_transit_gateway_vpc_attachment(self, r):
        mm.add_tgw_attachment(self.snap, r.node, self.ref(r, "transit_gateway_id"),
                              self.ref(r, "vpc_id"), self.refs(r, "subnet_ids"),
                              name=self.name_tag(r), tags=self.tags(r), source="terraform")

    def t_aws_vpc_peering_connection(self, r):
        mm.add_peering(self.snap, r.node, self.ref(r, "vpc_id"), self.ref(r, "peer_vpc_id"),
                       str(self.known(r, "accept_status") or ""),
                       accepter={"account": str(self.known(r, "peer_owner_id") or r.account),
                                 "region": self.known(r, "peer_region") or r.region},
                       name=self.name_tag(r))

    ROUTE_TARGETS = ("gateway_id", "nat_gateway_id", "transit_gateway_id",
                     "vpc_peering_connection_id", "egress_only_gateway_id", "vpc_endpoint_id",
                     "network_interface_id", "instance_id", "local_gateway_id",
                     "carrier_gateway_id")

    def _route_parts(self, block, r=None, prefix=""):
        dest = (block.get(prefix + "cidr_block") or block.get(prefix + "ipv6_cidr_block") or
                block.get("destination_prefix_list_id") or "")
        target = ""
        for key in self.ROUTE_TARGETS:
            if block.get(key):
                target = block[key]
                break
            if r is not None and not block.get(key) and r.refs.get(key):
                got = self._from_config(r, key)
                if got:
                    target = got[0]
                    break
        return dest, target

    def t_aws_route_table(self, r, main=False):
        routes = []
        for block in r.values.get("route") or []:
            if isinstance(block, dict):
                dest, target = self._route_parts(block)
                if dest and target:
                    routes.append({"dest": dest, "target": target})
        mm.add_route_table(self.snap, r.node, self.ref(r, "vpc_id"), routes, main=main,
                           name=self.name_tag(r), tags=self.tags(r), source="terraform")

    def t_aws_default_route_table(self, r):
        self.t_aws_route_table(r, main=True)

    def t_aws_route(self, r):
        dest = (self.known(r, "destination_cidr_block") or
                self.known(r, "destination_ipv6_cidr_block") or
                self.known(r, "destination_prefix_list_id") or "")
        target = ""
        for key in self.ROUTE_TARGETS:
            target = self.ref(r, key)
            if target:
                break
        rt = self.ref(r, "route_table_id")
        if rt and dest and target:
            mm.add_route(self.snap, rt, dest, target)

    def t_aws_route_table_association(self, r):
        rt, subnet = self.ref(r, "route_table_id"), self.ref(r, "subnet_id")
        if rt and subnet:
            mm.associate_subnet(self.snap, rt, subnet)

    def t_aws_main_route_table_association(self, r):
        rt, vpc = self.ref(r, "route_table_id"), self.ref(r, "vpc_id")
        if rt and vpc:
            mm.set_main_route_table(self.snap, vpc, rt)

    def t_aws_vpc_endpoint(self, r):
        mm.add_endpoint(self.snap, r.node, self.ref(r, "vpc_id"),
                        self.val(r, "service_name", ""),
                        self.known(r, "vpc_endpoint_type") or "Gateway",
                        self.refs(r, "subnet_ids"), self.refs(r, "route_table_ids"),
                        self.name_tag(r), self.tags(r), "terraform")

    def _inline_rules(self, r, attr):
        out = []
        for b in r.values.get(attr) or []:
            if not isinstance(b, dict):
                continue
            groups = list(b.get("security_groups") or [])
            if b.get("self"):
                groups.append(r.node)
            out.append(mm.rule(b.get("protocol"), b.get("from_port"), b.get("to_port"),
                               list(b.get("cidr_blocks") or []) + list(b.get("ipv6_cidr_blocks") or []),
                               groups, b.get("description", ""),
                               prefix_lists=list(b.get("prefix_list_ids") or [])))
        return out

    def t_aws_security_group(self, r):
        mm.add_security_group(self.snap, r.node, self.ref(r, "vpc_id"),
                              self.val(r, "name", r.name), self.known(r, "description") or "",
                              self._inline_rules(r, "ingress"), self._inline_rules(r, "egress"),
                              self.tags(r), "terraform")

    t_aws_default_security_group = t_aws_security_group

    def _vpc_rule(self, r, direction):
        sg = self.ref(r, "security_group_id")
        if not sg:
            return
        cidrs = [c for c in (self.known(r, "cidr_ipv4"), self.known(r, "cidr_ipv6")) if c]
        groups = [g for g in (self.ref(r, "referenced_security_group_id"),) if g]
        proto = self.known(r, "ip_protocol") or "-1"
        lists = [p for p in (self.known(r, "prefix_list_id"),) if isinstance(p, str)]
        mm.add_sg_rule(self.snap, sg, direction, mm.rule(
            proto, self.known(r, "from_port"), self.known(r, "to_port"), cidrs, groups,
            self.known(r, "description") or "", prefix_lists=lists))

    def t_aws_vpc_security_group_ingress_rule(self, r):
        self._vpc_rule(r, "ingress")

    def t_aws_vpc_security_group_egress_rule(self, r):
        self._vpc_rule(r, "egress")

    def t_aws_security_group_rule(self, r):
        sg = self.ref(r, "security_group_id")
        if not sg:
            return
        groups = [g for g in (self.ref(r, "source_security_group_id"),) if g]
        if r.values.get("self"):
            groups.append(sg)
        cidrs = list(r.values.get("cidr_blocks") or []) + list(r.values.get("ipv6_cidr_blocks") or [])
        mm.add_sg_rule(self.snap, sg, self.val(r, "type", "ingress"), mm.rule(
            r.values.get("protocol"), r.values.get("from_port"), r.values.get("to_port"),
            cidrs, groups, r.values.get("description", ""),
            prefix_lists=list(r.values.get("prefix_list_ids") or [])))

    def _acl_entries(self, r) -> list:
        """Inline ingress and egress blocks, plus the catch-all deny AWS adds to every
        network ACL (Terraform doesn't list it)."""
        out = []
        for attr, egress in (("ingress", False), ("egress", True)):
            if attr in r.unknown:
                continue
            for b in r.values.get(attr) or []:
                entry = self._acl_entry(b, egress, "action")
                if entry is not None:
                    out.append(entry)
        return out + mm.default_nacl_entries()

    @staticmethod
    def _acl_entry(b, egress, action_key):
        if not isinstance(b, dict):
            return None
        try:
            return mm.nacl_entry(b.get("rule_no", b.get("rule_number")), egress,
                                 b.get(action_key, "deny"), b.get("protocol", "-1"),
                                 b.get("cidr_block", ""), b.get("ipv6_cidr_block", ""),
                                 b.get("from_port"), b.get("to_port"), b.get("icmp_type"),
                                 b.get("icmp_code"))
        except (TypeError, ValueError):
            return None                  # a rule number that isn't known yet

    def _acl_unknown(self, node, r):
        """A plan where the inline rules are known only after apply: say so, so
        reachability doesn't take the ACL for one that only has the catch-all deny."""
        if node is not None and ("ingress" in r.unknown or "egress" in r.unknown):
            node.props["rules_unknown"] = True

    def t_aws_network_acl(self, r):
        node = mm.add_nacl(self.snap, r.node, self.ref(r, "vpc_id"), self.refs(r, "subnet_ids"),
                           False, self.name_tag(r), self.tags(r), "terraform",
                           entries=self._acl_entries(r))
        self._acl_unknown(node, r)

    def t_aws_default_network_acl(self, r):
        """Adopts the VPC's default ACL and replaces its rules with the ones given. It
        covers every subnet not associated with another ACL."""
        vpc = self.known(r, "vpc_id") or ""
        if not vpc:
            got = self._from_config(r, "default_network_acl_id")
            vpc = next((n for n in got if self.snap.get(n) is not None
                        and self.snap.get(n).kind == "vpc"), "")
        node = mm.add_nacl(self.snap, r.node, vpc, self.refs(r, "subnet_ids"), True,
                           self.name_tag(r), self.tags(r), "terraform",
                           entries=self._acl_entries(r))
        self._acl_unknown(node, r)

    def t_aws_network_acl_rule(self, r):
        acl = self.ref(r, "network_acl_id")
        if not acl:
            return
        node = self.snap.get(acl)
        vpc = acl if node is not None and node.kind == "vpc" else self.default_acls.get(acl, "")
        if vpc and (node is None or node.kind == "vpc"):
            # A rule added to a VPC's default ACL that this input doesn't manage itself:
            # the ACL starts with AWS's defaults, allow everything (100, and 101 for IPv6).
            ids = [a for a, v in self.default_acls.items() if v == vpc]
            acl = ids[0] if ids else f"{vpc}/default-network-acl"
            if self.snap.get(acl) is None:
                start = [mm.nacl_entry(100, eg, "allow", "-1", "0.0.0.0/0") for eg in (False, True)]
                start += [mm.nacl_entry(101, eg, "allow", "-1", "", "::/0") for eg in (False, True)]
                mm.add_nacl(self.snap, acl, vpc, (), True, source="terraform",
                            entries=start + mm.default_nacl_entries())
        entry = self._acl_entry(dict(r.values, rule_no=r.values.get("rule_number")),
                                bool(r.values.get("egress")), "rule_action")
        if entry is not None:
            mm.add_nacl_entry(self.snap, acl, entry)

    def t_aws_network_acl_association(self, r):
        acl, subnet = self.ref(r, "network_acl_id"), self.ref(r, "subnet_id")
        node = self.snap.get(acl)
        if node is None or node.kind != "nacl" or not subnet:
            return                  # like a VPC's default ACL in a plan, found as the VPC
        node.props["subnets"] = sorted(set(node.props.get("subnets", [])) | {subnet})
        # A subnet is in one ACL at a time: it leaves the default one.
        for other in self.snap.of_kind("nacl"):
            if other.id != acl and subnet in other.props.get("subnets", []) and \
                    other.props.get("default"):
                other.props["subnets"] = [s for s in other.props["subnets"] if s != subnet]

    def t_aws_db_subnet_group(self, r):
        name = self.known(r, "name") or r.name
        self.subnet_groups[name] = self.refs(r, "subnet_ids")
        self.subnet_groups[r.node] = self.subnet_groups[name]

    def t_aws_instance(self, r):
        subnet = self.ref(r, "subnet_id")
        meta = self.first(r, "metadata_options")
        public = self.val(r, "public_ip", "")
        if public in ("", None) and r.values.get("associate_public_ip_address"):
            public = KAA
        mm.add_instance(self.snap, r.node, subnet, self._vpc_of_subnet(subnet), self.name_tag(r),
                        self.val(r, "instance_type", ""),
                        self.known(r, "instance_state") or ("planned" if r.unknown else ""),
                        self.val(r, "private_ip", ""), public,
                        self.refs(r, "vpc_security_group_ids"), meta.get("http_tokens", ""),
                        meta.get("http_endpoint", ""),
                        self.known(r, "iam_instance_profile") or "", self.tags(r), "terraform",
                        **self._ipv6(r))

    def _ipv6(self, r) -> dict:
        ips = [x for x in (self.known(r, "ipv6_addresses") or []) if isinstance(x, str) and x]
        return {"ipv6_ips": sorted(set(ips))} if ips else {}

    def t_aws_lb(self, r):
        subnets = self.refs(r, "subnets")
        vpc = self.ref(r, "vpc_id") or (self._vpc_of_subnet(subnets[0]) if subnets else "")
        azs = sorted({self.snap.get(s).props.get("az", "") for s in subnets
                      if self.snap.get(s) is not None} - {""})
        internal = r.values.get("internal")
        mm.add_lb(self.snap, r.node, self.val(r, "name", r.name), vpc, subnets, azs,
                  "internal" if internal else "internet-facing",
                  self.known(r, "load_balancer_type") or "application", self.tags(r), "terraform",
                  security_groups=self.refs(r, "security_groups"))

    t_aws_alb = t_aws_lb

    def t_aws_lb_listener(self, r):
        lb = self.ref(r, "load_balancer_arn")
        node = self.snap.get(lb)
        if node is None or node.kind != "lb":
            return
        mm.add_listener(self.snap, lb, self.known(r, "port"), self.known(r, "protocol") or "")

    t_aws_alb_listener = t_aws_lb_listener

    def t_aws_db_instance(self, r):
        group = self.ref(r, "db_subnet_group_name")
        subnets = self.subnet_groups.get(group, [])
        vpc = self._vpc_of_subnet(subnets[0]) if subnets else ""
        mm.add_rds(self.snap, r.node, self.val(r, "identifier", r.name), vpc, subnets,
                   self.known(r, "availability_zone") or "", self.val(r, "engine", ""),
                   self.known(r, "engine_version") or "", self.val(r, "instance_class", ""),
                   bool(r.values.get("publicly_accessible")), self.tags(r), "terraform",
                   security_groups=self.refs(r, "vpc_security_group_ids"),
                   port=self.known(r, "port"))

    def t_aws_vpn_connection(self, r):
        cgw = self.ref(r, "customer_gateway_id")
        gw = self.ref(r, "vpn_gateway_id") or self.ref(r, "transit_gateway_id")
        if cgw and gw:
            mm.add_vpn(self.snap, r.node, cgw, gw, name=self.name_tag(r))

    # ---- IAM and Identity Center
    def t_aws_iam_role(self, r):
        policies = [p for p in (r.values.get("managed_policy_arns") or []) if isinstance(p, str)]
        mm.add_role(self.snap, r.node, self.val(r, "name", r.name), self.known(r, "path") or "/",
                    self.known(r, "assume_role_policy"), self.known(r, "description") or "",
                    policies, self.tags(r), "terraform")
        if not r.node.startswith("arn:"):
            node = self.snap.get(r.node)
            node.parent = r.account or mm.UNKNOWN_ACCOUNT
            node.account = r.account
            mm.ensure_account(self.snap, r.account, source="terraform")

    def t_aws_iam_role_policy_attachment(self, r):
        role = self.ref(r, "role")
        policy = self.known(r, "policy_arn") or ""
        for node in self.snap.of_kind("role"):
            if node.name == role or node.id == role:
                if policy:
                    node.props["policies"] = sorted(set(node.props.get("policies", [])) | {policy})
                break

    def t_aws_iam_openid_connect_provider(self, r):
        mm.add_oidc_provider(self.snap, r.node, self.val(r, "url", ""),
                             r.values.get("client_id_list") or [], "terraform")

    def t_aws_iam_saml_provider(self, r):
        mm.add_saml_provider(self.snap, r.node, "terraform")

    def t_aws_identitystore_user(self, r):
        self._principal_from(r)

    def t_aws_identitystore_group(self, r):
        self._principal_from(r)

    def t_aws_ssoadmin_permission_set(self, r):
        instance = self.ref(r, "instance_arn") or "identity-center"
        mm.add_identity_center(self.snap, instance, r.account, source="terraform")
        mm.add_permission_set(self.snap, r.node, self.val(r, "name", r.name), instance,
                              self.known(r, "description") or "",
                              session=self.known(r, "session_duration") or "",
                              source="terraform")

    def t_aws_ssoadmin_managed_policy_attachment(self, r):
        ps = self.snap.get(self.ref(r, "permission_set_arn"))
        policy = self.known(r, "managed_policy_name") or self.known(r, "managed_policy_arn")
        if ps is not None and policy:
            ps.props["policies"] = sorted(set(ps.props.get("policies", [])) |
                                          {str(policy).rsplit("/", 1)[-1]})

    def t_aws_ssoadmin_account_assignment(self, r):
        pid = str(self.ref(r, "principal_id") or "")
        if not pid:
            return
        ptype = str(self.known(r, "principal_type") or "USER").lower()
        kind, name = self.principal_names.get(pid.split("/")[-1], (ptype, ""))
        pnode = mm.add_principal(self.snap, kind if kind in ("user", "group") else "user", pid,
                                 name or f"{kind.capitalize()} {pid[:8]}", "terraform")
        mm.add_assignment(self.snap, pnode.id, self.ref(r, "target_id"),
                          self.ref(r, "permission_set_arn"))

    # ---- logging, storage, cost
    def t_aws_s3_bucket(self, r):
        name = self.known(r, "bucket") or r.address
        mm.add_bucket(self.snap, name, r.account, self.tags(r), "terraform")
        if r.node != f"arn:aws:s3:::{name}":
            self.snap.nodes[r.node] = self.snap.nodes.pop(f"arn:aws:s3:::{name}")
            self.snap.nodes[r.node].id = r.node

    def t_aws_cloudtrail(self, r):
        mm.add_trail(self.snap, r.node, self.val(r, "name", r.name),
                     self.known(r, "s3_bucket_name") or "", self.known(r, "home_region") or r.region,
                     bool(r.values.get("is_multi_region_trail")),
                     bool(r.values.get("is_organization_trail")),
                     bool(r.values.get("enable_log_file_validation")), "terraform")
        node = self.snap.get(r.node)
        if node is not None and not node.account and r.account:
            node.account = r.account
            node.parent = r.account
            mm.ensure_account(self.snap, r.account, source="terraform")

    def t_aws_budgets_budget(self, r):
        mm.add_cost(self.snap, r.account, [self.val(r, "name", r.name)], source="terraform")

    def t_aws_ce_anomaly_monitor(self, r):
        mm.add_cost(self.snap, r.account, anomaly_monitors=1, source="terraform")


def scp_summary(content) -> str:
    """'Deny organizations:LeaveOrganization' style summary of an SCP, for tooltips."""
    try:
        doc = json.loads(content) if isinstance(content, str) else content
    except ValueError:
        return ""
    if not isinstance(doc, dict):
        return ""
    parts = []
    for stmt in mm.iampolicy.statements(doc):
        effect = str(stmt.get("Effect", ""))
        actions = mm.iampolicy.as_list(stmt.get("Action")) or \
            ["everything except " + ", ".join(map(str, mm.iampolicy.as_list(stmt.get("NotAction"))))]
        text = f"{effect} {mm.join_names([str(a) for a in actions], 3)}"
        if stmt.get("Condition"):
            text += " (with conditions)"
        parts.append(text)
    return "; ".join(parts)


def build_unfinished(data, label="") -> tuple:
    resources, kind, providers = flatten(data)
    snap = Builder(resources, providers, label, kind).build()
    if kind == "plan":
        snap.warn("Drawn from a plan: things Terraform hasn't created yet show as "
                  "(known after apply) or by their Terraform address.")
    return snap, kind


def build(data, label="", known_accounts=()) -> mm.Snapshot:
    snap, kind = build_unfinished(data, label)
    snap.scanned_at = str(data.get("timestamp", "")) if kind == "plan" else ""
    snap.scope = {"inputs": [label], "kind": [kind],
                  "terraform_version": [str(data.get("terraform_version", ""))]}
    return mm.finish(snap, known_accounts)
