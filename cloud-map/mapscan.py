"""Cloud Map's live scan. Reads an AWS environment into the model. Read-only.

Scans several profiles at once the same way Exposure Audit does: one task per account
for the account-wide parts (Organizations, Identity Center, IAM, CloudTrail, budgets)
and one per account and region for the network. Tasks run in parallel and only collect
raw data. The model is built afterwards in a fixed order, so the same environment always
gives the same snapshot, whichever task finished first.

Anything a profile isn't allowed to read is skipped and listed at the end.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import unquote

from . import mapmodel as mm
from .common import (AuthError, AwsContext, error_code, error_text, is_access_denied, name_tag,
                     paginate, tags_dict)

# Error codes that mean "not here" rather than a problem worth reporting.
QUIET_CODES = {"AWSOrganizationsNotInUseException", "OptInRequired", "AuthFailure",
               "UnrecognizedClientException", "InvalidClientTokenId", "NotFoundException",
               "ResourceNotFoundException", "UnsupportedOperation"}
NOTABLE_ROLE_LIMIT = 60


class Notes:
    """Collects what a task couldn't read, without stopping it."""

    def __init__(self, label, where):
        self.label, self.where = label, where
        self.denied = []
        self.errors = []

    def call(self, what, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - boto raises many types here
            if is_access_denied(exc):
                self.denied.append(what)
            elif error_code(exc) in QUIET_CODES or type(exc).__name__ in (
                    "EndpointConnectionError",):
                pass
            else:
                self.errors.append(f"{what}: {error_text(exc)}")
            return None

    def listing(self, what, client, method, key, **kwargs):
        return self.call(what, lambda: list(paginate(client, method, key, **kwargs)))


# =================================================================== tasks

def task_org(ctx, region, notes):
    org = ctx.client("organizations", "us-east-1")
    try:
        d = org.describe_organization()["Organization"]
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "AWSOrganizationsNotInUseException":
            return {"none": True}
        if is_access_denied(exc):
            notes.denied.append("Organizations")
        elif error_code(exc) not in QUIET_CODES:
            notes.errors.append(f"Organizations: {error_text(exc)}")
        return None
    out = {"id": d["Id"], "arn": d.get("Arn", ""), "master": d.get("MasterAccountId", ""),
           "feature_set": d.get("FeatureSet", "")}
    roots = notes.listing("Organizations roots", org, "list_roots", "Roots")
    if not roots:
        out["partial"] = True
        return out
    policy_ids = {}

    def scps(target):
        got = notes.listing("Organizations policies", org, "list_policies_for_target",
                            "Policies", TargetId=target, Filter="SERVICE_CONTROL_POLICY") or []
        for p in got:
            policy_ids[p["Name"]] = p["Id"]
        return sorted(p["Name"] for p in got)

    def tags(target):
        got = notes.call("Organizations tags", lambda: list(paginate(
            org, "list_tags_for_resource", "Tags", ResourceId=target))) or []
        return tags_dict(got)

    root = roots[0]
    out["root_id"] = root["Id"]
    out["root_scps"] = scps(root["Id"])
    ous, accounts = [], []
    stack = [root["Id"]]
    while stack:
        parent = stack.pop()
        for ou in notes.listing("Organizations OUs", org, "list_organizational_units_for_parent",
                                "OrganizationalUnits", ParentId=parent) or []:
            ous.append({"id": ou["Id"], "name": ou.get("Name", ""), "arn": ou.get("Arn", ""),
                        "parent": parent, "scps": scps(ou["Id"]), "tags": tags(ou["Id"])})
            stack.append(ou["Id"])
        for a in notes.listing("Organizations accounts", org, "list_accounts_for_parent",
                               "Accounts", ParentId=parent) or []:
            accounts.append({"id": a["Id"], "name": a.get("Name", ""), "arn": a.get("Arn", ""),
                             "email": a.get("Email", ""), "status": a.get("Status", ""),
                             "parent": parent, "scps": scps(a["Id"]), "tags": tags(a["Id"])})
    summaries = {}
    from .maptf import scp_summary
    for name, pid in sorted(policy_ids.items()):
        if name == "FullAWSAccess":
            continue
        got = notes.call("Organizations policy details", org.describe_policy, PolicyId=pid)
        if got:
            summaries[name] = scp_summary(got.get("Policy", {}).get("Content", ""))
    out.update(ous=ous, accounts=accounts, summaries=summaries)
    return out


def task_sso(ctx, regions, notes):
    for region in regions:
        sso = ctx.client("sso-admin", region)
        instances = notes.listing("IAM Identity Center", sso, "list_instances", "Instances")
        if instances:
            break
    else:
        return None
    inst = instances[0]
    arn, store = inst["InstanceArn"], inst.get("IdentityStoreId", "")
    sets = []
    principals = set()
    for ps_arn in notes.listing("Identity Center permission sets", sso, "list_permission_sets",
                                "PermissionSets", InstanceArn=arn) or []:
        d = notes.call("Identity Center permission sets", sso.describe_permission_set,
                       InstanceArn=arn, PermissionSetArn=ps_arn) or {}
        d = d.get("PermissionSet", {})
        pols = notes.listing("Identity Center permission sets", sso,
                             "list_managed_policies_in_permission_set", "AttachedManagedPolicies",
                             InstanceArn=arn, PermissionSetArn=ps_arn) or []
        accounts = notes.listing("Identity Center assignments", sso,
                                 "list_accounts_for_provisioned_permission_set", "AccountIds",
                                 InstanceArn=arn, PermissionSetArn=ps_arn) or []
        assigns = []
        for acct in accounts:
            for a in notes.listing("Identity Center assignments", sso, "list_account_assignments",
                                   "AccountAssignments", InstanceArn=arn, AccountId=acct,
                                   PermissionSetArn=ps_arn) or []:
                assigns.append((a.get("PrincipalType", "USER"), a["PrincipalId"], acct))
                principals.add((a.get("PrincipalType", "USER"), a["PrincipalId"]))
        sets.append({"arn": ps_arn, "name": d.get("Name", ps_arn.rsplit("/", 1)[-1]),
                     "description": d.get("Description", ""),
                     "session": d.get("SessionDuration", ""),
                     "policies": [p.get("Name", "") for p in pols], "accounts": accounts,
                     "assignments": assigns})
    names = _principal_names(ctx.client("identitystore", region), store, principals, notes)
    return {"arn": arn, "store": store, "owner": inst.get("OwnerAccountId", "") or ctx.account,
            "region": region, "sets": sets, "names": names}


def _principal_names(ids, store, principals, notes) -> dict:
    """Names for the users and groups that have assignments. ListUsers and ListGroups
    come first because SecurityAudit allows them. DescribeUser and DescribeGroup are the
    fallback when the list calls are denied."""
    names = {}
    if not principals:
        return names
    quiet = Notes(notes.label, notes.where)
    wanted = {kind for kind, _ in principals}
    if "USER" in wanted:
        for u in quiet.listing("users", ids, "list_users", "Users", IdentityStoreId=store) or []:
            names[u["UserId"]] = u.get("DisplayName") or u.get("UserName", "")
    if "GROUP" in wanted:
        for g in quiet.listing("groups", ids, "list_groups", "Groups", IdentityStoreId=store) or []:
            names[g["GroupId"]] = g.get("DisplayName", "")
    for ptype, pid in sorted(principals):
        if pid in names:
            continue
        if ptype == "GROUP":
            got = notes.call("Identity Center users and groups", ids.describe_group,
                             IdentityStoreId=store, GroupId=pid) or {}
            names[pid] = got.get("DisplayName", "")
        else:
            got = notes.call("Identity Center users and groups", ids.describe_user,
                             IdentityStoreId=store, UserId=pid) or {}
            names[pid] = got.get("DisplayName") or got.get("UserName", "")
    return names


def _trust_doc(doc):
    if isinstance(doc, str):
        try:
            return json.loads(unquote(doc))
        except ValueError:
            return {}
    return doc or {}


def task_iam(ctx, region, notes):
    iam = ctx.client("iam")
    roles = notes.listing("IAM roles", iam, "list_roles", "Roles") or []
    out = {"roles": [], "oidc": [], "saml": [], "alias": ""}
    notable = 0
    for r in roles:
        trust = _trust_doc(r.get("AssumeRolePolicyDocument"))
        text = json.dumps(trust)
        policies = []
        interesting = ("Federated" in text or r.get("RoleName") in mm.BREAK_GLASS_ROLES or
                       any(acct != ctx.account for acct in _accounts_in(trust)))
        if interesting and notable < NOTABLE_ROLE_LIMIT and not r.get("Path", "/").startswith(
                "/aws-service-role/"):
            notable += 1
            got = notes.listing("IAM role policies", iam, "list_attached_role_policies",
                                "AttachedPolicies", RoleName=r["RoleName"]) or []
            policies = [p.get("PolicyArn", "") for p in got]
        out["roles"].append({"arn": r["Arn"], "name": r["RoleName"], "path": r.get("Path", "/"),
                             "trust": trust, "description": r.get("Description", ""),
                             "policies": policies})
    for p in (notes.call("IAM OIDC providers", iam.list_open_id_connect_providers) or {}).get(
            "OpenIDConnectProviderList", []):
        d = notes.call("IAM OIDC providers", iam.get_open_id_connect_provider,
                       OpenIDConnectProviderArn=p["Arn"]) or {}
        out["oidc"].append({"arn": p["Arn"], "url": d.get("Url", ""),
                            "audiences": d.get("ClientIDList", [])})
    for p in (notes.call("IAM SAML providers", iam.list_saml_providers) or {}).get(
            "SAMLProviderList", []):
        out["saml"].append({"arn": p["Arn"]})
    aliases = (notes.call("IAM account alias", iam.list_account_aliases) or {}).get("AccountAliases", [])
    out["alias"] = aliases[0] if aliases else ""
    return out


def _accounts_in(trust) -> set:
    out = set()
    for p in mm.trust_principals(trust):
        if p["type"] == "aws" and p.get("account"):
            out.add(p["account"])
    return out


def task_trail(ctx, region, notes):
    ct = ctx.client("cloudtrail", ctx.default_region)
    got = notes.call("CloudTrail", ct.describe_trails, includeShadowTrails=True) or {}
    return [{"arn": t["TrailARN"], "name": t.get("Name", ""), "bucket": t.get("S3BucketName", ""),
             "home": t.get("HomeRegion", ""), "multi": bool(t.get("IsMultiRegionTrail")),
             "org": bool(t.get("IsOrganizationTrail")),
             "validation": bool(t.get("LogFileValidationEnabled"))}
            for t in got.get("trailList", []) if t.get("TrailARN")]


def task_cost(ctx, region, notes):
    budgets = ctx.client("budgets", "us-east-1")
    got = notes.listing("Budgets", budgets, "describe_budgets", "Budgets", AccountId=ctx.account)
    ce = ctx.client("ce", "us-east-1")
    monitors = notes.call("Cost anomaly monitors", ce.get_anomaly_monitors) or {}
    if got is None and not monitors:
        return None
    return {"budgets": [b.get("BudgetName", "") for b in (got or [])],
            "monitors": len(monitors.get("AnomalyMonitors", []))}


def task_s3(ctx, region, notes):
    got = notes.call("S3 bucket list", ctx.client("s3", "us-east-1").list_buckets) or {}
    return sorted(b["Name"] for b in got.get("Buckets", []))


EC2_CALLS = (
    ("vpcs", "describe_vpcs", "Vpcs"), ("subnets", "describe_subnets", "Subnets"),
    ("route_tables", "describe_route_tables", "RouteTables"),
    ("igws", "describe_internet_gateways", "InternetGateways"),
    ("eigws", "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways"),
    ("nats", "describe_nat_gateways", "NatGateways"),
    ("tgws", "describe_transit_gateways", "TransitGateways"),
    ("tgw_attachments", "describe_transit_gateway_attachments", "TransitGatewayAttachments"),
    ("peerings", "describe_vpc_peering_connections", "VpcPeeringConnections"),
    ("endpoints", "describe_vpc_endpoints", "VpcEndpoints"),
    ("sgs", "describe_security_groups", "SecurityGroups"),
    ("nacls", "describe_network_acls", "NetworkAcls"),
    ("reservations", "describe_instances", "Reservations"),
    ("vgws", "describe_vpn_gateways", "VpnGateways"),
    ("cgws", "describe_customer_gateways", "CustomerGateways"),
    ("vpns", "describe_vpn_connections", "VpnConnections"),
)


def task_net(ctx, region, notes):
    ec2 = ctx.client("ec2", region)
    out = {}
    for key, method, field in EC2_CALLS:
        out[key] = notes.listing("EC2 " + key.replace("_", " "), ec2, method, field) or []
    elb = ctx.client("elbv2", region)
    out["lbs"] = notes.listing("Load balancers", elb, "describe_load_balancers",
                               "LoadBalancers") or []
    # One call per load balancer, so reachability can say whether anything listens on a
    # port. None when it couldn't be read, so "no listeners" isn't claimed by mistake.
    out["listeners"] = {}
    for lb in out["lbs"]:
        arn = lb.get("LoadBalancerArn")
        if arn:
            out["listeners"][arn] = notes.listing("Load balancer listeners", elb,
                                                  "describe_listeners", "Listeners",
                                                  LoadBalancerArn=arn)
    out["dbs"] = notes.listing("RDS", ctx.client("rds", region), "describe_db_instances",
                               "DBInstances") or []
    return out


ACCOUNT_TASKS = {"org": task_org, "iam": task_iam, "trail": task_trail, "cost": task_cost,
                 "s3": task_s3}


# =================================================================== running

def scan(profiles, regions=None, access=True, network=True, known_accounts=(), progress=None,
         cancel=None, workers=12) -> mm.Snapshot:
    """Scan one or more profiles into a finished snapshot."""
    profiles = list(profiles) or [None]
    started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [p for p, on in (("access", access), ("network", network)) if on]
    snap = mm.Snapshot("aws", started, {"profiles": [p or "default" for p in profiles],
                                        "regions": sorted(regions or []), "parts": parts})
    contexts, seen = [], {}
    for p in profiles:
        try:
            ctx = AwsContext(p)
            acct = ctx.account
        except AuthError as exc:
            snap.warn(f"{p or 'default'}: {exc}")
            continue
        if acct in seen:
            snap.warn(f"{ctx.label}: same account as {seen[acct]}, scanned once")
            continue
        seen[acct] = ctx.label
        contexts.append(ctx)

    tasks = []
    scan_regions = {}
    for ctx in contexts:
        regs = list(regions) if regions else ctx.enabled_regions()
        scan_regions[ctx.label] = regs
        if access:
            for name in ACCOUNT_TASKS:
                tasks.append((ctx, name, "global"))
            tasks.append((ctx, "sso", "global"))
        if network:
            for r in ctx.regions_for("ec2", regs):
                tasks.append((ctx, "net", r))
    if not regions:
        snap.scope["regions"] = sorted({r for regs in scan_regions.values() for r in regs})

    def run(task):
        ctx, name, region = task
        notes = Notes(ctx.label, region)
        if cancel is not None and cancel.is_set():
            return task, None, notes
        if name == "sso":
            ordered = [ctx.default_region] + [r for r in scan_regions[ctx.label]
                                              if r != ctx.default_region]
            return task, task_sso(ctx, ordered, notes), notes
        fn = task_net if name == "net" else ACCOUNT_TASKS[name]
        return task, fn(ctx, region, notes), notes

    results = {}
    denied = {}
    total, done = len(tasks), 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(run, t) for t in tasks]):
            (ctx, name, region), data, notes = fut.result()
            done += 1
            if progress:
                progress(done, total, f"{name} for {ctx.label} in {region}")
            results[(ctx.label, name, region)] = data
            for what in notes.denied:
                denied.setdefault((ctx.label, what), set()).add(region)
            for e in notes.errors:
                snap.warn(f"{ctx.label}: {e}" + (f" ({region})" if region != "global" else ""))
    for (label, what), regs in sorted(denied.items()):
        regs = sorted(regs)
        where = "" if regs == ["global"] else (f" ({regs[0]})" if len(regs) == 1 else
                                              f" ({len(regs)} regions)")
        snap.warn(f"{label}: no permission for {what}{where}")
    if cancel is not None and cancel.is_set():
        snap.warn("The scan was stopped early, so this map is incomplete.")

    build(snap, contexts, results, access, network)
    return mm.finish(snap, known_accounts)


# =================================================================== building

def build(snap, contexts, results, access, network):
    for ctx in contexts:
        mm.ensure_account(snap, ctx.account)
    if access:
        _build_access(snap, contexts, results)
    if network:
        regions = sorted({r for (_, name, r) in results if name == "net"})
        for ctx in contexts:
            for region in regions:
                data = results.get((ctx.label, "net", region))
                if data:
                    _build_network(snap, ctx, region, data)


def _build_access(snap, contexts, results):
    orgs = [results.get((c.label, "org", "global")) for c in contexts]
    orgs = [o for o in orgs if o and not o.get("none")]
    full = [o for o in orgs if not o.get("partial")]
    org = full[0] if full else (orgs[0] if orgs else None)
    master = org.get("master", "") if org else ""
    if org:
        mm.add_org(snap, org["id"], org.get("arn", ""), master, org.get("root_id", ""),
                   org.get("root_scps", []), [], org.get("summaries", {}),
                   partial=bool(org.get("partial")))
        for ou in org.get("ous", []):
            mm.add_ou(snap, ou["id"], ou["name"], ou["parent"], ou["arn"], ou["scps"], ou["tags"])
        for a in org.get("accounts", []):
            mm.add_org_account(snap, a["id"], a["name"], a["parent"], a["arn"], a["email"],
                               a["status"], a["scps"], a["tags"])
    sso = next((results.get((c.label, "sso", "global")) for c in contexts
                if results.get((c.label, "sso", "global"))), None)
    if sso:
        owner = master or sso["owner"]
        mm.add_identity_center(snap, sso["arn"], owner, sso["store"])
        for ps in sorted(sso["sets"], key=lambda p: p["arn"]):
            mm.add_permission_set(snap, ps["arn"], ps["name"], sso["arn"], ps["description"],
                                  ps["policies"], ps["session"], ps["accounts"])
            for ptype, pid, acct in sorted(ps["assignments"]):
                kind = "group" if ptype == "GROUP" else "user"
                mm.add_principal(snap, kind, pid, sso["names"].get(pid, ""))
                mm.add_assignment(snap, pid, acct, ps["arn"])
    else:
        scanned = {c.account for c in contexts}
        if org is None or (master and master not in scanned) or org.get("partial"):
            snap.warn("No IAM Identity Center instance was readable. If you use it, scan with "
                      "the management account or a delegated admin to see it.")
    buckets = {}
    for ctx in contexts:
        for name in results.get((ctx.label, "s3", "global")) or []:
            buckets.setdefault(name, ctx.account)
    trails = {}
    for ctx in contexts:
        iam = results.get((ctx.label, "iam", "global"))
        if iam:
            if iam.get("alias"):
                node = snap.get(ctx.account)
                if node is not None and not node.name:
                    node.name = iam["alias"]
            for p in iam["oidc"]:
                mm.add_oidc_provider(snap, p["arn"], p["url"], p["audiences"])
            for p in iam["saml"]:
                mm.add_saml_provider(snap, p["arn"])
            for r in iam["roles"]:
                mm.add_role(snap, r["arn"], r["name"], r["path"], r["trust"], r["description"],
                            r["policies"])
        for t in results.get((ctx.label, "trail", "global")) or []:
            trails.setdefault(t["arn"], t)
        cost = results.get((ctx.label, "cost", "global"))
        if cost is not None:
            count = len(cost["budgets"]) + cost["monitors"]
            if count or ctx.account == master or len(contexts) == 1:
                mm.add_cost(snap, ctx.account, cost["budgets"], cost["monitors"])
    for arn, t in sorted(trails.items()):
        mm.add_trail(snap, arn, t["name"], t["bucket"], t["home"], t["multi"], t["org"],
                     t["validation"])
        if t["bucket"] and t["bucket"] in buckets:
            mm.add_bucket(snap, t["bucket"], buckets[t["bucket"]])


def _tags(item):
    return tags_dict(item.get("Tags"))


def _build_network(snap, ctx, region, d):
    acct = ctx.account
    for v in d["vpcs"]:
        cidrs = [a["CidrBlock"] for a in v.get("CidrBlockAssociationSet", [])
                 if a.get("CidrBlockState", {}).get("State", "associated") == "associated"]
        mm.add_vpc(snap, v["VpcId"], v.get("OwnerId", acct), region, cidrs or [v.get("CidrBlock", "")],
                   name_tag(v.get("Tags")), v.get("IsDefault", False), _tags(v))
    for s in d["subnets"]:
        ipv6 = next((a.get("Ipv6CidrBlock", "") for a in s.get("Ipv6CidrBlockAssociationSet", [])), "")
        mm.add_subnet(snap, s["SubnetId"], s["VpcId"], s.get("AvailabilityZone", ""),
                      s.get("CidrBlock", ""), name_tag(s.get("Tags")), ipv6,
                      s.get("MapPublicIpOnLaunch"), s.get("OwnerId", acct), region, _tags(s))
    for g in d["igws"]:
        vpcs = [a["VpcId"] for a in g.get("Attachments", []) if a.get("State") in ("available", "attached")]
        mm.add_gateway(snap, "igw", g["InternetGatewayId"], vpcs[0] if vpcs else "", acct, region,
                       name_tag(g.get("Tags")), _tags(g))
    for g in d["eigws"]:
        vpcs = [a["VpcId"] for a in g.get("Attachments", []) if a.get("State") in ("available", "attached")]
        mm.add_gateway(snap, "eigw", g["EgressOnlyInternetGatewayId"], vpcs[0] if vpcs else "",
                       acct, region, name_tag(g.get("Tags")), _tags(g))
    for g in d["vgws"]:
        if g.get("State") in ("deleted", "deleting"):
            continue
        vpcs = [a["VpcId"] for a in g.get("VpcAttachments", []) if a.get("State") == "attached"]
        mm.add_gateway(snap, "vgw", g["VpnGatewayId"], vpcs[0] if vpcs else "", acct, region,
                       name_tag(g.get("Tags")), _tags(g), asn=str(g.get("AmazonSideAsn", "")))
    for n in d["nats"]:
        if n.get("State") in ("deleted", "deleting", "failed"):
            continue
        ips = [a.get("PublicIp", "") for a in n.get("NatGatewayAddresses", []) if a.get("PublicIp")]
        mm.add_nat(snap, n["NatGatewayId"], n.get("SubnetId", ""), n.get("VpcId", ""),
                   n.get("ConnectivityType", "public"), ips[0] if ips else "", n.get("State", ""),
                   name_tag(n.get("Tags")), _tags(n))
    for t in d["tgws"]:
        if t.get("State") in ("deleted", "deleting"):
            continue
        owner = t.get("OwnerId", acct)
        mm.add_tgw(snap, t["TransitGatewayId"], owner, region,
                   (t.get("Options") or {}).get("AmazonSideAsn", ""), name_tag(t.get("Tags")),
                   owner, _tags(t), stub_account=owner != acct)   # shared from another account
    for a in d["tgw_attachments"]:
        if a.get("ResourceType") != "vpc" or a.get("State") in ("deleted", "deleting", "rejected"):
            continue
        tgw = a.get("TransitGatewayId", "")
        if tgw and snap.get(tgw) is None:
            node = mm.add_tgw(snap, tgw, acct, region, owner=a.get("TransitGatewayOwnerId", ""))
            node.props["stub"] = True
        mm.add_tgw_attachment(snap, a["TransitGatewayAttachmentId"], tgw, a.get("ResourceId", ""),
                              state=a.get("State", ""), name=name_tag(a.get("Tags")), tags=_tags(a))
    for p in d["peerings"]:
        if (p.get("Status") or {}).get("Code") != "active":
            continue
        req, acc = p.get("RequesterVpcInfo", {}), p.get("AccepterVpcInfo", {})
        mm.add_peering(snap, p["VpcPeeringConnectionId"], req.get("VpcId", ""), acc.get("VpcId", ""),
                       "active", {"account": req.get("OwnerId", ""), "region": req.get("Region", ""),
                                  "cidr": req.get("CidrBlock", "")},
                       {"account": acc.get("OwnerId", ""), "region": acc.get("Region", ""),
                        "cidr": acc.get("CidrBlock", "")}, name_tag(p.get("Tags")))
    targets = ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
               "EgressOnlyInternetGatewayId", "NetworkInterfaceId", "InstanceId",
               "LocalGatewayId", "CarrierGatewayId")
    for rt in d["route_tables"]:
        routes, holes = [], []
        for r in rt.get("Routes", []):
            dest = (r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or
                    r.get("DestinationPrefixListId") or "")
            target = next((r[k] for k in targets if r.get(k)), "")
            if dest and target and r.get("State", "active") == "active":
                routes.append({"dest": dest, "target": target})
            elif dest and r.get("State") == "blackhole":
                holes.append({"dest": dest, "target": target})
        subnets = [a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")]
        main = any(a.get("Main") for a in rt.get("Associations", []))
        mm.add_route_table(snap, rt["RouteTableId"], rt.get("VpcId", ""), routes, subnets, main,
                           name_tag(rt.get("Tags")), _tags(rt), blackholes=holes)
    for e in d["endpoints"]:
        if e.get("State", "").lower() in ("deleted", "deleting", "rejected", "failed"):
            continue
        mm.add_endpoint(snap, e["VpcEndpointId"], e.get("VpcId", ""), e.get("ServiceName", ""),
                        e.get("VpcEndpointType", "Gateway"), e.get("SubnetIds", []),
                        e.get("RouteTableIds", []), name_tag(e.get("Tags")), _tags(e))
    for g in d["sgs"]:
        mm.add_security_group(snap, g["GroupId"], g.get("VpcId", ""), g.get("GroupName", ""),
                              g.get("Description", ""), _perms(g.get("IpPermissions", [])),
                              _perms(g.get("IpPermissionsEgress", [])), _tags(g))
    for n in d["nacls"]:
        mm.add_nacl(snap, n["NetworkAclId"], n.get("VpcId", ""),
                    [a["SubnetId"] for a in n.get("Associations", []) if a.get("SubnetId")],
                    n.get("IsDefault", False), name_tag(n.get("Tags")), _tags(n),
                    entries=_nacl_entries(n.get("Entries", [])))
    for res in d["reservations"]:
        for i in res.get("Instances", []):
            state = (i.get("State") or {}).get("Name", "")
            if state in ("terminated", "shutting-down") or not i.get("SubnetId"):
                continue
            meta = i.get("MetadataOptions") or {}
            ipv6 = sorted({a.get("Ipv6Address") for eni in i.get("NetworkInterfaces", [])
                           for a in eni.get("Ipv6Addresses", []) if a.get("Ipv6Address")})
            extra = {"ipv6_ips": ipv6} if ipv6 else {}
            mm.add_instance(snap, i["InstanceId"], i["SubnetId"], i.get("VpcId", ""),
                            name_tag(i.get("Tags")), i.get("InstanceType", ""), state,
                            i.get("PrivateIpAddress", ""), i.get("PublicIpAddress", ""),
                            [g["GroupId"] for g in i.get("SecurityGroups", [])],
                            meta.get("HttpTokens", ""), meta.get("HttpEndpoint", ""),
                            (i.get("IamInstanceProfile") or {}).get("Arn", ""), _tags(i),
                            **extra)
    listeners = d.get("listeners") or {}
    for lb in d["lbs"]:
        zones = lb.get("AvailabilityZones", [])
        got = listeners.get(lb["LoadBalancerArn"])
        mm.add_lb(snap, lb["LoadBalancerArn"], lb.get("LoadBalancerName", ""), lb.get("VpcId", ""),
                  [z.get("SubnetId", "") for z in zones if z.get("SubnetId")],
                  [z.get("ZoneName", "") for z in zones], lb.get("Scheme", ""),
                  lb.get("Type", "application"),
                  security_groups=list(lb.get("SecurityGroups") or []),
                  listeners=None if got is None else [
                      {"port": li.get("Port"), "protocol": li.get("Protocol", "")} for li in got])
    for db in d["dbs"]:
        group = db.get("DBSubnetGroup") or {}
        mm.add_rds(snap, db["DBInstanceArn"], db.get("DBInstanceIdentifier", ""),
                   group.get("VpcId", ""),
                   [s["SubnetIdentifier"] for s in group.get("Subnets", []) if s.get("SubnetIdentifier")],
                   db.get("AvailabilityZone", ""), db.get("Engine", ""), db.get("EngineVersion", ""),
                   db.get("DBInstanceClass", ""), db.get("PubliclyAccessible", False),
                   tags_dict(db.get("TagList")),
                   security_groups=[g.get("VpcSecurityGroupId") for g in db.get("VpcSecurityGroups", [])
                                    if g.get("VpcSecurityGroupId")],
                   port=(db.get("Endpoint") or {}).get("Port") or db.get("DbInstancePort") or None)
    for c in d["cgws"]:
        if c.get("State") in ("deleted", "deleting"):
            continue
        mm.add_cgw(snap, c["CustomerGatewayId"], acct, region, c.get("IpAddress", ""),
                   c.get("BgpAsn", ""), name_tag(c.get("Tags")), _tags(c))
    for v in d["vpns"]:
        if v.get("State") in ("deleted", "deleting"):
            continue
        gw = v.get("VpnGatewayId") or v.get("TransitGatewayId") or ""
        if v.get("CustomerGatewayId") and gw:
            mm.add_vpn(snap, v["VpnConnectionId"], v["CustomerGatewayId"], gw, v.get("State", ""),
                       name_tag(v.get("Tags")))


def _perms(perms) -> list:
    out = []
    for p in perms or []:
        cidrs = [r.get("CidrIp") for r in p.get("IpRanges", [])] + \
                [r.get("CidrIpv6") for r in p.get("Ipv6Ranges", [])]
        groups = [g.get("GroupId") for g in p.get("UserIdGroupPairs", [])]
        lists = [x.get("PrefixListId") for x in p.get("PrefixListIds", [])]
        desc = next((r.get("Description") for r in p.get("IpRanges", []) if r.get("Description")), "")
        out.append(mm.rule(p.get("IpProtocol", "-1"), p.get("FromPort"), p.get("ToPort"),
                           cidrs, groups, desc, prefix_lists=lists))
    return out


def _nacl_entries(entries) -> list:
    """DescribeNetworkAcls entries as model rules. AWS lists the catch-all deny (32767,
    and 32768 for IPv6) itself."""
    out = []
    for e in entries or []:
        ports = e.get("PortRange") or {}
        icmp = e.get("IcmpTypeCode") or {}
        try:
            out.append(mm.nacl_entry(e.get("RuleNumber"), e.get("Egress", False),
                                     e.get("RuleAction", "deny"), e.get("Protocol", "-1"),
                                     e.get("CidrBlock", ""), e.get("Ipv6CidrBlock", ""),
                                     ports.get("From"), ports.get("To"),
                                     icmp.get("Type"), icmp.get("Code")))
        except (TypeError, ValueError):
            continue
    return out
