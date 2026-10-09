"""Lab Sweep: finds things still costing money in lab accounts, and tears them down.

Scan is read-only. Teardown only touches what you select, and asks you to type
"delete" first. Right before each delete it reads the keep list and keep tag again,
and checks the profile still points at the account the item was found in.

The keep tag only works for types whose listing comes back with tags: EC2 instances,
NAT gateways, Elastic IPs, EBS volumes and snapshots, AMIs, VPC endpoints, VPNs,
transit gateway attachments, Client VPN, Network Firewall, RDS, Secrets Manager,
CloudHSM and GuardDuty. Anything else needs the keep list.

Prices are rough us-east-1 on-demand numbers so you can tell a $3 leftover from a
$300 one. They are not a bill. Use "spend" for what Cost Explorer actually shows.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone

from .common import (AuthError, AwsContext, age_text, error_code, error_text,
                     is_access_denied, load_config, money, name_tag, paginate, tags_dict)

H = 730  # hours in a month

EC2_HOURLY = {
    "t2.nano": 0.0058, "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
    "t2.large": 0.0928, "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208,
    "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3a.nano": 0.0047,
    "t3a.micro": 0.0094, "t3a.small": 0.0188, "t3a.medium": 0.0376, "t3a.large": 0.0752,
    "t4g.nano": 0.0042, "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336,
    "t4g.large": 0.0672, "m5.large": 0.096, "m5.xlarge": 0.192, "m6i.large": 0.096,
    "m6g.large": 0.077, "m7i.large": 0.1008, "m7g.large": 0.0816, "c5.large": 0.085,
    "c6i.large": 0.085, "c7g.large": 0.0725, "r5.large": 0.126, "r6i.large": 0.126,
}
RDS_HOURLY = {
    "db.t3.micro": 0.017, "db.t4g.micro": 0.016, "db.t3.small": 0.034, "db.t4g.small": 0.032,
    "db.t3.medium": 0.068, "db.t4g.medium": 0.065, "db.m5.large": 0.171,
    "db.m6g.large": 0.152, "db.r5.large": 0.25, "db.r6g.large": 0.225,
}
CACHE_HOURLY = {
    "cache.t2.micro": 0.017, "cache.t3.micro": 0.017, "cache.t4g.micro": 0.016,
    "cache.t3.small": 0.034, "cache.t4g.small": 0.032, "cache.t3.medium": 0.068,
    "cache.t4g.medium": 0.065, "cache.m5.large": 0.156, "cache.r6g.large": 0.206,
}
SEARCH_HOURLY = {
    "t3.small.search": 0.036, "t3.medium.search": 0.073, "m6g.large.search": 0.128,
    "r6g.large.search": 0.167, "m5.large.search": 0.142,
}
EBS_GB = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015,
          "standard": 0.05}


@dataclass
class Item:
    kind: str
    id: str
    name: str = ""
    state: str = ""
    detail: str = ""
    monthly: float | None = None
    created: datetime | None = None
    can_delete: bool = True
    note: str = ""
    extra: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    profile: str = ""
    account: str = ""
    region: str = ""
    kept: bool = False

    @property
    def kind_label(self) -> str:
        k = KINDS.get(self.kind)
        return k.label if k else self.kind

    def row(self) -> dict:
        return {
            "profile": self.profile or "default", "account": self.account, "region": self.region,
            "kind": self.kind_label, "id": self.id, "name": self.name, "state": self.state,
            "detail": self.detail, "monthly": self.monthly, "cost": money(self.monthly),
            "age": age_text(self.created),
            "action": ("kept" if self.kept else "can delete" if self.can_delete else "manual"),
            "note": self.note,
        }

    def as_dict(self) -> dict:
        d = asdict(self)
        d["created"] = self.created.isoformat() if isinstance(self.created, datetime) else None
        d["kind_label"] = self.kind_label
        return d


@dataclass
class Kind:
    key: str
    label: str
    service: str
    scan: object
    delete: object = None
    order: int = 99
    scope: str = "region"  # or "global"
    manual_note: str = ""


KINDS: dict = {}


def kind(key, label, service, order=99, scope="region", manual_note=""):
    def wrap(scan_fn):
        KINDS[key] = Kind(key, label, service, scan_fn, None, order, scope, manual_note)
        return scan_fn
    return wrap


def deleter(key):
    def wrap(fn):
        KINDS[key].delete = fn
        return fn
    return wrap


def _dt(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


# =================================================================== EC2 and VPC

@kind("ec2_instance", "EC2 instance", "ec2", order=20)
def scan_instances(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    flt = [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
    for res in paginate(ec2, "describe_instances", "Reservations", Filters=flt):
        for i in res.get("Instances", []):
            state = i.get("State", {}).get("Name", "")
            itype = i.get("InstanceType", "")
            rate = EC2_HOURLY.get(itype)
            cost = 0.0 if state == "stopped" else (rate * H if rate else None)
            bits = [itype]
            if i.get("InstanceLifecycle") == "spot":
                bits.append("spot")
            if i.get("PublicIpAddress"):
                bits.append("public IP")
            note = "Stopped instances are free, but their volumes still cost." if state == "stopped" else ""
            out.append(Item("ec2_instance", i["InstanceId"], name_tag(i.get("Tags")), state,
                            ", ".join(bits), cost, i.get("LaunchTime"), note=note,
                            tags=tags_dict(i.get("Tags"))))
    return out


@deleter("ec2_instance")
def delete_instance(ctx, item):
    ctx.client("ec2", item.region).terminate_instances(InstanceIds=[item.id])
    return "Terminating"


@kind("nat_gateway", "NAT gateway", "ec2", order=25)
def scan_nat(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    flt = [{"Name": "state", "Values": ["pending", "available"]}]
    for n in paginate(ec2, "describe_nat_gateways", "NatGateways", Filter=flt):
        ips = ", ".join(a.get("PublicIp", "") for a in n.get("NatGatewayAddresses", [])
                        if a.get("PublicIp"))
        detail = f"{n.get('ConnectivityType', 'public')} in {n.get('VpcId', '')}"
        if ips:
            detail += f", {ips}"
        out.append(Item("nat_gateway", n["NatGatewayId"], name_tag(n.get("Tags")),
                        n.get("State", ""), detail, 0.045 * H, n.get("CreateTime"),
                        note="Plus $0.045 per GB processed.", tags=tags_dict(n.get("Tags"))))
    return out


@deleter("nat_gateway")
def delete_nat(ctx, item):
    ctx.client("ec2", item.region).delete_nat_gateway(NatGatewayId=item.id)
    return "Deleting (takes a minute or two)"


@kind("elastic_ip", "Elastic IP", "ec2", order=40)
def scan_eips(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    for a in ec2.describe_addresses().get("Addresses", []):
        attached = a.get("InstanceId") or a.get("NetworkInterfaceId") or ""
        detail = a.get("PublicIp", "") + (f", attached to {attached}" if attached else ", not attached")
        out.append(Item("elastic_ip", a.get("AllocationId") or a.get("PublicIp", ""),
                        name_tag(a.get("Tags")), "associated" if a.get("AssociationId") else "idle",
                        detail, 0.005 * H, extra={"association": a.get("AssociationId", ""),
                                                  "ip": a.get("PublicIp", "")},
                        tags=tags_dict(a.get("Tags"))))
    return out


@deleter("elastic_ip")
def delete_eip(ctx, item):
    ec2 = ctx.client("ec2", item.region)
    assoc = item.extra.get("association")
    if assoc:
        try:
            ec2.disassociate_address(AssociationId=assoc)
        except Exception:  # noqa: BLE001 - NAT gateway IPs can't be disassociated, wait below
            pass
    # An IP still held by a NAT gateway that's being deleted frees up after a minute or two.
    deadline = time.time() + 360
    while True:
        try:
            ec2.release_address(AllocationId=item.id)
            return "Released"
        except Exception as exc:  # noqa: BLE001
            if error_code(exc) in ("InvalidIPAddress.InUse", "AuthFailure") and time.time() < deadline:
                time.sleep(15)
                continue
            raise


@kind("load_balancer", "Load balancer", "elbv2", order=25)
def scan_elbv2(ctx, region):
    elb = ctx.client("elbv2", region)
    out = []
    rate = {"application": 0.0225, "network": 0.0225, "gateway": 0.0125}
    for lb in paginate(elb, "describe_load_balancers", "LoadBalancers"):
        lbtype = lb.get("Type", "application")
        out.append(Item("load_balancer", lb["LoadBalancerArn"], lb.get("LoadBalancerName", ""),
                        lb.get("State", {}).get("Code", ""), f"{lbtype}, {lb.get('Scheme', '')}",
                        rate.get(lbtype, 0.0225) * H, lb.get("CreatedTime"),
                        note="Plus capacity units for traffic."))
    return out


@deleter("load_balancer")
def delete_elbv2(ctx, item):
    elb = ctx.client("elbv2", item.region)
    try:
        elb.delete_load_balancer(LoadBalancerArn=item.id)
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "OperationNotPermitted":
            raise RuntimeError("Deletion protection is on. Turn it off in the console first.") from exc
        raise
    return "Deleted"


@kind("classic_elb", "Classic load balancer", "elb", order=25)
def scan_clb(ctx, region):
    elb = ctx.client("elb", region)
    return [Item("classic_elb", lb["LoadBalancerName"], lb["LoadBalancerName"], "active",
                 lb.get("Scheme", ""), 0.025 * H, lb.get("CreatedTime"))
            for lb in paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")]


@deleter("classic_elb")
def delete_clb(ctx, item):
    ctx.client("elb", item.region).delete_load_balancer(LoadBalancerName=item.id)
    return "Deleted"


@kind("ebs_volume", "EBS volume", "ec2", order=60)
def scan_volumes(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    for v in paginate(ec2, "describe_volumes", "Volumes"):
        vtype = v.get("VolumeType", "gp3")
        size = v.get("Size", 0)
        cost = EBS_GB.get(vtype, 0.10) * size
        if vtype in ("io1", "io2"):
            cost += 0.065 * (v.get("Iops") or 0)
        elif vtype == "gp3":
            cost += 0.005 * max((v.get("Iops") or 3000) - 3000, 0)
            cost += 0.04 * max((v.get("Throughput") or 125) - 125, 0)
        state = v.get("State", "")
        attached = [a.get("InstanceId") for a in v.get("Attachments", []) if a.get("InstanceId")]
        detail = f"{size} GB {vtype}" + (f", on {', '.join(attached)}" if attached else ", unattached")
        can = state == "available"
        note = "" if can else "Attached. It goes away with the instance if delete-on-termination is set; otherwise scan again after."
        out.append(Item("ebs_volume", v["VolumeId"], name_tag(v.get("Tags")), state, detail, cost,
                        v.get("CreateTime"), can_delete=can, note=note, tags=tags_dict(v.get("Tags"))))
    return out


@deleter("ebs_volume")
def delete_volume(ctx, item):
    ctx.client("ec2", item.region).delete_volume(VolumeId=item.id)
    return "Deleted"


@kind("ebs_snapshot", "EBS snapshot", "ec2", order=60)
def scan_snapshots(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    for s in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
        size = s.get("VolumeSize", 0)
        tier = s.get("StorageTier", "standard")
        rate = 0.0125 if tier == "archive" else 0.05
        out.append(Item("ebs_snapshot", s["SnapshotId"], name_tag(s.get("Tags")),
                        s.get("State", ""), f"{size} GB, {tier}" + (
                            f", {s['Description'][:60]}" if s.get("Description") else ""),
                        rate * size, s.get("StartTime"),
                        note="Cost shown is the most it could be. Snapshots only bill for changed blocks.",
                        tags=tags_dict(s.get("Tags"))))
    return out


@deleter("ebs_snapshot")
def delete_snapshot(ctx, item):
    try:
        ctx.client("ec2", item.region).delete_snapshot(SnapshotId=item.id)
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "InvalidSnapshot.InUse":
            raise RuntimeError("An AMI uses this snapshot. Delete the AMI first.") from exc
        raise
    return "Deleted"


@kind("ami", "AMI", "ec2", order=50)
def scan_amis(ctx, region):
    ec2 = ctx.client("ec2", region)
    return [Item("ami", i["ImageId"], i.get("Name", ""), i.get("State", ""),
                 "Its snapshots are listed separately", 0.0, _dt(i.get("CreationDate")),
                 tags=tags_dict(i.get("Tags")))
            for i in ec2.describe_images(Owners=["self"]).get("Images", [])]


@deleter("ami")
def delete_ami(ctx, item):
    ctx.client("ec2", item.region).deregister_image(ImageId=item.id)
    return "Deregistered. Scan again to delete its snapshots."


@kind("vpc_endpoint", "VPC interface endpoint", "ec2", order=25)
def scan_endpoints(ctx, region):
    ec2 = ctx.client("ec2", region)
    out = []
    for e in paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        etype = e.get("VpcEndpointType", "")
        if etype == "Gateway" or e.get("State", "").lower() in ("deleted", "deleting"):
            continue  # gateway endpoints for S3 and DynamoDB are free
        azs = max(len(e.get("SubnetIds") or []), 1)
        svc = e.get("ServiceName", "").split(".")[-1]
        out.append(Item("vpc_endpoint", e["VpcEndpointId"], name_tag(e.get("Tags")),
                        e.get("State", ""), f"{svc}, {etype}, {azs} AZ", 0.01 * H * azs,
                        e.get("CreationTimestamp"), note="Plus $0.01 per GB.",
                        tags=tags_dict(e.get("Tags"))))
    return out


@deleter("vpc_endpoint")
def delete_endpoint(ctx, item):
    resp = ctx.client("ec2", item.region).delete_vpc_endpoints(VpcEndpointIds=[item.id])
    bad = resp.get("Unsuccessful") or []
    if bad:
        raise RuntimeError(bad[0].get("Error", {}).get("Message", "Couldn't delete"))
    return "Deleting"


@kind("vpn_connection", "Site-to-site VPN", "ec2", order=25)
def scan_vpn(ctx, region):
    ec2 = ctx.client("ec2", region)
    return [Item("vpn_connection", v["VpnConnectionId"], name_tag(v.get("Tags")), v.get("State", ""),
                 v.get("Type", ""), 0.05 * H, tags=tags_dict(v.get("Tags")))
            for v in ec2.describe_vpn_connections().get("VpnConnections", [])
            if v.get("State") in ("pending", "available")]


@deleter("vpn_connection")
def delete_vpn(ctx, item):
    ctx.client("ec2", item.region).delete_vpn_connection(VpnConnectionId=item.id)
    return "Deleting"


@kind("tgw_attachment", "Transit gateway attachment", "ec2", order=99,
      manual_note="Delete the attachment from the VPC console (Transit gateway attachments).")
def scan_tgw(ctx, region):
    ec2 = ctx.client("ec2", region)
    flt = [{"Name": "state", "Values": ["available", "pending", "pendingAcceptance", "modifying"]}]
    return [Item("tgw_attachment", a["TransitGatewayAttachmentId"], name_tag(a.get("Tags")),
                 a.get("State", ""), f"{a.get('ResourceType', '')} {a.get('ResourceId', '')}",
                 0.05 * H, a.get("CreationTime"), can_delete=False,
                 note="Plus $0.02 per GB.", tags=tags_dict(a.get("Tags")))
            for a in paginate(ec2, "describe_transit_gateway_attachments",
                              "TransitGatewayAttachments", Filters=flt)]


@kind("client_vpn", "Client VPN endpoint", "ec2", order=99,
      manual_note="Disassociate its target networks, then delete it in the VPC console.")
def scan_client_vpn(ctx, region):
    ec2 = ctx.client("ec2", region)
    return [Item("client_vpn", e["ClientVpnEndpointId"], name_tag(e.get("Tags")),
                 e.get("Status", {}).get("Code", ""), e.get("Description", ""), None,
                 _dt(e.get("CreationTime")), can_delete=False,
                 note="$0.10 an hour per associated subnet, plus $0.05 per connection hour.",
                 tags=tags_dict(e.get("Tags")))
            for e in paginate(ec2, "describe_client_vpn_endpoints", "ClientVpnEndpoints")
            if e.get("Status", {}).get("Code") not in ("deleted", "deleting")]


@kind("network_firewall", "Network Firewall", "network-firewall", order=25)
def scan_nfw(ctx, region):
    nfw = ctx.client("network-firewall", region)
    out = []
    for f in paginate(nfw, "list_firewalls", "Firewalls"):
        d = nfw.describe_firewall(FirewallArn=f["FirewallArn"])
        fw = d.get("Firewall", {})
        endpoints = max(len(fw.get("SubnetMappings") or []), 1)
        status = d.get("FirewallStatus", {}).get("Status", "")
        out.append(Item("network_firewall", f["FirewallArn"], f.get("FirewallName", ""), status,
                        f"{endpoints} endpoint(s)", 0.395 * H * endpoints,
                        note="Plus $0.065 per GB." + (" Delete protection is on." if fw.get("DeleteProtection") else ""),
                        can_delete=not fw.get("DeleteProtection"), tags=tags_dict(fw.get("Tags"))))
    return out


@deleter("network_firewall")
def delete_nfw(ctx, item):
    ctx.client("network-firewall", item.region).delete_firewall(FirewallArn=item.id)
    return "Deleting"


@kind("waf_acl", "WAF web ACL", "wafv2", order=25)
def scan_waf(ctx, region):
    waf = ctx.client("wafv2", region)
    scopes = ["REGIONAL"] + (["CLOUDFRONT"] if region == "us-east-1" else [])
    out = []
    for scope in scopes:
        for acl in waf.list_web_acls(Scope=scope, Limit=100).get("WebACLs", []):
            out.append(Item("waf_acl", acl["ARN"], acl.get("Name", ""), scope.lower(),
                            "Plus $1 a month per rule", 5.0,
                            extra={"name": acl.get("Name"), "acl_id": acl.get("Id"), "scope": scope}))
    return out


@deleter("waf_acl")
def delete_waf(ctx, item):
    waf = ctx.client("wafv2", item.region)
    e = item.extra
    token = waf.get_web_acl(Name=e["name"], Scope=e["scope"], Id=e["acl_id"])["LockToken"]
    try:
        waf.delete_web_acl(Name=e["name"], Scope=e["scope"], Id=e["acl_id"], LockToken=token)
    except Exception as exc:  # noqa: BLE001
        if "Associated" in error_code(exc):
            raise RuntimeError("Still attached to a load balancer, API or distribution.") from exc
        raise
    return "Deleted"


# =================================================================== databases and caches

@kind("rds_instance", "RDS instance", "rds", order=20)
def scan_rds(ctx, region):
    rds = ctx.client("rds", region)
    out = []
    for db in paginate(rds, "describe_db_instances", "DBInstances"):
        cls = db.get("DBInstanceClass", "")
        status = db.get("DBInstanceStatus", "")
        rate = RDS_HOURLY.get(cls)
        mult = 2 if db.get("MultiAZ") else 1
        storage = 0.115 * (db.get("AllocatedStorage") or 0)
        if status == "stopped":
            cost = storage
        elif rate is None:
            cost = None
        else:
            cost = rate * H * mult + (storage if not db.get("DBClusterIdentifier") else 0)
        note = []
        if status == "stopped":
            note.append("Stopped databases start again on their own after 7 days.")
        if db.get("DeletionProtection"):
            note.append("Deletion protection is on.")
        member = db.get("DBClusterIdentifier", "")
        detail = f"{db.get('Engine', '')} {cls}" + (", Multi-AZ" if db.get("MultiAZ") else "")
        if member:
            detail += f", in cluster {member}"
        out.append(Item("rds_instance", db["DBInstanceIdentifier"], db["DBInstanceIdentifier"],
                        status, detail, cost, db.get("InstanceCreateTime"),
                        can_delete=not db.get("DeletionProtection"), note=" ".join(note),
                        extra={"cluster": member, "arn": db.get("DBInstanceArn", "")},
                        tags=tags_dict(db.get("TagList"))))
    return out


@deleter("rds_instance")
def delete_rds(ctx, item):
    rds = ctx.client("rds", item.region)
    if item.extra.get("cluster"):
        rds.delete_db_instance(DBInstanceIdentifier=item.id)
    else:
        rds.delete_db_instance(DBInstanceIdentifier=item.id, SkipFinalSnapshot=True,
                               DeleteAutomatedBackups=True)
    return "Deleting, no final snapshot (takes 5 to 10 minutes)"


@kind("rds_cluster", "Aurora / DocumentDB cluster", "rds", order=30)
def scan_rds_clusters(ctx, region):
    rds = ctx.client("rds", region)
    out = []
    for c in paginate(rds, "describe_db_clusters", "DBClusters"):
        members = len(c.get("DBClusterMembers") or [])
        note = "Storage and I/O cost extra. Its instances are listed separately."
        if c.get("DeletionProtection"):
            note += " Deletion protection is on."
        if members:
            note += " Delete its instances first, then this cluster after they're gone."
        out.append(Item("rds_cluster", c["DBClusterIdentifier"], c["DBClusterIdentifier"],
                        c.get("Status", ""), f"{c.get('Engine', '')}, {members} instance(s)", None,
                        c.get("ClusterCreateTime"), can_delete=not c.get("DeletionProtection"),
                        note=note, tags=tags_dict(c.get("TagList"))))
    return out


@deleter("rds_cluster")
def delete_rds_cluster(ctx, item):
    try:
        ctx.client("rds", item.region).delete_db_cluster(DBClusterIdentifier=item.id,
                                                         SkipFinalSnapshot=True)
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "InvalidDBClusterStateFault":
            raise RuntimeError("Its instances aren't gone yet. Run teardown again in about 10 minutes.") from exc
        raise
    return "Deleting, no final snapshot"


@kind("rds_snapshot", "RDS manual snapshot", "rds", order=60)
def scan_rds_snapshots(ctx, region):
    rds = ctx.client("rds", region)
    out = []
    for s in paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        size = s.get("AllocatedStorage", 0)
        out.append(Item("rds_snapshot", s["DBSnapshotIdentifier"], s.get("DBInstanceIdentifier", ""),
                        s.get("Status", ""), f"{size} GB {s.get('Engine', '')}", 0.095 * size,
                        s.get("SnapshotCreateTime"), extra={"cluster": False},
                        tags=tags_dict(s.get("TagList"))))
    for s in paginate(rds, "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"):
        size = s.get("AllocatedStorage", 0)
        out.append(Item("rds_snapshot", s["DBClusterSnapshotIdentifier"],
                        s.get("DBClusterIdentifier", ""), s.get("Status", ""),
                        f"{size} GB {s.get('Engine', '')} cluster", 0.021 * size,
                        s.get("SnapshotCreateTime"), extra={"cluster": True},
                        tags=tags_dict(s.get("TagList"))))
    return out


@deleter("rds_snapshot")
def delete_rds_snapshot(ctx, item):
    rds = ctx.client("rds", item.region)
    if item.extra.get("cluster"):
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=item.id)
    else:
        rds.delete_db_snapshot(DBSnapshotIdentifier=item.id)
    return "Deleted"


@kind("elasticache", "ElastiCache", "elasticache", order=20)
def scan_cache(ctx, region):
    ec = ctx.client("elasticache", region)
    out = []
    for g in paginate(ec, "describe_replication_groups", "ReplicationGroups"):
        nodes = len(g.get("MemberClusters") or [])
        rate = CACHE_HOURLY.get(g.get("CacheNodeType", ""))
        out.append(Item("elasticache", g["ReplicationGroupId"], g.get("Description", ""),
                        g.get("Status", ""), f"{g.get('CacheNodeType', '')} x {nodes}",
                        rate * H * nodes if rate else None, g.get("ReplicationGroupCreateTime"),
                        extra={"type": "group"}))
    for c in paginate(ec, "describe_cache_clusters", "CacheClusters"):
        if c.get("ReplicationGroupId"):
            continue
        nodes = c.get("NumCacheNodes", 1)
        rate = CACHE_HOURLY.get(c.get("CacheNodeType", ""))
        out.append(Item("elasticache", c["CacheClusterId"], c["CacheClusterId"],
                        c.get("CacheClusterStatus", ""),
                        f"{c.get('Engine', '')} {c.get('CacheNodeType', '')} x {nodes}",
                        rate * H * nodes if rate else None, c.get("CacheClusterCreateTime"),
                        extra={"type": "cluster"}))
    try:
        for s in paginate(ec, "describe_serverless_caches", "ServerlessCaches"):
            if s.get("Status") in ("deleting",):
                continue
            out.append(Item("elasticache", s["ServerlessCacheName"], s["ServerlessCacheName"],
                            s.get("Status", ""), f"serverless {s.get('Engine', '')}", None,
                            s.get("CreateTime"), note="Serverless has a minimum storage charge.",
                            extra={"type": "serverless"}))
    except Exception as exc:  # noqa: BLE001 - older regions or SDKs
        if is_access_denied(exc):
            raise
    return out


@deleter("elasticache")
def delete_cache(ctx, item):
    ec = ctx.client("elasticache", item.region)
    t = item.extra.get("type")
    if t == "group":
        ec.delete_replication_group(ReplicationGroupId=item.id, RetainPrimaryCluster=False)
    elif t == "serverless":
        ec.delete_serverless_cache(ServerlessCacheName=item.id)
    else:
        ec.delete_cache_cluster(CacheClusterId=item.id)
    return "Deleting"


@kind("opensearch", "OpenSearch domain", "opensearch", order=20)
def scan_opensearch(ctx, region):
    osc = ctx.client("opensearch", region)
    names = [d["DomainName"] for d in osc.list_domain_names().get("DomainNames", [])]
    out = []
    for i in range(0, len(names), 5):
        for d in osc.describe_domains(DomainNames=names[i:i + 5]).get("DomainStatusList", []):
            if d.get("Deleted"):
                continue
            cc = d.get("ClusterConfig", {})
            itype, count = cc.get("InstanceType", ""), cc.get("InstanceCount", 1)
            rate = SEARCH_HOURLY.get(itype)
            ebs = (d.get("EBSOptions") or {}).get("VolumeSize") or 0
            cost = (rate * H * count + 0.122 * ebs * count) if rate else None
            out.append(Item("opensearch", d["DomainName"], d["DomainName"],
                            "processing" if d.get("Processing") else "active",
                            f"{itype} x {count}", cost))
    return out


@deleter("opensearch")
def delete_opensearch(ctx, item):
    ctx.client("opensearch", item.region).delete_domain(DomainName=item.id)
    return "Deleting"


@kind("aoss", "OpenSearch Serverless collection", "opensearchserverless", order=20)
def scan_aoss(ctx, region):
    aoss = ctx.client("opensearchserverless", region)
    return [Item("aoss", c["id"], c.get("name", ""), c.get("status", ""), "vector or search collection",
                 175.0, note="At least about $175 a month for the minimum capacity units.")
            for c in paginate(aoss, "list_collections", "collectionSummaries")
            if c.get("status") not in ("DELETING", "FAILED")]


@deleter("aoss")
def delete_aoss(ctx, item):
    ctx.client("opensearchserverless", item.region).delete_collection(id=item.id)
    return "Deleting"


@kind("eks_cluster", "EKS cluster", "eks", order=99,
      manual_note="Delete its node groups and Fargate profiles first, then the cluster (eksctl delete cluster does all of it).")
def scan_eks(ctx, region):
    eks = ctx.client("eks", region)
    return [Item("eks_cluster", name, name, "active", "Nodes are listed as EC2 instances", 0.10 * H,
                 can_delete=False)
            for name in paginate(eks, "list_clusters", "clusters")]


# =================================================================== keys and secrets

@kind("kms_key", "KMS key", "kms", order=70)
def scan_kms(ctx, region):
    kms = ctx.client("kms", region)
    aliases = {}
    for a in paginate(kms, "list_aliases", "Aliases"):
        if a.get("TargetKeyId"):
            aliases.setdefault(a["TargetKeyId"], a.get("AliasName", ""))
    out = []
    for k in paginate(kms, "list_keys", "Keys"):
        try:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        except Exception as exc:  # noqa: BLE001
            if is_access_denied(exc):
                continue  # key policy doesn't let us look; it's probably not ours to clean up
            raise
        if meta.get("KeyManager") != "CUSTOMER":
            continue
        if meta.get("KeyState") not in ("Enabled", "Disabled", "PendingImport"):
            continue
        name = aliases.get(k["KeyId"], "").replace("alias/", "") or meta.get("Description", "")[:40]
        out.append(Item("kms_key", k["KeyId"], name, meta.get("KeyState", "").lower(),
                        meta.get("KeySpec", ""), 1.0, meta.get("CreationDate"),
                        note="Deletion waits 7 days, and you can cancel it in that time."))
    return out


@deleter("kms_key")
def delete_kms(ctx, item):
    resp = ctx.client("kms", item.region).schedule_key_deletion(KeyId=item.id, PendingWindowInDays=7)
    when = resp.get("DeletionDate")
    return "Scheduled for deletion" + (f" on {when:%Y-%m-%d}" if isinstance(when, datetime) else "")


@kind("secret", "Secrets Manager secret", "secretsmanager", order=70)
def scan_secrets(ctx, region):
    sm = ctx.client("secretsmanager", region)
    out = []
    for s in paginate(sm, "list_secrets", "SecretList"):
        owner = s.get("OwningService", "")
        last = s.get("LastAccessedDate")
        detail = f"last used {last:%Y-%m-%d}" if isinstance(last, datetime) else "never read"
        out.append(Item("secret", s["ARN"], s.get("Name", ""), "active", detail, 0.40,
                        s.get("CreatedDate"), can_delete=not owner,
                        note=(f"Managed by {owner}. Delete it there." if owner else
                              "Deletion waits 7 days, and you can restore it in that time."),
                        tags=tags_dict(s.get("Tags"))))
    return out


@deleter("secret")
def delete_secret(ctx, item):
    ctx.client("secretsmanager", item.region).delete_secret(SecretId=item.id, RecoveryWindowInDays=7)
    return "Scheduled for deletion in 7 days"


@kind("private_ca", "Private CA", "acm-pca", order=70)
def scan_pca(ctx, region):
    pca = ctx.client("acm-pca", region)
    out = []
    for ca in paginate(pca, "list_certificate_authorities", "CertificateAuthorities"):
        status = ca.get("Status", "")
        if status in ("DELETED", "FAILED"):
            continue
        short = ca.get("UsageMode") == "SHORT_LIVED_CERTIFICATE"
        cn = (ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {}) or {}).get("CommonName", "")
        out.append(Item("private_ca", ca["Arn"], cn, status.lower(),
                        "short-lived certificate mode" if short else "general purpose",
                        50.0 if short else 400.0, ca.get("CreatedAt"),
                        note="Billed every month until deleted. Deletion waits 7 days.",
                        extra={"status": status}))
    return out


@deleter("private_ca")
def delete_pca(ctx, item):
    pca = ctx.client("acm-pca", item.region)
    if item.extra.get("status") == "ACTIVE":
        pca.update_certificate_authority(CertificateAuthorityArn=item.id, Status="DISABLED")
    pca.delete_certificate_authority(CertificateAuthorityArn=item.id, PermanentDeletionTimeInDays=7)
    return "Disabled and scheduled for deletion in 7 days"


@kind("cloudhsm", "CloudHSM cluster", "cloudhsmv2", order=99,
      manual_note="Delete its HSMs, then the cluster, in the CloudHSM console.")
def scan_hsm(ctx, region):
    hsm = ctx.client("cloudhsmv2", region)
    out = []
    for c in paginate(hsm, "describe_clusters", "Clusters"):
        if c.get("State") in ("DELETED", "DELETE_IN_PROGRESS"):
            continue
        n = len(c.get("Hsms") or [])
        out.append(Item("cloudhsm", c["ClusterId"], "", c.get("State", "").lower(), f"{n} HSM(s)",
                        1.45 * H * n, c.get("CreateTimestamp"), can_delete=False,
                        tags=tags_dict(c.get("TagList"))))
    return out


# =================================================================== security services

def _not_enabled(exc) -> bool:
    msg = str(getattr(exc, "response", {}).get("Error", {}).get("Message", "")).lower()
    return "not enabled" in msg or "not subscribed" in msg or "is not enabled" in msg


@kind("guardduty", "GuardDuty", "guardduty", order=10)
def scan_guardduty(ctx, region):
    gd = ctx.client("guardduty", region)
    out = []
    for det in gd.list_detectors().get("DetectorIds", []):
        d = gd.get_detector(DetectorId=det)
        if d.get("Status") == "ENABLED":
            out.append(Item("guardduty", det, "", "enabled", "Detector on", None,
                            _dt(d.get("CreatedAt")),
                            note="Billed by events and data analyzed. Free for the first 30 days.",
                            tags=dict(d.get("Tags") or {})))
    return out


@deleter("guardduty")
def delete_guardduty(ctx, item):
    ctx.client("guardduty", item.region).delete_detector(DetectorId=item.id)
    return "Turned off"


@kind("securityhub", "Security Hub", "securityhub", order=10)
def scan_securityhub(ctx, region):
    sh = ctx.client("securityhub", region)
    try:
        hub = sh.describe_hub()
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "InvalidAccessException" or _not_enabled(exc):
            return []
        raise
    return [Item("securityhub", hub.get("HubArn", "hub"), "", "enabled", "Security Hub on", None,
                 _dt(hub.get("SubscribedAt")), note="Billed by checks and findings.")]


@deleter("securityhub")
def delete_securityhub(ctx, item):
    ctx.client("securityhub", item.region).disable_security_hub()
    return "Turned off"


@kind("config_recorder", "AWS Config recorder", "config", order=10)
def scan_config(ctx, region):
    cfg = ctx.client("config", region)
    return [Item("config_recorder", s.get("name", ""), s.get("name", ""), "recording",
                 "Recording resource changes", None,
                 note="Billed per item recorded. Stopping keeps its history.")
            for s in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            if s.get("recording")]


@deleter("config_recorder")
def delete_config(ctx, item):
    ctx.client("config", item.region).stop_configuration_recorder(ConfigurationRecorderName=item.id)
    return "Recording stopped"


@kind("inspector", "Inspector", "inspector2", order=10)
def scan_inspector(ctx, region):
    ins = ctx.client("inspector2", region)
    out = []
    for acct in ins.batch_get_account_status().get("accounts", []):
        rs = acct.get("resourceState", {})
        on = [name for name, key in (("EC2", "ec2"), ("ECR", "ecr"), ("LAMBDA", "lambda"),
                                     ("LAMBDA_CODE", "lambdaCode"))
              if rs.get(key, {}).get("status") == "ENABLED"]
        if on:
            out.append(Item("inspector", acct.get("accountId", "inspector"), "", "enabled",
                            "Scanning " + ", ".join(on), None, note="Billed per resource scanned.",
                            extra={"types": on}))
    return out


@deleter("inspector")
def delete_inspector(ctx, item):
    ctx.client("inspector2", item.region).disable(resourceTypes=item.extra.get("types") or ["EC2"])
    return "Turned off"


@kind("macie", "Macie", "macie2", order=10)
def scan_macie(ctx, region):
    m = ctx.client("macie2", region)
    try:
        s = m.get_macie_session()
    except Exception as exc:  # noqa: BLE001
        if _not_enabled(exc) or error_code(exc) in ("ResourceNotFoundException",):
            return []
        raise
    if s.get("status") != "ENABLED":
        return []
    return [Item("macie", "macie", "", "enabled", "Macie on", None, s.get("createdAt"),
                 note="Billed per bucket monitored and data scanned.")]


@deleter("macie")
def delete_macie(ctx, item):
    ctx.client("macie2", item.region).disable_macie()
    return "Turned off"


# =================================================================== account-wide

@kind("s3_bucket", "S3 bucket", "s3", order=70, scope="global")
def scan_s3(ctx, region):
    s3 = ctx.client("s3", "us-east-1")
    out = []
    now = datetime.now(timezone.utc)
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        loc = b.get("BucketRegion")
        if not loc:
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except Exception:  # noqa: BLE001
                loc = "?"
        size_gb = None
        if loc != "?":
            try:
                cw = ctx.client("cloudwatch", loc)
                pts = cw.get_metric_statistics(
                    Namespace="AWS/S3", MetricName="BucketSizeBytes",
                    Dimensions=[{"Name": "BucketName", "Value": name},
                                {"Name": "StorageType", "Value": "StandardStorage"}],
                    StartTime=now - timedelta(days=3), EndTime=now, Period=86400,
                    Statistics=["Average"]).get("Datapoints", [])
                if pts:
                    size_gb = max(pts, key=lambda p: p["Timestamp"])["Average"] / 1e9
                else:
                    size_gb = 0.0
            except Exception:  # noqa: BLE001
                pass
        detail = f"about {size_gb:,.2f} GB" if size_gb is not None else "size unknown"
        item = Item("s3_bucket", name, name, "", detail,
                    0.023 * size_gb if size_gb is not None else None, b.get("CreationDate"),
                    note="Only deletes if the bucket is already empty.")
        item.region = loc
        out.append(item)
    return out


@deleter("s3_bucket")
def delete_s3(ctx, item):
    s3 = ctx.client("s3", item.region if item.region not in ("", "?") else "us-east-1")
    resp = s3.list_object_versions(Bucket=item.id, MaxKeys=1)
    if resp.get("Versions") or resp.get("DeleteMarkers"):
        raise RuntimeError(f"Not empty. Empty it first: aws s3 rm s3://{item.id} --recursive "
                           "(and delete old versions if versioning is on).")
    s3.delete_bucket(Bucket=item.id)
    return "Deleted"


@kind("route53_zone", "Route 53 hosted zone", "route53", order=99, scope="global",
      manual_note="Delete its records (except NS and SOA), then the zone, in the Route 53 console.")
def scan_route53(ctx, region):
    r53 = ctx.client("route53", "us-east-1")
    return [Item("route53_zone", z["Id"].split("/")[-1], z.get("Name", "").rstrip("."),
                 "private" if z.get("Config", {}).get("PrivateZone") else "public",
                 f"{z.get('ResourceRecordSetCount', 0)} records", 0.50, can_delete=False)
            for z in paginate(r53, "list_hosted_zones", "HostedZones")]


@kind("shield", "Shield Advanced", "shield", order=99, scope="global",
      manual_note="Shield Advanced is a 1-year commitment. Contact AWS Support to cancel.")
def scan_shield(ctx, region):
    sh = ctx.client("shield", "us-east-1")
    try:
        state = sh.get_subscription_state().get("SubscriptionState")
    except Exception as exc:  # noqa: BLE001
        if is_access_denied(exc):
            return []
        raise
    if state != "ACTIVE":
        return []
    return [Item("shield", "shield-advanced", "", "active", "Subscription on", 3000.0, can_delete=False)]


# =================================================================== running a sweep

def kind_choices() -> list:
    return sorted(KINDS)


def _arn_end(text) -> str:
    """The resource's own ID or name at the end of an ARN (key/1234 -> 1234, db:lab -> lab,
    arn:aws:s3:::bucket -> bucket), or "" for text that isn't an ARN."""
    parts = str(text).split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return ""
    return re.split(r"[:/]", parts[5])[-1]


def is_kept(item, cfg) -> bool:
    """True if the keep list names the item, or it has the keep tag. The tag can only
    match types whose scan reads tags (see the note at the top).

    The keep list takes IDs, ARNs or names. Most items are listed by ID, so an ARN on the
    keep list also keeps the item whose ID or name ends it, and an item listed by ARN is
    also kept by the ID at the end of its ARN."""
    keep = set(cfg.get("keep") or [])
    tag = cfg.get("keep_tag") or ""
    if item.id in keep or item.name in keep or bool(tag and tag in item.tags):
        return True
    ends = {_arn_end(k) for k in keep} - {""}
    if item.id in ends or (item.name and item.name in ends):
        return True
    own = _arn_end(item.id)
    return bool(own) and own in keep


def apply_keep(items, cfg=None):
    """Mark items kept or not from the keep list and keep tag as they are now."""
    cfg = load_config() if cfg is None else cfg
    for it in items:
        it.kept = is_kept(it, cfg)


# Errors that mean the service isn't offered there or isn't turned on for the account,
# so nothing of that type can be running.
NOT_OFFERED_NAMES = ("UnknownEndpoint", "UnknownEndpointError")
NOT_OFFERED_CODES = ("OptInRequired", "SubscriptionRequiredException")
# Errors that mean the check never ran: no connection, or AWS turned the credentials
# away (which is also what a region that isn't turned on does). These become warnings,
# so a scan that couldn't look doesn't pass for a clean one.
UNREACHABLE_NAMES = ("EndpointConnectionError",)
UNREACHABLE_CODES = ("UnrecognizedClientException", "InvalidClientTokenId", "AuthFailure")


def scan(profiles, regions=None, kinds=None, progress=None, cancel=None, workers=16):
    """Scan one or more profiles. Returns (items, warnings).

    progress(done, total, text) is called from worker threads.
    """
    cfg = load_config()
    profiles = list(profiles) or [None]
    wanted = [KINDS[k] for k in (kinds or KINDS) if k in KINDS]
    items, warnings = [], []
    denied = {}
    unreachable = {}

    contexts = []
    for p in profiles:
        try:
            ctx = AwsContext(p)
            ctx.account  # noqa: B018 - confirms the credentials work
            contexts.append(ctx)
        except AuthError as exc:
            warnings.append(f"{p or 'default'}: {exc}")
    tasks = []
    for ctx in contexts:
        regs = list(regions) if regions else ctx.enabled_regions()
        for k in wanted:
            if k.scope == "global":
                tasks.append((ctx, k, "global"))
            else:
                for r in ctx.regions_for(k.service, regs):
                    tasks.append((ctx, k, r))

    total = len(tasks)
    done = 0

    def run(task):
        ctx, k, region = task
        if cancel is not None and cancel.is_set():
            return task, [], None
        try:
            return task, k.scan(ctx, region), None
        except Exception as exc:  # noqa: BLE001
            return task, [], exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run, t) for t in tasks]
        for fut in as_completed(futures):
            (ctx, k, region), found, exc = fut.result()
            done += 1
            if progress:
                progress(done, total, f"{k.label} in {region}")
            if exc is not None:
                name, code = type(exc).__name__, error_code(exc)
                if name in NOT_OFFERED_NAMES or code in NOT_OFFERED_CODES:
                    continue  # service not offered or not turned on there
                if is_access_denied(exc):
                    denied.setdefault((ctx.label, k.label), []).append(region)
                elif name in UNREACHABLE_NAMES or code in UNREACHABLE_CODES:
                    _, kinds_hit, regs = unreachable.setdefault(
                        (ctx.label, code or name), (error_text(exc, ctx.profile), set(), set()))
                    kinds_hit.add(k.label)
                    regs.add(region)
                else:
                    warnings.append(f"{ctx.label}: {k.label} in {region}: {error_text(exc, ctx.profile)}")
                continue
            for it in found:
                it.profile = ctx.profile or ""
                it.account = ctx.account
                if not it.region:
                    it.region = region if region != "global" else "global"
                if KINDS[it.kind].delete is None:
                    it.can_delete = False
                    if not it.note:
                        it.note = KINDS[it.kind].manual_note
                    elif KINDS[it.kind].manual_note:
                        it.note += " " + KINDS[it.kind].manual_note
                it.kept = is_kept(it, cfg)
                items.append(it)

    for (label, code), (reason, kinds_hit, regs) in sorted(unreachable.items()):
        what = next(iter(kinds_hit)) if len(kinds_hit) == 1 else f"{len(kinds_hit)} types"
        where = ", ".join(sorted(regs)) if len(regs) <= 3 else f"{len(regs)} regions"
        text = f"{label}: couldn't check {what} in {where}. {reason}"
        if code in UNREACHABLE_CODES:
            text += " If a region isn't turned on for this account, take it out of the region list."
        warnings.append(text)
    for (label, kind_label), regs in sorted(denied.items()):
        where = regs[0] if len(regs) == 1 else f"{len(regs)} regions"
        warnings.append(f"{label}: no permission to list {kind_label} ({where})")
    items.sort(key=lambda i: (-(i.monthly or 0), i.profile, i.region, i.kind, i.id))
    return items, warnings


def total_monthly(items) -> float:
    return sum(i.monthly or 0 for i in items if not i.kept)


def summary_line(items) -> str:
    live = [i for i in items if not i.kept]
    if not live:
        return "Nothing found that costs money."
    unknown = sum(1 for i in live if i.monthly is None)
    text = f"{len(live)} item(s), about {money(total_monthly(live))}/month"
    if unknown:
        text += f" plus {unknown} with usage-based pricing"
    return text + "."


def account_problem(ctx, item) -> str:
    """Why item can't be deleted through ctx, or "" when ctx is still the account it was
    found in. Deletes go by name or ID, and some turn a service off for the whole account,
    so a profile pointed at another account since the scan would hit that account."""
    who = item.profile or "default"
    if not item.account:
        return f"Skipped, no account was recorded for it when profile {who} was scanned. Scan again."
    now = ctx.account
    if now != item.account:
        return f"Skipped, profile {who} now points at account {now}, not {item.account}. Scan again."
    return ""


def teardown(items, dry_run=False, progress=None, cancel=None):
    """Delete items in a safe order. Returns a list of (item, ok, message).

    Right before each item it reads the keep list and keep tag again, and checks the
    item's profile still points at the account the scan found it in.
    """
    results = []
    contexts = {}
    todo = sorted(items, key=lambda i: (KINDS[i.kind].order, i.region, i.id))
    for n, it in enumerate(todo, 1):
        if cancel is not None and cancel.is_set():
            results.append((it, False, "Skipped, stopped by you"))
            continue
        k = KINDS[it.kind]
        if is_kept(it, load_config()):
            it.kept = True  # added to the keep list, or the keep tag changed, since the scan
        if it.kept:
            results.append((it, False, "Kept (keep list or keep tag)"))
        elif not it.can_delete or k.delete is None:
            results.append((it, False, "Manual: " + (it.note or k.manual_note or "not supported")))
        elif dry_run:
            results.append((it, True, "Would delete"))
        else:
            try:
                ctx = contexts.get(it.profile)
                if ctx is None:
                    ctx = contexts[it.profile] = AwsContext(it.profile or None)
                problem = account_problem(ctx, it)
                if problem:
                    results.append((it, False, problem))
                else:
                    results.append((it, True, k.delete(ctx, it) or "Done"))
            except Exception as exc:  # noqa: BLE001
                results.append((it, False, error_text(exc, it.profile) if not isinstance(
                    exc, RuntimeError) else str(exc)))
        if progress:
            progress(n, len(todo), f"{k.label} {it.id}: {results[-1][2]}")
    return results


def month_spend(profile=None) -> dict:
    """Month-to-date cost by service from Cost Explorer. Each call costs $0.01."""
    ctx = AwsContext(profile)
    ce = ctx.client("ce", "us-east-1")
    today = date.today()
    start = today.replace(day=1)
    end = today + timedelta(days=1)
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    totals = {}
    unit = "USD"
    for period in resp.get("ResultsByTime", []):
        for g in period.get("Groups", []):
            amt = g.get("Metrics", {}).get("UnblendedCost", {})
            unit = amt.get("Unit", unit)
            totals[g["Keys"][0]] = totals.get(g["Keys"][0], 0.0) + float(amt.get("Amount", 0))
    rows = sorted(((s, a) for s, a in totals.items() if abs(a) >= 0.005), key=lambda x: -x[1])
    return {"profile": profile or "default", "start": start.isoformat(), "unit": unit,
            "total": sum(a for _, a in rows), "services": rows}
