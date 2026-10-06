"""Tests for Drift. AWS calls run against moto, so no real account is touched.

Run from the repo root:  python3 -m unittest tests.test_drift -v
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

from awskit import common, drift  # noqa: E402

try:
    import boto3
    from botocore.exceptions import ClientError
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

ACCOUNT = "123456789012"
PROVIDER = 'provider["registry.terraform.io/hashicorp/aws"]'
# Fake secrets. None of these may ever show up in anything Drift prints or writes.
DB_PASSWORD = "Sup3r-Secret-Pa55word"
RANDOM_RESULT = "R4nd0m-Result-Value-77"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----FAKEKEYMATERIAL"
USER_DATA = "userdata-with-a-token-in-it"
SECRET_TAG = "hunter2-owner-tag"
SECRET_TAG_NEW = "changed-owner-secret-9"
SECRETS = (DB_PASSWORD, RANDOM_RESULT, PRIVATE_KEY, USER_DATA, SECRET_TAG, SECRET_TAG_NEW)
TRUST = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def res(rtype, name, attrs, sensitive=None, module=""):
    """One resource for both state shapes. sensitive: show -json style marks."""
    return {"type": rtype, "name": name, "attrs": attrs, "sensitive": sensitive or {},
            "module": module}


def show_json(resources) -> dict:
    """terraform show -json shape."""
    out = []
    for r in resources:
        addr = f"{r['type']}.{r['name']}"
        out.append({"address": addr, "mode": "managed", "type": r["type"], "name": r["name"],
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "schema_version": 0, "values": r["attrs"],
                    "sensitive_values": r["sensitive"]})
    return {"format_version": "1.0", "terraform_version": "1.9.8",
            "values": {"root_module": {"resources": out}}}


def raw_state(resources) -> dict:
    """terraform.tfstate (version 4) shape, with sensitive_attributes paths."""
    out = []
    for r in resources:
        paths = []
        for attr, mark in r["sensitive"].items():
            if mark is True:
                paths.append([{"type": "get_attr", "value": attr}])
            elif isinstance(mark, dict):
                for key in mark:
                    paths.append([{"type": "get_attr", "value": attr},
                                  {"type": "index", "value": {"value": key, "type": "string"}}])
        out.append({"mode": "managed", "type": r["type"], "name": r["name"],
                    "provider": PROVIDER,
                    "instances": [{"schema_version": 0, "attributes": r["attrs"],
                                   "sensitive_attributes": paths}]})
    return {"version": 4, "terraform_version": "1.9.8", "serial": 7, "lineage": "test",
            "outputs": {}, "resources": out}


def write_json(name, doc) -> str:
    path = Path(TMP) / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def run_cli(argv) -> tuple:
    from awskit import cli
    out, errs = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
        code = cli.main(argv)
    return code, out.getvalue(), errs.getvalue()


def denied(op="DescribeVpcs"):
    return ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "not allowed"}}, op)


def by_id(findings):
    return {f.id: f for f in findings}


@unittest.skipIf(mock_aws is None, "boto3 and moto aren't installed")
class DriftAccountTests(unittest.TestCase):
    """One fake lab account built once, with a state that matches most of it."""

    @classmethod
    def setUpClass(cls):
        cls.mock = mock_aws()
        cls.mock.start()
        cls.ids = ids = {}
        ec2 = boto3.client("ec2", "us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc], Tags=[{"Key": "Name", "Value": "lab-vpc"},
                                               {"Key": "Env", "Value": "lab"}])
        sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24",
                                AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sub, MapPublicIpOnLaunch={"Value": True})
        sg = ec2.create_security_group(GroupName="web", Description="web",
                                       VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        # A rule managed by its own aws_vpc_security_group_ingress_rule resource.
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        inst = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                                 SubnetId=sub, SecurityGroupIds=[sg],
                                 TagSpecifications=[{"ResourceType": "instance", "Tags": [
                                     {"Key": "Name", "Value": "web-1"}]}])["Instances"][0]
        rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
        igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        s3 = boto3.client("s3", "us-east-1")
        s3.create_bucket(Bucket="lab-logs-bucket")
        s3.put_bucket_tagging(Bucket="lab-logs-bucket",
                              Tagging={"TagSet": [{"Key": "Env", "Value": "lab"}]})
        s3.put_bucket_versioning(Bucket="lab-logs-bucket",
                                 VersioningConfiguration={"Status": "Enabled"})
        s3.create_bucket(Bucket="console-experiment")            # not in the state
        s3.create_bucket(Bucket="ignored-by-id")                 # hidden by the ignore list
        iam = boto3.client("iam")
        iam.create_role(RoleName="lab-app", AssumeRolePolicyDocument=json.dumps(TRUST))
        pol = iam.create_policy(PolicyName="lab-read", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                                                    "Resource": "*"}]}))["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="lab-app", PolicyArn=pol)
        iam.create_service_linked_role(AWSServiceName="autoscaling.amazonaws.com")
        iam.create_user(UserName="lab-user")
        ddb = boto3.client("dynamodb", "us-east-1")
        ddb.create_table(TableName="lab-table", BillingMode="PAY_PER_REQUEST",
                         KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
        sqs = boto3.client("sqs", "us-east-1")
        queue = sqs.create_queue(QueueName="lab-queue")["QueueUrl"]
        cfn_queue = sqs.create_queue(QueueName="cfn-made-queue",
                                     tags={"aws:cloudformation:stack-name": "my-stack"})["QueueUrl"]
        tag_ignored = sqs.create_queue(QueueName="ignore-me-queue",
                                       tags={"awskit:drift-ignore": "yes"})["QueueUrl"]
        boto3.client("sqs", "us-west-2").create_queue(QueueName="west-queue")
        logs = boto3.client("logs", "us-east-1")
        logs.create_log_group(logGroupName="/lab/app")
        logs.create_log_group(logGroupName="/aws/lambda/console-fn")
        # The same name in another region is a different log group.
        boto3.client("logs", "us-west-2").create_log_group(logGroupName="/lab/app")
        boto3.client("ecr", "us-east-1").create_repository(repositoryName="console-repo")
        rds = boto3.client("rds", "us-east-1")
        rds.create_db_instance(DBInstanceIdentifier="lab-db", DBInstanceClass="db.t3.micro",
                               Engine="postgres", MasterUsername="labadmin",
                               MasterUserPassword=DB_PASSWORD, AllocatedStorage=20,
                               Tags=[{"Key": "Owner", "Value": SECRET_TAG}])
        kms = boto3.client("kms", "us-east-1")
        key = kms.create_key(Description="lab key")["KeyMetadata"]["KeyId"]
        kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
        ids.update(vpc=vpc, subnet=sub, sg=sg, instance=inst["InstanceId"], rt=rt, igw=igw,
                   policy=pol, queue=queue, cfn_queue=cfn_queue, tag_ignored=tag_ignored, key=key)

        arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}"
        resources = [
            res("aws_vpc", "main", {"id": vpc, "arn": f"{arn}:vpc/{vpc}", "cidr_block": "10.0.0.0/16",
                                    "tags": {"Name": "lab-vpc", "Env": "lab"},
                                    "tags_all": {"Name": "lab-vpc", "Env": "lab"}}),
            res("aws_subnet", "a", {"id": sub, "arn": f"{arn}:subnet/{sub}", "vpc_id": vpc,
                                    "availability_zone": "us-east-1a",
                                    "map_public_ip_on_launch": True, "tags": {}, "tags_all": {}}),
            res("aws_security_group", "web", {
                "id": sg, "arn": f"{arn}:security-group/{sg}", "name": "web", "vpc_id": vpc,
                "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                             "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
                             "prefix_list_ids": [], "security_groups": [], "self": False,
                             "description": "https"}],
                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0,
                            "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
                            "prefix_list_ids": [], "security_groups": [], "self": False,
                            "description": ""}],
                "tags": {}, "tags_all": {}}),
            res("aws_vpc_security_group_ingress_rule", "ssh", {
                "id": "sgr-0123", "security_group_id": sg, "ip_protocol": "tcp",
                "from_port": 22, "to_port": 22, "cidr_ipv4": "10.0.0.0/8"}),
            res("aws_instance", "web", {
                "id": inst["InstanceId"], "arn": f"{arn}:instance/{inst['InstanceId']}",
                "instance_type": "t3.micro", "subnet_id": sub, "vpc_security_group_ids": [sg],
                "user_data": USER_DATA, "tags": {"Name": "web-1"}, "tags_all": {"Name": "web-1"}},
                {"user_data": True}),
            res("aws_route_table", "public", {"id": rt, "arn": f"{arn}:route-table/{rt}",
                                              "vpc_id": vpc, "route": [], "tags": {}, "tags_all": {}}),
            res("aws_route", "default", {"id": "r-x", "route_table_id": rt,
                                         "destination_cidr_block": "0.0.0.0/0", "gateway_id": igw}),
            res("aws_internet_gateway", "main", {"id": igw, "arn": f"{arn}:internet-gateway/{igw}",
                                                 "vpc_id": vpc, "tags": {}, "tags_all": {}}),
            res("aws_s3_bucket", "logs", {"id": "lab-logs-bucket", "bucket": "lab-logs-bucket",
                                          "arn": "arn:aws:s3:::lab-logs-bucket", "region": "us-east-1",
                                          "tags": {"Env": "lab"}, "tags_all": {"Env": "lab"}}),
            res("aws_s3_bucket_versioning", "logs", {
                "id": "lab-logs-bucket", "bucket": "lab-logs-bucket",
                "versioning_configuration": [{"status": "Enabled", "mfa_delete": ""}]}),
            res("aws_iam_role", "app", {"id": "lab-app", "name": "lab-app", "path": "/",
                                        "arn": f"arn:aws:iam::{ACCOUNT}:role/lab-app",
                                        "assume_role_policy": json.dumps(TRUST),
                                        "managed_policy_arns": [], "tags": {}, "tags_all": {}}),
            res("aws_iam_role_policy_attachment", "app_read", {"id": "x", "role": "lab-app",
                                                              "policy_arn": pol}),
            res("aws_iam_user", "lab", {"id": "lab-user", "name": "lab-user",
                                        "arn": f"arn:aws:iam::{ACCOUNT}:user/lab-user",
                                        "tags": {}, "tags_all": {}}),
            res("aws_dynamodb_table", "t", {"id": "lab-table", "name": "lab-table",
                                            "arn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/lab-table",
                                            "tags": {}, "tags_all": {}}),
            res("aws_sqs_queue", "q", {"id": queue, "url": queue, "name": "lab-queue",
                                       "arn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:lab-queue",
                                       "tags": {}, "tags_all": {}}),
            res("aws_sqs_queue", "old", {
                "id": f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/deleted-in-console",
                "name": "deleted-in-console",
                "arn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:deleted-in-console",
                "tags": {}, "tags_all": {}}),
            res("aws_cloudwatch_log_group", "app", {
                "id": "/lab/app", "name": "/lab/app",
                "arn": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/lab/app",
                "tags": {}, "tags_all": {}}),
            res("aws_db_instance", "db", {
                "id": "db-ABCDEFGHIJ", "identifier": "lab-db", "password": DB_PASSWORD,
                "arn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:lab-db",
                "tags": {"Owner": SECRET_TAG}, "tags_all": {"Owner": SECRET_TAG}},
                {"password": True, "tags": {"Owner": True}, "tags_all": {"Owner": True}}),
            res("aws_kms_key", "lab", {"id": key, "key_id": key, "description": "lab key",
                                       "arn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{key}",
                                       "tags": {}, "tags_all": {}}),
            # Not AWS: never read, and their secrets must never show up anywhere.
            res("random_password", "db", {"id": "none", "result": RANDOM_RESULT}, {"result": True}),
            res("tls_private_key", "ssh", {"id": "x", "private_key_pem": PRIVATE_KEY},
                {"private_key_pem": True}),
        ]
        cls.resources = resources
        cls.show_path = write_json("lab-show.json", show_json(resources))
        cls.raw_path = write_json("lab.tfstate", raw_state(resources))

        # Changes made outside Terraform after the state was written.
        ec2.create_tags(Resources=[vpc], Tags=[{"Key": "Owner", "Value": "console"}])
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        rds.add_tags_to_resource(ResourceName=f"arn:aws:rds:us-east-1:{ACCOUNT}:db:lab-db",
                                 Tags=[{"Key": "Owner", "Value": SECRET_TAG_NEW}])

        drift.save_settings({"ignore": ["tag:awskit:drift-ignore", "ignored-by-id"]})
        cls.stack = drift.load_source(cls.show_path)
        cls.report, cls.inv = drift.compare([cls.stack], [None], ["us-east-1", "us-west-2"])

    @classmethod
    def tearDownClass(cls):
        cls.mock.stop()

    # ---- matching
    def test_reading_the_state_keeps_only_compared_settings(self):
        st = self.stack
        self.assertEqual(st.total, 19)                  # managed AWS resources only
        self.assertEqual(len(st.resources), 15)         # the types Drift reads on their own
        self.assertEqual(len(st.children), 4)           # rule, route, attachment, versioning
        text = repr(st)
        for secret in (DB_PASSWORD, RANDOM_RESULT, PRIVATE_KEY, USER_DATA):
            self.assertNotIn(secret, text)
        db = next(m for m in st.resources if m.type == "aws_db_instance")
        self.assertEqual(db.id, "lab-db")               # identifier, not the dbi resource id
        self.assertEqual(db.secret_tags, {"Owner"})
        self.assertTrue(all(m.region in ("us-east-1", "global") for m in st.resources))
        self.assertTrue(all(m.account == ACCOUNT for m in st.resources))

    def test_statuses(self):
        f = by_id(self.report.findings)
        ids = self.ids
        self.assertEqual(f[ids["vpc"]].status, "changed")
        self.assertEqual(f[ids["sg"]].status, "changed")
        self.assertEqual(f["lab-db"].status, "changed")
        gone = f[f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/deleted-in-console"]
        self.assertEqual(gone.status, "gone")
        self.assertEqual(gone.address, "aws_sqs_queue.old")
        self.assertIn("terraform state rm 'aws_sqs_queue.old'", gone.detail_text())
        self.assertEqual(f[ids["key"]].status, "gone")  # scheduled for deletion
        self.assertIn("scheduled for deletion", f[ids["key"]].detail)
        self.assertIn("cancel-key-deletion", f[ids["key"]].detail_text())
        self.assertEqual(gone.detail, "aws_sqs_queue.old: not in AWS any more")
        self.assertEqual(f["console-experiment"].status, "unmanaged")
        # Matched and unchanged: not reported at all.
        here = by_id(x for x in self.report.findings if x.region in ("us-east-1", "global"))
        for same in (ids["subnet"], ids["instance"], ids["rt"], ids["igw"], "lab-logs-bucket",
                     "lab-app", "lab-user", "lab-table", ids["queue"], "/lab/app"):
            self.assertNotIn(same, here, same)

    def test_same_name_in_another_region(self):
        same = [f for f in self.report.visible(show_all=True) if f.id == "/lab/app"]
        self.assertEqual([(f.status, f.region, f.in_scope) for f in same],
                         [("unmanaged", "us-west-2", False)])

    def test_raw_state_gives_the_same_result(self):
        stack = drift.load_source(self.raw_path)
        report = drift.evaluate([stack], self.inv)
        self.assertEqual({(x.status, x.id) for x in report.findings},
                         {(x.status, x.id) for x in self.report.findings})
        db = next(m for m in stack.resources if m.type == "aws_db_instance")
        self.assertEqual(db.secret_tags, {"Owner"})

    def test_changes_show_old_and_new_values(self):
        f = by_id(self.report.findings)
        vpc = f[self.ids["vpc"]]
        self.assertEqual([(c.setting, c.state, c.aws) for c in vpc.changes],
                         [("tag Owner", drift.NOT_SET, "console")])
        sg = f[self.ids["sg"]]
        self.assertEqual([(c.setting, c.state, c.aws) for c in sg.changes],
                         [("ingress rule", drift.NOT_THERE, "tcp 3389 from 0.0.0.0/0")])
        self.assertEqual(sg.detail, "aws_security_group.web: rules changed")
        db = f["lab-db"]
        self.assertEqual([(c.setting, c.state, c.aws) for c in db.changes],
                         [("tag Owner", drift.HIDDEN, drift.HIDDEN)])

    def test_children_cover_their_parents(self):
        # The SSH rule (its own resource), the route (aws_route), the role's attached policy
        # (aws_iam_role_policy_attachment) and bucket versioning all match, so the route
        # table, role and bucket aren't reported.
        sg = by_id(self.report.findings)[self.ids["sg"]]
        self.assertFalse(any("10.0.0.0/8" in c.aws or "10.0.0.0/8" in c.state for c in sg.changes))
        report = drift.evaluate([self._stack_without("aws_route", "aws_iam_role_policy_attachment",
                                                      "aws_vpc_security_group_ingress_rule")], self.inv)
        f = by_id(report.findings)
        self.assertEqual(f[self.ids["rt"]].changes[0].setting, "route 0.0.0.0/0")
        self.assertEqual(f[self.ids["rt"]].changes[0].aws, self.ids["igw"])
        self.assertEqual([(c.setting, c.aws) for c in f["lab-app"].changes],
                         [("attached policy", self.ids["policy"])])
        self.assertIn("tcp 22 from 10.0.0.0/8", [c.aws for c in f[self.ids["sg"]].changes])

    def _stack_without(self, *types):
        kept = [r for r in self.resources if r["type"] not in types]
        return drift.build_stack(show_json(kept), "partial", "", "state")

    # ---- what's left out
    def test_aws_made_things_are_left_out(self):
        ec2 = boto3.client("ec2", "us-east-1")
        default_vpc = [v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"] if v.get("IsDefault")][0]
        made = {default_vpc}
        made |= {s["SubnetId"] for s in ec2.describe_subnets()["Subnets"] if s.get("DefaultForAz")}
        made |= {g["GroupId"] for g in ec2.describe_security_groups()["SecurityGroups"]
                 if g["GroupName"] == "default"}
        made |= {n["NetworkAclId"] for n in ec2.describe_network_acls()["NetworkAcls"]
                 if n.get("IsDefault")}
        made |= {r["RouteTableId"] for r in ec2.describe_route_tables()["RouteTables"]
                 if any(a.get("Main") for a in r.get("Associations") or [])}
        self.assertGreater(len(made), 5)
        everything = {f.id for f in self.report.visible(show_all=True)}
        self.assertFalse(made & everything)
        self.assertNotIn("AWSServiceRoleForAutoScaling", everything)
        # The instance's root volume goes with the instance.
        self.assertFalse([f for f in self.report.findings if f.type == "aws_ebs_volume"])

    def test_cloudformation_tag(self):
        f = by_id(self.report.visible(show_all=True))[self.ids["cfn_queue"]]
        self.assertEqual(f.status, "other")
        self.assertEqual(f.label, "Managed by CloudFormation")
        self.assertEqual(f.detail, "stack my-stack")
        self.assertEqual(f.severity, "info")
        self.assertEqual(self.report.counts()["other"], 1)
        self.assertNotIn("1 not in Terraform, 0 gone", self.report.headline())

    def test_owner_tags(self):
        self.assertEqual(drift.owner_of({"aws:autoscaling:groupName": "web",
                                         "eks:nodegroup-name": "ng1"}), ("EKS", "node group ng1"))
        self.assertEqual(drift.owner_of({"elasticbeanstalk:environment-name": "env",
                                         "aws:cloudformation:stack-name": "awseb-x"}),
                         ("Elastic Beanstalk", "environment env"))
        self.assertEqual(drift.owner_of({"kubernetes.io/cluster/lab": "owned"}),
                         ("Kubernetes", "cluster lab"))
        self.assertEqual(drift.owner_of({"Name": "x"}), ("", ""))

    def test_ignore_list(self):
        everything = {f.id for f in self.report.visible(show_all=True)}
        self.assertNotIn("ignored-by-id", everything)
        self.assertNotIn(self.ids["tag_ignored"], everything)
        self.assertEqual(self.report.hidden, 2)
        # Addresses work too, for things that are gone or changed.
        report = drift.evaluate([self.stack], self.inv, ignore=["aws_sqs_queue.old"])
        self.assertNotIn("aws_sqs_queue.old", {f.address for f in report.findings})
        self.assertIn("ignored-by-id", {f.id for f in report.visible(True)})

    def test_settings_keep_other_config_keys(self):
        cfg = common.load_config()
        cfg["keep"] = ["i-keepme"]
        common.save_config(cfg)
        raw = json.loads(common.CONFIG_FILE.read_text(encoding="utf-8"))
        raw["secrets_scan"] = {"mode": "staged"}
        common.CONFIG_FILE.write_text(json.dumps(raw), encoding="utf-8")
        self.assertTrue(drift.save_settings({"ignore": ["tag:awskit:drift-ignore", "ignored-by-id"]}))
        raw = json.loads(common.CONFIG_FILE.read_text(encoding="utf-8"))
        self.assertEqual(raw["secrets_scan"], {"mode": "staged"})
        self.assertEqual(raw["keep"], ["i-keepme"])
        self.assertEqual(drift.load_settings()["ignore"], ["tag:awskit:drift-ignore", "ignored-by-id"])

    def test_only_types_and_regions_terraform_manages(self):
        shown = {f.id for f in self.report.visible()}
        everything = {f.id for f in self.report.visible(show_all=True)}
        west = f"https://sqs.us-west-2.amazonaws.com/{ACCOUNT}/west-queue"
        self.assertIn(west, everything)                       # a region the state doesn't use
        self.assertNotIn(west, shown)
        self.assertIn("console-repo", everything)             # a type the state doesn't use
        self.assertNotIn("console-repo", shown)
        self.assertIn("console-experiment", shown)            # both managed, so it's shown
        self.assertIn("/aws/lambda/console-fn", shown)
        lam = by_id(self.report.findings)["/aws/lambda/console-fn"]
        self.assertIn("Lambda makes this log group", lam.hint)
        self.assertGreaterEqual(self.report.elsewhere(), 2)
        self.assertIn("more in types or regions", self.report.subline())

    def test_headline(self):
        c = self.report.counts()
        self.assertEqual((c["gone"], c["changed"]), (2, 3))
        self.assertRegex(self.report.headline(), r"^Terraform manages 19 resources in 1 stack\. "
                                                 r"\d+ not in Terraform, 2 gone, 3 changed\.$")

    # ---- secrets
    def test_secrets_never_appear_anywhere(self):
        outputs = [f.detail_text() for f in self.report.findings]
        outputs += [json.dumps(f.as_dict()) for f in self.report.findings]
        outputs += [json.dumps(f.row()) for f in self.report.findings]
        outputs.append(drift.markdown_report(self.report, self.report.visible(True), True))
        outputs.append(drift.import_text(self.report.findings))
        outputs.append("\n".join(self.report.notes))
        for path in (self.show_path, self.raw_path):
            for args in ([], ["-v"], ["--json"], ["--all", "-v"]):
                code, out, err = run_cli(["drift", path, "-r", "us-east-1"] + args)
                outputs += [out, err]
            md = Path(TMP) / "drift-report.md"
            run_cli(["drift", path, "--markdown", str(md)])
            outputs.append(md.read_text(encoding="utf-8"))
        joined = "\n".join(outputs)
        for secret in SECRETS:
            self.assertNotIn(secret, joined)
        self.assertIn(drift.HIDDEN, joined)

    # ---- import blocks
    def test_import_blocks(self):
        text = drift.import_text(self.report.visible())
        self.assertIn('import {\n  to = aws_s3_bucket.console_experiment\n  id = "console-experiment"\n}',
                      text)
        names = re.findall(r"to = ([\w-]+)\.([\w-]+)", text)
        self.assertEqual(len(names), len(set(names)))
        for _, name in names:
            self.assertRegex(name, drift.TF_IDENT)

    def test_import_names_are_valid_and_unique(self):
        def unmanaged(name, ident):
            return drift.Finding("unmanaged", "aws_instance", ident, name)
        found = [unmanaged("My Web Server!!", "i-1"), unmanaged("my web server", "i-2"),
                 unmanaged("123abc", "i-3"), unmanaged("", "i-0abcdef1234567890"),
                 unmanaged("web", "i-5"), unmanaged("Ünïcode name", "i-6"),
                 unmanaged("../../etc", "i-7")]
        drift.assign_import_names(found, taken={("aws_instance", "web")})
        names = [f.import_name for f in found]
        self.assertEqual(len(names), len(set(names)))
        for n in names:
            self.assertRegex(n, drift.TF_IDENT)
        self.assertIn("web_2", names)
        self.assertIn("r_123abc", names)
        self.assertEqual(names[3], "instance_0abcdef12345")
        self.assertEqual(found[0].import_block,
                         'import {\n  to = aws_instance.%s\n  id = "i-1"\n}' % found[0].import_name)

    # ---- permissions
    def test_missing_permission_becomes_a_note(self):
        lt = drift.LIVE_TYPES["aws_vpc"]

        def no(scan, ctx, region):
            raise denied()
        with mock.patch.object(lt, "scan", no):
            inv = drift.read_account([self.stack], [None], ["us-east-1"])
        report = drift.evaluate([self.stack], inv)
        self.assertTrue(any("no permission to list VPCs" in n for n in report.notes), report.notes)
        self.assertTrue(any("VPCs couldn't be listed" in n for n in report.notes), report.notes)
        self.assertNotIn(self.ids["vpc"], {f.id for f in report.findings})  # not called gone
        self.assertIn("couldn't be checked", report.subline())

    def test_missing_tag_permission_becomes_a_note(self):
        import botocore.client
        original = botocore.client.BaseClient._make_api_call

        def fake(client, op, params):
            if op == "ListQueueTags":
                raise denied(op)
            return original(client, op, params)
        with mock.patch.object(botocore.client.BaseClient, "_make_api_call", fake):
            inv = drift.read_account([self.stack], [None], ["us-east-1"])
        self.assertTrue(any("no permission to read tags of SQS queues" in n for n in inv.notes),
                        inv.notes)
        report = drift.evaluate([self.stack], inv)
        # Without tags, the CloudFormation queue can't be told apart, but nothing breaks.
        self.assertIn(self.ids["cfn_queue"], {f.id for f in report.findings})

    def test_profile_that_cant_sign_in(self):
        inv = drift.read_account([self.stack], ["no-such-profile"], ["us-east-1"])
        self.assertFalse(inv.accounts)
        self.assertTrue(any("no-such-profile" in n for n in inv.notes))
        code, out, err = run_cli(["drift", self.show_path, "-p", "no-such-profile"])
        self.assertEqual(code, 1)
        self.assertIn("nothing was compared", err)

    def test_stopping(self):
        import threading
        stop = threading.Event()
        stop.set()
        inv = drift.read_account([self.stack], [None], ["us-east-1"], cancel=stop)
        report = drift.evaluate([self.stack], inv)
        self.assertFalse([f for f in report.findings if f.status == "gone"])
        self.assertTrue(any("Stopped" in n for n in report.notes))

    # ---- the command line
    def test_cli(self):
        code, out, err = run_cli(["drift", self.show_path, "-r", "us-east-1"])
        self.assertEqual(code, 0)
        self.assertIn("Terraform manages 19 resources in 1 stack.", out)
        self.assertIn("Gone", out)
        self.assertIn("Add --all", out)
        code, _, _ = run_cli(["drift", self.show_path, "-r", "us-east-1", "--fail-on-drift"])
        self.assertEqual(code, 2)
        code, out, _ = run_cli(["drift", self.show_path, "--json", "-r", "us-east-1"])
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["counts"]["gone"], 2)
        gone = [f for f in data["findings"] if f["state"] == "gone"]
        self.assertTrue(all(f["state_rm"].startswith("terraform state rm ") for f in gone))
        imports = Path(TMP) / "imports.tf"
        code, _, err = run_cli(["drift", self.show_path, "--imports", str(imports), "-q"])
        self.assertIn("import block", err)
        text = imports.read_text(encoding="utf-8")
        self.assertIn("to = aws_s3_bucket.console_experiment", text)
        self.assertNotIn("west-queue", text)             # elsewhere, unless --all
        run_cli(["drift", self.show_path, "--imports", str(imports), "--all", "-q",
                 "-r", "us-east-1", "-r", "us-west-2"])
        self.assertIn("west_queue", imports.read_text(encoding="utf-8"))

    def test_cli_clean_state(self):
        vpc = [r for r in self.resources if r["type"] == "aws_iam_user"]
        path = write_json("clean.json", show_json(vpc))
        code, out, _ = run_cli(["drift", path, "--fail-on-drift", "-q"])
        self.assertEqual(code, 0, out)
        self.assertIn("No drift found.", out)

    def test_cli_bad_input(self):
        bad = Path(TMP) / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        code, _, err = run_cli(["drift", str(bad)])
        self.assertEqual(code, 1)
        self.assertIn("isn't valid JSON", err)
        code, _, err = run_cli(["drift", str(Path(TMP) / "missing.tfstate")])
        self.assertEqual((code, "doesn't exist" in err), (1, True))
        binary = Path(TMP) / "plan.tfplan"
        binary.write_bytes(b"PK\x03\x04binary plan")
        code, _, err = run_cli(["drift", str(binary)])
        self.assertEqual(code, 1)
        self.assertIn("terraform show -json", err)
        code, _, err = run_cli(["drift", write_json("other.json", {"hello": "world"})])
        self.assertEqual(code, 1)
        self.assertIn("isn't a Terraform state or plan", err)
        with mock.patch("awskit.cli.stdin_has_data", return_value=False):
            code, _, err = run_cli(["drift"])
        self.assertEqual(code, 1)
        code, _, err = run_cli(["drift", self.show_path, "--exact"])
        self.assertEqual(code, 1)
        self.assertIn("only works for Terraform folders", err)


@unittest.skipIf(mock_aws is None, "boto3 and moto aren't installed")
class DriftTerraformTests(unittest.TestCase):
    """Folders, the exact check, and plan JSON, with Terraform itself faked."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ec2 = boto3.client("ec2", "us-east-1")
        self.vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
        self.state = show_json([
            res("aws_vpc", "main", {"id": self.vpc, "cidr_block": "10.9.0.0/16",
                                    "arn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/{self.vpc}",
                                    "tags": {}, "tags_all": {}}),
            res("aws_instance", "gone_by_my_check", {
                "id": "i-0aaaaaaaaaaaaaaaa", "instance_type": "t3.micro",
                "arn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0aaaaaaaaaaaaaaaa"}),
        ])
        self.folder = Path(tempfile.mkdtemp(prefix="drift-tf-", dir=TMP))
        (self.folder / "main.tf").write_text("# fake\n", encoding="utf-8")

    def tearDown(self):
        self.mock.stop()

    def refresh_plan(self):
        return {"format_version": "1.2", "terraform_version": "1.9.8", "planned_values": {},
                "resource_drift": [
                    {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main",
                     "change": {"actions": ["update"],
                                "before": {"id": self.vpc, "tags": {}, "enable_dns_support": True},
                                "after": {"id": self.vpc, "tags": {"Owner": "console"},
                                          "enable_dns_support": False},
                                "before_sensitive": {}, "after_sensitive": {}}},
                    {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
                     "name": "db",
                     "change": {"actions": ["update"],
                                "before": {"id": "db-x", "identifier": "lab-db", "password": "old-" + DB_PASSWORD,
                                           "instance_class": "db.t3.micro",
                                           "tags": {"Owner": SECRET_TAG}},
                                "after": {"id": "db-x", "identifier": "lab-db", "password": DB_PASSWORD,
                                          "instance_class": "db.t3.small",
                                          "tags": {"Owner": SECRET_TAG_NEW}},
                                "before_sensitive": {"password": True, "tags": {"Owner": True}},
                                "after_sensitive": {"password": True, "tags": {"Owner": True}}}},
                    {"address": "aws_lambda_function.fn", "mode": "managed",
                     "type": "aws_lambda_function", "name": "fn",
                     "change": {"actions": ["update"],
                                "before": {"function_name": "fn", "environment": [
                                    {"variables": {"API_KEY": "plain-" + USER_DATA}}]},
                                "after": {"function_name": "fn", "environment": [
                                    {"variables": {"API_KEY": USER_DATA}}]},
                                "before_sensitive": {}, "after_sensitive": {}}},
                    {"address": "aws_route.extra", "mode": "managed", "type": "aws_route",
                     "name": "extra",
                     "change": {"actions": ["delete"], "before": {"id": "r-rtb-1080289494"},
                                "after": None}},
                    {"address": "data.aws_ami.x", "mode": "data", "type": "aws_ami", "name": "x",
                     "change": {"actions": ["update"], "before": {}, "after": {}}},
                ]}

    def test_parse_drift_masks_secrets(self):
        entries = drift.parse_drift(self.refresh_plan())
        self.assertEqual([e["address"] for e in entries],
                         ["aws_vpc.main", "aws_db_instance.db", "aws_lambda_function.fn",
                          "aws_route.extra"])
        vpc = entries[0]["changes"]
        self.assertIn({"setting": "tag Owner", "state": drift.NOT_SET, "aws": "console"}, vpc)
        self.assertIn({"setting": "enable_dns_support", "state": "true", "aws": "false"}, vpc)
        text = json.dumps(entries)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        db = {c["setting"]: c for c in entries[1]["changes"]}
        self.assertEqual(db["password"]["aws"], drift.HIDDEN)
        self.assertEqual(db["tag Owner"]["state"], drift.HIDDEN)
        self.assertEqual(db["instance_class"]["aws"], "db.t3.small")
        self.assertEqual(entries[3]["action"], "delete")

    def test_folder_source_and_exact_check(self):
        calls = []

        def fake_plan(folder, extra_args=None, log=None, profile=None):
            calls.append(list(extra_args or []))
            return self.refresh_plan()
        with mock.patch("awskit.tfplan.terraform_bin", return_value="/usr/bin/terraform"), \
                mock.patch("awskit.tfplan.show_state", return_value=self.state) as show, \
                mock.patch("awskit.tfplan.plan_directory", side_effect=fake_plan):
            with self.assertRaises(drift.NeedsTerraform):
                drift.load_source(str(self.folder), run_terraform=False)
            self.assertFalse(show.called)
            code, out, err = run_cli(["drift", str(self.folder), "-v"])
            self.assertTrue(show.called)
            self.assertFalse(calls)                      # no plan without --exact
            self.assertIn("Gone", out)                   # Drift's own check: no such instance
            code, out, err = run_cli(["drift", str(self.folder), "--exact", "-v", "--all"])
        self.assertEqual(calls, [["-refresh-only"]])
        self.assertIn("Changed (from Terraform's refresh)", out)
        self.assertIn("Gone (from Terraform's refresh)", out)   # the route Drift doesn't read
        # Terraform's refresh found the instance, so Drift's own "gone" is dropped.
        self.assertNotIn("i-0aaaaaaaaaaaaaaaa", out)
        self.assertIn("enable_dns_support", out)
        self.assertIn(drift.NOT_SHOWN, out)              # Lambda environment
        for secret in SECRETS:
            self.assertNotIn(secret, out + err)

    def test_exact_check_failure_falls_back(self):
        from awskit import tfplan
        stack = drift.build_stack(self.state, "lab", str(self.folder), "folder")
        with mock.patch("awskit.tfplan.plan_directory",
                        side_effect=tfplan.PlanError("terraform plan failed:\nNo valid credential sources")):
            with self.assertRaises(drift.DriftError):
                drift.exact_check(self.folder)
        report, _ = drift.compare([stack], [None], ["us-east-1"],
                                  exact={"lab": "terraform plan failed: no credentials"})
        self.assertTrue(any("Exact check in lab didn't work" in n for n in report.notes))
        self.assertIn("i-0aaaaaaaaaaaaaaaa", {f.id for f in report.findings})

    def test_plan_json_input(self):
        plan = self.refresh_plan()
        plan["prior_state"] = self.state
        plan["resource_drift"] = [d for d in plan["resource_drift"] if d["type"] == "aws_instance"] + [
            {"address": "aws_instance.gone_by_my_check", "mode": "managed", "type": "aws_instance",
             "name": "gone_by_my_check",
             "change": {"actions": ["delete"], "before": {"id": "i-0aaaaaaaaaaaaaaaa"}, "after": None}}]
        stack = drift.load_source(write_json("plan.json", plan))
        self.assertEqual(stack.kind, "plan")
        report, _ = drift.compare([stack], [None], ["us-east-1"])
        f = by_id(report.findings)["i-0aaaaaaaaaaaaaaaa"]
        self.assertEqual((f.status, f.source), ("gone", "terraform"))
        self.assertEqual(f.label, "Gone (from Terraform's refresh)")

    def test_two_stacks_and_another_account(self):
        other = show_json([res("aws_vpc", "elsewhere", {
            "id": "vpc-0bbbbbbbbbbbbbbbb", "arn": "arn:aws:ec2:us-east-1:999999999999:vpc/vpc-0bbbbbbbbbbbbbbbb",
            "tags": {}})])
        a = drift.build_stack(self.state, "network", "", "state")
        b = drift.build_stack(other, "other-account", "", "state")
        report, _ = drift.compare([a, b], [None], ["us-east-1"])
        self.assertEqual(report.stacks, 2)
        self.assertTrue(any("account 999999999999" in n for n in report.notes), report.notes)
        self.assertNotIn("vpc-0bbbbbbbbbbbbbbbb", {f.id for f in report.findings})


PAGE_CHECK = r"""
import json, os, sys, tempfile
TMP = sys.argv[1]
os.environ.update({"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                   "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1",
                   "XDG_CONFIG_HOME": TMP, "AWS_CONFIG_FILE": os.path.join(TMP, "aws-config"),
                   "AWS_SHARED_CREDENTIALS_FILE": os.path.join(TMP, "aws-credentials")})
for name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL") or n in (
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CA_BUNDLE", "AWS_ROLE_ARN")]:
    os.environ.pop(name, None)
sys.path.insert(0, sys.argv[2])
import boto3
from moto import mock_aws
mock = mock_aws()
mock.start()
ec2 = boto3.client("ec2", "us-east-1")
vpc = ec2.create_vpc(CidrBlock="10.5.0.0/16")["Vpc"]["VpcId"]
boto3.client("s3", "us-east-1").create_bucket(Bucket="hand-made-bucket")
values = [
    {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main",
     "values": {"id": vpc, "arn": "arn:aws:ec2:us-east-1:123456789012:vpc/" + vpc,
                "tags": {}, "tags_all": {}}, "sensitive_values": {}},
    {"address": "aws_s3_bucket.old", "mode": "managed", "type": "aws_s3_bucket", "name": "old",
     "values": {"id": "deleted-bucket", "bucket": "deleted-bucket", "region": "us-east-1",
                "arn": "arn:aws:s3:::deleted-bucket", "tags": {}, "tags_all": {}},
     "sensitive_values": {}}]
good = os.path.join(TMP, "page-state.json")
with open(good, "w") as fh:
    json.dump({"format_version": "1.0", "values": {"root_module": {"resources": values}}}, fh)
bad = os.path.join(TMP, "page-bad.json")
with open(bad, "w") as fh:
    fh.write("{oops")

from gi.repository import GLib
from awskit import drift_page
from awskit.app import App
messages = []
drift_page.show_message = lambda win, heading, body="": messages.append(heading)
app = App(page="drift")
out = {}


def page():
    return app.get_active_window().pages["drift"]


def later(fn, ms=300):
    GLib.timeout_add(ms, lambda: fn() and False)


def wait(cond, then, tries=[0]):
    def check():
        tries[0] += 1
        if cond() or tries[0] > 200:
            then()
            return False
        return True
    GLib.timeout_add(100, check)


def start():
    page().add_file(bad)
    wait(lambda: messages, add_good)


def add_good():
    out["messages"] = list(messages)
    page().add_file(good)
    wait(lambda: page().sources, compare)


def compare():
    out["chip"] = page().sources[0]["stack"].label
    page().compare()
    wait(lambda: page().report is not None and page().compare_btn.get_sensitive(), compared)


def compared():
    p = page()
    out["headline"] = p.headline.get_text()
    out["rows"] = [(it.data["badge"], it.data["id"]) for it in p.table.visible_items()]
    p.tick_all()
    out["imports"] = p.import_mb.get_label()
    from awskit import drift
    out["import_text"] = drift.import_text(p.ticked())
    p.filter_dd.set_selected(2)  # Gone
    out["gone_rows"] = [it.data["id"] for it in p.table.visible_items()]
    p.filter_dd.set_selected(0)
    p.fill_ignore()
    p.ignore_view.get_buffer().set_text("hand-made-bucket")
    p.save_ignore()
    out["after_ignore"] = [it.data["id"] for it in p.table.visible_items()]
    out["hidden"] = p.report.hidden
    p.remove_source(p.sources[0])
    out["after_remove"] = p.headline.get_text()
    print(json.dumps(out), flush=True)
    app.quit()


app.connect("activate", lambda a: later(start, 500))
app.run([sys.argv[0]])
"""


class DriftPageTests(unittest.TestCase):
    """The Drift page itself, in a real GTK window under xvfb-run."""

    def test_page_flow(self):
        import shutil
        import subprocess
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        if mock_aws is None:
            self.skipTest("moto isn't installed")
        script = Path(tempfile.mkdtemp(prefix="drift-page-", dir=TMP))
        (script / "check.py").write_text(PAGE_CHECK, encoding="utf-8")
        cmd = [sys.executable, str(script / "check.py"), str(script), str(ROOT)]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                self.skipTest("no display and no xvfb-run")
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
        self.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
        got = json.loads(lines[-1])
        self.assertEqual(got["messages"], ["Couldn't read page-bad.json"])
        self.assertEqual(got["chip"], "page-state.json")
        self.assertEqual(got["headline"], "Terraform manages 2 resources in 1 stack. "
                                          "1 not in Terraform, 1 gone, 0 changed.")
        self.assertEqual(sorted(got["rows"]), [["Gone", "deleted-bucket"],
                                               ["Not in Terraform", "hand-made-bucket"]])
        self.assertEqual(got["imports"], "Import blocks (1)")
        self.assertIn("to = aws_s3_bucket.hand_made_bucket", got["import_text"])
        self.assertEqual(got["gone_rows"], ["deleted-bucket"])
        self.assertEqual(got["after_ignore"], ["deleted-bucket"])
        self.assertEqual(got["hidden"], 1)
        self.assertEqual(got["after_remove"], "No comparison yet.")


class DriftLogicTests(unittest.TestCase):
    """Pieces that don't need AWS."""

    def test_sqs_queue_urls_match_however_they_are_written(self):
        keys = {drift.match_key("aws_sqs_queue", x) for x in (
            f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/q1",
            f"https://queue.amazonaws.com/{ACCOUNT}/q1",
            f"arn:aws:sqs:us-east-1:{ACCOUNT}:q1")}
        self.assertEqual(keys, {f"{ACCOUNT}/q1"})

    def test_security_group_rules_normalize(self):
        tf = drift.rule_atoms("ingress", "6", "22", "22", ["10.0.0.5/8"], [], ["123456789012/sg-1"])
        live = drift.live_rule_atoms([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                       "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "x"}],
                                       "UserIdGroupPairs": [{"GroupId": "sg-1"}]}], "ingress")
        self.assertEqual(tf, live)
        everything = drift.rule_atoms("egress", "-1", 0, 0, ["0.0.0.0/0"])
        self.assertEqual(everything, drift.live_rule_atoms(
            [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "egress"))
        self.assertEqual(drift.atom_text(next(iter(everything))), "all traffic to 0.0.0.0/0")

    def test_trust_policies_compare_by_meaning(self):
        a = drift.norm_policy(json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": ["111122223333", "arn:aws:iam::444455556666:root"]},
            "Action": ["sts:AssumeRole"]}]}))
        b = drift.norm_policy({"Statement": {"Action": "sts:AssumeRole", "Principal": {"AWS": [
            "arn:aws:iam::444455556666:root", "arn:aws:iam::111122223333:root"]},
            "Effect": "Allow"}, "Version": "2012-10-17"})
        self.assertEqual(drift.policy_text(a), drift.policy_text(b))
        self.assertIsNone(drift.norm_policy("{nope"))
        self.assertIsNotNone(drift.norm_policy("%7B%22Version%22%3A%222012-10-17%22%7D"))

    def test_raw_sensitive_paths(self):
        marks = drift._path_marks([[{"type": "get_attr", "value": "password"}],
                                   [{"type": "get_attr", "value": "tags"},
                                    {"type": "index", "value": {"value": "Owner", "type": "string"}}],
                                   [{"type": "get_attr", "value": "ingress"},
                                    {"type": "index", "value": {"value": 0, "type": "number"}}]])
        self.assertEqual(marks, {"password": True, "tags": {"Owner": True}, "ingress": True})

    def test_unreadable_marks_hide_everything(self):
        state = show_json([res("aws_db_instance", "db", {"identifier": "x", "password": "p4ss",
                                                         "tags": {"Name": "db"}})])
        del state["values"]["root_module"]["resources"][0]["sensitive_values"]
        state["values"]["root_module"]["resources"][0]["sensitive_values"] = True
        st = drift.build_stack(state, "s", "", "state")
        self.assertEqual(st.resources, [])   # even the ID is treated as hidden
        self.assertEqual(st.unread["aws_db_instance"], 1)

    def test_import_blocks_escape_what_aws_returns(self):
        # Names (Name tags, KMS descriptions) and IDs come from the account, where anyone
        # who can tag something chooses them. They must stay inside the comment and the
        # quoted string, and never be read as a template.
        Finding = drift.Finding
        f = Finding("unmanaged", "aws_kms_key", "key-1", "line one\nMARKER_TWO\r\x1b[2K")
        g = Finding("unmanaged", "aws_iam_policy", 'a${MARKER}b%{x}c"d\\e\nf\x08g', "p")
        drift.assign_import_names([f, g])
        text = drift.import_text([f, g])
        lines = text.splitlines()
        self.assertFalse([x for x in lines if x.startswith("MARKER_TWO")], text)
        self.assertIn("# KMS key line one?MARKER_TWO??[2K", lines)
        self.assertIn('  id = "a$${MARKER}b%%{x}c\\"d\\\\e\\nf\\u0008g"', lines)
        self.assertNotIn("\x1b", text)
        # Every line is a comment, part of an import block, or empty.
        for line in lines:
            self.assertRegex(line, r'^(#.*|import \{|  to = [\w-]+\.[\w-]+|  id = ".*"|\}|)$')

    def test_rows_and_details_have_no_control_characters(self):
        f = drift.Finding("gone", "aws_vpc", "vpc-1\x1b[1A", "web\x1b]52;c;x\x07",
                          address='aws_vpc.this["a\x1b[2Kb"]', detail="d\x1b[8m", hint="h\nx")
        texts = [f.detail_text(), f.state_rm, json.dumps(f.row())]
        for text in texts:
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\\u001b", text)
            self.assertNotIn("\x07", text)
        self.assertEqual(f.state_rm, "terraform state rm 'aws_vpc.this[\"a?[2Kb\"]'")

    def test_missing_or_odd_marks_hide_values(self):
        def drift_entry(change):
            return {"resource_drift": [{"address": "aws_vpc.a", "mode": "managed",
                                        "type": "aws_vpc", "name": "a",
                                        "change": dict({"actions": ["update"],
                                                        "before": {"id": "vpc-1", "x": "old-value"},
                                                        "after": {"id": "vpc-1", "x": "new-value"}},
                                                       **change)}]}
        for marks in ({}, {"before_sensitive": "yes", "after_sensitive": [1]},
                      {"before_sensitive": {"x": "true"}, "after_sensitive": {"x": 1}}):
            text = json.dumps(drift.parse_drift(drift_entry(marks)))
            self.assertNotIn("old-value", text, marks)
            self.assertNotIn("new-value", text, marks)
        shown = drift.parse_drift(drift_entry({"before_sensitive": {}, "after_sensitive": False}))
        self.assertEqual(shown[0]["changes"][0]["aws"], "new-value")

        def one(sensitive, fmt="1.0", key="sensitive_values"):
            doc = show_json([res("aws_vpc", "a", {"id": "vpc-1", "tags": {"Name": "n"}})])
            doc["format_version"] = fmt
            r = doc["values"]["root_module"]["resources"][0]
            r.pop("sensitive_values")
            if sensitive is not None:
                r[key] = sensitive
            return drift.build_stack(doc, "s", "", "state")
        # A missing or odd sensitive_values hides everything, even the ID.
        for odd in (None, "yes", [True], 1):
            self.assertEqual(one(odd).resources, [], odd)
        # Terraform before 0.15 never wrote them, so there the values are read.
        self.assertEqual([m.id for m in one(None, fmt="0.1").resources], ["vpc-1"])
        raw = raw_state([res("aws_vpc", "a", {"id": "vpc-1"})])
        raw["resources"][0]["instances"][0]["sensitive_attributes"] = "id"
        self.assertEqual(drift.build_stack(raw, "s", "", "state").resources, [])

    def test_hostile_state_is_a_plain_error(self):
        deep = cur = {}
        for _ in range(1500):
            cur["x"] = {}
            cur = cur["x"]
        bad_types = res("aws_security_group", "a", {"id": "sg-1", "ingress": [
            {"protocol": "tcp", "cidr_blocks": 5}]})
        for doc in (show_json([res("aws_security_group", "a", {"id": "sg-1", "ingress": []},
                                   {"ingress": deep})]),
                    show_json([bad_types])):
            with self.assertRaisesRegex(drift.DriftError, "doesn't look like a Terraform state"):
                drift.build_stack(doc, "s", "", "state")

    def test_too_big_and_empty_inputs(self):
        path = write_json("big.json", show_json([]))
        with mock.patch.object(drift, "MAX_INPUT_BYTES", 10):
            with self.assertRaises(drift.DriftError):
                drift.load_source(path)
        empty = drift.load_source(write_json("empty.json", {"format_version": "1.0"}))
        self.assertEqual((empty.total, empty.resources), (0, []))
        raw_empty = drift.load_source(write_json("empty.tfstate", raw_state([])))
        self.assertEqual(raw_empty.total, 0)
        for doc in ([1, 2], {}, {"version": 4}):
            with self.assertRaisesRegex(drift.DriftError, "isn't a Terraform state or plan"):
                drift.load_source(write_json("other.json", doc))

    def test_region_and_account_guesses(self):
        st = drift.build_stack(show_json([
            res("aws_subnet", "a", {"id": "subnet-1", "availability_zone": "eu-west-1b",
                                    "owner_id": ACCOUNT}),
            res("aws_nat_gateway", "a", {"id": "nat-1", "subnet_id": "subnet-1"}),
            res("aws_eip", "a", {"id": "eipalloc-1", "allocation_id": "eipalloc-1"}),
            res("aws_iam_role", "r", {"id": "r", "name": "r"}),
        ]), "s", "", "state")
        got = {m.id: (m.region, m.account) for m in st.resources}
        self.assertEqual(got["subnet-1"], ("eu-west-1", ACCOUNT))
        self.assertEqual(got["nat-1"], ("eu-west-1", ACCOUNT))
        self.assertEqual(got["eipalloc-1"], ("eu-west-1", ACCOUNT))
        self.assertEqual(got["r"], ("global", ACCOUNT))

    def test_ignore_entries(self):
        ig = drift.IgnoreList(["i-1", "tag:team=red", "tag:skip", "# comment", ""])
        self.assertTrue(ig.matches(["i-1"]))
        self.assertTrue(ig.matches(["x"], {"team": "red"}))
        self.assertFalse(ig.matches(["x"], {"team": "blue"}))
        self.assertTrue(ig.matches(["x"], {"skip": ""}))
        self.assertFalse(ig.matches(["# comment"]))

    def test_help_stays_fast_and_lazy(self):
        # The command line imports drift for every command, so it must not pull in boto3
        # or the big Cloud Map modules just by being imported.
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); import awskit.drift; "
                "print('boto3' in sys.modules, 'awskit.maptf' in sys.modules, "
                "'awskit.mapmodel' in sys.modules)" % str(ROOT))
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             timeout=60).stdout.split()
        self.assertEqual(out, ["False", "False", "False"])


if __name__ == "__main__":
    unittest.main()
