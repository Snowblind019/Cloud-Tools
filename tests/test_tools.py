"""Tests for the AWS tools. AWS calls run against moto, so no real account is touched.

Run from the repo root:  python3 -m unittest discover -s tests -v
Needs: pip install boto3 "moto[ec2,s3,iam,rds,sts]"
"""
import json
import os
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
os.environ.pop("AWS_PROFILE", None)

from awskit import iampolicy, redact, tfplan  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None


def load_example(name):
    for folder in ("policy-check", "plan-check"):
        path = ROOT / folder / "examples" / name
        if path.exists():
            return path.read_text()
    raise FileNotFoundError(name)


class RedactTests(unittest.TestCase):
    def setUp(self):
        self.sample = (ROOT / "pii-redact" / "examples" / "sample.txt").read_text()

    def test_sample_redacts_ids_and_keeps_context(self):
        out, counts, ranges = redact.redact(self.sample, redact.Options())
        self.assertNotIn("123456789012", out)
        self.assertNotIn("54.201.33.17", out)
        self.assertNotIn("jane.doe@example.com", out)
        region, _, _ = redact.redact("arn:aws:ec2:us-west-2:123456789012:vpc/vpc-0a1b2c3d",
                                     redact.Options())
        self.assertIn("us-west-2", region)          # regions stay
        self.assertIn("10.20.1.25", out)            # private IPs stay by default
        self.assertIn("aws_instance.web", out)      # Terraform addresses stay
        self.assertEqual(sum(counts.values()), len(ranges))

    def test_numbered_keeps_same_value_same_number(self):
        text = "arn:aws:iam::111122223333:role/A and arn:aws:iam::111122223333:role/B"
        out, _, _ = redact.redact(text, redact.Options(numbered=True))
        self.assertEqual(out.count("[Redacted-AccountID-1]"), 2)

    def test_always_and_never_lists(self):
        opts = redact.Options(always=["snowcorp"], never=["123456789012"])
        out, _, _ = redact.redact("SnowCorp account 123456789012 and 210987654321", opts)
        self.assertNotIn("SnowCorp", out)
        self.assertIn("123456789012", out)
        self.assertNotIn("210987654321", out)

    def test_settings_carry_over_from_standalone_app(self):
        old = Path(TMP) / "pii-redact" / "config.json"
        old.parent.mkdir(parents=True, exist_ok=True)
        old.write_text(json.dumps({"numbered": True, "always_redact": ["snowcorp"]}))
        if redact.CONFIG_FILE.exists():
            redact.CONFIG_FILE.unlink()
        cfg = redact.load_config()
        self.assertTrue(cfg["numbered"])
        self.assertEqual(cfg["always_redact"], ["snowcorp"])

    def test_copy_redacted_helper_uses_engine(self):
        from awskit.common import pii_redact
        self.assertIn("[Redacted]", pii_redact("account 123456789012"))

    def test_command_line(self):
        import subprocess
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        r = subprocess.run([sys.executable, "-m", "awskit", "redact"], input="ip 54.201.33.17",
                           capture_output=True, text=True, env=env, cwd=ROOT)
        self.assertEqual(r.stdout, "ip [Redacted]")
        self.assertIn("Redacted 1", r.stderr)


class PolicyTests(unittest.TestCase):
    def titles(self, text, kind=None):
        doc, _ = iampolicy.load_policy(text)
        return {f.title for f in iampolicy.analyze(doc, kind)}

    def test_admin(self):
        t = self.titles('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}')
        self.assertIn("Full admin access", t)

    def test_tight_policy_is_clean(self):
        doc, _ = iampolicy.load_policy(load_example("tight-policy.json"))
        self.assertEqual(iampolicy.analyze(doc), [])

    def test_public_bucket_policy(self):
        doc, _ = iampolicy.load_policy(load_example("bucket-policy.json"))
        self.assertEqual(iampolicy.detect_kind(doc), "resource")
        sev = {f.title: f.severity for f in iampolicy.analyze(doc)}
        self.assertEqual(sev["Open to everyone"], "critical")

    def test_public_with_org_condition_is_info(self):
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}
        sev = {f.title: f.severity for f in iampolicy.analyze(doc)}
        self.assertEqual(sev.get("Public principal narrowed by a condition"), "info")

    def test_github_trust(self):
        doc, _ = iampolicy.load_policy(load_example("github-trust-policy.json"))
        self.assertEqual(iampolicy.detect_kind(doc), "trust")
        self.assertIn("GitHub OIDC repo check is loose", {f.title for f in iampolicy.analyze(doc)})

    def test_passrole_combo(self):
        t = self.titles(load_example("risky-policy.json"))
        self.assertIn("PassRole plus a service that runs as a role", t)
        self.assertIn("Can turn off security logging", t)

    def test_not_action(self):
        t = self.titles('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}')
        self.assertIn("Allow with NotAction", t)

    def test_unwraps_cli_output_and_boto_dicts(self):
        cli = {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}, "VersionId": "v1"}}
        doc, note = iampolicy.load_policy(json.dumps(cli))
        self.assertIn("Statement", doc)
        self.assertTrue(note)
        doc, _ = iampolicy.load_policy("{'Version': '2012-10-17', 'Statement': "
                                       "[{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}")
        self.assertEqual(doc["Version"], "2012-10-17")

    def test_bad_json_message(self):
        with self.assertRaises(iampolicy.PolicyError):
            iampolicy.load_policy('{"Statement": [')


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.summary = tfplan.summarize(json.loads(load_example("sample-plan.json")))

    def test_counts(self):
        self.assertEqual(self.summary.counts(),
                         {"create": 6, "update": 2, "replace": 1, "delete": 2, "forget": 0})

    def test_risks(self):
        titles = {(r.address, r.title) for r in self.summary.risks}
        self.assertIn(("aws_security_group.bastion", "Open to the internet: 22 SSH"), titles)
        self.assertIn(("aws_db_instance.app", "Database is publicly accessible"), titles)
        self.assertIn(("aws_iam_role.github_deploy", "GitHub OIDC trust without a repo check"), titles)
        self.assertIn(("aws_lambda_function_url.hook", "Lambda function URL has no auth"), titles)
        self.assertIn(("aws_cloudtrail.main", "Plan removes CloudTrail logging"), titles)
        self.assertIn(("aws_iam_role_policy_attachment.deploy_admin", "Attaches AdministratorAccess"), titles)
        self.assertEqual(self.summary.risks[0].severity, "critical")

    def test_replace_reason_and_drift(self):
        app = next(c for c in self.summary.changes if c.address == "aws_db_instance.app")
        self.assertEqual(app.forces, ["identifier"])
        self.assertEqual(self.summary.drift[0]["address"], "aws_security_group.legacy")

    def test_report_text(self):
        text = tfplan.report_text(self.summary)
        self.assertTrue(text.startswith("Plan: 6 to add, 2 to change, 1 to replace, 2 to destroy."))
        md = tfplan.report_text(self.summary, markdown=True)
        self.assertIn("## Things to look at", md)

    def test_unchanged_policy_not_reflagged(self):
        pol = json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        plan = {"format_version": "1.2", "resource_changes": [{
            "address": "aws_iam_policy.admin", "mode": "managed", "type": "aws_iam_policy",
            "change": {"actions": ["update"], "before": {"policy": pol, "description": "a"},
                       "after": {"policy": pol, "description": "b"}, "after_unknown": {}}}]}
        self.assertEqual(tfplan.summarize(plan).risks, [])


class ProfileTests(unittest.TestCase):
    def test_list_and_switch(self):
        from awskit import profiles
        Path(os.environ["AWS_CONFIG_FILE"]).write_text(
            "[default]\nregion = us-west-2\n\n"
            "[sso-session lab]\nsso_start_url = https://example.awsapps.com/start\nsso_region = us-west-2\n\n"
            "[profile lab-admin]\nsso_session = lab\nsso_account_id = 111111111111\n"
            "sso_role_name = AdministratorAccess\nregion = us-west-2\n\n"
            "[profile audit]\nrole_arn = arn:aws:iam::222222222222:role/Audit\nsource_profile = default\n")
        rows = {p["name"]: p for p in profiles.list_profiles()}
        self.assertEqual(rows["lab-admin"]["kind"], "sso")
        self.assertEqual(rows["lab-admin"]["sso_start_url"], "https://example.awsapps.com/start")
        self.assertEqual(rows["audit"]["account"], "222222222222")
        self.assertEqual(profiles.offline_status(rows["lab-admin"]), "not signed in")
        profiles.set_current_profile("lab-admin")
        self.assertEqual(profiles.current_profile(), "lab-admin")
        profiles.set_current_profile(None)
        self.assertIsNone(profiles.current_profile())
        self.assertIn("__awskit_sync", profiles.shell_hook("fish"))


@unittest.skipIf(mock_aws is None, "moto not installed")
class SweepAuditTests(unittest.TestCase):
    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        self.instance = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                                          TagSpecifications=[{"ResourceType": "instance", "Tags": [
                                              {"Key": "Name", "Value": "lab-box"}]}])["Instances"][0]["InstanceId"]
        self.kept = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                                      TagSpecifications=[{"ResourceType": "instance", "Tags": [
                                          {"Key": "awskit:keep", "Value": "yes"}]}])["Instances"][0]["InstanceId"]
        self.eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
        self.vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")["VolumeId"]
        vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        sg = ec2.create_security_group(GroupName="wide-open", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        self.sg = sg
        kms = boto3.client("kms", region_name="us-east-1")
        self.key = kms.create_key()["KeyMetadata"]["KeyId"]
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(Name="lab/db", SecretString="x")
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="awskit-test-bucket")

    def tearDown(self):
        self.mock.stop()

    def test_scan_finds_leftovers_and_respects_keep_tag(self):
        from awskit import sweep
        items, warnings = sweep.scan([None], regions=["us-east-1"])
        found = {(i.kind, i.id): i for i in items}
        self.assertIn(("ec2_instance", self.instance), found)
        self.assertIn(("elastic_ip", self.eip), found)
        self.assertIn(("ebs_volume", self.vol), found)
        self.assertIn(("kms_key", self.key), found)
        self.assertIn(("s3_bucket", "awskit-test-bucket"), found)
        self.assertTrue(any(k == "secret" for k, _ in found))
        self.assertTrue(found[("ec2_instance", self.kept)].kept)
        self.assertEqual(found[("ec2_instance", self.instance)].name, "lab-box")
        self.assertAlmostEqual(found[("ec2_instance", self.instance)].monthly, 0.0104 * 730, places=2)
        self.assertAlmostEqual(found[("ebs_volume", self.vol)].monthly, 1.6, places=2)
        self.assertGreater(sweep.total_monthly(items), 0)

    def test_teardown_deletes_selected_only(self):
        from awskit import sweep
        items, _ = sweep.scan([None], regions=["us-east-1"],
                              kinds=["ec2_instance", "elastic_ip", "ebs_volume", "kms_key", "s3_bucket"])
        dry = sweep.teardown(items, dry_run=True)
        self.assertTrue(all(msg in ("Would delete",) or not ok for _, ok, msg in dry))
        targets = [i for i in items if i.can_delete and not i.kept]
        results = sweep.teardown(targets)
        failed = [(i.kind, msg) for i, ok, msg in results if not ok]
        self.assertEqual(failed, [])
        ec2 = boto3.client("ec2", region_name="us-east-1")
        state = ec2.describe_instances(InstanceIds=[self.instance])["Reservations"][0]["Instances"][0]["State"]["Name"]
        self.assertIn(state, ("shutting-down", "terminated"))
        kept_state = ec2.describe_instances(InstanceIds=[self.kept])["Reservations"][0]["Instances"][0]["State"]["Name"]
        self.assertEqual(kept_state, "running")
        self.assertEqual(ec2.describe_addresses()["Addresses"], [])
        key = boto3.client("kms", region_name="us-east-1").describe_key(KeyId=self.key)["KeyMetadata"]
        self.assertEqual(key["KeyState"], "PendingDeletion")

    def test_audit_flags_open_ssh_and_iam(self):
        from awskit import audit
        findings, warnings = audit.audit([None], regions=["us-east-1"],
                                         checks=["open_sg", "ebs_encryption", "iam", "s3", "imds"])
        checks = {(f.check, f.resource) for f in findings}
        self.assertIn(("Open to the internet", self.sg), checks)
        self.assertIn(("Unencrypted EBS volume", self.vol), checks)
        self.assertTrue(any(f.check == "Root user has no MFA" for f in findings))
        self.assertEqual(findings, sorted(findings, key=lambda f: audit.SEVERITY_ORDER[f.severity]))


if __name__ == "__main__":
    unittest.main()
