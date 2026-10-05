"""Tests for the AWS tools. AWS calls run against moto, so no real account is touched.

Run from the repo root:  python3 -m unittest discover -s tests -v
Needs: pip install boto3 "moto[ec2,s3,iam,rds,sts,organizations,cloudtrail,budgets]"
The Image Redact tests need pycairo, and the end-to-end one also needs tesseract.
"""
import io
import json
import os
import shutil
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
        from unittest import mock
        from awskit import profiles
        # Never the real ~/.aws/sso/cache.
        patcher = mock.patch.object(profiles, "_sso_cache_dir", lambda: Path(TMP) / "sso-cache")
        patcher.start()
        self.addCleanup(patcher.stop)
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


try:
    import cairo
    from awskit import imageredact
except ImportError:  # pragma: no cover
    cairo = imageredact = None


def make_png(w, h, rgb=(1, 1, 1)):
    surface = cairo.ImageSurface(cairo.FORMAT_RGB24, w, h)
    cr = cairo.Context(surface)
    cr.set_source_rgb(*rgb)
    cr.paint()
    buf = io.BytesIO()
    surface.write_to_png(buf)
    return buf.getvalue()


def pixel(png, x, y):
    s = cairo.ImageSurface.create_from_png(io.BytesIO(png))
    s.flush()
    data = s.get_data()
    i = y * s.get_stride() + x * 4
    return data[i + 2], data[i + 1], data[i]


@unittest.skipIf(imageredact is None, "pycairo not installed")
class ImageRedactTests(unittest.TestCase):
    def word(self, text, left, top=10, height=14, line=1, cw=10):
        chars = [(left + i * cw, left + (i + 1) * cw) for i in range(len(text))]
        return imageredact.Word(text, left, top, len(text) * cw, height, 95, (0, line), chars)

    def test_find_spans_matches_redact(self):
        text = "arn:aws:iam::123456789012:user/jane.doe from 54.201.33.17"
        spans = redact.find_spans(text, redact.Options())
        out, counts, _ = redact.redact(text, redact.Options())
        self.assertEqual(len(spans), sum(counts.values()))
        self.assertEqual([text[s:e] for s, e, _ in spans],
                         ["123456789012", "jane.doe", "54.201.33.17"])

    def test_whole_word_box(self):
        words = [self.word("Account:", 10), self.word("123456789012", 100)]
        boxes = imageredact.find_boxes([words], redact.Options(), (400, 50))
        self.assertEqual(len(boxes), 1)
        x1, y1, x2, y2, label = boxes[0]
        self.assertEqual(label, "AccountID")
        self.assertLessEqual(x1, 100)
        self.assertGreaterEqual(x2, 220)
        self.assertGreater(x1, 90)  # "Account:" stays readable
        self.assertLessEqual(y1, 10)
        self.assertGreaterEqual(y2, 24)

    def test_part_of_a_word_uses_character_boxes(self):
        words = [self.word("arn:aws:iam::123456789012:user/jane", 0)]
        boxes = imageredact.find_boxes([words], redact.Options(), (600, 50))
        found = {b[4]: b for b in boxes}
        acct = found["AccountID"]
        self.assertLessEqual(acct[0], 130)
        self.assertGreaterEqual(acct[2], 250)
        self.assertGreaterEqual(acct[0], 110)  # "iam" stays readable
        self.assertLessEqual(acct[2], 270)     # "user" stays readable
        self.assertIn("IAMUser", found)

    def test_ocr_mixups_are_fixed(self):
        norm, index = imageredact.normalize('id = "1-0alb2c3d4e5f67890" acct 12345678901O')
        self.assertIn("i-0a1b2c3d4e5f67890", norm)
        self.assertIn("123456789010", norm)
        norm, _ = imageredact.normalize("arn:aws:iam: :123456789012:user/x")
        self.assertIn("iam::123456789012", norm)
        norm, _ = imageredact.normalize("export AWS SECRET ACCESS KEY=abc")
        self.assertIn("AWS_SECRET_ACCESS_KEY=", norm)
        self.assertEqual(len(index), len(imageredact.normalize('id = "1-0alb2c3d4e5f67890" '
                                                               'acct 12345678901O')[0]))

    def test_flatten_paints_boxes_into_pixels(self):
        png = make_png(100, 60)
        box = imageredact.cover_shape([20, 10, 60, 30, "AccountID"], (0, 0, 0, 1), auto=True)
        out = imageredact.encode(png, [box], ".png")
        self.assertEqual(pixel(out, 40, 20), (0, 0, 0))
        self.assertEqual(pixel(out, 80, 50), (255, 255, 255))
        self.assertNotIn(b"tEXt", out)
        self.assertNotIn(b"eXIf", out)
        jpg = imageredact.encode(png, [box], ".jpg")
        self.assertTrue(jpg.startswith(b"\xff\xd8"))

    def test_names(self):
        self.assertEqual(imageredact.default_name("/x/Screenshot 1.png"), "Screenshot 1-redacted.png")
        self.assertEqual(imageredact.default_name("/x/photo.JPG"), "photo-redacted.jpg")
        self.assertTrue(imageredact.default_name(None).startswith("redacted-"))
        self.assertEqual(imageredact.clean_name("shared", ".png"), "shared.png")
        self.assertEqual(imageredact.clean_name("a/b.jpg", ".png"), "a-b.jpg")
        self.assertEqual(imageredact.clean_name("notes.v2", ".png"), "notes.v2.png")
        with self.assertRaises(ValueError):
            imageredact.clean_name("  ", ".png")

    def test_rename_move_and_convert(self):
        folder = tempfile.mkdtemp(prefix="awskit-img-")
        try:
            first = os.path.join(folder, "a.png")
            imageredact.write_atomic(first, make_png(30, 20))
            renamed = imageredact.relocate(first, os.path.join(folder, "b.png"))
            self.assertFalse(os.path.exists(first))
            moved = imageredact.relocate(renamed, os.path.join(folder, "sub", "b.png"))
            self.assertTrue(os.path.exists(moved))
            converted = imageredact.relocate(moved, os.path.join(folder, "sub", "b.jpg"))
            with open(converted, "rb") as fh:
                self.assertTrue(fh.read(2) == b"\xff\xd8")
            self.assertFalse(os.path.exists(moved))
        finally:
            shutil.rmtree(folder)

    def test_command_line_saves_a_file(self):
        import subprocess
        folder = tempfile.mkdtemp(prefix="awskit-img-")
        try:
            src = os.path.join(folder, "shot.png")
            imageredact.write_atomic(src, make_png(40, 30))
            env = dict(os.environ, PYTHONPATH=str(ROOT), PATH="/nonexistent")
            r = subprocess.run([sys.executable, "-m", "awskit", "image", src, "-o", folder + "/"],
                               capture_output=True, text=True, env=env, cwd=ROOT)
            self.assertEqual(r.returncode, 1)          # no tesseract on that PATH
            self.assertIn("tesseract", r.stderr)
        finally:
            shutil.rmtree(folder)

    @unittest.skipUnless(shutil.which("tesseract"), "tesseract not installed")
    def test_finds_and_covers_text_in_a_screenshot(self):
        import gi
        gi.require_version("Pango", "1.0")
        gi.require_version("PangoCairo", "1.0")
        from gi.repository import Pango, PangoCairo
        text = 'Account: 123456789012\nOwner email: jane.doe@example.com\nRegion: us-west-2'
        for bg, fg in (((1, 1, 1), (0.1, 0.1, 0.1)), ((0.1, 0.1, 0.12), (0.88, 0.88, 0.9))):
            surface = cairo.ImageSurface(cairo.FORMAT_RGB24, 520, 110)
            cr = cairo.Context(surface)
            cr.set_source_rgb(*bg)
            cr.paint()
            layout = PangoCairo.create_layout(cr)
            layout.set_font_description(Pango.FontDescription.from_string("DejaVu Sans Mono 11"))
            layout.set_text(text, -1)
            cr.set_source_rgb(*fg)
            cr.move_to(12, 12)
            PangoCairo.show_layout(cr, layout)
            buf = io.BytesIO()
            surface.write_to_png(buf)
            boxes, _ = imageredact.detect(buf.getvalue())
            labels = {b[4] for b in boxes}
            self.assertIn("AccountID", labels)
            self.assertIn("Email", labels)

            def inside(sub):
                start = text.index(sub)
                pos = layout.index_to_pos(len(text[:start].encode()) + len(sub.encode()) // 2)
                x, y = 12 + pos.x / Pango.SCALE, 12 + pos.y / Pango.SCALE + 6
                return any(b[0] <= x <= b[2] and b[1] <= y <= b[3] for b in boxes)
            self.assertTrue(inside("123456789012"))
            self.assertTrue(inside("jane.doe@example.com"))
            self.assertFalse(inside("us-west-2"))


    def test_rounded_covers_still_cover_the_whole_rectangle(self):
        png = make_png(120, 80)
        box = imageredact.cover_shape([20, 20, 100, 60, "AccountID"], (0, 0, 0, 1), radius=20)
        out = imageredact.encode(png, [box], ".png")
        for x, y in ((20, 20), (99, 20), (99, 59), (20, 59), (60, 40)):
            self.assertEqual(pixel(out, x, y), (0, 0, 0), (x, y))
        self.assertEqual(pixel(out, 2, 2), (255, 255, 255))   # the rounding is still visible

    def test_text_without_pango(self):
        old = imageredact._measure.get("pango")
        imageredact._measure["pango"] = False   # how it runs on Windows
        try:
            w, h = imageredact.text_size("hello", 24)
            self.assertGreater(w, 30)
            self.assertGreater(h, 15)
            shape = {"kind": "text", "x": 5, "y": 5, "text": "hello", "size": 24,
                     "color": [1, 0, 0, 1], "width": 0, "fill": False}
            out = imageredact.encode(make_png(120, 50), [shape], ".png")
            reds = sum(1 for x in range(5, 80) for y in range(5, 35)
                       if pixel(out, x, y)[0] > 200 and pixel(out, x, y)[1] < 80)
            self.assertGreater(reds, 20)
        finally:
            if old is None:
                imageredact._measure.pop("pango", None)
            else:
                imageredact._measure["pango"] = old

    def test_opens_jpeg_with_pillow(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed")
        folder = tempfile.mkdtemp(prefix="awskit-img-")
        try:
            path = os.path.join(folder, "photo.jpg")
            Image.new("RGB", (40, 30), (200, 10, 10)).save(path, "JPEG")
            png = imageredact.load_image_bytes(path)
            self.assertTrue(png.startswith(b"\x89PNG"))
            self.assertEqual(imageredact.surface_from_png(png).get_width(), 40)
        finally:
            shutil.rmtree(folder)

    def test_windows_ocr_output_and_word_level_boxes(self):
        sample = ("0\t10\t20\t160\t24\tAccount:\n"
                  "0\t180\t20\t240\t24\t123456789012\n"
                  "1\t10\t60\t700\t24\tarn:aws:iam::123456789012:user/jane\n")
        words = imageredact.parse_windows_ocr(sample, 2.0, 0)
        self.assertEqual([w.text for w in words][:2], ["Account:", "123456789012"])
        self.assertEqual((words[1].left, words[1].width), (90.0, 120.0))
        boxes = imageredact.find_boxes([words], redact.Options(), (600, 100))
        acct = [b for b in boxes if b[4] == "AccountID"]
        self.assertEqual(len(acct), 2)
        # Without character boxes the ARN's account ID is estimated, with a wider margin.
        arn = max(acct, key=lambda b: b[1])
        cw = 350 / 35
        self.assertLessEqual(arn[0], 5 + 13 * cw)
        self.assertGreaterEqual(arn[2], 5 + 25 * cw)

    def test_powershell_errors_are_readable(self):
        clixml = ('#< CLIXML\n<Objs Version="1.1.0.1"><S S="Error">Add-Type : Cannot add type._x000D__x000A_</S>'
                  '<S S="Error">At line:4 char:1_x000D__x000A_</S><S S="Error">+ Add-Type x_x000D__x000A_</S></Objs>')
        self.assertEqual(imageredact.powershell_error(clixml), "Add-Type : Cannot add type.")


@unittest.skipIf(imageredact is None, "pycairo not installed")
class ImageEditorTests(unittest.TestCase):
    def setUp(self):
        from awskit import imageedit
        self.folder = tempfile.mkdtemp(prefix="awskit-edit-")
        self.ed = imageedit.Editor()
        self.ed.load(make_png(400, 300), os.path.join(self.folder, "shot.png"))

    def tearDown(self):
        shutil.rmtree(self.folder)

    def draw(self, tool, a, b):
        self.ed.set_tool(tool)
        self.ed.drag_begin(*a, 1.0)
        self.ed.drag_update(*b, False, 1.0)
        return self.ed.drag_end(1.0)

    def test_draw_move_resize_undo(self):
        ed = self.ed
        self.draw("cover", (10, 10), (110, 60))
        self.assertEqual(ed.shapes[-1]["kind"], "cover")
        self.assertTrue(ed.unsaved)
        self.draw("select", (50, 30), (70, 40))          # move it by 20, 10
        self.assertEqual((ed.shapes[-1]["x1"], ed.shapes[-1]["y1"]), (30, 20))
        self.draw("select", (130, 70), (150, 90))        # drag the bottom right corner
        self.assertEqual((ed.shapes[-1]["x2"], ed.shapes[-1]["y2"]), (150, 90))
        ed.undo()
        self.assertEqual((ed.shapes[-1]["x2"], ed.shapes[-1]["y2"]), (130, 70))
        ed.undo()
        ed.undo()
        self.assertEqual(ed.shapes, [])
        ed.redo()
        self.assertEqual(len(ed.shapes), 1)

    def test_text_request_and_commit(self):
        request = self.draw("text", (40, 40), (40, 40))
        self.assertEqual(request, ("new", (40, 40)))
        self.assertTrue(self.ed.commit_text(request, "hello"))
        self.assertEqual(self.ed.shapes[-1]["text"], "hello")

    def test_corners_follow_on_detected_boxes_only(self):
        ed = self.ed
        ed.shapes = [imageredact.cover_shape([10, 10, 50, 30, "Email"], (0, 0, 0, 1), auto=True)]
        self.draw("cover", (100, 100), (200, 150))       # one drawn by hand
        ed.set_tool("cover")
        self.assertTrue(ed.set_style(corners=9))
        self.assertEqual(ed.shapes[0]["radius"], 9.0)
        self.assertEqual(ed.shapes[1]["radius"], 0)
        self.assertEqual(ed.cfg["corners"], 9)
        self.draw("cover", (220, 100), (300, 150))
        self.assertEqual(ed.shapes[-1]["radius"], 9)
        ed.selected = ed.shapes[1]
        ed.set_style(corners=4)
        self.assertEqual(ed.shapes[1]["radius"], 4.0)
        self.assertEqual(ed.style()["corners"], 4.0)

    def test_rename_and_move_before_and_after_saving(self):
        ed = self.ed
        self.assertEqual(ed.name, "shot-redacted.png")
        self.assertEqual(ed.rename("shared").kind, "done")
        self.assertEqual(ed.target(), os.path.join(self.folder, "shared.png"))
        plan = ed.plan_save()
        self.assertEqual(ed.write(plan.dest).kind, "done")
        self.assertTrue(os.path.exists(os.path.join(self.folder, "shared.png")))
        self.assertEqual(ed.rename("final.jpg").kind, "done")
        self.assertTrue(os.path.exists(os.path.join(self.folder, "final.jpg")))
        other = os.path.join(self.folder, "other")
        os.makedirs(other)
        open(os.path.join(other, "final.jpg"), "wb").close()
        ask = ed.move_to(other)
        self.assertEqual(ask.kind, "ask")                 # something's already there
        self.assertEqual(ed.relocate(ask.dest, ask.message).kind, "done")
        self.assertEqual(ed.saved_path, os.path.join(other, "final.jpg"))
        self.assertFalse(os.path.exists(os.path.join(self.folder, "final.jpg")))
        self.assertIn(other, ed.cfg["recent_folders"])


class WindowsSupportTests(unittest.TestCase):
    """The Windows-only pieces that can be checked on any system."""

    def test_scheduled_task_is_valid_xml(self):
        import xml.etree.ElementTree as ET
        from awskit import cli
        xml = cli.windows_task_xml(r"C:\Users\a b\AppData\Local\AWSKit\venv\Scripts\pythonw.exe",
                                   '"C:\\x\\awskit.pyw" sweep --notify --quiet --profile "R&D"', "7:05")
        root = ET.fromstring(xml.split("?>", 1)[1])
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find(".//t:StartBoundary", ns).text, "2026-01-01T07:05:00")
        self.assertEqual(root.find(".//t:StartWhenAvailable", ns).text, "true")
        self.assertEqual(root.find(".//t:LogonType", ns).text, "InteractiveToken")
        self.assertIn('--profile "R&D"', root.find(".//t:Arguments", ns).text)
        self.assertTrue(root.find(".//t:Command", ns).text.endswith("pythonw.exe"))

    def test_powershell_hook_and_setup_lines(self):
        from awskit import profiles
        hook = profiles.shell_hook("powershell")
        self.assertIn("function global:awsp", hook)
        self.assertIn("APPDATA", hook)
        self.assertEqual(profiles.shell_hook("pwsh"), hook)
        self.assertEqual(profiles.shell_setup("powershell"),
                         ("awskit shell-init powershell | Out-String | Invoke-Expression", "$PROFILE"))
        self.assertEqual(profiles.shell_setup("bash"), ('eval "$(awskit shell-init bash)"', "~/.bashrc"))
        self.assertEqual(profiles.shell_setup("fish")[0], "awskit shell-init fish | source")
        with self.assertRaises(ValueError):
            profiles.shell_hook("tcsh")

    def test_shell_init_command_takes_powershell(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "awskit", "shell-init", "powershell"],
                           capture_output=True, text=True, cwd=ROOT,
                           env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("function global:__awskit_sync", r.stdout)

    def test_windows_launcher_needs_an_install(self):
        from awskit import cli
        self.assertIsNone(cli.windows_launcher())   # a plain checkout isn't an install

    def test_installer_scripts_are_ascii_with_windows_line_endings(self):
        # git gives these Windows line endings on checkout and in GitHub's Download ZIP,
        # because of .gitattributes. A patch applied with git apply can leave them plain.
        rules = (ROOT / ".gitattributes").read_text()
        self.assertIn("*.cmd text eol=crlf", rules)
        self.assertIn("*.ps1 text eol=crlf", rules)
        for name in ("install-windows.cmd", "windows/install.ps1", "windows/uninstall.ps1"):
            data = (ROOT / name).read_bytes()
            data.decode("ascii")                     # Windows PowerShell 5.1 reads these as ANSI
            self.assertNotIn(b"\r\r", data, name)


# =================================================================== Cloud Map

MAP_EXAMPLES = ROOT / "cloud-map" / "examples"


def map_snapshot(*names):
    from awskit import maptf
    return maptf.read([str(MAP_EXAMPLES / n) for n in names])


def map_export(snap, map_type="access", **kw):
    from awskit import cloudmap
    xml, lay = cloudmap.export(snap, map_type, **kw)
    return xml, lay


def drawio_cells(xml):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)
    cells = {}
    for obj in root.iter():
        if obj.tag in ("UserObject", "mxCell") and obj.get("id"):
            cell = obj if obj.tag == "mxCell" else obj.find("mxCell")
            cells[obj.get("id")] = (obj, cell)
    return root, cells


class CloudMapTests(unittest.TestCase):
    """Terraform input, the model, layout and the draw.io writer. No AWS needed."""

    def test_d1_example_builds_the_org(self):
        snap = map_snapshot("d1-org-state.json")
        org = snap.get("o-a1b2c3d4e5")
        self.assertEqual(org.caption, "FullAWSAccess on root")
        ou = snap.get("ou-ab12-wk7q2d9x")
        self.assertEqual(ou.parent, org.id)
        self.assertEqual(ou.caption, "SCPs: deny-leave-org, no-long-lived-keys, region-lock")
        lab, mgmt = snap.get("222222222222"), snap.get("111111111111")
        self.assertEqual(lab.parent, ou.id)
        self.assertTrue(mgmt.props["management"])
        self.assertEqual(lab.tags["Description"], "Every project deploys here")
        role = snap.get("arn:aws:iam::222222222222:role/gha-ephemeral-check")
        self.assertEqual(role.caption, "trusted by GitHub, Snowblind019/aws-platform, main only, read-only")
        self.assertEqual(role.props["category"], "ci")
        self.assertEqual(role.flags, [])
        glass = snap.get("arn:aws:iam::222222222222:role/OrganizationAccountAccessRole")
        self.assertTrue(glass.props["break_glass"])
        kinds = {(e.kind, e.src, e.dst) for e in snap.edges.values()}
        self.assertIn(("break-glass", "111111111111", glass.id), kinds)
        self.assertIn(("log-delivery", "222222222222",
                       "arn:aws:cloudtrail:us-west-2:111111111111:trail/org-trail"), kinds)
        self.assertEqual(snap.get("111111111111/cost").caption, "2 budgets, anomaly alerts")
        self.assertIn("arn:aws:s3:::snowy-lab-tfstate", [n.id for n in snap.children("222222222222")])

    def test_vpc_example_routes_and_public_subnets(self):
        snap = map_snapshot("two-az-vpc-state.json")
        pub = snap.get("subnet-0a1b2c3d4e5f60011")
        priv = snap.get("subnet-0a1b2c3d4e5f60021")
        self.assertTrue(pub.props["public"])
        self.assertFalse(priv.props["public"])
        self.assertEqual(pub.caption, "10.0.1.0/24, public, us-west-2a")
        routes = {(e.src, e.dst, e.label) for e in snap.edges.values() if e.kind == "route"}
        self.assertIn((pub.id, "igw-0a1b2c3d4e5f60031", "0.0.0.0/0"), routes)
        self.assertIn((priv.id, "nat-0a1b2c3d4e5f60041", "0.0.0.0/0"), routes)
        self.assertIn((priv.id, "vpce-0a1b2c3d4e5f60081", "S3 prefix list"), routes)
        self.assertEqual(snap.get("nat-0a1b2c3d4e5f60041").parent, pub.id)
        self.assertEqual(snap.get("arn:aws:rds:us-west-2:222222222222:db:lab-postgres").parent,
                         "subnet-0a1b2c3d4e5f60022")
        self.assertIn("Not drawn from Terraform: 1 aws_eip", snap.warnings)

    def test_ids_are_stable_aws_identifiers(self):
        a = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        b = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        self.assertEqual(sorted(a.nodes), sorted(b.nodes))
        for nid in ("111111111111", "o-a1b2c3d4e5", "vpc-0a1b2c3d4e5f60001",
                    "arn:aws:iam::222222222222:role/gha-ephemeral-check",
                    "arn:aws:s3:::snowy-org-cloudtrail-logs", "i-0a1b2c3d4e5f60093"):
            self.assertIn(nid, a.nodes)
        # the VPC state and the org state share the lab account, drawn once
        self.assertEqual(a.get("222222222222").name, "lab")

    def test_same_input_gives_byte_identical_files(self):
        from awskit import mapmodel
        a = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        b = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        self.assertEqual(a.dumps(), b.dumps())
        path = Path(TMP) / "round.cloudmap.json"
        a.save(path)
        loaded = mapmodel.Snapshot.load(path)
        self.assertEqual(loaded.dumps(), a.dumps())
        for map_type in ("access", "network", "combined"):
            for theme in ("dark", "light"):
                x1, _ = map_export(a, map_type, theme_name=theme, show={"routes", "sgs", "endpoints", "trust"})
                x2, _ = map_export(loaded, map_type, theme_name=theme, show={"routes", "sgs", "endpoints", "trust"})
                self.assertEqual(x1, x2, f"{map_type} {theme}")

    def test_drawio_is_well_formed_with_layers_and_metadata(self):
        snap = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        xml, lay = map_export(snap, "combined", show={"routes", "sgs", "endpoints", "trust"})
        root, cells = drawio_cells(xml)
        self.assertEqual(root.get("compressed"), "false")
        layers = {cid for cid, (obj, cell) in cells.items() if cell is not None and cell.get("parent") == "0"}
        self.assertEqual(layers, {"awskit-layer-base", "awskit-layer-routes", "awskit-layer-sgs",
                                  "awskit-layer-endpoints", "awskit-layer-trust",
                                  "awskit-layer-flags", "awskit-layer-legend"})
        for cid, (obj, cell) in cells.items():
            if cell is None:
                continue
            if cell.get("edge") == "1" and cell.get("source"):
                self.assertIn(cell.get("source"), cells, cid)
                self.assertIn(cell.get("target"), cells, cid)
            if cell.get("parent") not in (None, "0"):
                self.assertIn(cell.get("parent"), cells, cid)
        role = cells["arn:aws:iam::222222222222:role/gha-ephemeral-check"][0]
        self.assertEqual(role.tag, "UserObject")
        self.assertEqual(role.get("awskit"), "1")
        self.assertEqual(role.get("placeholders"), "1")
        self.assertEqual(role.get("kind"), "role")
        self.assertIn("Trusted by", role.get("tooltip"))
        self.assertEqual(cells["subnet-0a1b2c3d4e5f60011"][0].get("cidr"), "10.0.1.0/24")
        # detail shapes sit straight on their layer so the layer toggles them
        for gid in ("sg-0a1b2c3d4e5f60063", "vpce-0a1b2c3d4e5f60081"):
            parent = cells[gid][1].get("parent")
            self.assertIn(parent, ("awskit-layer-sgs", "awskit-layer-endpoints"))
        # route lines are on the Routes layer, trust lines on Trust paths
        route = [c for c in cells.values() if c[0].get("kind") == "route"]
        self.assertTrue(route and all(c[1].get("parent") == "awskit-layer-routes" for c in route))
        self.assertIn("Access through IAM Identity Center", xml)
        self.assertIn("Source: Terraform state", xml)

    def test_every_shape_is_a_real_drawio_shape(self):
        import re
        from awskit import mapdrawio, maplayout
        known = {line.strip() for line in (ROOT / "tests" / "drawio-aws4-shapes.txt").read_text().splitlines()
                 if line.startswith("mxgraph.")}
        for name in mapdrawio.all_shape_names() + list(mapdrawio.BASE_SHAPES):
            self.assertIn(name, known)
        drawn = maplayout.ACCESS_KINDS | maplayout.NETWORK_KINDS
        for kind in drawn - set(mapdrawio.GROUP_ICONS) - {"external", "az"}:
            self.assertIn(kind, mapdrawio.SHAPES, kind)
        snap = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        for map_type in ("access", "network", "combined"):
            xml, _ = map_export(snap, map_type, show={"routes", "sgs", "endpoints", "trust"})
            for shape in re.findall(r"(?:resIcon|grIcon|shape)=(mxgraph\.aws4\.[A-Za-z0-9_]+)", xml):
                self.assertIn(shape, known)

    def test_risky_trust_and_open_security_group_are_flagged(self):
        from awskit import mapmodel as mm
        snap = mm.Snapshot("terraform")
        mm.add_role(snap, "arn:aws:iam::111122223333:role/vendor", "vendor", trust={
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                    "Principal": {"AWS": "arn:aws:iam::999988887777:root"}}]})
        prov = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
        mm.add_oidc_provider(snap, prov, "token.actions.githubusercontent.com")
        mm.add_role(snap, "arn:aws:iam::111122223333:role/ci", "ci", trust={
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                                                    "Principal": {"Federated": prov},
                                                    "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:me/app:*"}}}]})
        mm.add_role(snap, "arn:aws:iam::111122223333:role/open", "open", trust={
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]})
        mm.add_vpc(snap, "vpc-1", "111122223333", "us-east-1", ["10.0.0.0/16"])
        mm.add_security_group(snap, "sg-1", "vpc-1", "ssh", ingress=[mm.rule("tcp", 22, 22, ["0.0.0.0/0"])])
        mm.add_security_group(snap, "sg-2", "vpc-1", "web", ingress=[mm.rule("tcp", 443, 443, ["0.0.0.0/0"])])
        mm.finish(snap)
        reasons = lambda n: " | ".join(f["reason"] for f in snap.get(n).flags)
        self.assertIn("999988887777", reasons("arn:aws:iam::111122223333:role/vendor"))
        self.assertIn("any branch of me/app", reasons("arn:aws:iam::111122223333:role/ci"))
        self.assertIn("audience", " ".join(f["reason"] for e in snap.edges.values() for f in e.flags))
        self.assertEqual(snap.get("arn:aws:iam::111122223333:role/open").flags[0]["severity"], "critical")
        self.assertIn("22 SSH", reasons("sg-1"))
        self.assertEqual(snap.get("sg-2").flags, [])       # web ports are normal
        outside = [e for e in snap.edges.values() if e.props.get("class") == "outside"][0]
        self.assertEqual(outside.flags[0]["severity"], "high")
        xml, lay = map_export(snap, "combined", show={"trust", "sgs"})
        root, cells = drawio_cells(xml)
        self.assertIn("sg-1#badge", cells)
        self.assertEqual(cells["sg-1#badge"][1].get("parent"), "awskit-layer-flags")
        self.assertIn(outside.id + "#flag", cells)
        self.assertIn("Security problem", xml)

    def test_redacted_export_leaks_nothing(self):
        import re
        snap = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        show = {"routes", "sgs", "endpoints", "trust"}
        xml, _ = map_export(snap, "combined", show=show, redacted=True)
        for secret in ("111111111111", "222222222222", "34.212.10.20", "34.212.10.30",
                       "aws-lab@example.com", "aws-mgmt@example.com", "snowy-org-cloudtrail-logs",
                       "snowy-lab-tfstate", "vpc-0a1b2c3d4e5f60001", "subnet-0a1b2c3d4e5f60011",
                       "o-a1b2c3d4e5", "ou-ab12-wk7q2d9x", "9067e1a2", "ps-1a2b3c4d5e6f7a8b"):
            self.assertNotIn(secret, xml, secret)
        root, cells = drawio_cells(xml)
        for cid, (obj, cell) in cells.items():
            if obj.get("awskit") == "1" and obj.get("role") is None:
                self.assertRegex(cid, r"^c[0-9a-f]{24}$")
        again, _ = map_export(snap, "combined", show=show, redacted=True)
        self.assertEqual(xml, again)                        # same key, same IDs
        self.assertTrue(re.search(r"\[Redacted", xml))

    def test_plan_with_unknown_values(self):
        from awskit import maptf
        plan = {
            "format_version": "1.2", "terraform_version": "1.9.8", "timestamp": "2026-10-01T10:00:00Z",
            "planned_values": {"root_module": {"resources": [
                {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main",
                 "values": {"cidr_block": "10.9.0.0/16", "tags": {"Name": "new"}}},
                {"address": "aws_subnet.a", "mode": "managed", "type": "aws_subnet", "name": "a",
                 "values": {"cidr_block": "10.9.1.0/24", "availability_zone": "us-east-2a"}},
                {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
                 "values": {"instance_type": "t3.micro", "metadata_options": [{"http_tokens": "required"}]}}]}},
            "resource_changes": [
                {"address": "aws_vpc.main", "change": {"actions": ["create"], "after_unknown": {"id": True, "arn": True}}},
                {"address": "aws_subnet.a", "change": {"actions": ["create"], "after_unknown": {"id": True, "vpc_id": True}}},
                {"address": "aws_instance.web", "change": {"actions": ["create"], "after_unknown": {"id": True, "subnet_id": True, "private_ip": True}}}],
            "configuration": {"provider_config": {"aws": {"name": "aws", "expressions": {
                "region": {"constant_value": "us-east-2"}, "allowed_account_ids": {"constant_value": ["444455556666"]}}}},
                "root_module": {"resources": [
                    {"address": "aws_vpc.main", "provider_config_key": "aws", "expressions": {}},
                    {"address": "aws_subnet.a", "provider_config_key": "aws", "expressions": {
                        "vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}},
                    {"address": "aws_instance.web", "provider_config_key": "aws", "expressions": {
                        "subnet_id": {"references": ["aws_subnet.a.id", "aws_subnet.a"]}}}]}}}
        snap = maptf.build(plan, "plan.json")
        self.assertIn("aws_vpc.main", snap.nodes)
        vpc = snap.get("aws_vpc.main")
        self.assertEqual((vpc.account, vpc.region), ("444455556666", "us-east-2"))
        self.assertEqual(snap.vpc_of(snap.get("aws_subnet.a")), "aws_vpc.main")
        web = snap.get("aws_instance.web")
        self.assertEqual(web.parent, "aws_subnet.a")
        self.assertIn("(known after apply)", web.caption)
        self.assertEqual(snap.scanned_at, "2026-10-01T10:00:00Z")

    def test_raw_tfstate_and_unmapped_types(self):
        from awskit import maptf
        raw = {"version": 4, "terraform_version": "1.9.8", "serial": 3, "lineage": "x", "resources": [
            {"mode": "managed", "type": "aws_vpc", "name": "main", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"attributes": {"id": "vpc-0abc", "cidr_block": "10.5.0.0/16",
                                           "arn": "arn:aws:ec2:eu-west-1:777788889999:vpc/vpc-0abc", "tags": {}}}]},
            {"mode": "managed", "type": "aws_subnet", "name": "s", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"index_key": 0, "attributes": {"id": "subnet-0abc", "vpc_id": "vpc-0abc",
                                                           "cidr_block": "10.5.1.0/24", "availability_zone": "eu-west-1a"}}]},
            {"mode": "managed", "type": "aws_kms_key", "name": "k", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"attributes": {"id": "k1"}}]}]}
        snap = maptf.build(raw, "terraform.tfstate")
        self.assertEqual(snap.get("vpc-0abc").parent, "777788889999/eu-west-1")
        self.assertEqual(snap.vpc_of(snap.get("subnet-0abc")), "vpc-0abc")
        self.assertIn("Not drawn from Terraform: 1 aws_kms_key", snap.warnings)

    def test_labels_and_collapsing(self):
        from awskit import mapmodel as mm
        snap = mm.Snapshot("terraform")
        mm.add_vpc(snap, "vpc-1", "111122223333", "us-east-1", ["10.0.0.0/16"], "lab")
        mm.add_subnet(snap, "subnet-1", "vpc-1", "us-east-1a", "10.0.1.0/24")
        for n in range(20):
            mm.add_instance(snap, f"i-{n:04d}", "subnet-1", "vpc-1", f"box-{n:02d}")
        mm.finish(snap)
        xml, lay = map_export(snap, "network", labels={"vpc-1": "Where the lab lives"})
        self.assertIn("Where the lab lives", xml)
        more = [b for b in lay.boxes if b.role == "more"]
        self.assertEqual(len(more), 1)
        self.assertEqual(more[0].title_lines, ["+8 more instances"])
        self.assertIn("box-19", json.dumps(more[0].tooltip))
        self.assertEqual(sum(1 for b in lay.boxes if b.kind == "instance" and b.role == "card"), 12)

    def test_layout_snaps_to_the_grid_and_text_fits(self):
        from awskit import maplayout
        snap = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        _, lay = map_export(snap, "combined", show={"routes", "sgs", "endpoints", "trust"})
        for b in lay.boxes:
            for v in (b.x, b.y, b.w, b.h):
                self.assertEqual(v % 10, 0, (b.id, v))
            if b.role == "card":
                for line in b.title_lines:
                    self.assertLessEqual(maplayout.text_width(line, 13, True), b.text[2] + 1)
                if b.icon:
                    self.assertGreaterEqual(b.text[0], b.icon[0] + b.icon[2])

    def test_command_line(self):
        import subprocess
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        snap = Path(TMP) / "cli.cloudmap.json"
        out = Path(TMP) / "cli.drawio"
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "tf",
                            str(MAP_EXAMPLES / "two-az-vpc-state.json"), "-o", str(snap)],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "export", str(snap), "--type",
                            "network", "--theme", "light", "--show", "all", "-o", str(out)],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("network map", r.stdout)
        self.assertIn("#FFFFFF", out.read_text())
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "export", str(snap), "--type",
                            "network", "--vpcs", "nope", "-o", str(out)],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 1)


# =================================================================== Cloud Map viewer

def encode_compact(root):
    """The reverse of mapicons.decode_compact, to test it: an XML stencil set packed the way
    draw.io 32's js/stencils.min.js packs it."""
    import base64
    import struct
    import zlib
    from awskit import mapicons
    ops, strings, names, attrs = bytearray(), [], [], []
    streams = [bytearray(), bytearray(), bytearray()]

    def varint(k, n):
        z = n * 2 if n >= 0 else -n * 2 - 1
        while True:
            b = z & 127
            z >>= 7
            streams[k].append(b | (128 if z else 0))
            if not z:
                break
    state = {"px": 0, "py": 0, "per": {}}

    def walk(el):
        if el.tag not in names:
            names.append(el.tag)
            strings.append(el.tag)
        leaf = len(el) == 0
        ops.append((names.index(el.tag) << 1) | (1 if leaf else 0))
        ops.append(len(el.attrib))
        if el.tag == "shape":
            state.update(px=0, py=0, per={})
        coords = el.tag in mapicons._DRAW
        for k, v in el.attrib.items():
            if k not in attrs:
                attrs.append(k)
                ops.append(len(attrs) - 1)
                strings.append(k)
            else:
                ops.append(attrs.index(k))
            try:
                num = round(float(v) * 1000)
                numeric = mapicons._fmt(num) == v
            except ValueError:
                numeric = False
            if not numeric:
                ops.append(0)
                strings.append(v)
            elif coords and k in mapicons._XS:
                ops.append(1)
                varint(0, num - state["px"])
                state["px"] = num
            elif coords and k in mapicons._YS:
                ops.append(1)
                varint(1, num - state["py"])
                state["py"] = num
            else:
                ops.append(1)
                key = el.tag + " " + k
                varint(2, num - state["per"].get(key, 0))
                state["per"][key] = num
        if not leaf:
            for child in el:
                walk(child)
            ops.append(255)
    walk(root)
    text = "\0".join(strings).encode("utf-8")
    parts = [bytes(ops)] + [bytes(s) for s in streams] + [text]
    data = struct.pack(">5I", *[len(p) for p in parts]) + b"".join(parts)
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(comp.compress(data) + comp.flush()).decode("ascii")


TINY_STENCILS = """<shapes name="mxgraph.aws4">
<shape name="Box Thing" w="40" h="20" aspect="fixed" strokewidth="inherit">
<connections/><foreground><path><move x="0" y="0"/><line x="40" y="0"/><line x="40" y="20"/>
<line x="0" y="20"/><close/></path><fill/></foreground></shape>
<shape name="arc thing" w="10" h="10" aspect="variable" strokewidth="1.5">
<foreground><path><move x="0" y="5"/><arc rx="5" ry="5" x-axis-rotation="0" large-arc-flag="1"
sweep-flag="1" x="10" y="5"/><curve x1="10" y1="7.25" x2="7.5" y2="10" x3="5" y3="10"/>
<close/></path><fillstroke/><fillcolor color="#FF0000"/><ellipse x="2" y="2" w="6" h="6"/>
<fill/></foreground></shape>
</shapes>"""


def fake_drawio(folder, packed=False, version="test"):
    """A draw.io folder with just enough in it for the icon loader."""
    from awskit.common import DRAWIO_MARKER
    folder = Path(folder)
    (folder / "js").mkdir(parents=True, exist_ok=True)
    (folder / "index.html").write_text("<html></html>")
    (folder / DRAWIO_MARKER).write_text(version)
    if packed:
        import xml.etree.ElementTree as ET
        blob = encode_compact(ET.fromstring(TINY_STENCILS))
        (folder / "js" / "stencils.min.js").write_text(
            "(function(){var f={};\nf['other.xml'] = 'AAAA';\nf['aws4.xml'] = '" + blob + "';\n})();")
    else:
        (folder / "stencils").mkdir(exist_ok=True)
        (folder / "stencils" / "aws4.xml").write_text(TINY_STENCILS)
    return folder


@unittest.skipIf(cairo is None, "pycairo not installed")
class CloudMapViewerTests(unittest.TestCase):
    """The renderer the viewer page, SVG and PNG share, the icons, hit testing and the
    draw.io download. None of it needs GTK."""

    @classmethod
    def setUpClass(cls):
        cls.both = map_snapshot("d1-org-state.json", "two-az-vpc-state.json")
        cls.show = {"routes", "sgs", "endpoints", "trust"}

    def layout(self, map_type="combined", **kw):
        from awskit import cloudmap
        return cloudmap.make_layout(self.both, map_type, show=self.show, **kw)

    def png_surface(self, png):
        return cairo.ImageSurface.create_from_png(io.BytesIO(png))

    def busy_fraction(self, surf, background):
        """How much of the picture isn't the page color, sampled on a grid."""
        surf.flush()
        data, stride = surf.get_data(), surf.get_stride()
        bg = tuple(int(background.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
        hits = total = 0
        for y in range(0, surf.get_height(), 7):
            for x in range(0, surf.get_width(), 7):
                i = y * stride + x * 4
                total += 1
                if abs(data[i + 2] - bg[0]) + abs(data[i + 1] - bg[1]) + abs(data[i] - bg[2]) > 24:
                    hits += 1
        return hits / max(total, 1)

    def test_examples_render_the_same_size_every_time_and_are_not_blank(self):
        import math
        from awskit import maprender, mapthemes
        cases = ((("d1-org-state.json",), "access"), (("two-az-vpc-state.json",), "network"),
                 (("d1-org-state.json", "two-az-vpc-state.json"), "combined"))
        from awskit import cloudmap
        for names, map_type in cases:
            snap = map_snapshot(*names)
            for theme in ("dark", "light"):
                lay = cloudmap.make_layout(snap, map_type, show=self.show)
                png = maprender.render_png(lay, theme, scale=1.0)
                surf = self.png_surface(png)
                self.assertEqual((surf.get_width(), surf.get_height()),
                                 (math.ceil(lay.width + 80), math.ceil(lay.height + 80)))
                busy = self.busy_fraction(surf, mapthemes.theme(theme)["page"])
                self.assertGreater(busy, 0.05, f"{map_type} {theme} looks blank ({busy:.2f})")
                again = maprender.render_png(lay, theme, scale=1.0)
                self.assertEqual(png, again, f"{map_type} {theme} isn't stable")
                big = self.png_surface(maprender.render_png(lay, theme, scale=2.0))
                self.assertEqual(big.get_width(), math.ceil((lay.width + 80) * 2))

    def test_svg_is_well_formed_and_a_redacted_one_leaks_nothing(self):
        import xml.etree.ElementTree as ET
        from awskit import cloudmap
        svg = cloudmap.render(self.layout(), "svg")
        root = ET.fromstring(svg)
        self.assertTrue(root.tag.endswith("svg"))
        self.assertTrue(root.get("width").startswith(str(self.layout().width + 80)))
        red = cloudmap.render(self.layout(redacted=True), "svg").decode("utf-8")
        ET.fromstring(red)
        self.assertNotIn("<text", red)        # text is drawn as shapes, so none can leak
        for secret in ("111111111111", "222222222222", "34.212.10.20", "aws-lab@example.com",
                       "snowy-org-cloudtrail-logs", "snowy-lab-tfstate", "vpc-0a1b2c3d4e5f60001",
                       "o-a1b2c3d4e5", "lab-bastion", "subnet-0a1b2c3d4e5f60011"):
            self.assertNotIn(secret, red, secret)

    def test_redacted_png_is_drawn_from_redacted_text(self):
        from awskit import cloudmap
        plain, red = self.layout(), self.layout(redacted=True)
        titles = " ".join(" ".join(b.title_lines + b.caption_lines) for b in red.boxes)
        self.assertNotIn("222222222222", titles)
        self.assertNotEqual(cloudmap.render(plain, "png"), cloudmap.render(red, "png"))

    def test_hit_testing_lands_on_the_right_box_at_any_zoom(self):
        from awskit import maprender
        lay = self.layout("network")
        scene = maprender.Scene(lay, "dark")
        cases = {
            "i-0a1b2c3d4e5f60093": (0.5, 0.5),           # a card inside a subnet
            "subnet-0a1b2c3d4e5f60011": (0.5, 0.08),     # the subnet's header, not its cards
            "vpc-0a1b2c3d4e5f60001": (0.3, 0.02),        # the VPC's own header
            "sg-0a1b2c3d4e5f60063": (0.5, 0.5),          # a card on the Security groups layer
        }
        for zoom in (0.15, 0.5, 1.0, 2.5, 6.0):
            vp = maprender.Viewport(zoom, ox=-37.5, oy=12.25)
            for box_id, (fx, fy) in cases.items():
                x, y, w, h = scene.rects[box_id]
                sx, sy = vp.to_screen(x + w * fx, y + h * fy)
                hit = scene.hit(*vp.to_page(sx, sy), tolerance=5 / zoom)
                self.assertEqual(hit, ("box", box_id), f"{box_id} at zoom {zoom}")
            link = next(lk for lk in lay.links if lk.kind == "route")
            (px, py), _ = maprender.point_at(scene.paths[link.id], 0.5)
            sx, sy = vp.to_screen(px + 2 / zoom, py)
            self.assertEqual(scene.hit(*vp.to_page(sx, sy), tolerance=5 / zoom), ("link", link.id))
            bx, by, bw, bh = scene.rects["i-0a1b2c3d4e5f60093"]
            sx, sy = vp.to_screen(bx + bw - 2, by + 2)
            self.assertEqual(scene.hit(*vp.to_page(sx, sy), tolerance=5 / zoom),
                             ("badge", "i-0a1b2c3d4e5f60093"))
        self.assertIsNone(scene.hit(-500, -500))

    def test_viewport_zooms_around_the_pointer_and_fits(self):
        from awskit import maprender
        vp = maprender.Viewport(1.0, 100, 50)
        before = vp.to_page(300, 200)
        vp.zoom_at(2.5, (300, 200))
        self.assertAlmostEqual(vp.to_page(300, 200)[0], before[0])
        self.assertAlmostEqual(vp.to_page(300, 200)[1], before[1])
        vp.zoom_at(1000, (0, 0))
        self.assertEqual(vp.zoom, vp.zoom_max)
        vp.fit(2000, 1000, 800, 600)
        self.assertAlmostEqual(vp.zoom, 0.392)
        self.assertAlmostEqual(vp.to_page(400, 300)[0], 1000)
        vp.fit(200, 100, 800, 600)
        self.assertEqual(vp.zoom, 1.0)                     # small maps aren't blown up

    def test_only_the_visible_area_is_drawn(self):
        from awskit import maprender
        scene = maprender.Scene(self.layout("network"), "dark")
        drawn = []
        for name in ("draw_box", "draw_link", "draw_flag", "draw_legend", "draw_text_block"):
            setattr(scene, name, lambda cr, obj, *a, n=name, **k: drawn.append((n, obj)))
        surf = cairo.ImageSurface(cairo.FORMAT_RGB24, 10, 10)
        scene.render(cairo.Context(surf), view=(-900, -900, -800, -800))
        self.assertEqual(drawn, [])
        x, y, w, h = scene.rects["i-0a1b2c3d4e5f60093"]
        scene.render(cairo.Context(surf), view=(x + 5, y + 5, x + 10, y + 10))
        ids = {getattr(obj, "id", None) for _, obj in drawn}
        self.assertIn("i-0a1b2c3d4e5f60093", ids)
        self.assertLess(len(drawn), len(scene.order) / 2)

    def test_stencil_set_reads_the_same_plain_or_packed(self):
        from awskit import mapicons
        folder = Path(tempfile.mkdtemp(prefix="awskit-icons-"))
        try:
            plain = mapicons.IconSet(fake_drawio(folder / "plain")).load()
            packed = mapicons.IconSet(fake_drawio(folder / "packed", packed=True)).load()
            self.assertEqual(plain.error, "")
            self.assertEqual(packed.error, "")
            self.assertEqual(sorted(plain.shapes), ["arc_thing", "box_thing"])
            for name in plain.shapes:
                self.assertEqual(plain.shapes[name].as_list(), packed.shapes[name].as_list())
            self.assertIsNotNone(plain.get("mxgraph.aws4.Box Thing"))
            # A second load comes from the cache file and gives the same shapes.
            again = mapicons.IconSet(folder / "packed").load()
            self.assertTrue((folder / "packed" / mapicons.CACHE_NAME).exists())
            self.assertEqual(again.shapes["arc_thing"].as_list(), packed.shapes["arc_thing"].as_list())
            surf = cairo.ImageSurface(cairo.FORMAT_RGB24, 40, 40)
            cr = cairo.Context(surf)
            mapicons.draw_stencil(cr, plain.get("box_thing"), 0, 0, 40, 40, fill="#00FF00")
            surf.flush()
            data, stride = surf.get_data(), surf.get_stride()
            self.assertEqual(tuple(data[20 * stride + 20 * 4: 20 * stride + 20 * 4 + 3]), (0, 255, 0))
            self.assertEqual(tuple(data[2 * stride + 20 * 4: 2 * stride + 20 * 4 + 3]), (0, 0, 0))
            mapicons.draw_stencil(cr, plain.get("arc_thing"), 0, 0, 40, 40, fill="#0000FF",
                                  stroke="#FFFFFF")
            missing = mapicons.IconSet(folder / "nothing-here").load()
            self.assertIn("isn't downloaded", missing.error)
        finally:
            shutil.rmtree(folder)

    def test_arcs_become_curves_that_end_where_they_should(self):
        from awskit import mapicons
        curves = mapicons.arc_to_curves(0, 5, 5, 5, 0, 1, 1, 10, 5)
        self.assertEqual(len(curves), 2)                      # a half circle in two parts
        self.assertAlmostEqual(curves[-1][4], 10)
        self.assertAlmostEqual(curves[-1][5], 5)
        self.assertLess(min(c[1] for c in curves), 1)         # it bulges up, to y=0

    def test_installed_drawio_has_every_icon_the_maps_use(self):
        from awskit import mapdrawio, mapicons
        from awskit.common import drawio_installed
        if not drawio_installed():
            self.skipTest("draw.io isn't downloaded here (awskit install fetches it)")
        from unittest import mock
        with mock.patch("awskit.common.write_atomic"):      # no cache file in the real install
            icons = mapicons.IconSet().load()
        self.assertEqual(icons.error, "")
        for name in set(mapdrawio.SHAPES.values()) | set(mapdrawio.GROUP_ICONS.values()):
            self.assertIn(name, icons, name)

    def test_maps_draw_without_icons(self):
        from awskit import mapicons, maprender
        none = mapicons.IconSet(Path(TMP) / "no-drawio").load()
        png = maprender.render_png(self.layout("network"), "light", scale=1.0, icons=none)
        self.assertGreater(self.busy_fraction(self.png_surface(png), "#FFFFFF"), 0.15)
        self.assertEqual(mapicons.abbreviation("instance"), "EC2")
        self.assertEqual(mapicons.abbreviation("mxgraph.aws4.group_vpc2"), "VPC")

    def test_command_line_writes_svg_and_png(self):
        import subprocess
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        snap = Path(TMP) / "viewer.cloudmap.json"
        self.both.save(snap)
        out_png = Path(TMP) / "viewer.png"
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "export", str(snap), "--type",
                            "network", "-o", str(out_png)], capture_output=True, text=True,
                           cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(out_png.read_bytes().startswith(b"\x89PNG"))
        out_svg = Path(TMP) / "viewer-redacted.svg"
        r = subprocess.run([sys.executable, "-m", "awskit", "map", "export", str(snap), "--format",
                            "svg", "--redact", "-o", str(out_svg)], capture_output=True, text=True,
                           cwd=ROOT, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("redacted", r.stdout)
        self.assertIn(b"<svg", out_svg.read_bytes()[:400])
        from awskit import cloudmap
        self.assertEqual(cloudmap.format_of("a.PNG"), "png")
        self.assertEqual(cloudmap.format_of("a.txt"), "drawio")
        self.assertEqual(cloudmap.format_of("a.png", "svg"), "svg")

    def test_drawio_download_is_checked_and_unpacked(self):
        import contextlib
        import hashlib
        import zipfile
        from unittest import mock
        from awskit import cli, common
        folder = Path(tempfile.mkdtemp(prefix="awskit-war-"))
        try:
            war = folder / "draw.war"
            with zipfile.ZipFile(war, "w") as zf:
                zf.writestr("index.html", "<html></html>")
                zf.writestr("js/app.min.js", "x")
                zf.writestr("js/app.min.js.map", "x")
                zf.writestr("WEB-INF/web.xml", "x")
                zf.writestr("META-INF/MANIFEST.MF", "x")
            sha = hashlib.sha256(war.read_bytes()).hexdigest()
            dest = folder / "drawio"
            quiet = contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())
            with mock.patch.object(common, "DRAWIO_SHA256", sha), quiet[0], quiet[1]:
                self.assertTrue(cli.install_drawio(str(war), dest))
            self.assertTrue((dest / "js" / "app.min.js").exists())
            self.assertFalse((dest / "js" / "app.min.js.map").exists())
            self.assertFalse((dest / "WEB-INF").exists())
            self.assertEqual(common.drawio_installed(dest), common.DRAWIO_VERSION)
            (dest / "keep-me").write_text("x")
            # A file that doesn't match the pinned SHA-256 changes nothing.
            quiet = contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())
            with mock.patch.object(common, "DRAWIO_SHA256", "0" * 64), quiet[0], quiet[1]:
                self.assertFalse(cli.install_drawio(str(war), dest))
            self.assertTrue((dest / "keep-me").exists())
            evil = folder / "evil.war"
            with zipfile.ZipFile(evil, "w") as zf:
                zf.writestr("index.html", "x")
                zf.writestr("../escape.txt", "x")
            with self.assertRaises(ValueError):
                cli.unpack_drawio(str(evil), folder / "other", "1")
            self.assertFalse((folder / "escape.txt").exists())
        finally:
            shutil.rmtree(folder)

    def test_page_settings_live_in_the_config(self):
        from awskit import common
        cfg = common.load_config()
        self.assertEqual(cfg["cloud_map"], {})
        cfg["cloud_map"] = {"map_type": "network", "theme": "light"}
        common.save_config(cfg)
        self.assertEqual(common.load_config()["cloud_map"]["theme"], "light")


def _memory_of(lay, map_type, pins=None):
    """A sidecar that remembers every box where a layout put it, as if the map had been
    saved in draw.io once, with pins {id: (dx, dy)} moved by hand."""
    from awskit import maplayoutmem
    memory = maplayoutmem.empty()
    sec = maplayoutmem.section(memory, map_type)
    for b in lay.boxes:
        holder = b.parent or b.hints.get("container", "")
        x, y = b.x, b.y
        if not b.parent and holder:
            c = lay.box(holder)
            x, y = b.ax - c.ax, b.ay - c.ay
        sec["nodes"][b.id] = {"parent": holder, "x": x, "y": y, "w": b.w, "h": b.h,
                              "pinned": False}
    for bid, (dx, dy) in (pins or {}).items():
        sec["nodes"][bid].update(x=sec["nodes"][bid]["x"] + dx, y=sec["nodes"][bid]["y"] + dy,
                                 pinned=True)
    return memory


def _overlapping(lay):
    """Pairs of sibling boxes that overlap."""
    from awskit import maplayoutmem
    groups = {}
    for b in lay.boxes:
        groups.setdefault((b.parent or b.hints.get("container", ""), b.layer == "base"), []).append(b)
    bad = []
    for group in groups.values():
        for i, a in enumerate(group):
            for c in group[i + 1:]:
                if maplayoutmem._overlaps((a.ax, a.ay, a.w, a.h), (c.ax, c.ay, c.w, c.h), 0):
                    bad.append((a.id, c.id))
    return bad


class CloudMapLayoutMemoryTests(unittest.TestCase):
    """Layout memory: reading a .drawio back after draw.io saved it, and applying it to
    the next export, the viewer and SVG and PNG. No GTK."""

    SHOW = {"routes", "sgs", "endpoints"}
    MOVED = "i-0a1b2c3d4e5f60093"          # the bastion, in public-a
    GONE = "i-0a1b2c3d4e5f60091"           # app-1, removed by the rescan
    NEW = "i-0fffffffffffff001"            # added by the rescan, next to the bastion

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="awskit-mem-"))
        self.snap = map_snapshot("two-az-vpc-state.json")
        self.snap_path = self.dir / "lab.cloudmap.json"
        self.snap.save(self.snap_path)
        self.labels = self.dir / "labels.json"

    def tearDown(self):
        shutil.rmtree(self.dir)

    def edit_like_drawio(self, xml, id_of=lambda x: x):
        """What draw.io does to a saved file: move a box, change a caption and a color,
        add a note. Then it writes the XML back out in its own formatting."""
        import re
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        model = root.find("diagram/mxGraphModel/root")
        cells = {el.get("id"): el for el in model}
        cell = cells[id_of(self.MOVED)].find("mxCell/mxGeometry")
        cell.set("y", str(float(cell.get("y")) + 120))
        sub = cells[id_of("subnet-0a1b2c3d4e5f60011")]
        sub.set("label", re.sub(r"10\.0\.1\.0/24, public, us-west-2a", "web tier", sub.get("label")))
        sg = cells[id_of("sg-0a1b2c3d4e5f60061")].find("mxCell")
        sg.set("style", re.sub(r"fillColor=[^;]*", "fillColor=#FF00FF", sg.get("style")))
        note = ET.SubElement(model, "mxCell", {"id": "my-note", "value": "Snowy's note",
                                                "style": "text;html=1;", "vertex": "1",
                                                "parent": id_of("subnet-0a1b2c3d4e5f60012")})
        ET.SubElement(note, "mxGeometry", {"x": "10", "y": "150", "width": "120", "height": "30",
                                            "as": "geometry"})
        ET.indent(root)
        return ET.tostring(root, encoding="unicode")

    def rescanned(self):
        from awskit import mapmodel as mm
        snap = mm.Snapshot.load(self.snap_path)
        snap.nodes.pop(self.GONE)
        for eid in [k for k, e in snap.edges.items() if self.GONE in (e.src, e.dst)]:
            snap.edges.pop(eid)
        mm.add_instance(snap, self.NEW, "subnet-0a1b2c3d4e5f60011", "vpc-0a1b2c3d4e5f60001",
                        name="new-box", instance_type="t3.micro", state="running")
        return snap

    def test_round_trip_keeps_what_was_changed_in_drawio(self):
        from awskit import cloudmap, maplayoutmem
        xml, lay = cloudmap.export(self.snap, "network", show=self.SHOW,
                                   snapshot_name=self.snap_path.name)
        before = lay.box(self.MOVED)
        drawio = self.dir / "lab-network.drawio"
        drawio.write_text(self.edit_like_drawio(xml))
        side = maplayoutmem.sidecar_path(self.snap_path)
        self.assertEqual(side.name, "lab.layout.json")
        got = maplayoutmem.remember(drawio, self.snap, side, labels_file=self.labels)
        self.assertEqual((got["moved"], got["styles"], got["captions"], got["extra"]), (1, 1, 1, 1))
        self.assertEqual(json.loads(self.labels.read_text())["subnet-0a1b2c3d4e5f60011"], "web tier")

        snap = self.rescanned()
        labels = maplayoutmem._read_labels(self.labels)
        lay2 = cloudmap.make_layout(snap, "network", show=self.SHOW, labels=labels,
                                    memory=cloudmap.memory_for(self.snap_path))
        moved = lay2.box(self.MOVED)
        self.assertEqual((moved.x, moved.y), (before.x, before.y + 120))   # stays put
        self.assertTrue(moved.hints.get("pinned"))
        self.assertIsNone(lay2.box(self.GONE))                             # gone
        new = lay2.box(self.NEW)
        self.assertEqual(new.parent, "subnet-0a1b2c3d4e5f60011")
        self.assertEqual(_overlapping(lay2), [])                           # no overlaps
        sub = lay2.box(new.parent)
        self.assertLessEqual(new.y + new.h, sub.h)                         # the subnet grew
        self.assertEqual(lay2.box("subnet-0a1b2c3d4e5f60011").caption_lines, ["web tier"])
        out = cloudmap.render(lay2, "drawio")
        self.assertIn("Snowy&apos;s note", out.replace("'", "&apos;"))   # the note survives
        self.assertIn("fillColor=#FF00FF", out)                           # and the color
        # The viewer, SVG and PNG draw the same: the note is in the scene.
        from awskit import maprender
        scene = maprender.Scene(lay2, "dark", icons=None)
        self.assertEqual([x.id for x in scene.extras], ["my-note"])
        sx, sy, _, _ = scene.extras[0].rect
        px, py, _, _ = scene.rects["subnet-0a1b2c3d4e5f60012"]
        self.assertEqual((sx, sy), (px + 10, py + 150))

    def test_a_file_saved_by_drawio_reads_back(self):
        """tests/cloudmap-edited-in-drawio.drawio was saved by the real draw.io editor
        through the bridge: the bastion moved down, a caption, two colors, a note and an
        arrow."""
        from awskit import cloudmap, maplayoutmem
        snap_path = self.dir / "two-az-vpc.cloudmap.json"
        self.snap.save(snap_path)
        drawio = self.dir / "two-az-vpc-network.drawio"
        shutil.copy(ROOT / "tests" / "cloudmap-edited-in-drawio.drawio", drawio)
        diagram, cells = maplayoutmem.read_cells(drawio.read_text())
        meta = maplayoutmem.meta_of(diagram, cells)
        self.assertEqual(meta["awskit_map"], "network")          # draw.io kept the metadata
        self.assertEqual(meta["awskit_snapshot"], "two-az-vpc.cloudmap.json")
        got = maplayoutmem.remember(drawio, self.snap, maplayoutmem.sidecar_path(snap_path),
                                    labels_file=self.labels)
        self.assertEqual((got["moved"], got["styles"], got["captions"], got["extra"]), (1, 2, 1, 2))
        sec = maplayoutmem.load(maplayoutmem.sidecar_path(snap_path))["maps"]["network"]
        self.assertEqual([k for k, v in sec["nodes"].items() if v["pinned"]], [self.MOVED])
        self.assertEqual(sec["nodes"][self.MOVED]["parent"], "subnet-0a1b2c3d4e5f60011")
        self.assertEqual(sec["styles"]["arn:aws:rds:us-west-2:222222222222:db:lab-postgres"],
                         {"fillColor": "#004488"})
        self.assertEqual(json.loads(self.labels.read_text())["subnet-0a1b2c3d4e5f60011"],
                         "web tier, keep it small")
        lay = cloudmap.make_layout(self.snap, "network", show=self.SHOW,
                                   memory=cloudmap.memory_for(snap_path))
        out = cloudmap.render(lay, "drawio")
        self.assertIn('id="snowy-note"', out)
        self.assertIn('id="snowy-arrow"', out)
        # The same command the page runs, from the command line.
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(cloudmap.main(["layout", str(snap_path), "--type", "network"]), 0)
        self.assertIn("1 moved by hand", printed.getvalue())

    def test_redacted_files_map_back_to_real_ids(self):
        from awskit import cloudmap, maplayoutmem
        xml, _ = cloudmap.export(self.snap, "network", show=self.SHOW, redacted=True,
                                 snapshot_name=self.snap_path.name)
        self.assertNotIn(self.snap_path.name, xml)              # no file name in a redacted file
        _, id_fn = cloudmap.redactors()
        drawio = self.dir / "redacted.drawio"
        drawio.write_text(self.edit_like_drawio(xml, id_fn))
        side = maplayoutmem.sidecar_path(self.snap_path)
        maplayoutmem.remember(drawio, self.snap, side, labels_file=self.labels)
        sec = maplayoutmem.load(side)["maps"]["network"]
        self.assertIn(self.MOVED, sec["nodes"])
        self.assertTrue(sec["nodes"][self.MOVED]["pinned"])
        self.assertTrue(all(not k.startswith("c") or ":" in k or "-" in k for k in sec["nodes"]))
        self.assertIn("fillColor", sec["styles"]["sg-0a1b2c3d4e5f60061"])
        self.assertEqual(sec["extra"][0].count("subnet-0a1b2c3d4e5f60012"), 1)  # real parent ID
        self.assertFalse(self.labels.exists())                  # no captions from redacted text
        # Applied to a plain export by real ID, and to a redacted one by hashed ID.
        plain = cloudmap.make_layout(self.snap, "network", show=self.SHOW,
                                     memory=cloudmap.memory_for(self.snap_path))
        self.assertTrue(plain.box(self.MOVED).hints.get("pinned"))
        red, _ = cloudmap.export(self.snap, "network", show=self.SHOW, redacted=True,
                                 memory=cloudmap.memory_for(self.snap_path))
        self.assertIn(id_fn("subnet-0a1b2c3d4e5f60012"), red)
        for secret in (self.MOVED, "subnet-0a1b2c3d4e5f60012", "222222222222", "lab.layout.json"):
            self.assertNotIn(secret, red)

    def test_rows_move_together_and_nothing_overlaps(self):
        from awskit import cloudmap
        for names, map_type, show in ((("two-az-vpc-state.json",), "network", self.SHOW),
                                      (("d1-org-state.json", "two-az-vpc-state.json"), "combined",
                                       {"routes", "sgs", "endpoints", "trust"}),
                                      (("d1-org-state.json",), "access", None)):
            snap = map_snapshot(*names)
            base = cloudmap.make_layout(snap, map_type, show=show)
            cards = [b for b in base.boxes if b.role not in ("container", "chip")]
            for n, pick in enumerate((cards[:3], cards[-3:], cards[::4])):
                memory = _memory_of(base, map_type, {b.id: (0, 80 + 40 * n) for b in pick})
                lay = cloudmap.make_layout(snap, map_type, show=show, memory=memory)
                self.assertEqual(_overlapping(lay), [], f"{names} {n}")
                for b in pick:
                    # Pinned boxes stay where they were put in their container (a VPC's
                    # detail cards go along with the VPC).
                    got, rec = lay.box(b.id), memory["maps"][map_type]["nodes"][b.id]
                    holder = lay.box(rec["parent"]) if rec["parent"] else None
                    rel = (got.ax - holder.ax, got.ay - holder.ay) if holder else (got.ax, got.ay)
                    self.assertEqual(rel, (rec["x"], rec["y"]), b.id)
        # A pinned app-2 pushes the database down, private-b and its zone grow, and the
        # VPC endpoints below stay in one row.
        base = cloudmap.make_layout(self.snap, "network", show=self.SHOW)
        lay = cloudmap.make_layout(self.snap, "network", show=self.SHOW,
                                   memory=_memory_of(base, "network", {"i-0a1b2c3d4e5f60092": (0, 100)}))
        s3, ssm = lay.box("vpce-0a1b2c3d4e5f60081"), lay.box("vpce-0a1b2c3d4e5f60082")
        self.assertEqual(s3.ay, ssm.ay)
        self.assertGreater(s3.ay, base.box("vpce-0a1b2c3d4e5f60081").ay)

    def test_tidy_up_and_reset(self):
        from awskit import cloudmap, maplayoutmem
        base = cloudmap.make_layout(self.snap, "network")
        side = maplayoutmem.sidecar_path(self.snap_path)
        memory = _memory_of(base, "network", {self.MOVED: (0, 100)})
        maplayoutmem.save(memory, side)
        self.assertEqual(maplayoutmem.tidy(memory, "network"), len(base.boxes) - 1)
        self.assertEqual(list(memory["maps"]["network"]["nodes"]), [self.MOVED])
        maplayoutmem.save(memory, side)
        lay = cloudmap.make_layout(self.snap, "network", memory=cloudmap.memory_for(self.snap_path))
        self.assertEqual(lay.box(self.MOVED).y, base.box(self.MOVED).y + 100)
        self.assertTrue(maplayoutmem.reset_file(side, "network"))
        self.assertFalse(side.exists())                          # nothing left in it
        lay = cloudmap.make_layout(self.snap, "network", memory=cloudmap.memory_for(self.snap_path))
        self.assertEqual(lay.box(self.MOVED).y, base.box(self.MOVED).y)

    def test_working_file_changed_outside_is_pulled_in_first(self):
        from awskit import cloudmap, maplayoutmem
        path, lay, pulled = cloudmap.prepare_edit(self.snap, self.snap_path, "network",
                                                  labels={}, show=self.SHOW)
        self.assertEqual(path, self.dir / "lab-network.drawio")
        self.assertIsNone(pulled)
        memory = maplayoutmem.load(maplayoutmem.sidecar_path(self.snap_path))
        self.assertFalse(maplayoutmem.changed_outside(memory, "network", path))
        # draw.io desktop saves it
        path.write_text(self.edit_like_drawio(path.read_text()))
        self.assertTrue(maplayoutmem.changed_outside(memory, "network", path))
        path2, lay2, pulled = cloudmap.prepare_edit(self.snap, self.snap_path, "network",
                                                    labels={}, show=self.SHOW)
        self.assertEqual(pulled["moved"], 1)
        self.assertEqual(lay2.box(self.MOVED).y, lay.box(self.MOVED).y + 120)
        self.assertIn("Snowy", path2.read_text())                # rewritten with the layout
        memory = maplayoutmem.load(maplayoutmem.sidecar_path(self.snap_path))
        self.assertFalse(maplayoutmem.changed_outside(memory, "network", path2))

    def test_drawn_shapes_and_style_changes_render(self):
        from awskit import maprender
        lay = map_export(self.snap, "network")[1]
        lay.extra = [
            '<mxCell id="n1" value="Hello &lt;b&gt;there&lt;/b&gt;" style="rounded=1;whiteSpace=wrap;'
            'html=1;fillColor=#00FF00;" vertex="1" parent="awskit-layer-base">'
            '<mxGeometry x="60" y="60" width="120" height="40" as="geometry"/></mxCell>',
            '<mxCell id="e1" style="endArrow=classic;html=1;strokeColor=#FF0000;" edge="1" '
            'parent="awskit-layer-base" source="n1" target="i-0a1b2c3d4e5f60093">'
            '<mxGeometry relative="1" as="geometry"/></mxCell>',
            '<mxCell id="broken" vertex="1" parent="awskit-layer-base">not xml',
        ]
        lay.box(self.MOVED).hints["style"] = {"fillColor": "#0000FF"}
        scene = maprender.Scene(lay, "dark", icons=None)
        self.assertEqual(sorted(x.id for x in scene.extras), ["e1", "n1"])
        self.assertEqual(maprender.label_lines("Hello <b>there</b><br>again"), ["Hello there", "again"])
        if cairo is None:
            return
        surf = cairo.ImageSurface(cairo.FORMAT_RGB24, int(scene.width), int(scene.height))
        scene.render(cairo.Context(surf), vector=True)
        surf.flush()
        data, stride = surf.get_data(), surf.get_stride()

        def px(x, y):
            i = int(y) * stride + int(x) * 4
            return (data[i + 2], data[i + 1], data[i])
        self.assertEqual(px(100, 64), (0, 255, 0))               # the green note
        bx, by, bw, bh = scene.rects[self.MOVED]
        self.assertEqual(px(bx + bw - 6, by + bh - 6), (0, 0, 255))   # the recolored card


class CloudMapBridgeTests(unittest.TestCase):
    """The local server between draw.io and AWS Kit, over real HTTP."""

    def setUp(self):
        from awskit import mapeditor
        self.dir = Path(tempfile.mkdtemp(prefix="awskit-bridge-"))
        self.drawio = fake_drawio(self.dir / "drawio")
        (self.drawio / "js" / "PreConfig.js").write_text("window.mxBasePath = 'mxgraph';\n")
        (self.drawio / "js" / "app.min.js").write_text("var App = {};")
        (self.drawio / "service-worker.js").write_text("self.x = 1;")
        (self.dir / "secret.txt").write_text("not for the page")
        self.file = self.dir / "map.drawio"
        self.file.write_text('<mxfile><diagram id="awskit-access"><mxGraphModel><root>'
                             '<mxCell id="0"/></root></mxGraphModel></diagram></mxfile>')
        self.saved, self.exits = [], []
        self.bridge = mapeditor.Bridge(self.file, drawio=self.drawio, theme="light",
                                       on_save=self.saved.append, on_exit=self.exits.append,
                                       idle_timeout=0)
        self.url = self.bridge.start()

    def tearDown(self):
        self.bridge.stop()
        shutil.rmtree(self.dir)

    def request(self, path, body=None, host=None, token=None):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.bridge.port, timeout=5)
        headers = {"Host": host or f"127.0.0.1:{self.bridge.port}"}
        if body is not None:
            headers["Content-Type"] = "application/xml"
        conn.request("POST" if body is not None else "GET",
                     f"/{token or self.bridge.token}/{path}", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def test_serves_the_page_and_the_file_with_the_token(self):
        self.assertTrue(self.url.startswith(f"http://127.0.0.1:{self.bridge.port}/"))
        self.assertEqual(self.bridge.server.server_address[0], "127.0.0.1")
        code, headers, body = self.request("")
        self.assertEqual(code, 200)
        page = body.decode()
        self.assertIn("embed=1", page)
        self.assertIn("proto=json", page)
        self.assertIn("lockdown=1", page)
        self.assertIn("dark=0", page)                            # the light theme
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("https:", headers["Content-Security-Policy"])
        code, _, body = self.request("file")
        self.assertEqual((code, body), (200, self.file.read_bytes()))
        code, _, body = self.request("drawio/js/app.min.js")
        self.assertEqual((code, body), (200, b"var App = {};"))
        code, _, body = self.request("drawio/js/PreConfig.js")
        self.assertIn(b"mxBasePath", body)                       # draw.io's own, plus ours
        self.assertIn(b"window.DRAWIO_CONFIG", body)
        self.assertIn(b'"defaultVertexStyle"', body)
        code, _, body = self.request("config")
        self.assertFalse(json.loads(body)["compressXml"])

    def test_refuses_wrong_tokens_hosts_and_paths(self):
        self.assertEqual(self.request("file", token="nope")[0], 403)
        self.assertEqual(self.request("", token=self.bridge.token[:-1] + "x")[0], 403)
        self.assertEqual(self.request("file", host="evil.example:80")[0], 403)
        for path in ("drawio/../secret.txt", "drawio/%2e%2e/secret.txt", "drawio/..%2fsecret.txt",
                     "drawio//etc/passwd", "drawio/js/../../secret.txt", "../secret.txt",
                     "drawio/service-worker.js", "drawio/\\..\\secret.txt", "drawio/js"):
            code, _, body = self.request(path)
            self.assertIn(code, (403, 404), path)
            self.assertNotIn(b"not for the page", body, path)
        self.assertEqual(self.request("save", body="x", token="nope")[0], 403)
        self.assertEqual(self.saved, [])

    def test_save_writes_the_file_and_exit_shuts_down(self):
        import http.client
        import time
        xml = '<mxfile><diagram id="x"><mxGraphModel><root/></mxGraphModel></diagram></mxfile>'
        code, _, body = self.request("save", body=xml)
        self.assertEqual(code, 200, body)
        self.assertEqual(self.file.read_text(), xml)
        self.assertEqual(self.saved, [self.file])
        self.assertEqual(self.request("save", body="not a diagram")[0], 400)
        self.assertEqual(self.file.read_text(), xml)             # a bad save changes nothing
        self.assertEqual(sorted(p.name for p in self.dir.iterdir() if "tmp" in p.name), [])
        code, _, _ = self.request("exit", body='{"saved": true}')
        self.assertEqual(code, 200)
        for _ in range(50):
            if self.exits:
                break
            time.sleep(0.02)
        self.assertEqual(self.exits, [{"saved": True, "reason": "exit"}])
        port = int(self.url.split(":")[2].split("/")[0])
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                conn.request("GET", "/")
                conn.getresponse()
                conn.close()
            except OSError:
                break
            time.sleep(0.05)
        else:
            self.fail("the bridge is still answering after exit")

    def test_a_closed_browser_window_ends_the_session(self):
        import time
        from awskit import mapeditor
        exits = []
        b = mapeditor.Bridge(self.file, drawio=self.drawio, on_exit=exits.append, idle_timeout=1.0)
        b.start()
        b.loaded = True                                           # the page loaded, then went quiet
        for _ in range(60):
            if exits:
                break
            time.sleep(0.1)
        self.assertEqual(exits, [{"saved": False, "reason": "closed"}])
        self.assertFalse(b.running())


class CloudMapEditCommandTests(unittest.TestCase):
    """awskit map edit: the bridge from the terminal, saved to through HTTP the way the
    editor page does it."""

    def test_edit_command_keeps_each_save(self):
        import re
        import subprocess
        import urllib.request
        folder = Path(tempfile.mkdtemp(prefix="awskit-edit-"))
        try:
            fake_drawio(folder / "drawio")
            snap_path = folder / "lab.cloudmap.json"
            map_snapshot("two-az-vpc-state.json").save(snap_path)
            env = dict(os.environ, PYTHONPATH=str(ROOT), AWSKIT_DRAWIO=str(folder / "drawio"))
            proc = subprocess.Popen([sys.executable, "-m", "awskit", "map", "edit", str(snap_path),
                                     "--type", "network", "--open", "none"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, cwd=ROOT, env=env)
            try:
                url = None
                for _ in range(20):
                    line = proc.stdout.readline()
                    m = re.search(r"(http://127\.0\.0\.1:\d+/[^/\s]+/)", line)
                    if m:
                        url = m.group(1)
                        break
                self.assertIsNotNone(url, proc.stderr.read() if proc.poll() is not None else "")
                drawio = folder / "lab-network.drawio"
                self.assertTrue(drawio.exists())
                text = drawio.read_text().replace('awskit_geo="20,60,', 'awskit_geo="20,0,', 1)
                req = urllib.request.Request(url + "save", data=text.encode(), method="POST",
                                             headers={"Content-Type": "application/xml"})
                self.assertEqual(json.loads(urllib.request.urlopen(req, timeout=10).read()), {"ok": True})
                lines = [proc.stdout.readline() for _ in range(2)]
                self.assertIn("Saved. Kept in lab.layout.json: 1 moved", "".join(lines))
                req = urllib.request.Request(url + "exit", data=b'{"saved": true}', method="POST")
                urllib.request.urlopen(req, timeout=10).read()
                self.assertEqual(proc.wait(timeout=10), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.stdout.close()
                proc.stderr.close()
            self.assertTrue((folder / "lab.layout.json").exists())
        finally:
            shutil.rmtree(folder)


class CloudMapEditorPlatformTests(unittest.TestCase):
    """Finding Edge, picking what Open in draw.io uses, and the fallback order. Windows
    can't run here, so its parts are mocked."""

    def test_finds_edge_from_the_registry_then_the_usual_folders(self):
        from unittest import mock
        from awskit import mapeditor
        folder = Path(tempfile.mkdtemp(prefix="awskit-edge-"))
        try:
            reg = folder / "Edge" / "msedge.exe"
            std = folder / "x86" / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            for p in (reg, std):
                p.parent.mkdir(parents=True)
                p.write_text("")
            with mock.patch.object(mapeditor.sys, "platform", "win32"), \
                    mock.patch.object(mapeditor, "_registry_path", lambda name: str(reg)):
                self.assertEqual(mapeditor.find_edge(), str(reg))
            with mock.patch.object(mapeditor.sys, "platform", "win32"), \
                    mock.patch.object(mapeditor, "_registry_path", lambda name: None), \
                    mock.patch.dict(os.environ, {"ProgramFiles(x86)": str(folder / "x86"),
                                                 "ProgramFiles": str(folder / "none"),
                                                 "LOCALAPPDATA": str(folder / "none")}):
                self.assertEqual(mapeditor.find_edge(), str(std))
                self.assertEqual(mapeditor.webkit_problem(), "WebKitGTK isn't part of GTK for Windows")
            with mock.patch.object(mapeditor.sys, "platform", "win32"), \
                    mock.patch.object(mapeditor, "_registry_path", lambda name: None), \
                    mock.patch.dict(os.environ, {"ProgramFiles(x86)": str(folder / "none"),
                                                 "ProgramFiles": str(folder / "none"),
                                                 "LOCALAPPDATA": str(folder / "none")}):
                self.assertIsNone(mapeditor.find_edge())
            with mock.patch.object(mapeditor.sys, "platform", "linux"), \
                    mock.patch.object(mapeditor, "is_wsl", lambda: False):
                self.assertIsNone(mapeditor.find_edge())          # plain Linux: no Edge app mode
        finally:
            shutil.rmtree(folder)

    def test_edge_opens_as_an_app_window_on_its_own_profile(self):
        from awskit import mapeditor
        cmd = mapeditor.edge_command(r"C:\Edge\msedge.exe", "http://127.0.0.1:5/t/", r"C:\p")
        self.assertEqual(cmd[0], r"C:\Edge\msedge.exe")
        self.assertIn("--app=http://127.0.0.1:5/t/", cmd)
        self.assertIn(r"--user-data-dir=C:\p", cmd)

    def test_the_button_uses_the_setting_or_the_best_available(self):
        from unittest import mock
        from awskit import mapeditor
        with mock.patch.object(mapeditor, "find_edge", lambda: "msedge.exe"), \
                mock.patch.object(mapeditor, "find_drawio_desktop", lambda: "draw.io.exe"):
            self.assertEqual(mapeditor.available_targets(), ["edge", "browser", "desktop"])
        with mock.patch.object(mapeditor, "find_edge", lambda: None), \
                mock.patch.object(mapeditor, "find_drawio_desktop", lambda: None):
            self.assertEqual(mapeditor.available_targets(), ["browser"])
        self.assertEqual(mapeditor.choose_target("desktop", ["edge", "browser", "desktop"]), "desktop")
        self.assertEqual(mapeditor.choose_target("desktop", ["edge", "browser"]), "edge")
        self.assertEqual(mapeditor.choose_target("", ["browser"]), "browser")
        self.assertEqual(mapeditor.choose_target("edge", []), "browser")

    def test_falls_back_from_edge_to_the_browser(self):
        from unittest import mock
        from awskit import mapeditor
        calls = []

        def no_edge(url):
            calls.append(("edge", url))
            raise mapeditor.BridgeError("Microsoft Edge wasn't found.")

        def browser(url):
            calls.append(("browser", url))
        with mock.patch.object(mapeditor, "open_in_edge", no_edge), \
                mock.patch.object(mapeditor, "open_in_browser", browser):
            used, _ = mapeditor.open_outside("edge", "http://127.0.0.1:1/t/", "map.drawio")
        self.assertEqual(used, "browser")
        self.assertEqual([c[0] for c in calls], ["edge", "browser"])
        with mock.patch.object(mapeditor, "open_in_desktop", lambda p: calls.append(("desktop", p))):
            self.assertEqual(mapeditor.open_outside("desktop", "u", "map.drawio")[0], "desktop")

        def broken(url):
            raise OSError("no")
        with mock.patch.object(mapeditor, "open_in_edge", broken), \
                mock.patch.object(mapeditor, "open_in_browser", broken):
            with self.assertRaises(mapeditor.BridgeError):
                mapeditor.open_outside("edge", "u", "p")

    def test_wsl_opens_the_windows_browser(self):
        from unittest import mock
        from awskit import mapeditor
        with mock.patch.object(mapeditor.sys, "platform", "linux"), \
                mock.patch.object(mapeditor, "is_wsl", lambda: True), \
                mock.patch.object(mapeditor.shutil, "which", lambda name: "/usr/bin/wslview" if name == "wslview" else None):
            self.assertEqual(mapeditor.browser_command("http://x/"), ["wslview", "http://x/"])
        with mock.patch.object(mapeditor.sys, "platform", "linux"), \
                mock.patch.object(mapeditor, "is_wsl", lambda: True), \
                mock.patch.object(mapeditor.shutil, "which", lambda name: None), \
                mock.patch.object(mapeditor, "windows_tool", lambda name: "/mnt/c/Windows/explorer.exe"):
            self.assertEqual(mapeditor.browser_command("http://x/"),
                             ["/mnt/c/Windows/explorer.exe", "http://x/"])
        saved = {k: os.environ.get(k) for k in ("WEBKIT_DISABLE_DMABUF_RENDERER",
                                                 "WEBKIT_DISABLE_COMPOSITING_MODE")}
        try:
            for k in saved:
                os.environ.pop(k, None)
            mapeditor.prepare_webkit_env()
            for k in saved:
                self.assertEqual(os.environ[k], "1")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


@unittest.skipUnless(os.environ.get("AWSKIT_EDITOR_TEST") == "1",
                     "set AWSKIT_EDITOR_TEST=1 to open the real editor in WebKitGTK")
class CloudMapEditorWebTests(unittest.TestCase):
    """The real draw.io editor in WebKitGTK, through the bridge, with networking blocked
    when unshare can do that. Needs WebKitGTK 6.0, draw.io downloaded, and a display
    (or xvfb-run)."""

    def test_editor_loads_and_saves_offline_without_outside_requests(self):
        import subprocess
        from awskit.common import drawio_installed
        if not drawio_installed():
            self.skipTest("draw.io isn't downloaded")
        out = Path(tempfile.mkdtemp(prefix="awskit-editor-"))
        cmd = [sys.executable, str(ROOT / "tests" / "editor_check.py"), str(out)]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                self.skipTest("no display and no xvfb-run")
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        offline = False
        if shutil.which("unshare") and shutil.which("ip") and subprocess.run(
                ["unshare", "-rn", "true"], capture_output=True).returncode == 0:
            cmd = ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$@"', "sh"] + cmd
            offline = True
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                           env=dict(os.environ, PYTHONPATH=str(ROOT)))
        lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
        self.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
        got = json.loads(lines[-1])
        self.assertTrue(got["loaded"], got)
        self.assertEqual(got["saved"], 1, got)
        self.assertEqual(got["outside"], [], got)
        self.assertIn('"y":140', got["moved"].replace(" ", ""))
        self.assertTrue(got["exit"] and got["exit"]["saved"], got)
        saved = Path(got["file"]).read_text()
        self.assertIn('awskit_map="network"', saved)
        if not offline:
            print("(networking wasn't blocked for this run: unshare isn't available)")
        shutil.rmtree(out)


DESIGNS = ROOT / "cloud-map" / "examples"

# Each broken example design, and the message it has to fail with.
BROKEN_DESIGNS = {
    "arrow-not-between-groups": "has to connect two security groups",
    "bad-cidr": "10.0.0.0/33 isn't a valid CIDR block",
    "bad-security-group-rule": "ports 99999 have to be between 0 and 65535",
    "duplicate-names": 'Two subnets are called "private-a"',
    "missing-zone": "has no availability zone",
    "nat-in-private-subnet": "which is private. NAT gateways go in public subnets",
    "no-region": "The design has no region",
    "overlapping-subnets": 'overlaps subnet "private-a" (10.0.11.0/24)',
    "private-subnet-without-nat": "is in zone b, which has no NAT gateway",
    "public-subnet-without-igw": "has no internet gateway",
    "subnet-outside-vpc-cidr": "10.1.12.0/24 isn't inside its VPC's 10.0.0.0/16",
    "subnet-outside-vpc": "isn't inside a VPC",
    "unsafe-name": "the name can only have letters",
    "zone-not-in-region": "us-west-2 has no zone us-west-2e",
}
WARNING_DESIGNS = {
    "warning-single-nat-open-ssh": ("shared by private subnets in zones a, b",
                                    "allows tcp 22 from 0.0.0.0/0"),
    "warning-public-only": ("has no private subnets",),
}


class CloudMapDesignerTests(unittest.TestCase):
    """The designer: reading designs, the checks, the Terraform it writes, and that a
    plan of that Terraform draws the same network. No GTK, no AWS."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="awskit-design-"))
        self.good = DESIGNS / "design-two-az-vpc.drawio"

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_the_example_reads_the_way_it_was_drawn(self):
        from awskit import mapdesign
        d = mapdesign.read(self.good)
        self.assertEqual((d.name, d.region), ("two-az-vpc", "us-west-2"))
        by_name = {(s.type, s.name): s for s in d.shapes.values() if not s.edge}
        vpc = by_name[("vpc", "lab")]
        self.assertEqual(by_name[("subnet", "private-b")].vpc, vpc.id)
        self.assertEqual(by_name[("nat", "nat-a")].container, by_name[("subnet", "public-a")].id)
        self.assertEqual(by_name[("igw", "lab-igw")].vpc, vpc.id)       # on the border
        self.assertEqual(mapdesign.check(d), [])
        nets = mapdesign.network(d)
        m = nets["lab"]
        self.assertEqual(m["subnets"]["private-a"], {"cidr": "10.0.11.0/24", "az": "a", "public": False,
                                                     "route_table": "private-a"})
        self.assertEqual(m["route_tables"], {"private-a": {"nat_gateway": "nat-a"},
                                             "private-b": {"nat_gateway": "nat-b"},
                                             "public": {"internet_gateway": True}})
        self.assertEqual(m["gateway_endpoints"]["s3"]["route_tables"], ["private-a", "private-b"])
        self.assertEqual(m["ingress_rules"]["app-tcp-8080-from-web"]["referenced_security_group"], "web")

    def test_each_broken_design_fails_with_its_message(self):
        from awskit import mapdesign
        folder = DESIGNS / "broken-designs"
        self.assertEqual(sorted(p.stem for p in folder.glob("*.drawio")),
                         sorted(list(BROKEN_DESIGNS) + list(WARNING_DESIGNS)))
        for name, wanted in BROKEN_DESIGNS.items():
            design = mapdesign.read(folder / f"{name}.drawio")
            problems = mapdesign.check(design)
            errs = [p.message for p in mapdesign.errors(problems)]
            self.assertTrue(any(wanted in e for e in errs), f"{name}: {errs}")
            out = self.dir / name
            with self.assertRaises(mapdesign.DesignError):
                mapdesign.build(design, out, fmt=False)
            self.assertFalse(out.exists(), name)                    # nothing written
        for name, wanted in WARNING_DESIGNS.items():
            problems = mapdesign.check(mapdesign.read(folder / f"{name}.drawio"))
            self.assertEqual(mapdesign.errors(problems), [], name)
            for w in wanted:
                self.assertTrue(any(w in p.message for p in problems), f"{name}: {w}")

    def test_problems_are_marked_on_their_shapes(self):
        from awskit import mapdesign, maprender
        design = mapdesign.read(DESIGNS / "broken-designs" / "overlapping-subnets.drawio")
        lay = mapdesign.layout(design)
        flagged = {b.attrs.get("name"): b.flags for b in lay.boxes if b.flags}
        self.assertEqual(list(flagged), ["private-b"])
        self.assertEqual(flagged["private-b"][0]["severity"], "high")
        scene = maprender.Scene(lay, "dark", icons=None)
        self.assertIn(("flag", lay.box(next(b.id for b in lay.boxes if b.flags))),
                      [(k, o) for k, o, _ in scene.order if k == "flag"])
        self.assertTrue(any(lk.kind == "sg-reference" for lk in lay.links))
        png = maprender.render_png(lay, "light", scale=1.0)
        self.assertTrue(png.startswith(b"\x89PNG"))

    def test_build_writes_the_expected_files(self):
        from awskit import mapdesign
        out = self.dir / "two-az-vpc-tf"
        result = mapdesign.build(mapdesign.read(self.good), out, fmt=False)
        expected = ROOT / "tests" / "design-two-az-vpc-tf"
        got = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
        want = sorted(str(p.relative_to(expected)) for p in expected.rglob("*") if p.is_file())
        self.assertEqual(got, want)
        for rel in want:
            self.assertEqual((out / rel).read_text(), (expected / rel).read_text(), rel)
        self.assertEqual(result.files, sorted(r for r in want if r != ".awskit-designer"))
        main = (out / "main.tf").read_text()
        self.assertIn("for_each = var.subnets", main)
        self.assertNotIn("count", main)
        everything = "".join((out / r).read_text() for r in want if r.endswith(".tf"))
        self.assertNotIn("us-west-2", everything.replace((out / "examples/basic/terraform.tfvars").read_text(), ""))
        self.assertNotRegex(everything, r"\b\d{12}\b")              # no account IDs
        for rel in want:
            if rel.endswith(".tf"):
                self.assertTrue((out / rel).read_text().startswith(
                    "# Generated by AWS Kit Cloud Map from the design design-two-az-vpc.drawio."), rel)
        self.assertIn("aws_vpc_security_group_ingress_rule", (out / "security.tf").read_text())

    def test_only_writes_into_its_own_folder(self):
        from awskit import mapdesign
        design = mapdesign.read(self.good)
        theirs = self.dir / "theirs"
        theirs.mkdir()
        (theirs / "main.tf").write_text("# mine")
        with self.assertRaises(mapdesign.BuildError):
            mapdesign.build(design, theirs, fmt=False)
        self.assertEqual((theirs / "main.tf").read_text(), "# mine")
        self.assertEqual(sorted(p.name for p in theirs.iterdir()), ["main.tf"])
        ours = self.dir / "ours"
        mapdesign.build(design, ours, fmt=False)
        (ours / "main.tf").write_text("# changed by hand")
        (ours / "examples" / "basic" / "terraform.tfstate").write_text("{}")   # not ours
        (ours / "old.tf").write_text("# from an older build")
        (ours / "edited.tf").write_text("# an old file of ours the user changed")
        marker = json.loads((ours / ".awskit-designer").read_text())
        self.assertIsInstance(marker["files"], dict)                    # name: sha256
        import hashlib
        sha = lambda text: hashlib.sha256(text.encode()).hexdigest()   # noqa: E731
        marker["files"]["old.tf"] = sha("# from an older build")
        marker["files"]["edited.tf"] = sha("# what the designer wrote")
        marker["files"]["examples/basic/terraform.tfstate"] = sha("not what's there")
        marker["files"]["../escape.tf"] = sha("# outside")
        marker["files"]["C:escape.tf"] = sha("# outside")
        (ours / ".awskit-designer").write_text(json.dumps(marker))
        (self.dir / "escape.tf").write_text("# outside")
        result = mapdesign.build(design, ours, fmt=False)
        self.assertIn("for_each", (ours / "main.tf").read_text())     # overwritten
        self.assertEqual(result.removed, ["old.tf"])                  # only an unchanged file of ours
        self.assertTrue((ours / "edited.tf").exists())
        self.assertTrue((ours / "examples" / "basic" / "terraform.tfstate").exists())
        self.assertTrue((self.dir / "escape.tf").exists())
        marker["files"] = "ab"                                        # not a list or a map
        (ours / "a").write_text("x")
        (ours / ".awskit-designer").write_text(json.dumps(marker))
        mapdesign.build(design, ours, fmt=False)
        self.assertTrue((ours / "a").exists())
        fake = self.dir / "fake"
        fake.mkdir()
        (fake / ".awskit-designer").write_text("{}")
        with self.assertRaises(mapdesign.BuildError):
            mapdesign.build(design, fake, fmt=False)
        if hasattr(os, "symlink"):
            linked = self.dir / "linked"
            mapdesign.build(design, linked, fmt=False)
            (linked / "main.tf").unlink()
            os.symlink(self.dir / "escape.tf", linked / "main.tf")
            with self.assertRaises(mapdesign.BuildError):
                mapdesign.build(design, linked, fmt=False)
            self.assertEqual((self.dir / "escape.tf").read_text(), "# outside")

    def test_rules_ports_and_names(self):
        from awskit import mapdesign
        rules = mapdesign.parse_rules("tcp 443 0.0.0.0/0; udp 53 10.0.0.0/8 # dns\nall ::/0\nicmp 10.0.0.0/16")
        self.assertEqual([(r.protocol, r.from_port, r.to_port, r.cidr) for r in rules],
                         [("tcp", 443, 443, "0.0.0.0/0"), ("udp", 53, 53, "10.0.0.0/8"),
                          ("-1", None, None, "::/0"), ("icmp", -1, -1, "10.0.0.0/16")])
        self.assertEqual(rules[1].description, "dns")
        self.assertEqual(mapdesign.parse_ports("tcp", "8000-8080"), ("tcp", 8000, 8080))
        for bad in ("tcp 443", "tcp 443 0.0.0.0/33", "ssh 22 0.0.0.0/0", "tcp 90-80 10.0.0.0/8",
                    "tcp 443 10.0.0.1/8"):
            with self.assertRaises(ValueError, msg=bad):
                mapdesign.parse_rules(bad)
        self.assertEqual(mapdesign.name_prefix_of("My Lab!"), "my-lab")
        self.assertEqual(mapdesign.name_prefix_of("sg-net"), "net-sg-net")
        self.assertEqual(mapdesign.hcl_string("a ${b} %{c}"), '"a $${b} %%{c}"')

    def test_a_new_design_and_the_library(self):
        import importlib.util
        from awskit import mapdesign
        path = mapdesign.new_design(self.dir / "fresh", region="eu-west-1")
        self.assertEqual(path.name, "fresh.drawio")
        design = mapdesign.read(path)
        self.assertEqual((design.name, design.region), ("fresh", "eu-west-1"))
        self.assertEqual(mapdesign.errors(mapdesign.check(design)), [])
        with self.assertRaises(mapdesign.DesignError):
            mapdesign.new_design(path)
        # The committed library and example designs are what the script makes.
        spec = importlib.util.spec_from_file_location(
            "make_designer_files", ROOT / "cloud-map" / "designer" / "make_designer_files.py")
        maker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(maker)
        for out, text in maker.outputs().items():
            self.assertEqual(Path(out).read_text(), text, f"{out} is out of date: run the script")
        import xml.etree.ElementTree as ET
        lib = ET.fromstring(mapdesign.library_xml())
        items = json.loads(lib.text)
        self.assertEqual(len(items), len(mapdesign.LIBRARY_ITEMS) + 1)
        for item in items:
            ET.fromstring(item["xml"])                                  # each is valid XML
        self.assertTrue(all("awskit_type" in i["xml"] for i in items))

    def test_a_plan_of_the_output_draws_the_same_network(self):
        """tests/design-two-az-vpc-plan.json is `tofu show -json` of a plan of the example's
        output (made offline, with AWS's credential checks turned off)."""
        from awskit import cloudmap, mapdesign, maptf
        snap = maptf.read([str(ROOT / "tests" / "design-two-az-vpc-plan.json")])
        design = mapdesign.read(self.good)
        prefix = "two-az-vpc-"
        names = {}
        for n in snap.nodes.values():
            if n.kind in ("vpc", "subnet", "nat", "igw", "sg", "endpoint"):
                names[(n.kind, n.title[len(prefix):] if n.title.startswith(prefix) else n.title)] = n
        drawn = {(s.type, s.name) for s in design.shapes.values() if not s.edge}
        self.assertEqual(set(names), drawn)
        for s in design.of_type("subnet"):
            node = names[("subnet", s.name)]
            self.assertEqual(node.props["cidr"], s.get("cidr"))
            self.assertEqual(node.props["az"], "us-west-2" + s.get("az"))
            self.assertEqual(node.props["public"], s.get("type") == "public", s.name)
            self.assertEqual(snap.get(node.parent).parent, names[("vpc", "lab")].id)
        self.assertEqual(names[("nat", "nat-b")].parent, names[("subnet", "public-b")].id)
        routes = {(snap.get(e.src).title, snap.get(e.dst).title, e.label)
                  for e in snap.edges.values() if e.kind == "route"}
        self.assertEqual(routes, {
            ("two-az-vpc-public-a", "two-az-vpc-lab-igw", "0.0.0.0/0"),
            ("two-az-vpc-public-b", "two-az-vpc-lab-igw", "0.0.0.0/0"),
            ("two-az-vpc-private-a", "two-az-vpc-nat-a", "0.0.0.0/0"),
            ("two-az-vpc-private-b", "two-az-vpc-nat-b", "0.0.0.0/0"),
            ("two-az-vpc-private-a", "two-az-vpc-s3", "S3 prefix list"),
            ("two-az-vpc-private-b", "two-az-vpc-s3", "S3 prefix list")})
        refs = [(snap.get(e.src).title, snap.get(e.dst).title, e.label)
                for e in snap.edges.values() if e.kind == "sg-reference"]
        self.assertEqual(refs, [("two-az-vpc-web", "two-az-vpc-app", "tcp 8080")])
        lay = cloudmap.make_layout(snap, "network", show={"routes", "sgs", "endpoints"})
        self.assertEqual(len([b for b in lay.boxes if b.kind == "subnet"]), 4)

    def test_command_line(self):
        import subprocess
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        run = lambda *a: subprocess.run([sys.executable, "-m", "awskit", "map", "design", *a],
                                        capture_output=True, text=True, cwd=self.dir, env=env)
        r = run("new", "lab", "--region", "us-west-2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.dir / "lab.drawio").exists())
        r = run("check", str(DESIGNS / "broken-designs" / "overlapping-subnets.drawio"))
        self.assertEqual(r.returncode, 1)
        self.assertIn('overlaps subnet "private-a"', r.stdout)
        r = run("check", str(self.good))
        self.assertEqual(r.returncode, 0, r.stdout)
        shutil.copy(self.good, self.dir / "two-az.drawio")
        r = run("build", "two-az.drawio", "--no-validate", "--no-fmt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.dir / "two-az-tf" / "examples" / "basic" / "main.tf").exists())
        self.assertIn("never runs apply", r.stdout)
        r = run("build", str(DESIGNS / "broken-designs" / "bad-cidr.drawio"), "-o",
                str(self.dir / "nope"), "--no-validate")
        self.assertEqual(r.returncode, 1)
        self.assertFalse((self.dir / "nope").exists())


@unittest.skipUnless(os.environ.get("AWSKIT_TF_TEST") == "1",
                     "set AWSKIT_TF_TEST=1 to run terraform or tofu on the designer's output")
class CloudMapDesignerTerraformTests(unittest.TestCase):
    """Runs terraform (or tofu) on the designer's output for real: init, validate, then a
    plan with AWS's credential checks turned off, read back through the Terraform input.
    Needs terraform or tofu on PATH and the AWS provider (from the registry, or a mirror
    set in TF_CLI_CONFIG_FILE)."""

    def test_output_validates_and_plans_into_the_same_map(self):
        import subprocess
        from awskit import mapdesign, maptf, tfplan
        tf = tfplan.terraform_bin()
        if not tf:
            self.skipTest("terraform and tofu aren't installed")
        folder = Path(tempfile.mkdtemp(prefix="awskit-tf-"))
        try:
            result = mapdesign.build(mapdesign.read(DESIGNS / "design-two-az-vpc.drawio"),
                                     folder / "out", validate=True)
            self.assertIn("nothing to change", result.formatted)       # already formatted
            self.assertEqual([c[1] for c in result.checks], [True, True], result.checks)
            example = folder / "out" / "examples" / "basic"
            (example / "zz_offline_override.tf").write_text(
                'provider "aws" {\n  skip_credentials_validation = true\n'
                '  skip_requesting_account_id  = true\n  skip_metadata_api_check     = true\n'
                '  access_key                  = "test"\n  secret_key                  = "test"\n}\n')
            r = subprocess.run([tf, "plan", "-input=false", "-no-color", "-out=p.plan"],
                               cwd=example, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            plan = subprocess.run([tf, "show", "-json", "p.plan"], cwd=example,
                                  capture_output=True, text=True, check=True).stdout
            (folder / "plan.json").write_text(plan)
            snap = maptf.read([str(folder / "plan.json")])
            kinds = sorted(n.kind for n in snap.nodes.values()
                           if n.kind in ("vpc", "subnet", "nat", "igw", "sg", "endpoint"))
            self.assertEqual(kinds, ["endpoint", "igw", "nat", "nat", "sg", "sg", "subnet",
                                     "subnet", "subnet", "subnet", "vpc"])
            self.assertEqual(sum(1 for e in snap.edges.values() if e.kind == "route"), 6)
        finally:
            shutil.rmtree(folder)


class _Denied:
    """Stands in for a boto3 client the profile isn't allowed to use."""

    def __init__(self, service):
        self.service = service

    def can_paginate(self, method):
        return False

    def __getattr__(self, name):
        from botocore.exceptions import ClientError

        def call(*a, **k):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, name)
        return call


class _FakeCE:
    def get_anomaly_monitors(self, **k):
        return {"AnomalyMonitors": [{"MonitorArn": "arn:aws:ce::123456789012:anomalymonitor/x"}]}


@unittest.skipIf(mock_aws is None, "moto not installed")
class CloudMapScanTests(unittest.TestCase):
    """The live scan against moto. Cost Explorer's anomaly monitors aren't in moto, so
    that one call is stubbed."""

    def setUp(self):
        from unittest import mock
        from awskit import common
        self.mock = mock_aws()
        self.mock.start()
        self.denied = set()
        real = common.AwsContext.client
        test = self

        def client(ctx, service, region=None):
            if service in test.denied:
                return _Denied(service)
            if service == "ce":
                return _FakeCE()
            return real(ctx, service, region)
        self.patch = mock.patch.object(common.AwsContext, "client", client)
        self.patch.start()
        org = boto3.client("organizations", region_name="us-east-1")
        org.create_organization(FeatureSet="ALL")
        root = org.list_roots()["Roots"][0]["Id"]
        self.ou = org.create_organizational_unit(ParentId=root, Name="Workloads")["OrganizationalUnit"]["Id"]
        self.lab = org.create_account(Email="lab@example.com", AccountName="lab")["CreateAccountStatus"]["AccountId"]
        org.move_account(AccountId=self.lab, SourceParentId=root, DestinationParentId=self.ou)
        org.enable_policy_type(RootId=root, PolicyType="SERVICE_CONTROL_POLICY")
        pid = org.create_policy(Name="deny-leave-org", Description="", Type="SERVICE_CONTROL_POLICY", Content=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}]}))["Policy"]["PolicySummary"]["Id"]
        org.attach_policy(PolicyId=pid, TargetId=self.ou)
        iam = boto3.client("iam", region_name="us-east-1")
        prov = iam.create_open_id_connect_provider(Url="https://token.actions.githubusercontent.com",
                                                   ClientIDList=["sts.amazonaws.com"], ThumbprintList=["a" * 40])["OpenIDConnectProviderArn"]
        iam.create_role(RoleName="gha-any-repo", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": prov}, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:someone/*"}}}]}))
        iam.create_role(RoleName="vendor", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]}))
        iam.create_role(RoleName="AWSServiceRoleForSupport", Path="/aws-service-role/support.amazonaws.com/",
                        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                            "Effect": "Allow", "Principal": {"Service": "support.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
        ec2 = boto3.client("ec2", region_name="us-east-1")
        self.vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        self.subnet = ec2.create_subnet(VpcId=self.vpc, CidrBlock="10.1.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
        self.igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=self.igw, VpcId=self.vpc)
        rt = ec2.create_route_table(VpcId=self.vpc)["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=self.igw)
        ec2.associate_route_table(RouteTableId=rt, SubnetId=self.subnet)
        self.sg = ec2.create_security_group(GroupName="ssh", Description="x", VpcId=self.vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=self.sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        self.instance = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=self.subnet,
                                          SecurityGroupIds=[self.sg],
                                          MetadataOptions={"HttpTokens": "optional"})["Instances"][0]["InstanceId"]
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="org-trail-logs")
        boto3.client("cloudtrail", region_name="us-east-1").create_trail(
            Name="org-trail", S3BucketName="org-trail-logs", IsMultiRegionTrail=True, IsOrganizationTrail=True)

    def tearDown(self):
        self.patch.stop()
        self.mock.stop()

    def test_scan_builds_access_and_network(self):
        from awskit import mapscan
        snap = mapscan.scan([None], ["us-east-1"])
        me = boto3.client("sts").get_caller_identity()["Account"]
        self.assertEqual(snap.meta["org"], "full")
        self.assertEqual(snap.get(self.ou).caption, "SCPs: deny-leave-org")
        self.assertEqual(snap.get(self.lab).parent, self.ou)
        vendor = snap.get(f"arn:aws:iam::{me}:role/vendor")
        self.assertEqual(vendor.flags[0]["severity"], "high")
        gha = snap.get(f"arn:aws:iam::{me}:role/gha-any-repo")
        self.assertIn("any repo in someone", gha.caption)
        self.assertTrue(gha.flags)
        self.assertTrue(snap.get(f"arn:aws:iam::{me}:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport").props["service_linked"])
        self.assertTrue(snap.get(self.subnet).props["public"])
        self.assertIn(f"route:{self.subnet}->{self.igw}", snap.edges)
        self.assertIn("22 SSH", snap.get(self.sg).flags[0]["reason"])
        self.assertIn("IMDSv1", snap.get(self.instance).flags[0]["reason"])
        self.assertIn("arn:aws:s3:::org-trail-logs", snap.nodes)
        self.assertEqual(snap.get(f"{me}/cost").caption, "anomaly alerts")
        for map_type in ("access", "network", "combined"):
            xml, lay = map_export(snap, map_type)
            self.assertTrue(lay.boxes)
            self.assertNotIn("AWSServiceRoleForSupport", xml)   # hidden by default
        xml, _ = map_export(snap, "access", service_linked=True)
        self.assertIn("AWSServiceRoleForSupport", xml)
        xml, lay = map_export(snap, "network")
        self.assertNotIn("172.31.0.0/16", xml)                  # empty default VPC left out
        self.assertIn("empty default VPC", xml)

    def test_access_denied_parts_are_skipped(self):
        from awskit import mapscan
        self.denied = {"organizations", "sso-admin"}
        snap = mapscan.scan([None], ["us-east-1"])
        self.assertEqual(snap.meta["org"], "none")
        self.assertTrue(any("no permission for Organizations" in w for w in snap.warnings))
        self.assertTrue(any("IAM Identity Center" in w for w in snap.warnings))
        self.assertIn(self.vpc, snap.nodes)                     # the rest still scanned
        self.assertTrue(snap.of_kind("role"))
        xml, _ = map_export(snap, "access")
        self.assertIn("no permission for Organizations", xml)  # in the footnote

    def test_identity_center_names_prefer_list_calls(self):
        from awskit import mapscan
        calls = []

        class Store:
            def can_paginate(self, method):
                return False

            def list_users(self, **k):
                calls.append("list_users")
                return {"Users": [{"UserId": "u1", "UserName": "snowy", "DisplayName": "Snowy"}]}

            def list_groups(self, **k):
                from botocore.exceptions import ClientError
                calls.append("list_groups")
                raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "ListGroups")

            def describe_group(self, **k):
                calls.append("describe_group")
                return {"DisplayName": "Admins"}

        notes = mapscan.Notes("p", "global")
        names = mapscan._principal_names(Store(), "d-1", {("USER", "u1"), ("GROUP", "g1")}, notes)
        self.assertEqual(names, {"u1": "Snowy", "g1": "Admins"})
        self.assertNotIn("describe_user", calls)
        self.assertEqual(notes.denied, [])      # the fallback worked, so nothing to report

    def test_member_account_view_gives_the_org_footnote(self):
        from awskit import mapscan
        real = mapscan.task_org

        def partial(ctx, region, notes):
            out = real(ctx, region, notes)
            return {k: out[k] for k in ("id", "arn", "master")} | {"partial": True}
        from unittest import mock
        with mock.patch.object(mapscan, "task_org", partial), \
                mock.patch.dict(mapscan.ACCOUNT_TASKS, {"org": partial}):
            snap = mapscan.scan([None], ["us-east-1"], network=False)
        self.assertEqual(snap.meta["org"], "partial")
        xml, _ = map_export(snap, "access")
        self.assertIn("Organizations data isn&#x27;t available from this account".replace("&#x27;", "'"),
                      xml.replace("&#x27;", "'"))


class SecurityReviewTests(unittest.TestCase):
    """Fixes from the security review: file writes that can't be redirected, nothing
    from a design or a .drawio becoming code or leaking from a redacted export, and
    hostile input that can't stall or break things."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="awskit-sec-"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    # ---- writing files
    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_write_atomic_never_writes_through_a_link(self):
        from awskit.common import write_atomic
        victim = self.dir / "victim.txt"
        victim.write_text("keep me")
        target = self.dir / "out.txt"
        os.symlink(victim, target)                              # a link where the file goes
        for name in (".out.txt.awskit-tmp", ".out.txt.tmp", ".awskit-planted.tmp"):
            os.symlink(victim, self.dir / name)                 # and links at old temp names
        write_atomic(target, "new")
        self.assertEqual(victim.read_text(), "keep me")
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_text(), "new")
        secret = self.dir / "secret"
        write_atomic(secret, b"x", mode=0o600)
        if os.name != "nt":
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            secret.chmod(0o640)
            write_atomic(secret, b"y")                          # keeps its permissions
            self.assertEqual(secret.stat().st_mode & 0o777, 0o640)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_designer_ignores_planted_temp_links(self):
        from awskit import mapdesign
        design = mapdesign.read(DESIGNS / "design-two-az-vpc.drawio")
        out = self.dir / "two-az-vpc-tf"
        mapdesign.build(design, out, fmt=False)
        victim = self.dir / "victim"
        victim.write_text("keep me")
        for rel in ("examples/basic/.main.tf.awskit-tmp", ".main.tf.awskit-tmp", ".awskit-designer.tmp"):
            os.symlink(victim, out / rel)
        mapdesign.build(design, out, fmt=False)
        self.assertEqual(victim.read_text(), "keep me")
        self.assertIn("for_each", (out / "main.tf").read_text())

    def test_designer_paths_stay_inside_the_folder(self):
        from awskit import mapdesign
        for rel in ("C:x.tf", "D:/x.tf", "a.tf:stream", "/etc/x", "\\\\server\\x", "../x", "a/../../x", ""):
            with self.assertRaises(mapdesign.BuildError, msg=rel):
                mapdesign._inside_folder(self.dir, rel)
        self.assertEqual(mapdesign._inside_folder(self.dir, "examples/basic/main.tf"),
                         self.dir / "examples" / "basic" / "main.tf")

    # ---- nothing from a design becomes code
    def test_design_names_cant_become_terraform(self):
        from awskit import mapdesign
        text = (DESIGNS / "design-two-az-vpc.drawio").read_text()
        name = 'x\ndata "external" "pwn" { program = ["sh","-c","id"] }\n#'
        if os.name == "nt":
            name = name.replace('"', "'")
        path = self.dir / f"{name}.drawio"
        try:
            path.write_text(text.replace('awskit_name="', 'awskit_name="&lt;img src=x onerror=alert(1)&gt;[run](https://evil) '))
        except OSError:
            self.skipTest("this file system doesn't take that name")
        out = self.dir / "out"
        mapdesign.build(mapdesign.read(path), out, fmt=False)
        for f in out.rglob("*.tf"):
            for line in f.read_text().splitlines():
                self.assertNotIn('data "external"', line.split("#")[0], f)
        readme = (out / "README.md").read_text()
        self.assertNotRegex(readme, r"(?<!\\)<img")              # shown as text, not HTML
        self.assertNotRegex(readme, r"(?<!\\)\]\(https://evil")  # and not a link
        self.assertEqual(readme.count("-->"), 1)                 # the comment ends where it should

    def test_hcl_strings_only_use_escapes_hcl_knows(self):
        from awskit import mapdesign
        self.assertEqual(mapdesign.hcl_string("a\bb\fc\x7f"), '"a\\u0008b\\u000cc\\u007f"')
        self.assertEqual(mapdesign.hcl_string('q"\\ ${x} %{y}'), '"q\\"\\\\ $${x} %%{y}"')
        self.assertEqual(mapdesign.hcl_string("a\nb\tc"), '"a\\nb\\tc"')

    def test_icmp_ranges_and_rule_name_clashes(self):
        from awskit import mapdesign
        with self.assertRaises(ValueError):
            mapdesign.parse_ports("icmp", "300")
        with self.assertRaises(ValueError):
            mapdesign.parse_ports("icmp", "8-999")
        self.assertEqual(mapdesign.parse_ports("icmp", "8-0"), ("icmp", 8, 0))

    def test_checking_a_folder_with_other_terraform_is_skipped(self):
        from awskit import mapdesign
        design = mapdesign.read(DESIGNS / "design-two-az-vpc.drawio")
        out = self.dir / "tf"
        result = mapdesign.build(design, out, fmt=False)
        self.assertEqual(mapdesign.foreign_files(out, result.files), [])
        (out / "examples" / "basic" / "extra.tf").write_text('data "external" "x" {}\n')
        (out / "examples" / "basic" / ".terraform").mkdir()
        self.assertEqual(mapdesign.foreign_files(out, result.files),
                         ["examples/basic/extra.tf", "examples/basic/.terraform"])
        result = mapdesign.build(design, out, fmt=False, validate=True)
        self.assertEqual(len(result.checks), 1)
        self.assertIsNone(result.checks[0][1])                  # didn't run
        self.assertIn("examples/basic/extra.tf", result.checks[0][2])

    # ---- the editor's bridge
    def test_bridge_refuses_odd_requests_cleanly(self):
        import http.client
        import socket
        from awskit import mapeditor
        drawio = fake_drawio(self.dir / "drawio")
        (drawio / "app.js").write_text("var x;")
        f = self.dir / "map.drawio"
        f.write_text("<mxfile><diagram><mxGraphModel><root/></mxGraphModel></diagram></mxfile>")
        exits = []
        b = mapeditor.Bridge(f, drawio=drawio, idle_timeout=0, on_exit=exits.append)
        b.start()
        try:
            host = f"127.0.0.1:{b.port}"
            c = http.client.HTTPConnection("127.0.0.1", b.port, timeout=5)
            c.request("GET", "/%C3%A9%C3%A9/" + "x" * 300, headers={"Host": host})
            self.assertEqual(c.getresponse().status, 403)      # not a traceback
            c.close()
            c = http.client.HTTPConnection("127.0.0.1", b.port, timeout=5)
            c.request("GET", f"/{b.token}/drawio/app.js", headers={"Host": host})
            r = c.getresponse()
            self.assertEqual(r.getheader("Content-Type"), "application/javascript; charset=utf-8")
            r.read()
            c.request("GET", f"/{b.token}/drawio/" + "y" * 400 + ".js", headers={"Host": host})
            self.assertEqual(c.getresponse().status, 404)      # a name too long: not found
            c.close()
            # A refused POST's body isn't read as a second request.
            inner = f"GET /{b.token}/file HTTP/1.1\r\nHost: {host}\r\n\r\n"
            raw = (f"POST /{b.token}/save HTTP/1.1\r\nHost: evil.example\r\n"
                   f"Content-Length: {len(inner)}\r\n\r\n{inner}").encode()
            s = socket.create_connection(("127.0.0.1", b.port), timeout=5)
            s.sendall(raw)
            got = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
            s.close()
            self.assertEqual(got.count(b"HTTP/1.1 "), 1)
            self.assertIn(b"403", got.split(b"\r\n")[0])
            c = http.client.HTTPConnection("127.0.0.1", b.port, timeout=5)
            c.request("POST", f"/{b.token}/exit", body="[1, 2]", headers={"Host": host})
            self.assertEqual(c.getresponse().status, 200)      # a JSON list doesn't break it
            c.close()
            for _ in range(50):
                if exits:
                    break
                import time
                time.sleep(0.02)
            self.assertEqual(exits, [{"saved": False, "reason": "exit"}])
        finally:
            b.stop()

    # ---- redaction
    def test_redaction_key_is_private_and_never_replaced(self):
        from unittest import mock
        from awskit import cloudmap
        key_file = self.dir / "map" / "redact.key"
        with mock.patch.object(cloudmap, "KEY_FILE", key_file), \
                mock.patch.object(cloudmap, "MAP_DIR", key_file.parent):
            key = cloudmap.redact_key()
            self.assertEqual(cloudmap.redact_key(), key)
            if os.name != "nt":
                self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
            key_file.write_text("damaged\n")
            with self.assertRaises(ValueError):
                cloudmap.redact_key()
            self.assertEqual(key_file.read_text(), "damaged\n")   # not silently replaced

    def test_redacted_drawio_has_no_filter_ids_or_names(self):
        from awskit import cloudmap, maplayoutmem
        snap = map_snapshot("two-az-vpc-state.json")
        snap.scope["profiles"] = ["acmecorp-prod-admin"]
        role = next(iter(snap.nodes.values()))
        role.tags["Owner"] = "alice.smith"
        role.tags["Project"] = "payroll"
        xml, _ = cloudmap.export(snap, "network", accounts=["222222222222"],
                                 vpcs=["vpc-0a1b2c3d4e5f60001"], redacted=True)
        for secret in ("222222222222", "vpc-0a1b2c3d4e5f60001", "two-az-vpc-state.json",
                       "acmecorp-prod-admin", "alice.smith"):
            self.assertNotIn(secret, xml)
        self.assertIn("awskit_accounts=", xml)
        # remember() still finds the filters, through the same keyed hash.
        snap_path = self.dir / "lab.cloudmap.json"
        snap.save(snap_path)
        drawio = self.dir / "red.drawio"
        drawio.write_text(xml)
        got = maplayoutmem.remember(drawio, snap, maplayoutmem.sidecar_path(snap_path),
                                    labels_file=self.dir / "labels.json")
        self.assertEqual(got["map_type"], "network")
        _, id_fn = cloudmap.redactors()
        meta = maplayoutmem.meta_for({"accounts": ["222222222222"], "vpcs": ["lab-vpc"]}, True, id_fn=id_fn)
        self.assertEqual(meta["awskit_accounts"], maplayoutmem.filter_hash(id_fn, "222222222222"))
        self.assertEqual(maplayoutmem.meta_for({"accounts": ["222222222222"]}, True)["awskit_accounts"], "")

    def test_redacted_attributes_keep_secrets_out(self):
        from awskit import cloudmap, maplayout
        text_fn, id_fn = cloudmap.redactors()
        vn = maplayout.VNode("n1", "role", "r", "", "", "x", [("Tag Owner", "Alice Smith")],
                             {"tags": "Owner=alice.smith; Project=payroll",
                              "trust_policy": '{"Condition":{"StringEquals":{"sts:ExternalId":"S3cr3t"}}}',
                              "title": 123456789012}, [], "r", {}, 1)
        view = maplayout.View({"n1": vn}, [], "access", set(), [],
                              ["Source: live scan of profile acmecorp-prod-admin"])
        out = maplayout.redact_view(view, text_fn, id_fn, hide=["acmecorp-prod-admin"])
        node = next(iter(out.nodes.values()))
        self.assertNotIn("alice", node.attrs["tags"])
        self.assertIn("Project=payroll", node.attrs["tags"])
        self.assertNotIn("trust_policy", node.attrs)
        self.assertNotIn("Alice", node.tooltip[0][1])
        self.assertNotIn("123456789012", node.attrs["title"])  # numbers are redacted too
        self.assertEqual(out.source_lines, ["Source: live scan"])

    def test_hand_drawn_pictures_and_links_stay_out_of_redacted_exports(self):
        from awskit import cloudmap, maplayoutmem
        text_fn, _ = cloudmap.redactors()
        style = "shape=image;image=https://wiki.corp/222222222222.png;link=data:x;fillColor=#FF0000;note=222222222222"
        self.assertEqual(maplayoutmem.redact_style(style, text_fn), "shape=image;fillColor=#FF0000;")

    # ---- hostile .drawio files and snapshots
    def test_bad_drawio_files_give_clean_errors(self):
        import base64
        import zlib
        from awskit import maplayoutmem
        with self.assertRaises(maplayoutmem.MemoryError_):
            maplayoutmem.read_cells("<mxfile><diagram>")       # cut off
        packer = zlib.compressobj(9, zlib.DEFLATED, -15)
        bomb = packer.compress(b"<" + b"a" * (maplayoutmem.MAX_DIAGRAM + 10)) + packer.flush()
        text = f"<mxfile><diagram>{base64.b64encode(bomb).decode()}</diagram></mxfile>"
        self.assertLess(len(text), 200_000)
        with self.assertRaises(maplayoutmem.MemoryError_):
            maplayoutmem.read_cells(text)
        cells = ('<mxfile><diagram><mxGraphModel><root><mxCell id="0"/>'
                 '<mxCell id="a" vertex="1"><mxGeometry x="1e300" y="-5" width="1e9" height="10"/></mxCell>'
                 '</root></mxGraphModel></diagram></mxfile>')
        _, got = maplayoutmem.read_cells(cells)
        self.assertEqual(got["a"].geo, (maplayoutmem.COORD_LIMIT, -5.0, maplayoutmem.COORD_LIMIT, 10.0))
        with self.assertRaises(maplayoutmem.MemoryError_):
            maplayoutmem.read_cells(cells.replace('x="1e300"', 'x="nan"'))
        side = self.dir / "s.layout.json"
        side.write_text(json.dumps({"format": maplayoutmem.FORMAT, "maps": {"network": {
            "nodes": {"a": {"x": "inf", "y": 0, "w": 1, "h": 1}, "b": {"x": 1, "y": 2, "w": 3, "h": 4}},
            "edges": {"e": {"points": [["nan", 1]]}}}}}))
        sec = maplayoutmem.load(side)["maps"]["network"]
        self.assertEqual(list(sec["nodes"]), ["b"])
        self.assertEqual(sec["edges"], {})

    def test_odd_styles_dont_break_rendering(self):
        from awskit import maprender
        self.assertEqual(maprender._num("nan", 3), 3)
        self.assertEqual(maprender._num("1e999", 3), 3)
        self.assertEqual(maprender._num("1e300", 3), maprender.NUM_LIMIT)

        class Scene:
            width, height = 1e6, 1e6
        with self.assertRaises(ValueError):
            maprender.png_scale(Scene, 2.0)
        Scene.width, Scene.height = 30000, 2000
        self.assertLessEqual(maprender.png_scale(Scene, 2.0) * Scene.width, maprender.MAX_SIDE)

    def test_damaged_snapshots_raise_snapshot_errors(self):
        from awskit import mapmodel as mm
        base = {"format": mm.FORMAT_NAME, "format_version": 1}
        for nodes in ([{"kind": "vpc"}], ["vpc-1"], [{"id": "a", "kind": "vpc", "flags": "high"}],
                      [{"id": "a", "kind": "vpc", "name": {"x": 1}}]):
            with self.assertRaises(mm.SnapshotError, msg=nodes):
                mm.Snapshot.from_dict(dict(base, nodes=nodes))
        snap = mm.Snapshot.from_dict(dict(base, nodes=[{"id": "a", "kind": "vpc", "name": 5,
                                                        "props": {"category": ["x"]}}]))
        self.assertEqual(snap.nodes["a"].name, "5")

    def test_wildcard_trust_and_foreign_peers(self):
        from awskit import mapmodel as mm
        doc = {"Statement": [{"Effect": "Allow", "Action": "sts:Assume*",
                              "Principal": {"AWS": "arn:aws:iam::999988887777:root"}}]}
        self.assertTrue(mm.trust_principals(doc))
        doc["Statement"][0]["Action"] = "s3:GetObject"
        self.assertFalse(mm.trust_principals(doc))
        doc["Statement"][0].pop("Action")
        doc["Statement"][0]["NotAction"] = "s3:*"
        self.assertTrue(mm.trust_principals(doc))
        snap = mm.Snapshot()
        mm.add_vpc(snap, "vpc-1", "111111111111", "us-east-1")
        mm.add_peering(snap, "pcx-1", "vpc-1", "vpc-2", accepter={"account": "999988887777",
                                                                 "region": "us-east-1"})
        self.assertTrue(snap.get("999988887777").props.get("stub"))
        inside, _ = mm._inside_org(snap, set())
        self.assertEqual(inside, {"111111111111"})

    def test_big_inputs_stay_quick(self):
        import time
        from awskit import maplayout, mapmodel as mm
        start = time.monotonic()
        lines = maplayout.wrap("a" * 100_000, 12, 200)
        snap = mm.Snapshot()
        for i in range(4000):
            mm.add_sg_rule(snap, "sg-1", "ingress", {"protocol": "tcp", "from_port": i, "cidr": "10.0.0.0/8"})
        self.assertLess(time.monotonic() - start, 3.0)
        self.assertLessEqual(len(lines), 4)
        self.assertEqual(len(snap.get("sg-1").props["ingress"]), 4000)

    # ---- the core
    def test_launcher_never_looks_in_the_current_folder(self):
        from awskit import cli
        script = cli.launcher_script("redact ", "test")
        self.assertNotIn(" -m awskit", script)
        self.assertIn("sys.path[0] = os.environ.pop(\"AWSKIT_HOME\")", script)
        if os.name != "nt" and shutil.which("sh"):
            from unittest import mock
            with mock.patch.object(cli, "share_dir", lambda: ROOT):
                (self.dir / "awskit").write_text(cli.launcher_script("", "test"))
            evil = self.dir / "here"
            evil.mkdir()
            (evil / "json.py").write_text("raise SystemExit('the json.py in this folder ran')")
            bin_dir = self.dir / "bin"
            bin_dir.mkdir()
            os.symlink(sys.executable, bin_dir / "python3")
            env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
            import subprocess
            r = subprocess.run(["sh", str(self.dir / "awskit"), "--version"], cwd=evil, env=env,
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("awskit", r.stdout)

    def test_timer_lines_and_csv_cells_are_quoted(self):
        from awskit import cli
        from awskit.common import csv_cell, to_csv
        self.assertEqual(cli.systemd_quote('a b$c%d"e'), '"a b$$c%%d\\"e"')
        self.assertFalse(cli.PROFILE_NAME.fullmatch("lab; rm -rf ~"))
        self.assertTrue(cli.PROFILE_NAME.fullmatch("lab-admin@corp"))
        self.assertEqual(csv_cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(csv_cell("-5"), "-5")
        self.assertIn("'@SUM", to_csv([{"n": "@SUM(A1)"}], [("n", "Name")]))

    def test_drawio_install_leaves_other_folders_alone(self):
        import zipfile
        from awskit import cli
        war = self.dir / "draw.war"
        with zipfile.ZipFile(war, "w") as zf:
            zf.writestr("index.html", "<html></html>")
        mine = self.dir / "my-drawio"
        mine.mkdir()
        (mine / "notes.txt").write_text("mine")
        with self.assertRaises(ValueError):
            cli.unpack_drawio(str(war), mine, "1")
        self.assertEqual((mine / "notes.txt").read_text(), "mine")
        fresh = self.dir / "fresh"
        cli.unpack_drawio(str(war), fresh, "1")
        cli.unpack_drawio(str(war), fresh, "2")                 # its own folder: replaced
        self.assertTrue((fresh / "index.html").exists())


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
