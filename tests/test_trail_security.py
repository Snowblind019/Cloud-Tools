"""CloudTrail's security events: the CIS-style flags on events worth a second look.

Run from the repo root:  python3 -m unittest tests.test_trail_security -v
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
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
for _name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
              "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
              "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
    os.environ.pop(_name, None)
for _name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL_")]:
    os.environ.pop(_name, None)

from awskit import trail  # noqa: E402

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def record(name, source, **extra):
    d = {"eventName": name, "eventSource": source, "eventTime": NOW.isoformat(),
         "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.10",
         "userIdentity": {"type": "AssumedRole",
                          "arn": "arn:aws:sts::111111111111:assumed-role/lab-admin/alex"}}
    d.update(extra)
    return d


def lookup_event(detail):
    return {"EventId": "e-" + detail["eventName"], "EventName": detail["eventName"],
            "EventTime": NOW, "EventSource": detail["eventSource"],
            "CloudTrailEvent": json.dumps(detail)}


class SecurityRuleTests(unittest.TestCase):
    def flag(self, detail):
        return trail.security_alert(detail)

    def test_root_use_is_high_but_not_aws_acting_for_root(self):
        root = record("ListBuckets", "s3.amazonaws.com", userIdentity={"type": "Root"})
        self.assertEqual(self.flag(root)[:2], ("high", "Root user used"))
        service = record("Decrypt", "kms.amazonaws.com",
                         userIdentity={"type": "Root", "invokedBy": "s3.amazonaws.com"})
        self.assertEqual(self.flag(service), ())

    def test_console_sign_in_without_mfa_only_for_iam_users_and_root(self):
        no_mfa = record("ConsoleLogin", "signin.amazonaws.com",
                        userIdentity={"type": "IAMUser", "userName": "jane"},
                        responseElements={"ConsoleLogin": "Success"},
                        additionalEventData={"MFAUsed": "No"})
        self.assertEqual(self.flag(no_mfa)[1], "Console sign-in without MFA")
        with_mfa = dict(no_mfa, additionalEventData={"MFAUsed": "Yes"})
        self.assertEqual(self.flag(with_mfa), ())
        sso = dict(no_mfa, userIdentity={"type": "AssumedRole", "arn": "arn:aws:sts::1:x"})
        self.assertEqual(self.flag(sso), ())
        failed = record("ConsoleLogin", "signin.amazonaws.com",
                        userIdentity={"type": "IAMUser", "userName": "jane"},
                        responseElements={"ConsoleLogin": "Failure"},
                        errorMessage="Failed authentication")
        self.assertEqual(self.flag(failed)[:2], ("medium", "Failed console sign-in"))

    def test_cis_change_events(self):
        cases = {
            ("StopLogging", "cloudtrail.amazonaws.com"): "CloudTrail changed",
            ("StopConfigurationRecorder", "config.amazonaws.com"): "AWS Config recording changed",
            ("ScheduleKeyDeletion", "kms.amazonaws.com"): "KMS key disabled or set to be deleted",
            ("AttachRolePolicy", "iam.amazonaws.com"): "IAM policy changed",
            ("CreateAccessKey", "iam.amazonaws.com"): "New IAM user or credentials",
            ("DetachPolicy", "organizations.amazonaws.com"): "Organizations changed",
            ("PutBucketPolicy", "s3.amazonaws.com"): "S3 bucket policy or ACL changed",
            ("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"): "Security group changed",
            ("ReplaceNetworkAclEntry", "ec2.amazonaws.com"): "Network ACL changed",
            ("AttachInternetGateway", "ec2.amazonaws.com"): "Network gateway changed",
            ("CreateRoute", "ec2.amazonaws.com"): "Route table changed",
            ("CreateVpcPeeringConnection", "ec2.amazonaws.com"): "VPC changed",
            ("DeleteDetector", "guardduty.amazonaws.com"): "GuardDuty turned off",
            ("DeletePublicAccessBlock", "s3.amazonaws.com"): "S3 Block Public Access loosened",
        }
        for (name, source), title in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.flag(record(name, source))[1], title)
        # The same names from another service aren't the same thing.
        self.assertEqual(self.flag(record("CreateRoute", "apigateway.amazonaws.com")), ())
        self.assertEqual(self.flag(record("DescribeInstances", "ec2.amazonaws.com")), ())

    def test_public_snapshot_and_loosened_block_public_access(self):
        public = record("ModifySnapshotAttribute", "ec2.amazonaws.com", requestParameters={
            "snapshotId": "snap-0abc", "attributeType": "CREATE_VOLUME_PERMISSION",
            "createVolumePermission": {"add": {"items": [{"group": "all"}]}}})
        self.assertEqual(self.flag(public)[0], "critical")
        to_account = record("ModifySnapshotAttribute", "ec2.amazonaws.com", requestParameters={
            "createVolumePermission": {"add": {"items": [{"userId": "222222222222"}]}}})
        self.assertEqual(self.flag(to_account), ())
        tighter = record("PutPublicAccessBlock", "s3.amazonaws.com", requestParameters={
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                               "BlockPublicPolicy": True,
                                               "RestrictPublicBuckets": True}})
        self.assertEqual(self.flag(tighter), ())
        looser = record("PutPublicAccessBlock", "s3.amazonaws.com", requestParameters={
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}})
        self.assertEqual(self.flag(looser)[1], "S3 Block Public Access loosened")

    def test_guardduty_update_only_flags_turning_it_off(self):
        off = record("UpdateDetector", "guardduty.amazonaws.com",
                     requestParameters={"detectorId": "d1", "enable": False})
        self.assertEqual(self.flag(off)[1], "GuardDuty turned off")
        other = record("UpdateDetector", "guardduty.amazonaws.com",
                       requestParameters={"detectorId": "d1", "findingPublishingFrequency": "SIX_HOURS"})
        self.assertEqual(self.flag(other), ())

    def test_denied_calls_are_medium_and_odd_records_dont_crash(self):
        denied = record("GetSecretValue", "secretsmanager.amazonaws.com", errorCode="AccessDenied")
        self.assertEqual(self.flag(denied)[:2], ("medium", "Call denied"))
        unauthorized = record("RunInstances", "ec2.amazonaws.com",
                              errorCode="Client.UnauthorizedOperation")
        self.assertEqual(self.flag(unauthorized)[1], "Call denied")
        for odd in ({}, {"eventName": None}, {"userIdentity": "x"}, {"requestParameters": 5},
                    {"responseElements": []}, "not a dict"):
            self.assertEqual(trail.security_alert(odd), ())

    def test_parsed_event_carries_the_flag_into_row_and_details(self):
        ev = trail.parse_event(lookup_event(record("StopLogging", "cloudtrail.amazonaws.com")),
                               "us-east-1")
        self.assertEqual(ev.row()["flag"], "high")
        text = ev.detail_text()
        self.assertTrue(text.startswith("[HIGH] CloudTrail changed"))
        self.assertIn("Why it's worth a look:", text)
        plain = trail.parse_event(lookup_event(record("ListBuckets", "s3.amazonaws.com")),
                                  "us-east-1")
        self.assertEqual(plain.row()["flag"], "")
        self.assertFalse(plain.detail_text().startswith("["))


@unittest.skipIf(mock_aws is None, "moto not installed")
class SecurityLookupTests(unittest.TestCase):
    """LookupEvents isn't in moto, so the paginator is patched with recorded pages."""

    EVENTS = [record("ListBuckets", "s3.amazonaws.com"),
              record("StopLogging", "cloudtrail.amazonaws.com"),
              record("DescribeInstances", "ec2.amazonaws.com"),
              record("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com")]

    def run_lookup(self, **kw):
        class Pager:
            def __init__(self, pages):
                self.pages = pages
                self.kwargs = None

            def paginate(self, **kwargs):
                self.kwargs = kwargs
                return iter(self.pages)

        pager = Pager([{"Events": [lookup_event(d) for d in self.EVENTS]}])
        with mock_aws():
            import botocore.client
            real = botocore.client.BaseClient.get_paginator

            def fake(client, name):
                if name == "lookup_events":
                    return pager
                return real(client, name)
            with mock.patch.object(botocore.client.BaseClient, "get_paginator", fake):
                events, warnings = trail.lookup(None, ["us-east-1"], NOW - timedelta(hours=1),
                                                NOW, limit=100, **kw)
        return events, warnings, pager.kwargs

    def test_security_only_keeps_flagged_events_and_reads_further(self):
        everything, _, plain_kwargs = self.run_lookup()
        self.assertEqual(len(everything), 4)
        flagged, warnings, kwargs = self.run_lookup(security_only=True)
        self.assertEqual(warnings, [])
        self.assertEqual(sorted(e.name for e in flagged),
                         ["AuthorizeSecurityGroupIngress", "StopLogging"])
        self.assertGreater(kwargs["PaginationConfig"]["MaxItems"],
                           plain_kwargs["PaginationConfig"]["MaxItems"])

    def test_cli_security_flag(self):
        from awskit import cli
        out, err = io.StringIO(), io.StringIO()
        events = [trail.parse_event(lookup_event(d), "us-east-1") for d in self.EVENTS
                  if trail.security_alert(d)]
        with mock.patch.object(trail, "lookup", return_value=(events, [])) as looked, \
                mock.patch("awskit.common.AwsContext") as ctx, \
                redirect_stdout(out), redirect_stderr(err):
            ctx.return_value.default_region = "us-east-1"
            code = cli.main(["trail", "--security", "--since", "1h"])
        self.assertEqual(code, 0)
        self.assertTrue(looked.call_args.kwargs["security_only"])
        text = out.getvalue()
        self.assertIn("Flag", text)
        self.assertIn("CloudTrail changed: ", text)
        self.assertIn("Security group changed: ", text)


try:
    import gi
    gi.require_version("Gtk", "4.0")
    from awskit import trail_page
except (ImportError, ValueError):  # pragma: no cover
    trail_page = None


@unittest.skipIf(trail_page is None, "GTK 4 not installed")
class TrailPageTests(unittest.TestCase):
    """The page's methods on a stand-in, so no display is needed."""

    class Page:
        def __init__(self):
            import threading
            from types import SimpleNamespace
            P = trail_page.TrailPage
            for name in ("search", "mine", "done", "failed", "set_busy"):
                setattr(self, name, getattr(P, name).__get__(self))
            self.WINDOWS, self.busy, self.events = P.WINDOWS, False, []
            self.cancel = threading.Event()
            self.attr_keys = [None] + list(trail.LOOKUP_KEYS)
            self.win = SimpleNamespace(profile=None)
            for name in ("attr", "value", "window", "regions", "errors", "writes", "security",
                         "search_btn", "status", "table", "detail"):
                setattr(self, name, mock.Mock())
            self.attr.get_selected.return_value = self.attr_keys.index("user")
            self.value.get_text.return_value = "alice"
            self.window.get_selected.return_value = 1
            self.regions.selected.return_value = ["us-east-1"]

        def new_cancel(self):
            import threading
            self.cancel = threading.Event()
            return self.cancel

    def test_one_search_at_a_time(self):
        # Enter in the search box ran a second search over the first, and whichever
        # finished last filled the table, even if it was the older search.
        page = self.Page()
        with mock.patch.object(trail_page, "run_bg") as run_bg:
            page.search()
            first_cancel = page.cancel
            page.value.get_text.return_value = "bob"
            page.search()   # Enter while alice's search runs
            page.mine()     # My actions too
            self.assertEqual(run_bg.call_count, 1)
            self.assertIs(page.cancel, first_cancel)   # Stop still stops alice's search
            page.status.busy.assert_called_once()
            page.search_btn.set_sensitive.assert_called_with(False)
            page.done(([], []))
            page.search_btn.set_sensitive.assert_called_with(True)
            page.search()
            self.assertEqual(run_bg.call_count, 2)
        with mock.patch.object(trail_page, "show_message"):
            page.failed(RuntimeError("nope"))
        self.assertFalse(page.busy)
        page.search_btn.set_sensitive.assert_called_with(True)

    def test_a_new_search_clears_the_last_ones_notes(self):
        page = self.Page()
        page.done(([], ["us-west-2: AccessDenied: no"]))
        self.assertIn("us-west-2", page.detail.set_text.call_args.args[0])
        page.done(([], []))
        page.detail.set_text.assert_called_with("")


if __name__ == "__main__":
    unittest.main()
