"""Tests for Org & SCPs: the policy evaluator, reading the org (moto, Terraform state and
snapshots), SCP and RCP inheritance, draft SCPs, and the command line.

Run from the repo root:  python3.12 -m unittest tests.test_org_scps -v
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
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

from awskit import policyeval as pe  # noqa: E402
from awskit import scpcheck as sc  # noqa: E402

try:
    import boto3
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

D1 = ROOT / "cloud-map" / "examples" / "d1-org-state.json"
DEMO = ROOT / "org-scps" / "examples" / "demo-org.json"
DRAFT = ROOT / "org-scps" / "examples" / "draft-small-instances-only.json"


def cond(op, key, values, context):
    return pe.evaluate_condition(op, key, values, pe.make_context(context))


def stmt_result(stmt, action="s3:GetObject", resource="", context=None, version=pe.VERSION):
    return pe.evaluate_statement(stmt, pe.Request(action, resource, context or {}), 0, version)


def run_cli(args):
    from awskit import cli
    out, errs = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
        rc = cli.main(args)
    return rc, out.getvalue(), errs.getvalue()


# =================================================================== the evaluator

class ThreeValuedTests(unittest.TestCase):
    def test_all_any_negate(self):
        self.assertIs(pe.all_of([True, True]), True)
        self.assertIs(pe.all_of([True, None]), None)
        self.assertIs(pe.all_of([None, False]), False)
        self.assertIs(pe.all_of([]), True)
        self.assertIs(pe.any_of([False, None]), None)
        self.assertIs(pe.any_of([None, True]), True)
        self.assertIs(pe.any_of([]), False)
        self.assertIs(pe.negate(None), None)
        self.assertIs(pe.negate(True), False)


class StringOperatorTests(unittest.TestCase):
    def test_string_equals(self):
        c = cond("StringEquals", "aws:PrincipalTag/team", ["data", "ml"], {"aws:PrincipalTag/team": "ml"})
        self.assertIs(c.result, True)
        c = cond("StringEquals", "aws:PrincipalTag/team", "data", {"aws:PrincipalTag/team": "Data"})
        self.assertIs(c.result, False)                     # values are case-sensitive
        c = cond("StringEquals", "aws:PrincipalTag/team", "data", {})
        self.assertIs(c.result, None)                      # depends on the missing key
        self.assertIs(c.if_unset, False)                   # a missing key fails a positive op
        self.assertEqual(c.depends_on, ["aws:PrincipalTag/team"])
        c = cond("StringEquals", "aws:PrincipalTag/team", "data", {"aws:principaltag/team": pe.ABSENT})
        self.assertIs(c.result, False)                     # known not to be set: definite
        self.assertEqual(c.depends_on, [])

    def test_string_not_equals(self):
        c = cond("StringNotEquals", "aws:RequestedRegion", ["us-east-1", "us-west-2"],
                 {"aws:RequestedRegion": "eu-west-1"})
        self.assertIs(c.result, True)
        c = cond("StringNotEquals", "aws:RequestedRegion", ["us-east-1", "us-west-2"],
                 {"aws:RequestedRegion": "us-west-2"})
        self.assertIs(c.result, False)                     # several values: NOR
        c = cond("StringNotEquals", "aws:PrincipalTag/team", "data", {})
        self.assertIs(c.result, None)
        self.assertIs(c.if_unset, True)                    # a missing key passes a negated op
        c = cond("StringNotEquals", "aws:PrincipalTag/team", "data", {"aws:PrincipalTag/team": None})
        self.assertIs(c.result, True)

    def test_always_present_keys_never_count_as_unset(self):
        c = cond("StringNotEquals", "aws:RequestedRegion", "us-east-1", {})
        self.assertIs(c.result, None)
        self.assertIs(c.if_unset, None)

    def test_ignore_case(self):
        self.assertIs(cond("StringEqualsIgnoreCase", "aws:PrincipalTag/team", "DATA",
                           {"aws:PrincipalTag/team": "data"}).result, True)
        self.assertIs(cond("StringNotEqualsIgnoreCase", "aws:PrincipalTag/team", "DATA",
                           {"aws:PrincipalTag/team": "data"}).result, False)
        self.assertIs(cond("StringNotEqualsIgnoreCase", "aws:PrincipalTag/team", "DATA",
                           {"aws:PrincipalTag/team": "ops"}).result, True)

    def test_context_keys_are_case_insensitive(self):
        c = cond("StringEquals", "AWS:REQUESTEDREGION", "us-east-1", {"aws:requestedRegion": "us-east-1"})
        self.assertIs(c.result, True)

    def test_string_like(self):
        ctx = {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/OrganizationAccountAccessRole"}
        self.assertIs(cond("StringLike", "aws:PrincipalArn",
                           "arn:aws:iam::*:role/OrganizationAccountAccessRole", ctx).result, True)
        self.assertIs(cond("StringNotLike", "aws:PrincipalArn",
                           "arn:aws:iam::*:role/OrganizationAccountAccessRole", ctx).result, False)
        self.assertIs(cond("StringLike", "s3:prefix", "home/?ob/*", {"s3:prefix": "home/bob/x"}).result, True)
        self.assertIs(cond("StringLike", "s3:prefix", "home/?ob/*", {"s3:prefix": "home/bobby/x"}).result, False)
        # square brackets are plain characters in IAM, not a character class
        self.assertIs(cond("StringLike", "s3:prefix", "[ab]", {"s3:prefix": "a"}).result, False)
        self.assertIs(cond("StringLike", "s3:prefix", "[ab]", {"s3:prefix": "[ab]"}).result, True)
        # StringEquals takes * as a plain character
        self.assertIs(cond("StringEquals", "s3:prefix", "home/*", {"s3:prefix": "home/bob"}).result, False)
        c = cond("StringNotLike", "aws:PrincipalArn", "arn:aws:iam::*:role/x", {})
        self.assertEqual((c.result, c.if_unset), (None, None))   # PrincipalArn is always set


class OtherOperatorTests(unittest.TestCase):
    def test_numeric(self):
        ctx = {"aws:MultiFactorAuthAge": "3600"}
        self.assertIs(cond("NumericLessThan", "aws:MultiFactorAuthAge", "7200", ctx).result, True)
        self.assertIs(cond("NumericLessThan", "aws:MultiFactorAuthAge", "3600", ctx).result, False)
        self.assertIs(cond("NumericLessThanEquals", "aws:MultiFactorAuthAge", "3600", ctx).result, True)
        self.assertIs(cond("NumericGreaterThan", "aws:MultiFactorAuthAge", "60", ctx).result, True)
        self.assertIs(cond("NumericGreaterThanEquals", "aws:MultiFactorAuthAge", "3601", ctx).result, False)
        self.assertIs(cond("NumericEquals", "aws:MultiFactorAuthAge", "3600.0", ctx).result, True)
        self.assertIs(cond("NumericNotEquals", "aws:MultiFactorAuthAge", "3600", ctx).result, False)
        self.assertIs(cond("NumericEquals", "aws:MultiFactorAuthAge", "lots", ctx).result, False)
        c = cond("NumericNotEquals", "aws:MultiFactorAuthAge", "1", {})
        self.assertEqual((c.result, c.if_unset), (None, True))
        c = cond("NumericLessThanIfExists", "aws:MultiFactorAuthAge", "1", {})
        self.assertEqual((c.result, c.if_unset), (None, True))

    def test_dates(self):
        ctx = {"aws:CurrentTime": "2026-10-05T12:00:00Z"}
        self.assertIs(cond("DateLessThan", "aws:CurrentTime", "2027-01-01T00:00:00Z", ctx).result, True)
        self.assertIs(cond("DateGreaterThan", "aws:CurrentTime", "2027-01-01", ctx).result, False)
        self.assertIs(cond("DateGreaterThanEquals", "aws:CurrentTime", "2026-10-05T12:00:00Z", ctx).result, True)
        self.assertIs(cond("DateLessThanEquals", "aws:CurrentTime", "2026-10-05T11:59:59.5Z", ctx).result, False)
        self.assertIs(cond("DateEquals", "aws:CurrentTime", "1791201600", ctx).result, True)  # epoch
        self.assertIs(cond("DateNotEquals", "aws:CurrentTime", "1791201600", ctx).result, False)
        self.assertIs(cond("DateLessThan", "aws:EpochTime", "2026-10-06", {"aws:EpochTime": "1791201600"}).result, True)
        self.assertIs(cond("DateLessThan", "aws:CurrentTime", "not a date", ctx).result, False)
        # Windows raises OSError for a negative epoch time: still just "no match"
        with mock.patch.object(pe, "_date", side_effect=OSError(22, "Invalid argument")):
            self.assertIs(cond("DateLessThan", "aws:CurrentTime", "-1", ctx).result, False)

    def test_bool(self):
        self.assertIs(cond("Bool", "aws:SecureTransport", "false", {"aws:SecureTransport": "false"}).result, True)
        self.assertIs(cond("Bool", "aws:SecureTransport", False, {"aws:SecureTransport": True}).result, False)
        self.assertIs(cond("Bool", "aws:MultiFactorAuthPresent", "true", {"aws:MultiFactorAuthPresent": "TRUE"}).result, True)
        c = cond("Bool", "aws:MultiFactorAuthPresent", "false", {})
        self.assertEqual((c.result, c.if_unset), (None, False))
        c = cond("BoolIfExists", "aws:MultiFactorAuthPresent", "false", {})
        self.assertEqual((c.result, c.if_unset), (None, True))

    def test_binary(self):
        ctx = {"aws:Example": "aGVsbG8="}
        self.assertIs(cond("BinaryEquals", "aws:Example", "aGVsbG8=", ctx).result, True)
        self.assertIs(cond("BinaryEquals", "aws:Example", "d29ybGQ=", ctx).result, False)

    def test_ip_address(self):
        ctx = {"aws:SourceIp": "203.0.113.25"}
        self.assertIs(cond("IpAddress", "aws:SourceIp", ["203.0.113.0/24"], ctx).result, True)
        self.assertIs(cond("IpAddress", "aws:SourceIp", "198.51.100.0/24", ctx).result, False)
        self.assertIs(cond("NotIpAddress", "aws:SourceIp", "203.0.113.0/24", ctx).result, False)
        self.assertIs(cond("IpAddress", "aws:SourceIp", "203.0.113.25", ctx).result, True)
        self.assertIs(cond("IpAddress", "aws:SourceIp", "2001:db8::/32", ctx).result, False)  # v6 vs v4
        self.assertIs(cond("IpAddress", "aws:SourceIp", "2001:db8::/32", {"aws:SourceIp": "2001:db8::5"}).result, True)
        c = cond("NotIpAddress", "aws:SourceIp", "10.0.0.0/8", {})
        self.assertEqual((c.result, c.if_unset), (None, True))

    def test_arn_operators(self):
        ctx = {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:alerts"}
        self.assertIs(cond("ArnEquals", "aws:SourceArn", "arn:aws:sns:us-east-1:111122223333:alerts", ctx).result, True)
        self.assertIs(cond("ArnLike", "aws:SourceArn", "arn:aws:sns:*:111122223333:*", ctx).result, True)
        self.assertIs(cond("ArnLike", "aws:SourceArn", "arn:aws:sns:*:444455556666:*", ctx).result, False)
        self.assertIs(cond("ArnNotLike", "aws:SourceArn", "arn:aws:sns:*:444455556666:*", ctx).result, True)
        self.assertIs(cond("ArnNotEquals", "aws:SourceArn", "arn:aws:sns:us-east-1:111122223333:alerts", ctx).result, False)
        # a wildcard in the region part doesn't run on into the account part
        self.assertIs(cond("ArnLike", "aws:SourceArn", "arn:aws:sns:*:alerts", ctx).result, False)

    def test_null(self):
        self.assertIs(cond("Null", "aws:TokenIssueTime", "true", {}).result, None)
        self.assertIs(cond("Null", "aws:TokenIssueTime", "true", {}).if_unset, True)
        self.assertIs(cond("Null", "aws:TokenIssueTime", "true", {"aws:TokenIssueTime": "x"}).result, False)
        self.assertIs(cond("Null", "aws:TokenIssueTime", "false", {"aws:TokenIssueTime": "x"}).result, True)
        self.assertIs(cond("Null", "aws:TokenIssueTime", "false", {"aws:TokenIssueTime": pe.ABSENT}).result, False)

    def test_if_exists_with_value(self):
        self.assertIs(cond("StringEqualsIfExists", "aws:PrincipalTag/team", "data",
                           {"aws:PrincipalTag/team": "ops"}).result, False)
        c = cond("StringEqualsIfExists", "aws:PrincipalTag/team", "data", {})
        self.assertEqual((c.result, c.if_unset), (None, True))

    def test_unknown_operator(self):
        c = cond("StringSortOf", "aws:PrincipalTag/team", "data", {"aws:PrincipalTag/team": "data"})
        self.assertIn("unknown condition operator", c.error)
        self.assertFalse(pe.known_operator("NullIfExists"))
        self.assertTrue(pe.known_operator("ForAnyValue:StringNotLikeIfExists"))


class SetOperatorTests(unittest.TestCase):
    def test_for_all_values(self):
        op = "ForAllValues:StringEquals"
        self.assertIs(cond(op, "aws:TagKeys", ["Owner", "Team"], {"aws:TagKeys": ["Owner"]}).result, True)
        self.assertIs(cond(op, "aws:TagKeys", ["Owner", "Team"], {"aws:TagKeys": ["Owner", "Cost"]}).result, False)
        self.assertIs(cond(op, "aws:TagKeys", ["Owner"], {"aws:TagKeys": []}).result, True)  # empty: true
        c = cond(op, "aws:TagKeys", ["Owner"], {})
        self.assertEqual((c.result, c.if_unset), (None, True))
        self.assertIs(cond("ForAllValues:StringNotEquals", "aws:TagKeys", ["Secret"],
                           {"aws:TagKeys": ["Owner", "Team"]}).result, True)
        self.assertIs(cond("ForAllValues:StringLike", "aws:TagKeys", ["team-*"],
                           {"aws:TagKeys": ["team-a", "other"]}).result, False)

    def test_for_any_value(self):
        op = "ForAnyValue:StringEquals"
        self.assertIs(cond(op, "aws:TagKeys", ["Owner"], {"aws:TagKeys": ["Cost", "Owner"]}).result, True)
        self.assertIs(cond(op, "aws:TagKeys", ["Owner"], {"aws:TagKeys": ["Cost"]}).result, False)
        self.assertIs(cond(op, "aws:TagKeys", ["Owner"], {"aws:TagKeys": []}).result, False)  # empty: false
        c = cond(op, "aws:TagKeys", ["Owner"], {})
        self.assertEqual((c.result, c.if_unset), (None, False))
        self.assertIs(cond("ForAnyValue:StringNotEquals", "aws:TagKeys", ["Owner"],
                           {"aws:TagKeys": ["Owner", "Cost"]}).result, True)
        self.assertIs(cond("ForAnyValue:StringNotEquals", "aws:TagKeys", ["Owner"],
                           {"aws:TagKeys": ["Owner"]}).result, False)
        c = cond("ForAnyValue:StringEqualsIfExists", "aws:TagKeys", ["Owner"], {})
        self.assertEqual((c.result, c.if_unset), (None, True))   # IfExists wins when missing


class ActionResourceTests(unittest.TestCase):
    def test_action_and_not_action(self):
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "S3:getobject", "Resource": "*"}).result)
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:Get*", "Resource": "*"}).result)
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:?etObject", "Resource": "*"}).result)
        self.assertFalse(stmt_result({"Effect": "Deny", "Action": "s3:Put*", "Resource": "*"}).result)
        self.assertTrue(stmt_result({"Effect": "Allow", "Action": "*", "Resource": "*"}).result)
        r = stmt_result({"Effect": "Deny", "NotAction": ["iam:*", "S3:*"], "Resource": "*"})
        self.assertFalse(r.result)
        self.assertEqual(r.why_not, "it doesn't cover this action")
        self.assertTrue(stmt_result({"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}).result)
        self.assertIn("Action", stmt_result({"Effect": "Deny", "Resource": "*"}).error)
        self.assertIn("Effect", stmt_result({"Effect": "Maybe", "Action": "*"}).error)

    def test_resource_matching(self):
        s = {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::logs-bucket/*"}
        self.assertTrue(stmt_result(s, resource="arn:aws:s3:::logs-bucket/2026/a.gz").result)
        self.assertFalse(stmt_result(s, resource="arn:aws:s3:::logs-bucket").result)
        self.assertFalse(stmt_result(s, resource="arn:aws:s3:::other/x").result)
        r = stmt_result(s)   # no resource given
        self.assertIs(r.result, None)
        self.assertEqual(r.depends_on, [pe.RESOURCE])
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:*", "Resource": "*"}).result)
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:*"}).result)   # no Resource
        role = {"Effect": "Deny", "Action": "iam:*", "Resource": "arn:aws:iam::*:role/admin"}
        self.assertTrue(stmt_result(role, "iam:DeleteRole", "arn:aws:iam::111122223333:role/admin").result)
        self.assertFalse(stmt_result(role, "iam:DeleteRole", "arn:aws:iam::111122223333:role/admin2").result)
        # a wildcard in the account part doesn't swallow the colon after it
        self.assertFalse(stmt_result({"Effect": "Deny", "Action": "iam:*",
                                      "Resource": "arn:aws:iam::*role/x"},
                                     "iam:DeleteRole", "arn:aws:iam::111122223333:role/x").result)
        # but a * that ends the pattern covers the rest, colons and all
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "iam:*",
                                     "Resource": "arn:aws:iam::*"},
                                    "iam:DeleteRole", "arn:aws:iam::111122223333:role/x").result)
        # a short pattern ending in * matches the rest
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:*"},
                                    resource="arn:aws:s3:::any/key").result)

    def test_crafted_wildcards_dont_hang(self):
        # a regex like .*a.*a.*a... took minutes on this; the matcher has to stay quick
        import time
        start = time.monotonic()
        self.assertFalse(pe.glob_match("*a" * 40 + "b", "a" * 300))
        self.assertFalse(pe.action_matches("s3:*e" * 30 + "x", "s3:" + "e" * 300))
        self.assertFalse(stmt_result({"Effect": "Deny", "Action": "s3:*",
                                      "Resource": "arn:aws:s3:::" + "*a" * 40 + "b"},
                                     resource="arn:aws:s3:::" + "a" * 300).result)
        self.assertTrue(pe.glob_match("*a" * 40, "a" * 300))
        self.assertLess(time.monotonic() - start, 5)

    def test_star_that_ends_a_segment_runs_on(self):
        # AWS: "If the * wildcard is the last character of a resource ARN segment, it can
        # expand to match beyond the colon boundaries." That's the Resource element.
        s = {"Effect": "Deny", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:*:table/prod-*"}
        self.assertTrue(stmt_result(s, "dynamodb:DeleteTable",
                                    "arn:aws:dynamodb:us-east-1:111122223333:table/prod-x").result)
        self.assertFalse(stmt_result(s, "dynamodb:DeleteTable",
                                     "arn:aws:dynamodb:us-east-1:111122223333:table/dev-x").result)
        # ArnLike checks the six parts one by one
        self.assertIs(cond("ArnLike", "aws:SourceArn", "arn:aws:dynamodb:*:table/prod-*",
                           {"aws:SourceArn": "arn:aws:dynamodb:us-east-1:111122223333:table/prod-x"}
                           ).result, False)
        self.assertTrue(pe.glob_match("[a]?c", "[a]bc"))
        self.assertTrue(pe.action_matches("EC2:Describe*", "ec2:DescribeInstances"))

    def test_wildcard_in_the_request_resource(self):
        deny = {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data/*"}
        r = stmt_result(deny, resource="arn:aws:s3:::*")             # some of them: depends
        self.assertIs(r.result, None)
        self.assertEqual(r.depends_on, [pe.RESOURCE])
        self.assertIs(stmt_result(deny, resource="arn:aws:s3:::prod-*").result, None)
        self.assertTrue(stmt_result(deny, resource="arn:aws:s3:::prod-data/logs/*").result)
        self.assertFalse(stmt_result(deny, resource="arn:aws:s3:::dev-*").result)
        self.assertFalse(stmt_result(deny, resource="arn:aws:ec2:*:*:instance/*").result)
        self.assertTrue(stmt_result({"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
                                    resource="arn:aws:s3:::*").result)
        # NotResource: covered means excluded, part covered means it depends
        nr = {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::public/*"}
        self.assertIs(stmt_result(nr, resource="arn:aws:s3:::*").result, None)
        self.assertFalse(stmt_result(nr, resource="arn:aws:s3:::public/img/*").result)
        org = small_org()
        add_policy(org, "p-d", "keep-prod", [deny], "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject", "arn:aws:s3:::*", "us-east-1")
        self.assertEqual(v.outcome, "depends")
        self.assertTrue(any("taken as a pattern" in n for n in v.notes))

    def test_not_resource(self):
        s = {"Effect": "Deny", "Action": "s3:*", "NotResource": ["arn:aws:s3:::public-site/*"]}
        self.assertFalse(stmt_result(s, resource="arn:aws:s3:::public-site/index.html").result)
        self.assertTrue(stmt_result(s, resource="arn:aws:s3:::private/x").result)
        self.assertIs(stmt_result(s).result, None)
        self.assertFalse(stmt_result({"Effect": "Deny", "Action": "s3:*", "NotResource": "*"}).result)

    def test_principal_element(self):
        rcp = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}
        self.assertTrue(stmt_result(rcp).result)
        named = {"Effect": "Deny", "Principal": {"AWS": "111122223333"}, "Action": "s3:*", "Resource": "*"}
        self.assertTrue(stmt_result(named, context={"aws:PrincipalAccount": "111122223333"}).result)
        self.assertFalse(stmt_result(named, context={"aws:PrincipalAccount": "444455556666"}).result)
        self.assertIs(stmt_result(named).result, None)
        not_named = {"Effect": "Deny", "NotPrincipal": {"AWS": "111122223333"}, "Action": "s3:*",
                     "Resource": "*"}
        self.assertFalse(stmt_result(not_named, context={"aws:PrincipalAccount": "111122223333"}).result)
        self.assertTrue(stmt_result(not_named, context={"aws:PrincipalAccount": "444455556666"}).result)


class PolicyVariableTests(unittest.TestCase):
    S = {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::home/${aws:PrincipalTag/team}/*"}

    def test_substituted_from_context(self):
        self.assertTrue(stmt_result(self.S, resource="arn:aws:s3:::home/data/x",
                                    context={"aws:PrincipalTag/team": "data"}).result)
        self.assertFalse(stmt_result(self.S, resource="arn:aws:s3:::home/ml/x",
                                     context={"aws:PrincipalTag/team": "data"}).result)

    def test_missing_variable_depends_on_its_key(self):
        r = stmt_result(self.S, resource="arn:aws:s3:::home/data/x")
        self.assertIs(r.result, None)
        self.assertEqual(r.depends_on, ["aws:PrincipalTag/team"])
        self.assertIs(r.if_unset, False)          # with no value it matches nothing
        r = stmt_result(self.S, resource="arn:aws:s3:::home/data/x",
                        context={"aws:PrincipalTag/team": pe.ABSENT})
        self.assertIs(r.result, False)

    def test_default_values_escapes_and_versions(self):
        s = {"Effect": "Allow", "Action": "s3:*",
             "Resource": "arn:aws:s3:::home/${aws:PrincipalTag/team, 'shared'}/*"}
        self.assertTrue(stmt_result(s, resource="arn:aws:s3:::home/shared/x").result)
        star = {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::a${*}b"}
        self.assertTrue(pe.arn_match(pe.substitute(star["Resource"], {}), "arn:aws:s3:::a*b"))
        self.assertFalse(stmt_result(star, resource="arn:aws:s3:::axxb").result)  # literal *
        # a * in the request is taken as a pattern, which a literal * covers only in part
        self.assertIs(stmt_result(star, resource="arn:aws:s3:::a*b").result, None)
        old = stmt_result(self.S, resource="arn:aws:s3:::home/${aws:PrincipalTag/team}/x",
                          version="2008-10-17")
        self.assertTrue(old.result)               # plain text before 2012-10-17

    def test_variable_in_condition_value(self):
        c = cond("StringEquals", "aws:ResourceTag/owner", "${aws:username}",
                 {"aws:ResourceTag/owner": "dev-user", "aws:username": "dev-user"})
        self.assertIs(c.result, True)
        c = cond("StringEquals", "aws:ResourceTag/owner", "${aws:username}",
                 {"aws:ResourceTag/owner": "dev-user"})
        self.assertIs(c.result, None)
        self.assertEqual(c.depends_on, ["aws:username"])
        self.assertIs(c.if_unset, False)


class WordingTests(unittest.TestCase):
    def test_describe_statements(self):
        d = pe.describe_statement
        self.assertEqual(d({"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}),
                         "denies organizations:LeaveOrganization for everyone")
        self.assertEqual(d({"Effect": "Allow", "Action": "*", "Resource": "*"}), "allows everything")
        self.assertEqual(
            d({"Effect": "Deny", "NotAction": ["iam:*", "sts:*"], "Resource": "*",
               "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}}}),
            "denies everything except iam:* and sts:* unless the region is us-east-1 or us-west-2")
        self.assertEqual(
            d({"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringNotLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/OrganizationAccountAccessRole"}}}),
            "denies everything unless the caller is OrganizationAccountAccessRole")
        self.assertEqual(
            d({"Effect": "Allow", "Action": ["ec2:*", "s3:*"], "Resource": "*",
               "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}),
            "allows ec2:* and s3:* only when the region is eu-west-1")
        self.assertEqual(
            d({"Effect": "Deny", "Action": "s3:*", "Resource": "*",
               "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}),
            "denies s3:* when the caller didn't sign in with MFA (or that isn't known)")
        self.assertIn("when the caller's tag team isn't set",
                      d({"Effect": "Deny", "Action": "ec2:*", "Resource": "*",
                         "Condition": {"Null": {"aws:PrincipalTag/team": "true"}}}))
        self.assertIn("on arn:aws:s3:::logs", d({"Effect": "Deny", "Action": "s3:DeleteBucket",
                                                 "Resource": "arn:aws:s3:::logs"}))
        self.assertIn("s3:A4 and 2 more", d({"Effect": "Deny", "Action": [f"s3:A{i}" for i in range(7)]}))

    def test_given_text_and_join(self):
        stmt = {"Condition": {"StringNotEquals": {"aws:RequestedRegion": "x"},
                              "StringNotLike": {"aws:PrincipalArn": "y"}}}
        ctx = pe.make_context({"aws:RequestedRegion": "eu-west-1",
                               "aws:PrincipalArn": "arn:aws:iam::111122223333:role/dev"})
        self.assertEqual(pe.given_text(stmt, ctx),
                         "the region is eu-west-1 and the caller is dev in 111122223333")
        self.assertEqual(pe.join_words(["a", "b", "c"], "or"), "a, b or c")

    def test_problems(self):
        self.assertEqual(pe.problems({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}), [])
        bad = pe.problems({"Statement": [
            {"Effect": "deny", "Action": "s3", "NotAction": "x:y", "Principal": "*",
             "Resource": "*", "NotResource": "*", "Condition": {"StringSortOf": {"a:b": "c"}}}]})
        text = " ".join(bad)
        for want in ("Effect", "Action or NotAction", "isn't an action", "not both",
                     "can't name a Principal", "StringSortOf"):
            self.assertIn(want, text)
        self.assertIn("can only deny", " ".join(pe.problems(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*"}]}, "rcp")))


# =================================================================== org model helpers

def small_org(**changes):
    """Root > Workloads > lab, plus the management account, with FullAWSAccess everywhere."""
    org = sc.Org(id="o-exampleorg1", management="111111111111", root="r-root",
                 enabled=[sc.SCP], source="aws", label="test")
    org.nodes["r-root"] = sc.Node("r-root", "root", "Root")
    org.nodes["ou-wk"] = sc.Node("ou-wk", "ou", "Workloads", "r-root")
    org.nodes["222222222222"] = sc.Node("222222222222", "account", "lab", "ou-wk")
    org.nodes["111111111111"] = sc.Node("111111111111", "account", "mgmt", "r-root")
    sc._add_full_access(org, sc.SCP)
    for n in org.nodes.values():
        n.policies.append("p-FullAWSAccess")
    for k, v in changes.items():
        setattr(org, k, v)
    return org


def add_policy(org, pid, name, statements, target, ptype=sc.SCP):
    org.policies[pid] = sc.Policy(pid, name, ptype, json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    org.nodes[target].policies.append(pid)


class RequestTests(unittest.TestCase):
    def test_parse_context(self):
        got = sc.parse_context('aws:PrincipalTag/team=data aws:TagKeys=a aws:TagKeys=b '
                               '"aws:PrincipalTag/name=two words" !aws:MultiFactorAuthPresent')
        self.assertEqual(got["aws:PrincipalTag/team"], ["data"])
        self.assertEqual(got["aws:TagKeys"], ["a", "b"])
        self.assertEqual(got["aws:PrincipalTag/name"], ["two words"])
        self.assertIs(got["aws:MultiFactorAuthPresent"], pe.ABSENT)
        for bad in ("novalue", "notakey=1", '"unclosed', "!nokey"):
            with self.assertRaises(sc.ScpError):
                sc.parse_context(bad)

    def test_parse_principal(self):
        p = sc.parse_principal("arn:aws:iam::222222222222:role/deploy")
        self.assertEqual((p["type"], p["account"], p["service_linked"]), ("AssumedRole", "222222222222", False))
        p = sc.parse_principal("arn:aws:sts::222222222222:assumed-role/deploy/session-1")
        self.assertEqual(p["arn"], "arn:aws:iam::222222222222:role/deploy")
        self.assertTrue(p["note"])
        p = sc.parse_principal("arn:aws:iam::222222222222:role/aws-service-role/support.amazonaws.com/"
                               "AWSServiceRoleForSupport")
        self.assertTrue(p["service_linked"])
        self.assertEqual(sc.parse_principal("arn:aws:iam::222222222222:user/ci")["type"], "User")
        self.assertEqual(sc.parse_principal("arn:aws:iam::222222222222:root")["type"], "Account")
        with self.assertRaises(sc.ScpError):
            sc.parse_principal("deploy")

    def test_bad_requests(self):
        org = small_org()
        for kwargs in ({"action": ""}, {"action": "s3:*"}, {"action": "DeleteBucket"},
                       {"action": "s3:GetObject", "resource": "my-bucket"},
                       {"action": "s3:GetObject", "region": "Narnia"},
                       {"action": "s3:GetObject", "principal": "arn:aws:iam::333333333333:role/x"}):
            with self.assertRaises(sc.ScpError, msg=str(kwargs)):
                sc.check_action(org, "lab", **kwargs)
        with self.assertRaises(sc.ScpError):
            sc.check_action(org, "Workloads", "s3:GetObject")     # not an account
        with self.assertRaises(sc.ScpError):
            sc.check_action(org, "nobody", "s3:GetObject")

    def test_service_linked_role_needs_its_path(self):
        org = small_org()
        add_policy(org, "p-d", "deny-all", [{"Effect": "Deny", "Action": "*", "Resource": "*"}], "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject",
                            principal="arn:aws:iam::222222222222:role/AWSServiceRoleForAnything")
        self.assertEqual((v.outcome, v.exempt), ("denied", ""))     # no /aws-service-role/ path
        v = sc.check_action(org, "lab", "s3:GetObject", principal=(
            "arn:aws:sts::222222222222:assumed-role/AWSServiceRoleForSupport/s1"))
        self.assertEqual(v.outcome, "denied")
        self.assertTrue(any("looks like a service-linked role" in n for n in v.notes))
        v = sc.check_action(org, "lab", "s3:GetObject", principal=(
            "arn:aws:iam::222222222222:role/aws-service-role/support.amazonaws.com/"
            "AWSServiceRoleForSupport"))
        self.assertEqual((v.outcome, v.exempt), ("allowed", "service-linked role"))

    def test_deny_statement_that_cant_be_read_makes_it_depend(self):
        org = small_org()
        add_policy(org, "p-odd", "odd", [{"Effect": "Deny", "Action": "*", "Resource": "*",
                                          "Condition": {"StringEqualsSorta": {"aws:x": "y"}}}],
                   "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "depends")
        self.assertIn("the text of odd", v.depends_on)
        self.assertIn("unknown condition operator", v.reason)
        self.assertTrue(any("couldn't be checked" in ln["text"] for ln in v.lines))

    def test_rcp_services(self):
        org = small_org(enabled=[sc.SCP, sc.RCP])
        sc._add_full_access(org, sc.RCP)
        for n in org.nodes.values():
            n.policies.append("p-RCPFullAWSAccess")
        add_policy(org, "p-r", "deny-everything", [{"Effect": "Deny", "Principal": "*",
                                                    "Action": "*", "Resource": "*"}],
                   "ou-wk", sc.RCP)
        for action in ("s3:GetObject", "events:PutEvents", "codebuild:StartBuild"):
            v = sc.check_action(org, "lab", action, region="us-east-1")
            self.assertEqual(v.headline, "Blocked by RCP deny-everything", action)
        v = sc.check_action(org, "lab", "kms:RetireGrant", region="us-east-1")
        self.assertEqual(v.outcome, "allowed")        # RCPs don't apply to kms:RetireGrant
        # a service AWS Kit doesn't know RCPs cover: not checked, but said
        with mock.patch.object(pe, "RCP_SERVICES", frozenset({"s3"})):
            v = sc.check_action(org, "lab", "events:PutEvents", region="us-east-1")
        self.assertEqual(v.outcome, "allowed")
        self.assertTrue(any(ln["status"] == "warn" and "deny-everything" in ln["text"]
                            for ln in v.lines))

    def test_global_service_region_and_context_used(self):
        org = small_org()
        add_policy(org, "p-rl", "region-lock", [{
            "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}}], "ou-wk")
        v = sc.check_action(org, "lab", "organizations:DescribeOrganization")
        self.assertEqual(v.outcome, "allowed")      # organizations calls go to us-east-1
        self.assertTrue(any("global service" in c["from"] for c in v.context))

    def test_unreadable_policy_makes_it_depend(self):
        org = small_org()
        org.policies["p-x"] = sc.Policy("p-x", "mystery", error="Its text isn't known yet.")
        org.nodes["ou-wk"].policies.append("p-x")
        v = sc.check_action(org, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "depends")
        self.assertIn("the text of mystery", v.depends_on)
        self.assertEqual(v.exit_code, sc.EXIT_DEPENDS)

    def test_scps_turned_off(self):
        org = small_org(enabled=[])
        add_policy(org, "p-d", "deny-all", [{"Effect": "Deny", "Action": "*", "Resource": "*"}], "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject")
        self.assertEqual(v.outcome, "allowed")
        self.assertIn("aren't turned on", v.reason)

    def test_condition_in_allow_list(self):
        org = small_org()
        org.nodes["ou-wk"].policies.remove("p-FullAWSAccess")
        add_policy(org, "p-al", "eu-only", [{
            "Effect": "Allow", "Action": "*", "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}], "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "denied")
        self.assertIn("eu-only allows everything only when the region is eu-west-1", v.reason)
        self.assertEqual(v.no_allow_at[0]["target_id"], "ou-wk")
        v = sc.check_action(org, "lab", "s3:GetObject")
        self.assertEqual(v.outcome, "depends")
        self.assertEqual(v.depends_on, ["aws:RequestedRegion"])
        v = sc.check_action(org, "lab", "s3:GetObject", region="eu-west-1")
        self.assertEqual(v.outcome, "allowed")

    def test_if_unset_answer(self):
        org = small_org()
        add_policy(org, "p-mfa", "need-mfa", [{
            "Effect": "Deny", "Action": "ec2:*", "Resource": "*",
            "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}], "ou-wk")
        v = sc.check_action(org, "lab", "ec2:StopInstances", region="us-east-1")
        self.assertEqual(v.outcome, "depends")
        self.assertEqual(v.if_unset["outcome"], "denied")
        v = sc.check_action(org, "lab", "ec2:StopInstances", region="us-east-1",
                            context=["aws:MultiFactorAuthPresent=true"])
        self.assertEqual(v.outcome, "allowed")
        v = sc.check_action(org, "lab", "ec2:StopInstances", region="us-east-1",
                            context=["!aws:MultiFactorAuthPresent"])
        self.assertEqual(v.outcome, "denied")


class SummaryTests(unittest.TestCase):
    def test_summary_lists_denies_and_allow_lists(self):
        org = sc.load_file(DEMO)
        s = sc.summarize(org, "777777777777")
        self.assertEqual(s["limits"][0]["where"], "OU Sandbox")
        self.assertIn("FullAWSAccess isn't attached there", s["limits"][0]["text"])
        self.assertIn("lambda:*", s["limits"][0]["text"])
        texts = [d["text"] for d in s["denies"]]
        self.assertIn("Denies organizations:LeaveOrganization for everyone.", texts)
        self.assertTrue(any(d["type"] == "RCP" for d in s["denies"]))
        prod = sc.summarize(org, "555555555555")
        self.assertTrue(any("unless the caller is break-glass" in d["text"] for d in prod["denies"]))
        self.assertTrue(any("unless the region is us-east-1 or us-west-2" in d["text"]
                            for d in prod["denies"]))
        self.assertEqual(prod["limits"], [])
        self.assertTrue(sc.summarize(org, "111111111111")["exempt"])
        rows = sc.policy_rows(org, "555555555555")
        self.assertEqual([r["name"] for r in rows if r["type"] == "RCP"],
                         ["RCPFullAWSAccess", "s3-https-only"])
        self.assertIn("(here)", rows[[r["where_id"] for r in rows].index("555555555555")]["where"])


# =================================================================== Terraform input

class TerraformTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(D1.read_text())
        self.org = sc.from_terraform(self.data, "d1-org-state.json")

    def test_reads_the_d1_org(self):
        org = self.org
        self.assertEqual((org.id, org.root, org.management), ("o-a1b2c3d4e5", "r-ab12", "111111111111"))
        self.assertEqual(org.enabled, [sc.SCP])
        self.assertEqual(org.nodes["ou-ab12-wk7q2d9x"].parent, "r-ab12")
        self.assertEqual(org.nodes["222222222222"].parent, "ou-ab12-wk7q2d9x")
        self.assertTrue(org.nodes["111111111111"].guessed_parent)
        self.assertEqual(sorted(p.name for p in org.policies.values()),
                         ["FullAWSAccess", "deny-leave-org", "no-long-lived-keys", "region-lock"])
        self.assertEqual(sorted(org.nodes["ou-ab12-wk7q2d9x"].policies),
                         ["p-aaaa1111", "p-bbbb2222", "p-cccc3333"])

    def test_full_access_is_assumed_and_said(self):
        org = self.org
        for node in org.nodes.values():
            self.assertIn("p-FullAWSAccess", node.assumed)
            self.assertNotIn("p-FullAWSAccess", node.policies)
        self.assertIn("FullAWSAccess is assumed", org.notes[0])
        v = sc.check_action(org, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "allowed")
        self.assertIn("Allowed by FullAWSAccess (assumed).", [ln["text"] for ln in v.lines])
        self.assertTrue(any("FullAWSAccess is assumed" in n for n in v.notes))
        rows = sc.policy_rows(org, "222222222222")
        self.assertTrue(all(r["assumed"] for r in rows if r["name"] == "FullAWSAccess"))

    def test_verdicts(self):
        org = self.org
        v = sc.check_action(org, "lab", "ec2:RunInstances", region="eu-west-1")
        self.assertEqual((v.outcome, v.headline), ("denied", "Blocked by region-lock"))
        self.assertEqual(v.blocked_by[0]["attached_to"], "OU Workloads")
        self.assertIn("Here the region is eu-west-1.", v.reason)
        self.assertEqual(sc.check_action(org, "lab", "ec2:RunInstances", region="us-west-2").outcome,
                         "allowed")
        v = sc.check_action(org, "lab", "ec2:RunInstances")
        self.assertEqual((v.outcome, v.depends_on), ("depends", ["aws:RequestedRegion"]))
        self.assertIsNone(v.if_unset)            # a region is always set
        v = sc.check_action(org, "lab", "iam:CreateUser")
        self.assertEqual(v.headline, "Blocked by no-long-lived-keys")
        self.assertIn("it denies iam:CreateAccessKey and iam:CreateUser for everyone", v.reason)
        v = sc.check_action(org, "lab", "organizations:LeaveOrganization")
        self.assertEqual(v.blocked_by[0]["policy"], "deny-leave-org")
        v = sc.check_action(org, "111111111111", "organizations:LeaveOrganization")
        self.assertEqual((v.outcome, v.exempt), ("allowed", "management account"))

    def test_full_access_managed_in_state(self):
        mod = self.data["values"]["root_module"]["resources"]

        def attach(name, policy, target):
            mod.append({"address": f"aws_organizations_policy_attachment.{name}",
                        "mode": "managed", "type": "aws_organizations_policy_attachment",
                        "name": name, "values": {"policy_id": policy, "target_id": target}})
        attach("full_root", "p-FullAWSAccess", "r-ab12")
        attach("full_ou", "p-FullAWSAccess", "ou-ab12-wk7q2d9x")
        attach("lab_keys", "p-cccc3333", "222222222222")      # lab gets an SCP, not FullAWSAccess
        org = sc.from_terraform(self.data, "d1")
        self.assertFalse(org.nodes["222222222222"].assumed)
        self.assertEqual(org.nodes["111111111111"].assumed, ["p-FullAWSAccess"])  # no SCP at all
        self.assertTrue(any("Terraform manages FullAWSAccess" in n for n in org.notes))
        v = sc.check_action(org, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "denied")
        self.assertEqual(v.headline, "Blocked: nothing allows it at Account lab")
        self.assertIn("isn't attached there in the Terraform state", v.reason)
        everywhere = sc.from_terraform(self.data, "d1", full_access="everywhere")
        self.assertEqual(sc.check_action(everywhere, "lab", "s3:GetObject", region="us-east-1").outcome,
                         "allowed")
        bare = sc.from_terraform(json.loads(D1.read_text()), "d1", full_access="state")
        v = sc.check_action(bare, "lab", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "denied")
        self.assertIn("no SCP attached at all", v.reason)

    def test_raw_tfstate(self):
        raw = {"version": 4, "terraform_version": "1.9.0", "resources": []}
        for r in self.data["values"]["root_module"]["resources"]:
            raw["resources"].append({"mode": "managed", "type": r["type"], "name": r["name"],
                                     "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                                     "instances": [{"attributes": r["values"]}]})
        org = sc.from_terraform(raw, "raw")
        self.assertEqual(sc.check_action(org, "lab", "iam:CreateUser").outcome, "denied")

    def test_plan_with_unknown_policy_text(self):
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
            {"address": "aws_organizations_organization.this", "mode": "managed",
             "type": "aws_organizations_organization", "name": "this",
             "values": {"id": "o-exampleorg1", "master_account_id": "111111111111",
                        "enabled_policy_types": ["SERVICE_CONTROL_POLICY"],
                        "roots": [{"id": "r-ex12"}], "accounts": []}},
            {"address": "aws_organizations_organizational_unit.dev", "mode": "managed",
             "type": "aws_organizations_organizational_unit", "name": "dev",
             "values": {"name": "Dev", "parent_id": "r-ex12"}},
            {"address": "aws_organizations_policy.later", "mode": "managed",
             "type": "aws_organizations_policy", "name": "later",
             "values": {"name": "later", "type": "SERVICE_CONTROL_POLICY"}},
            {"address": "aws_organizations_policy_attachment.later", "mode": "managed",
             "type": "aws_organizations_policy_attachment", "name": "later", "values": {}},
        ]}}, "resource_changes": [
            {"address": "aws_organizations_policy.later",
             "change": {"after_unknown": {"content": True, "id": True}}},
            {"address": "aws_organizations_organizational_unit.dev",
             "change": {"after_unknown": {"id": True}}},
            {"address": "aws_organizations_policy_attachment.later",
             "change": {"after_unknown": {"policy_id": True, "target_id": True}}}],
            "configuration": {"root_module": {"resources": [
                {"address": "aws_organizations_policy_attachment.later", "expressions": {
                    "policy_id": {"references": ["aws_organizations_policy.later.id",
                                                 "aws_organizations_policy.later"]},
                    "target_id": {"references": ["aws_organizations_organizational_unit.dev.id",
                                                 "aws_organizations_organizational_unit.dev"]}}}]}}}
        org = sc.from_terraform(plan, "plan.json")
        self.assertIn("Read from a plan", " ".join(org.notes))
        ou = org.nodes["aws_organizations_organizational_unit.dev"]
        self.assertIn("aws_organizations_policy.later", ou.policies)
        self.assertIn("known yet", org.policies["aws_organizations_policy.later"].error)
        self.assertEqual(ou.parent, "r-ex12")

    def test_other_policy_types_are_left_out(self):
        mod = self.data["values"]["root_module"]["resources"]
        mod.append({"address": "aws_organizations_policy.tags", "mode": "managed",
                    "type": "aws_organizations_policy", "name": "tags",
                    "values": {"id": "p-tag11111", "name": "tags", "type": "TAG_POLICY",
                               "content": "{\"tags\": {}}"}})
        mod.append({"address": "aws_organizations_policy_attachment.tags", "mode": "managed",
                    "type": "aws_organizations_policy_attachment", "name": "tags",
                    "values": {"policy_id": "p-tag11111", "target_id": "222222222222"}})
        org = sc.from_terraform(self.data, "d1")
        self.assertNotIn("p-tag11111", org.policies)
        self.assertNotIn("p-tag11111", org.nodes["222222222222"].policies)
        self.assertEqual(sc.check_action(org, "lab", "s3:GetObject", region="us-east-1").outcome,
                         "allowed")
        self.assertTrue(any("tag policy" in n for n in org.notes))

    def test_values_of_the_wrong_type(self):
        for r in self.data["values"]["root_module"]["resources"]:
            if r["type"] == "aws_organizations_organization":
                r["values"]["accounts"] = 3
        with self.assertRaises(sc.ScpError) as cm:
            sc.from_terraform(self.data, "d1")
        self.assertIn("couldn't be read", str(cm.exception))

    def test_no_org_resources(self):
        with self.assertRaises(sc.ScpError):
            sc.from_terraform({"values": {"root_module": {"resources": []}}}, "empty")
        with self.assertRaises(sc.ScpError):
            sc.from_terraform({"something": "else"}, "odd")
        with self.assertRaises(sc.ScpError):
            sc.from_terraform([1, 2], "list")


# =================================================================== snapshots and files

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))

    def test_round_trip(self):
        org = sc.from_terraform(json.loads(D1.read_text()), "d1-org-state.json")
        path = sc.save_snapshot(org, self.dir / "org.json")
        again = sc.load_file(path)
        self.assertEqual(sorted(again.nodes), sorted(org.nodes))
        self.assertEqual(again.nodes["222222222222"].assumed, ["p-FullAWSAccess"])
        self.assertEqual(again.notes, org.notes)
        self.assertTrue(again.saved_at)
        for a, b in ((org, again),):
            va = sc.check_action(a, "lab", "ec2:RunInstances", region="eu-west-1")
            vb = sc.check_action(b, "lab", "ec2:RunInstances", region="eu-west-1")
            self.assertEqual((va.outcome, va.headline), (vb.outcome, vb.headline))
        data = json.loads(path.read_text())
        self.assertEqual((data["format"], data["format_version"]), (sc.FORMAT_NAME, 1))
        self.assertNotIn("email", path.read_text())          # no account emails kept

    def test_demo_example_loads(self):
        org = sc.load_file(DEMO)
        self.assertEqual(org.counts(), {"accounts": 6, "ous": 5, "policies": 9})
        self.assertEqual(org.enabled, [sc.RCP, sc.SCP])

    def test_files_saved_on_windows(self):
        # Notepad can save UTF-8 with a byte order mark, and Windows PowerShell 5.1 writes
        # UTF-16 with one for terraform show -json > state.json. They were "isn't JSON".
        for src, enc in ((DEMO, "utf-8-sig"), (DEMO, "utf-16"), (D1, "utf-8-sig"), (D1, "utf-16")):
            path = self.dir / f"{src.stem}-{enc}.json"
            path.write_bytes(src.read_text(encoding="utf-8").encode(enc))
            self.assertEqual(sc.load_file(path).counts(), sc.load_file(src).counts(), path.name)
        path = self.dir / "words.json"
        path.write_bytes("not json at all".encode("utf-16"))
        with self.assertRaises(sc.ScpError) as cm:
            sc.load_file(path)
        self.assertIn("isn't JSON", str(cm.exception))

    def bad(self, data, text=None):
        path = self.dir / "bad.json"
        path.write_text(json.dumps(data) if not isinstance(data, str) else data)
        with self.assertRaises(sc.ScpError) as cm:
            sc.load_file(path)
        if text:
            self.assertIn(text, str(cm.exception))

    def test_damaged_snapshots(self):
        good = sc.to_dict(sc.load_file(DEMO))
        self.bad({**good, "format_version": 99}, "newer")
        self.bad({**good, "format_version": "1"}, "format version")
        self.bad({**good, "organization": None}, "no organization")
        self.bad({**good, "nodes": "x"}, "lists")
        self.bad({**good, "nodes": [n for n in good["nodes"] if n["kind"] != "root"]}, "one root")
        self.bad({**good, "nodes": good["nodes"] + [{"id": "x", "kind": "planet"}]}, "unknown kind")
        self.bad({**good, "policies": [{"id": "p-1", "name": {"no": 1}}]}, "isn't text")
        self.bad({"format": "awskit-cloudmap", "format_version": 1}, "Cloud Map snapshot")

    def test_stray_and_looping_nodes_go_under_the_root(self):
        good = sc.to_dict(sc.load_file(DEMO))
        for n in good["nodes"]:
            if n["id"] == "ou-k3x9-prd10001":
                n["parent"] = "555555555555"           # Prod under its own account: a loop
            if n["id"] == "333333333333":
                n["parent"] = "ou-missing"
        path = self.dir / "loop.json"
        path.write_text(json.dumps(good))
        org = sc.load_file(path)
        self.assertEqual(org.nodes["333333333333"].parent, org.root)
        self.assertEqual(org.nodes["ou-k3x9-prd10001"].parent, org.root)
        self.assertTrue(any("couldn't be placed" in n for n in org.notes))
        sc.check_action(org, "shop-prod", "s3:GetObject", region="us-east-1")   # still works

    def test_bad_input_files(self):
        self.bad("not json at all", "isn't JSON")
        self.bad("{\"a\": ", "isn't valid JSON")
        self.bad("[" * 50000 + "]" * 50000)                      # not an object
        self.bad("{\"a\":" * 100000 + "1" + "}" * 100000, "nested too deeply")
        (self.dir / "bin.json").write_bytes(b"\x00\x01binary plan")
        with self.assertRaises(sc.ScpError):
            sc.load_file(self.dir / "bin.json")
        with self.assertRaises(sc.ScpError):
            sc.load_file(self.dir / "missing.json")
        with self.assertRaises(sc.ScpError):
            sc.load_file(self.dir)                               # a folder needs load_folder
        text = json.dumps(sc.to_dict(sc.load_file(DEMO)))
        with mock.patch.object(sc, "MAX_INPUT_BYTES", 10):
            self.bad(text, "over 64 MB")
        policy_text = json.dumps({"Statement": [{"Effect": "Deny", "Action": "*"}]}) + " " * 70000
        self.assertIn("over 64 KB", sc.parse_policy_text(policy_text)[1])
        self.assertIn("valid JSON", sc.parse_policy_text("{")[1])

    def test_deep_and_wide_trees(self):
        nodes = [{"id": "r-deep", "kind": "root", "name": "Root"}]
        parent = "r-deep"
        for i in range(3000):                                   # far deeper than AWS allows
            nodes.append({"id": f"ou-{i}", "kind": "ou", "name": f"ou{i}", "parent": parent})
            parent = f"ou-{i}"
        nodes.append({"id": "222222222222", "kind": "account", "name": "lab", "parent": parent})
        snap = {"format": sc.FORMAT_NAME, "format_version": 1, "nodes": nodes, "policies": [],
                "organization": {"id": "o-exampleorg1", "root": "r-deep",
                                 "enabled_policy_types": [sc.SCP]}}
        path = self.dir / "deep.json"
        path.write_text(json.dumps(snap))
        org = sc.load_file(path)
        self.assertTrue(all(len(org.path(n)) <= sc.MAX_DEPTH for n in org.nodes))
        self.assertTrue(any("couldn't be placed" in n for n in org.notes))
        self.assertIn("222222222222", sc.tree_text(org))       # no RecursionError
        kids = org.children_map()
        for n in org.nodes:
            self.assertEqual(kids.get(n, []), org.children(n))

    @unittest.skipUnless(os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_endless_input_is_cut_off(self):
        with mock.patch.object(sc, "MAX_INPUT_BYTES", 1000), \
                self.assertRaises(sc.ScpError) as cm:
            sc.load_file("/dev/zero")                           # its size says 0
        self.assertIn("over 64 MB", str(cm.exception))

    def test_load_folder_without_terraform(self):
        from awskit import tfplan
        with mock.patch.object(tfplan, "terraform_bin", return_value=None):
            with self.assertRaises(sc.ScpError) as cm:
                sc.load_folder(self.dir)
        self.assertIn("isn't installed", str(cm.exception))


# =================================================================== draft SCPs

class DraftTests(unittest.TestCase):
    def setUp(self):
        self.org = sc.load_file(DEMO)
        self.text = DRAFT.read_text()

    def test_draft_what_if(self):
        draft = sc.make_draft(self.text, "Workloads", self.org)
        self.assertEqual(draft.target, "ou-k3x9-wrk10001")
        res = "arn:aws:ec2:us-east-1:666666666666:instance/*"
        v = sc.check_action(self.org, "shop-dev", "ec2:RunInstances", res, "us-east-1",
                            context=["ec2:InstanceType=m5.4xlarge"], draft=draft)
        self.assertEqual((v.outcome, v.headline), ("denied", "Blocked by the draft SCP"))
        self.assertTrue(v.blocked_by[0]["draft"])
        self.assertEqual(v.without_draft["outcome"], "allowed")
        self.assertTrue(any(ln["draft"] for ln in v.lines))
        self.assertIn("Without the draft", v.lines[-1]["text"])
        v = sc.check_action(self.org, "shop-dev", "ec2:RunInstances", res, "us-east-1",
                            context=["ec2:InstanceType=t3.micro"], draft=draft)
        self.assertEqual(v.outcome, "allowed")
        v = sc.check_action(self.org, "shop-dev", "ec2:RunInstances", "", "us-east-1",
                            context=["ec2:InstanceType=m5.large"], draft=draft)
        self.assertEqual((v.outcome, v.depends_on), ("depends", ["the resource ARN"]))
        elsewhere = sc.make_draft(self.text, "Sandbox", self.org)
        v = sc.check_action(self.org, "shop-dev", "ec2:RunInstances", res, "us-east-1",
                            context=["ec2:InstanceType=m5.large"], draft=elsewhere)
        self.assertEqual(v.outcome, "allowed")    # not above shop-dev
        rows = sc.policy_rows(self.org, "666666666666", draft)
        self.assertIn("the draft SCP", [r["name"] for r in rows])
        self.assertTrue(any(d["draft"] for d in sc.summarize(self.org, "666666666666", draft)["denies"]))

    def test_draft_problems(self):
        for text, want in (("{ nope", "valid JSON"), ("", "Paste a policy"),
                           (json.dumps({"Statement": [{"Effect": "Deny", "Principal": "*",
                                                       "Action": "s3:*"}]}), "Principal"),
                           (json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*",
                                                       "Condition": {"StringIsh": {"a:b": "c"}}}]}),
                            "StringIsh")):
            with self.assertRaises(sc.ScpError) as cm:
                sc.make_draft(text, "root", self.org)
            self.assertIn(want, str(cm.exception))
        doc, problems, warnings = sc.check_draft(json.dumps(
            {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}))
        self.assertEqual(problems, [])
        self.assertTrue(any("No Version" in w for w in warnings))
        with self.assertRaises(sc.ScpError):
            sc.make_draft(self.text, "nowhere", self.org)

    def test_draft_with_number_sids(self):
        # Checking it raised TypeError, which left the page's "Looks fine" up with no draft
        # and turned the next org load into "Couldn't read the organization".
        text = json.dumps({"Version": "2012-10-17", "Statement": [
            {"Sid": 1, "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
            {"Sid": 1, "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]})
        _doc, problems, warnings = sc.check_draft(text)
        self.assertEqual(problems, [])
        self.assertTrue(any(w.startswith("Duplicate Sid") for w in warnings))
        v = sc.check_action(self.org, "shop-dev", "s3:DeleteBucket", region="us-east-1",
                            draft=sc.make_draft(text, "Workloads", self.org))
        self.assertEqual(v.headline, "Blocked by the draft SCP")


PAGE_CHECK = r'''
import json, os, sys
root, cfg, folder = sys.argv[1:4]
os.environ["XDG_CONFIG_HOME"] = cfg
sys.path.insert(0, root)
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib
from awskit import app, scp_page

msgs, out = [], {}
scp_page.show_message = lambda parent, heading, body="": msgs.append(f"{heading}: {body}")
a = app.App(page="scp")
DEMO = os.path.join(root, "org-scps", "examples", "demo-org.json")


def page():
    return a.get_active_window().pages["scp"]


def load():
    page().load_path(DEMO)


def ps_draft():
    s = page()
    s.draft_check.set_active(True)
    s._load_draft_file(os.path.join(folder, "draft-ps.json"))   # UTF-16, from PowerShell
    s._draft_changed(now=True)
    out["ps"] = [s.draft is not None, s.draft_status.get_text()]


def number_sids():
    page().draft_buffer.set_text(json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": 1, "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
        {"Sid": 1, "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}))


def checked():
    s = page()
    out["sids"] = [s.draft is not None, s.draft_status.get_text()]
    load()                                   # load the org again, with that draft on


def finish():
    out["reloaded"] = page().draft is not None
    out["msgs"] = msgs
    print(json.dumps(out))
    a.quit()


steps = [(300, load), (1500, ps_draft), (300, number_sids), (900, checked), (1500, finish)]


def run(i=0):
    if i < len(steps):
        ms, fn = steps[i]

        def go():
            try:
                fn()
            except Exception as exc:
                import traceback
                traceback.print_exc()
                print(json.dumps({"error": repr(exc)}))
                a.quit()
                return False
            run(i + 1)
            return False
        GLib.timeout_add(ms, go)


def start():
    if a.get_active_window() is None:
        return True
    run()
    return False


GLib.timeout_add(200, start)
a.run([])
'''


class PageTests(unittest.TestCase):
    def test_draft_files_from_windows_and_odd_drafts(self):
        import shutil
        import subprocess
        try:
            import gi
            gi.require_version("Gtk", "4.0")
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")
        folder = Path(tempfile.mkdtemp(prefix="scp-page-", dir=TMP))
        (folder / "check.py").write_text(PAGE_CHECK, encoding="utf-8")
        (folder / "draft-ps.json").write_bytes(DRAFT.read_text(encoding="utf-8").encode("utf-16"))
        cmd = [sys.executable, str(folder / "check.py"), str(ROOT), str(folder), str(folder)]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if not shutil.which("xvfb-run"):
                self.skipTest("no display and no xvfb-run")
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
        self.assertTrue(lines, r.stdout[-2000:] + r.stderr[-2000:])
        got = json.loads(lines[-1])
        self.assertNotIn("error", got)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(got["ps"][0], True, got["ps"][1])        # the UTF-16 draft opened
        self.assertTrue(got["sids"][0], got["sids"][1])           # Sid 1 twice: a warning only
        self.assertIn("Duplicate Sid", got["sids"][1])
        self.assertTrue(got["reloaded"])
        self.assertEqual(got["msgs"], [])


# =================================================================== reading AWS (moto)

class _Denied:
    """Stands in for a boto3 client the profile isn't allowed to use."""

    def can_paginate(self, method):
        return False

    def __getattr__(self, name):
        from botocore.exceptions import ClientError

        def call(*a, **k):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, name)
        return call


class _Partly:
    """A real client where some methods fail with an error code."""

    def __init__(self, real, fail):
        self.real, self.fail = real, fail

    def can_paginate(self, method):
        return method not in self.fail and self.real.can_paginate(method)

    def get_paginator(self, method):
        return self.real.get_paginator(method)

    def __getattr__(self, name):
        if name in self.fail:
            from botocore.exceptions import ClientError
            code, when = self.fail[name]

            def call(*a, **k):
                if when(k):
                    raise ClientError({"Error": {"Code": code, "Message": "no"}}, name)
                return getattr(self.real, name)(*a, **k)
            return call
        return getattr(self.real, name)


@unittest.skipIf(mock_aws is None, "moto not installed")
class LiveTests(unittest.TestCase):
    """Root
       |- deny-leave-org (SCP)
       |- Sandbox (allow list: ec2 and s3, FullAWSAccess detached)  > play
       `- Workloads (region lock, except OrganizationAccountAccessRole) > dev
           `- Prod (no s3:DeleteBucket)                              > shop"""

    def setUp(self):
        from awskit import common
        self.mock = mock_aws()
        self.mock.start()
        self.failing = {}
        self.denied = False
        real = common.AwsContext.client
        test = self

        def client(ctx, service, region=None):
            if test.denied:
                return _Denied()
            got = real(ctx, service, region)
            return _Partly(got, test.failing) if test.failing else got
        self.patch = mock.patch.object(common.AwsContext, "client", client)
        self.patch.start()
        org = boto3.client("organizations", region_name="us-east-1")
        self.org_client = org
        org.create_organization(FeatureSet="ALL")
        self.root = org.list_roots()["Roots"][0]["Id"]
        org.enable_policy_type(RootId=self.root, PolicyType="SERVICE_CONTROL_POLICY")

        def ou(name, parent):
            return org.create_organizational_unit(ParentId=parent, Name=name)["OrganizationalUnit"]["Id"]

        def account(name, parent):
            aid = org.create_account(Email=f"{name}@example.com", AccountName=name)["CreateAccountStatus"]["AccountId"]
            org.move_account(AccountId=aid, SourceParentId=self.root, DestinationParentId=parent)
            return aid

        def policy(name, statements, target):
            pid = org.create_policy(Name=name, Description="", Type="SERVICE_CONTROL_POLICY", Content=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}))["Policy"]["PolicySummary"]["Id"]
            org.attach_policy(PolicyId=pid, TargetId=target)
            return pid
        self.sandbox = ou("Sandbox", self.root)
        self.work = ou("Workloads", self.root)
        self.prod = ou("Prod", self.work)
        self.play = account("play", self.sandbox)
        self.dev = account("dev", self.work)
        self.shop = account("shop", self.prod)
        self.master = org.describe_organization()["Organization"]["MasterAccountId"]
        policy("deny-leave-org", [{"Sid": "NoLeaving", "Effect": "Deny",
                                   "Action": "organizations:LeaveOrganization", "Resource": "*"}], self.root)
        policy("sandbox-allow", [{"Effect": "Allow", "Action": ["ec2:*", "s3:*"], "Resource": "*"}],
               self.sandbox)
        org.detach_policy(PolicyId="p-FullAWSAccess", TargetId=self.sandbox)
        policy("region-lock", [{
            "Sid": "OnlyUsRegions", "Effect": "Deny", "NotAction": ["iam:*", "organizations:*", "sts:*"],
            "Resource": "*", "Condition": {
                "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]},
                "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/OrganizationAccountAccessRole"}}}],
            self.work)
        policy("prod-no-deletes", [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}],
               self.prod)

    def tearDown(self):
        self.patch.stop()
        self.mock.stop()

    def read(self, **kw):
        return sc.read_live(None, **kw)

    def test_reads_the_tree_and_attachments(self):
        org = self.read()
        self.assertEqual(org.enabled, [sc.SCP])
        self.assertEqual(org.management, self.master)
        self.assertEqual(org.nodes[self.prod].parent, self.work)
        self.assertEqual(org.nodes[self.shop].parent, self.prod)
        names = {n: sorted(p.name for p, _ in org.attached(n)) for n in org.nodes}
        self.assertEqual(names[self.root], ["FullAWSAccess", "deny-leave-org"])
        self.assertEqual(names[self.sandbox], ["sandbox-allow"])
        self.assertEqual(names[self.prod], ["FullAWSAccess", "prod-no-deletes"])
        self.assertIn("Allow", org.policies["p-FullAWSAccess"].text)
        self.assertEqual(org.notes, [])

    def test_both_ways_of_reading_attachments_agree(self):
        a = self.read(attachments="by-policy")
        b = self.read(attachments="by-target")
        self.assertEqual({k: sorted(n.policies) for k, n in a.nodes.items()},
                         {k: sorted(n.policies) for k, n in b.nodes.items()})

    def test_progress_and_cancel(self):
        seen = []
        self.read(progress=lambda done, total, text: seen.append((done, total)))
        self.assertTrue(seen and all(d <= t for d, t in seen))
        stop = threading.Event()
        stop.set()
        with self.assertRaises(sc.Cancelled):
            self.read(cancel=stop)

    def test_inheritance(self):
        org = self.read()
        v = sc.check_action(org, "dev", "organizations:LeaveOrganization")      # deny at the root
        self.assertEqual((v.outcome, v.blocked_by[0]["attached_to"]), ("denied", "Root"))
        self.assertEqual(v.blocked_by[0]["sid"], "NoLeaving")
        self.assertEqual(v.exit_code, sc.EXIT_DENIED)
        v = sc.check_action(org, "shop", "s3:DeleteBucket", region="us-east-1")  # deny at an OU
        self.assertEqual((v.outcome, v.blocked_by[0]["attached_to"]), ("denied", "OU Prod"))
        v = sc.check_action(org, "dev", "s3:DeleteBucket", region="us-east-1")   # not above dev
        self.assertEqual(v.outcome, "allowed")
        self.assertEqual(v.exit_code, sc.EXIT_ALLOWED)

    def test_allow_list_without_full_access(self):
        org = self.read()
        v = sc.check_action(org, "play", "lambda:CreateFunction", region="us-east-1")
        self.assertEqual(v.outcome, "denied")
        self.assertEqual(v.headline, "Blocked: nothing allows it at OU Sandbox")
        self.assertIn("OU Sandbox has no SCP that allows lambda:CreateFunction; FullAWSAccess was "
                      "removed there.", v.reason)
        self.assertEqual(v.no_allow_at[0]["target_id"], self.sandbox)
        self.assertEqual(sc.check_action(org, "play", "s3:PutObject", region="us-east-1").outcome,
                         "allowed")
        limits = sc.summarize(org, self.play)["limits"]
        self.assertEqual(limits[0]["where"], "OU Sandbox")

    def test_management_account_is_exempt(self):
        org = self.read()
        v = sc.check_action(org, self.master, "organizations:LeaveOrganization")
        self.assertEqual((v.outcome, v.exempt), ("allowed", "management account"))

    def test_region_lock_and_role_exception(self):
        org = self.read()
        role = f"arn:aws:iam::{self.dev}:role/OrganizationAccountAccessRole"
        v = sc.check_action(org, "dev", "ec2:RunInstances", region="eu-west-1",
                            principal=f"arn:aws:iam::{self.dev}:role/deploy")
        self.assertEqual(v.headline, "Blocked by region-lock")
        self.assertIn("unless the region is us-east-1 or us-west-2, or the caller is "
                      "OrganizationAccountAccessRole", v.reason)
        self.assertEqual(sc.check_action(org, "dev", "ec2:RunInstances", region="eu-west-1",
                                         principal=role).outcome, "allowed")
        self.assertEqual(sc.check_action(org, "dev", "ec2:RunInstances", region="us-west-2").outcome,
                         "allowed")
        v = sc.check_action(org, "dev", "ec2:RunInstances", region="eu-west-1")
        self.assertEqual((v.outcome, v.depends_on), ("depends", ["aws:PrincipalArn"]))
        self.assertIn("Give a principal ARN to test it.", v.reason)
        self.assertEqual(v.exit_code, sc.EXIT_DEPENDS)
        v = sc.check_action(org, "dev", "ec2:RunInstances")
        self.assertEqual(v.depends_on, ["aws:RequestedRegion", "aws:PrincipalArn"])
        self.assertEqual(sc.check_action(org, "dev", "iam:CreateRole", region="eu-west-1").outcome,
                         "allowed")   # NotAction leaves IAM out

    def test_service_linked_roles_are_exempt(self):
        org = self.read()
        slr = (f"arn:aws:iam::{self.dev}:role/aws-service-role/autoscaling.amazonaws.com/"
               "AWSServiceRoleForAutoScaling")
        v = sc.check_action(org, "dev", "ec2:RunInstances", region="eu-west-1", principal=slr)
        self.assertEqual((v.outcome, v.exempt), ("allowed", "service-linked role"))

    def test_draft_what_if(self):
        org = self.read()
        draft = sc.make_draft(json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"}]}), "Prod", org)
        v = sc.check_action(org, "shop", "ec2:TerminateInstances", region="us-east-1", draft=draft)
        self.assertEqual((v.outcome, v.without_draft["outcome"]), ("denied", "allowed"))
        self.assertEqual(sc.check_action(org, "dev", "ec2:TerminateInstances", region="us-east-1",
                                         draft=draft).outcome, "allowed")

    def test_rcps(self):
        self.org_client.enable_policy_type(RootId=self.root, PolicyType="RESOURCE_CONTROL_POLICY")
        pid = self.org_client.create_policy(
            Name="s3-https-only", Description="", Type="RESOURCE_CONTROL_POLICY",
            Content=json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))["Policy"]["PolicySummary"]["Id"]
        self.org_client.attach_policy(PolicyId=pid, TargetId=self.work)
        org = self.read()
        self.assertIn(sc.RCP, org.enabled)
        self.assertEqual(org.policies[pid].type, sc.RCP)
        v = sc.check_action(org, "dev", "s3:GetObject", "arn:aws:s3:::dev-bucket/key", "us-east-1",
                            context=["aws:SecureTransport=false"])
        self.assertEqual(v.headline, "Blocked by RCP s3-https-only")
        self.assertEqual(sc.check_action(org, "dev", "s3:GetObject", region="us-east-1").outcome,
                         "allowed")   # HTTPS is the default
        self.assertEqual(sc.check_action(org, "dev", "ec2:RunInstances", region="us-east-1").outcome,
                         "allowed")   # RCPs don't cover EC2
        # the bucket is in the management account, whose resources RCPs don't cover
        v = sc.check_action(org, "dev", "s3:GetObject", region="us-east-1",
                            context=["aws:SecureTransport=false", f"aws:ResourceAccount={self.master}"])
        self.assertEqual(v.outcome, "allowed")
        self.assertTrue(any("management account" in ln["text"] for ln in v.lines))
        # in an account outside the org, RCPs don't apply either
        v = sc.check_action(org, "dev", "s3:GetObject", region="us-east-1",
                            context=["aws:SecureTransport=false", "aws:ResourceAccount=999999999999"])
        self.assertEqual(v.outcome, "allowed")

    def test_rcps_unreadable_quietly(self):
        self.org_client.enable_policy_type(RootId=self.root, PolicyType="RESOURCE_CONTROL_POLICY")
        self.failing = {"list_policies": ("InvalidInputException",
                                       lambda k: k.get("Filter") == "RESOURCE_CONTROL_POLICY")}
        org = self.read()
        self.assertIn(sc.RCP, org.unreadable)
        self.assertTrue(any("RCPs weren't checked" in n for n in org.notes))
        v = sc.check_action(org, "dev", "s3:GetObject", region="us-east-1")
        self.assertTrue(any(ln["status"] == "warn" for ln in v.lines))
        self.assertEqual(v.outcome, "depends")       # an unread RCP could block it
        self.assertEqual(sc.check_action(org, "dev", "ec2:RunInstances",
                                         region="us-east-1").outcome, "allowed")

    def test_describe_policy_denied(self):
        self.failing = {"describe_policy": ("AccessDeniedException",
                                         lambda k: k.get("PolicyId") != "p-FullAWSAccess")}
        org = self.read()
        self.assertTrue(any("Couldn't read the text" in n for n in org.notes))
        v = sc.check_action(org, "dev", "organizations:LeaveOrganization")
        self.assertEqual(v.outcome, "depends")
        self.assertIn("the text of deny-leave-org", v.depends_on)

    def test_no_permission(self):
        self.denied = True
        with self.assertRaises(sc.ScpError) as cm:
            self.read()
        self.assertIn("management account or a delegated administrator", str(cm.exception))

    def test_member_account(self):
        self.failing = {"list_roots": ("AccessDeniedException", lambda k: True)}
        with mock.patch.object(sc.AwsContext, "account", new_callable=mock.PropertyMock,
                               return_value=self.dev):
            with self.assertRaises(sc.ScpError) as cm:
                self.read()
        self.assertIn(f"signed in to account {self.dev}, a member account", str(cm.exception))
        self.assertIn(f"management account ({self.master})", str(cm.exception))

    def test_attachments_unreadable_are_noted(self):
        self.failing = {"list_targets_for_policy": ("AccessDeniedException", lambda k: True)}
        org = self.read(attachments="by-policy")
        self.assertTrue(any("Couldn't read where" in n and "region-lock" in n for n in org.notes))

    def test_unread_attachments_never_say_allowed(self):
        lock = next(p.id for p in self.read().policies.values() if p.name == "region-lock")
        self.failing = {"list_targets_for_policy": ("AccessDeniedException",
                                                 lambda k: k.get("PolicyId") == lock)}
        org = self.read(attachments="by-policy")
        self.assertEqual(org.unplaced, [lock])
        v = sc.check_action(org, "dev", "ec2:RunInstances", region="eu-west-1",
                            principal=f"arn:aws:iam::{self.dev}:role/deploy")
        self.assertEqual(v.outcome, "depends")       # region-lock could be attached above dev
        self.assertIn("where region-lock is attached", v.depends_on)
        self.assertTrue(any(ln["status"] == "warn" for ln in v.lines))
        # a policy that can't block this one doesn't get in the way
        self.assertEqual(sc.check_action(org, "dev", "iam:CreateRole", region="eu-west-1").outcome,
                         "allowed")
        # and the snapshot keeps it
        again = sc.from_dict(json.loads(sc.dumps(org)))
        self.assertEqual(again.unplaced, [lock])
        self.failing = {"list_policies_for_target": ("AccessDeniedException",
                                                  lambda k: k.get("TargetId") == self.work)}
        org = self.read(attachments="by-target")
        self.assertEqual(org.unread_targets, [self.work])
        v = sc.check_action(org, "dev", "s3:GetObject", region="us-east-1")
        self.assertEqual(v.outcome, "depends")
        self.assertEqual(sc.check_action(org, "play", "s3:GetObject", region="us-east-1").outcome,
                         "allowed")                  # Sandbox isn't under Workloads

    def test_not_in_an_organization(self):
        self.patch.stop()
        self.mock.stop()
        self.mock = mock_aws()
        self.mock.start()
        self.patch.start()
        with self.assertRaises(sc.ScpError) as cm:
            self.read()
        self.assertIn("isn't in an organization", str(cm.exception))

    def test_cli_reads_live(self):
        rc, out, _ = run_cli(["scp", "tree", "-q"])
        self.assertEqual(rc, 0)
        self.assertIn("Sandbox (OU)", out)
        path = Path(tempfile.mkdtemp(dir=TMP)) / "live.json"
        rc, out, _ = run_cli(["scp", "save", str(path), "-q"])
        self.assertEqual(rc, 0)
        rc, out, _ = run_cli(["scp", "test", "play", "lambda:CreateFunction", str(path), "-r", "us-east-1"])
        self.assertEqual(rc, sc.EXIT_DENIED)
        self.assertIn("nothing allows it at OU Sandbox", out)


# =================================================================== command line

class CliTests(unittest.TestCase):
    def test_tree_and_show(self):
        rc, out, _ = run_cli(["scp", "tree", str(D1)])
        self.assertEqual(rc, 0)
        self.assertIn("Workloads (OU)", out)
        self.assertIn("FullAWSAccess*", out)
        self.assertIn("FullAWSAccess is assumed", out)
        rc, out, _ = run_cli(["scp", "tree", str(D1), "--json"])
        self.assertEqual(json.loads(out)["format"], sc.FORMAT_NAME)
        rc, out, _ = run_cli(["scp", "show", "Workloads", str(D1)])
        self.assertEqual(rc, 0)
        self.assertIn("What's blocked here", out)
        self.assertIn("unless the region is us-west-2 or us-east-1", out)
        rc, out, _ = run_cli(["scp", "show", "lab", str(D1), "--json"])
        self.assertEqual(json.loads(out)["node"]["id"], "222222222222")

    def test_exit_codes(self):
        rc, out, _ = run_cli(["scp", "test", "lab", "ec2:RunInstances", "--region", "eu-west-1", str(D1)])
        self.assertEqual(rc, sc.EXIT_DENIED)
        self.assertIn("Blocked by region-lock", out)
        rc, out, _ = run_cli(["scp", "test", "lab", "ec2:RunInstances", str(D1), "-r", "us-east-1"])
        self.assertEqual(rc, sc.EXIT_ALLOWED)
        rc, out, _ = run_cli(["scp", "test", "lab", "ec2:RunInstances", str(D1)])
        self.assertEqual(rc, sc.EXIT_DEPENDS)
        rc, _, err = run_cli(["scp", "test", "nobody", "ec2:RunInstances", str(D1)])
        self.assertEqual(rc, sc.EXIT_ERROR)
        self.assertIn("No account called nobody", err)
        rc, _, err = run_cli(["scp", "test", "lab", "ec2:*", str(D1)])
        self.assertEqual(rc, sc.EXIT_ERROR)
        rc, _, err = run_cli(["scp", "test", "lab", "s3:GetObject", "/no/such/file.json"])
        self.assertEqual(rc, sc.EXIT_ERROR)
        rc, _, err = run_cli(["scp", "test", "lab", "s3:GetObject", str(D1), "--attach", "root"])
        self.assertEqual(rc, sc.EXIT_ERROR)

    def test_json_context_and_draft(self):
        rc, out, _ = run_cli(["scp", "test", "shop-dev", "ec2:RunInstances", str(DEMO),
                              "--resource", "arn:aws:ec2:us-east-1:666666666666:instance/*",
                              "--region", "us-east-1", "--context", "ec2:InstanceType=m5.large",
                              "--draft", str(DRAFT), "--attach", "Workloads", "--json"])
        self.assertEqual(rc, sc.EXIT_DENIED)
        data = json.loads(out)
        self.assertEqual(data["headline"], "Blocked by the draft SCP")
        self.assertEqual(data["without_draft"]["outcome"], "allowed")
        self.assertIn({"key": "ec2:InstanceType", "value": "m5.large", "from": "you gave it"},
                      data["context"])
        rc, out, _ = run_cli(["scp", "test", "shop-prod", "s3:DeleteBucket", str(DEMO),
                              "--principal", "arn:aws:iam::555555555555:role/break-glass",
                              "-r", "us-east-1"])
        self.assertEqual(rc, sc.EXIT_ALLOWED)
        bad = Path(tempfile.mkdtemp(dir=TMP)) / "draft.json"
        bad.write_text("{not json")
        rc, _, err = run_cli(["scp", "test", "shop-dev", "ec2:RunInstances", str(DEMO),
                              "--draft", str(bad)])
        self.assertEqual(rc, sc.EXIT_ERROR)
        self.assertIn("draft SCP has problems", err)
        ps = bad.with_name("draft-ps.json")         # Windows PowerShell's > writes UTF-16
        ps.write_bytes(DRAFT.read_text(encoding="utf-8").encode("utf-16"))
        rc, out, err = run_cli(["scp", "test", "shop-dev", "ec2:RunInstances", str(DEMO),
                                "--resource", "arn:aws:ec2:us-east-1:666666666666:instance/*",
                                "--region", "us-east-1", "--context", "ec2:InstanceType=m5.large",
                                "--draft", str(ps), "--attach", "Workloads"])
        self.assertEqual(rc, sc.EXIT_DENIED, err)
        self.assertIn("Blocked by the draft SCP", out)

    def test_save_from_a_state(self):
        path = Path(tempfile.mkdtemp(dir=TMP)) / "snap.json"
        rc, out, _ = run_cli(["scp", "save", str(path), str(D1)])
        self.assertEqual(rc, 0)
        self.assertIn("Saved 2 accounts", out)
        rc, out, _ = run_cli(["scp", "test", "lab", "iam:CreateUser", str(path)])
        self.assertEqual(rc, sc.EXIT_DENIED)

    def test_help_mentions_exit_codes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            from awskit import cli
            cli.main(["scp", "--help"])
        self.assertIn("3 blocked", out.getvalue())


if __name__ == "__main__":
    unittest.main()
