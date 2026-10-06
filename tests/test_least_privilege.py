"""Tests for Least Privilege: event to action mapping, resource scoping, the draft policy,
reading Event history (with LookupEvents patched), reading CloudTrail files, comparing with
the current policies (moto for IAM, last accessed data patched), and the command line.

Run from the repo root:  python3 -m unittest tests.test_least_privilege -v

moto has no CloudTrail LookupEvents or IAM last accessed details, so those client methods
are replaced with fakes here. Every account, role, bucket and key is made up.
"""
import argparse
import contextlib
import gzip
import io
import json
import os
import random
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
# test_tools sets up the fake AWS environment and a temp config folder. Every test file
# shares that one, since awskit reads XDG_CONFIG_HOME once, when it's first imported.
import test_tools  # noqa: E402

TMP = test_tools.TMP
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

from awskit import cli, iampolicy, trail  # noqa: E402
from awskit import leastpriv as lp  # noqa: E402

try:
    import boto3
    from botocore.exceptions import ClientError
    from moto import mock_aws
except ImportError:  # pragma: no cover
    boto3 = mock_aws = None
    ClientError = Exception

SAMPLE = ROOT / "least-privilege" / "examples" / "lab-deployer-trail.json"
ACCOUNT = "111111111111"
ROLE = "lab-deployer"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/{ROLE}"
NOW = datetime.now(timezone.utc).replace(microsecond=0)
_ids = iter(range(1, 10 ** 9))


# ------------------------------------------------------------------ hand-made events

def role_ident(role=ROLE, session="s1", account=ACCOUNT, path="/"):
    return {"type": "AssumedRole",
            "principalId": f"AROAEXAMPLE:{session}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
            "accountId": account,
            "sessionContext": {"sessionIssuer": {
                "type": "Role", "arn": f"arn:aws:iam::{account}:role{path}{role}",
                "accountId": account, "userName": role}}}


def user_ident(name="lab-user", account=ACCOUNT):
    return {"type": "IAMUser", "arn": f"arn:aws:iam::{account}:user/{name}",
            "accountId": account, "userName": name}


def rec(source, name, params=None, region="us-east-1", ident=None, error=None, message=None,
        resources=None, response=None, etype="AwsApiCall", when=None, account=ACCOUNT,
        data=False):
    r = {"eventVersion": "1.09", "userIdentity": ident or role_ident(account=account),
         "eventTime": (when or NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "eventSource": f"{source}.amazonaws.com", "eventName": name, "awsRegion": region,
         "sourceIPAddress": "203.0.113.10", "requestParameters": params,
         "responseElements": response, "eventID": f"00000000-0000-4000-8000-{next(_ids):012d}",
         "eventType": etype, "recipientAccountId": account, "managementEvent": not data,
         "eventCategory": "Data" if data else "Management"}
    if resources:
        r["resources"] = resources
    if error:
        r["errorCode"] = error
        r["errorMessage"] = message or ""
    return r


def assume(session, by=None, role_arn=ROLE_ARN, region="us-east-1", when=None, error=None,
           account=ACCOUNT, tags=None):
    """Someone assuming the role, the way STS records it."""
    params = {"roleArn": role_arn, "roleSessionName": session}
    if tags:
        params["tags"] = tags
    resp = None if error else {"assumedRoleUser": {
        "arn": f"arn:aws:sts::{account}:assumed-role/{role_arn.rsplit('/', 1)[-1]}/{session}"}}
    return rec("sts", "AssumeRole", params, region, by or user_ident(account=account),
               error=error, response=resp, when=when, account=account,
               resources=[{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account}])


def ev(record):
    return trail.parse_event({"CloudTrailEvent": json.dumps(record)}, record.get("awsRegion", ""))


PRINCIPAL = lp.Principal("role", ROLE, ROLE_ARN, ACCOUNT)


def draft(records, principal=PRINCIPAL, current=None, source="files", **options):
    act = lp.collect([ev(r) for r in records], principal)
    info = lp.ReadInfo(source, "files" if source == "files" else "quick",
                       ["us-east-1"] if source == "aws" else [])
    return lp.Result(principal, info, act, current, lp.Options(**options), 30,
                     NOW - timedelta(days=30))


def actions_of(result):
    return sorted({a for s in result.statements for a in s["actions"]})


def statements_with(doc, action):
    return [s for s in doc["Statement"] if action in iampolicy.as_list(s["Action"])]


def resources_of(doc, action):
    out = set()
    for s in statements_with(doc, action):
        out |= set(iampolicy.as_list(s["Resource"]))
    return out


def one(source, name, params=None, **kw):
    """The draft's resources for one action from a single call."""
    res = draft([rec(source, name, params, **kw)])
    return res


# ------------------------------------------------------------------ mapping

class MappingTests(unittest.TestCase):
    def mapped(self, source, name, params=None, **kw):
        m = lp.map_event(rec(source, name, params, **kw), PRINCIPAL)
        return m

    def test_service_prefix_exceptions(self):
        for source, name, action in (("monitoring", "PutMetricAlarm", "cloudwatch:PutMetricAlarm"),
                                     ("email", "SendEmail", "ses:SendEmail"),
                                     ("tagging", "GetResources", "tag:GetResources"),
                                     ("ec2", "DescribeVpcs", "ec2:DescribeVpcs"),
                                     ("sts", "AssumeRole", "sts:AssumeRole")):
            with self.subTest(source=source):
                m = self.mapped(source, name)
                self.assertEqual(m.status, "ok")
                self.assertEqual(m.uses[0][0], action)

    def test_s3_name_mismatches(self):
        cases = {"ListObjects": "s3:ListBucket", "ListObjectsV2": "s3:ListBucket",
                 "HeadObject": "s3:GetObject", "HeadBucket": "s3:ListBucket",
                 "ListBuckets": "s3:ListAllMyBuckets", "GetBucketLocation": "s3:GetBucketLocation",
                 "ListObjectVersions": "s3:ListBucketVersions", "DeleteObjects": "s3:DeleteObject",
                 "CreateMultipartUpload": "s3:PutObject", "UploadPart": "s3:PutObject",
                 "GetBucketEncryption": "s3:GetEncryptionConfiguration",
                 "DeleteBucketLifecycle": "s3:PutLifecycleConfiguration",
                 "GetBucketCors": "s3:GetBucketCORS", "ListParts": "s3:ListMultipartUploadParts",
                 "PutObjectLockConfiguration": "s3:PutBucketObjectLockConfiguration"}
        for name, action in cases.items():
            with self.subTest(name=name):
                m = self.mapped("s3", name, {"bucketName": "example-bucket"})
                self.assertEqual([a for a, _ in m.uses][0], action)

    def test_lambda_api_version_suffixes_and_invoke(self):
        for name, action in (("GetFunction20150331v2", "lambda:GetFunction"),
                             ("UpdateFunctionCode20150331v2", "lambda:UpdateFunctionCode"),
                             ("ListFunctions20150331", "lambda:ListFunctions"),
                             ("CreateFunction20150331", "lambda:CreateFunction"),
                             ("Invoke", "lambda:InvokeFunction"),
                             ("GetFunctionUrlConfig", "lambda:GetFunctionUrlConfig")):
            with self.subTest(name=name):
                self.assertEqual(self.mapped("lambda", name, {"functionName": "f"}).uses[0][0],
                                 action)

    def test_strip_version_leaves_normal_names_alone(self):
        self.assertEqual(lp.strip_version("ListObjectsV2"), "ListObjectsV2")
        self.assertEqual(lp.strip_version("GetObject"), "GetObject")
        self.assertEqual(lp.strip_version("CreateDistribution2020_05_31"), "CreateDistribution")
        self.assertEqual(lp.strip_version("AddPermission20150331v2"), "AddPermission")

    def test_kms_reencrypt_needs_two_actions(self):
        m = self.mapped("kms", "ReEncrypt")
        self.assertEqual([a for a, _ in m.uses], ["kms:ReEncryptFrom", "kms:ReEncryptTo"])

    def test_copy_object_reads_the_source_too(self):
        m = self.mapped("s3", "CopyObject", {"bucketName": "dest-bucket",
                                             "x-amz-copy-source": "src-bucket/a/b.txt"})
        self.assertIn(("s3:PutObject", {"arn:aws:s3:::dest-bucket/*"}), m.uses)
        self.assertIn(("s3:GetObject", {"arn:aws:s3:::src-bucket/*"}), m.uses)

    def test_unknown_service_and_unmappable_calls_are_listed_not_guessed(self):
        records = [rec("madeup", "DoThing"), rec("apigateway", "GetRestApis"),
                   rec("dynamodb", "TransactWriteItems", {"transactItems": []}),
                   rec("dynamodb", "ExecuteStatement", {"statement": "x"}),
                   rec("s3", "Get Object", {"bucketName": "b"}),
                   rec("s3", "ListBuckets")]
        r = draft(records)
        self.assertEqual(actions_of(r), ["s3:ListAllMyBuckets"])
        rows = {(u["source"], u["event"]): u["why"] for u in r.unmapped_rows()}
        self.assertIn(("madeup.amazonaws.com", "DoThing"), rows)
        self.assertIn("service table", rows[("madeup.amazonaws.com", "DoThing")])
        self.assertIn("HTTP methods", rows[("apigateway.amazonaws.com", "GetRestApis")])
        self.assertIn(("dynamodb.amazonaws.com", "TransactWriteItems"), rows)
        self.assertIn("PartiQL", rows[("dynamodb.amazonaws.com", "ExecuteStatement")])
        self.assertIn(("s3.amazonaws.com", "Get Object"), rows)
        self.assertFalse(any("madeup" in json.dumps(s) for s in r.doc["Statement"]))

    def test_events_a_policy_doesnt_control_are_skipped(self):
        records = [rec("kms", "RotateKey", etype="AwsServiceEvent"),
                   rec("signin", "ConsoleLogin", etype="AwsConsoleSignIn"),
                   rec("signin", "ConsoleLogin"),
                   rec("sts", "GetCallerIdentity"),
                   rec("s3", "ListBuckets")]
        r = draft(records)
        self.assertEqual(actions_of(r), ["s3:ListAllMyBuckets"])
        self.assertEqual(r.activity.skipped["AWS service events"], 1)
        self.assertEqual(r.activity.skipped["console sign-ins"], 2)
        self.assertEqual(r.activity.skipped["calls that need no permission"], 1)
        self.assertTrue(any("Left out 4 events" in n for n in r.notes()))

    def test_being_assumed_isnt_a_call_but_assuming_another_role_is(self):
        other = f"arn:aws:iam::{ACCOUNT}:role/deploy-helper"
        records = [assume("s1"), assume("s2", by={"type": "AWSService",
                                                  "invokedBy": "lambda.amazonaws.com"}),
                   assume("s9", error="AccessDenied"),
                   assume("helper", by=role_ident(), role_arn=other, tags=[{"key": "team",
                                                                           "value": "lab"}])]
        r = draft(records)
        self.assertEqual(r.activity.assumed, 2)
        self.assertEqual(set(r.activity.sessions), {"s1", "s2"})
        self.assertEqual(resources_of(r.doc, "sts:AssumeRole"), {other})
        self.assertEqual(resources_of(r.doc, "sts:TagSession"), {other})

    def test_only_the_principals_own_calls_count(self):
        records = [rec("s3", "ListBuckets"),
                   rec("ec2", "DescribeVpcs", ident=role_ident("ci-runner")),
                   rec("ec2", "DescribeSubnets", ident=role_ident(account="222222222222"),
                       account="222222222222"),
                   rec("ec2", "DescribeImages", ident=user_ident(ROLE)),
                   rec("iam", "ListRoles", ident={"type": "Root",
                                                  "arn": f"arn:aws:iam::{ACCOUNT}:root",
                                                  "accountId": ACCOUNT})]
        r = draft(records)
        self.assertEqual(actions_of(r), ["s3:ListAllMyBuckets"])
        self.assertEqual(r.activity.others, 4)

    def test_role_with_a_path_still_matches_by_name(self):
        records = [rec("s3", "ListBuckets", ident=role_ident(path="/service-role/"))]
        self.assertEqual(actions_of(draft(records)), ["s3:ListAllMyBuckets"])

    def test_iam_user_principal(self):
        user = lp.Principal("user", "lab-user", f"arn:aws:iam::{ACCOUNT}:user/lab-user", ACCOUNT)
        records = [rec("s3", "ListBuckets", ident=user_ident()),
                   rec("ec2", "DescribeVpcs", ident=role_ident("lab-user"))]
        r = draft(records, principal=user)
        self.assertEqual(actions_of(r), ["s3:ListAllMyBuckets"])

    def test_bad_credentials_are_skipped_and_other_errors_still_count(self):
        records = [rec("s3", "ListBuckets", error="InvalidClientTokenId"),
                   rec("iam", "GetRole", {"roleName": "gone"}, error="NoSuchEntity")]
        r = draft(records)
        self.assertEqual(actions_of(r), ["iam:GetRole"])
        self.assertEqual(r.activity.skipped["calls with bad or expired credentials"], 1)

    def test_parse_principal(self):
        self.assertEqual(lp.parse_principal(ROLE_ARN).kind, "role")
        self.assertEqual(lp.parse_principal(f"arn:aws:iam::{ACCOUNT}:role/a/b/name").name, "name")
        u = lp.parse_principal(f"arn:aws:iam::{ACCOUNT}:user/lab-user")
        self.assertEqual((u.kind, u.name, u.account), ("user", "lab-user", ACCOUNT))
        s = lp.parse_principal(f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/s1")
        self.assertEqual((s.kind, s.name, s.arn), ("role", ROLE, ""))
        self.assertEqual(lp.parse_principal("user/bob").kind, "user")
        self.assertEqual(lp.parse_principal("bob").kind, "")
        for bad in ("", "root", f"arn:aws:iam::{ACCOUNT}:root", "arn:aws:s3:::bucket",
                    "has space", "a;b"):
            with self.subTest(bad=bad), self.assertRaises(lp.LeastPrivError):
                lp.parse_principal(bad)


# ------------------------------------------------------------------ denied

class DeniedTests(unittest.TestCase):
    MSG = (f"User: arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/s1 is not authorized to perform: "
           "s3:PutBucketPolicy on resource: \"arn:aws:s3:::example-site\" because no "
           "identity-based policy allows the s3:PutBucketPolicy action")

    def records(self):
        return [rec("s3", "ListBuckets"),
                rec("s3", "PutBucketPolicy", {"bucketName": "example-site"}, error="AccessDenied",
                    message=self.MSG),
                rec("ec2", "TerminateInstances",
                    {"instancesSet": {"items": [{"instanceId": "i-0abc1234def567890"}]}},
                    error="Client.UnauthorizedOperation",
                    message="You are not authorized to perform this operation. Encoded "
                            "authorization failure message: SECRETBLOB"),
                rec("kms", "Decrypt", error="AccessDeniedException"),
                rec("sns", "Publish", {"topicArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:t"},
                    error="AuthorizationError"),
                rec("lambda", "CreateFunction20150331", {"functionName": "f", "role":
                                                         f"arn:aws:iam::{ACCOUNT}:role/x"},
                    error="AccessDeniedException")]

    def test_denied_calls_are_listed_but_not_in_the_draft(self):
        r = draft(self.records())
        self.assertEqual(actions_of(r), ["s3:ListAllMyBuckets"])
        denied = {row["full"]: row for row in r.denied_rows()}
        self.assertEqual(set(denied), {"s3:PutBucketPolicy", "ec2:TerminateInstances",
                                       "kms:Decrypt", "sns:Publish", "lambda:CreateFunction"})
        self.assertIn("Missing permission: s3:PutBucketPolicy on arn:aws:s3:::example-site",
                      denied["s3:PutBucketPolicy"]["message"])
        self.assertIn("decode-authorization-message", denied["ec2:TerminateInstances"]["message"])
        self.assertNotIn("SECRETBLOB", denied["ec2:TerminateInstances"]["message"])
        self.assertNotIn(("iam:PassRole", ""), r.activity.implied)  # denied calls imply nothing
        rows = {row["full"]: row for row in r.rows()}
        self.assertEqual(rows["s3:PutBucketPolicy"]["calls_text"], "1 denied")
        self.assertTrue(rows["s3:PutBucketPolicy"]["_dim"])

    def test_check_box_adds_them(self):
        r = draft(self.records(), include_denied=True)
        self.assertIn("s3:PutBucketPolicy", actions_of(r))
        sids = [s["Sid"] for s in statements_with(r.doc, "s3:PutBucketPolicy")]
        self.assertTrue(all(s.startswith("PreviouslyDenied") for s in sids))
        self.assertEqual(resources_of(r.doc, "s3:PutBucketPolicy"), {"arn:aws:s3:::example-site"})

    def test_denied_codes(self):
        for code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                     "Client.UnauthorizedOperation", "AuthorizationError",
                     "KMS.AccessDeniedException", "UnauthorizedException"):
            self.assertTrue(lp.is_denied_code(code), code)
        for code in ("", "NoSuchEntity", "ThrottlingException", "ValidationException"):
            self.assertFalse(lp.is_denied_code(code), code)


# ------------------------------------------------------------------ resources

class ResourceTests(unittest.TestCase):
    def res(self, source, name, params=None, action=None, **kw):
        m = lp.map_event(rec(source, name, params, **kw), PRINCIPAL)
        self.assertEqual(m.status, "ok", m.reason)
        uses = dict(m.uses)
        return uses[action] if action else list(uses.values())[0]

    def test_s3(self):
        self.assertEqual(self.res("s3", "ListObjectsV2", {"bucketName": "site"}),
                         {"arn:aws:s3:::site"})
        self.assertEqual(self.res("s3", "PutObject", {"bucketName": "site", "key": "a/b"}),
                         {"arn:aws:s3:::site/*"})
        self.assertEqual(self.res("s3", "GetObjectAcl", {"bucketName": "site"}),
                         {"arn:aws:s3:::site/*"})
        self.assertEqual(self.res("s3", "GetBucketPolicy", {"bucketName": "site"}),
                         {"arn:aws:s3:::site"})
        self.assertEqual(self.res("s3", "PutObjectLockConfiguration", {"bucketName": "site"}),
                         {"arn:aws:s3:::site"})
        self.assertEqual(self.res("s3", "ListBuckets"), {"*"})
        self.assertEqual(self.res("s3", "GetObject", {"key": "x"}), {"*"})

    def test_dynamodb(self):
        table = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders"
        self.assertEqual(self.res("dynamodb", "DescribeTable", {"tableName": "orders"}), {table})
        self.assertEqual(self.res("dynamodb", "Query", {"tableName": "orders",
                                                        "indexName": "by-date"}),
                         {table, table + "/index/by-date"})
        self.assertEqual(self.res("dynamodb", "BatchWriteItem", {"requestItems": [
            {"tableName": "orders"}, {"tableName": "items"}]}),
            {table, f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/items"})
        self.assertEqual(self.res("dynamodb", "ListTables"), {"*"})

    def test_lambda(self):
        fn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:api"
        self.assertEqual(self.res("lambda", "GetFunction20150331v2", {"functionName": "api"}),
                         {fn})
        self.assertEqual(self.res("lambda", "Invoke", {"functionName": fn}), {fn})
        self.assertEqual(self.res("lambda", "Invoke", {"functionName": "api:live"}),
                         {fn, fn + ":*"})
        self.assertEqual(self.res("lambda", "GetFunction", {"functionName":
                                                            f"{ACCOUNT}:function:api"}), {fn})
        other = "arn:aws:lambda:eu-west-1:222222222222:function:far"
        self.assertEqual(self.res("lambda", "GetFunction", {"functionName": other}), {other})
        self.assertEqual(self.res("lambda", "CreateEventSourceMapping20150331",
                                  {"functionName": "api"}), {"*"})
        self.assertEqual(self.res("lambda", "ListFunctions20150331"), {"*"})

    def test_sqs(self):
        q = f"arn:aws:sqs:us-east-1:{ACCOUNT}:jobs"
        self.assertEqual(self.res("sqs", "GetQueueAttributes", {
            "queueUrl": f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/jobs"}), {q})
        self.assertEqual(self.res("sqs", "SendMessage", {
            "queueUrl": f"https://queue.amazonaws.com/{ACCOUNT}/jobs"}), {q})
        self.assertEqual(self.res("sqs", "SendMessage", {
            "queueUrl": f"https://us-west-2.queue.amazonaws.com/{ACCOUNT}/jobs"}),
            {f"arn:aws:sqs:us-west-2:{ACCOUNT}:jobs"})
        self.assertEqual(self.res("sqs", "CreateQueue", {"queueName": "jobs"}), {q})
        self.assertEqual(self.res("sqs", "ListQueues"), {"*"})
        self.assertEqual(self.res("sqs", "SendMessage", {"queueUrl": "not a url"}), {"*"})

    def test_sns(self):
        t = f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"
        self.assertEqual(self.res("sns", "Publish", {"topicArn": t}), {t})
        self.assertEqual(self.res("sns", "CreateTopic", {"name": "alerts"}), {t})
        self.assertEqual(self.res("sns", "ListTopics"), {"*"})
        self.assertEqual(self.res("sns", "Publish", {"phoneNumber": "+15555550100"}), {"*"})

    def test_kms(self):
        key = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/0e3f8a1c-1111-4222-8333-444455556666"
        self.assertEqual(self.res("kms", "Decrypt", resources=[
            {"type": "AWS::KMS::Key", "ARN": key}]), {key})
        self.assertEqual(self.res("kms", "DescribeKey", {
            "keyId": "0e3f8a1c-1111-4222-8333-444455556666"}), {key})
        self.assertEqual(self.res("kms", "Encrypt", {"keyId": "alias/app"}), {"*"})
        self.assertEqual(self.res("kms", "CreateAlias", {"aliasName": "alias/app",
                                                         "targetKeyId": key}),
                         {key, f"arn:aws:kms:us-east-1:{ACCOUNT}:alias/app"})
        self.assertEqual(self.res("kms", "ListKeys"), {"*"})

    def test_secrets_manager(self):
        self.assertEqual(self.res("secretsmanager", "GetSecretValue", {"secretId": "app/db"}),
                         {f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-??????"})
        full = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-AbCdEf"
        self.assertEqual(self.res("secretsmanager", "GetSecretValue", {"secretId": full}), {full})
        self.assertEqual(self.res("secretsmanager", "CreateSecret", {"name": "new"}),
                         {f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:new-??????"})
        self.assertEqual(self.res("secretsmanager", "ListSecrets"), {"*"})

    def test_ssm(self):
        p = f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter"
        self.assertEqual(self.res("ssm", "GetParameter", {"name": "/app/db-host"}),
                         {p + "/app/db-host"})
        self.assertEqual(self.res("ssm", "GetParameter", {"name": "plain"}), {p + "/plain"})
        self.assertEqual(self.res("ssm", "GetParameters", {"names": ["/a", "/b"]}),
                         {p + "/a", p + "/b"})
        self.assertEqual(self.res("ssm", "GetParametersByPath", {"path": "/app/"}),
                         {p + "/app", p + "/app/*"})
        self.assertEqual(self.res("ssm", "DescribeParameters"), {"*"})
        self.assertEqual(self.res("ssm", "SendCommand", {"documentName": "AWS-RunShellScript",
                                                         "instanceIds": ["i-0abc1234def567890"]}),
                         {"arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
                          f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc1234def567890"})
        self.assertEqual(self.res("ssm", "StartSession", {"target": "i-0abc1234def567890"}),
                         {f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc1234def567890",
                          f"arn:aws:ssm:us-east-1:{ACCOUNT}:document/SSM-SessionManagerRunShell"})

    def test_logs(self):
        g = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/lambda/api:*"
        self.assertEqual(self.res("logs", "CreateLogStream", {"logGroupName": "/aws/lambda/api"}),
                         {g})
        self.assertEqual(self.res("logs", "StartQuery", {"logGroupIdentifiers": [
            f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/lambda/api"]}), {g})
        self.assertEqual(self.res("logs", "DescribeLogGroups"), {"*"})

    def test_iam(self):
        a = f"arn:aws:iam::{ACCOUNT}:"
        self.assertEqual(self.res("iam", "GetRole", {"roleName": "r"}), {a + "role/r"})
        self.assertEqual(self.res("iam", "CreateRole", {"roleName": "r", "path": "/service-role/"}),
                         {a + "role/service-role/r"})
        self.assertEqual(self.res("iam", "AttachRolePolicy", {
            "roleName": "r", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
            {a + "role/r"})
        self.assertEqual(self.res("iam", "GetPolicyVersion", {"policyArn": a + "policy/p",
                                                              "versionId": "v1"}),
                         {a + "policy/p"})
        self.assertEqual(self.res("iam", "AddUserToGroup", {"groupName": "g", "userName": "u"}),
                         {a + "group/g"})
        self.assertEqual(self.res("iam", "ListGroupsForUser", {"userName": "u"}), {a + "user/u"})
        self.assertEqual(self.res("iam", "AddRoleToInstanceProfile", {
            "instanceProfileName": "ip", "roleName": "r"}), {a + "instance-profile/ip"})
        self.assertEqual(self.res("iam", "ListRoles"), {"*"})

    def test_ec2(self):
        i = f"arn:aws:ec2:us-west-2:{ACCOUNT}:instance/i-0abc1234def567890"
        items = {"instancesSet": {"items": [{"instanceId": "i-0abc1234def567890"}]}}
        self.assertEqual(self.res("ec2", "StopInstances", items, region="us-west-2"), {i})
        self.assertEqual(self.res("ec2", "DescribeInstances", items, region="us-west-2"), {"*"})
        self.assertEqual(self.res("ec2", "RunInstances", {"instanceType": "t3.micro"}), {"*"})
        self.assertEqual(self.res("ec2", "AuthorizeSecurityGroupIngress",
                                  {"groupId": "sg-0123456789abcdef0"}),
                         {f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-0123456789abcdef0"})
        self.assertEqual(self.res("ec2", "AttachVolume", {"volumeId": "vol-0123456789abcdef0",
                                                          "instanceId": "i-0abc1234def567890"}),
                         {f"arn:aws:ec2:us-east-1:{ACCOUNT}:volume/vol-0123456789abcdef0",
                          f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc1234def567890"})
        self.assertEqual(self.res("ec2", "CreateTags", {"resourcesSet": {"items": [
            {"resourceId": "i-0abc1234def567890"}, {"resourceId": "snap-0123456789abcdef0"}]}}),
            {f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc1234def567890",
             "arn:aws:ec2:us-east-1::snapshot/snap-0123456789abcdef0"})
        self.assertEqual(self.res("ec2", "CreateTags", {"resourcesSet": {"items": [
            {"resourceId": "i-0abc1234def567890"}, {"resourceId": "weird-thing"}]}}), {"*"})

    def test_other_services_and_stacks(self):
        self.assertEqual(self.res("ecr", "BatchGetImage", {"repositoryName": "app"}),
                         {f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/app"})
        self.assertEqual(self.res("ecr", "GetAuthorizationToken"), {"*"})
        self.assertEqual(self.res("cloudformation", "DescribeStacks", {"stackName": "lab"}),
                         {f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/lab/*"})
        self.assertEqual(self.res("rds", "DescribeDBInstances"), {"*"})

    def test_account_region_and_partition_come_from_the_event(self):
        ident = role_ident(account="222222222222")
        ident["arn"] = ident["arn"].replace("arn:aws:", "arn:aws-us-gov:")
        m = lp.map_event(rec("dynamodb", "DescribeTable", {"tableName": "t"},
                             region="us-gov-west-1", ident=ident, account="222222222222"),
                         PRINCIPAL)
        self.assertEqual(m.uses[0][1],
                         {"arn:aws-us-gov:dynamodb:us-gov-west-1:222222222222:table/t"})

    def test_wildcards_in_event_names_stay_literal(self):
        # A name like "*" from an event (a failed call, or a crafted file) must not become a
        # wildcard in the draft. IAM reads ${*}, ${?} and ${$} as the plain characters.
        a = f"arn:aws:iam::{ACCOUNT}:"
        cases = [
            ("s3", "GetBucketPolicy", {"bucketName": "*"}, None, {"arn:aws:s3:::${*}"}),
            ("s3", "GetObject", {"bucketName": "b?"}, None, {"arn:aws:s3:::b${?}/*"}),
            ("s3", "CopyObject", {"bucketName": "dst", "x-amz-copy-source": "*/k"},
             "s3:GetObject", {"arn:aws:s3:::${*}/*"}),
            ("dynamodb", "DescribeTable", {"tableName": "*"}, None,
             {f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/${{*}}"}),
            ("dynamodb", "DescribeTable", {"tableArn": "arn:aws:dynamodb:*:*:table/*"}, None,
             {"arn:aws:dynamodb:${*}:${*}:table/${*}"}),
            ("lambda", "GetFunction", {"functionName":
                                       f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:*"}, None,
             {f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:${{*}}"}),
            ("sqs", "GetQueueUrl", {"queueName": "*", "queueOwnerAWSAccountId": "*"}, None,
             {"arn:aws:sqs:us-east-1:${*}:${*}"}),
            ("secretsmanager", "GetSecretValue", {"secretId": "*"}, None,
             {f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:${{*}}-??????"}),
            ("ssm", "GetParameter", {"name": "/app/*"}, None,
             {f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/${{*}}"}),
            ("ssm", "GetParameters", {"names": "*"}, None, {"*"}),  # not a list of names
            ("logs", "CreateLogStream", {"logGroupName": "*"}, None,
             {f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:${{*}}:*"}),
            ("iam", "GetRole", {"roleName": "*"}, None, {a + "role/${*}"}),
            ("iam", "GetRole", {"roleName": "${aws:username}"}, None,
             {a + "role/${$}{aws:username}"}),
            ("sts", "AssumeRole", {"roleArn": "arn:aws:iam::*:role/*",
                                   "roleSessionName": "x"}, None,
             {"arn:aws:iam::${*}:role/${*}"}),
            ("lambda", "CreateFunction20150331", {"functionName": "f", "role": a + "role/*"},
             "iam:PassRole", {a + "role/${*}"}),
        ]
        for source, name, params, action, expected in cases:
            with self.subTest(source=source, name=name, params=params):
                # A call that failed for a reason other than access still counts.
                r = draft([rec(source, name, params, error="ValidationException")])
                act = action or r.statements[0]["actions"][0]
                self.assertEqual(resources_of(r.doc, act), expected)
        r = draft([rec("s3", "GetBucketPolicy", {"bucketName": "*"})])
        self.assertTrue(any("${*}" in n for n in r.notes()))
        self.assertFalse(any("${*}" in n for n in draft([rec("s3", "ListBuckets")]).notes()))

    def test_region_and_account_from_the_event_stay_literal(self):
        record = rec("dynamodb", "DescribeTable", {"tableName": "t"}, region="*")
        record["recipientAccountId"] = "*"
        self.assertEqual(resources_of(draft([record]).doc, "dynamodb:DescribeTable"),
                         {"arn:aws:dynamodb:${*}:${*}:table/t"})

    def test_lambda_latest_qualifier_still_works(self):
        fn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:api"
        self.assertEqual(self.res("lambda", "Invoke", {"functionName": "api:$LATEST"}),
                         {fn, fn + ":*"})

    def test_specific_resources_off(self):
        r = draft([rec("s3", "PutObject", {"bucketName": "b"}),
                   rec("lambda", "CreateFunction20150331", {"functionName": "f", "role":
                                                            f"arn:aws:iam::{ACCOUNT}:role/x"})],
                  specific=False)
        for st in r.doc["Statement"]:
            self.assertEqual(st["Resource"], "*")


# ------------------------------------------------------------------ implied permissions

class ImpliedTests(unittest.TestCase):
    def test_create_function_needs_passrole_on_that_role(self):
        role = f"arn:aws:iam::{ACCOUNT}:role/example-lambda-role"
        r = draft([rec("lambda", "CreateFunction20150331", {"functionName": "f", "role": role})])
        st = statements_with(r.doc, "iam:PassRole")
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["Resource"], role)
        self.assertEqual(st[0]["Condition"], {"StringEquals": {"iam:PassedToService":
                                                               "lambda.amazonaws.com"}})
        self.assertEqual(st[0]["Sid"], "IAMPassRoleToLambda")
        titles = [f.title for f in r.findings]
        self.assertNotIn("iam:PassRole on any role", titles)
        row = next(x for x in r.rows() if x["full"] == "iam:PassRole")
        self.assertEqual(row["calls_text"], "needed")
        self.assertIn("lambda:CreateFunction", row["source"])

    def test_instance_profile_cant_be_scoped(self):
        r = draft([rec("ec2", "RunInstances", {"iamInstanceProfile": {"name": "web"}})])
        self.assertEqual(resources_of(r.doc, "iam:PassRole"), {"*"})
        self.assertTrue(any("instance profile" in n for n in r.notes()))
        titles = [f.title for f in r.findings]
        self.assertIn("PassRole plus a service that runs as a role", titles)
        # Without the iam:PassedToService condition, Policy Check calls out PassRole on "*".
        doc = json.loads(r.text)
        for st in doc["Statement"]:
            st.pop("Condition", None)
        self.assertIn("iam:PassRole on any role",
                      [f.title for f in iampolicy.analyze(doc, "identity")])

    def test_run_instances_without_a_profile_needs_no_passrole(self):
        r = draft([rec("ec2", "RunInstances", {"instanceType": "t3.micro"})])
        self.assertEqual(statements_with(r.doc, "iam:PassRole"), [])

    def test_nested_role_parameters(self):
        role = f"arn:aws:iam::{ACCOUNT}:role/events-role"
        r = draft([rec("events", "PutTargets", {"rule": "r", "targets": [
            {"id": "1", "arn": "arn:aws:states:us-east-1:111111111111:stateMachine:sm",
             "roleArn": role}]})])
        self.assertEqual(resources_of(r.doc, "iam:PassRole"), {role})
        cfg = f"arn:aws:iam::{ACCOUNT}:role/config-role"
        r = draft([rec("config", "PutConfigurationRecorder", {"configurationRecorder": {
            "name": "default", "roleARN": cfg}})])
        self.assertEqual(resources_of(r.doc, "iam:PassRole"), {cfg})

    def test_passrole_only_for_the_parameter_that_passes_a_role(self):
        # A tag (or anything else) that happens to be called "role" isn't a role being passed.
        role = f"arn:aws:iam::{ACCOUNT}:role/fn-role"
        admin = f"arn:aws:iam::{ACCOUNT}:role/admin"
        r = draft([rec("lambda", "CreateFunction20150331", {
            "functionName": "f", "role": role, "tags": {"role": admin},
            "environment": {"variables": {"role": admin}}})])
        self.assertEqual(resources_of(r.doc, "iam:PassRole"), {role})
        r = draft([rec("events", "PutTargets", {"rule": "r", "roleArn": admin, "targets": [
            {"id": "1", "arn": "arn:aws:sqs:us-east-1:111111111111:q"}]})])
        self.assertEqual(statements_with(r.doc, "iam:PassRole"), [])

    def test_passrole_on_any_role_is_flagged_without_run_instances(self):
        # Policy Check doesn't flag iam:PassRole on "*" with a PassedToService condition
        # unless something like ec2:RunInstances is there too. AssociateIamInstanceProfile can
        # still put any role on an instance, so the draft's findings must say so.
        r = draft([rec("ec2", "AssociateIamInstanceProfile", {
            "instanceId": "i-0abc1234def567890", "iamInstanceProfile": {"name": "web"}})])
        self.assertEqual(resources_of(r.doc, "iam:PassRole"), {"*"})
        # Policy Check now knows AssociateIamInstanceProfile as a PassRole pair, so its own
        # high finding covers it; either way a high PassRole finding must be there.
        self.assertTrue(any(f.severity == "high" and "PassRole" in f.title for f in r.findings),
                        [(f.severity, f.title) for f in r.findings])
        self.assertEqual(r.findings[0].severity, "high")
        self.assertIn("1 high", r.summary()[0])
        # With RunInstances, Policy Check's own finding is enough: no second one.
        r = draft([rec("ec2", "RunInstances", {"iamInstanceProfile": {"name": "web"}})])
        self.assertNotIn("iam:PassRole on any role", [f.title for f in r.findings])


# ------------------------------------------------------------------ the policy

class PolicyTests(unittest.TestCase):
    def test_sample_passes_policy_check_without_critical_findings(self):
        res = lp.run(who=ROLE, files=[str(SAMPLE)])
        self.assertEqual(res.doc["Version"], "2012-10-17")
        doc, _ = iampolicy.load_policy(res.text)
        self.assertEqual(doc, res.doc)
        sev = {f.severity for f in iampolicy.analyze(doc, "identity")}
        self.assertFalse(sev & {"critical", "high"}, sev)
        self.assertEqual(resources_of(res.doc, "s3:PutObject"), {"arn:aws:s3:::example-lab-site/*"})
        self.assertEqual(resources_of(res.doc, "s3:ListBucket"), {"arn:aws:s3:::example-lab-site"})
        self.assertNotIn("s3:PutBucketPolicy", actions_of(res))        # denied
        self.assertNotIn("sts:GetCallerIdentity", actions_of(res))     # needs no permission
        self.assertNotIn("sts:AssumeRole", actions_of(res))            # it was assumed
        self.assertEqual(res.principal.kind, "role")
        self.assertEqual(res.principal.account, ACCOUNT)
        self.assertTrue(res.activity.data_events)
        self.assertEqual(len(res.unmapped_rows()), 1)
        self.assertLess(len(json.dumps(res.doc, separators=(",", ":"))), lp.POLICY_SIZE_LIMIT)

    def test_same_input_same_policy(self):
        base = json.loads(SAMPLE.read_text())["Records"]
        texts = set()
        for seed in range(6):
            records = list(base)
            random.Random(seed).shuffle(records)
            act = lp.collect([ev(r) for r in records], PRINCIPAL)
            res = lp.Result(PRINCIPAL, lp.ReadInfo("files", "files"), act, None, lp.Options(),
                            30, NOW)
            texts.add(res.text)
        self.assertEqual(len(texts), 1)
        doc = json.loads(texts.pop())
        sids = [s["Sid"] for s in doc["Statement"]]
        self.assertEqual(len(sids), len(set(sids)))
        for sid in sids:
            self.assertRegex(sid, r"^[A-Za-z0-9]{1,60}$")
        for st in doc["Statement"]:
            actions = iampolicy.as_list(st["Action"])
            self.assertEqual(actions, sorted(actions))
            resources = iampolicy.as_list(st["Resource"])
            self.assertEqual(resources, sorted(resources))

    def test_readable_sids(self):
        res = lp.run(who=ROLE, files=[str(SAMPLE)])
        sids = {s["Sid"] for s in res.doc["Statement"]}
        for expected in ("S3ReadExampleLabSiteBucket", "S3AccessExampleLabSiteObjects",
                         "DynamoDBAccessExampleOrdersTable", "KMSDecryptKey",
                         "IAMPassRoleToLambda", "S3ListAllMyBuckets"):
            self.assertIn(expected, sids)

    def test_many_resources_collapse_to_a_wildcard(self):
        named = [rec("dynamodb", "DescribeTable", {"tableName": f"orders-{i:02d}"})
                 for i in range(12)]
        r = draft(named)
        self.assertEqual(resources_of(r.doc, "dynamodb:DescribeTable"),
                         {f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders-*"})
        self.assertTrue(any("touched 12 resources" in n for n in r.notes()))
        mixed = [rec("dynamodb", "DescribeTable", {"tableName": f"{w}-t"})
                 for w in "abcdefghijkl"]
        self.assertEqual(resources_of(draft(mixed).doc, "dynamodb:DescribeTable"),
                         {f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/*"})
        few = [rec("dynamodb", "DescribeTable", {"tableName": f"orders-{i}"}) for i in range(10)]
        self.assertEqual(len(resources_of(draft(few).doc, "dynamodb:DescribeTable")), 10)

    def test_collapse_keeps_types_accounts_and_regions_apart(self):
        ids = [f"i-0abc1234def5678{i:02d}" for i in range(11)]
        recs = [rec("ec2", "StopInstances", {"instancesSet": {"items": [{"instanceId": i}]}})
                for i in ids]
        recs.append(rec("ec2", "StopInstances", {"instancesSet": {"items": [
            {"instanceId": "i-0fff1234def567890"}]}}, region="eu-west-1"))
        res = resources_of(draft(recs).doc, "ec2:StopInstances")
        self.assertEqual(res, {f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/*",
                               f"arn:aws:ec2:eu-west-1:{ACCOUNT}:instance/i-0fff1234def567890"})
        buckets = [rec("s3", "PutObject", {"bucketName": f"{w}{w}-data"}) for w in "abcdefghijk"]
        self.assertEqual(resources_of(draft(buckets).doc, "s3:PutObject"), {"arn:aws:s3:::*/*"})
        logs = [rec("logs", "CreateLogStream", {"logGroupName": f"/aws/lambda/fn{i}"})
                for i in range(11)]
        self.assertEqual(resources_of(draft(logs).doc, "logs:CreateLogStream"),
                         {f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/lambda/fn*"})

    def test_collapse_never_cuts_a_literal_character_in_half(self):
        names = [f"labs{'*?'[i % 2]}{i:02d}" for i in range(12)]
        r = draft([rec("dynamodb", "DescribeTable", {"tableName": n}) for n in names])
        self.assertEqual(resources_of(r.doc, "dynamodb:DescribeTable"),
                         {f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/labs*"})
        same = [f"labs*{i:02d}" for i in range(12)]
        r = draft([rec("dynamodb", "DescribeTable", {"tableName": n}) for n in same])
        self.assertEqual(resources_of(r.doc, "dynamodb:DescribeTable"),
                         {f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/labs${{*}}*"})

    def test_no_calls_no_policy(self):
        r = draft([rec("sts", "GetCallerIdentity")])
        self.assertIsNone(r.doc)
        self.assertEqual(r.text, "")
        self.assertIn("no policy to draft", r.summary()[0])


def fake_current(window_days_ago=2):
    when = NOW - timedelta(days=window_days_ago)
    admin = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*",
                                                     "Resource": "*"}]}
    inline = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*",
                                                      "Resource": "*"}]}
    cur = lp.Current()
    cur.policies = [{"name": "AdministratorAccess", "kind": "managed",
                     "arn": "arn:aws:iam::aws:policy/AdministratorAccess", "via": "",
                     "doc": admin, "findings": iampolicy.analyze(admin, "identity")},
                    {"name": "extra", "kind": "inline", "arn": "", "via": "", "doc": inline,
                     "findings": iampolicy.analyze(inline, "identity")}]
    cur.services = [
        {"ServiceName": "Amazon S3", "ServiceNamespace": "s3", "LastAuthenticated": when,
         "LastAuthenticatedRegion": "us-east-1", "TrackedActionsLastAccessed": [
             {"ActionName": "DeleteObject", "LastAccessedTime": when,
              "LastAccessedRegion": "us-east-1"},
             {"ActionName": "ListAllMyBuckets", "LastAccessedTime": when},
             {"ActionName": "PutBucketTagging", "LastAccessedTime": NOW - timedelta(days=200)}]},
        {"ServiceName": "AWS Lambda", "ServiceNamespace": "lambda", "LastAuthenticated": when,
         "LastAuthenticatedRegion": "eu-west-1"},
        {"ServiceName": "Amazon RDS", "ServiceNamespace": "rds"},
        {"ServiceName": "AWS Glue", "ServiceNamespace": "glue"},
        {"ServiceName": "Amazon ECR", "ServiceNamespace": "ecr",
         "LastAuthenticated": NOW - timedelta(days=120), "LastAuthenticatedRegion": "us-west-2"},
    ]
    return cur


class ComparisonResultTests(unittest.TestCase):
    def records(self):
        return [rec("s3", "ListBuckets"), rec("dynamodb", "DescribeTable", {"tableName": "t"})]

    def test_summary_lines(self):
        r = draft(self.records(), current=fake_current(), source="aws")
        lines = r.summary()
        self.assertIn("Used in the last 30 days: 2 actions in 2 services, plus 1 more from IAM "
                      "last accessed data.", lines)
        self.assertIn("Now: AdministratorAccess plus 1 inline policy. Policy Check on those: "
                      "1 critical, 1 high.", lines)
        self.assertIn("Allowed but not used in 400 days: 2 services.", lines)
        self.assertEqual([s["namespace"] for s in r.never_used()], ["glue", "rds"])
        self.assertEqual([s["namespace"] for s in r.unused_services()], ["glue", "rds", "ecr"])

    def test_last_accessed_actions_are_added_and_marked(self):
        r = draft(self.records(), current=fake_current(), source="aws")
        self.assertIn("s3:DeleteObject", actions_of(r))
        self.assertNotIn("s3:PutBucketTagging", actions_of(r))  # used before the window
        st = statements_with(r.doc, "s3:DeleteObject")
        self.assertEqual(len(st), 1)
        self.assertTrue(st[0]["Sid"].startswith("LastAccessed"))
        self.assertEqual(st[0]["Resource"], "*")
        self.assertEqual(len(statements_with(r.doc, "s3:ListAllMyBuckets")), 1)  # no duplicate
        off = r.rebuild(lp.Options(include_last_accessed=False))
        self.assertNotIn("s3:DeleteObject", actions_of(off))
        row = next(x for x in off.rows() if x["full"] == "s3:DeleteObject")
        self.assertTrue(row["_dim"])
        self.assertEqual(row["calls_text"], "last accessed")

    def test_notes_about_data_events_and_regions(self):
        r = draft(self.records(), current=fake_current(), source="aws")
        notes = " ".join(r.notes())
        self.assertIn("Event history doesn't record data events", notes)
        self.assertIn("current policies allow some of these", notes)
        self.assertIn("lambda on", notes)
        self.assertIn("in eu-west-1 (a region that wasn't read)", notes)
        self.assertIn("ecr (", notes)  # used before the window
        files = draft([rec("s3", "GetObject", {"bucketName": "b"}, data=True)])
        self.assertIn("The files include data events", " ".join(files.notes()))
        no_data = draft(self.records())
        self.assertIn("These files have no data events", " ".join(no_data.notes()))

    def test_report_is_json(self):
        r = draft(self.records(), current=fake_current(), source="aws")
        rep = json.loads(json.dumps(r.report(), default=str))
        self.assertEqual(rep["policy"], r.doc)
        self.assertEqual(rep["principal"]["name"], ROLE)
        self.assertTrue(rep["unused_services"])
        self.assertTrue(all(not k.startswith("_") for row in rep["actions"] for k in row))


# ------------------------------------------------------------------ files

class FileTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))
        self.records = json.loads(SAMPLE.read_text())["Records"]

    def lookup_output(self):
        events = []
        for r in self.records:
            events.append({"EventId": r["eventID"], "EventName": r["eventName"],
                           "EventTime": r["eventTime"], "EventSource": r["eventSource"],
                           "Resources": [], "CloudTrailEvent": json.dumps(r)})
        return {"Events": events}

    def test_lookup_events_output_and_gzip_give_the_same_policy(self):
        base = lp.run(who=ROLE, files=[str(SAMPLE)]).text
        lookup = self.dir / "lookup.json"
        lookup.write_text(json.dumps(self.lookup_output()))
        self.assertEqual(lp.run(who=ROLE, files=[str(lookup)]).text, base)
        gz = self.dir / "111111111111_CloudTrail_us-east-1_20260920T0800Z_example.json.gz"
        gz.write_bytes(gzip.compress(SAMPLE.read_bytes()))
        self.assertEqual(lp.run(who=ROLE, files=[str(gz)]).text, base)
        bare = self.dir / "list.json"
        bare.write_text(json.dumps(self.records))
        self.assertEqual(lp.run(who=ROLE, files=[str(bare)]).text, base)

    def test_folder_walk_skips_what_isnt_json(self):
        a = self.dir / "AWSLogs" / ACCOUNT / "CloudTrail" / "us-east-1" / "2026" / "09"
        a.mkdir(parents=True)
        half = len(self.records) // 2
        (a / "one.json.gz").write_bytes(gzip.compress(json.dumps(
            {"Records": self.records[:half]}).encode()))
        (a / "two.json").write_text(json.dumps({"Records": self.records[half:]}))
        (a / "notes.txt").write_text("not json")
        (a / "broken.json").write_text('{"Records": [')
        (a / "other.json").write_text('{"hello": 1}')
        (a / "digest.json").write_text('{"digestStartTime": "x"}')
        res = lp.run(who=ROLE, files=[str(self.dir)])
        self.assertEqual(res.text, lp.run(who=ROLE, files=[str(SAMPLE)]).text)
        self.assertEqual(res.info.files_read, 2)
        notes = " ".join(res.notes())
        self.assertIn("Skipped 1 file(s) that aren't .json or .json.gz", notes)
        self.assertIn("broken.json isn't valid JSON", notes)
        self.assertIn("other.json doesn't hold CloudTrail events", notes)
        self.assertNotIn("digest.json", notes)

    def test_gzip_bomb_is_refused_without_unpacking_it(self):
        bomb = self.dir / "bomb.json.gz"
        with gzip.open(bomb, "wb") as fh:
            chunk = b" " * (1024 * 1024)
            for _ in range(8):
                fh.write(chunk)
        self.assertLess(bomb.stat().st_size, 100 * 1024)
        with mock.patch.object(lp, "MAX_FILE_BYTES", 1024 * 1024):
            with self.assertRaises(lp.LeastPrivError) as cm:
                lp.read_capped(bomb)
            self.assertIn("once unpacked", str(cm.exception))
            real = gzip.GzipFile.read
            sizes = []

            def spy(fh, n=-1):
                sizes.append(n)
                return real(fh, n)
            with mock.patch.object(gzip.GzipFile, "read", spy):
                with self.assertRaises(lp.LeastPrivError):
                    lp.read_capped(bomb)
            self.assertEqual(sizes, [1024 * 1024 + 1])  # never asked for the whole thing
            good = self.dir / "good.json"
            good.write_text(SAMPLE.read_text())
            res = lp.run(who=ROLE, files=[str(bomb), str(good)])
            self.assertIn("bomb.json.gz is over 1 MB once unpacked. Skipped.", res.notes())

    def test_big_plain_file_and_total_limit(self):
        big = self.dir / "big.json"
        big.write_text(json.dumps({"Records": self.records}))
        with mock.patch.object(lp, "MAX_FILE_BYTES", 1000):
            with self.assertRaises(lp.LeastPrivError) as cm:
                lp.run(who=ROLE, files=[str(big)])
            self.assertIn("big.json is over", str(cm.exception))
        for i in range(3):
            (self.dir / f"f{i}.json").write_text(SAMPLE.read_text())
        with mock.patch.object(lp, "MAX_TOTAL_BYTES", SAMPLE.stat().st_size + 10):
            res = lp.run(who=ROLE, files=[str(self.dir / f"f{i}.json") for i in range(3)])
        self.assertEqual(res.info.files_read, 1)
        self.assertTrue(any("which is the limit" in n for n in res.notes()), res.notes())

    def test_nothing_readable(self):
        bad = self.dir / "bad.json"
        bad.write_bytes(b"\xff\xfe\x00garbage")
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.run(who=ROLE, files=[str(bad)])
        self.assertIn("isn't UTF-8", str(cm.exception))
        with self.assertRaises(lp.LeastPrivError):
            lp.run(who=ROLE, files=[str(self.dir / "missing.json")])

    def test_principal_picked_from_files_when_there_is_one(self):
        only = self.dir / "only.json"
        mine = [r for r in self.records if r["userIdentity"].get("sessionContext", {}).get(
            "sessionIssuer", {}).get("userName") == ROLE]
        only.write_text(json.dumps({"Records": mine}))
        res = lp.run(files=[str(only)])
        self.assertEqual((res.principal.kind, res.principal.name), ("role", ROLE))
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.run(files=[str(SAMPLE)])  # lab-deployer, ci-runner and lab-user
        self.assertIn("Name the one", str(cm.exception))
        self.assertIn("lab-deployer (", str(cm.exception))

    def test_bare_name_works_offline_for_users_too(self):
        f = self.dir / "user.json"
        f.write_text(json.dumps({"Records": [rec("s3", "ListBuckets", ident=user_ident())]}))
        res = lp.run(who="lab-user", files=[str(f)])
        self.assertEqual(res.principal.kind, "user")
        self.assertEqual(actions_of(res), ["s3:ListAllMyBuckets"])

    def test_same_name_in_two_accounts_asks_which(self):
        # An organization trail can hold a role of the same name in every account. Their calls
        # must not be mixed into one draft.
        other = "222222222222"
        f = self.dir / "org.json"
        f.write_text(json.dumps({"Records": [
            rec("s3", "ListBuckets"),
            rec("iam", "DeleteRole", {"roleName": "prod-app"}, ident=role_ident(account=other),
                account=other)]}))
        for who in (ROLE, f"role/{ROLE}"):
            with self.subTest(who=who), self.assertRaises(lp.LeastPrivError) as cm:
                lp.run(who=who, files=[str(f)])
            self.assertIn("in 2 accounts", str(cm.exception))
            self.assertIn(f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", str(cm.exception))
        res = lp.run(who=f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", files=[str(f)])
        self.assertEqual(actions_of(res), ["s3:ListAllMyBuckets"])
        res = lp.run(who=f"arn:aws:iam::{other}:role/{ROLE}", files=[str(f)])
        self.assertEqual(actions_of(res), ["iam:DeleteRole"])

    def test_role_and_user_with_the_same_name_asks_which(self):
        f = self.dir / "both.json"
        f.write_text(json.dumps({"Records": [
            rec("s3", "ListBuckets", ident=role_ident("deploy")),
            rec("iam", "CreateAccessKey", {"userName": "x"}, ident=user_ident("deploy"))]}))
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.run(who="deploy", files=[str(f)])
        self.assertIn("role/deploy or user/deploy", str(cm.exception))
        self.assertEqual(actions_of(lp.run(who="role/deploy", files=[str(f)])),
                         ["s3:ListAllMyBuckets"])

    def test_odd_records_are_skipped_not_fatal(self):
        odd = [dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}), errorCode={"a": 1}),
               dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}), awsRegion=["x"]),
               dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}), eventID=["x"]),
               dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}),
                    eventTime="2026-09-20T08:00:00"),  # no time zone
               dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}), eventSource=5),
               dict(rec("s3", "GetBucketAcl", {"bucketName": "b"}), errorCode="AccessDenied",
                    errorMessage=["not text"])]
        f = self.dir / "odd.json"
        f.write_text(json.dumps({"Records": [rec("s3", "ListBuckets")] + odd}))
        res = lp.run(who=ROLE, files=[str(f)])
        self.assertIn("s3:ListAllMyBuckets", actions_of(res))
        # trail.parse_event now reads odd fields as text, so none of these is skipped
        self.assertTrue(any(n.startswith("Read 1 file: 7 events") for n in res.notes()),
                        res.notes())
        lookup = self.dir / "lookup.json"
        lookup.write_text(json.dumps({"Events": [
            {"CloudTrailEvent": json.dumps(rec("s3", "ListBuckets"))},
            {"CloudTrailEvent": 5}, {"CloudTrailEvent": "[1]"}]}))
        res = lp.run(who=ROLE, files=[str(lookup)])
        self.assertEqual(actions_of(res), ["s3:ListAllMyBuckets"])
        self.assertIn("Skipped 2 record(s) that couldn't be read as CloudTrail events.",
                      res.notes())

    def test_folder_walk_skips_links_and_special_files(self):
        outside = Path(tempfile.mkdtemp(dir=TMP)) / "elsewhere.json"
        outside.write_text(json.dumps({"Records": [rec("iam", "CreateUser", {"userName": "x"})]}))
        (self.dir / "a.json").write_text(SAMPLE.read_text())
        try:
            os.symlink(outside, self.dir / "link.json")
        except (OSError, NotImplementedError):
            self.skipTest("can't make links here")
        res = lp.run(who=ROLE, files=[str(self.dir)])
        self.assertEqual(res.info.files, ["a.json"])
        self.assertNotIn("iam:CreateUser", actions_of(res))
        self.assertTrue(any("Skipped 1 link(s)" in n for n in res.notes()))
        # Named directly, a link is read: that's the user's own choice.
        direct = lp.run(who=ROLE, files=[str(self.dir / "link.json")])
        self.assertIn("iam:CreateUser", actions_of(direct))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_named_pipe_never_hangs_the_read(self):
        (self.dir / "a.json").write_text(SAMPLE.read_text())
        os.mkfifo(self.dir / "pipe.json")
        got = {}

        def work():
            try:
                got["folder"] = lp.run(who=ROLE, files=[str(self.dir)])
                lp.read_capped(self.dir / "pipe.json")
            except lp.LeastPrivError as exc:
                got["direct"] = str(exc)
        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(10)
        self.assertFalse(t.is_alive(), "reading a named pipe blocked")
        self.assertEqual(got["folder"].info.files, ["a.json"])
        self.assertTrue(any("aren't plain files" in n for n in got["folder"].notes()))
        self.assertIn("isn't a regular file", got["direct"])

    def test_cancel_stops_between_files(self):
        for i in range(3):
            (self.dir / f"f{i}.json").write_text(SAMPLE.read_text())
        cancel = threading.Event()
        cancel.set()
        res = lp.run(who=ROLE, files=[str(self.dir)], cancel=cancel)
        self.assertTrue(res.info.cancelled)
        self.assertEqual(res.info.files_read, 0)
        self.assertIsNone(res.doc)


# ------------------------------------------------------------------ reading Event history

class FakeTrail:
    """Stands in for LookupEvents: one lookup attribute, the time window, MaxResults and
    NextToken paging. Records every call and how many ran at once."""

    def __init__(self, records_by_region, fail=None, delay=0.0, on_call=None):
        self.records = records_by_region
        self.fail = fail or {}
        self.delay = delay
        self.on_call = on_call
        self.calls = []
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.threads = set()

    @staticmethod
    def username(r):
        ident = r.get("userIdentity") or {}
        if ident.get("type") == "AssumedRole":
            return ident["arn"].rsplit("/", 1)[-1]
        return ident.get("userName", "")

    @staticmethod
    def resource_names(r):
        names = [x.get("ARN") for x in r.get("resources") or []]
        return names + [(r.get("requestParameters") or {}).get("roleArn")]

    @staticmethod
    def when(r):
        return datetime.strptime(r["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def lookup(self, region, **kw):
        attrs = kw.get("LookupAttributes") or []
        key = (attrs[0]["AttributeKey"], attrs[0]["AttributeValue"]) if attrs else (None, None)
        with self.lock:
            self.calls.append({"region": region, "attr": key[0], "value": key[1],
                               "token": kw.get("NextToken"), "time": time.monotonic(),
                               "max": kw.get("MaxResults")})
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.threads.add(threading.current_thread().name)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.on_call:
                self.on_call(region, kw)
            if region in self.fail:
                raise self.fail[region]
            items = []
            for r in self.records.get(region, []):
                if not (kw["StartTime"] <= self.when(r) <= kw["EndTime"]):
                    continue
                if key[0] == "Username" and self.username(r) != key[1]:
                    continue
                if key[0] == "ResourceName" and key[1] not in self.resource_names(r):
                    continue
                items.append(r)
            items.sort(key=self.when, reverse=True)
            start = int(kw.get("NextToken") or 0)
            n = kw.get("MaxResults") or 50
            page = items[start:start + n]
            resp = {"Events": [{"EventId": r["eventID"], "EventName": r["eventName"],
                                "EventTime": self.when(r), "EventSource": r["eventSource"],
                                "Username": self.username(r),
                                "Resources": [{"ResourceName": x} for x in
                                              self.resource_names(r) if x],
                                "CloudTrailEvent": json.dumps(r)} for r in page]}
            if start + n < len(items):
                resp["NextToken"] = str(start + n)
            return resp
        finally:
            with self.lock:
                self.active -= 1


class FakeCtx:
    """An AwsContext whose CloudTrail clients are real boto3 clients with LookupEvents
    replaced, so the real paginator runs. IAM goes to a given client (moto) when set."""

    def __init__(self, fake, iam=None, account=ACCOUNT):
        self.fake = fake
        self.iam = iam
        self._account = account
        self.profile = None
        self.default_region = "us-east-1"
        self.clients = {}
        self.lock = threading.Lock()

    @property
    def account(self):
        return self._account

    def identity(self):
        return {"Account": self._account, "Arn": f"arn:aws:iam::{self._account}:user/tester"}

    def client(self, service, region=None):
        region = region or self.default_region
        if service == "iam" and self.iam is not None:
            return self.iam
        with self.lock:
            if (service, region) not in self.clients:
                c = boto3.client(service, region_name=region)
                c.lookup_events = lambda _r=region, **kw: self.fake.lookup(_r, **kw)
                self.clients[(service, region)] = c
            return self.clients[(service, region)]


def denied_error(op="LookupEvents"):
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Not allowed"}}, op)


@unittest.skipUnless(boto3, "boto3 isn't installed")
class ReadAwsTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(lp, "LOOKUP_INTERVAL", 0.0)
        p.start()
        self.addCleanup(p.stop)
        self.start = NOW - timedelta(days=30)
        self.end = NOW + timedelta(minutes=5)

    def read(self, fake, principal=PRINCIPAL, regions=("us-east-1", "us-west-2"), **kw):
        ctx = FakeCtx(fake)
        events, info = lp.read_aws(ctx, principal, list(regions), self.start, self.end, **kw)
        return events, info, lp.collect(events, principal)

    def world(self):
        east = [assume("s1"), assume("s2", by={"type": "AWSService",
                                                "invokedBy": "lambda.amazonaws.com"}),
                assume("s9", error="AccessDenied"),
                rec("s3", "ListBuckets", ident=role_ident(session="s1")),
                rec("ec2", "DescribeVpcs", ident=role_ident("ci-runner", session="s1"))]
        west = [rec("dynamodb", "DescribeTable", {"tableName": "t"}, region="us-west-2",
                    ident=role_ident(session="s2"))]
        return {"us-east-1": east, "us-west-2": west}

    def test_quick_mode_finds_sessions_then_reads_them(self):
        fake = FakeTrail(self.world())
        _, info, act = self.read(fake)
        self.assertEqual(set(info.sessions), {"s1", "s2"})
        self.assertEqual(sorted(act.used), ["dynamodb:DescribeTable", "s3:ListAllMyBuckets"])
        firsts = {(c["region"], c["attr"], c["value"]) for c in fake.calls if not c["token"]}
        self.assertEqual(firsts, {(r, "ResourceName", ROLE_ARN) for r in ("us-east-1", "us-west-2")}
                         | {(r, "Username", s) for r in ("us-east-1", "us-west-2")
                            for s in ("s1", "s2")})
        self.assertEqual(act.others, 1)  # ci-runner's session also called s1
        self.assertTrue(all(c["max"] == lp.PAGE_SIZE for c in fake.calls))

    def test_thorough_reads_everything_and_filters_by_role(self):
        fake = FakeTrail(self.world())
        _, info, act = self.read(fake, thorough=True)
        self.assertEqual(info.mode, "thorough")
        self.assertEqual({c["attr"] for c in fake.calls}, {None})
        self.assertEqual(sorted(act.used), ["dynamodb:DescribeTable", "s3:ListAllMyBuckets"])

    def test_iam_user_reads_by_user_name(self):
        user = lp.Principal("user", "lab-user", f"arn:aws:iam::{ACCOUNT}:user/lab-user", ACCOUNT)
        fake = FakeTrail({"us-east-1": [rec("s3", "ListBuckets", ident=user_ident())]})
        _, info, act = self.read(fake, user, regions=["us-east-1"])
        self.assertEqual(info.mode, "user")
        self.assertEqual([(c["attr"], c["value"]) for c in fake.calls], [("Username", "lab-user")])
        self.assertEqual(sorted(act.used), ["s3:ListAllMyBuckets"])

    def test_pagination(self):
        many = [rec("s3", "ListBuckets", ident=role_ident(session="s1"),
                    when=NOW - timedelta(minutes=i)) for i in range(120)]
        fake = FakeTrail({"us-east-1": [assume("s1")] + many})
        _, info, act = self.read(fake, regions=["us-east-1"])
        tokens = [c["token"] for c in fake.calls if c["attr"] == "Username"]
        self.assertEqual(tokens, [None, "50", "100"])
        self.assertEqual(act.used["s3:ListAllMyBuckets"].calls, 120)
        self.assertEqual(info.events_read, 121)

    def test_cap(self):
        many = [rec("s3", "ListBuckets", when=NOW - timedelta(minutes=i)) for i in range(120)]
        fake = FakeTrail({"us-east-1": many})
        events, info, act = self.read(fake, regions=["us-east-1"], thorough=True, cap=60)
        self.assertTrue(info.cap_hit)
        self.assertEqual(info.events_read, 60)
        self.assertEqual(len(events), 60)
        res = lp.Result(PRINCIPAL, info, act, None, lp.Options(), 30, self.start)
        self.assertTrue(any("the cap" in n for n in res.notes()))
        self.assertIn("Stopped at the event cap", res.status_text())

    def test_cancel(self):
        cancel = threading.Event()
        many = [rec("s3", "ListBuckets", when=NOW - timedelta(minutes=i)) for i in range(120)]
        fake = FakeTrail({"us-east-1": many}, on_call=lambda region, kw: cancel.set())
        events, info, _ = self.read(fake, regions=["us-east-1"], thorough=True, cancel=cancel)
        self.assertTrue(info.cancelled)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(len(events), 50)

    def test_regions_run_in_parallel(self):
        regions = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]
        fake = FakeTrail({r: [rec("s3", "ListBuckets", region=r)] for r in regions}, delay=0.3)
        t0 = time.monotonic()
        _, info, act = self.read(fake, regions=regions, thorough=True)
        took = time.monotonic() - t0
        self.assertGreaterEqual(fake.max_active, 2)
        self.assertGreater(len(fake.threads), 1)
        self.assertLess(took, 0.3 * len(regions))
        self.assertEqual(act.used["s3:ListAllMyBuckets"].regions, set(regions))
        self.assertEqual(info.regions, sorted(regions))

    def test_calls_in_one_region_are_spaced_out(self):
        many = [rec("s3", "ListBuckets", when=NOW - timedelta(minutes=i)) for i in range(120)]
        fake = FakeTrail({"us-east-1": many})
        with mock.patch.object(lp, "LOOKUP_INTERVAL", 0.08):
            self.read(fake, regions=["us-east-1"], thorough=True)
        times = [c["time"] for c in fake.calls]
        self.assertEqual(len(times), 3)
        self.assertTrue(all(b - a >= 0.07 for a, b in zip(times, times[1:])), times)

    def test_permission_errors_become_notes(self):
        fake = FakeTrail(self.world(), fail={"us-west-2": denied_error()})
        _, info, act = self.read(fake)
        self.assertIn("us-west-2: no permission to read Event history (cloudtrail:LookupEvents).",
                      info.notes)
        self.assertEqual(info.regions_failed, ["us-west-2"])
        self.assertIn("s3:ListAllMyBuckets", act.used)
        # It stops asking a region once it has said no.
        self.assertEqual(sum(1 for c in fake.calls if c["region"] == "us-west-2"), 1)

    def test_every_region_failing_is_an_error(self):
        fake = FakeTrail({}, fail={"us-east-1": denied_error(), "us-west-2": denied_error()})
        with self.assertRaises(lp.LeastPrivError) as cm:
            self.read(fake)
        self.assertIn("no permission", str(cm.exception))

    def test_other_errors_are_named(self):
        err = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}},
                          "LookupEvents")
        fake = FakeTrail(self.world(), fail={"us-west-2": err})
        _, info, _ = self.read(fake)
        self.assertTrue(any("slow down" in n for n in info.notes))

    def test_too_many_sessions(self):
        fake = FakeTrail(self.world())
        with mock.patch.object(lp, "MAX_SESSIONS", 1):
            _, info, _ = self.read(fake)
        self.assertEqual(len(info.sessions), 1)
        self.assertEqual(info.sessions_found, 2)
        self.assertTrue(any("read the newest 1" in n for n in info.notes))

    def test_no_sessions_note(self):
        fake = FakeTrail({"us-east-1": [rec("s3", "ListBuckets")]})
        _, info, act = self.read(fake, regions=["us-east-1"])
        res = lp.Result(PRINCIPAL, info, act, None, lp.Options(), 30, self.start)
        self.assertTrue(any("No AssumeRole events" in n for n in res.notes()))


# ------------------------------------------------------------------ comparing with AWS

@unittest.skipUnless(mock_aws, "moto isn't installed")
class CompareTests(unittest.TestCase):
    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        self.addCleanup(self.mock.stop)
        p = mock.patch.object(lp, "POLL_START", 0.01)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(lp, "LOOKUP_INTERVAL", 0.0)
        p.start()
        self.addCleanup(p.stop)
        self.iam = boto3.client("iam", region_name="us-east-1")
        trust = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]})
        self.iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=trust)
        self.iam.create_role(RoleName="AWSServiceRoleForExample", AssumeRolePolicyDocument=trust,
                             Path="/aws-service-role/example.amazonaws.com/")
        admin = self.iam.create_policy(PolicyName="lab-admin", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*",
                                                    "Resource": "*"}]}))["Policy"]["Arn"]
        self.iam.attach_role_policy(RoleName=ROLE, PolicyArn=admin)
        self.iam.put_role_policy(RoleName=ROLE, PolicyName="extra", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*",
                                                    "Resource": "*"}]}))
        self.account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
        self.states = ["IN_PROGRESS", "IN_PROGRESS", "COMPLETED"]
        self.gen_calls = []

        def gen(**kw):
            self.gen_calls.append(kw)
            return {"JobId": "job-1"}

        def get(JobId, Marker=None, **kw):
            if Marker:
                return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [
                    {"ServiceName": "AWS Glue", "ServiceNamespace": "glue"}]}
            state = self.states.pop(0) if self.states else "COMPLETED"
            return {"JobStatus": state, "IsTruncated": state == "COMPLETED", "Marker": "m2",
                    "ServicesLastAccessed": [
                        {"ServiceName": "Amazon S3", "ServiceNamespace": "s3",
                         "LastAuthenticated": NOW - timedelta(days=1),
                         "TrackedActionsLastAccessed": [
                             {"ActionName": "DeleteObject",
                              "LastAccessedTime": NOW - timedelta(days=1)}]},
                        {"ServiceName": "Amazon RDS", "ServiceNamespace": "rds"}]}
        self.iam.generate_service_last_accessed_details = gen
        self.iam.get_service_last_accessed_details = get

    def ctx(self, fake=None):
        return FakeCtx(fake or FakeTrail({}), iam=self.iam, account=self.account)

    def principal(self):
        return lp.resolve_principal(self.ctx(), lp.parse_principal(ROLE))

    def test_resolve_principal(self):
        p = self.principal()
        self.assertEqual(p.arn, f"arn:aws:iam::{self.account}:role/{ROLE}")
        self.iam.create_user(UserName="lab-user")
        u = lp.resolve_principal(self.ctx(), lp.parse_principal("lab-user"))
        self.assertEqual(u.kind, "user")
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.resolve_principal(self.ctx(), lp.parse_principal("role/nobody"))
        self.assertIn("no role named nobody", str(cm.exception))
        with self.assertRaises(lp.LeastPrivError):
            lp.resolve_principal(self.ctx(), lp.parse_principal("nobody"))
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.resolve_principal(self.ctx(), lp.parse_principal(
                "arn:aws:iam::999999999999:role/" + ROLE))
        self.assertIn("account 999999999999", str(cm.exception))

    def test_resolve_without_get_role_permission_is_a_note(self):
        ctx = self.ctx()
        with mock.patch.object(self.iam, "get_role", side_effect=denied_error("GetRole")):
            notes = []
            p = lp.resolve_principal(ctx, lp.parse_principal(ROLE), notes)
        self.assertEqual(p.arn, f"arn:aws:iam::{self.account}:role/{ROLE}")
        self.assertTrue(notes and "Couldn't look up the role" in notes[0])

    def test_current_policies_and_last_accessed(self):
        cur = lp.fetch_current(self.ctx(), self.principal())
        self.assertEqual([(p["name"], p["kind"]) for p in cur.policies],
                         [("lab-admin", "managed"), ("extra", "inline")])
        self.assertEqual(cur.policies[0]["findings"][0].severity, "critical")
        self.assertEqual([s["ServiceNamespace"] for s in cur.services], ["s3", "rds", "glue"])
        self.assertEqual(self.gen_calls, [{"Arn": f"arn:aws:iam::{self.account}:role/{ROLE}",
                                           "Granularity": "ACTION_LEVEL"}])
        self.assertEqual(cur.notes, [])

    def test_last_accessed_failures_are_notes(self):
        self.iam.get_service_last_accessed_details = lambda **kw: {
            "JobStatus": "FAILED", "Error": {"Message": "boom"}}
        services, note = lp.last_accessed(self.ctx(), "arn")
        self.assertIsNone(services)
        self.assertIn("boom", note)
        self.iam.get_service_last_accessed_details = lambda **kw: {"JobStatus": "IN_PROGRESS"}
        services, note = lp.last_accessed(self.ctx(), "arn", wait=0.05)
        self.assertIsNone(services)
        self.assertIn("hadn't finished", note)
        self.iam.generate_service_last_accessed_details = mock.Mock(
            side_effect=denied_error("GenerateServiceLastAccessedDetails"))
        services, note = lp.last_accessed(self.ctx(), "arn")
        self.assertIsNone(services)
        self.assertIn("No permission for IAM last accessed data", note)

    def test_missing_permissions_for_policies_are_notes(self):
        with mock.patch.object(self.iam, "list_role_policies",
                               side_effect=denied_error("ListRolePolicies")):
            cur = lp.fetch_current(self.ctx(), self.principal())
        self.assertEqual([p["name"] for p in cur.policies], ["lab-admin"])
        self.assertTrue(any("inline policies" in n for n in cur.notes))

    def test_list_roles_skips_service_linked_roles(self):
        self.assertEqual([r["name"] for r in lp.list_roles(self.ctx())], [ROLE])

    def test_full_run_against_event_history(self):
        acct = self.account
        role_arn = f"arn:aws:iam::{acct}:role/{ROLE}"
        east = [assume("s1", role_arn=role_arn, account=acct),
                rec("s3", "PutObject", {"bucketName": "example-site"}, account=acct,
                    ident=role_ident(account=acct)),
                rec("lambda", "CreateFunction20150331", {"functionName": "f", "role":
                                                         f"arn:aws:iam::{acct}:role/fn-role"},
                    account=acct, ident=role_ident(account=acct))]
        fake = FakeTrail({"us-east-1": east})
        res = lp.run(who=ROLE, regions=["us-east-1"], ctx=self.ctx(fake))
        self.assertEqual(res.principal.arn, role_arn)
        self.assertIn("s3:PutObject", actions_of(res))
        self.assertIn("s3:DeleteObject", actions_of(res))  # from last accessed
        self.assertIn("iam:PassRole", actions_of(res))
        lines = res.summary()
        self.assertIn("Now: lab-admin plus 1 inline policy. Policy Check on those: 1 critical, "
                      "1 high.", lines)
        self.assertIn("Allowed but not used in 400 days: 2 services.", lines)
        self.assertIn("Event history doesn't record data events", " ".join(res.notes()))
        self.assertFalse({f.severity for f in res.findings} & {"critical"})

    def test_files_with_compare(self):
        f = Path(tempfile.mkdtemp(dir=TMP)) / "t.json"
        f.write_text(json.dumps({"Records": [rec("s3", "ListBuckets",
                                                 ident=role_ident(account=self.account),
                                                 account=self.account)]}))
        res = lp.run(who=ROLE, files=[str(f)], compare=True, ctx=self.ctx())
        self.assertIsNotNone(res.current)
        self.assertEqual(res.principal.arn, f"arn:aws:iam::{self.account}:role/{ROLE}")
        other = lp.run(who=ROLE, files=[str(SAMPLE)], compare=True, ctx=self.ctx())
        self.assertIsNone(other.current)
        self.assertTrue(any("files are from account 111111111111" in n for n in other.notes()))

    def test_days_outside_event_history(self):
        with self.assertRaises(lp.LeastPrivError) as cm:
            lp.run(who=ROLE, days=120, ctx=self.ctx())
        self.assertIn("90 days", str(cm.exception))


# ------------------------------------------------------------------ command line

def add_profiles(sp, many=True):
    sp.add_argument("-p", "--profile", action="append")
    if many:
        sp.add_argument("--all-profiles", action="store_true")


def run_cli(argv):
    """Runs the command through its own parser, so other tools' modules don't matter here."""
    parser = argparse.ArgumentParser(prog="awskit")
    sub = parser.add_subparsers(dest="cmd")
    lp.register_cli(sub, add_profiles)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        args = parser.parse_args(argv)
        code = args.func(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_policy_to_stdout_notes_to_stderr(self):
        code, out, err = run_cli(["least-priv", ROLE, "--files", str(SAMPLE)])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["Version"], "2012-10-17")
        self.assertEqual(out, lp.run(who=ROLE, files=[str(SAMPLE)]).text)
        self.assertIn("Draft for role lab-deployer", err)
        self.assertIn("Denied (not in the draft, add --include-denied):", err)
        self.assertIn("s3:PutBucketPolicy", err)
        self.assertIn("Couldn't map these", err)
        self.assertIn("Notes:", err)
        self.assertNotIn("Draft for", out)

    def test_output_file(self):
        target = Path(tempfile.mkdtemp(dir=TMP)) / "policy.json"
        code, out, err = run_cli(["least-priv", ROLE, "--files", str(SAMPLE), "-o", str(target)])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(target.read_text())["Version"], "2012-10-17")
        self.assertIn(f"Wrote {target}", err)

    def test_json_report(self):
        code, out, _ = run_cli(["least-priv", ROLE, "--files", str(SAMPLE), "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(out)
        self.assertEqual(rep["principal"]["name"], ROLE)
        self.assertIn("Statement", rep["policy"])
        self.assertTrue(rep["denied"])
        self.assertTrue(rep["unmapped"])
        self.assertTrue(rep["notes"])

    def test_options(self):
        _, out, _ = run_cli(["least-priv", ROLE, "--files", str(SAMPLE), "--no-resources"])
        self.assertTrue(all(s["Resource"] == "*" for s in json.loads(out)["Statement"]))
        _, out, _ = run_cli(["least-priv", ROLE, "--files", str(SAMPLE), "--include-denied"])
        self.assertTrue(any(s["Sid"].startswith("PreviouslyDenied")
                            for s in json.loads(out)["Statement"]))
        _, _, err = run_cli(["least-priv", ROLE, "--files", str(SAMPLE), "-q"])
        self.assertNotIn("Notes:", err)
        self.assertIn("Draft for role", err)

    def test_mistakes(self):
        code, out, err = run_cli(["least-priv"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Name a role or IAM user", err)
        code, out, err = run_cli(["least-priv", "--files", str(SAMPLE)])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Name the one", err)
        code, out, err = run_cli(["least-priv", ROLE, "--days", "200"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("90 days", err)
        code, out, err = run_cli(["least-priv", "nobody-here", "--files", str(SAMPLE)])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("No calls found", err)

    def test_control_characters_from_events_arent_printed(self):
        # An error message can echo what the caller sent, and file names can be anything:
        # escape sequences in them must not reach the terminal.
        d = Path(tempfile.mkdtemp(dir=TMP))
        f = d / "evil\x1b]0;title\x07.json"
        f.write_text(json.dumps({"Records": [
            rec("s3", "ListBuckets"),
            rec("s3", "PutBucketPolicy", {"bucketName": "b"}, error="AccessDenied",
                message="no \x1b[2J\x1b]0;pwned\x07 way")]}))
        bad = d / "bad\x1b[31m.json"
        bad.write_text("{")
        code, _, err = run_cli(["least-priv", ROLE, "--files", str(f), str(bad)])
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", err)
        self.assertNotIn("\x07", err)
        self.assertIn("no ?[2J?]0;pwned? way", err)
        self.assertIn("bad?[31m.json isn't valid JSON", err)

    def test_auth_error_is_one_line(self):
        with mock.patch.object(lp, "AwsContext", side_effect=lp.AuthError(
                "Sign-in for profile lab has expired. Run: aws sso login --profile lab")):
            code, out, err = run_cli(["least-priv", ROLE, "-p", "lab"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("aws sso login --profile lab", err)
        self.assertNotIn("Traceback", err)

    def test_registered_in_awskit(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            cli.main(["least-priv", "--help"])
        self.assertEqual(cm.exception.code, 0)
        text = out.getvalue()
        for flag in ("--days", "--thorough", "--files", "--no-resources", "--include-denied",
                     "--json", "-o", "--region", "--profile"):
            self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
