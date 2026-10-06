"""Tests for Credentials: the findings, the inventory, thresholds, admin detection, missing
permissions, and the command line.

Run from the repo root:  python3 -m unittest tests.test_credentials -v

The date-based findings use hand-made credential reports and authorization details with a
fixed "now", so they don't drift. The end-to-end tests run the command line against moto.
"""
import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import threading
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

from awskit import cli  # noqa: E402
from awskit import creds  # noqa: E402

try:
    import boto3
    import botocore.client
    from botocore.exceptions import ClientError
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
ACCT = "111122223333"
AWS = "arn:aws:iam::aws:policy/"
HEADER = ("user,arn,user_creation_time,password_enabled,password_last_used,"
          "password_last_changed,password_next_rotation,mfa_active,access_key_1_active,"
          "access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,"
          "access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,"
          "access_key_2_last_used_date,access_key_2_last_used_region,"
          "access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,"
          "cert_2_last_rotated").split(",")
ROOT_BAD = {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1,
            "AccountSigningCertificatesPresent": 1}
ADMIN_DOC = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


# =================================================================== hand-made data

def d(days):
    return NOW - timedelta(days=days, hours=1)


def iso(days):
    return "N/A" if days is None else d(days).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def row(user, created=400, password=None, used=None, mfa=False, keys=(), certs=(),
        root=False):
    """One credential report row. password and used are days ago (used=None: never)."""
    r = {h: "N/A" for h in HEADER}
    r.update(user=user, arn=f"arn:aws:iam::{ACCT}:" + ("root" if root else f"user/{user}"),
             user_creation_time=iso(created),
             password_enabled="not_supported" if root else "false",
             mfa_active="true" if mfa else "false", access_key_1_active="false",
             access_key_2_active="false", cert_1_active="false", cert_2_active="false")
    if password is not None or root:
        if not root:
            r["password_enabled"] = "true"
            r["password_last_changed"] = iso(password)
        r["password_last_used"] = iso(used) if used is not None else "no_information"
    for n, k in enumerate(keys, 1):
        r[f"access_key_{n}_active"] = "true" if k.get("active", True) else "false"
        r[f"access_key_{n}_last_rotated"] = iso(k["created"])
        if k.get("used") is not None:
            r[f"access_key_{n}_last_used_date"] = iso(k["used"])
            r[f"access_key_{n}_last_used_region"] = k.get("region", "us-east-1")
            r[f"access_key_{n}_last_used_service"] = k.get("service", "s3")
    for n, c in enumerate(certs, 1):
        r[f"cert_{n}_active"] = "true" if c.get("active", True) else "false"
        r[f"cert_{n}_last_rotated"] = iso(c.get("created", 100))
    return r


def report_csv(rows) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, HEADER)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


def user(name, created=400, groups=(), attached=(), inline=None, boundary=None):
    u = {"UserName": name, "Path": "/", "Arn": f"arn:aws:iam::{ACCT}:user/{name}",
         "CreateDate": d(created), "GroupList": list(groups),
         "UserPolicyList": [{"PolicyName": k, "PolicyDocument": v}
                            for k, v in (inline or {}).items()],
         "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a}
                                     for a in attached]}
    if boundary:
        u["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return u


def group(name, attached=(), inline=None):
    return {"GroupName": name, "Path": "/", "Arn": f"arn:aws:iam::{ACCT}:group/{name}",
            "GroupPolicyList": [{"PolicyName": k, "PolicyDocument": v}
                                for k, v in (inline or {}).items()],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a}
                                        for a in attached]}


def role(name, created=400, used=None, region="us-east-1", path="/", attached=(), inline=None,
         profiles=(), trust=None):
    return {"RoleName": name, "Path": path, "Arn": f"arn:aws:iam::{ACCT}:role{path}{name}",
            "CreateDate": d(created),
            "AssumeRolePolicyDocument": trust or {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                 "Action": "sts:AssumeRole"}]},
            "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v}
                               for k, v in (inline or {}).items()],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a}
                                        for a in attached],
            "InstanceProfileList": [{"InstanceProfileName": p} for p in profiles],
            "RoleLastUsed": {"LastUsedDate": d(used), "Region": region} if used is not None
            else {}}


def customer_policy(name, doc):
    return {"PolicyName": name, "Arn": f"arn:aws:iam::{ACCT}:policy/{name}",
            "PolicyVersionList": [{"Document": doc, "IsDefaultVersion": True,
                                   "VersionId": "v1"}]}


def key(kid, created, used=None, active=True, service="s3", region="us-east-1"):
    return creds.AccessKey(id=kid, status="Active" if active else "Inactive",
                           created=d(created), last_used=d(used) if used is not None else None,
                           service=service if used is not None else "",
                           region=region if used is not None else "")


def account(rows=None, users=None, groups=(), roles=(), policies=(), keys=None,
            summary=None, policy=None, policy_read=True, profile="lab", **extra):
    """An AccountData as read_account would leave it. rows=None means no report was read,
    users=None means no authorization details were read."""
    data = creds.AccountData(profile=profile, account=ACCT)
    if rows is not None:
        data.report = creds.parse_report(report_csv(rows))
    data.summary = summary if summary is not None else {"AccountMFAEnabled": 1,
                                                       "AccountAccessKeysPresent": 0}
    data.password_policy = policy
    data.password_policy_read = policy_read
    if users is not None:
        data.auth = {"users": list(users), "groups": list(groups), "roles": list(roles),
                     "policies": list(policies)}
    data.keys = keys if keys is not None else {}
    for k, v in extra.items():
        setattr(data, k, v)
    return data


def run(data, **kw):
    return creds.analyze([data], now=NOW, **kw)


def codes(result, name=None) -> list:
    return [f.code for f in result.findings if name is None or f.name == name]


def only(result, code, name=None):
    found = [f for f in result.findings if f.code == code and (name is None or f.name == name)]
    if len(found) != 1:
        raise AssertionError(f"expected one {code} for {name}, got {[f.code for f in found]} "
                             f"of {codes(result)}")
    return found[0]


def ident(result, name, kind="user"):
    return next(i for i in result.identities if i.name == name and i.kind == kind)


# =================================================================== helpers

class HelperTests(unittest.TestCase):
    def test_mask_key(self):
        self.assertEqual(creds.mask_key("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE")
        self.assertEqual(creds.mask_key("SHORT"), "****")
        self.assertEqual(creds.mask_key(""), "")
        self.assertEqual(creds.mask_key(None), "")

    def test_parse_date(self):
        for value in ("N/A", "no_information", "not_supported", "", None, "garbage"):
            self.assertIsNone(creds.parse_date(value), value)
        dt = creds.parse_date("2026-03-01T10:00:00+00:00")
        self.assertEqual((dt.year, dt.month, dt.tzinfo is not None), (2026, 3, True))
        self.assertIsNotNone(creds.parse_date("2026-03-01T10:00:00Z").tzinfo)

    def test_parse_report_keeps_every_column(self):
        rows = creds.parse_report(report_csv([row("<root_account>", root=True, mfa=True),
                                              row("alice", password=50, used=3)]))
        self.assertEqual([r["user"] for r in rows], ["<root_account>", "alice"])
        self.assertEqual(rows[1]["password_enabled"], "true")
        self.assertIn("cert_2_last_rotated", rows[1])
        self.assertEqual(creds.parse_report(b""), [])

    def test_report_rows_that_dont_line_up_are_left_out(self):
        # IAM names can hold commas. Written without quotes, a user named like this would
        # pose as alice in the report, with MFA on. Its ARN gives it away.
        name = "alice,x,2020-01-01,true,2026-10-04,2020-01-01,,true"
        real = report_csv([row("alice", created=300, password=300, used=1)]).decode()
        forged = (f"{name},arn:aws:iam::{ACCT}:user/{name},2026-01-01T00:00:00+00:00"
                  + ",false" * 15 + "\n")
        rows, skipped = creds.report_rows(real + forged)
        self.assertEqual([r["user"] for r in rows], ["alice"])
        self.assertEqual(skipped, 1)
        data = account(None, users=[user("alice", 300)])
        data.report, data.report_skipped = rows, skipped
        r = run(data)
        self.assertIn("console_no_mfa", codes(r, "alice"))
        self.assertTrue(any("didn't line up" in w for w in r.warnings))
        # Too few columns, or an ARN for someone else, is left out too.
        short = "\n".join(real.splitlines()[:1] + ["bob,arn:aws:iam::1:user/bob,N/A"])
        self.assertEqual(creds.report_rows(short), ([], 1))
        other = real.replace("user/alice", "user/mallory")
        self.assertEqual(creds.report_rows(other)[1], 1)

    def test_days_argument(self):
        self.assertEqual(creds.days_arg("90"), 90)
        self.assertEqual(creds.days_arg("30d"), 30)
        import argparse
        for bad in ("0", "abc", "5000", "-3"):
            with self.assertRaises(argparse.ArgumentTypeError):
                creds.days_arg(bad)

    def test_shell_words(self):
        self.assertEqual(creds.q("alice@example.com"), "alice@example.com")
        self.assertEqual(creds.q("a b"), "'a b'")
        self.assertEqual(creds.q("x;rm -rf ~"), "'x;rm -rf ~'")

    def test_text_has_no_long_dashes(self):
        text = "".join((ROOT / "credentials" / name).read_text(encoding="utf-8")
                       for name in ("creds.py", "creds_page.py", "README.md"))
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\u2013", text)


# =================================================================== root

class RootTests(unittest.TestCase):
    def test_root_keys_mfa_and_certs(self):
        r = run(account([row("<root_account>", root=True, mfa=False, created=900, used=400,
                              keys=[{"created": 800, "used": 300}],
                              certs=[{"created": 700}])], users=[], summary=ROOT_BAD))
        f = only(r, "root_keys")
        self.assertEqual(f.severity, "critical")
        self.assertIn("1 active access key", f.detail)
        self.assertEqual(only(r, "root_mfa").severity, "high")
        self.assertEqual(only(r, "root_certs").severity, "low")
        self.assertNotIn("root_used", codes(r))  # 300 and 400 days ago is outside 90

    def test_root_used_recently_with_the_date(self):
        r = run(account([row("<root_account>", root=True, mfa=True, used=12)], users=[]))
        f = only(r, "root_used")
        self.assertEqual(f.severity, "medium")
        self.assertIn((NOW - timedelta(days=12, hours=1)).strftime("%Y-%m-%d"), f.detail)
        self.assertIn("12 days ago", f.detail)
        self.assertIn("awskit trail --user root", f.command)
        self.assertTrue(f.command.endswith(" -p lab"))  # the account it was found in
        # The window is the Unused for setting.
        self.assertNotIn("root_used", codes(run(account(
            [row("<root_account>", root=True, mfa=True, used=12)], users=[]), unused=10)))

    def test_root_key_use_counts_as_root_use(self):
        r = run(account([row("<root_account>", root=True, mfa=True,
                              keys=[{"created": 50, "used": 2, "region": "eu-west-1"}])],
                        users=[], summary={"AccountMFAEnabled": 1,
                                           "AccountAccessKeysPresent": 1}))
        self.assertIn("eu-west-1", only(r, "root_used").detail)
        self.assertEqual(only(r, "root_keys").severity, "critical")

    def test_the_live_summary_wins_over_an_older_report(self):
        # MFA was added and the keys deleted after IAM made the report.
        r = run(account([row("<root_account>", root=True, mfa=False,
                              keys=[{"created": 800, "used": 300}], certs=[{"created": 70}])],
                        users=[], summary={"AccountMFAEnabled": 1,
                                           "AccountAccessKeysPresent": 0,
                                           "AccountSigningCertificatesPresent": 0}))
        self.assertEqual(codes(r), [])
        # Without the summary, the report is all there is.
        r = run(account([row("<root_account>", root=True, mfa=False,
                              keys=[{"created": 800, "used": 300}])], users=[]))
        r.accounts[0].summary = None
        r = creds.analyze(r.accounts, now=NOW)
        self.assertEqual(sorted(codes(r)), ["root_keys", "root_mfa"])

    def test_clean_root(self):
        r = run(account([row("<root_account>", root=True, mfa=True, used=200)], users=[]))
        self.assertEqual(codes(r), [])
        root = ident(r, "root", "root")
        self.assertEqual(root.admin, "yes")
        self.assertIn("Root has MFA and no access keys.", r.summary())

    def test_root_from_the_account_summary_when_the_report_has_no_root_row(self):
        r = run(account([], users=[], summary={"AccountMFAEnabled": 0,
                                               "AccountAccessKeysPresent": 1,
                                               "AccountSigningCertificatesPresent": 1}))
        self.assertEqual(sorted(codes(r)), ["root_certs", "root_keys", "root_mfa"])
        row_ = creds.identity_row(ident(r, "root", "root"), NOW)
        self.assertEqual(row_["password"], "?")
        self.assertEqual(row_["activity"], "?")


# =================================================================== users

class UserTests(unittest.TestCase):
    def test_console_without_mfa(self):
        r = run(account([row("jane", created=100, password=100, used=5)],
                        users=[user("jane", 100)]))
        f = only(r, "console_no_mfa", "jane")
        self.assertEqual(f.severity, "high")
        self.assertIn("aws iam delete-login-profile --user-name jane", f.command)
        self.assertIn("5 days ago", f.detail)
        self.assertNotIn("console_no_mfa", codes(run(account(
            [row("jane", created=100, password=100, used=5, mfa=True)], users=[user("jane", 100)]))))

    def test_password_unused_follows_the_threshold(self):
        data = account([row("bob", created=300, password=300, used=100, mfa=True,
                            keys=[{"created": 50, "used": 1}])],
                       users=[user("bob", 300)])
        f = only(run(data), "password_unused", "bob")
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.command, "aws iam delete-login-profile --user-name bob")
        self.assertNotIn("password_unused", codes(run(data, unused=120)))
        self.assertEqual(only(run(data, unused=60), "password_unused").check,
                         "Console password not used in 60+ days")

    def test_password_never_used_after_a_week(self):
        old = account([row("new", created=30, password=10, mfa=True,
                           keys=[{"created": 5, "used": 1}])], users=[user("new", 30)])
        f = only(run(old), "password_never_used", "new")
        self.assertEqual(f.severity, "medium")
        self.assertIn("never used", f.detail)
        fresh = account([row("new", created=30, password=3, mfa=True,
                             keys=[{"created": 5, "used": 1}])], users=[user("new", 30)])
        self.assertNotIn("password_never_used", codes(run(fresh)))

    def test_key_never_used_shows_the_id_only_in_the_command(self):
        data = account([row("ci", created=60, keys=[{"created": 30}, {"created": 40, "used": 2}])],
                       users=[user("ci", 60)],
                       keys={"ci": [key("AKIAEXAMPLENEVER0001", 30),
                                    key("AKIAEXAMPLEINUSE0002", 40, used=2)]})
        r = run(data)
        f = only(r, "key_never_used", "ci")
        self.assertEqual(f.severity, "medium")
        self.assertIn("aws iam update-access-key --user-name ci --access-key-id "
                      "AKIAEXAMPLENEVER0001 --status Inactive", f.command)
        self.assertIn("aws iam delete-access-key --user-name ci --access-key-id "
                      "AKIAEXAMPLENEVER0001", f.command)
        self.assertEqual(f.resource, "ci (AKIA****0001)")
        self.assertNotIn("AKIAEXAMPLENEVER0001", f.detail)
        # A key made in the last week isn't flagged yet.
        data.keys["ci"][0] = key("AKIAEXAMPLENEVER0001", 3)
        self.assertNotIn("key_never_used", codes(run(data)))

    def test_key_unused_and_key_age_thresholds(self):
        data = account([row("tf", created=500, keys=[{"created": 400, "used": 100}])],
                       users=[user("tf", 500)],
                       keys={"tf": [key("AKIAEXAMPLETFKEY0001", 400, used=100)]})
        # Used 100 days ago, so with 90 days unused it's flagged as unused (and the user as a
        # whole has had no activity, which replaces the key finding).
        self.assertIn("user_inactive", codes(run(data)))
        self.assertNotIn("key_unused", codes(run(data)))
        # Add a console sign-in yesterday so the user is active: now the key itself is unused.
        data.report = creds.parse_report(report_csv([row(
            "tf", created=500, password=500, used=1, mfa=True,
            keys=[{"created": 400, "used": 100}])]))
        f = only(run(data), "key_unused", "tf")
        self.assertEqual(f.severity, "medium")
        self.assertIn("100 days ago", f.detail)
        # With 120 days allowed, it's in use, but older than 90 days.
        old = only(run(data, unused=120), "key_old", "tf")
        self.assertEqual(old.severity, "low")
        self.assertIn("aws iam create-access-key --user-name tf", old.command)
        self.assertIn("Access key older than 90 days", old.check)
        self.assertEqual(codes(run(data, unused=120, key_age=500), "tf"), [])

    def test_two_active_keys_retire_the_least_used(self):
        data = account([row("svc", created=300, password=300, used=1, mfa=True,
                            keys=[{"created": 20, "used": 1}, {"created": 10, "used": 30}])],
                       users=[user("svc", 300)],
                       keys={"svc": [key("AKIAEXAMPLEKEEPS0001", 20, used=1),
                                     key("AKIAEXAMPLEDROPS0002", 10, used=30)]})
        f = only(run(data), "two_keys", "svc")
        self.assertEqual(f.severity, "low")
        self.assertIn("AKIAEXAMPLEDROPS0002 --status Inactive", f.command)
        self.assertNotIn("AKIAEXAMPLEKEEPS0001", f.command)
        self.assertIn("Keep AKIA****0001", f.fix)

    def test_inactive_keys_left_behind(self):
        data = account([row("old", created=300, password=300, used=1, mfa=True)],
                       users=[user("old", 300)],
                       keys={"old": [key("AKIAEXAMPLEINACTIV01", 200, used=150, active=False)]})
        f = only(run(data), "inactive_keys", "old")
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.command, "aws iam delete-access-key --user-name old --access-key-id "
                                    "AKIAEXAMPLEINACTIV01")

    def test_inactive_user_gets_one_delete_finding(self):
        data = account([row("intern", created=330, password=330, used=300,
                            keys=[{"created": 320}])],
                       users=[user("intern", 330, groups=["devs"], attached=[AWS + "ReadOnlyAccess"],
                                   inline={"extra": {"Version": "2012-10-17", "Statement": []}})],
                       groups=[group("devs")],
                       keys={"intern": [key("AKIAEXAMPLEINTERN001", 320)]},
                       ssh={}, mfa={})
        r = run(data)
        f = only(r, "user_inactive", "intern")
        self.assertEqual(f.severity, "medium")
        self.assertIn("300 days ago", f.detail)
        lines = f.command.splitlines()
        self.assertEqual(lines[-1], "aws iam delete-user --user-name intern")
        for expected in ("aws iam delete-login-profile --user-name intern",
                         "aws iam delete-access-key --user-name intern --access-key-id "
                         "AKIAEXAMPLEINTERN001",
                         "aws iam remove-user-from-group --user-name intern --group-name devs",
                         "aws iam detach-user-policy --user-name intern --policy-arn "
                         + AWS + "ReadOnlyAccess",
                         "aws iam delete-user-policy --user-name intern --policy-name extra"):
            self.assertIn(expected, lines)
        # The unused password and key are part of this one finding, not extra ones.
        for code in ("password_unused", "key_never_used", "key_unused"):
            self.assertNotIn(code, codes(r, "intern"))
        self.assertIn("console_no_mfa", codes(r, "intern"))  # still worth its own finding

    def test_never_active_user_with_nothing_at_all(self):
        r = run(account([row("ghost", created=200)], users=[user("ghost", 200)]))
        f = only(r, "user_inactive", "ghost")
        self.assertIn("can't do anything", f.detail)

    def test_ssh_keys_and_service_credentials_stop_the_inactive_finding(self):
        data = account([row("git", created=200)], users=[user("git", 200)],
                       ssh={"git": [{"id": "APKAEXAMPLESSHKEY001", "status": "Active",
                                     "uploaded": d(190)}]},
                       service_creds={"git": [
                           {"id": "ACCAEXAMPLESVC00001", "status": "Active",
                            "service": "codecommit.amazonaws.com", "created": d(180)},
                           {"id": "ACCAEXAMPLESVC00002", "status": "Active",
                            "service": "cassandra.amazonaws.com", "created": d(10)},
                           {"id": "ACCAEXAMPLESVC00003", "status": "Inactive",
                            "service": "codecommit.amazonaws.com", "created": d(10)}]})
        r = run(data)
        self.assertNotIn("user_inactive", codes(r))
        ssh = only(r, "ssh_keys", "git")
        self.assertEqual(ssh.severity, "low")
        self.assertIn("CodeCommit", ssh.detail)
        self.assertIn("--ssh-public-key-id APKAEXAMPLESSHKEY001", ssh.command)
        self.assertNotIn("APKAEXAMPLESSHKEY001", ssh.detail)
        svc = only(r, "service_creds", "git")
        self.assertIn("CodeCommit Git over HTTPS", svc.detail)
        self.assertIn("Amazon Keyspaces", svc.detail)
        self.assertEqual(svc.command.count("delete-service-specific-credential"), 2)

    def test_signing_certificates(self):
        r = run(account([row("soap", created=300, password=300, used=1, mfa=True,
                             certs=[{"created": 100}])], users=[user("soap", 300)],
                        certs={"soap": [{"id": "CERTEXAMPLE00001", "status": "Active",
                                         "uploaded": d(100)}]}))
        f = only(r, "signing_certs", "soap")
        self.assertEqual(f.severity, "low")
        self.assertIn("--certificate-id CERTEXAMPLE00001", f.command)
        # From the report alone there's no ID, so the command says how to find it.
        r = run(account([row("soap", created=300, password=300, used=1, mfa=True,
                             certs=[{"created": 100}])], users=[user("soap", 300)]))
        self.assertIn("list-signing-certificates", only(r, "signing_certs").command)

    def test_inline_policies_on_a_user(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
        r = run(account([row("dev", created=300, password=300, used=1, mfa=True)],
                        users=[user("dev", 300, inline={"read-b": doc, "read-c": doc})]))
        f = only(r, "inline_policy", "dev")
        self.assertEqual(f.severity, "low")
        self.assertIn("read-b, read-c", f.detail)
        self.assertIn("aws iam delete-user-policy --user-name dev --policy-name read-c", f.command)

    def test_user_not_in_the_report_yet(self):
        data = account([row("old", created=300, password=300, used=1, mfa=True)],
                       users=[user("old", 300), user("brand-new", 0)],
                       keys={"brand-new": [key("AKIAEXAMPLEBRANDNEW1", 0)]})
        r = run(data)
        new = ident(r, "brand-new")
        self.assertFalse(new.in_report)
        self.assertIsNone(new.console)
        self.assertEqual(codes(r, "brand-new"), [])
        self.assertTrue(any("brand-new" in w and "4 hours" in w for w in r.warnings))
        self.assertEqual(creds.identity_row(new, NOW)["console"], "?")

    def test_key_use_from_the_report_when_last_used_is_not_allowed(self):
        data = account([row("ci", created=300, password=300, used=1, mfa=True,
                            keys=[{"created": 200, "used": 150}])], users=[user("ci", 300)],
                       keys={"ci": [creds.AccessKey(id="AKIAEXAMPLEFROMREPT1", status="Active",
                                                    created=d(200))]},
                       key_use_read=False)
        f = only(run(data), "key_unused", "ci")
        self.assertIn("AKIAEXAMPLEFROMREPT1", f.command)

    def test_keys_from_the_report_without_ids(self):
        data = account([row("ci", created=300, password=300, used=1, mfa=True,
                            keys=[{"created": 200}])], users=[user("ci", 300)])
        f = only(run(data), "key_never_used", "ci")
        self.assertIn("ACCESS_KEY_ID", f.command)
        self.assertIn("aws iam list-access-keys --user-name ci", f.command)
        self.assertEqual(f.resource, "ci (key 1)")

    def test_report_only_key_commands_say_which_key(self):
        # Without IDs, the command has to say which key to look up, or the one in use
        # could be deactivated by mistake.
        data = account([row("ci", created=300, password=300, used=1, mfa=True,
                            keys=[{"created": 200, "used": 150}, {"created": 100, "used": 2}])],
                       users=[user("ci", 300)])
        f = only(run(data), "two_keys", "ci")
        self.assertIn(f"key created {d(200):%Y-%m-%d %H:%M} UTC", f.command)
        self.assertIn(f"key created {d(200):%Y-%m-%d %H:%M} UTC",
                      only(run(data), "key_unused", "ci").command)

    def test_unknown_key_use_is_not_never_used(self):
        # GetAccessKeyLastUsed wasn't allowed and the report can't say either.
        k = key("AKIAEXAMPLEUNKNOWN01", 200)
        k.use_known = False
        data = account([row("ci", created=300)], users=[user("ci", 300)],
                       keys={"ci": [k]}, key_use_read=False)
        r = run(data)
        self.assertNotIn("key_never_used", codes(r))
        self.assertNotIn("user_inactive", codes(r))  # it may be in use every day
        f = only(r, "key_old", "ci")
        self.assertIn("couldn't be read", f.detail)
        self.assertIn("get-access-key-last-used --access-key-id AKIAEXAMPLEUNKNOWN01", f.command)
        self.assertIn("last use not known", creds.identity_row(ident(r, "ci"), NOW)["keys"])
        # Two keys: no guess at which one to keep.
        k2 = key("AKIAEXAMPLEUNKNOWN02", 20)
        k2.use_known = False
        data.keys["ci"].append(k2)
        f = only(run(data), "two_keys", "ci")
        self.assertNotIn("update-access-key", f.command)
        self.assertIn("isn't known which one to keep", f.detail)

    def test_new_credentials_hold_off_the_inactive_finding(self):
        # Someone just made a key for an old, unused user: don't say delete the user.
        data = account([row("old", created=300)], users=[user("old", 300)],
                       keys={"old": [key("AKIAEXAMPLEJUSTMADE1", 1)]})
        self.assertEqual(codes(run(data), "old"), [])
        data.keys["old"][0] = key("AKIAEXAMPLEJUSTMADE1", 20)
        self.assertEqual(codes(run(data), "old"), ["user_inactive"])

    def test_unread_ssh_keys_hold_off_the_inactive_finding(self):
        # IAM doesn't record SSH key use, so if they couldn't be listed, the user may be
        # pushing to CodeCommit every day.
        data = account([row("git", created=200)], users=[user("git", 200)],
                       denied={"ssh": Exception("not allowed")})
        self.assertNotIn("user_inactive", codes(run(data)))
        data.ssh = {"git": []}  # read before the permission error, so it's known
        self.assertIn("user_inactive", codes(run(data)))


# =================================================================== admin

class AdminTests(unittest.TestCase):
    def setUp(self):
        self.rows = [row("a", created=300, password=300, used=1, mfa=True)]

    def admin_of(self, u, groups=(), policies=(), managed=None):
        data = account(self.rows, users=[u], groups=groups, policies=policies,
                       managed_docs=managed or {})
        r = run(data)
        return ident(r, u["UserName"]), r

    def test_admin_through_a_group_with_and_without_keys(self):
        data = account(self.rows, users=[user("a", 300, groups=["Admins"])],
                       groups=[group("Admins", attached=[AWS + "AdministratorAccess"])])
        r = run(data)
        a = ident(r, "a")
        self.assertEqual(a.admin, "yes")
        self.assertEqual(a.admin_why, "AdministratorAccess through group Admins")
        f = only(r, "admin_user", "a")
        self.assertEqual(f.severity, "medium")
        self.assertIn("aws iam remove-user-from-group --user-name a --group-name Admins",
                      f.command)
        data.keys = {"a": [key("AKIAEXAMPLEADMINKEY1", 30, used=1)]}
        r = run(data)
        f = only(r, "admin_keys", "a")
        self.assertEqual(f.severity, "high")
        self.assertIn("AKIAEXAMPLEADMINKEY1 --status Inactive", f.command)
        self.assertIn("AKIA****KEY1", f.detail)
        self.assertEqual(ident(r, "a").worst.code, "admin_keys")

    def test_admin_through_inline_and_customer_policies(self):
        a, r = self.admin_of(user("a", 300, inline={"god": ADMIN_DOC}))
        self.assertEqual(a.admin, "yes")
        self.assertIn("inline policy god allows * on *", a.admin_why)
        self.assertIn("aws iam delete-user-policy --user-name a --policy-name god",
                      only(r, "admin_user").command)
        arn = f"arn:aws:iam::{ACCT}:policy/custom-admin"
        a, r = self.admin_of(user("a", 300, attached=[arn]),
                             policies=[customer_policy("custom-admin", ADMIN_DOC)])
        self.assertEqual(a.admin, "yes")
        self.assertIn(f"detach-user-policy --user-name a --policy-arn {arn}",
                      only(r, "admin_user").command)

    def test_not_action_policies(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": "*"}]}
        a, _ = self.admin_of(user("a", 300, inline={"almost": doc}))
        self.assertEqual(a.admin, "yes")
        a, _ = self.admin_of(user("a", 300, attached=[AWS + "PowerUserAccess"]))
        self.assertEqual(a.admin, "no")

    def test_can_make_itself_admin(self):
        a, r = self.admin_of(user("a", 300, attached=[AWS + "IAMFullAccess"]))
        self.assertEqual(a.admin, "can become")
        f = only(r, "can_escalate", "a")
        self.assertEqual(f.severity, "high")
        self.assertIn("iam:*", f.detail)
        self.assertIn(f"detach-user-policy --user-name a --policy-arn {AWS}IAMFullAccess",
                      f.command)
        put = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:PutUserPolicy", "iam:AttachUserPolicy"],
             "Resource": "*"}]}
        a, _ = self.admin_of(user("a", 300, groups=["ops"]), groups=[group("ops", inline={"x": put})])
        self.assertEqual(a.admin, "can become")
        self.assertIn("through group ops", a.admin_why)

    def test_own_user_arn(self):
        self_grant = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PutUserPolicy",
             "Resource": "arn:aws:iam::*:user/${aws:username}"}]}
        a, _ = self.admin_of(user("a", 300, inline={"self": self_grant}))
        self.assertEqual(a.admin, "can become")
        self.assertIn("on the user itself", a.admin_why)
        manage_own = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:UpdateLoginProfile",
                                           "iam:*MFADevice"],
             "Resource": "arn:aws:iam::*:user/${aws:username}"}]}
        a, r = self.admin_of(user("a", 300, inline={"own": manage_own}))
        self.assertEqual(a.admin, "no")
        self.assertNotIn("can_escalate", codes(r))

    def test_passrole_with_a_service_that_runs_as_a_role(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"}]}
        a, r = self.admin_of(user("a", 300, inline={"deploy": doc}))
        self.assertEqual(a.admin, "can become")
        self.assertIn("iam:PassRole", a.admin_why)
        self.assertIn("lambda:CreateFunction", a.admin_why)
        narrow = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole",
             "Resource": f"arn:aws:iam::{ACCT}:role/lambda-exec"},
            {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"}]}
        a, _ = self.admin_of(user("a", 300, inline={"deploy": narrow}))
        self.assertEqual(a.admin, "no")

    def test_narrow_iam_and_deny_only(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:AttachRolePolicy",
             "Resource": f"arn:aws:iam::{ACCT}:role/app-role"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        a, _ = self.admin_of(user("a", 300, inline={"narrow": doc}))
        self.assertEqual(a.admin, "no")

    def test_own_user_arn_written_out(self):
        # The user's own ARN, or a pattern that covers it, is the same as user/${aws:username}.
        for res in (f"arn:aws:iam::{ACCT}:user/a", f"arn:aws:iam::{ACCT}:user/*a",
                    "arn:aws:iam::*:user/${aws:UserName}"):
            doc = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": res}]}
            a, r = self.admin_of(user("a", 300, inline={"self": doc}))
            self.assertEqual(a.admin, "can become", res)
            self.assertIn("on the user itself", a.admin_why)
        # Another user's ARN isn't its own.
        doc["Statement"][0]["Resource"] = f"arn:aws:iam::{ACCT}:user/b"
        a, _ = self.admin_of(user("a", 300, inline={"other": doc}))
        self.assertEqual(a.admin, "no")

    def test_managing_own_credentials_with_any_spelling_is_fine(self):
        # Policy variables aren't case sensitive, and the account part is a wildcard.
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
             "Resource": "arn:aws:iam::*:user/${aws:userName}"}]}
        a, r = self.admin_of(user("a", 300, inline={"own": doc}))
        self.assertEqual(a.admin, "no")
        self.assertNotIn("can_escalate", codes(r))

    def test_wildcards_on_other_services_cant_touch_iam(self):
        for res in ("arn:aws:s3:::*", "arn:aws:dynamodb:*:*:table/app-*"):
            doc = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": res}]}
            a, r = self.admin_of(user("a", 300, inline={"data": doc}))
            self.assertEqual(a.admin, "no", res)
            self.assertNotIn("can_escalate", codes(r))
        # A service wildcard can still match IAM.
        doc["Statement"][0]["Resource"] = "arn:aws:*:*:*:*"
        a, _ = self.admin_of(user("a", 300, inline={"data": doc}))
        self.assertEqual(a.admin, "yes")

    def test_role_that_can_change_its_own_policies(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PutRolePolicy",
             "Resource": f"arn:aws:iam::{ACCT}:role/deployer"}]}
        r = run(account([], users=[], roles=[role("deployer", 10, used=1,
                                                   inline={"self": doc})]))
        d_ = ident(r, "deployer", "role")
        self.assertEqual(d_.admin, "can become")
        self.assertIn("on the role itself", d_.admin_why)
        # user/${aws:username} means nothing for a role.
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PutUserPolicy",
             "Resource": "arn:aws:iam::*:user/${aws:username}"}]}
        r = run(account([], users=[], roles=[role("app", 10, used=1, inline={"x": doc})]))
        self.assertEqual(ident(r, "app", "role").admin, "no")

    def test_unknown_aws_managed_policy_leaves_admin_open(self):
        a, r = self.admin_of(user("a", 300, attached=[AWS + "SomethingNew"]))
        self.assertEqual(a.admin, "")
        self.assertEqual(creds.identity_row(a, NOW)["admin"], "?")
        a, _ = self.admin_of(user("a", 300, attached=[AWS + "SomethingNew"]),
                             managed={AWS + "SomethingNew": ADMIN_DOC})
        self.assertEqual(a.admin, "yes")

    def test_boundary_is_mentioned(self):
        _, r = self.admin_of(user("a", 300, attached=[AWS + "AdministratorAccess"],
                                  boundary=f"arn:aws:iam::{ACCT}:policy/boundary"))
        self.assertIn("permissions boundary", only(r, "admin_user").detail)


# =================================================================== roles

class RoleTests(unittest.TestCase):
    def roles(self, *roles, **kw):
        return run(account([], users=[], roles=list(roles)), **kw)

    def test_unused_role(self):
        r = self.roles(role("old-lambda", 400, used=200, region="eu-west-1",
                            attached=[AWS + "ReadOnlyAccess"], inline={"x": {"Statement": []}},
                            profiles=["old-lambda-profile"]))
        f = only(r, "role_unused", "old-lambda")
        self.assertEqual(f.severity, "low")
        self.assertIn("200 days ago", f.detail)
        self.assertIn("eu-west-1", f.detail)
        self.assertIn("400 days", f.why)
        lines = f.command.splitlines()
        self.assertTrue(lines[0].startswith("# Detach"))
        self.assertEqual(lines[-1], "aws iam delete-role --role-name old-lambda")
        self.assertIn("aws iam detach-role-policy --role-name old-lambda --policy-arn "
                      + AWS + "ReadOnlyAccess", lines)
        self.assertIn("aws iam delete-role-policy --role-name old-lambda --policy-name x", lines)
        self.assertIn("aws iam remove-role-from-instance-profile --instance-profile-name "
                      "old-lambda-profile --role-name old-lambda", lines)
        self.assertEqual(codes(self.roles(role("old-lambda", 400, used=200)), "old-lambda"),
                         ["role_unused"])
        self.assertEqual(codes(self.roles(role("old-lambda", 400, used=200), unused=365)), [])

    def test_unused_admin_role_is_medium(self):
        r = self.roles(role("break-glass", 400, used=150, attached=[AWS + "AdministratorAccess"]))
        f = only(r, "role_unused")
        self.assertEqual(f.severity, "medium")
        self.assertIn("It has admin", f.detail)

    def test_never_used_role(self):
        r = self.roles(role("never", 120), role("new", 10),
                       role("never-admin", 120, inline={"god": ADMIN_DOC}))
        self.assertEqual(only(r, "role_never_used", "never").severity, "low")
        self.assertEqual(only(r, "role_never_used", "never-admin").severity, "medium")
        self.assertEqual(codes(r, "new"), [])

    def test_aws_managed_roles_are_counted_but_not_flagged(self):
        r = self.roles(
            role("AWSServiceRoleForSupport", 900, path="/aws-service-role/support.amazonaws.com/",
                 attached=[AWS + "aws-service-role/AWSSupportServiceRolePolicy"]),
            role("AWSReservedSSO_AdministratorAccess_0123456789abcdef", 900,
                 path="/aws-reserved/sso.amazonaws.com/", attached=[AWS + "AdministratorAccess"]),
            role("AWSReservedSSO_ReadOnly_0123456789abcdef", 900,
                 path="/aws-reserved/sso.amazonaws.com/eu-west-1/"),
            role("mine", 900, used=300))
        self.assertEqual(codes(r), ["role_unused"])
        self.assertEqual(len([i for i in r.identities if i.kind == "role"]), 4)
        self.assertEqual(r.stats["roles"], 4)
        self.assertEqual(r.stats["roles_aws"], 3)
        self.assertEqual(r.stats["roles_unused"], 1)
        sso = ident(r, "AWSReservedSSO_AdministratorAccess_0123456789abcdef", "role")
        self.assertEqual(sso.admin, "yes")  # people's admin access shows in the inventory
        slr = ident(r, "AWSServiceRoleForSupport", "role")
        self.assertEqual(slr.admin, "")
        rowd = creds.identity_row(slr, NOW)
        self.assertTrue(rowd["_dim"])
        self.assertIn("managed by AWS", rowd["top"])
        self.assertIn("4 roles (3 managed by AWS), 1 unused for 90 days or more", r.summary())

    def test_trust_summary(self):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {
                "Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
             "Action": "sts:AssumeRoleWithWebIdentity"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:role/ci"},
             "Action": "sts:AssumeRole"}]}
        r = self.roles(role("x", 10, trust=trust))
        self.assertEqual(ident(r, "x", "role").trust,
                         ["account 444455556666", "GitHub OIDC", f"arn:aws:iam::{ACCT}:role/ci"])


# =================================================================== password policy

class PasswordPolicyTests(unittest.TestCase):
    console = [row("p", created=300, password=300, used=1, mfa=True)]

    def test_missing_only_matters_with_console_users(self):
        r = run(account(self.console, users=[user("p", 300)], policy=None))
        f = only(r, "no_password_policy")
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.kind, "account")
        self.assertIn("--minimum-password-length 14", f.command)
        self.assertIn("--password-reuse-prevention 24", f.command)
        keys_only = [row("k", created=300, keys=[{"created": 10, "used": 1}])]
        self.assertEqual(codes(run(account(keys_only, users=[user("k", 300)], policy=None))), [])

    def test_weak_policy_keeps_the_good_settings(self):
        weak = {"MinimumPasswordLength": 8, "RequireSymbols": True, "MaxPasswordAge": 90,
                "AllowUsersToChangePassword": False}
        f = only(run(account(self.console, users=[user("p", 300)], policy=weak)),
                 "weak_password_policy")
        self.assertEqual(f.severity, "low")
        for text in ("minimum length is 8", "used again", "can't change their own"):
            self.assertIn(text, f.detail.lower())
        self.assertNotIn("max", f.detail.lower())  # no expiry is fine, per current NIST advice
        self.assertIn("--require-symbols", f.command)
        self.assertIn("--max-password-age 90", f.command)
        self.assertNotIn("--require-numbers", f.command)

    def test_good_policy(self):
        good = {"MinimumPasswordLength": 16, "PasswordReusePrevention": 5,
                "AllowUsersToChangePassword": True}
        self.assertEqual(codes(run(account(self.console, users=[user("p", 300)], policy=good))),
                         [])

    def test_unreadable_policy_is_not_reported_as_missing(self):
        r = run(account(self.console, users=[user("p", 300)], policy=None, policy_read=False))
        self.assertNotIn("no_password_policy", codes(r))


# =================================================================== inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.data = account(
            [row("<root_account>", root=True, mfa=True, used=40),
             row("alice", created=400, password=400, used=3, mfa=False,
                 keys=[{"created": 120, "used": 3}]),
             row("bot", created=500, keys=[{"created": 400, "used": 1}, {"created": 30, "used": 200}])],
            users=[user("alice", 400, groups=["Admins"]), user("bot", 500)],
            groups=[group("Admins", attached=[AWS + "AdministratorAccess"])],
            roles=[role("deploy", 300, used=1), role("stale", 300, used=150)],
            keys={"alice": [key("AKIAEXAMPLEALICE0001", 120, used=3)],
                  "bot": [key("AKIAEXAMPLEBOTKEY001", 400, used=1),
                          key("AKIAEXAMPLEBOTKEY002", 30, used=200)]})
        self.r = run(self.data)

    def test_rows(self):
        rows = {(i.kind, i.name): creds.identity_row(i, NOW) for i in self.r.identities}
        alice = rows[("user", "alice")]
        self.assertEqual(alice["console"], "yes, no MFA")
        self.assertEqual(alice["password"], "3 days ago")
        self.assertEqual(alice["keys"], "1 active, 120 days old, used 3 days ago")
        self.assertEqual(alice["activity"], "3 days ago")
        self.assertEqual(alice["admin"], "yes")
        self.assertEqual(alice["worst"], "high")
        self.assertEqual(alice["top"], "Admin user with access keys")
        bot = rows[("user", "bot")]
        self.assertEqual(bot["console"], "no")
        self.assertEqual(bot["keys"], "2 active, oldest 400 days, last used 1 day ago")
        self.assertEqual(bot["activity"], "1 day ago")
        self.assertEqual(bot["admin"], "no")
        self.assertEqual(rows[("root", "root")]["activity"], "40 days ago")
        self.assertEqual(rows[("role", "deploy")]["activity"], "1 day ago")
        self.assertEqual(rows[("role", "stale")]["worst"], "low")
        order = [(i.kind, i.name) for i in self.r.identities]
        self.assertEqual(order[0], ("root", "root"))
        self.assertLess(order.index(("user", "bot")), order.index(("role", "deploy")))

    def test_summary_line(self):
        self.assertEqual(self.r.summary(),
                         "2 users, 1 with console access, 1 without MFA. 3 active access "
                         "keys, 2 older than 90 days. 2 roles, 1 unused for 90 days or more. "
                         "Root has MFA and no access keys.")
        self.assertIn("1 older than 200 days", run(self.data, key_age=200).summary())

    def test_masking_everywhere_but_commands(self):
        full = ["AKIAEXAMPLEALICE0001", "AKIAEXAMPLEBOTKEY001", "AKIAEXAMPLEBOTKEY002"]
        shown = []
        for f in self.r.findings:
            shown += [str(v) for k, v in f.row().items() if k != "command"]
        for i in self.r.identities:
            shown += [str(v) for v in creds.identity_row(i, NOW).values()]
            shown.append(creds.identity_text(i, NOW))
            shown.append(json.dumps(creds.identity_json(i, NOW), default=str))
        blob = "\n".join(shown)
        for k in full:
            self.assertNotIn(k, blob)
        self.assertIn("AKIA****0001", blob)
        commands = "\n".join(f.command for f in self.r.findings)
        self.assertIn("AKIAEXAMPLEBOTKEY002", commands)
        text = creds.finding_text(only(self.r, "two_keys", "bot"), ident(self.r, "bot"), NOW)
        before, _, after = text.partition("Command:")
        self.assertNotIn("AKIAEXAMPLEBOTKEY002", before)
        self.assertIn("AKIAEXAMPLEBOTKEY002", after.split("About this identity")[0])

    def test_identity_text(self):
        text = creds.identity_text(ident(self.r, "alice"), NOW)
        for expected in ("User alice", "Groups: Admins", "AdministratorAccess (through group "
                         "Admins)", "Admin: yes", "AKIA****0001", "Findings:",
                         "[HIGH] Admin user with access keys"):
            self.assertIn(expected, text)
        role_text = creds.identity_text(ident(self.r, "deploy", "role"), NOW)
        self.assertIn("Trusted by: ec2.amazonaws.com", role_text)

    def test_thresholds_change_the_judgement_without_new_data(self):
        again = creds.analyze(self.r.accounts, key_age=30, unused=365, now=NOW)
        self.assertNotIn("role_unused", codes(again))
        self.assertIn("key_old", codes(again, "alice"))
        self.assertEqual(again.key_age, 30)

    def test_markdown_report(self):
        text = creds.markdown_report(self.r, ["lab"])
        self.assertIn("# Credentials", text)
        self.assertIn("## Findings", text)
        self.assertIn("## Identities", text)
        self.assertIn("## Commands", text)
        self.assertIn("```bash", text)
        self.assertIn("Profiles: lab", text)
        tables = text.split("## Commands")[0]
        self.assertNotIn("AKIAEXAMPLEALICE0001", tables)


# =================================================================== reading

def denied(op):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, op)


class FakeIAM:
    """Stands in for the IAM client. Methods listed in deny raise AccessDenied, ones in
    errors raise that ClientError code, everything else returns from responses."""

    def __init__(self, responses=None, deny=(), errors=None):
        self.responses = responses or {}
        self.deny = set(deny)
        self.errors = errors or {}
        self.calls = []
        self.lock = threading.Lock()

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            with self.lock:
                self.calls.append(name)
            if name in self.deny:
                raise denied(name)
            if name in self.errors:
                raise ClientError({"Error": {"Code": self.errors[name], "Message": "x"}}, name)
            value = self.responses.get(name, {})
            return value(**kwargs) if callable(value) else value
        return call

    def get_paginator(self, name):
        outer = self

        class Pager:
            def paginate(self, **kwargs):
                outer.calls.append(name)
                if name in outer.deny:
                    raise denied(name)
                yield from outer.responses.get(name, [{}])
        return Pager()


class FakeCtx:
    def __init__(self, iam, profile="lab"):
        self.iam = iam
        self.profile = profile
        self.account = ACCT

    def client(self, service, region=None):
        return self.iam


@unittest.skipIf(mock_aws is None, "boto3 or moto not installed")
class ReadingTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(creds, "REPORT_POLL", 0.01)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_permission_at_all_turns_into_notes(self):
        everything = ("generate_credential_report", "get_credential_report",
                      "get_account_summary", "get_account_password_policy",
                      "get_account_authorization_details")
        data = creds.read_account(FakeCtx(FakeIAM(deny=everything)))
        r = creds.analyze([data], now=NOW)
        self.assertEqual(r.identities, [])
        self.assertEqual(sorted(codes(r)), ["auth_missing", "report_missing"])
        self.assertTrue(all(f.severity == "info" for f in r.findings))
        notes = "\n".join(r.warnings)
        for action in ("iam:GetAccountAuthorizationDetails", "iam:GetCredentialReport",
                       "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy"):
            self.assertIn(action, notes)
        self.assertIn("lab: no permission", notes)
        self.assertEqual(r.summary(), "Nothing could be read.")

    def test_report_states(self):
        for code, words in (("ReportInProgress", "still making"),
                            ("ReportNotPresent", "no credential report yet"),
                            ("ReportExpired", "4 hours")):
            iam = FakeIAM({"generate_credential_report": {"State": "COMPLETE"}},
                          errors={"get_credential_report": code})
            data = creds.read_account(FakeCtx(iam))
            r = creds.analyze([data], now=NOW)
            self.assertTrue(any(words in w for w in r.warnings), (code, r.warnings))
            self.assertIn("report_missing", codes(r))

    def test_old_report_used_when_generating_is_not_allowed(self):
        iam = FakeIAM({"get_credential_report": {
            "Content": report_csv([row("<root_account>", root=True, mfa=True)]),
            "GeneratedTime": d(0)}}, deny=["generate_credential_report"])
        data = creds.read_account(FakeCtx(iam))
        self.assertTrue(data.generate_denied)
        self.assertEqual(len(data.report), 1)
        r = creds.analyze([data], now=NOW)
        self.assertTrue(any("used the last credential report" in w for w in r.warnings))

    def test_report_is_waited_for(self):
        states = iter(["STARTED", "INPROGRESS", "COMPLETE"])
        iam = FakeIAM({"generate_credential_report": lambda: {"State": next(states)},
                       "get_credential_report": {"Content": report_csv([])}})
        creds.read_account(FakeCtx(iam))
        self.assertEqual(iam.calls.count("generate_credential_report"), 3)

    def test_a_denied_user_call_is_only_tried_once(self):
        users = [user(f"u{n}", 100) for n in range(6)]
        iam = FakeIAM({
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": report_csv([row(f"u{n}", 100) for n in range(6)])},
            "get_account_authorization_details": [{"UserDetailList": users[:3]},
                                                   {"UserDetailList": users[3:]}],
            "list_access_keys": {"AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLEPAGEDKEY1", "Status": "Active", "CreateDate": d(50)}]},
            "get_access_key_last_used": {"AccessKeyLastUsed": {"LastUsedDate": d(2),
                                                               "ServiceName": "s3",
                                                               "Region": "us-east-1"}},
            "list_signing_certificates": {"Certificates": []},
        }, deny=["list_ssh_public_keys"], errors={"list_service_specific_credentials": "Boom"})
        data = creds.read_account(FakeCtx(iam), workers=1)
        self.assertEqual(iam.calls.count("list_ssh_public_keys"), 1)
        self.assertEqual(iam.calls.count("list_service_specific_credentials"), 1)
        self.assertEqual(len(data.auth["users"]), 6)  # both pages
        self.assertEqual(data.keys["u3"][0].service, "s3")
        r = creds.analyze([data], now=NOW)
        notes = "\n".join(r.warnings)
        self.assertIn("no permission for iam:ListSSHPublicKeys, so SSH keys weren't checked",
                      notes)
        self.assertIn("couldn't read service-specific credentials", notes)

    def test_key_use_that_cant_be_read_anywhere(self):
        # No credential report and no GetAccessKeyLastUsed: the key isn't "never used".
        iam = FakeIAM({
            "get_account_authorization_details": [{"UserDetailList": [user("ci", 300)]}],
            "list_access_keys": {"AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLEINUSEKEY1", "Status": "Active",
                 "CreateDate": d(200)}]},
        }, deny=["generate_credential_report", "get_credential_report",
                 "get_access_key_last_used"])
        data = creds.read_account(FakeCtx(iam))
        self.assertFalse(data.keys["ci"][0].use_known)
        r = creds.analyze([data], now=NOW)
        self.assertNotIn("key_never_used", codes(r))
        self.assertIn("couldn't be read", only(r, "key_old", "ci").detail)
        # With the report, its slot fills in the use.
        iam.deny.discard("get_credential_report")
        iam.responses["get_credential_report"] = {"Content": report_csv([row(
            "ci", created=300, keys=[{"created": 200, "used": 3}])])}
        r = creds.analyze([creds.read_account(FakeCtx(iam))], now=NOW)
        self.assertTrue(ident(r, "ci").keys[0].use_known)
        self.assertEqual(codes(r, "ci"), ["key_old"])
        self.assertIn("3 days ago", only(r, "key_old").detail)

    def test_aws_managed_policies_are_read_once_and_shared(self):
        users = [user("a", 100, attached=[AWS + "SomethingNew"]),
                 user("b", 100, attached=[AWS + "AdministratorAccess"])]
        responses = {
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": report_csv([])},
            "get_account_authorization_details": [{"UserDetailList": users}],
            "get_policy": {"Policy": {"DefaultVersionId": "v3"}},
            "get_policy_version": {"PolicyVersion": {"Document": ADMIN_DOC}},
        }
        cache = {}
        iam = FakeIAM(responses)
        data = creds.read_account(FakeCtx(iam), cache=cache)
        creds.read_account(FakeCtx(iam, "other"), cache=cache)
        self.assertEqual(iam.calls.count("get_policy"), 1)  # AdministratorAccess is built in
        self.assertEqual(ident(creds.analyze([data], now=NOW), "a").admin, "yes")

    def test_cancel(self):
        cancel = threading.Event()
        cancel.set()
        iam = FakeIAM({"generate_credential_report": {"State": "STARTED"}})
        with self.assertRaises(creds.Stopped):
            creds.read_account(FakeCtx(iam), cancel=cancel)


# =================================================================== end to end with moto

@contextlib.contextmanager
def output():
    out, errs = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
        yield out, errs


@unittest.skipIf(mock_aws is None, "boto3 or moto not installed")
class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.config = Path(os.environ["AWS_CONFIG_FILE"])
        self.creds_file = Path(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
        self.saved = {p: p.read_bytes() if p.exists() else None
                      for p in (self.config, self.creds_file)}
        self.config.write_text("[profile lab-a]\nregion = us-east-1\n"
                               "[profile lab-b]\nregion = us-east-1\n")
        self.creds_file.write_text("[lab-a]\naws_access_key_id = testing\n"
                                   "aws_secret_access_key = testing\n"
                                   "[lab-b]\naws_access_key_id = testing\n"
                                   "aws_secret_access_key = testing\n")
        self.mock = mock_aws(config={"iam": {"load_aws_managed_policies": True}})
        self.mock.start()
        for p in (mock.patch.object(creds, "REPORT_POLL", 0.01),
                  mock.patch("awskit.profiles.current_profile", lambda: "lab-a")):
            p.start()
            self.addCleanup(p.stop)
        # moto has no ListServiceSpecificCredentials yet, so answer it here.
        real = botocore.client.BaseClient._make_api_call

        def api(client, operation, params):
            if operation == "ListServiceSpecificCredentials":
                if params.get("UserName") == "git-bot":
                    return {"ServiceSpecificCredentials": [{
                        "ServiceSpecificCredentialId": "ACCAEXAMPLEGITBOT001",
                        "ServiceName": "codecommit.amazonaws.com", "Status": "Active",
                        "ServiceUserName": "git-bot-at-123456789012", "CreateDate": d(10)}]}
                return {"ServiceSpecificCredentials": []}
            if operation in getattr(self, "deny", ()):
                raise denied(operation)
            return real(client, operation, params)
        p = mock.patch.object(botocore.client.BaseClient, "_make_api_call", api)
        p.start()
        self.addCleanup(p.stop)

        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_group(GroupName="Admins")
        iam.attach_group_policy(GroupName="Admins", PolicyArn=AWS + "AdministratorAccess")
        iam.create_user(UserName="alice")
        iam.create_login_profile(UserName="alice", Password="Long-enough-password-1")
        iam.add_user_to_group(GroupName="Admins", UserName="alice")
        self.key_id = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
        iam.create_user(UserName="tf")
        iam.attach_user_policy(UserName="tf", PolicyArn=AWS + "IAMFullAccess")
        iam.create_user(UserName="git-bot")
        iam.upload_ssh_public_key(UserName="git-bot",
                                  SSHPublicKeyBody="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLx git")
        iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
                "Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
        iam.attach_role_policy(RoleName="app", PolicyArn=AWS + "AWSLambda_FullAccess")
        iam.create_role(RoleName="AWSServiceRoleForSupport",
                        Path="/aws-service-role/support.amazonaws.com/",
                        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17",
                                                             "Statement": []}))

    def tearDown(self):
        self.mock.stop()
        for p, data in self.saved.items():
            if data is None:
                if p.exists():
                    p.unlink()
            else:
                p.write_bytes(data)

    def cli(self, *args):
        with output() as (out, errs):
            code = cli.main(["creds"] + list(args))
        return code, out.getvalue(), errs.getvalue()

    def test_findings_table(self):
        code, out, errs = self.cli()
        self.assertEqual(code, 0)
        for text in ("Admin user with access keys", "Console user without MFA",
                     "User can make itself admin", "Active SSH keys",
                     "Active service-specific credentials", "No IAM password policy",
                     "Root user has no MFA"):
            self.assertIn(text, out)
        self.assertIn("3 users, 1 with console access, 1 without MFA.", out)
        self.assertIn("2 roles (1 managed by AWS)", out)
        self.assertNotIn(self.key_id, out)  # tables are masked
        self.assertNotIn("Profile", out.splitlines()[0])  # one profile, no profile column
        self.assertIn("Add -v", out)
        self.assertEqual(errs, "")

    def test_verbose_prints_the_commands_with_the_key_id(self):
        code, out, _ = self.cli("-v")
        self.assertIn(f"aws iam update-access-key --user-name alice --access-key-id "
                      f"{self.key_id} --status Inactive", out)
        self.assertIn("aws iam remove-user-from-group --user-name alice --group-name Admins", out)
        self.assertIn("aws iam delete-service-specific-credential --user-name git-bot "
                      "--service-specific-credential-id ACCAEXAMPLEGITBOT001", out)

    def test_identities(self):
        code, out, _ = self.cli("--identities")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertIn("Access keys", lines[0])
        names = {line.split()[1] for line in lines[1:] if line.strip() and
                 line.split()[0] in ("root", "user", "role")}
        self.assertEqual(names, {"root", "alice", "tf", "git-bot", "app",
                                 "AWSServiceRoleForSupport"})
        alice = next(line for line in lines if line.startswith("user") and " alice " in line)
        self.assertIn("yes, no MFA", alice)
        self.assertIn("1 active", alice)
        self.assertNotIn(self.key_id, out)
        app = next(line for line in lines if line.startswith("role") and " app " in line)
        self.assertIn("can become", app)  # AWSLambda_FullAccess: PassRole plus lambda

    def test_json(self):
        code, out, _ = self.cli("--json", "--key-age", "30", "--unused", "60")
        data = json.loads(out)
        self.assertEqual((data["key_age_days"], data["unused_days"]), (30, 60))
        self.assertEqual(set(data), {"summary", "counts", "key_age_days", "unused_days",
                                     "findings", "identities", "warnings"})
        found = {(f["code"], f["name"]) for f in data["findings"]}
        self.assertIn(("admin_keys", "alice"), found)
        self.assertIn(("can_escalate", "tf"), found)
        alice = next(i for i in data["identities"] if i["name"] == "alice")
        self.assertEqual(alice["admin"], "yes")
        self.assertEqual(alice["access_keys"][0]["id"], creds.mask_key(self.key_id))
        cmd = next(f for f in data["findings"] if f["code"] == "admin_keys")["command"]
        self.assertIn(self.key_id, cmd)
        self.assertEqual(data["counts"]["high"], sum(1 for f in data["findings"]
                                                     if f["severity"] == "high"))

    def test_fail_on(self):
        self.assertEqual(self.cli("--fail-on", "high")[0], 2)
        self.assertEqual(self.cli("--fail-on", "critical")[0], 0)
        with output():
            with self.assertRaises(SystemExit):
                cli.main(["creds", "--unused", "0"])

    def test_markdown_file(self):
        path = Path(tempfile.mkdtemp(dir=TMP)) / "creds.md"
        code, out, _ = self.cli("--markdown", str(path))
        self.assertEqual(code, 0)
        self.assertIn(f"Wrote {path}", out)
        text = path.read_text()
        self.assertIn("## Commands", text)
        self.assertIn(self.key_id, text.split("## Commands")[1])
        self.assertNotIn(self.key_id, text.split("## Commands")[0])

    def test_several_profiles(self):
        code, out, _ = self.cli("-p", "lab-a", "-p", "lab-b")
        self.assertEqual(code, 0)
        self.assertIn("Profile", out.splitlines()[0])
        self.assertIn("lab-a", out)
        self.assertIn("lab-b", out)
        self.assertIn("2 accounts.", out)
        steps = []
        r = creds.check(["lab-a", "lab-b"], progress=lambda d, t, text: steps.append((d, t)))
        self.assertEqual(len(r.accounts), 2)
        self.assertEqual({i.profile for i in r.identities}, {"lab-a", "lab-b"})
        self.assertEqual(steps[-1][1], 2 * creds.STEPS)
        self.assertEqual(max(d for d, _ in steps), 2 * creds.STEPS)

    def test_all_profiles(self):
        code, out, _ = self.cli("--all-profiles", "--json")
        self.assertEqual({f["profile"] for f in json.loads(out)["findings"]}, {"lab-a", "lab-b"})

    def test_missing_permission_end_to_end(self):
        self.deny = {"GetAccountAuthorizationDetails", "ListSSHPublicKeys"}
        code, out, errs = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("Couldn't read users, roles and policies", out)
        self.assertIn("no permission for iam:GetAccountAuthorizationDetails", errs)
        self.assertIn("no permission for iam:ListSSHPublicKeys", errs)
        self.assertIn("Console user without MFA", out)  # the credential report still worked
        self.assertNotIn("Traceback", out + errs)

    def test_profile_that_cannot_sign_in(self):
        code, out, errs = self.cli("-p", "no-such-profile")
        self.assertEqual(code, 1)
        self.assertIn("no-such-profile", errs)

    def test_fail_on_does_not_pass_a_profile_that_was_not_read(self):
        code, _, errs = self.cli("-p", "lab-a", "-p", "no-such-profile", "--fail-on", "critical")
        self.assertEqual(code, 1)
        self.assertIn("no-such-profile", errs)
        # Without --fail-on, the profiles that worked still count as a normal run.
        self.assertEqual(self.cli("-p", "lab-a", "-p", "no-such-profile")[0], 0)


if __name__ == "__main__":
    unittest.main()
