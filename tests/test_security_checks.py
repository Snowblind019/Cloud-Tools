"""Tests for the Policy Check, Plan Check and Exposure Audit fixes from the security review.

Run from the repo root:  python3 tests/test_security_checks.py (or every test file with
python3 -m unittest discover -s tests)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tools  # noqa: E402,F401  sets up the fake AWS environment and sys.path

from awskit import audit, iampolicy, tfplan  # noqa: E402


def policy(*statements, version="2012-10-17"):
    return {"Version": version, "Statement": list(statements)}


def public_stmt(condition=None, action="s3:GetObject", resource="arn:aws:s3:::b/*"):
    s = {"Effect": "Allow", "Principal": "*", "Action": action, "Resource": resource}
    if condition is not None:
        s["Condition"] = condition
    return s


def github_trust(condition):
    cond = dict(condition)
    cond.setdefault("StringEquals", {})["token.actions.githubusercontent.com:aud"] = \
        "sts.amazonaws.com"
    return policy({"Effect": "Allow",
                   "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/"
                                              "token.actions.githubusercontent.com"},
                   "Action": "sts:AssumeRoleWithWebIdentity", "Condition": cond})


def severities(doc, kind=None):
    return {f.title: f.severity for f in iampolicy.analyze(doc, kind)}


# =================================================================== Policy Check

class ConditionTests(unittest.TestCase):
    """A public principal only counts as narrowed by a positive condition with a real value."""

    def weak(self, condition):
        sev = severities(policy(public_stmt(condition)))
        self.assertNotIn("Public principal narrowed by a condition", sev, condition)
        self.assertEqual(sev.get("Public principal with a weak condition"), "high", condition)

    def narrowed(self, condition):
        sev = severities(policy(public_stmt(condition)))
        self.assertEqual(sev.get("Public principal narrowed by a condition"), "info", condition)
        self.assertNotIn("Public principal with a weak condition", sev, condition)

    def test_not_operators_dont_narrow(self):
        self.weak({"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}})
        self.weak({"ArnNotLike": {"aws:SourceArn": "arn:aws:s3:::mine"}})
        self.weak({"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}})

    def test_null_and_if_exists_dont_narrow(self):
        self.weak({"Null": {"aws:SourceArn": "true"}})
        self.weak({"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123"}})
        self.weak({"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})

    def test_wide_values_dont_narrow(self):
        self.weak({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})
        self.weak({"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "::/0"]}})
        self.weak({"IpAddress": {"aws:SourceIp": ["0.0.0.0/1", "128.0.0.0/1"]}})
        self.weak({"StringLike": {"aws:PrincipalOrgID": "*"}})
        self.weak({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::*"}})
        self.weak({"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:*:alerts"}})

    def test_real_conditions_still_narrow(self):
        self.narrowed({"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})
        self.narrowed({"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": "o-abc/r-1/ou-2/*"}})
        self.narrowed({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
        self.narrowed({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}})
        # StringEquals takes * literally, so it matches nobody
        self.narrowed({"StringEquals": {"aws:SourceAccount": "*"}})

    def test_one_narrowing_condition_is_enough(self):
        self.narrowed({"StringNotEquals": {"aws:SourceVpce": "vpce-1"},
                       "StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})

    def test_weak_detail_says_why(self):
        found = iampolicy.analyze(policy(public_stmt(
            {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}})))
        f = next(f for f in found if f.title == "Public principal with a weak condition")
        self.assertIn("StringNotEquals on aws:PrincipalOrgID", f.detail)

    def test_service_principal_source_check_needs_a_positive_operator(self):
        stmt = {"Effect": "Allow", "Principal": {"Service": "logging.s3.amazonaws.com"},
                "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}
        bad = dict(stmt, Condition={"StringNotEquals": {"aws:SourceAccount": "111111111111"}})
        good = dict(stmt, Condition={"StringEquals": {"aws:SourceAccount": "111111111111"}})
        self.assertIn("Service principal without a source check", severities(policy(bad)))
        self.assertNotIn("Service principal without a source check", severities(policy(good)))


class GitHubSubTests(unittest.TestCase):
    def sub_findings(self, condition):
        sev = severities(github_trust(condition))
        return {t: s for t, s in sev.items() if t.startswith("GitHub OIDC")}

    def test_any_owner_is_high(self):
        for sub in ("repo:*:*", "repo:*/myrepo:*", "repo:my-*/app:*", "*", "repo:*"):
            got = self.sub_findings({"StringLike": {"token.actions.githubusercontent.com:sub": sub}})
            self.assertEqual(got, {"GitHub OIDC repo check is loose": "high"}, sub)

    def test_any_repo_of_one_owner_is_medium(self):
        got = self.sub_findings({"StringLike": {"token.actions.githubusercontent.com:sub":
                                                "repo:example-org/*"}})
        self.assertEqual(got, {"GitHub OIDC repo check is loose": "medium"})

    def test_pinned_repo_is_fine(self):
        for op, sub in (("StringLike", "repo:example-org/app:*"),
                        ("StringEquals", "repo:example-org/app:ref:refs/heads/main"),
                        ("StringEquals", "repo:*:*")):   # StringEquals takes * literally
            got = self.sub_findings({op: {"token.actions.githubusercontent.com:sub": sub}})
            self.assertEqual(got, {}, (op, sub))

    def test_not_operator_alone_is_no_repo_check(self):
        got = self.sub_findings({"StringNotLike": {"token.actions.githubusercontent.com:sub":
                                                   "repo:evil-org/*"}})
        self.assertEqual(got, {"GitHub OIDC trust without a repo check": "critical"})
        found = iampolicy.analyze(github_trust({"StringNotLike": {
            "token.actions.githubusercontent.com:sub": "repo:evil-org/*"}}))
        self.assertIn("StringNotLike", found[0].detail)

    def test_not_operator_next_to_a_pinned_one_only_narrows(self):
        got = self.sub_findings({
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/app:*"},
            "StringNotLike": {"token.actions.githubusercontent.com:sub":
                              "repo:example-org/app:ref:refs/heads/dev"}})
        self.assertEqual(got, {})

    def test_tightest_condition_decides(self):
        got = self.sub_findings({
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:*:*"},
            "StringEquals": {"token.actions.githubusercontent.com:sub":
                             "repo:example-org/app:ref:refs/heads/main"}})
        self.assertEqual(got, {})

    def test_null_only_is_no_repo_check(self):
        got = self.sub_findings({"Null": {"token.actions.githubusercontent.com:sub": "false"}})
        self.assertEqual(got, {"GitHub OIDC trust without a repo check": "critical"})


class BroadResourceTests(unittest.TestCase):
    def test_broad(self):
        for r in ("*", "arn:*", "arn:aws:*", "arn:*:iam::*:role/*", "arn:aws:iam::*:role/admin",
                  "arn:aws:iam::123456789012:role*", "arn:aws:lambda:us-east-1:123456789012:function*",
                  "arn:aws:iam::123456789012:*", "arn:aws:s3:::*", "arn:aws:s3:::*/*",
                  "arn:aws:s3:::*-logs/*", "arn:aws:ec2:*:*", "arn:aws:s3:*",
                  "arn:aws:iam::123456789012:role/*", "arn:aws:iam::123456789012:user/*",
                  "arn:aws:lambda:us-east-1:123456789012:function:*", "arn:aws-cn:*:*:*:*:*",
                  "arn:aws:sqs:us-east-1:123456789012:*"):
            self.assertTrue(iampolicy.is_broad_resource([r]), r)

    def test_not_broad(self):
        for r in ("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket", "arn:aws:s3:::logs-*",
                  "arn:aws:iam::123456789012:role/app-*", "arn:aws:iam::123456789012:role/app/*",
                  "arn:aws:lambda:*:123456789012:function:my-fn",
                  "arn:aws:lambda:us-east-1:123456789012:function:my-fn*",
                  "arn:aws:sqs:us-east-1:123456789012:orders*",
                  "arn:aws:dynamodb:us-east-1:123456789012:table/orders*",
                  "arn:aws:iam::123456789012:user/${aws:username}"):
            self.assertFalse(iampolicy.is_broad_resource([r]), r)

    def test_passrole_on_any_role_in_any_account(self):
        doc = policy({"Effect": "Allow", "Action": "iam:PassRole",
                      "Resource": "arn:*:iam::*:role/*"})
        self.assertEqual(severities(doc).get("iam:PassRole on any role"), "high")


class LoadPolicyTests(unittest.TestCase):
    def bad(self, text):
        with self.assertRaises(iampolicy.PolicyError):
            iampolicy.load_policy(text)

    def test_unhashable_key_in_printed_dict(self):
        self.bad("{[1]: 2}")
        self.bad("{'Statement': [], {'a': 1}: 2}")

    def test_deep_nesting(self):
        self.bad("[" * 100000 + "]" * 100000)
        self.bad('{"Statement": ' + "[" * 100000 + "]" * 100000 + "}")
        self.bad('{"Statement": ' + "[" * 50 + "]" * 50 + "}")   # parses, but no policy is that deep
        self.bad("{'Statement': " + "[" * 100 + "]" * 100 + "}")
        self.bad(json.dumps(json.dumps({"Statement": []})[:-1] + "[" * 100000))

    def test_size_cap(self):
        pad = " " * 10
        text = json.dumps(policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                                  "Sid": "x" * (iampolicy.MAX_POLICY_TEXT + 1)}))
        self.bad(pad + text)

    def test_normal_policies_still_load(self):
        doc, _ = iampolicy.load_policy(json.dumps(policy(public_stmt(
            {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}))))
        self.assertIn("Statement", doc)


class _FakeIam:
    def __init__(self):
        self.asked = []

    def get_role(self, RoleName):
        self.asked.append(RoleName)
        return {"Role": {"RoleName": RoleName, "AssumeRolePolicyDocument": policy(
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
             "Action": "sts:AssumeRole"})}}


class _FakeCtx:
    profile = None

    def __init__(self, account="111111111111", **clients):
        self.account = account
        self.clients = clients

    def client(self, service, region=None):
        return self.clients[service]


class FetchPolicyTests(unittest.TestCase):
    def test_role_arn_from_another_account_is_refused(self):
        iam = _FakeIam()
        with self.assertRaises(iampolicy.PolicyError) as err:
            iampolicy.fetch_policy(_FakeCtx(iam=iam), "arn:aws:iam::222222222222:role/deploy")
        self.assertIn("222222222222", str(err.exception))
        self.assertEqual(iam.asked, [])

    def test_same_account_and_bare_names_load(self):
        iam = _FakeIam()
        _, kind, label = iampolicy.fetch_policy(_FakeCtx(iam=iam),
                                                "arn:aws:iam::111111111111:role/ci/deploy")
        self.assertEqual((kind, label), ("trust", "deploy trust policy"))
        iampolicy.fetch_policy(_FakeCtx(iam=iam), "role/other")
        self.assertEqual(iam.asked, ["deploy", "other"])


# =================================================================== Plan Check

def rc(rtype, after, action="create", before=None, unknown=None, name="this", module=""):
    addr = (module + "." if module else "") + f"{rtype}.{name}"
    out = {"address": addr, "mode": "managed", "type": rtype, "name": name,
           "change": {"actions": [action], "before": before, "after": after,
                      "after_unknown": unknown or {}}}
    if module:
        out["module_address"] = module
    return out


def plan(*changes, configuration=None):
    p = {"format_version": "1.2", "planned_values": {}, "resource_changes": list(changes)}
    if configuration is not None:
        p["configuration"] = configuration
    return p


def risks(*changes, configuration=None):
    return {(r.address, r.title): r.severity
            for r in tfplan.summarize(plan(*changes, configuration=configuration)).risks}


ADMIN_DOC = json.dumps(policy({"Effect": "Allow", "Action": "*", "Resource": "*"}))
PUBLIC_DOC = json.dumps(policy(public_stmt(action="sqs:SendMessage", resource="*")))
NOTE = "Couldn't check {}, it's only known after apply"


class PlanShapeTests(unittest.TestCase):
    def test_state_json_isnt_a_plan(self):
        state = {"format_version": "1.0", "terraform_version": "1.9.0",
                 "values": {"root_module": {"resources": []}}}
        with self.assertRaises(tfplan.PlanError) as err:
            tfplan.summarize(state)
        self.assertIn("isn't a Terraform plan", str(err.exception))

    def test_no_op_plan_is_still_a_plan(self):
        s = tfplan.summarize({"format_version": "1.2", "planned_values": {"root_module": {}}})
        self.assertEqual(s.risks, [])
        self.assertTrue(s.headline().startswith("No changes"))

    def test_bad_resource_changes(self):
        with self.assertRaises(tfplan.PlanError):
            tfplan.summarize({"format_version": "1.2", "resource_changes": "nope"})


class UnknownValueTests(unittest.TestCase):
    def test_unknown_policy_gets_a_note(self):
        got = risks(rc("aws_iam_role_policy", {"name": "x"}, unknown={"policy": True}))
        self.assertEqual(got, {("aws_iam_role_policy.this", NOTE.format("policy")): "info"})

    def test_unknown_trust_policy_gets_a_note(self):
        got = risks(rc("aws_iam_role", {"name": "x"}, unknown={"assume_role_policy": True}))
        self.assertIn(("aws_iam_role.this", NOTE.format("assume_role_policy")), got)

    def test_unknown_rule_cidrs_get_a_note(self):
        got = risks(rc("aws_security_group_rule", {"type": "ingress", "protocol": "tcp",
                                                   "from_port": 22, "to_port": 22},
                       unknown={"cidr_blocks": True}),
                    rc("aws_vpc_security_group_ingress_rule", {"ip_protocol": "tcp"},
                       unknown={"cidr_ipv4": True}, name="v"))
        self.assertIn(("aws_security_group_rule.this", NOTE.format("cidr_blocks")), got)
        self.assertIn(("aws_vpc_security_group_ingress_rule.v", NOTE.format("cidr_ipv4")), got)

    def test_partly_unknown_ingress_gets_a_note_and_known_rules_are_checked(self):
        after = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                              "cidr_blocks": ["0.0.0.0/0"]},
                             {"protocol": "tcp", "from_port": 5432, "to_port": 5432}]}
        unknown = {"ingress": [{}, {"cidr_blocks": True}]}
        got = risks(rc("aws_security_group", after, unknown=unknown))
        self.assertIn(("aws_security_group.this", "Open to the internet: 22 SSH"), got)
        self.assertIn(("aws_security_group.this", NOTE.format("ingress")), got)

    def test_unknown_source_group_isnt_a_note(self):
        after = {"ingress": [{"protocol": "tcp", "from_port": 5432, "to_port": 5432,
                              "cidr_blocks": []}]}
        got = risks(rc("aws_security_group", after, unknown={"ingress": [{"security_groups": True}]}))
        self.assertEqual(got, {})

    def test_self_filled_values_only_get_a_note_when_the_code_sets_them(self):
        sg = rc("aws_security_group", {"name": "web"}, unknown={"ingress": True}, module="module.net")
        key = rc("aws_kms_key", {"description": "k"}, unknown={"policy": True}, name="k")
        # No configuration section: can't tell, so no note
        self.assertEqual(risks(sg, key), {})

        def config(sg_args, key_args):
            return {"root_module": {
                "resources": [{"address": "aws_kms_key.k", "mode": "managed", "type": "aws_kms_key",
                               "name": "k", "expressions": {a: {} for a in key_args}}],
                "module_calls": {"net": {"module": {"resources": [
                    {"address": "aws_security_group.this", "mode": "managed",
                     "type": "aws_security_group", "name": "this",
                     "expressions": {a: {} for a in sg_args}}]}}}}}
        self.assertEqual(risks(sg, key, configuration=config(["name"], ["description"])), {})
        got = risks(sg, key, configuration=config(["name", "ingress"], ["policy"]))
        self.assertEqual(got, {("module.net.aws_security_group.this", NOTE.format("ingress")): "info",
                               ("aws_kms_key.k", NOTE.format("policy")): "info"})


class NewRuleTests(unittest.TestCase):
    def test_public_aurora_instance(self):
        got = risks(rc("aws_rds_cluster_instance", {"publicly_accessible": True}))
        self.assertEqual(got.get(("aws_rds_cluster_instance.this",
                                  "Database is publicly accessible")), "high")

    def test_inline_bucket_acl_and_policy(self):
        got = risks(rc("aws_s3_bucket", {"bucket": "b", "acl": "public-read",
                                         "policy": json.dumps(policy(public_stmt()))}))
        self.assertEqual(got.get(("aws_s3_bucket.this", "Bucket ACL is public-read")), "high")
        self.assertEqual(got.get(("aws_s3_bucket.this", "Open to everyone")), "critical")
        self.assertEqual(risks(rc("aws_s3_bucket", {"bucket": "b", "acl": "private"})), {})

    def test_inline_queue_and_topic_policies(self):
        got = risks(rc("aws_sqs_queue", {"policy": PUBLIC_DOC}, name="q"),
                    rc("aws_sns_topic", {"policy": PUBLIC_DOC}, name="t"))
        self.assertEqual(got.get(("aws_sqs_queue.q", "Open to everyone")), "critical")
        self.assertEqual(got.get(("aws_sns_topic.t", "Open to everyone")), "critical")

    def test_role_managed_policy_arns(self):
        admin = "arn:aws:iam::aws:policy/AdministratorAccess"
        got = risks(rc("aws_iam_role", {"managed_policy_arns": [admin]}))
        self.assertEqual(got.get(("aws_iam_role.this", "Attaches AdministratorAccess")), "high")
        # already attached before this plan: not flagged again
        got = risks(rc("aws_iam_role", {"managed_policy_arns": [admin], "description": "b"},
                       action="update", before={"managed_policy_arns": [admin], "description": "a"}))
        self.assertNotIn(("aws_iam_role.this", "Attaches AdministratorAccess"), got)

    def test_role_inline_policy(self):
        got = risks(rc("aws_iam_role", {"inline_policy": [{"name": "everything",
                                                           "policy": ADMIN_DOC}]}))
        self.assertEqual(got.get(("aws_iam_role.this", "Full admin access")), "critical")
        s = tfplan.summarize(plan(rc("aws_iam_role", {"inline_policy": [
            {"name": "everything", "policy": ADMIN_DOC}]})))
        self.assertIn("inline policy everything", s.risks[0].detail)
        same = [{"name": "everything", "policy": ADMIN_DOC}]
        got = risks(rc("aws_iam_role", {"inline_policy": same, "description": "b"},
                       action="update", before={"inline_policy": same, "description": "a"}))
        self.assertEqual(got, {})


class LoadPlanTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="awskit-fix-"))

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def test_without_terraform_folders_and_saved_plans_are_refused(self):
        saved = self.folder / "tfplan"
        saved.write_bytes(b"PK\x03\x04 a zip, like a saved plan")
        with mock.patch.object(tfplan, "_run", side_effect=AssertionError("ran terraform")):
            for source in (str(self.folder), str(saved)):
                with self.assertRaises(tfplan.NeedsTerraform):
                    tfplan.load_plan(source, run_terraform=False)
            (self.folder / "plan.json").write_text('{"format_version": "1.2"}')
            self.assertEqual(tfplan.load_plan(str(self.folder / "plan.json"), run_terraform=False),
                             {"format_version": "1.2"})

    def test_plan_file_goes_in_a_private_temp_folder(self):
        calls = []

        def fake_run(cmd, cwd, timeout=900, profile=None):
            calls.append((cmd, cwd, profile))
            if cmd[1] == "plan":
                out = next(c for c in cmd if c.startswith("-out="))[5:]
                Path(out).write_text("secret plan")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, '{"format_version": "1.2"}', "")
        with mock.patch.object(tfplan, "terraform_bin", return_value="/usr/bin/terraform"), \
                mock.patch.object(tfplan, "_run", side_effect=fake_run):
            self.assertEqual(tfplan.plan_directory(str(self.folder), profile="lab"),
                             {"format_version": "1.2"})
        (plan_cmd, plan_cwd, plan_profile), (show_cmd, show_cwd, show_profile) = calls
        out = Path(next(c for c in plan_cmd if c.startswith("-out="))[5:])
        self.assertNotEqual(out.parent, self.folder.resolve())
        self.assertFalse(str(out).startswith(str(self.folder.resolve())))
        self.assertFalse(out.parent.exists())             # cleaned up
        self.assertEqual(list(self.folder.iterdir()), [])
        self.assertEqual(show_cmd[-1], str(out))
        self.assertEqual((plan_cwd, show_cwd), (str(self.folder.resolve()),) * 2)
        self.assertEqual((plan_profile, show_profile), ("lab", "lab"))


class TerraformRunTests(unittest.TestCase):
    def test_env_with_and_without_a_profile(self):
        with mock.patch.dict(os.environ, {"AWS_PROFILE": "old", "AWS_DEFAULT_PROFILE": "older"}):
            env = tfplan._env("lab")
            self.assertEqual(env["AWS_PROFILE"], "lab")
            self.assertNotIn("AWS_DEFAULT_PROFILE", env)
            self.assertEqual(env["TF_IN_AUTOMATION"], "1")
            env = tfplan._env(None)
            self.assertEqual(env, {**os.environ, "TF_IN_AUTOMATION": "1"})

    @unittest.skipIf(os.name == "nt", "needs a POSIX shell")
    def test_run_passes_the_profile(self):
        r = tfplan._run(["sh", "-c", 'echo "$AWS_PROFILE"'], cwd=tempfile.gettempdir(),
                        profile="lab")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "lab"))

    @unittest.skipIf(os.name == "nt" or not Path("/proc").is_dir(), "needs Linux")
    def test_timeout_stops_child_processes_too(self):
        folder = tempfile.mkdtemp(prefix="awskit-fix-")
        try:
            pidfile = Path(folder) / "pid"
            with self.assertRaises(tfplan.PlanError):
                tfplan._run(["sh", "-c", f'sleep 60 & echo $! > "{pidfile}"; wait'],
                            cwd=folder, timeout=1)
            pid = int(pidfile.read_text())
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                except OSError:
                    break                                     # gone
                if state == "Z":
                    break                                     # dead, just not reaped yet
                time.sleep(0.1)
            else:
                self.fail("the child process outlived the timeout")
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class TerraformBinTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="awskit-fix-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def folder(self, name, *files):
        d = self.root / name
        d.mkdir()
        for f in files:
            (d / f).write_text("x")
        return d

    def find(self, *folders, cwd=None):
        path = os.pathsep.join(str(f) for f in folders)
        with mock.patch.object(tfplan.os, "name", "nt"), \
                mock.patch.dict(os.environ, {"PATH": path}):
            old = os.getcwd()
            os.chdir(cwd or self.root)
            try:
                return tfplan.terraform_bin()
            finally:
                os.chdir(old)

    def test_windows_only_takes_exe_from_absolute_path_folders(self):
        here = self.folder("here", "terraform.exe")         # the current folder, not in PATH
        shim = self.folder("shim", "terraform.cmd", "terraform.bat", "terraform")
        real = self.folder("real", "terraform.exe")
        found = self.find(Path("."), shim, real, cwd=here)
        self.assertEqual(found, os.path.join(str(real), "terraform.exe"))

    def test_windows_relative_entries_and_shims_give_none(self):
        here = self.folder("here", "terraform.exe", "tofu.exe")
        shim = self.folder("shim", "terraform.cmd", "tofu.bat")
        self.assertIsNone(self.find(Path("."), Path("here"), shim, cwd=here.parent))

    def test_windows_falls_back_to_tofu(self):
        tofu = self.folder("tofu", "tofu.exe")
        self.assertEqual(self.find(tofu), os.path.join(str(tofu), "tofu.exe"))


# =================================================================== Exposure Audit

class _Stub:
    """A boto3 client stand-in: each method returns a fixed reply, or raises it."""

    def __init__(self, **replies):
        self.replies = replies

    def can_paginate(self, method):
        return False

    def __getattr__(self, name):
        if name not in self.replies:
            raise AttributeError(name)
        reply = self.replies[name]

        def call(**kwargs):
            value = reply(**kwargs) if callable(reply) else reply
            if isinstance(value, Exception):
                raise value
            return value
        return call


def client_error(code, op="Op"):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": "nope"}}, op)


class WideSourceTests(unittest.TestCase):
    def sources(self, v4=(), v6=()):
        return audit.wide_sources({"IpRanges": [{"CidrIp": c} for c in v4],
                                   "Ipv6Ranges": [{"CidrIpv6": c} for c in v6]})

    def test_open_and_broad(self):
        self.assertEqual(self.sources(["0.0.0.0/0"]), (["0.0.0.0/0"], []))
        self.assertEqual(self.sources(v6=["::/0"]), (["::/0"], []))
        self.assertEqual(self.sources(["0.0.0.0/1", "128.0.0.0/1"]),
                         (["0.0.0.0/1", "128.0.0.0/1"], []))
        self.assertEqual(self.sources(["3.0.0.0/8"]), ([], ["3.0.0.0/8"]))
        self.assertEqual(self.sources(["0.0.0.0/1"]), ([], ["0.0.0.0/1"]))
        self.assertEqual(self.sources(v6=["2600::/12"]), ([], ["2600::/12"]))

    def test_narrow_and_private_ranges_are_left_alone(self):
        self.assertEqual(self.sources(["203.0.113.0/24", "10.0.0.0/8", "3.0.0.0/9"],
                                      ["fc00::/7", "2600:1f18::/32"]), ([], []))


class AuditCheckTests(unittest.TestCase):
    def sg_findings(self, perm, attached=True):
        ec2 = _Stub(describe_network_interfaces={"NetworkInterfaces": [
                        {"Groups": [{"GroupId": "sg-1"}]}] if attached else []},
                    describe_security_groups={"SecurityGroups": [
                        {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [perm]}]})
        return audit.check_security_groups(_FakeCtx(ec2=ec2), "us-east-1")

    def test_split_ranges_count_as_open(self):
        found = self.sg_findings({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [
            {"CidrIp": "0.0.0.0/1"}, {"CidrIp": "128.0.0.0/1"}]})
        self.assertEqual([(f.check, f.severity) for f in found], [("Open to the internet", "high")])
        self.assertIn("whole internet", found[0].detail)

    def test_broad_range_is_one_step_lower(self):
        perm = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "3.0.0.0/8"}]}
        found = self.sg_findings(perm)
        self.assertEqual([(f.check, f.severity) for f in found],
                         [("Open to a very broad range", "medium")])
        found = self.sg_findings(dict(perm, IpProtocol="-1"), attached=False)
        self.assertEqual([(f.check, f.severity) for f in found],   # critical, broad, unattached
                         [("Open to a very broad range", "medium")])

    def lambda_findings(self, statement, **extra):
        lam = _Stub(list_functions={"Functions": [{"FunctionName": "fn"}]},
                    list_function_url_configs=extra.get("urls", {"FunctionUrlConfigs": []}),
                    get_policy=extra.get("policy", {"Policy": json.dumps(policy(statement))}))
        return audit.check_lambda(_FakeCtx(**{"lambda": lam}), "us-east-1")

    def test_lambda_reports_high_policy_findings(self):
        stmt = {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction",
                "Resource": "arn:aws:lambda:us-east-1:111111111111:function:fn",
                "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}}
        found = self.lambda_findings(stmt)
        self.assertEqual([(f.check, f.severity) for f in found],
                         [("Function policy: Public principal with a weak condition", "high")])
        del stmt["Condition"]
        self.assertEqual([f.check for f in self.lambda_findings(stmt)],
                         ["Function policy allows anyone"])

    def test_lambda_access_denied_is_reported(self):
        found = self.lambda_findings({}, urls=client_error("AccessDeniedException"),
                                     policy=client_error("AccessDeniedException"))
        self.assertEqual(sorted(f.check for f in found),
                         ["Couldn't check function URLs", "Couldn't check function policies"])
        self.assertTrue(all(f.severity == "info" for f in found))

    def test_account_public_access_block_denied_is_reported(self):
        ctx = _FakeCtx(s3control=_Stub(get_public_access_block=client_error("AccessDenied")),
                       s3=_Stub(list_buckets={"Buckets": []}))
        found = audit.check_s3(ctx, "global")
        self.assertEqual([(f.check, f.severity) for f in found],
                         [("Couldn't check the account's S3 public access block", "info")])

    def test_credential_report_denied_keeps_the_root_findings(self):
        # A role without iam:GenerateCredentialReport used to lose the whole IAM check,
        # root without MFA included, to one "no permission" note.
        iam = _Stub(get_account_summary={"SummaryMap": {"AccountMFAEnabled": 0,
                                                        "AccountAccessKeysPresent": 1,
                                                        "Users": 2}},
                    get_account_password_policy={"PasswordPolicy": {"MinimumPasswordLength": 14}},
                    generate_credential_report=client_error("AccessDenied"))
        found = audit.check_iam(_FakeCtx(iam=iam), "global")
        self.assertEqual([(f.check, f.severity) for f in found],
                         [("Root user has access keys", "critical"),
                          ("Root user has no MFA", "high"),
                          ("Couldn't read the credential report", "info")])
        self.assertIn("weren't checked", found[-1].detail)
        throttled = _Stub(get_account_summary={"SummaryMap": {}},
                          get_account_password_policy={"PasswordPolicy": {}},
                          generate_credential_report=client_error("Throttling"))
        with self.assertRaises(Exception):  # still a warning for the whole check
            audit.check_iam(_FakeCtx(iam=throttled), "global")


@unittest.skipIf(test_tools.mock_aws is None, "moto not installed")
class AuditMotoTests(unittest.TestCase):
    def setUp(self):
        self.mock = test_tools.mock_aws()
        self.mock.start()

    def tearDown(self):
        self.mock.stop()
        audit.CHECKS.pop("_unreachable", None)

    def test_public_aurora_snapshot(self):
        import boto3
        from awskit.common import AwsContext
        rds = boto3.client("rds", region_name="us-east-1")
        rds.create_db_cluster(DBClusterIdentifier="c1", Engine="aurora-postgresql",
                              MasterUsername="admin1", MasterUserPassword="password1234")
        for sid in ("open", "closed"):
            rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=sid, DBClusterIdentifier="c1")
        rds.modify_db_cluster_snapshot_attribute(DBClusterSnapshotIdentifier="open",
                                                 AttributeName="restore", ValuesToAdd=["all"])
        found = audit.check_rds(AwsContext(None), "us-east-1")
        snaps = [(f.check, f.resource, f.severity) for f in found if "snapshot" in f.check]
        self.assertEqual(snaps, [("Public Aurora cluster snapshot", "open", "critical")])

    def test_unreachable_regions_become_notes(self):
        from botocore.exceptions import EndpointConnectionError

        def fails(ctx, region):
            if region == "us-east-1":
                raise EndpointConnectionError(endpoint_url="https://ec2.us-east-1.amazonaws.com")
            raise client_error("AuthFailure")
        audit.CHECKS["_unreachable"] = {"key": "_unreachable", "title": "Test check",
                                        "service": "ec2", "scope": "region", "fn": fails}
        findings, warnings = audit.audit([None], regions=["us-east-1", "us-west-2", "eu-west-1"],
                                         checks=["_unreachable"])
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 2, warnings)
        self.assertTrue(all("couldn't check Test check" in w for w in warnings), warnings)
        self.assertTrue(any("2 regions" in w for w in warnings), warnings)


try:
    import gi
    gi.require_version("Gtk", "4.0")
    from awskit import audit_page
except (ImportError, ValueError):  # pragma: no cover
    audit_page = None


@unittest.skipIf(audit_page is None, "GTK 4 not installed")
class AuditPageTests(unittest.TestCase):
    """The page's methods on a stand-in, so no display is needed."""

    class Page:
        def __init__(self, stopped):
            self.done = audit_page.AuditPage.done.__get__(self)
            self.cancel = threading.Event()
            if stopped:
                self.cancel.set()
            self.run_btn, self.table, self.status, self.detail = (mock.Mock() for _ in range(4))
            self.show_counts, self.apply_level = mock.Mock(), mock.Mock()

    def test_stopping_an_audit_never_looks_clean(self):
        # Stop used to end in "Audit finished" and "No findings.", like a clean account
        page = self.Page(stopped=True)
        page.done(([], []))
        self.assertIn("Stopped before the checks finished", page.table.clear.call_args.args[0])
        page.show_counts.assert_called_once_with(True)
        self.assertIn("stopped early", page.status.idle.call_args.args[0])
        self.assertIn("some checks didn't run", page.status.idle.call_args.args[0])

        page = self.Page(stopped=False)
        page.done(([], []))
        self.assertIn("No findings", page.table.clear.call_args.args[0])
        page.show_counts.assert_called_once_with(False)
        self.assertTrue(page.status.idle.call_args.args[0].startswith("Audit finished"))


if __name__ == "__main__":
    unittest.main()
