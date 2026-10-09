"""Shared fixes from the second security review: PII Redact's private key rule on crafted
text, which Terraform binary runs, Terraform's JSON output, PassRole findings, control
characters in terminal tables, odd CloudTrail records, and config keys from newer versions.

Run from the repo root:  python3 -m unittest tests.test_security_shared -v
"""
import json
import os
import stat
import sys
import tempfile
import time
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
for _name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
              "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
              "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
    os.environ.pop(_name, None)
for _name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL_")]:
    os.environ.pop(_name, None)

from awskit import common, iampolicy, redact, tfplan, trail  # noqa: E402


class RedactPrivateKeyTests(unittest.TestCase):
    def test_many_begin_lines_without_an_end_stay_fast(self):
        line = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9C\n"
        start = time.time()
        out, counts, _ = redact.redact(line * 6000, redact.Options())
        self.assertLess(time.time() - start, 5)
        self.assertNotIn("MIIBOgIBAAJBAKj34Gkx", out)

    def test_a_normal_key_is_still_one_redaction(self):
        key = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIB\n"
               "AQC7abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH\n-----END PRIVATE KEY-----")
        out, counts, _ = redact.redact("before\n" + key + "\nafter", redact.Options())
        self.assertEqual(out, "before\n[Redacted]\nafter")
        self.assertEqual(counts["PrivateKey"], 1)


@unittest.skipIf(os.name == "nt", "the PATH rules tested here are for Linux and macOS")
class TerraformBinaryTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(dir=TMP))
        fake = self.folder / "terraform"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        self.cwd = os.getcwd()
        os.chdir(self.folder)

    def tearDown(self):
        os.chdir(self.cwd)

    def test_a_terraform_in_the_current_folder_is_never_picked(self):
        for path in (".", "", f".{os.pathsep}", f"{os.pathsep}/nonexistent-awskit"):
            with mock.patch.dict(os.environ, {"PATH": path}):
                self.assertIsNone(tfplan.terraform_bin(), repr(path))

    def test_a_full_path_in_path_is_used_as_a_full_path(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.folder)}):
            got = tfplan.terraform_bin()
        self.assertEqual(got, str(self.folder / "terraform"))
        self.assertTrue(os.path.isabs(got))

    def test_terraform_output_that_is_too_deep_is_a_plain_error(self):
        with self.assertRaises(tfplan.PlanError):
            tfplan._json_out("[" * 100000)
        with self.assertRaises(tfplan.PlanError):
            tfplan._json_out("not json")
        self.assertEqual(tfplan._json_out('{"a": 1}'), {"a": 1})


class PassRoleTests(unittest.TestCase):
    def findings(self, statements):
        doc = {"Version": "2012-10-17", "Statement": statements}
        return [(f.severity, f.title) for f in iampolicy.analyze(doc, "identity")]

    def test_passed_to_service_still_flags_passrole_on_any_role(self):
        got = self.findings([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
                              "Condition": {"StringEquals": {
                                  "iam:PassedToService": "ec2.amazonaws.com"}}}])
        self.assertIn(("medium", "iam:PassRole on any role, for some services"), got)
        self.assertNotIn(("high", "iam:PassRole on any role"), got)

    def test_attaching_a_role_to_a_running_instance_is_a_passrole_pair(self):
        got = self.findings([
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
             "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
            {"Effect": "Allow", "Action": "ec2:AssociateIamInstanceProfile", "Resource": "*"}])
        self.assertIn(("high", "PassRole plus a service that runs as a role"), got)

    def test_scoped_passrole_is_quiet(self):
        got = self.findings([{"Effect": "Allow", "Action": "iam:PassRole",
                              "Resource": "arn:aws:iam::111111111111:role/app"}])
        self.assertFalse([t for _, t in got if "PassRole" in t])


class TerminalTextTests(unittest.TestCase):
    def test_tables_show_control_characters_as_question_marks(self):
        rows = [{"name": "web\x1b[2K\x1b[1Aserver", "tag": "a\u202eb\tc", "n": 3}]
        text = common.table_text(rows, [("name", "Name"), ("tag", "Tag"), ("n", "N")])
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("web?[2K?[1Aserver", text)
        self.assertEqual(common.terminal_safe("line\nnext\ttab"), "line\nnext\ttab")

    def test_markdown_rows_stay_whole(self):
        rows = [{"name": "a\rb", "tag": "c\r\nd|e\nf"}]
        text = common.to_markdown(rows, [("name", "Name"), ("tag", "Tag")])
        self.assertNotIn("\r", text)
        self.assertEqual(text.splitlines()[-1], "| a b | c d\\|e f |")


class TrailRecordTests(unittest.TestCase):
    def test_odd_records_dont_stop_a_search(self):
        odd = [
            {"CloudTrailEvent": "[1, 2]"},
            {"CloudTrailEvent": json.dumps({"userIdentity": "root", "eventName": 5,
                                            "errorCode": ["x"], "awsRegion": None})},
            {"CloudTrailEvent": json.dumps({"userIdentity": {"type": "AssumedRole",
                                                             "sessionContext": "x"}})},
            {"CloudTrailEvent": json.dumps({"eventTime": "2026-10-05T10:00:00"}),
             "Resources": "not a list"},
            {"CloudTrailEvent": "[" * 50000},
            {"CloudTrailEvent": 7},
        ]
        for ev in odd:
            with self.subTest(ev=str(ev)[:60]):
                e = trail.parse_event(ev, "us-east-1")
                self.assertIsInstance(e.name, str)
                self.assertIsInstance(e.error, str)
                self.assertIsNotNone(e.time.tzinfo)
                e.row()
                e.detail_text()


class ConfigTests(unittest.TestCase):
    def test_keys_from_a_newer_version_survive_a_save(self):
        common.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        common.CONFIG_FILE.write_text(json.dumps({"keep": ["i-1"], "from_v9": {"x": [1]},
                                                  "regions": "not a list"}), encoding="utf-8")
        cfg = common.load_config()
        self.assertEqual(cfg["from_v9"], {"x": [1]})
        self.assertEqual(cfg["regions"], [])                  # wrong type, default kept
        cfg["keep"].append("i-2")
        common.save_config(cfg)
        raw = json.loads(common.CONFIG_FILE.read_text(encoding="utf-8"))
        self.assertEqual(raw["from_v9"], {"x": [1]})
        self.assertEqual(raw["keep"], ["i-1", "i-2"])
        self.assertIn("secrets_scan", raw)
        self.assertIn("drift", raw)

    def write(self, data: bytes):
        common.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        common.CONFIG_FILE.write_bytes(data)

    def test_byte_order_mark_and_whole_numbers(self):
        # Notepad and PowerShell can put a byte order mark first, which used to mean every
        # setting was ignored. "notify_threshold": 20 (no .0) was ignored too.
        self.write(b"\xef\xbb\xbf" + json.dumps({"keep": ["i-0abc"], "notify_threshold": 20,
                                                  "regions": ["us-east-1"]}).encode())
        cfg = common.load_config()
        self.assertEqual(cfg["keep"], ["i-0abc"])
        self.assertEqual(cfg["regions"], ["us-east-1"])
        self.assertEqual(cfg["notify_threshold"], 20.0)
        self.assertIsInstance(cfg["notify_threshold"], float)
        self.write(json.dumps({"notify_threshold": True}).encode())
        self.assertEqual(common.load_config()["notify_threshold"], 1.0)   # not a number

    def test_a_file_that_cant_be_read_is_kept_before_saving(self):
        # A typo made by hand used to be wiped by the next save, keep list and all
        bad = common.CONFIG_FILE.with_name("config.json.bad")
        self.addCleanup(lambda: bad.exists() and bad.unlink())
        typo = '{"keep": ["i-0abc", "i-0def",], "regions": ["us-east-1"]}'
        self.write(typo.encode())
        cfg = common.load_config()
        self.assertEqual(cfg["keep"], [])
        cfg["appearance"] = {"style": "dark"}
        self.assertTrue(common.save_config(cfg))
        self.assertEqual(bad.read_text(), typo)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(bad.stat().st_mode), 0o600)
        bad.unlink()
        self.assertTrue(common.save_config(common.load_config()))   # a good file isn't
        self.assertFalse(bad.exists())


class ClipboardTests(unittest.TestCase):
    def test_wsl_without_windows_programs_copies_through_wslg(self):
        # With interop turned off in wsl.conf, clip.exe can't run. Reading fell back to
        # wl-paste, but copying stopped with an error even when wl-copy was there.
        import subprocess
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd[0])
            if cmd[0].endswith("clip.exe"):
                raise OSError(8, "Exec format error")
            return subprocess.CompletedProcess(cmd, 0)
        clip = "/mnt/c/Windows/System32/clip.exe"
        with mock.patch.object(common, "windows_tool", return_value=clip), \
                mock.patch.object(common.subprocess, "run", side_effect=fake_run):
            with mock.patch.object(common, "clip_backends", return_value=["windows", "wayland"]):
                common.write_clipboard("x")
            self.assertEqual(calls, [clip, "wl-copy"])
            with mock.patch.object(common, "clip_backends", return_value=["windows"]), \
                    self.assertRaises(common.ClipboardError):
                common.write_clipboard("x")


class TimeTests(unittest.TestCase):
    def test_a_date_without_dashes_is_a_message(self):
        # awskit trail --since 20261001 read it as 20 million hours and ended in a traceback
        for text in ("20261001", "99999999999999999999w"):
            with self.subTest(text), self.assertRaises(ValueError) as caught:
                common.parse_when(text)
            self.assertIn("Use 2h, 3d, or 2026-10-01 14:30", str(caught.exception))
        self.assertLess(abs((common.parse_when("2h") - common.parse_when("120m")).total_seconds()), 5)


class FlashTests(unittest.TestCase):
    def test_second_click_goes_back_to_the_buttons_own_label(self):
        # Two quick clicks on Copy used to leave the button saying Copied for good
        try:
            from gi.repository import GLib
            from awskit import widgets
        except (ImportError, ValueError):
            self.skipTest("GTK 4 for Python isn't installed")

        class Button:
            label = "Copy"

            def get_label(self):
                return self.label

            def set_label(self, text):
                self.label = text

        def spin(seconds):
            ctx = GLib.MainContext.default()
            end = time.time() + seconds
            while time.time() < end:
                ctx.iteration(False)
                time.sleep(0.005)

        b = Button()
        widgets.flash(b, "Copied", 100)
        spin(0.03)
        widgets.flash(b, "Copied", 100)
        self.assertEqual(b.label, "Copied")
        spin(0.4)
        self.assertEqual(b.label, "Copy")


if __name__ == "__main__":
    unittest.main()
