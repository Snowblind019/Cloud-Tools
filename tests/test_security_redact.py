"""Tests for the PII Redact and Profiles fixes from the security review: secrets that used to get through, slow
input, the settings file, and odd ~/.aws files.

Run from the repo root:  python3 tests/test_security_redact.py (or every test file with
python3 -m unittest discover -s tests)
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tools  # noqa: E402,F401  (sets up the fake AWS environment and sys.path)

from awskit import profiles, redact  # noqa: E402

ROOT = test_tools.ROOT
KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def run(text, **opts):
    return redact.redact(text, redact.Options(**opts))[0]


class RedactCase(unittest.TestCase):
    def check(self, text, gone=(), kept=(), **opts):
        """Redact text, then make sure every secret is gone and the context is still there."""
        out = run(text, **opts)
        for s in gone:
            self.assertNotIn(s, out, f"{s!r} leaked in:\n{out}")
        for k in kept:
            self.assertIn(k, out, f"{k!r} went missing from:\n{out}")
        return out


class NestedSecretTests(RedactCase):
    """H1: settings inside a value that isn't itself a secret."""

    def test_secret_string_from_the_cli(self):
        text = ('{\n    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",\n'
                '    "Name": "prod/db",\n'
                '    "SecretString": "{\\"username\\":\\"admin\\",\\"password\\":\\"Summer2026!\\"}",\n'
                '    "VersionStages": ["AWSCURRENT"]\n}')
        self.check(text, gone=["Summer2026!", "123456789012"],
                   kept=['"Name": "prod/db"', '"SecretString": "', "AWSCURRENT",
                         ":secret:prod/db-AbCdEf"])

    def test_secret_string_from_boto3(self):
        text = ("{'ARN': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db', "
                "'Name': 'prod/db', "
                "'SecretString': '{\"username\":\"admin\",\"password\":\"Summer2026!\"}'}")
        self.check(text, gone=["Summer2026!"], kept=["'Name': 'prod/db'", "'SecretString': '"])

    def test_json_inside_a_setting_that_isnt_secret(self):
        # An SSM parameter holding JSON: Value isn't a secret name, password inside is
        text = '{"Name": "/app/db", "Value": "{\\"host\\":\\"db.internal\\",\\"password\\":\\"Summer2026!\\"}"}'
        self.check(text, gone=["Summer2026!"],
                   kept=['"Name": "/app/db"', '\\"host\\":\\"db.internal\\"', '\\"password\\":\\"'])
        text = "{'Value': '{\"password\": \"Summer2026!\", \"port\": 5432}'}"
        self.check(text, gone=["Summer2026!"], kept=['"port": 5432'])

    def test_query_string_token_after_a_url(self):
        self.check("GET https://api.example.com/v1/items?page=2&token=s3cr3tT0ken&x=1",
                   gone=["s3cr3tT0ken"], kept=["page=2&token=", "&x=1"])

    def test_empty_query_string_values(self):
        # ?token=&state=1 used to stop PII Redact with AttributeError
        for text in ("https://example.com/cb?code=abc&token=&state=xyz",
                     'curl "https://api.example.com/v1?api_key=&q=1"', "x?secret=#frag"):
            with self.subTest(text):
                self.assertEqual(run(text), text)
        self.check("https://example.com/cb?token=&password=hunter2x&state=xyz",
                   gone=["hunter2x"], kept=["?token=&password=", "&state=xyz"])


class SecretKeyTests(RedactCase):
    """H2: secret keys right after = and inside escaped JSON."""

    def test_key_right_after_equals(self):
        for line in (f"AWS_SECRET_KEY={KEY}", f"TF_VAR_secret={KEY}", f"MY_KEY={KEY}",
                     f"export SOMETHING={KEY} # note"):
            name = line.split("=")[0]
            self.check(line, gone=[KEY], kept=[name + "="])

    def test_env_file_inside_a_json_string(self):
        text = ('{"Environment": "REGION=us-east-1\\nAWS_SECRET_ACCESS_KEY=' + KEY
                + '\\nUSER_EMAIL=jane@example.com\\nDEBUG=1"}')
        out = self.check(text, gone=[KEY, "jane@example.com"],
                         kept=["REGION=us-east-1\\n", "\\nAWS_SECRET_ACCESS_KEY=", "\\nDEBUG=1"])
        self.assertNotIn("nAWS_SECRET_ACCESS_KEY=[", out.replace("\\nAWS", ""))

    def test_keys_without_a_digit(self):
        # About 1 in 900 real keys has no digit. Most of them are caught now.
        rng = random.Random(2026)
        alphabet = string.ascii_letters + "/+"
        keys = ["".join(rng.choice(alphabet) for _ in range(40)) for _ in range(400)]
        caught = sum(run(f"key {k} end") == "key [Redacted] end" for k in keys)
        self.assertGreater(caught / len(keys), 0.9)
        self.check("aws_secret = wJalrXUtnFEMIKqMDENGbPxRfiCYEXAMPLEKEYab",
                   gone=["wJalrXUtnFEMIKqMDENGbPxRfiCYEXAMPLEKEYab"])

    def test_ordinary_40_character_strings_stay(self):
        for s in ("3f786850e387550fdab836ed7e6dc881de23001b",      # git commit
                  "ThisIsAVeryLongCamelCaseIdentifierNameXy",      # code identifier
                  "AWSServiceRoleForAmazonElasticsearchSear",       # role-ish name
                  "/usr/share/applications/firefoxdesktopxy",       # path
                  "supercalifragilisticexpialidociouslywxyz"):      # long word
            self.assertEqual(len(s), 40, s)
            self.check(f"value {s} here", kept=[s])
            self.check(f"thing={s}", kept=[s])


class SecretNameTests(RedactCase):
    """M1: more setting names, command line flags and Authorization headers."""

    def test_names_that_end_like_a_secret(self):
        for key in ("MasterUserPassword", "DATABASE_PASSWORD", "POSTGRES_PASSWORD", "PGPASSWORD",
                    "MYSQL_PWD", "JWT_SECRET", "DB_PASS", "api_secret", "x-api-key",
                    "TF_VAR_db_password", "client_secret", "GITHUB_TOKEN", "password_wo",
                    "private_key_pem", "aws_credentials", "basic_auth"):
            self.check(f"{key}=hunter2x", gone=["hunter2x"], kept=[f"{key}="])
            self.check(f'"{key}": "hunter2x"', gone=["hunter2x"], kept=[f'"{key}": "'])
            self.check(f"{key}: hunter2x", gone=["hunter2x"], kept=[f"{key}: "])

    def test_names_that_only_look_like_secrets(self):
        text = ('{"NextToken": "AAEAAWV4YW1wbGU", "PasswordLastUsed": "2026-09-30T18:00:00Z",\n'
                ' "MinimumPasswordLength": 14, "SecretId": "prod/db", "KeyId": "alias/app",\n'
                ' "token_endpoint": "https://login.example.com/oauth2/token",\n'
                ' "AuthorizationType": "AWS_IAM", "ClientToken": "abc-123"}\n'
                "user ALL=(ALL) NOPASSWD: ALL\n"
                "aws_secretsmanager_secret_version.token: Creating...\n"
                "random_password.db_password: Creation complete after 0s [id=none]\n"
                "  # aws_instance.web will be updated in-place\n")
        self.check(text, kept=["AAEAAWV4YW1wbGU", "2026-09-30T18:00:00Z", '"prod/db"',
                               "https://login.example.com/oauth2/token", '"AWS_IAM"',
                               "abc-123", "NOPASSWD: ALL", "token: Creating...",
                               "db_password: Creation complete after 0s",
                               "aws_instance.web"])

    def test_command_line_passwords(self):
        self.check("mysql -h db.internal -u root -phunter2x appdb",
                   gone=["hunter2x"], kept=["-u root -p", " appdb"])
        self.check("mysql -u root -p appdb", kept=["-p appdb"])  # -p alone asks for it
        self.check("docker login -u AWS -p hunter2x 123456789012.dkr.ecr.us-east-1.amazonaws.com",
                   gone=["hunter2x", "123456789012"], kept=["-u AWS -p ", ".dkr.ecr."])
        self.check("docker login --username AWS --password hunter2x registry.example.com",
                   gone=["hunter2x"], kept=["--password ", " registry.example.com"])
        self.check("docker login --password=hunter2x registry.example.com",
                   gone=["hunter2x"], kept=["--password=", " registry.example.com"])
        self.check("aws rds create-db-instance --master-user-password 'Hunter 2x' --engine mysql",
                   gone=["Hunter 2x"], kept=["--master-user-password '", "' --engine mysql"])
        # Flags that take no value, or aren't passwords, leave the next word alone
        self.check("docker login -u AWS --password-stdin registry.example.com\n"
                   "ssh -p 2222 bastion.example.com\ndocker run -p 8080:80 nginx\n"
                   "curl --anyauth https://intranet.example.com/x\nmkdir -p build",
                   kept=["--password-stdin registry.example.com", "-p 2222 bastion",
                         "-p 8080:80 nginx", "--anyauth https://intranet.example.com/x",
                         "mkdir -p build"])

    def test_authorization_headers(self):
        self.check("Authorization: Bearer abcdef0123456789xyz",
                   gone=["abcdef0123456789xyz"], kept=["Authorization: Bearer "])
        self.check("authorization: Basic YWRtaW46aHVudGVyMg==",
                   gone=["YWRtaW46aHVudGVyMg"], kept=["authorization: Basic "])
        self.check("curl -H 'Authorization: Token tok_live_1234' -H \"X-Api-Key: k3yk3y\" "
                   "https://api.example.com",
                   gone=["tok_live_1234", "k3yk3y"], kept=["https://api.example.com"])
        self.check('{"headers": {"Authorization": "Bearer abc.def-ghi", "Accept": "json"}}',
                   gone=["abc.def-ghi"], kept=['"Accept": "json"'])


class UnquotedValueTests(RedactCase):
    """M2: unquoted values that were cut short or skipped."""

    def test_whole_value_on_a_setting_line(self):
        self.check("password=Abc(123xyz", gone=["Abc", "123xyz"], kept=["password="])
        self.check("password=hunter2#extra", gone=["hunter2", "#extra"], kept=["password="])
        text = ("db:\n  host: db.internal\n  password: correct horse battery staple\n"
                "  port: 5432\n")
        self.check(text, gone=["correct", "horse", "battery", "staple"],
                   kept=["host: db.internal", "  password: ", "port: 5432"])
        self.check("export DB_PASSWORD=pa ss # set by ops\nexport DB_PORT=5432",
                   gone=["pa ss", "set by ops"], kept=["export DB_PASSWORD=", "DB_PORT=5432"])

    def test_whole_names(self):
        # Owner: Jane Doe used to become Owner: [Redacted] Doe, so the surname leaked.
        self.check("Owner: Jane Doe", gone=["Jane", "Doe"], kept=["Owner: "])
        self.check("DisplayName: Mary Ann Smith-Jones (admin)",
                   gone=["Mary", "Ann", "Smith-Jones"], kept=["(admin)"])
        self.check("first_name: Se\u00e1n O\u2019Brien", gone=["Se\u00e1n", "Brien"])
        self.check("Tags: Owner=Jane Doe Env=prod, team=ops", gone=["Jane", "Doe"],
                   kept=["Env=prod", "team=ops"])
        self.check("Owner: Jane Doe is on call.", gone=["Jane", "Doe"], kept=[" is on call."])
        self.check("user: admin logged in", gone=["admin"], kept=[" logged in"])
        self.check("User: jdoe Status: Active", gone=["jdoe"], kept=["Status: Active"])

    def test_inline_values_stop_at_the_next_setting(self):
        self.check("level=info password=hunter2#x user_count=3",
                   gone=["hunter2#x"], kept=["level=info password=", " user_count=3"])
        self.check("Server=db;Database=app;Password=Pa55(w0rd;Encrypt=true",
                   gone=["Pa55(w0rd"], kept=["Database=app;Password=", ";Encrypt=true"])
        self.check("connect(host='db', password=hunter2)", gone=["hunter2"], kept=["password=", ")"])

    def test_expressions_are_not_secrets(self):
        text = ('resource "aws_db_instance" "x" {\n'
                "  password = var.db_password\n"
                "  password = random_password.db.result\n"
                '  password = "${var.pw}"\n'
                "  password = sensitive(var.pw)\n"
                "  secret_string = jsonencode({\n"
                "  password = (sensitive value)\n"
                "  token = (known after apply)\n"
                "}\n"
                "MasterUserPassword: !Ref DbPassword\n"
                'pw = os.getenv("DB_PASSWORD")\n')
        self.check(text, kept=["var.db_password", "random_password.db.result", "${var.pw}",
                               "sensitive(var.pw)", "jsonencode({", "(sensitive value)",
                               "(known after apply)", "!Ref DbPassword",
                               'os.getenv("DB_PASSWORD")'])

    def test_url_password_with_a_slash(self):
        self.check("postgres://admin:pa/ss@db.example.internal:5432/app",
                   gone=["admin", "pa/ss"], kept=["@db.example.internal:5432/app"])
        # A port and path before an @ isn't a password
        self.check("see https://example.com:8443/releases/tag@v2 for details",
                   kept=["https://example.com:8443/releases/tag@v2"])


class PrivateKeyTests(RedactCase):
    """M3: private keys cut off before their END line, and PuTTY keys."""

    BODY = ("MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
            "qrstuvwxyzABCDEFGHIJ0123456789+/abcdefghijklmnopqrstuvwxyz0123456",
            "AbCdEf0123==")

    def test_key_without_an_end_line(self):
        text = ("Here's the key:\n-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(self.BODY)
                + "\n\nThat's all I copied.")
        self.check(text, gone=list(self.BODY), kept=["Here's the key:\n", "That's all I copied."])

    def test_encrypted_key_without_an_end_line(self):
        text = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" + "\n".join(self.BODY))
        self.check(text, gone=list(self.BODY) + ["0123456789ABCDEF0123456789ABCDEF"])

    def test_cut_off_key_inside_json(self):
        text = ('{"pasted": "-----BEGIN PRIVATE KEY-----\\n' + "\\n".join(self.BODY[:2])
                + '\\n", "client_email": "x"}')
        self.check(text, gone=list(self.BODY[:2]), kept=['"pasted": "', '\\n", "client_email"'])

    def test_whole_key_still_redacted(self):
        text = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(self.BODY)
                + "\n-----END OPENSSH PRIVATE KEY-----\nnext")
        self.assertEqual(run(text), "[Redacted]\nnext")

    def test_putty_key(self):
        text = ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"
                "Comment: eddsa-key-20261004\nPublic-Lines: 2\n"
                "AAAAC3NzaC1lZDI1NTE5AAAAIB0123456789abcdefghijklmnopqrstuvwxyzABCD\nEFGH\n"
                "Private-Lines: 2\nAAAAIF0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n"
                "QRSTUVWXYZabcdef\nPrivate-MAC: 0123\n")
        self.check(text, gone=["AAAAIF0123456789", "QRSTUVWXYZabcdef"],
                   kept=["Private-Lines: 2\n", "\nPrivate-MAC:", "Encryption: none"])


class PresignedUrlTests(RedactCase):
    """L2: the whole session token in a presigned URL."""

    def test_presigned_url(self):
        token = ("IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIQD"
                 "%2Babc%2BdefghijQ%3D%3D%2Fklmnop")
        url = ("https://b.s3.us-east-1.amazonaws.com/report.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256"
               "&X-Amz-Credential=ASIAQWERTYUIOPASDFGH%2F20261004%2Fus-east-1%2Fs3%2Faws4_request"
               "&X-Amz-Date=20261004T000000Z&X-Amz-Expires=3600&X-Amz-Security-Token=" + token
               + "&X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
               "&X-Amz-SignedHeaders=host")
        out = self.check(url, gone=["ASIAQWERTYUIOPASDFGH", "EJr", "wEaCXVz", "klmnop", "Babc",
                                    "fe5f80f77d5f"],
                         kept=["%2F20261004%2Fus-east-1%2Fs3%2Faws4_request",
                               "X-Amz-Date=20261004T000000Z", "&X-Amz-SignedHeaders=host",
                               "X-Amz-Expires=3600&"])
        self.assertIn("X-Amz-Security-Token=[Redacted]&X-Amz-Signature=[Redacted]&", out)


class SpeedTests(unittest.TestCase):
    """L1: big pastes of one long word or blob used to take minutes."""

    LIMIT = 2.0

    def timed(self, text, **opts):
        start = time.perf_counter()
        redact.redact(text, redact.Options(**opts))
        return time.perf_counter() - start

    def test_long_runs_are_fast(self):
        rng = random.Random(1)
        n = 100_000
        blobs = {
            "base64": base64.b64encode(rng.randbytes(n)).decode()[:n],
            "base64url": base64.urlsafe_b64encode(rng.randbytes(n)).decode()[:n],
            "hex": rng.randbytes(n // 2).hex(),
            "one word": "a" * n,
            "dotted": ".".join("a" * (n // 2)),
            "dashed": "-".join(["ab"] * (n // 3)),
            "colons": ":".join(["ab"] * (n // 3)),
            "equals": "=".join(["ab"] * (n // 3)),
        }
        for name, text in blobs.items():
            with self.subTest(name):
                self.assertLess(self.timed(text), self.LIMIT, name)

    def test_never_list_with_many_matches(self):
        text = "account 123456789012 ip 54.1.2.3 keep-me " * 3000
        self.assertLess(self.timed(text, never=["keep-me", "54.1.2.3"]), self.LIMIT)
        out = run("keep 54.1.2.3 and 54.1.2.4, account 123456789012 and 210987654321",
                  never=["54.1.2.3", "123456789012"])
        self.assertEqual(out, "keep 54.1.2.3 and [Redacted], account 123456789012 and [Redacted]")


class SettingsFileTests(unittest.TestCase):
    """L3: the settings file is private from the start and never written through a link."""

    def tearDown(self):
        for p in (redact.CONFIG_FILE, redact.CONFIG_FILE.with_name("decoy.json"),
                  redact.CONFIG_FILE.with_suffix(".tmp")):
            if p.is_symlink() or p.exists():
                p.unlink()

    def test_saved_owner_only(self):
        old = os.umask(0o022)
        try:
            self.assertTrue(redact.save_config(redact.default_config()))
        finally:
            os.umask(old)
        mode = stat.S_IMODE(redact.CONFIG_FILE.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(json.loads(redact.CONFIG_FILE.read_text())["placeholder"], "Redacted")
        self.assertEqual([p.name for p in redact.CONFIG_DIR.glob("*.tmp")], [])

    def test_planted_temp_file_link_is_not_followed(self):
        # The old code always wrote redact.tmp first, so a link there sent the write elsewhere
        redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        decoy = redact.CONFIG_FILE.with_name("decoy.json")
        decoy.write_text("untouched")
        decoy.chmod(0o644)
        redact.CONFIG_FILE.with_suffix(".tmp").symlink_to(decoy)
        self.assertTrue(redact.save_config(redact.default_config()))
        self.assertEqual(decoy.read_text(), "untouched")
        self.assertEqual(stat.S_IMODE(decoy.stat().st_mode), 0o644)
        self.assertFalse(redact.CONFIG_FILE.is_symlink())
        self.assertEqual(stat.S_IMODE(redact.CONFIG_FILE.stat().st_mode), 0o600)

    def test_link_is_replaced_not_followed(self):
        redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        decoy = redact.CONFIG_FILE.with_name("decoy.json")
        decoy.write_text("untouched")
        if redact.CONFIG_FILE.exists() or redact.CONFIG_FILE.is_symlink():
            redact.CONFIG_FILE.unlink()
        redact.CONFIG_FILE.symlink_to(decoy)
        self.assertTrue(redact.save_config(redact.default_config()))
        self.assertEqual(decoy.read_text(), "untouched")
        self.assertFalse(redact.CONFIG_FILE.is_symlink())

    def test_odd_settings_dont_stop_redacting(self):
        # "categories" that isn't an object stopped every redaction with AttributeError
        redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        for categories in (["emails"], "emails", 5):
            redact.CONFIG_FILE.write_text(json.dumps({"categories": categories,
                                                      "always_redact": ["snowcorp"]}))
            with self.subTest(categories):
                cfg = redact.load_config()
                self.assertEqual(cfg["categories"], redact.default_config()["categories"])
                self.assertEqual(cfg["always_redact"], ["snowcorp"])

    def test_settings_saved_with_a_byte_order_mark(self):
        # Notepad and PowerShell can put a byte order mark first. It used to mean every
        # setting was ignored.
        redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        redact.CONFIG_FILE.write_bytes(b"\xef\xbb\xbf" + json.dumps(
            {"numbered": True, "always_redact": ["snowcorp"]}).encode())
        cfg = redact.load_config()
        self.assertTrue(cfg["numbered"])
        self.assertEqual(cfg["always_redact"], ["snowcorp"])

    def test_unreadable_settings_are_kept_before_saving(self):
        # A typo made by hand used to be wiped by the next save, word lists and all
        bad = redact.CONFIG_FILE.with_name("redact.json.bad")
        self.addCleanup(lambda: bad.exists() and bad.unlink())
        redact.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        typo = '{"always_redact": ["Jane Doe", "snowcorp",]}'
        redact.CONFIG_FILE.write_text(typo)
        self.assertEqual(redact.load_config()["always_redact"], [])
        self.assertTrue(redact.save_config(redact.default_config()))
        self.assertEqual(bad.read_text(), typo)
        self.assertEqual(stat.S_IMODE(bad.stat().st_mode), 0o600)
        bad.unlink()
        self.assertTrue(redact.save_config(redact.default_config()))   # a good file isn't
        self.assertFalse(bad.exists())


class RunEchoTests(unittest.TestCase):
    """I3: pii-redact run shows the command it runs, redacted."""

    def test_command_line_is_redacted_before_it_shows(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        err, out = Terminal(), io.StringIO()
        done = subprocess.CompletedProcess([], 0, stdout=b"ok\n")
        args = redact.build_parser().parse_args([])
        cmd = ["mysql", "-u", "root", "--password", "hunter2x", "-h", "54.201.33.17"]
        with mock.patch.object(redact.subprocess, "run", return_value=done), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            self.assertEqual(redact.cmd_run(cmd, redact.default_config(), args), 0)
        self.assertIn("Running mysql -u root --password [Redacted]", err.getvalue())
        self.assertNotIn("hunter2x", err.getvalue())
        self.assertNotIn("54.201.33.17", err.getvalue())

    @unittest.skipIf(os.name == "nt", "file modes")
    def test_command_that_cant_run_is_a_message(self):
        # A script without the executable bit, or a folder, used to end in a traceback
        folder = Path(tempfile.mkdtemp(prefix="awskit-run-"))
        self.addCleanup(shutil.rmtree, folder)
        script = folder / "plan.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o644)
        args = redact.build_parser().parse_args([])
        for cmd in ([str(script)], [str(folder)]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(redact.cmd_run(cmd, redact.default_config(), args), 126)
            self.assertIn(f"pii-redact: can't run {cmd[0]}", err.getvalue())


@unittest.skipUnless(shutil.which("xvfb-run") or os.environ.get("DISPLAY")
                     or os.environ.get("WAYLAND_DISPLAY"), "no display")
class RedactWindowTests(unittest.TestCase):
    """L1b: the paste window redacts in the background and drops stale results."""

    SCRIPT = r'''
import sys, time
sys.path.insert(0, sys.argv[1])
import gi
gi.require_version("Gtk", "4.0")
from collections import Counter
from gi.repository import GLib
from awskit import redact, redact_page

ctx = GLib.MainContext.default()

def out_text(v):
    return v.out_buf.get_text(v.out_buf.get_start_iter(), v.out_buf.get_end_iter(), False)

def spin(until, limit=10):
    end = time.time() + limit
    while time.time() < end and not until():
        ctx.iteration(False)
        time.sleep(0.005)
    return until()

v = redact_page.RedactView("account 123456789012")
assert spin(lambda: out_text(v) == "account [Redacted]"), out_text(v)

# A result that comes back after the text changed is dropped, and the run starts again
v.in_buf.set_text("ip 54.201.33.17")
v._busy = True
v._finished(v._gen - 1, "old", redact.load_config(), ("STALE", Counter(), []))
assert out_text(v) != "STALE"
assert spin(lambda: out_text(v) == "ip [Redacted]"), out_text(v)

# A big paste doesn't hold up the window: _run hands the work off and returns
v.in_buf.set_text("account 123456789012 in us-east-1\n" * 20000)
if v._pending:
    GLib.source_remove(v._pending)
start = time.perf_counter()
v._run()
handoff = time.perf_counter() - start
assert v._busy
assert spin(lambda: not v._busy and out_text(v).startswith("account [Redacted] in us-east-1\n"))
assert handoff < 0.5, handoff

# Copy while the output is catching up copies the up-to-date result once it's ready
v.in_buf.set_text("mail jane@example.com")
v.copy()
assert spin(lambda: v.status.get_text().startswith("Copied")), v.status.get_text()
assert out_text(v) == "mail [Redacted]", out_text(v)
print("ok")
'''

    def run_script(self, script, *args):
        cmd = [sys.executable, "-c", script, str(ROOT), *args]
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            cmd = ["xvfb-run", "-a", "-s", "-screen 0 1280x800x24"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, PYTHONPATH=str(ROOT)))
        if "No module named 'gi'" in r.stderr or "Namespace Gtk not available" in r.stderr:
            self.skipTest("GTK 4 for Python isn't installed")
        return r

    def test_background_redaction(self):
        r = self.run_script(self.SCRIPT)
        self.assertEqual(r.stdout.strip().splitlines()[-1:], ["ok"], r.stderr[-3000:])

    # The settings window is an app window too. With only it left open, opening AWS Kit
    # or PII Redact again used to bring back just the settings window.
    REOPEN = r'''
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib
from awskit import app

mode = sys.argv[2] or None
a = app.App(page=mode)
out = {}

def names():
    return sorted(type(w).__name__ for w in a.get_windows())

def first():
    try:
        w = a.get_active_window()
        (w.pages["redact"].view if mode is None else w.view).open_settings()
        w.close()
        out["left"] = names()
        if mode is None:       # awskit gui map, while only the settings window is open
            a.activate_action("show-page", GLib.Variant.new_string("map"))
        a.activate()
        out["after"] = names()
        mains = [w for w in a.get_windows() if type(w).__name__ == "MainWindow"]
        out["page"] = mains[0].stack.get_visible_child_name() if mains else None
        print(json.dumps(out))
    finally:
        a.quit()
    return False

def start():
    if a.get_active_window() is None:
        return True
    GLib.timeout_add(300, first)
    return False

GLib.timeout_add(100, start)
a.run([])
'''

    def test_opening_again_brings_the_window_back(self):
        for mode, window in (("", "MainWindow"), ("redact-window", "RedactWindow")):
            with self.subTest(mode or "main"):
                r = self.run_script(self.REOPEN, mode)
                lines = [x for x in r.stdout.splitlines() if x.startswith("{")]
                self.assertTrue(lines, r.stderr[-3000:])
                got = json.loads(lines[-1])
                self.assertEqual(got["left"], ["RedactSettingsWindow"])
                self.assertEqual(got["after"], sorted([window, "RedactSettingsWindow"]))
                if not mode:
                    self.assertEqual(got["page"], "map")


class ProfileFileTests(unittest.TestCase):
    """L4, L5 and I1: odd ~/.aws files and profile names."""

    def setUp(self):
        self.config = Path(os.environ["AWS_CONFIG_FILE"])
        self.creds = Path(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
        self.saved = {p: p.read_bytes() if p.exists() else None for p in (self.config, self.creds)}

    def tearDown(self):
        for p, data in self.saved.items():
            if data is None:
                if p.exists():
                    p.unlink()
            else:
                p.write_bytes(data)

    def names(self):
        return {p["name"]: p for p in profiles.list_profiles()}

    def test_duplicate_sections_dont_hide_later_profiles(self):
        self.config.write_text(
            "[default]\nregion = us-west-2\n\n"
            "[profile dev]\nregion = us-east-1\n\n"
            "[profile dev]\nregion = eu-west-1\nregion = eu-west-2\n\n"
            "[profile prod]\nrole_arn = arn:aws:iam::222222222222:role/Admin\n"
            "source_profile = default\n")
        self.creds.write_text("[dev]\naws_access_key_id = AKIAEXAMPLE\n[dev]\n"
                              "aws_secret_access_key = x\n[keys-only]\naws_access_key_id = y\n")
        rows = self.names()
        self.assertEqual(set(rows), {"default", "dev", "prod", "keys-only"})
        self.assertEqual(rows["dev"]["region"], "eu-west-2")  # the later one wins
        self.assertEqual(rows["prod"]["account"], "222222222222")

    def test_bad_lines_bom_and_settings_before_the_first_section(self):
        self.config.write_bytes(
            "\ufeffregion = us-east-1\n[profile a]\nregion = us-west-1\n"
            "this line is broken\n[profile b]\nregion = us-west-2\n".encode("utf-8"))
        self.creds.write_bytes(b"[c]\naws_access_key_id = \xff\xfe\n")
        rows = self.names()
        self.assertEqual(rows["a"]["region"], "us-west-1")
        self.assertEqual(rows["b"]["region"], "us-west-2")
        self.assertIn("c", rows)

    def test_damaged_sso_cache_files(self):
        cache = Path(tempfile.mkdtemp(prefix="awskit-sso-"))
        self.addCleanup(shutil.rmtree, cache)
        profile = {"kind": "sso", "sso_session": "lab", "sso_start_url": "https://x.awsapps.com/start"}
        with mock.patch.object(profiles, "_sso_cache_dir", return_value=cache):
            for content in ('["not", "a", "dict"]', '{"expiresAt": 12345}', '"just text"',
                            '{"expiresAt": ["2026"]}', '{"expiresAt": "garbage"}'):
                for key in ("lab", "https://x.awsapps.com/start"):
                    name = hashlib.sha1(key.encode()).hexdigest() + ".json"
                    (cache / name).write_text(content)
                with self.subTest(content):
                    self.assertIsNone(profiles.sso_expiry(profile))
                    self.assertEqual(profiles.offline_status(profile), "not signed in")
            (cache / (hashlib.sha1(b"lab").hexdigest() + ".json")).write_text(
                json.dumps({"expiresAt": "2099-01-01T00:00:00Z"}))
            self.assertTrue(profiles.offline_status(profile).startswith("signed in until"))

    def test_unsafe_profile_names_are_refused_before_running_aws(self):
        with mock.patch.object(profiles.shutil, "which", return_value="C:\\aws\\aws.cmd"), \
                mock.patch.object(profiles.subprocess, "run") as run_mock:
            for name in ('x" & calc & "', "a|b", "a%PATH%", "a b", "a^b", "a>b", ""):
                ok, message = profiles.sso_login(name)
                self.assertFalse(ok, name)
                self.assertIn("can only use letters, numbers", message)
            run_mock.assert_not_called()
            run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")
            for name in ("lab-admin", "team.prod", "jane@example.com", "a+b=c,d/e", "x_1"):
                ok, _ = profiles.sso_login(name)
                self.assertTrue(ok, name)
            self.assertEqual(run_mock.call_args[0][0][-2:], ["--profile", "x_1"])


if __name__ == "__main__":
    unittest.main()
