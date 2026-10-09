"""Tests for Secrets Scan: detection, masking, allow lists, git scanning, the commit hook,
and the command line.

Run from the repo root:  python3 -m unittest tests.test_secrets_scan -v

Every key, token and password here is built from random characters at run time, so this
file holds nothing that looks like a secret itself. The git tests make throwaway repos in a
temp folder and skip when git isn't installed.
"""
import contextlib
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
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT =Path(__file__).resolve().parent.parent
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
# Nor may your own git settings (a global core.hooksPath, signing, templates) leak in.
_GIT_GLOBAL = os.path.join(TMP, "gitconfig-global")
Path(_GIT_GLOBAL).write_text("[init]\n\tdefaultBranch = main\n", encoding="utf-8")
os.environ.update({"GIT_CONFIG_GLOBAL": _GIT_GLOBAL, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_TERMINAL_PROMPT": "0"})
for _name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
    os.environ.pop(_name, None)

from awskit import cli, common  # noqa: E402
from awskit import redact as pii  # noqa: E402
from awskit import secretscan as ss  # noqa: E402

GIT = shutil.which("git")
needs_git = unittest.skipUnless(GIT, "git isn't installed")
needs_sh = unittest.skipUnless(GIT and os.name != "nt" and shutil.which("sh"),
                               "needs git and a POSIX sh")

RNG = random.Random(20261005)
ALNUM = string.ascii_letters + string.digits
B32 = string.ascii_uppercase + "234567"


def rnd(n, chars=ALNUM):
    return "".join(RNG.choice(chars) for _ in range(n))


def access_key():
    while True:
        k = "AKIA" + rnd(16, B32)
        if not ss._fake_token(k[4:]):
            return k


def secret_key():
    while True:
        s = rnd(40, ALNUM + "/+")
        if pii.secret_40_check(s) and pii.mixed_charset(s) and "/" not in s[:1]:
            return s


def strong_password():
    return rnd(6) + "#" + rnd(5) + "!" + str(RNG.randint(10, 99))


def github_token():
    return "ghp_" + rnd(36)


def private_key():
    body = "\n".join(rnd(64, ALNUM + "+/") for _ in range(6))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


def kinds(text, path="file.txt", **kw):
    return [(c.kind, c.level) for c in ss.detect(text, path, **kw) if not c.example]


def git(repo, *args, check=True):
    return subprocess.run([GIT, "-C", str(repo), *args], check=check, capture_output=True,
                          text=True)


def make_repo():
    repo = Path(tempfile.mkdtemp(prefix="secrets-repo-", dir=TMP))
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Test User")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


def write(repo, name, text):
    p = Path(repo) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def commit_all(repo, msg="commit"):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", msg)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(["secrets", *argv])
    return rc, out.getvalue(), err.getvalue()


# =================================================================== detection

class DetectionTests(unittest.TestCase):
    def test_aws_key_pair_blocks_and_points_at_each_other(self):
        ak, sk = access_key(), secret_key()
        found = ss.detect(f"[lab]\naws_access_key_id = {ak}\naws_secret_access_key = {sk}\n",
                          "credentials")
        by_kind = {c.kind: c for c in found}
        self.assertEqual(by_kind["aws_access_key"].level, "block")
        self.assertEqual(by_kind["aws_secret_key"].level, "block")
        self.assertIn("next line", by_kind["aws_access_key"].note)

    def test_access_key_alone_and_session_token_block(self):
        self.assertIn(("aws_access_key", "block"), kinds(f"key: {access_key()}"))
        token = "IQoJb3JpZ2lu" + rnd(300, ALNUM + "/+")
        self.assertIn(("aws_session_token", "block"), kinds(f"session = {token}"))

    def test_aws_documentation_examples_are_skipped(self):
        text = ("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "arn:aws:iam::123456789012:role/Admin\n"
                "arn:aws:iam::111111111111:root and arn:aws:iam::111122223333:root\n"
                "AKIAI44QH8DHBEXAMPLE\n")
        found = ss.detect(text, "README.md")
        self.assertTrue(found)
        self.assertTrue(all(c.example for c in found), [(c.kind, c.value) for c in found])
        findings, allowed, examples = ss.scan_text(text, "README.md")
        self.assertEqual((findings, allowed), ([], []))
        self.assertGreaterEqual(examples, 5)

    def test_placeholders_and_references_are_not_secrets(self):
        cases = {
            "config.yml": ['password: "changeme"', "password: REPLACE_ME", "secret: example",
                           'api_key: "<your-api-key>"', "token: xxxxxxxx", 'password: ""',
                           "password: ${DB_PASSWORD}", "password: $DB_PASS",
                           'password: "{{ vault_db_password }}"', "password: !vault |",
                           "token: ${{ secrets.GITHUB_TOKEN }}", "password: DB_PASSWORD",
                           "api_key: your-api-key-here", "password: null",
                           "secret_name: prod/db/password", "password_hash: $2b$12$abc",
                           "private_key: ./keys/deploy.pem", "password: ********"],
            "app.py": ['api_key = os.environ["API_KEY"]', "password = args.password",
                       "token = get_token()", "def login(user, password=None):",
                       "password: str = ''", 'if password == "admin123":',
                       'DB_PASSWORD = os.environ.get("DB_PASSWORD", "")'],
            "main.tf": ["password = var.db_password",
                        "password = random_password.db.result",
                        'password = data.aws_ssm_parameter.db.value'],
            "en.json": ['{"password": "Password", "forgotPassword": "Forgot your password?"}'],
            "paginators-1.json": ['"input_token": "ExclusiveStartBackupArn",',
                                  '"output_token": "NextMarker || Contents[-1].Key",'],
            "service-2.json": ['"AwsS3BucketServerSideEncryptionByDefault":{',
                               '"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"',
                               '"documentation": "<p>the password: <code>! # $</code></p>"'],
            "x509.pyi": ["private_key: typing.Optional[PrivateKeyTypes]"],
            "style.css": [".sk-fading-circle-animation-container { color: red }"],
            "docs.md": ["curl -H 'Authorization: Bearer $TOKEN' https://api",
                        "SLACK_TOKEN=xoxb-your-token-here", "GITHUB=ghp_" + "x" * 36,
                        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n"
                        "-----END RSA PRIVATE KEY-----"],
        }
        for path, lines in cases.items():
            for line in lines:
                with self.subTest(path=path, line=line):
                    self.assertEqual(kinds(line, path), [])

    def test_real_looking_values_block(self):
        cases = [
            (".env", f"DB_PASSWORD={strong_password()}", "password"),
            ("settings.py", f'API_KEY = "{rnd(32)}"', "api_key"),
            ("main.tf", f'master_password = "{strong_password()}"', "password"),
            ("settings.xml", f"<password>{strong_password()}</password>", "password"),
            ("deploy.sh", f"export CLIENT_SECRET={rnd(24)}", "secret"),
            ("app.js", f'const authToken = "{rnd(30)}";', "token"),
            ("docker-compose.yml",
             f"  - DATABASE_URL=postgres://app:{strong_password()}@db.prod.example.net/app",
             "url_password"),
            ("run.sh", f"curl -H 'Authorization: Bearer {rnd(40)}' https://api", "auth_header"),
        ]
        for path, line, kind in cases:
            with self.subTest(path=path):
                self.assertIn((kind, "block"), kinds(line, path))

    def test_weak_and_default_passwords_only_warn(self):
        for line in ("POSTGRES_PASSWORD=postgres", "password: admin123",
                     "DB_PASS=P@ssw0rd", "JWT_SECRET=supersecretkey",
                     "redis_url = redis://user:devpass99@localhost:6379"):
            with self.subTest(line=line):
                found = kinds(line, ".env")
                self.assertTrue(found and all(level == "warn" for _, level in found), found)

    def test_ids_and_example_files_only_warn(self):
        uuid = "bcd2f1b8-9a78-44d3-8a7a-4dd07d7cf635"
        self.assertEqual(kinds(f'"LifecycleActionToken": "{uuid}"', "x.json"),
                         [("token", "warn")])
        line = f"DB_PASSWORD={strong_password()}"
        for name in (".env.example", "config.sample.yml", "settings.php.dist",
                     "examples-1.json"):
            with self.subTest(name=name):
                self.assertEqual(kinds(line, name), [("password", "warn")])
        self.assertEqual(kinds(f"KEY={access_key()}", ".env.example"),
                         [("aws_access_key", "block")])

    def test_unquoted_values_in_code_are_references_but_literal_in_config(self):
        pw = strong_password()
        self.assertEqual(kinds(f"password = {pw}", "app.py"), [])
        self.assertIn(("password", "block"), kinds(f"password = {pw}", "app.ini"))
        self.assertIn(("password", "block"), kinds(f'password = b"{pw}"', "app.py"))

    def test_developer_tokens(self):
        for token, kind in ((github_token(), "github_token"),
                            ("gho_" + rnd(36), "github_token"),
                            ("github_pat_11" + rnd(80, ALNUM + "_"), "github_token"),
                            (f"xoxb-{RNG.randint(10**10, 10**11)}-{rnd(24)}", "slack_token"),
                            ("npm_" + rnd(36), "npm_token")):
            with self.subTest(kind=kind):
                self.assertIn((kind, "block"), kinds(f"value: {token}"))
        hook = ("https://hooks.slack.com/services/T" + rnd(9, B32) + "/B" + rnd(9, B32) + "/"
                + rnd(24))
        self.assertIn(("slack_webhook", "block"), kinds(f'URL = "{hook}"', "notify.sh"))

    def test_private_keys_block_and_certificates_dont(self):
        self.assertIn(("private_key", "block"), kinds(private_key(), "id_rsa"))
        cert = ("-----BEGIN CERTIFICATE-----\n" +
                "\n".join(rnd(64, ALNUM + "+/") for _ in range(3)) + "\n" +
                secret_key().replace("/", "a").replace("+", "b") +
                "\n-----END CERTIFICATE-----\n")
        self.assertEqual(kinds(cert, "ca.pem"), [])

    def test_private_keys_inside_json_and_base64(self):
        import base64
        pem = private_key()
        body_line = pem.splitlines()[1]
        escaped = json.dumps({"type": "service_account", "private_key": pem + "\n"})
        findings, _, _ = ss.scan_text(escaped, "sa.json")
        self.assertEqual([f.kind for f in findings], ["private_key"])
        self.assertNotIn(body_line, findings[0].context + findings[0].preview)
        self.assertTrue(findings[0].preview.startswith("-----BEGIN RSA PRIVATE KEY----- ("))
        # A key written on one line with \n in it shows its BEGIN line, never its body.
        one_line = pem.replace("\n", "\\n")
        findings, _, _ = ss.scan_text(f"KEY={one_line}\n", "key.env")
        self.assertEqual([f.kind for f in findings], ["private_key"])
        self.assertNotIn(body_line, findings[0].context)
        encoded = base64.b64encode(pem.encode()).decode()
        findings, _, _ = ss.scan_text(f"    client-key-data: {encoded}\n", "kubeconfig")
        self.assertEqual([(f.kind, f.what) for f in findings],
                         [("private_key", "Private key, base64-encoded")])
        self.assertNotIn(encoded, findings[0].context + findings[0].preview)
        cert = base64.b64encode(b"-----BEGIN CERTIFICATE-----\n" + rnd(300).encode()).decode()
        self.assertEqual(kinds(f"certificate-authority-data: {cert}", "kubeconfig"), [])

    def test_lone_random_40_characters_only_warn(self):
        lone = secret_key()
        self.assertEqual(kinds(f"value {lone} here", "notes.txt"),
                         [("aws_secret_maybe", "warn")])
        self.assertEqual(kinds(f"sha1-checksum {lone}", "notes.txt"), [])
        self.assertNotIn("aws_secret_key", [k for k, _ in kinds(
            f'SECRET_KEY = "django-insecure-{lone}"', "settings.py")])

    def test_test_and_docs_files_downgrade_generic_but_not_keys(self):
        text = f'password = "{strong_password()}"\nkey = "{access_key()}"\n'
        found = dict(kinds(text, "tests/test_login.py"))
        self.assertEqual(found["password"], "warn")
        self.assertEqual(found["aws_access_key"], "block")
        self.assertEqual(dict(kinds(text, "docs/setup.md"))["password"], "warn")

    def test_account_ids_need_context_and_can_block(self):
        account = str(RNG.randint(2 * 10 ** 11, 9 * 10 ** 11))
        self.assertEqual(kinds(f"arn:aws:iam::{account}:role/x"), [("account_id", "warn")])
        self.assertEqual(kinds(f"order number {account}"), [])
        self.assertEqual(kinds(f"arn:aws:iam::{account}:role/x", block_account_ids=True),
                         [("account_id", "block")])

    def test_internal_ips_and_emails(self):
        self.assertEqual(kinds('host = "10.20.1.25"'), [("internal_ip", "warn")])
        for quiet in ('cidr = "10.20.0.0/16"', 'gw = "10.20.1.1"', 'doc = "192.0.2.10"',
                      "imds 169.254.169.254", "range fd00:: here", "version 10.2.3.4"):
            with self.subTest(text=quiet):
                self.assertEqual(kinds(quiet), [])
        domain = "".join(RNG.choice(string.ascii_lowercase) for _ in range(12)) + ".net"
        self.assertEqual(kinds(f"mail bob.smith@{domain}"), [("email", "warn")])
        self.assertEqual(kinds("mail jane@example.com"), [])
        self.assertEqual(kinds(f"Copyright Bob <bob.smith@{domain}>", "LICENSE"), [])

    def test_overlaps_keep_the_most_specific(self):
        token = github_token()
        self.assertEqual(kinds(f'GITHUB_TOKEN = "{token}"', "app.py"),
                         [("github_token", "block")])

    def test_the_word_example_next_to_a_real_key_doesnt_hide_it(self):
        sk = secret_key()
        for line in (f"aws_secret_access_key = {sk} (not the EXAMPLE one)",
                     f"AWS_SECRET_ACCESS_KEY={sk} EXAMPLE"):
            with self.subTest(line=line):
                findings, _, examples = ss.scan_text(line, "creds.ini")
                self.assertEqual([(f.kind, f.level) for f in findings],
                                 [("aws_secret_key", "block")])
                self.assertEqual(examples, 0)

    def test_private_keys_flattened_onto_one_line(self):
        body = [rnd(64, ALNUM + "+/") for _ in range(6)]
        for path, line in (
                (".env", "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY----- " + " ".join(body)
                 + " -----END RSA PRIVATE KEY-----"),
                ("app.py", 'KEY = "-----BEGIN PRIVATE KEY-----' + "".join(body)
                 + '-----END PRIVATE KEY-----"'),
                ("a.yml", "key: -----BEGIN OPENSSH PRIVATE KEY----- " + " ".join(body))):
            with self.subTest(path=path):
                findings, _, _ = ss.scan_text(line, path)
                self.assertEqual([(f.kind, f.level) for f in findings],
                                 [("private_key", "block")])
                f = findings[0]
                self.assertTrue(f.preview.startswith("-----BEGIN "), f.preview)
                for part in body:
                    self.assertNotIn(part[:12], f.preview + f.context + f.detail_text())

    def test_bedrock_api_keys(self):
        import base64
        account = str(RNG.randint(2 * 10 ** 11, 9 * 10 ** 11))
        secret = base64.b64encode(bytes(RNG.getrandbits(8) for _ in range(48)))
        long_key = "ABSK" + base64.b64encode(b"BedrockAPIKey-" + rnd(4).lower().encode()
                                             + b"-at-" + account.encode() + b":"
                                             + secret).decode()
        url = ("bedrock.amazonaws.com/?Action=CallWithBearerToken&X-Amz-Credential=ASIA"
               + rnd(16, B32) + "%2F20261005%2Fus-east-1%2Fbedrock%2Faws4_request"
               "&X-Amz-Security-Token=IQoJb3JpZ2lu" + rnd(300) + "&X-Amz-Signature="
               + rnd(64))
        short_key = "bedrock-api-key-" + base64.b64encode(url.encode()).decode()
        for path, line in ((".env", f"AWS_BEARER_TOKEN_BEDROCK={long_key}"),
                           ("app.py", f'key = "{long_key}"'),
                           ("run.sh", f"export AWS_BEARER_TOKEN_BEDROCK={short_key}")):
            with self.subTest(path=path):
                findings, _, _ = ss.scan_text(line, path)
                self.assertEqual([(f.kind, f.level) for f in findings],
                                 [("bedrock_key", "block")])
                self.assertNotIn(long_key[22:40], findings[0].preview + findings[0].context)
        self.assertEqual(kinds("AWS_BEARER_TOKEN_BEDROCK=ABSKQmVkcm9ja0FQSUtleS1" + "x" * 60,
                               ".env"), [])

    def test_random_passwords_with_symbols_are_not_taken_for_code_or_templates(self):
        symbols = "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
        # Each of these used to be skipped: letters then a ( or [ looked like a function
        # call, a / looked like a path, and ${, <% or #{ looked like a template.
        for pw in (f"Ab[{rnd(8)}%{rnd(6)}", f"Zq({rnd(10)}!{rnd(4)}",
                   f"/{rnd(6)}}}|{rnd(6)}*", f"{rnd(5)}<%{rnd(8)}#",
                   f"{rnd(5)}${{{rnd(8)}!", f"{rnd(4)}#{{{rnd(9)}@"):
            with self.subTest(pw=pw):
                self.assertIn("password", [k for k, _ in kinds(f"DB_PASSWORD={pw}", ".env")])
        missed = 0
        for _ in range(3000):
            pw = "".join(RNG.choice(ALNUM + symbols) for _ in range(20))
            missed += ss.password_level(pw, "password") is None
        self.assertLess(missed / 3000, 0.015)  # it was about 8 in 100
        # Real templates with their closing part are still references, not values
        for ref in ("${DB_PASSWORD}", "$(cat /run/secrets/db)", "{{ vault_pw }}",
                    "<%= ENV['PW'] %>", "#{ENV['PW']}", "!Ref DBPassword",
                    "config.get(db_password)", "/run/secrets/db_password"):
            with self.subTest(ref=ref):
                self.assertEqual(kinds(f"password: {ref}", "config.yml"), [])


class SpeedTests(unittest.TestCase):
    """Big or crafted files used to take minutes (time grew with the square of the size),
    which hangs a commit hook. These took 30 seconds to many minutes before."""

    def timed(self, text, path=".env"):
        import time
        start = time.monotonic()
        ss.scan_text(text, path)
        return time.monotonic() - start

    def test_many_matches(self):
        ips = "".join(f"host = 10.{RNG.randint(2, 250)}.{RNG.randint(2, 250)}."
                      f"{RNG.randint(2, 250)}\n" for _ in range(30000))
        self.assertLess(self.timed(ips, "hosts.txt"), 25)

    def test_begin_lines_without_an_end(self):
        self.assertLess(self.timed("-----BEGIN PRIVATE KEY-----\n" * 30000), 10)
        self.assertLess(self.timed("-----BEGIN CERTIFICATE-----\n" * 30000), 10)

    def test_a_long_run_of_spaces_in_a_value(self):
        self.assertLess(self.timed("PASSWORD=x" + " " * 200000 + "y\n"), 10)


# =================================================================== masking

class MaskingTests(unittest.TestCase):
    def test_previews(self):
        self.assertEqual(ss.mask_value("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
                         "AKIA************MPLE")
        self.assertEqual(ss.mask_value("hunter2-and-more", "password"),
                         "******** (16 characters)")
        self.assertTrue(ss.mask_value(private_key(), "private_key")
                        .startswith("-----BEGIN RSA PRIVATE KEY----- ("))
        self.assertEqual(ss.mask_value("10.20.1.25", "internal_ip"), "10.20.*.*")

    def test_context_hides_every_copy_of_a_secret(self):
        sk, pw = secret_key(), strong_password()
        text = (f"aws_secret_access_key = {sk}\n# check that {sk} is gone\n"
                f"db_password = '{pw}'\nnote: {pw}\n")
        findings, _, _ = ss.scan_text(text, "deploy.ini")
        self.assertTrue(findings)
        for f in findings:
            for raw in (sk, pw):
                self.assertNotIn(raw, f.context)
                self.assertNotIn(raw, f.detail_text())
                self.assertNotIn(raw, f.preview)

    def test_context_hides_copies_of_a_lowercase_password(self):
        pw = "".join(RNG.choice(string.ascii_lowercase) for _ in range(22))
        findings, _, _ = ss.scan_text(f'db_password = "{pw}"\n# the password is {pw}\n',
                                      "app.ini")
        self.assertEqual([(f.kind, f.level) for f in findings], [("password", "block")])
        self.assertNotIn(pw, findings[0].context)

    def test_control_characters_never_reach_the_output(self):
        text = f"X=1\n# \x1b[8m\u202e hidden\nGITHUB={github_token()}\n"
        findings, _, _ = ss.scan_text(text, "a\x1b[2Jb.env")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("\x1b", findings[0].context)
        self.assertNotIn("\u202e", findings[0].context)
        folder = Path(tempfile.mkdtemp(dir=TMP))
        name = "odd\x1b[2Jname.env" if os.name != "nt" else "plain.env"
        write(folder, name, text)
        rc, out, err = run_cli(str(folder), "--files", "-v")
        self.assertEqual(rc, 1)
        self.assertNotIn("\x1b", out + err)

    def test_long_minified_lines_are_cut_around_the_finding(self):
        token = github_token()
        text = "var a=" + "x" * 50000 + f';var t="{token}";' + "y" * 50000
        findings, _, _ = ss.scan_text(text, "bundle.min.js")
        self.assertEqual(len(findings), 1)
        self.assertLess(len(findings[0].context), 600)
        self.assertNotIn(token, findings[0].context)
        self.assertIn("ghp_****", findings[0].context)


# =================================================================== allowing

class AllowTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))

    def test_inline_marker_in_any_comment_style(self):
        for line in (f'token = "{github_token()}"  # awskit:allow',
                     f'token = "{github_token()}"; // awskit:allow test fixture',
                     f'<token>{github_token()}</token> <!-- AWSKIT:ALLOW -->'):
            with self.subTest(line=line):
                findings, allowed, _ = ss.scan_text(line, "x.txt")
                self.assertEqual(findings, [])
                self.assertEqual(len(allowed), 1)
                self.assertIn("awskit:allow", allowed[0].allowed)
        findings, allowed, _ = ss.scan_text("# awskit:allow\n" + private_key(), "k.pem")
        self.assertEqual((len(findings), len(allowed)), (0, 1))

    def test_allow_file_hash_path_and_pattern(self):
        token, other = github_token(), github_token()
        (self.dir / ss.ALLOW_FILE).write_text(
            "# comment\n"
            f"sha256:{ss.value_hash(token)}\n"
            "path:tests/fixtures/*.pem\npath:vendor/\npath:**/fake-keys.txt\n"
            "re:^ghp_TEST\nre:([unclosed\nbogus line\n", encoding="utf-8")
        allow = ss.AllowList.load(self.dir)
        self.assertEqual(len(allow.notes), 2)  # the bad regex and the bogus line
        found, allowed, _ = ss.scan_text(f"a = {token}\nb = {other}\n", "x.cfg", allow=allow)
        self.assertEqual([f.line for f in found], [2])
        self.assertEqual([f.line for f in allowed], [1])
        self.assertTrue(allow.path_allowed("tests/fixtures/server.pem"))
        self.assertTrue(allow.path_allowed("vendor/lib/a.py"))
        self.assertTrue(allow.path_allowed("fake-keys.txt"))
        self.assertTrue(allow.path_allowed("deep/down/fake-keys.txt"))
        self.assertFalse(allow.path_allowed("src/server.pem"))
        self.assertTrue(allow.value_allowed("ghp_TEST" + "a" * 32, "0" * 64))

    def test_add_allow_entries_keeps_lines_and_never_writes_the_value(self):
        path = self.dir / ss.ALLOW_FILE
        path.write_text("path:docs/\n", encoding="utf-8")
        token = github_token()
        findings, _, _ = ss.scan_text(f"token: {token}", "a.yml")
        where, added = ss.add_allow_entries(self.dir, findings)
        self.assertEqual((where, added), (path, 1))
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("path:docs/\n"))
        self.assertIn(f"sha256:{findings[0].value_hash}", text)
        self.assertNotIn(token, text)
        self.assertEqual(ss.add_allow_entries(self.dir, findings)[1], 0)  # no duplicates
        found, allowed, _ = ss.scan_text(f"token: {token}", "a.yml",
                                         allow=ss.AllowList.load(self.dir))
        self.assertEqual((found, len(allowed)), ([], 1))

    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_allow_file_through_a_link_is_refused(self):
        target = self.dir / "elsewhere.txt"
        target.write_text("", encoding="utf-8")
        os.symlink(target, self.dir / ss.ALLOW_FILE)
        findings, _, _ = ss.scan_text(f"token: {github_token()}", "a.yml")
        with self.assertRaises(OSError):
            ss.add_allow_entries(self.dir, findings)
        self.assertEqual(target.read_text(encoding="utf-8"), "")


# =================================================================== diff parsing

class DiffParsingTests(unittest.TestCase):
    def test_content_that_looks_like_headers_is_still_content(self):
        diff = (b"diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
                b"@@ -1,0 +2,3 @@\n+++ not a header\n+diff --git a/x b/x\n+third\n"
                b"diff --git a/g.txt b/g.txt\nnew file mode 100644\n--- /dev/null\n"
                b"+++ \"b/sp ace\\twith tab\\303\\251\"\n@@ -0,0 +1 @@\n+hello\n")
        files = list(ss.parse_diff(io.BytesIO(diff)))
        self.assertEqual([f.path for f in files], ["f.txt", "sp ace\twith tabé"])
        self.assertEqual([n for n, _ in files[0].added], [2, 3, 4])
        self.assertEqual(files[0].added[0][1], b"++ not a header")

    def test_deleted_files_and_binary_files(self):
        diff = (b"diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n"
                b"--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
                b"diff --git a/img.png b/img.png\n--- /dev/null\n+++ b/img.png\n"
                b"@@ -0,0 +1 @@\n+\x89PNG\x00\x01\n")
        files = list(ss.parse_diff(io.BytesIO(diff)))
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].binary)


# =================================================================== git scans

@needs_git
class GitScanTests(unittest.TestCase):
    def test_staged_reports_only_added_lines_with_new_line_numbers(self):
        repo = make_repo()
        old = github_token()
        write(repo, "app/config.py", f'A = 1\nOLD = "{old}"\nB = 2\nC = 3\n')
        commit_all(repo)
        new = github_token()
        write(repo, "app/config.py", f'A = 1\nOLD = "{old}"\nB = 2\nINSERTED = 1\n'
                                     f'NEW = "{new}"\nC = 3\n')
        git(repo, "add", "app/config.py")
        result = ss.scan(repo, "staged")
        self.assertEqual([(f.path, f.line, f.kind) for f in result.findings],
                         [("app/config.py", 5, "github_token")])
        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.exit_code(), 1)
        # unstaged changes don't count
        write(repo, "app/config.py", f'X = "{github_token()}"\n')
        self.assertEqual(len(ss.scan(repo, "staged").findings), 1)

    def test_staged_new_file_in_a_subfolder_and_a_scan_from_inside_it(self):
        repo = make_repo()
        write(repo, "README.md", "hi\n")
        commit_all(repo)
        write(repo, "deploy/env/prod.env", f"\n\nDB_PASSWORD={strong_password()}\n")
        git(repo, "add", "-A")
        result = ss.scan(repo / "deploy", "staged")
        self.assertEqual([(f.path, f.line) for f in result.findings],
                         [("deploy/env/prod.env", 3)])
        self.assertEqual(ss.scan(repo / "README.md", "staged").findings, [])

    def test_renames(self):
        repo = make_repo()
        write(repo, "old.cfg", f"token: {github_token()}\nx: 1\n")
        commit_all(repo)
        git(repo, "mv", "old.cfg", "new.cfg")
        self.assertEqual(ss.scan(repo, "staged").findings, [])  # nothing new was added
        with open(repo / "new.cfg", "a", encoding="utf-8") as fh:
            fh.write(f"other: {github_token()}\n")
        git(repo, "add", "-A")
        result = ss.scan(repo, "staged")
        self.assertEqual([(f.path, f.line) for f in result.findings], [("new.cfg", 3)])

    def test_unborn_repo_deleted_files_and_binary_files(self):
        repo = make_repo()
        write(repo, "a.env", f"API_TOKEN={rnd(30)}\n")
        (repo / "blob.bin").write_bytes(b"\x00\x01" + github_token().encode() + b"\x00")
        git(repo, "add", "-A")
        result = ss.scan(repo, "staged")  # no commits yet
        self.assertEqual([f.path for f in result.findings], ["a.env"])
        self.assertTrue(any("binary" in n and "blob.bin" in n for n in result.notes))
        commit_all(repo)
        git(repo, "rm", "-q", "a.env")
        self.assertEqual(ss.scan(repo, "staged").findings, [])

    def test_a_huge_staged_file_is_skipped_and_the_rest_still_checked(self):
        repo = make_repo()
        write(repo, "big.min.js", "x" * (ss.MAX_FILE * 3) + f'"{github_token()}"')
        write(repo, "small.env", f"TOKEN={rnd(32)}\n")
        git(repo, "add", "-A")
        result = ss.scan(repo, "staged")
        self.assertEqual([f.path for f in result.findings], ["small.env"])
        self.assertTrue(any("over 2 MB" in n and "big.min.js" in n for n in result.notes))

    def test_history_finds_a_key_that_was_removed(self):
        repo = make_repo()
        ak, sk = access_key(), secret_key()
        write(repo, "creds", f"[x]\naws_access_key_id = {ak}\naws_secret_access_key = {sk}\n")
        commit_all(repo, "add creds")
        first = git(repo, "rev-parse", "HEAD").stdout.strip()
        (repo / "creds").unlink()
        write(repo, "README.md", "clean now\n")
        commit_all(repo, "remove creds")
        self.assertEqual(ss.scan(repo, "all").findings, [])
        result = ss.scan(repo, "history", history=50)
        self.assertEqual(result.scanned, 2)
        self.assertEqual(sorted(f.kind for f in result.findings),
                         ["aws_access_key", "aws_secret_key"])
        for f in result.findings:
            self.assertEqual(f.commit, first)
            self.assertIs(f.still_in_files, False)
            self.assertIn("still in git history", f.note)
        self.assertEqual(len(ss.scan(repo, "history", history=1).findings), 0)

    def test_history_keeps_the_commit_that_added_it(self):
        repo = make_repo()
        token = github_token()
        write(repo, "a.txt", f"t = {token}\n")
        commit_all(repo, f"one, with {token} in the message too")
        first = git(repo, "rev-parse", "HEAD").stdout.strip()
        write(repo, "a.txt", f"t =  {token}\n")  # touched again
        commit_all(repo, "two")
        result = ss.scan(repo, "history")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].commit, first)
        self.assertEqual(result.findings[0].occurrences, 2)
        self.assertIs(result.findings[0].still_in_files, True)
        detail = result.findings[0].detail_text()
        self.assertNotIn(token, detail)
        self.assertIn("one, with ******** in the message", detail)
        self.assertIn("Added in 2 commits", detail)

    def test_staged_utf16_files_are_read(self):
        # Windows PowerShell 5 writes UTF-16 with a byte order mark for
        # aws iam create-access-key > key.json, and git shows it with NUL bytes.
        repo = make_repo()
        write(repo, "a.txt", "hi\n")
        commit_all(repo)
        ak, sk = access_key(), secret_key()
        text = ('{\r\n    "AccessKey": {\r\n        "UserName": "lab",\r\n'
                f'        "AccessKeyId": "{ak}",\r\n        "Status": "Active",\r\n'
                f'        "SecretAccessKey": "{sk}"\r\n    }}\r\n}}\r\n')
        (repo / "key.json").write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
        (repo / "key-be.json").write_bytes(b"\xfe\xff" + text.encode("utf-16-be"))
        git(repo, "add", "-A")
        result = ss.scan(repo, "staged")
        self.assertEqual(sorted((f.path, f.line, f.kind) for f in result.findings),
                         [("key-be.json", 4, "aws_access_key"),
                          ("key-be.json", 6, "aws_secret_key"),
                          ("key.json", 4, "aws_access_key"), ("key.json", 6, "aws_secret_key")])
        commit_all(repo)
        self.assertEqual(len(ss.scan(repo, "history").findings), 4)

    def test_history_subject_is_masked_before_it_is_cut_short(self):
        repo = make_repo()
        token = github_token()
        write(repo, "a.txt", f"t = {token}\n")
        commit_all(repo, "x" * 100 + " " + token)
        result = ss.scan(repo, "history")
        self.assertEqual(len(result.findings), 1)
        self.assertNotIn(token[:12], result.findings[0].detail_text())
        self.assertIn("********", result.findings[0].commit_subject)

    def test_a_partial_clone_never_fetches(self):
        # git log -p in a partial clone fetches missing files from the remote, the way the
        # repo's own config says: here a core.sshCommand that would run a program.
        src = make_repo()
        for i in range(3):
            write(src, f"f{i}.txt", f"line {i}\n")
            commit_all(src, f"c{i}")
        git(src, "config", "uploadpack.allowFilter", "true")
        clone = Path(tempfile.mkdtemp(dir=TMP)) / "clone"
        r = subprocess.run([GIT, "clone", "-q", "--filter=blob:none", "--no-checkout",
                            src.as_uri(), str(clone)], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("this git can't make a partial clone: " + r.stderr.strip())
        mark = clone.parent / "ran-ssh"
        git(clone, "config", "remote.origin.url", "ssh://example.invalid/x.git")
        git(clone, "config", "core.sshCommand", f"sh -c 'touch {mark}' --")
        with self.assertRaises(ss.ScanError) as ctx:
            ss.scan(clone, "history")
        self.assertIn("partial clone", str(ctx.exception))
        self.assertFalse(mark.exists())

    def test_all_files_includes_untracked_but_not_ignored(self):
        repo = make_repo()
        write(repo, ".gitignore", "secret.env\n")
        commit_all(repo)
        write(repo, "new.env", f"TOKEN={rnd(32)}\n")
        write(repo, "secret.env", f"TOKEN={rnd(32)}\n")
        result = ss.scan(repo, "all")
        self.assertEqual([f.path for f in result.findings], ["new.env"])

    def test_path_entries_in_the_allow_file_skip_files(self):
        repo = make_repo()
        write(repo, "tests/fixtures/key.pem", private_key())
        write(repo, "app.env", f"TOKEN={rnd(32)}\n")
        write(repo, ss.ALLOW_FILE, "path:tests/fixtures/\n")
        result = ss.scan(repo, "all")
        self.assertEqual([f.path for f in result.findings], ["app.env"])
        self.assertTrue(any("path:" in n for n in result.notes))
        git(repo, "add", "-A")
        self.assertEqual([f.path for f in ss.scan(repo, "staged").findings], ["app.env"])

    def test_default_mode(self):
        repo = make_repo()
        write(repo, "a.txt", "hello\n")
        commit_all(repo)
        self.assertEqual(ss.scan(repo).mode, "all")
        write(repo, "b.txt", "new\n")
        git(repo, "add", "b.txt")
        self.assertEqual(ss.scan(repo).mode, "staged")
        plain = Path(tempfile.mkdtemp(dir=TMP))
        self.assertEqual(ss.scan(plain).mode, "files")
        with self.assertRaises(ss.ScanError):
            ss.scan(plain, "staged")

    def test_cancel_stops_early(self):
        repo = make_repo()
        write(repo, "a.txt", "x\n")
        commit_all(repo)
        stop = threading.Event()
        stop.set()
        result = ss.scan(repo, "all", cancel=stop)
        self.assertTrue(result.cancelled)
        self.assertIn("Stopped early", result.summary())

    def test_a_malicious_repo_config_runs_nothing(self):
        repo = make_repo()
        write(repo, "a.txt", "one\n")
        commit_all(repo)
        token = github_token()
        write(repo, "a.txt", f"one\ntoken: {token}\n")
        git(repo, "add", "a.txt")
        marks = Path(tempfile.mkdtemp(dir=TMP))
        scripts = {}
        for name in ("fsmonitor", "external", "textconv", "pager", "gpg", "filter"):
            p = marks / f"evil-{name}"
            p.write_text(f"#!/bin/sh\ntouch '{marks}/ran-{name}'\nexit 0\n",
                         encoding="utf-8")
            p.chmod(0o755)
            scripts[name] = str(p)
        for key, value in (("core.fsmonitor", scripts["fsmonitor"]),
                           ("diff.external", scripts["external"]),
                           ("diff.evil.textconv", scripts["textconv"]),
                           ("core.pager", scripts["pager"]),
                           ("pager.diff", scripts["pager"]), ("pager.log", scripts["pager"]),
                           ("log.showSignature", "true"), ("gpg.program", scripts["gpg"]),
                           ("filter.evil.clean", scripts["filter"]),
                           ("filter.evil.smudge", scripts["filter"]),
                           ("diff.noprefix", "true"), ("color.ui", "always"),
                           ("color.diff", "always"), ("log.showRoot", "false")):
            git(repo, "config", key, value)
        write(repo, ".gitattributes", "* diff=evil filter=evil\n")

        staged = ss.scan(repo, "staged")
        self.assertEqual([(f.path, f.line) for f in staged.findings], [("a.txt", 2)])
        ss.scan(repo, "all")
        history = ss.scan(repo, "history")
        ss.hook_status(repo)
        ss.install_hook(repo)
        ss.remove_hook(repo)
        run_cli(str(repo), "--json")
        self.assertEqual(sorted(p.name for p in marks.glob("ran-*")), [])
        self.assertEqual(history.scanned, 1)

        # The settings above are live: plain git commands do run them. (The pager needs a
        # terminal and gpg a signed commit, so those two can't be shown firing here.)
        for args in (["status"], ["diff", "HEAD"], ["diff", "--no-ext-diff", "HEAD"]):
            subprocess.run([GIT, "-C", str(repo), *args], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        fired = {p.name for p in marks.glob("ran-*")}
        self.assertTrue({"ran-fsmonitor", "ran-external", "ran-textconv"} <= fired, fired)

    def test_git_is_never_taken_from_the_current_folder(self):
        real = ss.find_git()
        folder = Path(tempfile.mkdtemp(dir=TMP))
        fake = folder / ("git.exe" if os.name == "nt" else "git")
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        old_cwd, old_path = os.getcwd(), os.environ["PATH"]
        try:
            os.chdir(folder)
            os.environ["PATH"] = os.pathsep.join([".", "", old_path])
            self.assertEqual(ss.find_git(), real)
        finally:
            os.chdir(old_cwd)
            os.environ["PATH"] = old_path


@needs_git
class FolderScanTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_plain_folder_skips_links_git_dirs_vendor_and_big_files(self):
        outside = Path(tempfile.mkdtemp(dir=TMP))
        write(outside, "leak.env", f"TOKEN={rnd(32)}\n")
        folder = Path(tempfile.mkdtemp(dir=TMP))
        write(folder, "real.env", f"TOKEN={rnd(32)}\n")
        os.symlink(outside / "leak.env", folder / "link.env")
        os.symlink(outside, folder / "linkdir")
        write(folder, ".git/config", f"token = {github_token()}\n")
        write(folder, "node_modules/pkg/index.js", f'token = "{github_token()}"\n')
        write(folder, "big.json", "x" * (ss.MAX_FILE + 10))
        (folder / "pic.png").write_bytes(b"\x89PNG\x00\x00" + github_token().encode())
        result = ss.scan(folder, "files")
        self.assertEqual([f.path for f in result.findings], ["real.env"])
        notes = " ".join(result.notes)
        self.assertIn("over 2 MB", notes)
        self.assertIn("binary", notes)

    def test_single_file(self):
        folder = Path(tempfile.mkdtemp(dir=TMP))
        p = write(folder, "one.env", f"TOKEN={rnd(32)}\n")
        write(folder, "two.env", f"TOKEN={rnd(32)}\n")
        result = ss.scan(p, "files")
        self.assertEqual([f.path for f in result.findings], ["one.env"])


# =================================================================== the hook

@needs_git
class HookTests(unittest.TestCase):
    def test_install_status_remove(self):
        repo = make_repo()
        self.assertEqual(ss.hook_status(repo)["state"], "off")
        msg = ss.install_hook(repo)
        hook = repo / ".git" / "hooks" / "pre-commit"
        self.assertIn(str(hook), msg)
        self.assertEqual(ss.hook_status(repo)["state"], "on")
        text = hook.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn(ss.HOOK_MARKER, text)
        self.assertIn("command -v awskit", text)
        self.assertIn("secrets --staged --hook", text)
        self.assertNotIn("\r", text)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(hook.stat().st_mode), 0o755)
        ss.install_hook(repo)  # installing again just rewrites ours
        self.assertIn("Removed", ss.remove_hook(repo))
        self.assertFalse(hook.exists())
        self.assertIn("No commit hook", ss.remove_hook(repo))
        self.assertEqual(ss.hook_status(Path(tempfile.mkdtemp(dir=TMP)))["state"], "not_git")

    def test_someone_elses_hook_is_kept_and_can_be_chained(self):
        repo = make_repo()
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        hook.chmod(0o755)
        self.assertEqual(ss.hook_status(repo)["state"], "other")
        with self.assertRaises(ss.HookError):
            ss.install_hook(repo)
        self.assertEqual(hook.read_text(encoding="utf-8"), "#!/bin/sh\necho mine\n")
        ss.install_hook(repo, chain=True)
        self.assertEqual((hook.parent / ss.CHAINED_HOOK).read_text(encoding="utf-8"),
                         "#!/bin/sh\necho mine\n")
        status = ss.hook_status(repo)
        self.assertEqual((status["state"], status["chained"]), ("on", True))
        self.assertIn("put your old one back", ss.remove_hook(repo))
        self.assertEqual(hook.read_text(encoding="utf-8"), "#!/bin/sh\necho mine\n")
        self.assertFalse((hook.parent / ss.CHAINED_HOOK).exists())
        # never removes a hook that isn't ours
        with self.assertRaises(ss.HookError):
            ss.remove_hook(repo)

    def test_core_hooks_path_is_respected(self):
        repo = make_repo()
        git(repo, "config", "core.hooksPath", ".githooks")
        ss.install_hook(repo)
        self.assertTrue((repo / ".githooks" / "pre-commit").exists())
        self.assertFalse((repo / ".git" / "hooks" / "pre-commit").exists())
        self.assertEqual(ss.hook_status(repo)["state"], "on")

    def test_a_hooks_path_outside_the_repo_is_left_alone(self):
        repo = make_repo()
        shared = Path(tempfile.mkdtemp(dir=TMP))
        (shared / "pre-commit").write_text("#!/bin/sh\necho a tool\n", encoding="utf-8")
        git(repo, "config", "core.hooksPath", str(shared))
        for chain in (False, True):
            with self.assertRaises(ss.HookError) as ctx:
                ss.install_hook(repo, chain=chain)
            self.assertIn("outside this repo", str(ctx.exception))
        self.assertEqual(sorted(p.name for p in shared.iterdir()), ["pre-commit"])
        self.assertEqual((shared / "pre-commit").read_text(encoding="utf-8"),
                         "#!/bin/sh\necho a tool\n")

    def _bin_with_awskit(self):
        folder = Path(tempfile.mkdtemp(dir=TMP))
        exe = folder / "awskit"
        exe.write_text(f"#!/bin/sh\nPYTHONPATH='{ROOT}' exec '{sys.executable}' -m awskit "
                       '"$@"\n', encoding="utf-8")
        exe.chmod(0o755)
        return folder

    def _commit(self, repo, path_dirs, home=None):
        env = dict(os.environ, PATH=os.pathsep.join(path_dirs))
        if home:
            env["HOME"] = home
        return subprocess.run([GIT, "-C", str(repo), "commit", "-q", "-m", "test"], env=env,
                              capture_output=True, text=True, timeout=120)

    @needs_sh
    def test_the_hook_stops_a_real_commit(self):
        repo = make_repo()
        write(repo, "a.txt", "hello\n")
        commit_all(repo)
        ss.install_hook(repo)
        token = github_token()
        write(repo, "app.py", f'TOKEN = "{token}"\n')
        git(repo, "add", "app.py")
        dirs = [str(self._bin_with_awskit()), os.path.dirname(GIT), "/usr/bin", "/bin"]
        r = self._commit(repo, dirs)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("app.py:1", r.stderr)
        self.assertIn("GitHub token", r.stderr)
        self.assertIn("--no-verify", r.stderr)
        self.assertNotIn(token, r.stderr + r.stdout)
        # a false positive, allowed in the file, goes through
        write(repo, "app.py", f'TOKEN = "{token}"  # awskit:allow\n')
        git(repo, "add", "app.py")
        r = self._commit(repo, dirs)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr.strip(), "")

    @needs_sh
    def test_a_chained_hook_runs_first_and_can_stop_the_commit(self):
        repo = make_repo()
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho old hook says no >&2\nexit 3\n", encoding="utf-8")
        hook.chmod(0o755)
        ss.install_hook(repo, chain=True)
        write(repo, "a.txt", "clean\n")
        git(repo, "add", "a.txt")
        dirs = [str(self._bin_with_awskit()), os.path.dirname(GIT), "/usr/bin", "/bin"]
        r = self._commit(repo, dirs)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("old hook says no", r.stderr)

    @needs_sh
    def test_the_hook_never_runs_an_awskit_the_repo_ships(self):
        # An empty entry in PATH (like a trailing :) means the current folder, which is
        # the top of the repo while the hook runs.
        repo = make_repo()
        mark = Path(tempfile.mkdtemp(dir=TMP)) / "ran"
        fake = write(repo, "awskit", f"#!/bin/sh\ntouch '{mark}'\nexit 0\n")
        fake.chmod(0o755)
        ss.install_hook(repo)
        write(repo, "a.txt", "clean\n")
        git(repo, "add", "a.txt")
        empty_home = tempfile.mkdtemp(dir=TMP)
        r = self._commit(repo, [os.path.dirname(GIT), "/usr/bin", "/bin", ""], home=empty_home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("awskit isn't on PATH", r.stderr)
        self.assertFalse(mark.exists())

    def test_the_hook_says_which_files_it_couldnt_check(self):
        repo = make_repo()
        write(repo, "a.txt", "hi\n")
        commit_all(repo)
        (repo / "blob.bin").write_bytes(b"\x00\x01" + github_token().encode() + b"\x00")
        git(repo, "add", "-A")
        rc, out, err = run_cli(str(repo), "--hook")
        self.assertEqual((rc, out), (0, ""))
        self.assertIn("Not checked", err)
        self.assertIn("blob.bin", err)

    @unittest.skipIf(os.name == "nt", "no FIFOs on Windows")
    def test_a_fifo_in_place_of_the_hook_doesnt_hang(self):
        repo = make_repo()
        hooks = repo / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        os.mkfifo(hooks / "pre-commit")
        box = {}
        t = threading.Thread(target=lambda: box.update(s=ss.hook_status(repo)), daemon=True)
        t.start()
        t.join(30)
        self.assertFalse(t.is_alive(), "hook_status is stuck opening the FIFO")
        self.assertEqual(box["s"]["state"], "other")

    @needs_sh
    def test_without_awskit_the_commit_goes_through_with_a_warning(self):
        repo = make_repo()
        ss.install_hook(repo)
        write(repo, "app.py", f'TOKEN = "{github_token()}"\n')
        git(repo, "add", "app.py")
        empty_home = tempfile.mkdtemp(dir=TMP)
        r = self._commit(repo, [os.path.dirname(GIT), "/usr/bin", "/bin"], home=empty_home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("awskit isn't on PATH", r.stderr)


# =================================================================== command line

@needs_git
class CliTests(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()
        write(self.repo, "README.md", "AKIAIOSFODNN7EXAMPLE is AWS's own example\n")
        commit_all(self.repo)
        self.ak, self.sk, self.pw = access_key(), secret_key(), strong_password()
        self.token = github_token()
        self.raw = [self.ak, self.sk, self.pw, self.token]

    def stage_secrets(self):
        write(self.repo, ".env", f"AWS_ACCESS_KEY_ID={self.ak}\n"
                                 f"AWS_SECRET_ACCESS_KEY={self.sk}\nDB_PASSWORD={self.pw}\n")
        write(self.repo, "src/app.py", f'GITHUB = "{self.token}"\n'
                                       'HOST = "10.20.30.40"\n')
        git(self.repo, "add", "-A")

    def assertNoSecrets(self, text):
        for raw in self.raw:
            self.assertNotIn(raw, text)

    def test_exit_codes(self):
        rc, out, _ = run_cli(str(self.repo))
        self.assertEqual(rc, 0)
        self.assertIn("nothing found", out)
        write(self.repo, "hosts.txt", 'host = "10.20.30.40"\n')
        git(self.repo, "add", "hosts.txt")
        rc, out, _ = run_cli(str(self.repo), "--staged")
        self.assertEqual(rc, 0)  # a warning doesn't fail
        self.assertIn("1 warning", out)
        self.stage_secrets()
        rc, out, _ = run_cli(str(self.repo))
        self.assertEqual(rc, 1)
        self.assertIn("staged file", out)
        self.assertNoSecrets(out)
        plain = tempfile.mkdtemp(dir=TMP)
        rc, _, err = run_cli(plain, "--staged")
        self.assertEqual(rc, 2)
        self.assertIn("isn't in a git repo", err)
        rc, _, err = run_cli(os.path.join(plain, "missing"))
        self.assertEqual(rc, 2)

    def test_no_output_ever_holds_a_secret(self):
        self.stage_secrets()
        outputs = []
        for args in ([], ["-v"], ["--json"], ["--all", "-v"], ["--files", "-v"],
                     ["--hook"], ["--all", "--json"]):
            rc, out, err = run_cli(str(self.repo), *args)
            self.assertEqual(rc, 1, args)
            outputs += [out, err]
        md = Path(TMP) / "report.md"
        run_cli(str(self.repo), "--all", "--markdown", str(md))
        outputs.append(md.read_text(encoding="utf-8"))
        result = ss.scan(self.repo, "all")
        for f in result.findings:
            outputs += [f.detail_text(), f.context, json.dumps(f.as_dict()), str(f.row())]
        for text in outputs:
            self.assertNoSecrets(text)
        data = json.loads(run_cli(str(self.repo), "--json")[1])
        self.assertEqual(data["counts"]["block"], 4)
        self.assertNotIn("value_hash", json.dumps(data))
        kinds_found = {f["kind"] for f in data["findings"]}
        self.assertTrue({"aws_access_key", "aws_secret_key", "password",
                         "github_token"} <= kinds_found)

    def test_hook_output_is_short_and_says_how_to_fix(self):
        self.stage_secrets()
        rc, out, err = run_cli(str(self.repo), "--hook")
        self.assertEqual((rc, out), (1, ""))
        for words in ("stopped this commit", ".env:1", "src/app.py:1", "How to fix",
                      "rotate it", "awskit:allow", "--no-verify", "Warnings (1)"):
            self.assertIn(words, err)
        git(self.repo, "reset", "-q")
        rc, out, err = run_cli(str(self.repo), "--hook")
        self.assertEqual((rc, out, err), (0, "", ""))

    def test_allow_from_the_command_line(self):
        write(self.repo, "src/app.py", f'GITHUB = "{self.token}"\n')
        git(self.repo, "add", "-A")
        self.assertEqual(run_cli(str(self.repo))[0], 1)
        rc, out, _ = run_cli("--allow", str(self.repo / "src" / "app.py") + ":1")
        self.assertEqual(rc, 0, out)
        self.assertIn("Added 1 line", out)
        allow_text = (self.repo / ss.ALLOW_FILE).read_text(encoding="utf-8")
        self.assertNoSecrets(allow_text)
        self.assertEqual(run_cli(str(self.repo))[0], 0)
        rc, _, err = run_cli("--allow", str(self.repo / "src" / "app.py") + ":9")
        self.assertEqual(rc, 2)
        rc, _, err = run_cli("--allow", "no-line-number")
        self.assertEqual(rc, 2)

    def test_history_flag_takes_a_number_or_the_folder(self):
        write(self.repo, "creds.txt", f"key {self.ak}\n")
        commit_all(self.repo)
        (self.repo / "creds.txt").unlink()
        commit_all(self.repo)
        rc, out, _ = run_cli("--history", str(self.repo))
        self.assertEqual(rc, 1)
        self.assertIn("3 commits", out)
        rc, out, _ = run_cli(str(self.repo), "--history", "1")
        self.assertEqual(rc, 0)
        self.assertIn("1 commit,", out)

    def test_install_and_remove_hook(self):
        rc, out, _ = run_cli(str(self.repo), "--install-hook")
        self.assertEqual(rc, 0)
        self.assertIn("Installed", out)
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho theirs\n", encoding="utf-8")
        rc, _, err = run_cli(str(self.repo), "--install-hook")
        self.assertEqual(rc, 2)
        self.assertIn("--chain", err)
        rc, out, _ = run_cli(str(self.repo), "--install-hook", "--chain")
        self.assertEqual(rc, 0)
        rc, out, _ = run_cli(str(self.repo), "--remove-hook")
        self.assertEqual(rc, 0)
        self.assertEqual(hook.read_text(encoding="utf-8"), "#!/bin/sh\necho theirs\n")

    def test_block_account_ids_flag_and_setting(self):
        account = str(RNG.randint(2 * 10 ** 11, 9 * 10 ** 11))
        write(self.repo, "main.tf", f'principal = "arn:aws:iam::{account}:root"\n')
        git(self.repo, "add", "-A")
        self.assertEqual(run_cli(str(self.repo))[0], 0)
        self.assertEqual(run_cli(str(self.repo), "--block-account-ids")[0], 1)
        ss.save_settings({"block_account_ids": True})
        try:
            self.assertEqual(run_cli(str(self.repo))[0], 1)
        finally:
            ss.save_settings({"block_account_ids": False})


class SettingsTests(unittest.TestCase):
    def test_settings_live_under_their_own_key_and_keep_the_rest(self):
        cfg = common.load_config()
        cfg["keep"] = ["i-0abc"]
        common.save_config(cfg)
        raw = json.loads(common.CONFIG_FILE.read_text(encoding="utf-8"))
        raw["another_tool"] = {"x": 1}
        common.CONFIG_FILE.write_text(json.dumps(raw), encoding="utf-8")
        self.assertTrue(ss.save_settings({"folder": "/tmp/x", "mode": "history",
                                          "history_commits": 50, "nonsense": 1}))
        raw = json.loads(common.CONFIG_FILE.read_text(encoding="utf-8"))
        self.assertEqual(raw["keep"], ["i-0abc"])
        self.assertEqual(raw["another_tool"], {"x": 1})
        self.assertNotIn("nonsense", raw[ss.CONFIG_KEY])
        loaded = ss.load_settings()
        self.assertEqual((loaded["folder"], loaded["mode"], loaded["history_commits"]),
                         ("/tmp/x", "history", 50))
        raw[ss.CONFIG_KEY] = {"mode": "sideways", "history_commits": True,
                              "block_account_ids": "yes"}
        common.CONFIG_FILE.write_text(json.dumps(raw), encoding="utf-8")
        self.assertEqual(ss.load_settings(), dict(ss.DEFAULT_SETTINGS, folder=""))
        ss.save_settings(dict(ss.DEFAULT_SETTINGS))


# =================================================================== the window's page

try:
    import gi
    gi.require_version("Gtk", "4.0")
    from awskit import secrets_page
except (ImportError, ValueError):  # pragma: no cover
    secrets_page = None


class _Sensitive:
    def __init__(self):
        self.sensitive = True

    def set_sensitive(self, value):
        self.sensitive = value


@unittest.skipIf(secrets_page is None, "GTK 4 not installed")
class SecretsPageTests(unittest.TestCase):
    """The page's methods on a stand-in, so no display is needed."""

    class Page:
        def __init__(self, folder):
            P = secrets_page.SecretsPage
            for name in ("run", "done", "failed", "set_folder", "show_folder", "current_mode",
                         "apply_block_ids", "hook_job"):
                setattr(self, name, getattr(P, name).__get__(self))
            self.folder, self.result, self.hook = folder, None, {"state": "on"}
            self.scanning, self._scan_gen = False, 0
            self.cancel = threading.Event()
            self.scan_btn = _Sensitive()
            self.mode = mock.Mock()
            self.mode.get_selected.return_value = secrets_page.MODE_KEYS.index("files")
            self.depth = mock.Mock()
            self.depth.get_value.return_value = 200
            self.block_ids = mock.Mock()
            self.block_ids.get_active.return_value = False
            for name in ("allow_btn", "hook_btn", "status", "folder_label", "table", "detail",
                         "save", "show_counts", "refresh_hook", "fill_table"):
                setattr(self, name, mock.Mock())

        def new_cancel(self):
            self.cancel = threading.Event()
            return self.cancel

    @staticmethod
    def result(root, *findings):
        return ss.ScanResult(mode="files", root=root, target=root, findings=list(findings))

    def test_picking_another_folder_drops_the_running_scan(self):
        # Picking a folder mid-scan used to turn Scan back on, so two scans ran at once and
        # the old folder's findings could land under the new folder.
        page = self.Page("/tmp/repo-a")
        with mock.patch.object(secrets_page, "run_bg") as run_bg:
            page.run()
            self.assertFalse(page.scan_btn.sensitive)
            first_cancel = page.cancel
            _, done_a, failed_a = run_bg.call_args.args
            page.set_folder("/tmp/repo-b", check_mode=False)
            self.assertTrue(first_cancel.is_set())
            self.assertTrue(page.scan_btn.sensitive)
            page.run()
            page.run()  # a second press while repo-b's scan runs does nothing
            self.assertEqual(run_bg.call_count, 2)
            self.assertFalse(page.scan_btn.sensitive)
            _, done_b, _ = run_bg.call_args.args
        done_a(self.result("/tmp/repo-a"))   # repo-a's scan finishing late
        failed_a(ss.ScanError("stopped"))
        self.assertIsNone(page.result)
        self.assertTrue(page.scanning)
        self.assertFalse(page.scan_btn.sensitive)
        done_b(self.result("/tmp/repo-b"))
        self.assertEqual(page.result.root, "/tmp/repo-b")
        self.assertFalse(page.scanning)
        self.assertTrue(page.scan_btn.sensitive)

    def test_account_ids_follow_the_box_ticked_during_a_scan(self):
        page = self.Page("/tmp/repo-a")
        with mock.patch.object(secrets_page, "run_bg") as run_bg:
            page.run()   # started with the box off
        page.block_ids.get_active.return_value = True   # ticked while it runs
        acct = ss.Finding("warn", "account_id", "AWS account ID", "main.tf", 3, 1, "1111****2222")
        run_bg.call_args.args[1](self.result("/tmp/repo-a", acct))
        self.assertEqual(page.result.findings[0].level, "block")

    def test_a_hook_change_during_a_scan_keeps_stop_working(self):
        page = self.Page("/tmp/repo-a")
        with mock.patch.object(secrets_page, "run_bg") as run_bg:
            page.run()
            page.status.reset_mock()
            page.hook_job(lambda: "Installed the commit hook.")
            hook_done = run_bg.call_args.args[1]
        with mock.patch.object(secrets_page.secretscan, "find_awskit_on_path", return_value=True):
            hook_done("Installed the commit hook.")
        page.status.idle.assert_not_called()  # idle hides Stop while the scan still runs
        page.detail.set_text.assert_called_with("Installed the commit hook.")


if __name__ == "__main__":
    unittest.main()
