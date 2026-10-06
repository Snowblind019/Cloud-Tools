"""Make a throwaway git repo with fake leaks in it, to try Secrets Scan on.

    python3 secrets-scan/examples/make_demo_repo.py            # in a new temp folder
    python3 secrets-scan/examples/make_demo_repo.py ~/demo     # or a folder you name

Every key, token and password is made up at run time from random characters, so this
file holds no secrets itself (and doesn't trip GitHub's push protection or the scanner).
None of them work anywhere. The repo gets:

- two commits, where the second one deletes a credentials file the first one added (so it's
  only in git history),
- tracked files with a GitHub token, a database password, an account ID and internal IPs,
- a staged .env with an AWS access key pair and a private key, ready for a commit that the
  hook would stop,
- a README with AWS's own documentation keys, which are allowed on their own.
"""
from __future__ import annotations

import random
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path

RNG = random.Random(2026)
B32 = string.ascii_uppercase + "234567"
ALNUM = string.ascii_letters + string.digits


def rnd(n, chars=ALNUM):
    return "".join(RNG.choice(chars) for _ in range(n))


def git(repo, *args):
    exe = shutil.which("git")
    if not exe:
        sys.exit("git isn't installed.")
    subprocess.run([exe, "-C", str(repo), *args], check=True, stdout=subprocess.DEVNULL)


def write(repo, name, text):
    path = Path(repo) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv):
    repo = Path(argv[0]).expanduser() if argv else Path(tempfile.mkdtemp(prefix="leaky-lab-"))
    if repo.exists() and any(repo.iterdir()):
        sys.exit(f"{repo} isn't empty. Pick a new folder.")
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Demo User")
    git(repo, "config", "user.email", "demo@example.com")

    old_key, old_secret = "AKIA" + rnd(16, B32), rnd(40, ALNUM + "/+")
    write(repo, "README.md",
          "# Leaky lab\n\nA demo repo for AWS Kit's Secrets Scan.\n\n"
          "AWS's own example keys are fine to keep in docs:\n\n"
          "    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
          "    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
    write(repo, "scripts/credentials",
          f"[lab]\naws_access_key_id = {old_key}\naws_secret_access_key = {old_secret}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "Lab setup")

    (repo / "scripts" / "credentials").unlink()
    account = str(RNG.randint(2 * 10 ** 11, 9 * 10 ** 11))
    write(repo, "terraform/main.tf",
          'resource "aws_db_instance" "lab" {\n'
          '  engine         = "postgres"\n'
          '  username       = "labadmin"\n'
          f'  password       = "{rnd(6)}-{rnd(5)}-{rnd(4)}"\n'
          "  instance_class = \"db.t4g.micro\"\n}\n\n"
          'resource "aws_iam_role" "deploy" {\n'
          '  name               = "lab-deploy"\n'
          "  assume_role_policy = jsonencode({\n"
          '    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",\n'
          f'      Principal = {{ AWS = "arn:aws:iam::{account}:root" }} }}]\n'
          "  })\n}\n\n"
          'output "bastion" {\n  value = "10.20.4.17"\n}\n')
    write(repo, "app/config.py",
          "import os\n\n"
          'DB_HOST = os.environ.get("DB_HOST", "10.20.8.33")\n'
          'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
          f'GITHUB_TOKEN = "ghp_{rnd(36)}"\n'
          'SLACK_WEBHOOK = "https://hooks.slack.com/services/T' + rnd(9, B32) + "/B"
          + rnd(9, B32) + "/" + rnd(24) + '"\n')
    write(repo, "tests/test_login.py",
          'def test_login(client):\n'
          f'    assert client.login("demo", password="Lab{rnd(6)}!")\n')
    write(repo, "docker-compose.yml",
          "services:\n  db:\n    image: postgres:16\n    environment:\n"
          "      - POSTGRES_PASSWORD=postgres\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "Terraform for the lab database")

    key_lines = "\n".join(rnd(64, ALNUM + "+/") for _ in range(6))
    write(repo, ".env",
          f"AWS_ACCESS_KEY_ID={'AKIA' + rnd(16, B32)}\n"
          f"AWS_SECRET_ACCESS_KEY={rnd(40, ALNUM + '/+')}\n"
          "AWS_REGION=us-west-2\n")
    write(repo, "deploy/lab-key.pem",
          f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_lines}\n-----END OPENSSH PRIVATE KEY-----\n")
    git(repo, "add", ".env", "deploy/lab-key.pem")
    print(repo)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
