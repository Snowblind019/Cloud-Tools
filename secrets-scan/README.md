# Secrets Scan

Finds AWS keys, tokens, private keys and passwords in a git repo before they get committed, and adds a git pre-commit hook that stops a commit with one in it. It uses the same patterns as [PII Redact](../pii-redact/), plus a few developer tokens, and sorts what it finds into things that should stop a commit and things that are only worth a look. It can check what's staged, every file, or past commits, and it never shows a whole secret.

![Secrets Scan with an AWS secret access key selected, the key masked in the lines around it](docs/screenshot.png)

Part of [AWS Kit](../awskit/). The screenshot uses test data.

## Why I made it

PII Redact already knows what an access key, a session token or a password setting looks like, so the same patterns could stop one from landing in a commit in the first place. In lab and Terraform repos, the easy mistake is a terraform.tfvars, a .env or a quick test script with a key pasted in. Catching it at commit time is a two-second fix. Catching it after a push means rotating the key.

## What it costs

Nothing. It reads files and git on your machine. There are no AWS calls and no network calls, so it needs no credentials and no IAM permissions.

## What it finds

Each finding has a level. **Block** findings stop the commit hook and make the command exit with 1. **Warn** findings are shown, but don't stop anything.

| What | Level | Notes |
|---|---|---|
| AWS access key ID (`AKIA...`, `ASIA...`) | block | Alone or with its secret key. When both are there, each points at the other. |
| AWS secret access key | block | A 40-character key in a setting named like one, near an access key ID, or on a line that mentions AWS or secrets. A random 40-character string with none of that around it is a warning. |
| AWS session token | block | Including the `X-Amz-Security-Token` in a presigned URL |
| Amazon Bedrock API key | block | Long-term keys (`ABSK...`) and short-term ones (`bedrock-api-key-...`), the value of `AWS_BEARER_TOKEN_BEDROCK` |
| Signed URL signature | warn | A presigned S3 or CloudFront URL, which works until it expires |
| Private key | block | PEM, OpenSSH and PuTTY keys, keys written inside JSON strings (like a service account file), keys flattened onto one line, and base64-encoded keys (like kubeconfig's `client-key-data`). Certificates and public keys aren't flagged. |
| GitHub token | block | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` |
| Slack token and webhook URL | block | `xoxb-`, `xoxp-` and the others, and `hooks.slack.com` URLs |
| GitLab, npm, PyPI, OpenAI, Anthropic and Terraform Cloud tokens, Stripe live keys | block | |
| Google API key, Stripe test key, JWT | warn | Often meant to be public, or test values |
| Password | block | A real-looking value for a setting named password, passwd, pwd, pass or passphrase (`DB_PASSWORD=...`, `"password": "..."`, `<password>` in XML, `--password`, `mysql -p`) |
| Password in a URL | block | `postgres://user:password@host` |
| Secret, token or API key in a setting | block | `client_secret`, `API_TOKEN`, `x-api-key` and similar, when the value looks random |
| Authorization header | block | `Authorization: Bearer ...` and `Basic ...` with a real-looking value |
| AWS account ID | warn | Only with something AWS-like on the line, like an ARN. **Also block account IDs** makes it a block. |
| Internal IP address | warn | Private addresses like `10.20.1.25`. CIDR blocks, gateways (`.1`) and documentation ranges are left alone. |
| Email address | warn | Not in files that are meant to have them (LICENSE, AUTHORS, package files), and not example.com or noreply addresses |

### What it leaves alone

A security tool that cries wolf gets turned off, so a lot of the work is in what isn't a secret:

- **AWS's documentation examples:** `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, any other AWS key or token with `EXAMPLE` in it (AWS's docs mark made-up values that way), and the account IDs `123456789012`, repeated digits like `111111111111` and `111122223333`. The summary says how many it skipped.
- **Placeholders:** `changeme`, `REPLACE_ME`, `<your-key>`, `xxxx`, `example`, `your-api-key-here`, empty values and values that are all stars.
- **References instead of values:** `${VAR}`, `$VAR`, `{{ vault_pw }}`, `${{ secrets.X }}`, `os.environ["X"]`, Terraform's `var.x` and `random_password.db.result`, environment variable names like `DB_PASSWORD`, CloudFormation's `{{resolve:...}}`, Ansible vault and SOPS values, and password hashes.
- **Code:** in code files (Python, JavaScript, Go, Terraform and so on) only quoted strings count, so `password=args.password` is a variable, not a password. In `.env`, YAML, INI and shell files, an unquoted value is the value.
- **Words that aren't values:** `"password": "Password"` in a translation file, `secret_name: prod/db/creds`, names written in CamelCase like `"input_token": "NextToken"`, anything with spaces in it where a token should be, CSS classes like `sk-fading-circle`, and AWS's own made-up values marked `EXAMPLE`.

Some things get a warning instead of a block:

- Default and test passwords like `postgres`, `admin123` or `P@ssw0rd`, and URLs with a password that point at `localhost` or a container like `db`.
- A UUID in a token or secret setting, which is usually an ID (a request or a client token), though some services use them as keys.
- Passwords and secret settings in test files (`tests/`, `test_*.py`, `*.spec.ts` and so on), docs (`.md` files, `docs/`, `examples/`) and example files (`.env.example`, `config.sample.yml`, `settings.php.dist`). Keys and tokens in a known format still block there.

## What it scans

| Mode | What it reads |
|---|---|
| **Staged changes** (`--staged`) | Only the lines being added in the next commit, from `git diff --cached`. Line numbers are the ones in the new file. Renamed files only count their new lines, deleted files are skipped. |
| **All files** (`--all`) | Every file git tracks, plus new files that `.gitignore` doesn't ignore |
| **Git history** (`--history N`) | The lines added in each of the last N commits (200 by default), with the commit that added them. A key that was committed and deleted later is still in history, so it shows up here, marked "Removed from the files later, but still in git history". |
| **Folder, not git** (`--files`) | Every file under a folder, git or not. It skips `.git`, `node_modules`, `.terraform`, `.venv`, `venv` and cache folders. |

Every mode skips binary files, files over 2 MB, and links (it never follows one out of the folder). Files you list with `path:` in the allow file are skipped too.

Choosing a subfolder or a file inside a repo limits the scan to that part of it.

## Using it in the window

1. Press **Folder** and pick a repo or folder. It remembers the last one.
2. Pick **What to scan**. For **Git history**, set how many commits to read.
3. Press **Scan**. The counts at the top show how many findings need fixing and how many are warnings.
4. Click a finding to see the lines around it, with every secret in them masked, and how to fix it. **Copy** copies that text, masks included.
5. If it's a false positive, press **Allow this**. It adds the value's sha256 (never the value) to `.awskit-secrets-allow` at the top of the repo, and the finding goes away along with every other copy of the same value. Commit that file so the hook and CI skip it too.
6. **Install commit hook** adds the hook to the repo. The label next to it says whether it's on, off, or whether another tool's hook is already there.
7. **Also block account IDs** makes account IDs stop commits too. It's saved, so the hook and the terminal do the same.
8. **Export** saves the findings as Markdown, CSV or JSON, with the values masked.

## Using it in the terminal

```bash
awskit secrets                          # staged changes, or every file if nothing is staged
awskit secrets --all ~/aws-platform     # every file in a repo
awskit secrets ~/aws-platform --history 50
awskit secrets --history ~/aws-platform # last 200 commits
awskit secrets --files ~/Downloads/lab  # a folder that isn't a git repo
awskit secrets --all -v                 # with the lines around each finding and how to fix it
awskit secrets --all --json > secrets.json
awskit secrets --all --markdown secrets.md
awskit secrets --install-hook           # check every commit in this repo from now on
awskit secrets --allow app/config.py:12 # a false positive, added to the allow file
```

With no mode, it checks the staged changes when there are some, every file in a git repo otherwise, and the plain folder when it isn't a git repo.

```text
Level  File                   What                   Preview
BLOCK  .env:1                 AWS access key ID      AKIA************O6VV
BLOCK  .env:2                 AWS secret access key  SO9G****************XnBd
BLOCK  deploy/lab-key.pem:1   Private key            OPENSSH PRIVATE KEY
WARN   terraform/main.tf:12   AWS account ID         8877****0290

Scanned 3 staged files, 3 to fix, 1 warning.
```

| Option | What it does |
|---|---|
| `PATH` | Folder or file to scan. Default: the current folder. |
| `--staged` | Staged changes only |
| `--all` | Every tracked file, plus new files git doesn't ignore |
| `--history [N]` | Lines added in the last N commits. Default 200. |
| `--files` | A plain folder or file, git or not |
| `--json` | Print JSON. Values are masked, and the sha256 of a value is never printed. |
| `--markdown FILE` | Write a Markdown report with how to fix each finding |
| `-v`, `--verbose` | Show the lines around each finding (masked) and how to fix it |
| `-q`, `--quiet` | Only print the summary line |
| `--block-account-ids` | Treat AWS account IDs as something to fix for this run |
| `--install-hook` | Add the commit hook. Add `--chain` to keep an existing hook and run it first. |
| `--remove-hook` | Remove the commit hook |
| `--allow FILE:LINE` | Add the finding at that line to `.awskit-secrets-allow`. Repeatable. |
| `--hook` | The short output the commit hook uses |

Exit codes: **0** when nothing needs fixing (warnings don't count), **1** when something does, and **2** when it couldn't scan, like a folder that isn't a git repo with `--staged`. A hook or a CI job stops on anything but 0.

## The commit hook

```bash
cd ~/aws-platform
awskit secrets --install-hook
```

This writes a small `pre-commit` script into the repo's hooks folder (`.git/hooks`, or wherever `core.hooksPath` points). Before each commit, it runs `awskit secrets --staged --hook` from the top of the repo, which checks only the lines being committed. If one of them blocks, the commit stops and you see:

```text
AWS Kit stopped this commit: it adds something that looks like a secret.

  .env:2  AWS secret access key: SO9G****************XnBd (40 characters)

How to fix it:
  - Take it out of the file, then git add the file again.
  - Keep secrets in environment variables, a .env file listed in .gitignore,
    or AWS Secrets Manager or SSM Parameter Store.
  - If a key was ever pushed or shared, rotate it. Deleting the line doesn't
    take it back.

Not a secret?
  - Add awskit:allow in a comment on that line, or
  - run: awskit secrets --allow FILE:LINE   (adds its sha256 to .awskit-secrets-allow)

To skip this check for one commit: git commit --no-verify
```

Warnings are listed too, but the commit goes through. So are files it couldn't check (binary files, files over 2 MB), under "Not checked", so a skipped file never looks clean. With nothing to report, the hook prints nothing.

- **A hook that's already there** (yours, or another tool's) is never overwritten. `--install-hook --chain`, or **Run both** in the window, renames it to `pre-commit.before-awskit`. AWS Kit's hook runs it first, and the commit stops if either one fails. `--remove-hook` only removes AWS Kit's hook (it checks for its marker line) and puts the old one back.
- **awskit has to be on PATH.** The hook finds it with `command -v awskit`, and only takes a full path, never `./awskit` from the repo (which a `.` or an empty entry in PATH would give). If it can't find it there or in `~/.local/bin`, it prints a warning and lets the commit through unchecked, so a missing install never blocks your work. `awskit secrets --install-hook` warns you when that would happen.
- **Windows:** Git for Windows runs hooks with its own `sh`, so the same script works. The Windows installer puts `awskit.cmd` on PATH, and the hook looks for that too.
- The hook doesn't touch your files or the index. It only reads what's staged, including with `git commit -a`.
- **A hooks folder outside the repo** (`core.hooksPath` pointing at a shared folder like `~/.githooks`) is left alone, since hooks there run for other repos too, and a repo you cloned can point it anywhere. It says so, and you can add `awskit secrets --staged --hook || exit 1` to that folder's `pre-commit` yourself. A `core.hooksPath` inside the repo, like `.githooks`, works as usual.

If you use the [pre-commit](https://pre-commit.com) framework, add it as a local hook instead:

```yaml
repos:
  - repo: local
    hooks:
      - id: awskit-secrets
        name: AWS Kit secrets scan
        entry: awskit secrets --staged --hook
        language: system
        pass_filenames: false
```

## Allowing a false positive

Three ways, from the quickest to the widest:

- **On the line:** put `awskit:allow` anywhere on it, in whatever comment style the file uses (`# awskit:allow`, `// awskit:allow`, `<!-- awskit:allow -->`). For a private key block, put it on the line just above the BEGIN line.
- **One value, everywhere:** press **Allow this** in the window, or run `awskit secrets --allow FILE:LINE`. Either adds a `sha256:` line to `.awskit-secrets-allow` at the top of the repo. The file holds the hash, never the value. To add one by hand: `printf '%s' 'the value' | sha256sum`.
- **Files or patterns:** add lines to `.awskit-secrets-allow` yourself.

```text
# Test keys for the TLS tests
path:tests/fixtures/*.pem
path:vendor/
path:**/fake-credentials.json
sha256:5e05697b964e6c4ef0e7240fd21a8a10b4b84298a3f03de4383e03054c7bd01f
re:^sk_test_
```

| Line | What it allows |
|---|---|
| `sha256:HASH` | The value with that sha256 |
| `path:GLOB` | Files matching the pattern, relative to the top of the repo. `*` matches across folders too, so `tests/fixtures/*.pem` also skips files in folders under `fixtures`. A pattern without `/` also matches the file name anywhere, and one ending in `/` skips every folder with that path, at any depth (`vendor/` skips `src/vendor/` too). |
| `re:REGEX` | Values the regular expression finds a match in. Use `^` and `$` to match the whole value. |

Lines starting with `#` are comments. Lines it can't read are listed as notes after the scan, so a typo doesn't quietly do nothing.

Allowed findings are counted in the summary (like "1 allowed"), and `--json` lists them with what allowed each one. Treat changes to `.awskit-secrets-allow` and new `awskit:allow` comments like code changes in a review: they're how a real key could get waved through.

Only allow values that really aren't secrets. A sha256 of a long random key can't be reversed, but the sha256 of a short password can be guessed.

## Use it in CI

The same check can run on every push. It exits with 1 when something needs fixing, which fails the job. In a GitHub Actions workflow, after checking out your repo:

```yaml
- uses: actions/checkout@COMMIT_SHA  # v4, pinned to a full commit SHA
  with:
    fetch-depth: 0  # only needed for --history
- name: Check for secrets
  run: |
    git clone --filter=blob:none https://github.com/Snowblind019/cloud-tools.git "$RUNNER_TEMP/cloud-tools"
    git -C "$RUNNER_TEMP/cloud-tools" checkout --quiet AWSKIT_COMMIT_SHA
    PYTHONPATH="$RUNNER_TEMP/cloud-tools" python3 -m awskit secrets --all
```

Put the full commit SHA of the actions/checkout release you've looked at in place of `COMMIT_SHA`, and the AWS Kit commit you've looked at in place of `AWSKIT_COMMIT_SHA`, rather than whatever a tag or the default branch points at that day. It needs only Python 3.9 or newer, no GTK and no boto3. Use `--history 50` instead of `--all` to also catch keys that were committed and deleted. The output only ever shows masked values, so it's fine in a build log.

## Settings

The window saves its settings in the AWS Kit config (`~/.config/awskit/config.json`, or `%APPDATA%\awskit\config.json` on Windows) under `secrets_scan`:

| Setting | What it is |
|---|---|
| `folder` | The last folder you picked |
| `mode` | The last thing you scanned: `staged`, `all`, `history` or `files` |
| `history_commits` | How many commits Git history reads |
| `block_account_ids` | Treat AWS account IDs as something to fix. The commit hook and the terminal use it too. |

## How it works

- **PII Redact's patterns.** It runs PII Redact's rules for AWS keys, session tokens, presigned URLs, private keys, API tokens, Authorization headers, passwords in URLs, password and secret settings, account IDs, emails and IPs, and keeps which rule matched. It adds Amazon Bedrock API keys, Slack webhooks, npm and PyPI tokens, base64-encoded private keys and `<password>` style XML. Then it checks each match: a known format can still be a placeholder (`ghp_xxxx...`), and a setting named password can hold a variable.
- **Overlaps.** When two matches cover the same text, a block wins over a warning, a known format wins over a generic setting, and then the longer one.
- **Masking.** Previews show the first and last 4 characters of a key or token (`AKIA************MPLE`), and only the length of a password (`******** (12 characters)`). The lines around a finding have every found value masked, every other copy of the same value on those lines, and anything PII Redact's own rules find there. The values themselves are never kept, printed or written anywhere, and allowing one stores only its sha256.
- **Git, safely.** A repo's own `.git/config` can name programs for git to run, and a repo you cloned is someone else's file. So git runs with `core.fsmonitor`, external diff tools, textconv filters, the pager and signature checks turned off, and with a list of arguments, never through a shell. It never fetches: in a partial clone, `git log -p` would download missing files the way the repo's config says (its `core.sshCommand`, an `ext::` URL or a credential helper, any of which runs a program), so every protocol is switched off with `GIT_ALLOW_PROTOCOL` and `GIT_NO_LAZY_FETCH`, and Git history stops with a note instead. git itself is looked up on PATH, never in the current folder. Staged changes are read with `git diff --cached -U0 --no-ext-diff --no-textconv --text`, so a `.gitattributes` that marks a file as binary can't hide it. A new UTF-16 file (Windows PowerShell 5 writes those with `>`, like `aws iam create-access-key > key.json`) is read as text. Other files with NUL bytes are skipped as binary, and the notes and the hook say so. Git's output is read a line at a time, with a time limit.
- **Files, safely.** It reads at most 2 MB of a file, never through a link, and never from anything that isn't a regular file.

## Limits

- It's pattern matching. It can miss a secret in a format it doesn't know, or with nothing around it to say it's a secret (like a password in a plain sentence). It can also flag something harmless, which is what the allow list is for.
- Staged changes only cover lines being added. A secret that's already in the repo shows up with **All files**, and one that was removed with **Git history**.
- Git history reads the last N commits on the current branch, not every branch. Merges show up through the commits they bring in.
- A shallow clone (like a CI checkout with depth 1) only has the history it fetched. A partial clone (`--filter=blob:none`) can't be read with Git history, since it never downloads the missing files.
- In staged changes and Git history, a UTF-16 file is read as text only when its first line is part of the change (where the byte order mark is). An edit further down an existing UTF-16 file is skipped as binary, with a note. All files reads the whole file either way.
- It doesn't check whether a key works. Treat any real-looking key as live and rotate it.
- `awskit:allow` and the allow file are trusted. Anyone who can change the repo can allow a value, so review those changes.

## Files

| File | What it is |
|---|---|
| `secretscan.py` | Detection, the git and folder scans, the allow list, the hook and the command line. No GTK. |
| `secrets_page.py` | The Secrets Scan page |
| `examples/make_demo_repo.py` | Makes a throwaway repo with fake leaks (made up at run time) to try it on: `python3 secrets-scan/examples/make_demo_repo.py` |
| `docs/screenshot.png` | The screenshot above |
