# PII Redact

I made this because I found it tedious to redact stuff every time I needed to troubleshoot something while working on my [aws-platform](https://github.com/Snowblind019/aws-platform) projects. Before I could share any output, I had to go through it by hand and pull out account IDs, keys, ARNs and anything else that pointed back to me or my accounts. So I made a tool that does it for me.

It takes Terraform, AWS CLI, boto3 or any other output and gives it back with account IDs, keys, ARNs, resource IDs, emails, public IPs and other identifying info swapped out for `[Redacted]`. It's one of the tools in [AWS Kit](../awskit/), so it's a page in the AWS Kit window, a small paste window of its own for a keybind, and a terminal command.

![The PII Redact page in AWS Kit: raw output on the left, redacted output on the right](docs/screenshot.png)

Part of [AWS Kit](../awskit/). The screenshots use the fake data in `examples/sample.txt`.

## Features

- **Paste window.** Paste on the left and the redacted version shows up on the right as you paste. Every replacement is highlighted so you can check it at a glance, and there's a Copy button (Ctrl+Shift+C). It's the first page in AWS Kit, and it also opens as a small window on its own with `pii-redact`, which suits a keybind.
- **Settings window with checkboxes.** Turn each of the 26 categories on or off, with All and None buttons per section. You also get an always-redact list for your own names and domains, a never-redact list for things you're fine showing, numbered placeholders, a custom placeholder word, and auto copy.
- **Clipboard mode.** `pii-redact clip` takes whatever you copied, redacts it and puts it back. Bind it to a key, and copy, press, paste is the whole workflow.
- **Terminal mode.** Pipe output in, pass a file, or use `pii-redact run terraform plan` to run a command and redact what it prints. Add `-c` to copy the result.
- **Numbered placeholders.** `[Redacted-AccountID-1]` instead of `[Redacted]`, so the same value keeps the same number. This lets someone helping you still tell when two ARNs point at the same account.
- **Knows what to leave alone.** Regions, private IPs, CIDR blocks, Terraform references, version numbers and commit hashes stay, so the output still makes sense.
- **Strips terminal color codes** before redacting, so colored Terraform output doesn't hide values.
- **Keeps the clipboard after closing** on Niri, Hyprland, Sway and X11, where the clipboard normally empties when the app that copied closes.
- **Built into the other tools.** Every **Copy redacted** button in AWS Kit, and `awskit plan --redact`, uses PII Redact with your settings. So a CloudTrail event, an audit finding or a plan summary can be shared in one click. [Image Redact](../image-redact/) uses the same rules and settings to cover things in screenshots.
- **Local only.** No network calls, nothing leaves your machine.

![The small paste window, opened with pii-redact or a keybind](docs/main-window.png)

## Install

PII Redact installs with the rest of AWS Kit. On Fedora:

```bash
sudo dnf install python3-gobject gtk4 wl-clipboard python3-boto3
git clone https://github.com/Snowblind019/cloud-tools.git
cd cloud-tools
./install.sh
```

| Distro | Command |
|---|---|
| Fedora | `sudo dnf install python3-gobject gtk4 wl-clipboard python3-boto3` |
| Debian / Ubuntu | `sudo apt install python3-gi gir1.2-gtk-4.0 wl-clipboard python3-boto3` |
| Arch | `sudo pacman -S python-gobject gtk4 wl-clipboard python-boto3` |

On X11, install `xclip` instead of `wl-clipboard`. PII Redact itself only needs Python 3.9+, GTK 4 for the windows, and a clipboard tool for `clip` and `-c`. boto3 is for the AWS tools.

That gives you two commands that do the same thing: `pii-redact` and `awskit redact`. It also adds two launcher entries, **PII Redact** and **PII Redact Settings**, which show up in fuzzel, rofi, Noctalia, GNOME, KDE and other launchers. In GNOME and KDE, right-clicking **PII Redact** also gives you **Redact clipboard** and **Settings**.

**Coming from the standalone pii-redact?** Your settings carry over on first run, from `~/.config/pii-redact/config.json` (or the older `pii-redactor` folder). The installer replaces the old `~/.local/bin/pii-redact` and removes the old launcher entries, so nothing shows up twice. Your keybinds keep working, but window rules need the new app ID, see [Keybinds](#keybinds).

To update, run `git pull && ./install.sh` from the root of the repo. To remove it, run `awskit uninstall`, which removes AWS Kit and PII Redact together.

Want to try it before installing? From the root of the repo, run `python3 -m awskit redact pii-redact/examples/sample.txt`. The sample is all fake data.

## Quick start

There are three ways to use it. Pick whichever fits the moment.

1. **Window.** Run `pii-redact` or open it from your launcher, paste, then hit Copy. If AWS Kit is already open, it's the first page there too.
2. **Clipboard.** Copy some output, run `pii-redact clip` (best bound to a key), then paste. A notification tells you what got redacted.
3. **Terminal.** Run `terraform plan 2>&1 | pii-redact -c`. This prints the redacted output and copies it.

Before and after:

```text
"Arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_4f3c9a1b2d6e8f70/jane.doe@example.com"
public_ip = "54.201.33.17"
on /home/jane/aws-platform/modules/logging/main.tf line 14
```

```text
"Arn": "arn:aws:sts::[Redacted]:assumed-role/AWSReservedSSO_AdministratorAccess_[Redacted]/[Redacted]"
public_ip = "[Redacted]"
on /home/[Redacted]/aws-platform/modules/logging/main.tf line 14
```

## Commands

`pii-redact` and `awskit redact` are the same command, so anything below works with either.

| Command | What it does |
|---|---|
| `pii-redact` | Opens the paste window. If something is piped in, it redacts that and prints it instead. |
| `pii-redact FILE...` | Redacts one or more files and prints the result. Use `-` for stdin. |
| `pii-redact clip` | Redacts whatever is on the clipboard and puts it back. |
| `pii-redact run COMMAND...` | Runs a command and redacts everything it prints, stdout and stderr together. Keeps the command's exit code. |
| `pii-redact gui [FILE]` | Opens the paste window, filled in with FILE if you give one. |
| `pii-redact settings` | Opens the settings window. |
| `pii-redact categories` | Lists every category name and whether it's on. |
| `awskit gui redact` | Opens AWS Kit on the PII Redact page. |
| `pii-redact --help` | Shows all of this in the terminal. |
| `pii-redact --version` | Shows the version. |

Install and uninstall go through AWS Kit now: `./install.sh` and `awskit uninstall`.

## Options

These work with piped input, files, `clip` and `run`.

| Option | What it does |
|---|---|
| `-c`, `--copy` | Copy the result to the clipboard. |
| `-q`, `--quiet` | Don't print the result. Handy with `-c` when you only want it copied. |
| `-g`, `--gui` | Open the result in the paste window instead of printing it, so you can look it over first. |
| `-n`, `--numbered` | Use numbered placeholders for this run. |
| `-p`, `--private-ips` | Also redact private IPs for this run. |
| `-w WORD`, `--word WORD` | Also redact WORD for this run. Can repeat. |
| `-k WORD`, `--keep WORD` | Don't redact WORD for this run. Can repeat. |
| `--skip NAMES` | Turn categories off for this run, comma separated, like `--skip buckets,uuids`. |
| `--only NAMES` | Use only these categories for this run, like `--only account_ids,aws_keys`. |

Short options can be combined, so `-cq` copies without printing and `-gn` opens the window with numbering on.

With `run`, put the options between `run` and the command: `pii-redact run -cq terraform plan`. Once the command name starts, everything after it belongs to the command.

## Using it with different tools

### Terraform

```bash
terraform plan 2>&1 | pii-redact -c         # print and copy, errors included
pii-redact run -c terraform plan            # same thing, shorter
pii-redact run -g terraform validate        # look it over in the window first
terraform show -json | pii-redact -cq       # copy only, print nothing
terraform output | pii-redact -n            # numbered placeholders
```

`2>&1` matters when piping, because Terraform writes errors to stderr. `run` already includes stderr.

### AWS CLI

```bash
aws sts get-caller-identity | pii-redact -c
pii-redact run -c aws iam list-roles
pii-redact run -g aws ec2 describe-instances --region us-west-2
aws s3 ls s3://my-bucket --recursive 2>&1 | pii-redact --skip buckets
```

### Python and boto3

```bash
python3 list_instances.py 2>&1 | pii-redact -c
pii-redact run -c python3 list_instances.py
pii-redact run -g python3 -m pytest tests/
```

boto3's dict output (`{'Account': '123456789012', ...}`) is handled the same as JSON. Tracebacks go to stderr, so use `2>&1` or `run` to include them.

### Anything else

```bash
journalctl -u myservice -n 200 | pii-redact -c
docker logs api 2>&1 | pii-redact -g
kubectl describe pod web-0 | pii-redact -c
git diff | pii-redact -c
pii-redact app.log > app-redacted.log
```

## Shell shortcuts

These cut it down even more. For bash or zsh, add them to `~/.bashrc` or `~/.zshrc`:

```bash
alias rd='pii-redact'
alias rdc='pii-redact clip'
alias rdw='pii-redact -g'                        # some-command | rdw
tfr()  { pii-redact run -c terraform "$@"; }    # tfr plan
awsr() { pii-redact run -c aws "$@"; }          # awsr sts get-caller-identity
pyr()  { pii-redact run -c python3 "$@"; }      # pyr list_instances.py
```

For fish, add them to `~/.config/fish/config.fish`:

```fish
alias rd pii-redact
alias rdc 'pii-redact clip'
alias rdw 'pii-redact -g'
function tfr;  pii-redact run -c terraform $argv; end
function awsr; pii-redact run -c aws $argv; end
function pyr;  pii-redact run -c python3 $argv; end
```

## Keybinds

Two binds cover most of it: one opens the paste window, and one redacts the clipboard in place. The examples use Super+Alt+R and Super+Alt+C, so swap them for whatever is free in your config. They use the full path because your compositor's PATH might not include `~/.local/bin`.

The window rules are optional. They make the window open floating, which suits a quick tool like this.

These are the PII Redact ones. [AWS Kit's README](../awskit/README.md#keybinds) has binds for the whole kit, including the main window and the profile picker.

If you set this up for the standalone pii-redact before, the commands are the same, but the app ID in window rules changed from `io.github.Snowblind019.PiiRedact` to `io.github.Snowblind019.AwsKit.Redact`.

### Niri

In `~/.config/niri/config.kdl`:

```kdl
binds {
    Mod+Alt+R { spawn-sh "~/.local/bin/pii-redact gui"; }
    Mod+Alt+C { spawn-sh "~/.local/bin/pii-redact clip"; }
}

window-rule {
    match app-id=r#"^io\.github\.Snowblind019\.AwsKit\.Redact"#
    open-floating true
}

window-rule {
    match app-id=r#"^io\.github\.Snowblind019\.AwsKit\.Redact$"#
    default-column-width { fixed 1150; }
    default-window-height { fixed 740; }
}
```

The first rule matches both the paste window and the settings window. `spawn-sh` needs niri 25.08 or newer. On older versions, use `spawn "sh" "-c" "~/.local/bin/pii-redact gui"`.

### Hyprland 0.55 and newer (Lua config)

In `~/.config/hypr/hyprland.lua`:

```lua
hl.bind("SUPER + ALT + R", hl.dsp.exec_cmd("~/.local/bin/pii-redact gui"))
hl.bind("SUPER + ALT + C", hl.dsp.exec_cmd("~/.local/bin/pii-redact clip"))

hl.window_rule({
    match = { class = "^io.github.Snowblind019.AwsKit.Redact" },
    float = true,
})
hl.window_rule({
    match = { class = "^io.github.Snowblind019.AwsKit.Redact$" },
    size = "1150 740",
})
```

### Hyprland before 0.55 (hyprland.conf)

```ini
bind = SUPER ALT, R, exec, ~/.local/bin/pii-redact gui
bind = SUPER ALT, C, exec, ~/.local/bin/pii-redact clip

# 0.53 and 0.54
windowrule = match:class ^io.github.Snowblind019.AwsKit.Redact, float on

# 0.52 and older
windowrulev2 = float, class:^(io.github.Snowblind019.AwsKit.Redact.*)$
```

### Sway

In `~/.config/sway/config`:

```text
bindsym $mod+Mod1+r exec ~/.local/bin/pii-redact gui
bindsym $mod+Mod1+c exec ~/.local/bin/pii-redact clip
for_window [app_id="^io\.github\.Snowblind019\.AwsKit\.Redact"] floating enable
```

### i3

In `~/.config/i3/config`. This needs `xclip` for clip mode.

```text
bindsym $mod+Mod1+r exec --no-startup-id ~/.local/bin/pii-redact gui
bindsym $mod+Mod1+c exec --no-startup-id ~/.local/bin/pii-redact clip
for_window [title="^PII Redact"] floating enable
```

### GNOME

1. Go to Settings, then Keyboard, then View and Customize Shortcuts, then Custom Shortcuts, and press **+**.
2. For the name, use **PII Redact**.
3. For the command, use `sh -c "$HOME/.local/bin/pii-redact gui"`.
4. Set the shortcut, then repeat with `clip` for a second one.

On GNOME Wayland, clip mode depends on wl-clipboard, which GNOME doesn't fully support, so it can be hit or miss. The paste window always works.

### KDE Plasma

1. Go to System Settings, then Keyboard, then Shortcuts, then Add New, then Command or Script.
2. For the command, use `sh -c "$HOME/.local/bin/pii-redact gui"`.
3. Set the shortcut, then repeat with `clip`.

## Settings

![The settings window](docs/settings-window.png)

Open it with `pii-redact settings`, the **PII Redact Settings** launcher entry, the Settings button on the PII Redact page or in the paste window, or Ctrl+, in either.

**Categories.** Every type of thing it can redact has its own checkbox, grouped into AWS, Keys and tokens, Personal info, and Network. Each group has All and None buttons.

**Output.**
- Number the redactions.
- Copy automatically when you paste into the window.
- Copy terminal results automatically, which is the same as always adding `-c`.
- Change the placeholder word. `HIDDEN` gives you `[HIDDEN]`.

**Always redact.** One word per line. Nothing can guess that a word is your name, so put your name, GitHub handle, employer, domains you own and project names here. Matching is whole word and ignores case. On first run, this list starts with your Linux username and hostname.

**Never redact.** One per line. Anything matching these stays visible, like AWS's documentation account `123456789012` or a bucket name you don't mind showing.

Changes save right away and apply immediately, even in a paste window that's already open, and to every **Copy redacted** button in AWS Kit. **Reset to defaults** resets the checkboxes and output options but keeps your word lists.

Settings live in `~/.config/awskit/redact.json`, readable only by you, so you can also edit or back it up by hand.

### Categories

Use these names with `--skip` and `--only`.

| Name | Default | What it covers |
|---|---|---|
| `account_ids` | on | 12-digit account numbers, including the ones inside ARNs and ECR URLs |
| `aws_keys` | on | AKIA and ASIA access keys, secret access keys and session tokens |
| `iam_ids` | on | AIDA, AROA and similar IDs from get-caller-identity and IAM output |
| `iam_names` | on | The user name in IAM user ARNs and the session name in assumed-role ARNs |
| `sso_hash` | on | The random ending on AWSReservedSSO_ role names |
| `org_ids` | on | o-, ou- and r- IDs from AWS Organizations, plus Identity Center directory IDs |
| `resource_ids` | on | i-, vpc-, subnet-, sg-, ami-, vol-, tgw- and other EC2 and VPC IDs |
| `uuids` | on | KMS key IDs, request IDs and anything else in UUID format |
| `aws_hostnames` | on | The unique part of API Gateway, Lambda URL, CloudFront, RDS, ELB and access portal hostnames, plus Route 53 zone and CloudFront distribution IDs |
| `buckets` | on | Bucket names in s3:// URLs, S3 ARNs, S3 hostnames and bucket settings |
| `canonical_ids` | on | The 64-character owner IDs in S3 output |
| `private_keys` | on | PEM and OpenSSH private key blocks |
| `ssh_keys` | on | The key and comment after ssh-ed25519, ssh-rsa and similar |
| `tokens` | on | GitHub, GitLab, Slack, Terraform Cloud, OpenAI, Anthropic, Google and Stripe tokens, JWTs, and long random strings |
| `url_creds` | on | The user:password part of URLs like https://user:pass@host |
| `secret_values` | on | Values of password, secret, token, api_key and similar settings |
| `emails` | on | Email addresses |
| `phones` | on | US formats and +country numbers |
| `names` | on | Values of owner, user, username, display_name, first_name, organization and similar settings |
| `home_paths` | on | The name in /home/name, /Users/name and C:\Users\name |
| `gov_ids` | on | US Social Security numbers and birth date fields |
| `cards` | on | Checked with the Luhn formula to avoid false hits |
| `custom_words` | on | Words in your always-redact list |
| `public_ips` | on | IPv4 and IPv6 |
| `private_ips` | **off** | 10.x, 172.16-31.x, 192.168.x, fe80:: and fd00:: addresses and CIDR blocks. Off by default so VPC layouts still make sense |
| `macs` | on | Colon, dash and Cisco dotted formats |

## What it leaves alone on purpose

These are kept so the output is still useful for troubleshooting:

- AWS regions
- Private IPs and CIDR blocks, unless you turn that category on
- `0.0.0.0/0`, subnet masks and loopback addresses
- Git commit hashes, version numbers and timestamps
- Terraform references like `var.owner` or `aws_s3_bucket.logs.id`
- Terraform's `(sensitive value)` and `(known after apply)`
- Resource names like `aws_instance.web`
- Role and policy names. Only the account ID, user name, session name and SSO suffix inside an ARN are removed.
- `git@github.com` in module sources

## How it works

It's all pattern matching, done locally:

- Known formats like AKIA keys, `vpc-` IDs, ARNs and UUIDs get matched directly.
- Values next to settings like `password =`, `"Owner":` or `AWS_SECRET_ACCESS_KEY=` get matched by the setting name. This works in HCL, JSON, YAML, `.env`, INI and boto3 dict output.
- A few extra checks cut down on false hits. Card numbers have to pass the Luhn formula, secret keys and tokens have to look random enough, and IPs are sorted into public and private.
- When two matches overlap, the bigger one wins. The text is then rebuilt with placeholders.

## Heads up

- Pattern matching can't be perfect. It can miss something unusual or catch something harmless, which is why the window highlights every replacement. Give it a look before sharing, and add your own names to the always-redact list.
- `run` and pipes show the output when the command finishes, and they can't show prompts. For `terraform apply`, use `-auto-approve` or apply a saved plan.
- It's built for Linux. Terminal mode should run anywhere with Python 3.9+, but the clipboard features use Linux tools.

## Files

| File | What it is |
|---|---|
| `redact.py` | The rules, the settings and the command line. No GTK. |
| `redact_page.py` | The PII Redact page, the small paste window and the settings window |
| `examples/sample.txt` | Fake output to try it on |
| `docs/` | Screenshots |

## License

MIT. See [LICENSE](../LICENSE).

This is a personal project and isn't affiliated with or endorsed by Amazon Web Services.
