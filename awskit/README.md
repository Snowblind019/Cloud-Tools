# AWS Kit

The app that holds all nine tools in this repo. It gives them one window with a sidebar, one `awskit` command, one installer, and shared code for AWS sessions, tables, exporting, the clipboard and redaction.

![The AWS Kit window on the PII Redact page](../pii-redact/docs/screenshot.png)

| Tool | Page | Command | README |
|---|---|---|---|
| PII Redact | PII Redact | `pii-redact` or `awskit redact` | [pii-redact/](../pii-redact/) |
| Image Redact | Image Redact | `awskit image` | [image-redact/](../image-redact/) |
| Lab Sweep | Lab Sweep | `awskit sweep` | [lab-sweep/](../lab-sweep/) |
| Exposure Audit | Exposure Audit | `awskit audit` | [exposure-audit/](../exposure-audit/) |
| CloudTrail | CloudTrail | `awskit trail` | [cloudtrail/](../cloudtrail/) |
| Plan Check | Plan Check | `awskit plan` | [plan-check/](../plan-check/) |
| Policy Check | Policy Check | `awskit policy` | [policy-check/](../policy-check/) |
| Profiles | Profiles | `awskit profile` or `awsp` | [profiles/](../profiles/) |
| Cloud Map | Cloud Map | `awskit map` | [cloud-map/](../cloud-map/) |

This README covers what they have in common, plus keybinds for the whole kit. Each tool's README goes into how that tool works.

## Install

From the root of the repo:

```bash
sudo dnf install python3-boto3 python3-gobject gtk4 wl-clipboard
./install.sh
```

| Needed for | Fedora package |
|---|---|
| The AWS tools | `python3-boto3` |
| The windows | `python3-gobject gtk4` |
| `pii-redact clip`, and copying that sticks around after a window closes on Niri, Hyprland and Sway | `wl-clipboard`, or `xclip` on X11 |
| Image Redact finding text in screenshots | `tesseract tesseract-langpack-eng` |
| SSO sign-in from the Profiles page | `awscli2` |
| Plan Check running plans by itself, Cloud Map reading a Terraform folder, and the designer checking what it writes | `terraform` or `tofu` |
| Cloud Map's editor inside the window (optional) | `webkitgtk6.0` (Debian and Ubuntu: `gir1.2-webkit-6.0`, Arch: `webkitgtk-6.0`). Without it, the editor opens in its own browser window |

PII Redact, Image Redact, Plan Check and Policy Check work offline and don't need boto3, and neither do Cloud Map's Terraform maps. On Debian and Ubuntu, Image Redact and the Cloud Map page also need `python3-gi-cairo`. Without GTK, everything still works from the terminal.

On Windows, see [Windows](#windows) below. On WSL, see [WSL](../README.md#wsl) in the main README for what works differently.

The installer:

- copies `awskit/` and the nine tool folders to `~/.local/share/awskit/`
- writes two small launchers: `~/.local/bin/awskit`, and `~/.local/bin/pii-redact`, which is the same as `awskit redact`
- adds five launcher entries: **AWS Kit** (right-click opens a tool directly), **AWS Profile Picker**, **PII Redact** (right-click has Redact clipboard and Settings), **PII Redact Settings**, and **Image Redact** (right-click has Open clipboard image and Redact clipboard image), which also shows up under Open With for images
- removes launcher entries left over from the standalone pii-redact, if you had it
- downloads the draw.io web app (about 48 MB, 110 MB unpacked) to `~/.local/share/awskit/drawio/` and checks its SHA-256. Cloud Map draws draw.io's own AWS icons from it and runs its offline editor from it (see [Icons](../cloud-map/README.md#icons) for why it isn't in the repo). It only downloads again when the pinned version changes

If GitHub downloads are blocked, download `draw.war` from the link the installer prints (the pinned release on github.com/jgraph/drawio) another way, then run `./install.sh --drawio-zip /path/to/draw.war`. `./install.sh --no-drawio` skips it, and Cloud Map then draws simple labels in place of the AWS icons and has no editor.

To update, `git pull` and run `./install.sh` again. To remove everything, run `awskit uninstall`. That leaves your settings in `~/.config/awskit/`, so delete that folder too if you want them gone.

To try it without installing, run `python3 -m awskit` from the root of the repo.

## The window

Run `awskit` with no arguments, or open **AWS Kit** from your launcher. It opens on PII Redact, the tool you'll probably use most. `awskit gui audit` opens it on a certain page (redact, image, sweep, audit, trail, plan, policy, profiles or map). If the window is already open, it switches to that page instead of opening a second window.

Things that work the same on every page:

- **Profile button** in the top right. It shows the current profile and switches it for the window and for your terminals. If you switch with `awsp` in a terminal, the window follows right away.
- **Filter rows** box above each table. It matches text in any column.
- **Click a column header** to sort by it. Cost and severity sort by value, not by text.
- **Details pane** under the table. It shows everything about the selected row. **Copy** copies it, and **Copy redacted** runs it through PII Redact first, using your PII Redact settings.
- **Status bar** at the bottom. It shows progress while a scan runs, and **Stop** cancels it after the calls already running finish.
- **Export** saves the table as Markdown, CSV or JSON. The file name you pick decides the format.

Keyboard: Ctrl+1 to Ctrl+9 switch pages, and Ctrl+Q quits. On the PII Redact page, Ctrl+Shift+C copies and Ctrl+, opens its settings. Image Redact has its own shortcuts, see [image-redact/](../image-redact/#the-editor), and so does the Cloud Map page, see [cloud-map/](../cloud-map/README.md#the-cloud-map-page).

All AWS calls run in the background, so the window stays usable during a scan.

Besides the main window, four windows open on their own, which suits keybinds:

| Window | Opens with | App ID |
|---|---|---|
| AWS Kit (main window) | `awskit` | `io.github.Snowblind019.AwsKit` |
| PII Redact paste window | `pii-redact` | `io.github.Snowblind019.AwsKit.Redact` |
| PII Redact settings | `pii-redact settings` | `io.github.Snowblind019.AwsKit.RedactSettings` |
| AWS profile picker | `awskit profile` or `awsp` | `io.github.Snowblind019.AwsKit.Profiles` |
| Image Redact | `awskit image` | `io.github.Snowblind019.AwsKit.ImageRedact` |

## Keybinds

These cover the whole kit. Pick the ones you want and swap the keys for whatever is free in your config. They use the full path because your compositor's PATH might not include `~/.local/bin`.

| Keys in the examples | Command | What it does |
|---|---|---|
| Super+Alt+R | `pii-redact gui` | Open the PII Redact paste window |
| Super+Alt+C | `pii-redact clip` | Redact the clipboard in place, with a notification |
| Super+Alt+I | `awskit image clip -g` | Open the clipboard screenshot in Image Redact |
| Super+Alt+A | `awskit profile` | Open the AWS profile picker |
| Super+Alt+K | `awskit` | Open AWS Kit, or bring it to the front |

Two more that are handy if you use them a lot: `awskit gui trail` opens straight to CloudTrail, and `awskit gui plan` to Plan Check.

The window rules are optional. They make the small windows open floating, which suits quick tools like these, and give the main window a good size.

### Niri

In `~/.config/niri/config.kdl`:

```kdl
binds {
    Mod+Alt+R { spawn-sh "~/.local/bin/pii-redact gui"; }
    Mod+Alt+C { spawn-sh "~/.local/bin/pii-redact clip"; }
    Mod+Alt+I { spawn-sh "~/.local/bin/awskit image clip -g"; }
    Mod+Alt+A { spawn-sh "~/.local/bin/awskit profile"; }
    Mod+Alt+K { spawn-sh "~/.local/bin/awskit"; }
}

// The PII Redact windows and the profile picker float
window-rule {
    match app-id=r#"^io\.github\.Snowblind019\.AwsKit\.(Redact|RedactSettings|Profiles)$"#
    open-floating true
}

window-rule {
    match app-id=r#"^io\.github\.Snowblind019\.AwsKit\.Redact$"#
    default-column-width { fixed 1150; }
    default-window-height { fixed 740; }
}

window-rule {
    match app-id=r#"^io\.github\.Snowblind019\.AwsKit$"#
    default-column-width { fixed 1240; }
}
```

`spawn-sh` needs niri 25.08 or newer. On older versions, use `spawn "sh" "-c" "~/.local/bin/pii-redact gui"` and so on.

### Hyprland 0.55 and newer (Lua config)

In `~/.config/hypr/hyprland.lua`:

```lua
hl.bind("SUPER + ALT + R", hl.dsp.exec_cmd("~/.local/bin/pii-redact gui"))
hl.bind("SUPER + ALT + C", hl.dsp.exec_cmd("~/.local/bin/pii-redact clip"))
hl.bind("SUPER + ALT + I", hl.dsp.exec_cmd("~/.local/bin/awskit image clip -g"))
hl.bind("SUPER + ALT + A", hl.dsp.exec_cmd("~/.local/bin/awskit profile"))
hl.bind("SUPER + ALT + K", hl.dsp.exec_cmd("~/.local/bin/awskit"))

hl.window_rule({
    match = { class = "^io.github.Snowblind019.AwsKit.(Redact|RedactSettings|Profiles)$" },
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
bind = SUPER ALT, I, exec, ~/.local/bin/awskit image clip -g
bind = SUPER ALT, A, exec, ~/.local/bin/awskit profile
bind = SUPER ALT, K, exec, ~/.local/bin/awskit

# 0.53 and 0.54
windowrule = match:class ^io.github.Snowblind019.AwsKit.(Redact|RedactSettings|Profiles)$, float on

# 0.52 and older
windowrulev2 = float, class:^(io.github.Snowblind019.AwsKit.(Redact|RedactSettings|Profiles))$
```

### Sway

In `~/.config/sway/config`:

```text
bindsym $mod+Mod1+r exec ~/.local/bin/pii-redact gui
bindsym $mod+Mod1+c exec ~/.local/bin/pii-redact clip
bindsym $mod+Mod1+i exec ~/.local/bin/awskit image clip -g
bindsym $mod+Mod1+a exec ~/.local/bin/awskit profile
bindsym $mod+Mod1+k exec ~/.local/bin/awskit
for_window [app_id="^io\.github\.Snowblind019\.AwsKit\.(Redact|RedactSettings|Profiles)$"] floating enable
```

### i3

In `~/.config/i3/config`. This needs `xclip` for clip mode.

```text
bindsym $mod+Mod1+r exec --no-startup-id ~/.local/bin/pii-redact gui
bindsym $mod+Mod1+c exec --no-startup-id ~/.local/bin/pii-redact clip
bindsym $mod+Mod1+i exec --no-startup-id ~/.local/bin/awskit image clip -g
bindsym $mod+Mod1+a exec --no-startup-id ~/.local/bin/awskit profile
bindsym $mod+Mod1+k exec --no-startup-id ~/.local/bin/awskit
for_window [title="^(PII Redact|PII Redact settings|AWS profile)$"] floating enable
```

### GNOME

1. Go to Settings, then Keyboard, then View and Customize Shortcuts, then Custom Shortcuts, and press **+**.
2. Give it a name, like **PII Redact**.
3. For the command, use `sh -c "$HOME/.local/bin/pii-redact gui"`.
4. Set the shortcut, then repeat for the others: `pii-redact clip`, `awskit image clip -g`, `awskit profile` and `awskit`.

On GNOME Wayland, clip mode depends on wl-clipboard, which GNOME doesn't fully support, so it can be hit or miss. The paste window always works.

### KDE Plasma

1. Go to System Settings, then Keyboard, then Shortcuts, then Add New, then Command or Script.
2. For the command, use `sh -c "$HOME/.local/bin/pii-redact gui"`.
3. Set the shortcut, then repeat for `pii-redact clip`, `awskit image clip -g`, `awskit profile` and `awskit`.

## Commands

| Command | What it does |
|---|---|
| `awskit` | Open the window |
| `awskit gui [PAGE]` | Open the window on a page |
| `pii-redact`, `awskit redact` | PII Redact, see [pii-redact/](../pii-redact/) |
| `awskit image` | Image Redact, see [image-redact/](../image-redact/) |
| `awskit sweep` | Lab Sweep, see [lab-sweep/](../lab-sweep/) |
| `awskit audit` | Exposure Audit, see [exposure-audit/](../exposure-audit/) |
| `awskit trail` | CloudTrail lookups, see [cloudtrail/](../cloudtrail/) |
| `awskit plan` | Plan Check, see [plan-check/](../plan-check/) |
| `awskit policy` | Policy Check, see [policy-check/](../policy-check/) |
| `awskit profile` | Profile picker, see [profiles/](../profiles/) |
| `awskit map` | Cloud Map: `scan`, `tf`, `export` (to `.drawio`, SVG or PNG), `edit` in the offline draw.io, `remember` and `layout` for the saved layout, and `design` for the designer (`new`, `edit`, `check`, `build`), see [cloud-map/](../cloud-map/) |
| `awskit shell-init bash` | Print the shell hook for `awsp` (bash, zsh, fish or powershell) |
| `awskit install` | Install to `~/.local` (what `install.sh` runs). `--drawio-zip PATH` and `--no-drawio` as above |
| `awskit uninstall` | Remove it |
| `awskit --version` | Print the version |

Every command has `--help`. Options that most AWS commands share:

| Option | What it does |
|---|---|
| `-p NAME`, `--profile NAME` | Use this AWS profile. Repeat it to cover several accounts in one run (sweep and audit). |
| `--all-profiles` | Use every profile in `~/.aws/config` (sweep and audit) |
| `-r REGION`, `--region REGION` | Only this region. Repeatable. |
| `--json` | Print JSON instead of a table |

PII Redact has its own options, like `-c` to copy and `-n` for numbered placeholders. See its README.

Without `-p`, AWS commands use the profile picked in AWS Kit, then `AWS_PROFILE`, then `default`.

Colors are turned off when the output isn't a terminal or when `NO_COLOR` is set.

Exit codes: `0` for success, `1` for an error, `2` when `--fail-on` finds something at or above the level you gave it. That makes `audit`, `plan` and `policy` easy to use in CI. `pii-redact run` keeps the exit code of the command it ran.

## Credentials

AWS Kit uses the normal boto3 credential chain, so anything that works with the AWS CLI works here: SSO profiles, `role_arn` profiles, access keys, `credential_process`, and environment variables.

It never stores credentials. For each scan, it reads the profile's credentials once and shares them between the worker threads, so an SSO profile only reads its token once even when scanning 17 regions.

When an SSO sign-in has expired, you get a plain message with the command to fix it, like `Sign-in for profile lab-admin has expired. Run: aws sso login --profile lab-admin`. On the Profiles page, **Sign in** does that for you.

AWS Kit only talks to AWS APIs. PII Redact and Image Redact don't talk to anything. There's no telemetry and nothing else leaves your machine.

## Permissions

| Tool | What it needs |
|---|---|
| PII Redact | Nothing. It never calls AWS. |
| Image Redact | Nothing. It never calls AWS. |
| Lab Sweep scan | Read access. `SecurityAudit` covers almost all of it, plus `ce:GetCostAndUsage` for the spend button. |
| Lab Sweep teardown | Delete permissions for whatever you tick. In a lab account that's usually an admin role. |
| Exposure Audit | `SecurityAudit` |
| CloudTrail | `cloudtrail:LookupEvents` |
| Plan Check | Nothing in AWS. Running a plan needs whatever your Terraform needs. |
| Policy Check | Nothing offline. `access-analyzer:ValidatePolicy` for Also ask AWS, and `iam:GetPolicy`, `iam:GetPolicyVersion` and `iam:GetRole` for Load from AWS. |
| Profiles | `sts:GetCallerIdentity` for Check all |
| Cloud Map | `SecurityAudit`, plus `budgets:ViewBudget` and `ce:GetAnomalyMonitors` for the cost box. Organizations and Identity Center need the management account or a delegated admin. Terraform maps need nothing in AWS. |

Each tool's README lists the exact actions. When a role can't read something, scans keep going and list what they couldn't check at the end instead of failing.

## Settings

Everything lives in `~/.config/awskit/`:

| File | What's in it |
|---|---|
| `config.json` | Lab Sweep, Exposure Audit and Cloud Map settings, below. Lab Sweep's **Settings** button edits it. |
| `redact.json` | PII Redact's settings. Its **Settings** window edits it. Image Redact uses them too. See [pii-redact/](../pii-redact/). |
| `image.json` | Image Redact's colors, widths and recent folders. The editor saves it as you go. See [image-redact/](../image-redact/). |
| `current-profile` | The profile picked in Profiles. See [profiles/](../profiles/). |
| `cloud-map/` | Cloud Map's labels file, redaction key, and the snapshots the page saves. See [cloud-map/](../cloud-map/#settings). |

`config.json`:

| Key | Default | What it does |
|---|---|---|
| `keep` | `[]` | IDs, ARNs or names Lab Sweep never offers to delete |
| `keep_tag` | `"awskit:keep"` | Resources with this tag key are kept, for the types where AWS lists tags (see the Lab Sweep README). Use `keep` for the rest |
| `regions` | `[]` | Regions that Lab Sweep and Exposure Audit scan. Empty means every region enabled in the account. Setting this makes scans faster if you only use a few regions. |
| `notify_threshold` | `1.0` | Lab Sweep's daily check only notifies above this many dollars a month |
| `timer_profiles` | `[]` | Profiles the daily check covers. Empty means the current one. |
| `sns_topic` | `""` | SNS topic ARN for daily check summaries |
| `known_accounts` | `[]` | Account IDs Cloud Map treats as yours when it can't read the org, so a role trusted by one of them isn't flagged |
| `cloud_map` | `{}` | What the Cloud Map page showed last. The page keeps it up to date. |

## Windows

AWS Kit runs on Windows 10 and 11 the same way it does on Linux: the same window, all nine tools, and the same commands. It's the same code, running on GTK 4 for Windows.

### Install

1. Download the repo: **Code**, then **Download ZIP** on GitHub, and extract it. Or `git clone` it.
2. Double-click `install-windows.cmd` in that folder. If Windows says it protected your PC, click **More info**, then **Run anyway**. That's because the file came from the internet.
3. It asks if you want a desktop shortcut, and if you want to open AWS Kit when it's done.

No admin rights needed. Everything goes in `%LOCALAPPDATA%\AWSKit`, for your user only. The first install downloads about 380 MB and takes a few minutes. The installer:

- uses your Python 3.14 if you have it, or installs Python 3.14 from python.org just for AWS Kit, in that folder. It has to be 3.14, since that's what the Windows build of GTK's Python bindings is made for. The installer only runs if Windows confirms it's signed by the Python Software Foundation.
- downloads GTK 4 for Windows from the [gvsbuild](https://github.com/wingtk/gvsbuild) project and unpacks only what AWS Kit needs, about 180 MB. The zip has to match the SHA-256 pinned in `install.ps1`, the same way draw.io's does
- installs PyGObject, pycairo, boto3 and Pillow into its own environment there, so it doesn't touch any other Python setup
- downloads the draw.io web app (about 48 MB) into `drawio`, checks its SHA-256 and unpacks it, for Cloud Map's AWS icons and its offline editor
- adds an **AWS Kit** folder to the Start menu with **AWS Kit**, **PII Redact**, **Image Redact** and **AWS Profile Picker**
- adds Image Redact to **Open with** for PNG, JPEG, BMP and WebP files, without changing what opens them by default
- adds `awskit`, `pii-redact` and `awsp` to your PATH for new terminals
- adds **AWS Kit** to Settings, Apps, Installed apps, which is where you remove it

To update, download the repo again and run `install-windows.cmd` again. It only downloads GTK and draw.io again when their versions change. Your settings stay.

If your network uses a proxy, set it in PowerShell and run the installer from that same window:

```powershell
$env:HTTPS_PROXY = "http://proxy.example.com:8080"
powershell -NoProfile -ExecutionPolicy Bypass -File windows\install.ps1
```

If GitHub downloads are blocked, download `GTK4_Gvsbuild_2026.8.0_x64.zip` from the gvsbuild releases page another way and pass it in with `-GtkZip C:\path\to\it.zip`, and the same for draw.io's `draw.war` (the link is in the installer's message) with `-DrawioZip C:\path\to\draw.war`. `-NoDrawio` skips draw.io, and Cloud Map then draws simple labels in place of the AWS icons and has no editor. The installer also takes `-Desktop` to add the desktop shortcut without asking, `-NoPath` to leave your PATH alone, and `-Quiet` to not ask anything.

### What's different on Windows

| Thing | On Linux | On Windows |
|---|---|---|
| Settings | `~/.config/awskit` | `%APPDATA%\awskit` |
| AWS profiles | `~/.aws` | `%USERPROFILE%\.aws`, which is where the AWS CLI keeps them on Windows too |
| `awsp` and the prompt helper | bash, zsh or fish hook | PowerShell hook, see below |
| Lab Sweep daily check | systemd user timer | Task Scheduler, as **AWS Kit Lab Sweep**, for your user only |
| Notifications | `notify-send` | Windows notifications. They show under Windows PowerShell's name. |
| Clipboard | `wl-copy` or `xclip` | The Windows clipboard |
| Image Redact text detection | tesseract | The OCR built into Windows, or Tesseract if it's installed |
| Cloud Map's draw.io editor | Inside the page, with WebKitGTK | In its own window: an Edge app window, the default browser, or draw.io desktop. GTK for Windows has no WebKitGTK. See [Editing in draw.io](../cloud-map/README.md#windows) |
| Installing | `./install.sh` | `install-windows.cmd` |

SSO sign-in from the Profiles page needs the AWS CLI v2, same as on Linux. Plan Check needs `terraform` or `tofu` on your PATH to run plans by itself.

### awsp in PowerShell

Open your PowerShell profile with `notepad $PROFILE` (say yes if it asks to create the file) and add this line:

```powershell
awskit shell-init powershell | Out-String | Invoke-Expression
```

Open a new PowerShell window. Then `awsp` opens the picker, `awsp NAME` switches, and every open PowerShell window follows at its next prompt. `__awskit_ps1` returns `(aws:NAME) ` for your own prompt function, and Starship and Oh My Posh show the profile with their aws module.

If PowerShell says running scripts is disabled, run this once. It only applies to your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Removing it

Settings, Apps, Installed apps, **AWS Kit**, **Uninstall**. That removes the Start menu folder, the Open with entry, the PATH entry, the Lab Sweep scheduled task, the Python it installed, and `%LOCALAPPDATA%\AWSKit`. Your settings in `%APPDATA%\awskit` and your profiles in `.aws` stay.

### Troubleshooting on Windows

| Problem | Fix |
|---|---|
| The installer says running scripts is disabled or blocked by policy | Your organization blocks PowerShell scripts. Ask IT, since the installer and the PowerShell hook both need them. |
| `pip couldn't install` | Usually a proxy. See the proxy example above. |
| `GTK did not load` at the end of the install | The message above it says why. Running `install-windows.cmd` again redoes anything missing. |
| The window comes up blank or flickers, often over Remote Desktop or in a VM | GTK couldn't use the GPU there. Set `GSK_RENDERER=cairo` as a user environment variable, then open AWS Kit again. |
| Something went wrong in Image Redact | Details are in `%APPDATA%\awskit\image-redact.log` |

## How the code is laid out

```text
awskit/                    shared app code (this folder)
├── __init__.py            adds the tool folders to the package path
├── __main__.py            lets python3 -m awskit run it
├── cli.py                 every command, install and uninstall
├── common.py              AWS sessions, regions, errors, export, clipboard, notifications
├── widgets.py             shared GTK pieces: tables, details pane, pickers, dialogs
└── app.py                 the main window and the small windows

pii-redact/                one folder per tool
├── redact.py              the tool itself: rules, settings, command line, no GTK
├── redact_page.py         its page in the window, plus its own small windows
├── README.md
├── docs/                  screenshots
└── examples/              something to try it on
```

Every tool folder follows the same pattern: one file with the logic, which has no GTK in it and is what the commands use, and one `_page.py` file for the window. Cloud Map splits its logic over several files (model, scan, Terraform, layout, themes, draw.io writer, renderer, icons, the editor's local server, layout memory and the designer), with `map_page.py` for its page and `map_edit.py` for editing on it. Image Redact has two more: `imageedit.py`, the editor without a window, and `image_tk.py`, a simpler tkinter window it falls back to when GTK isn't set up. Both windows drive `imageedit.py`, so they behave the same. On Windows the GTK window is used, same as on Linux.

The tool folders sit next to `awskit/` instead of inside it so that each tool is easy to find on its own. To make that work, `awskit/__init__.py` adds them to the package's search path, so `pii-redact/redact.py` loads as `awskit.redact` and can use `common.py` and `widgets.py` like any file inside the package. The installer copies the folders the same way, side by side, into `~/.local/share/awskit/`.

## Tests

The tests use [moto](https://github.com/getmoto/moto), which fakes AWS locally, so they never touch a real account. From the root of the repo:

```bash
pip install --user moto
python3 -m unittest discover -s tests -v
```

They cover PII Redact against its sample file and its settings, Image Redact's box placement, OCR cleanup, saving, renaming and moving (plus reading a real rendered screenshot when tesseract is installed), the scan and teardown logic against fake EC2, EBS, KMS, Secrets Manager and S3 resources, the audit checks, the plan and policy rules against the files in each tool's `examples/` folder, profile parsing, and Cloud Map: its Terraform input, model, layout and draw.io output against its example states (stable IDs, byte-identical output, real draw.io shape names, flags, layers and redaction), its live scan against fake Organizations, IAM, EC2 and CloudTrail, including the AccessDenied path, the renderer behind its page and its SVG and PNG export (stable sizes, hit testing at several zoom levels, redacted SVGs, the icon reader and the draw.io download check), its designer (each check against a broken example, the generated files against a saved copy, the folder rules, and a plan of the output read back into the same map), and its editor: layout memory round trips (moved boxes, captions, colors and notes surviving a rescan with a resource added and one removed, redacted files, and a file saved by the real draw.io), the local server over HTTP (tokens, paths it refuses, saving, shutting down), `awskit map edit`, and finding Edge and the fallback order with Windows mocked.

`AWSKIT_TF_TEST=1` adds a test that runs terraform or tofu on the designer's output (fmt, init, validate and an offline plan). It needs the AWS provider, from the registry or a mirror in `TF_CLI_CONFIG_FILE`. `AWSKIT_EDITOR_TEST=1` adds one more that opens the real draw.io editor in WebKitGTK, with networking blocked when `unshare` can, and checks it loads and saves without reaching anything outside the machine. It needs WebKitGTK 6.0, draw.io downloaded, and a display or `xvfb-run`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `GTK 4 for Python is missing` | Install `python3-gobject gtk4`. The commands still work without it. |
| `boto3 is missing` | `sudo dnf install python3-boto3` |
| `Sign-in ... has expired` | `aws sso login --profile NAME`, or Sign in on the Profiles page |
| A scan lists "no permission to ..." notes | The role can't read that service. The rest of the scan is still valid. |
| Scans are slow | Set `regions` in the settings to only the regions you use |
| Copying doesn't stick after closing a window | Install `wl-clipboard` (Wayland) or `xclip` (X11) |
| `pii-redact clip` says it can't reach the clipboard | Same, install `wl-clipboard` or `xclip` |
| Image Redact says it needs tesseract | `sudo dnf install tesseract tesseract-langpack-eng`. Drawing by hand works without it. |
| Image Redact crashes with `Couldn't find foreign struct converter for 'cairo.Context'` | Debian/Ubuntu: `sudo apt install python3-gi-cairo` |
| Crashes on start with `Couldn't open libGLESv2.so.2` | GTK couldn't set up the GPU. AWS Kit draws in software on WSL by itself, so this shouldn't happen there. Anywhere else, run `GSK_RENDERER=cairo awskit` or install the GLES library (Fedora: `libglvnd-gles`) |
| On WSL, `pii-redact clip` can't read the Windows clipboard | PowerShell is missing or blocked. Install `wl-clipboard` so it can fall back to the WSLg clipboard |
| Old window rules for PII Redact stopped matching | The app ID changed to `io.github.Snowblind019.AwsKit.Redact`, see [Keybinds](#keybinds) |
| Terminals don't switch profile | Add the shell hook, see [profiles/](../profiles/) |
| `awskit: command not found` | `~/.local/bin` isn't in your PATH. Fedora adds it by default for bash. |

## License

MIT. See [LICENSE](../LICENSE).
