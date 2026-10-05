# Cloud Tools

![Cloud](https://img.shields.io/badge/Cloud-AWS-FF9900) ![IaC](https://img.shields.io/badge/IaC-Terraform-7B42BC) ![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB) ![GTK](https://img.shields.io/badge/GTK-4-4A86CF) ![Platform](https://img.shields.io/badge/Platform-Linux-FCC624) ![Windows](https://img.shields.io/badge/Platform-Windows-0078D4) [![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

These are small tools I made for my own AWS and Terraform work on Fedora. Each one started from something that kept slowing me down while working on my [aws-platform](https://github.com/Snowblind019/aws-platform) projects and lab accounts: redacting output and screenshots before asking for help, leftover resources costing money, chasing down AccessDenied errors, reading long Terraform plans, and keeping track of which AWS account I'm in.

They all live in one Linux app called **AWS Kit**: one GTK 4 window with a sidebar of all nine tools, plus commands for everything in the terminal.

https://github.com/user-attachments/assets/0f908fbd-b985-4e66-84f2-98f8df8eb8e5

*A short tour of all nine tools in the real app. Every account, key and name in it is made up.*

## How I built these

I built these with AI. I used Claude to help me brainstorm the ideas, plan how each tool should work, and write most of the code. The problems they solve are mine, and I decided which tools to make and what they needed to do.

## The tools

| Tool | What it does | Why I made it |
|---|---|---|
| [**PII Redact**](pii-redact/) | Swaps account IDs, keys, ARNs, emails and other identifying info for `[Redacted]` in Terraform, AWS CLI or any other output | Redacting output by hand every time I needed help troubleshooting got tedious |
| [**Image Redact**](image-redact/) | Reads the text in a screenshot and covers the same things with solid boxes, with drawing tools to fix it up, and rename and move built in. | I was covering things in screenshots by hand in Gradia every time I shared one |
| [**Lab Sweep**](lab-sweep/) | Finds anything still costing money in every region across your accounts, and tears it down after you confirm | Forgotten NAT gateways and Elastic IPs from labs keep billing, and the old lab accounts from my previous org needed cleaning up |
| [**Exposure Audit**](exposure-audit/) | Looks for things open to the internet or missing basic protection, like open security groups, public buckets and snapshots, and IMDSv1 | I wanted a small scanner I wrote and understand, like a mini Prowler |
| [**CloudTrail**](cloudtrail/) | Shows who did what and when from CloudTrail event history, and explains AccessDenied errors | Debugging permission errors in my own builds meant digging through raw CloudTrail events |
| [**Plan Check**](plan-check/) | Turns a Terraform plan into a short list of changes and flags the risky ones | Long plans are easy to skim past, and a destroyed bucket or an open port can hide in the middle |
| [**Policy Check**](policy-check/) | Checks an IAM policy for wildcards, privilege escalation paths, public access and weak GitHub OIDC trust | I wanted a quick way to sanity check policies before putting them in Terraform |
| [**Profiles**](profiles/) | Picks which AWS profile your terminals use from a small window or `awsp`, with SSO sign-in status | Once my AWS Organization has several accounts, it's easy to run a command in the wrong one |
| [**Cloud Map**](cloud-map/) | Draws an AWS environment, live or from Terraform, with AWS icons: an access map (org, accounts, Identity Center, roles, who trusts what) or a network map (VPCs, subnets, routing), with security problems marked in red. Shown on its own page with pan, zoom, search and details, edited in an offline draw.io that remembers where you moved things, and exported as draw.io, SVG or PNG. Its designer goes the other way: draw a network, get Terraform for it | I wanted clear diagrams of my AWS setup that stay right when things change, instead of a picture that goes out of date |

Each tool's code and in-depth README live in its own folder. The parts they share, like the window, the commands and the installer, live in [awskit/](awskit/), which has its own README too.

PII Redact is built into the others. Every **Copy redacted** button in AWS Kit runs text through it with your settings, so a CloudTrail event, an audit finding or a plan summary can be shared without leaking account details. Image Redact uses the same rules and settings for screenshots.

## Install

On Fedora:

```bash
sudo dnf install python3-boto3 python3-gobject gtk4 wl-clipboard tesseract tesseract-langpack-eng
git clone https://github.com/Snowblind019/cloud-tools.git
cd cloud-tools
./install.sh
```

| Distro | Packages |
|---|---|
| Fedora | `python3-boto3 python3-gobject gtk4 wl-clipboard tesseract tesseract-langpack-eng` |
| Debian / Ubuntu | `python3-boto3 python3-gi python3-gi-cairo gir1.2-gtk-4.0 wl-clipboard tesseract-ocr` |
| Windows | Nothing. `install-windows.cmd` sets everything up for your user. |
| Arch | `python-boto3 python-gobject python-cairo gtk4 wl-clipboard tesseract tesseract-data-eng` |
| Optional, for Cloud Map's built-in editor | WebKitGTK 6.0: `webkitgtk6.0` on Fedora, `gir1.2-webkit-6.0` on Debian and Ubuntu, `webkitgtk-6.0` on Arch. Without it, the editor opens in its own browser window |

On X11, use `xclip` instead of `wl-clipboard`. PII Redact, Image Redact, Plan Check, Policy Check and Cloud Map's Terraform maps don't need boto3. Tesseract is only for Image Redact finding text by itself.

Everything installs into your home folder: the `awskit` and `pii-redact` commands in `~/.local/bin`, and launcher entries for **AWS Kit**, **PII Redact**, **PII Redact Settings**, **Image Redact** and **AWS Profile Picker**. Image Redact also shows up under Open With for images. The installer also downloads the draw.io web app (about 48 MB, 110 MB unpacked) for Cloud Map's AWS icons and its offline editor. If GitHub is blocked, `./install.sh --drawio-zip PATH` takes a copy you downloaded another way, see [Install](awskit/README.md#install). To update, run `git pull && ./install.sh`. To remove it all, run `awskit uninstall`.

If you had the standalone pii-redact installed before, your settings carry over and the old launcher entries are cleaned up.

### Windows

All of AWS Kit runs on Windows 10 and 11 too, natively, with the same window and all nine tools. Double-click `install-windows.cmd`. It installs for your user only, without admin rights, and adds an AWS Kit folder to the Start menu. [Windows](awskit/README.md#windows) in AWS Kit's README has the details.

### WSL

AWS Kit also runs on WSL2 with WSLg. Install the same packages inside the distro and run `./install.sh` as usual. A few things work differently there:

- The windows draw in software instead of on the GPU. WSL usually doesn't have a GL driver GTK can use, and GTK 4 crashes on startup without one, so AWS Kit switches to software drawing by itself. To try the GPU anyway, run `GSK_RENDERER=ngl awskit`.
- Copying goes straight to the Windows clipboard through `clip.exe`, and `pii-redact clip` reads it back with PowerShell, so you can copy in any Windows app, run it, and paste. wl-clipboard isn't needed, but it's used as a fallback if PowerShell is blocked.
- Image Redact pastes and copies images through the Windows clipboard with PowerShell too, so a screenshot from Win+Shift+S pastes straight in, and the finished image pastes into any Windows app.
- Cloud Map's editor tries WebKitGTK with its GPU paths turned off. If it won't start, it opens in Windows instead, in Edge's app window or the default browser, and saves still come back to the map.
- Desktop notifications, like the one `pii-redact clip` shows and the scheduled Lab Sweep ones, usually don't show up in Windows. Set `sns_topic` in the settings to get sweep summaries through SNS instead. The schedule also only runs while WSL is running.

## Quick start

| Command | What it does |
|---|---|
| `awskit` | Open the AWS Kit window |
| `pii-redact` | Open the small PII Redact paste window |
| `pii-redact clip` | Redact whatever is on the clipboard, in place |
| `awskit image` | Open Image Redact to cover things in a screenshot |
| `awskit image shot.png -o out.png` | Cover what it finds in a screenshot, without a window |
| `terraform plan \| pii-redact` | Redact command output in the terminal |
| `awskit sweep` | List what's costing money in every region |
| `awskit audit -v` | Run the exposure checks |
| `awskit trail --mine --errors --since 2h` | My own failed AWS calls in the last 2 hours |
| `awskit plan` | Run `terraform plan` here and summarize it |
| `awskit policy policy.json` | Check a policy |
| `awskit map --type network -o lab.drawio` | Draw the current account's network as a draw.io diagram |
| `awskit map tf . -o lab.cloudmap.json` | Read this Terraform folder into a snapshot, then draw it with `awskit map export` |
| `awskit map export lab.cloudmap.json --type network -o lab.png` | Draw a snapshot as a picture (`.drawio`, `.svg` or `.png`) |
| `awskit map edit lab.cloudmap.json --type network` | Open it in the offline draw.io editor and keep the layout for the next scan |
| `awskit map design build lab.drawio` | Turn a network drawn with the designer into Terraform, in `lab-tf/` |
| `awsp` | Pick the AWS profile for your terminals |

Each tool's README has the full details.

## Keybinds

The quickest way to use these is from keybinds: one for the PII Redact paste window, one to redact the clipboard in place, one for Image Redact, one for the profile picker and one for the main window. [AWS Kit's README](awskit/README.md#keybinds) has them for Niri, Hyprland, Sway, i3, GNOME and KDE, with window rules so the small windows float.

## Repo layout

```text
cloud-tools/
├── README.md            this file
├── install.sh           installs AWS Kit with all nine tools
├── install-windows.cmd  installs AWS Kit on Windows, no admin needed
├── LICENSE
├── awskit/              the shared app: window, commands, installer, keybinds
├── pii-redact/          redact account IDs, keys and personal info from output
├── image-redact/        cover the same things in screenshots, with drawing tools
├── windows/             the Windows installer and uninstaller
├── lab-sweep/           cost watchdog and teardown
├── exposure-audit/      public access and missing protection checks
├── cloudtrail/          who did what, from CloudTrail
├── plan-check/          Terraform plan summary and risk flags
├── policy-check/        IAM policy checker
├── profiles/            AWS profile switcher and shell integration
├── cloud-map/           access and network maps, live or from Terraform, and a designer that writes Terraform
└── tests/               tests, with AWS calls run against a fake AWS
```

## Status

PII Redact gives the same output it did as a standalone tool, checked against its sample file. Image Redact has been tested on light and dark screenshots of that same sample, with tesseract 5, in its Linux window. The Windows version was run under Wine, with a real Windows build of Python 3.14 and the Windows GTK 4 bundle the installer uses: every page of the main window, the PII Redact, Image Redact and profile picker windows, and the commands all ran. The installer, Windows OCR, toasts, Task Scheduler and the Windows clipboard haven't been tried on a real Windows machine yet. The PowerShell scripts were checked with PowerShell 7, and the PowerShell profile hook was run there. Cloud Map's maps were checked by rendering its examples with draw.io desktop 31.7.0's own exporter. Its page was driven under Xvfb with real mouse and keyboard input (pan, zoom, clicks, search, layers, themes, export), and against a fake AWS for Scan now. Its editor was driven the same way inside the page with WebKitGTK (a real drag in draw.io, then Done) and in its own window, with a stand-in for the browser, and it was run with networking blocked to check it loads, saves and reaches nothing outside the machine. Its designer was driven the same way (real drags from its shape library, then Done and Build), and the Terraform it writes was checked with OpenTofu 1.13 and AWS provider 6.67: fmt, init, validate, and a plan read back into the same map. Edge's app window on Windows and the WSL fallback haven't been tried on a real machine yet. Its live scan has been tested against fake AWS (moto), not against a real account yet.

To run the tests:

```bash
pip install --user moto
python3 -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).

These are personal projects and aren't affiliated with or endorsed by Amazon Web Services.
