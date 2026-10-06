# Windows installer

Installs [AWS Kit](../awskit/), with all fourteen tools and the same window as on Linux, for your Windows user, without admin rights.

To install, double-click `install-windows.cmd` in the root of the repo. It runs `install.ps1` from this folder.

The first install downloads about 380 MB, draw.io's 48 MB included. The GTK zip and draw.io are checked against the SHA-256 pinned for each, and the Python installer against its python.org signature, before anything from them runs. On a network that blocks GitHub, `-GtkZip` and `-DrawioZip` take the GTK bundle and draw.io's `draw.war` downloaded another way, and `-NoDrawio` skips draw.io (Cloud Map then has stand-in icons and no editor). Cloud Map's editor opens in an Edge app window on Windows, since GTK for Windows has no WebKitGTK, see [Editing in draw.io](../cloud-map/README.md#windows).

| File | What it is |
|---|---|
| `install.ps1` | The installer. Finds or installs Python 3.14 for your user, sets up GTK 4 for Windows, the draw.io web app (Cloud Map's icons and offline editor) and the Python packages in `%LOCALAPPDATA%\AWSKit`, and adds the Start menu folder, Open with, PATH commands and the Apps entry |
| `uninstall.ps1` | Removes all of that, plus the Lab Sweep scheduled task. The installer copies it to `%LOCALAPPDATA%\AWSKit`, and Settings, Apps, AWS Kit runs it from there |
| `awskit.ico`, `image-redact.ico` | The shortcut icons |
| `make_icons.py` | Draws the icons. Run `python3 windows/make_icons.py` after changing one |

[Windows](../awskit/README.md#windows) in AWS Kit's README has the details: what the installer does, proxies, what's different on Windows, and `awsp` in PowerShell.
