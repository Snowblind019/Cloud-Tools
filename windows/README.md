# Windows installer

Installs [AWS Kit](../awskit/), with all eight tools and the same window as on Linux, for your Windows user, without admin rights.

To install, double-click `install-windows.cmd` in the root of the repo. It runs `install.ps1` from this folder.

| File | What it is |
|---|---|
| `install.ps1` | The installer. Finds or installs Python 3.14 for your user, sets up GTK 4 for Windows and the Python packages in `%LOCALAPPDATA%\AWSKit`, and adds the Start menu folder, Open with, PATH commands and the Apps entry |
| `uninstall.ps1` | Removes all of that, plus the Lab Sweep scheduled task. The installer copies it to `%LOCALAPPDATA%\AWSKit`, and Settings, Apps, AWS Kit runs it from there |
| `awskit.ico`, `image-redact.ico` | The shortcut icons |
| `make_icons.py` | Draws the icons. Run `python3 windows/make_icons.py` after changing one |

[Windows](../awskit/README.md#windows) in AWS Kit's README has the details: what the installer does, proxies, what's different on Windows, and `awsp` in PowerShell.
