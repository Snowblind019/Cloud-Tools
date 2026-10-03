#!/usr/bin/env bash
# Installs AWS Kit, with all seven tools, for your user. No sudo needed for this part.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

missing=()
python3 -c 'import gi; gi.require_version("Gtk", "4.0")' 2>/dev/null || missing+=("GTK 4 for Python")
python3 -c 'import boto3' 2>/dev/null || missing+=("boto3")
wsl=""
if [[ -n "${WSL_DISTRO_NAME:-}" ]] || grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  wsl=1
fi
if [[ -n "$wsl" ]] && { command -v clip.exe >/dev/null || [[ -x /mnt/c/Windows/System32/clip.exe ]]; }; then
  :  # On WSL, copying goes straight to the Windows clipboard.
elif [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
  command -v wl-copy >/dev/null || missing+=("wl-clipboard")
elif [[ -n "${DISPLAY:-}" ]]; then
  command -v xclip >/dev/null || command -v xsel >/dev/null || missing+=("xclip")
fi

if (( ${#missing[@]} )); then
  echo "Missing: ${missing[*]}"
  echo
  echo "  Fedora:        sudo dnf install python3-boto3 python3-gobject gtk4 wl-clipboard"
  echo "  Debian/Ubuntu: sudo apt install python3-boto3 python3-gi gir1.2-gtk-4.0 wl-clipboard"
  echo "  Arch:          sudo pacman -S python-boto3 python-gobject gtk4 wl-clipboard"
  echo "  On X11, use xclip instead of wl-clipboard."
  echo
  echo "Without GTK, everything still works from the terminal. Without boto3, PII Redact,"
  echo "Plan Check and Policy Check still work. The clipboard tool is for pii-redact clip"
  echo "and copying that sticks around after a window closes."
  read -rp "Install anyway? [y/N] " answer
  [[ "${answer,,}" == y* ]] || exit 1
fi

command -v aws >/dev/null || echo "Note: the AWS CLI is needed for SSO sign-in from the Profiles page (Fedora: sudo dnf install awscli2)."
command -v terraform >/dev/null || command -v tofu >/dev/null || \
  echo "Note: Plan Check can only run plans itself if terraform or tofu is installed."

python3 -m awskit install
