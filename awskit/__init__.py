"""AWS Kit: the app that ties the tools in this repo together.

Each tool keeps its code in its own folder next to this one (pii-redact/,
image-redact/, lab-sweep/, plan-check/, cloud-map/ and so on). Adding those folders to this
package's search path lets their files load as awskit.<module>, so they can share
common.py and widgets.py.
"""
import os as _os

TOOL_DIRS = ("pii-redact", "image-redact", "secrets-scan", "lab-sweep", "exposure-audit",
             "credentials", "cloudtrail", "least-privilege", "plan-check", "drift",
             "policy-check", "org-scps", "profiles", "cloud-map")

_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _name in TOOL_DIRS:
    _path = _os.path.join(_root, _name)
    if _os.path.isdir(_path) and _path not in __path__:
        __path__.append(_path)

_dll_dirs = []


def _windows_gtk():
    """On Windows, GTK comes from the bundle the installer puts in %LOCALAPPDATA%\\AWSKit\\gtk
    (or wherever AWSKIT_GTK points). Python only loads DLLs from folders it's told about,
    so this has to run before anything imports gi."""
    gtk = _os.environ.get("AWSKIT_GTK") or _os.path.join(
        _os.environ.get("LOCALAPPDATA", ""), "AWSKit", "gtk")
    bin_dir = _os.path.join(gtk, "bin")
    if not _os.path.isdir(bin_dir):
        return
    if bin_dir not in _os.environ.get("PATH", "").split(_os.pathsep):
        _os.environ["PATH"] = bin_dir + _os.pathsep + _os.environ.get("PATH", "")
    try:
        _dll_dirs.append(_os.add_dll_directory(bin_dir))
    except (AttributeError, OSError):
        pass
    _os.environ.setdefault("GI_TYPELIB_PATH", _os.path.join(gtk, "lib", "girepository-1.0"))
    _os.environ.setdefault("XDG_DATA_DIRS", _os.path.join(gtk, "share"))


if _os.name == "nt":
    _windows_gtk()

from .common import VERSION as __version__  # noqa: E402,F401
