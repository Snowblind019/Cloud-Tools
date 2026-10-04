"""AWS Kit: the app that ties the tools in this repo together.

Each tool keeps its code in its own folder next to this one (pii-redact/,
image-redact/, lab-sweep/, plan-check/ and so on). Adding those folders to this
package's search path lets their files load as awskit.<module>, so they can share
common.py and widgets.py.
"""
import os as _os

TOOL_DIRS = ("pii-redact", "image-redact", "lab-sweep", "exposure-audit", "cloudtrail",
             "plan-check", "policy-check", "profiles")

_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _name in TOOL_DIRS:
    _path = _os.path.join(_root, _name)
    if _os.path.isdir(_path) and _path not in __path__:
        __path__.append(_path)

from .common import VERSION as __version__  # noqa: E402,F401
