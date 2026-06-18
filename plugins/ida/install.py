#!/usr/bin/env python3
"""Installer for the CFF Deobfuscator IDA plugin.

Copies this self-contained plugin (the `cff_deobfuscator.py` entry point, the
`cff/` engine package, and `ida-plugin.json`) into your IDA user plugins
directory so IDA's Plugin Manager discovers it on the next start.

Usage:
    python3 install.py              # install / upgrade
    python3 install.py --uninstall  # remove a previous install
    python3 install.py --dir PATH   # install into a specific IDA user dir

The IDA user directory defaults to $IDAUSR, else the platform default:
    Windows : %APPDATA%\\Hex-Rays\\IDA Pro
    Linux   : ~/.idapro
    macOS   : ~/.idapro
"""

import argparse
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIRNAME = "cff-deobfuscator"
# Items copied into the installed plugin folder.
_PAYLOAD = ("cff_deobfuscator.py", "ida-plugin.json", "cff")


def _ida_user_dir(override=None):
    if override:
        return os.path.expanduser(override)
    env = os.environ.get("IDAUSR")
    if env:
        # IDAUSR may list several paths; the first is the writable user dir.
        return os.path.expanduser(env.split(os.pathsep)[0])
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Hex-Rays", "IDA Pro")
    return os.path.expanduser(os.path.join("~", ".idapro"))


def _target_dir(user_dir):
    return os.path.join(user_dir, "plugins", _PLUGIN_DIRNAME)


def _ignore(_dir, names):
    return [n for n in names if n == "__pycache__" or n.endswith(".pyc")]


def install(user_dir):
    target = _target_dir(user_dir)
    if os.path.exists(target):
        shutil.rmtree(target)
    os.makedirs(target, exist_ok=True)
    for item in _PAYLOAD:
        src = os.path.join(_HERE, item)
        dst = os.path.join(target, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=_ignore)
        else:
            shutil.copy2(src, dst)
    print("Installed CFF Deobfuscator to:\n    %s" % target)
    print("Restart IDA (or use the Plugin Manager). The plugin appears under")
    print("    Edit > Plugins > CFF Deobfuscator: ...")


def uninstall(user_dir):
    target = _target_dir(user_dir)
    if os.path.exists(target):
        shutil.rmtree(target)
        print("Removed %s" % target)
    else:
        print("Nothing to remove at %s" % target)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Install the CFF Deobfuscator IDA plugin.")
    ap.add_argument("--uninstall", action="store_true", help="remove a previous install")
    ap.add_argument("--dir", default=None,
                    help="IDA user directory (default: $IDAUSR or platform default)")
    args = ap.parse_args(argv)

    user_dir = _ida_user_dir(args.dir)
    if not os.path.isdir(user_dir):
        print("warning: IDA user directory does not exist yet: %s" % user_dir)
        print("         (it will be created; pass --dir to choose another)")

    if args.uninstall:
        uninstall(user_dir)
    else:
        install(user_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
