"""Shared console output for the CFF deobfuscator.

The layer engines already emit their own `[layer1]` / `[layer2]` progress
lines; this module only adds the orchestrator's top-level banners and a small,
uniform status vocabulary so the whole run reads as one report in IDA's Output
window.
"""

_WIDTH = 76


def msg(s):
    """Write to IDA's Output window (falls back to stdout outside IDA)."""
    try:
        import ida_kernwin
        ida_kernwin.msg(s)
    except Exception:
        print(s, end="")


def line(s=""):
    msg(s + "\n")


def rule(ch="-"):
    line(ch * _WIDTH)


def banner(title):
    line("")
    rule("=")
    line("  " + title)
    rule("=")


def stage(idx, total, title):
    line("")
    rule("-")
    line("  STAGE %d/%d -- %s" % (idx, total, title))
    rule("-")


def info(s):
    line("  [*] " + s)


def ok(s):
    line("  [+] " + s)


def warn(s):
    line("  [!] " + s)


def skip(s):
    line("  [-] " + s)
