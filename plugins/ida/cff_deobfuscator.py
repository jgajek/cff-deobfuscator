"""CFF Deobfuscator -- standalone IDA Pro plugin.

Applies, in one resilient multi-pass shot:

    Layer 1   indirect-jump (`jmp <reg>`) de-indirection
    Layer 2   control-flow unflattening
    Layer 3   import / API call annotation

The plugin records its progress in the database, so running it again on an
already-processed IDB is detected and ends gracefully instead of corrupting
state. It exposes exactly two actions (Edit > Plugins, or the plugin's own
run dialog):

    CFF Deobfuscator: Dry run (report only)
    CFF Deobfuscator: Full run (patch + annotate)

Installation: copy this file together with the `cff/` package directory into
your IDA `plugins` folder (keep them side by side).
"""

import os
import sys
import traceback

import idaapi
import ida_kernwin


# Make the sibling `cff` package importable regardless of how IDA loads us.
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)


_PLUGIN_NAME = "CFF Deobfuscator"
_MENU_PATH = "Edit/Plugins/"
_ACT_DRY = "cff:dry_run"
_ACT_FULL = "cff:full_run"


def _orchestrator():
    """Import the engine lazily so a Hex-Rays-less IDA gives a clear message
    instead of a load-time traceback."""
    from cff import orchestrator
    return orchestrator


def _run_dry():
    try:
        _orchestrator().dry_run()
    except Exception:
        ida_kernwin.warning("CFF Deobfuscator dry run failed:\n\n%s"
                            % traceback.format_exc())


def _run_full():
    if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "CFF Deobfuscator -- FULL RUN\n\n"
            "This byte-patches the database (Layer 1 + Layer 2) and writes "
            "API annotations (Layer 3).\n\n"
            "Already-completed stages are detected and skipped. Proceed?"
    ) != ida_kernwin.ASKBTN_YES:
        return
    try:
        _orchestrator().full_run()
    except Exception:
        ida_kernwin.warning("CFF Deobfuscator full run failed:\n\n%s"
                            % traceback.format_exc())


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, fn):
        ida_kernwin.action_handler_t.__init__(self)
        self._fn = fn

    def activate(self, ctx):
        self._fn()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# (action id, menu label, callback)
_ACTIONS = (
    (_ACT_DRY,  "CFF Deobfuscator: Dry run (report only)",      _run_dry),
    (_ACT_FULL, "CFF Deobfuscator: Full run (patch + annotate)", _run_full),
)


def _register_actions():
    for aid, label, cb in _ACTIONS:
        try:
            ida_kernwin.unregister_action(aid)  # idempotent across reloads
            desc = ida_kernwin.action_desc_t(
                aid, label, _Handler(cb), "", "CFF deobfuscation", -1)
            ida_kernwin.register_action(desc)
            ida_kernwin.attach_action_to_menu(
                _MENU_PATH, aid, ida_kernwin.SETMENU_APP)
        except Exception as ex:
            print("[cff] failed to register %s: %r" % (aid, ex))


def _unregister_actions():
    for aid, _label, _cb in _ACTIONS:
        try:
            ida_kernwin.detach_action_from_menu(_MENU_PATH, aid)
            ida_kernwin.unregister_action(aid)
        except Exception:
            pass


class CffDeobfuscatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Multi-pass CFF deobfuscator (de-indirection + unflatten + imports)"
    help = "Apply Layer 1/2/3 CFF deobfuscation in one resilient pass"
    wanted_name = _PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        _register_actions()
        print("[cff] %s loaded -- Edit > Plugins > CFF Deobfuscator: ..."
              % _PLUGIN_NAME)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        b = ida_kernwin.ask_buttons(
            "Full run", "Dry run", "Cancel", -1,
            "CFF Deobfuscator\n\n"
            "Full run: apply Layer 1 + Layer 2 patches and Layer 3 "
            "annotations (modifies the IDB).\n"
            "Dry run: read-only report of what each layer would do.")
        if b == 1:
            _run_full()
        elif b == 0:
            _run_dry()

    def term(self):
        _unregister_actions()


def PLUGIN_ENTRY():
    return CffDeobfuscatorPlugin()
