"""Multi-pass driver for the CFF deobfuscator.

Two entry points:

    dry_run()   -- read-only. Reports what each layer would do against the
                   database's *current* state. Never writes.
    full_run()  -- applies all three layers in order, recording progress so a
                   repeated or interrupted run is resilient (completed stages
                   are skipped instead of re-patching).

Both print a single, uniform report to IDA's Output window.
"""

import time

from . import layer1 as L1
from . import layer2 as L2
from . import imports as L3
from . import runstate
from . import log
from . import __version__


# ---------------------------------------------------------------------------
# stat summarisers (turn each engine's native return value into a flat dict)
# ---------------------------------------------------------------------------
def _sum_l1_patch(results):
    results = results or []
    return {
        "functions": len(results),
        "patched": sum(len(r.get("patched", [])) for r in results),
        "refused": sum(len(r.get("refused", [])) for r in results),
        "unresolved": sum(len(r.get("unresolved", [])) for r in results),
    }


def _sum_l1_report(reports):
    reports = reports or []
    return {
        "functions": len(reports),
        "resolvable": sum(len(r.get("resolved", {})) for r in reports),
        "unresolved": sum(len(r.get("unresolved", [])) for r in reports),
    }


# ---------------------------------------------------------------------------
# full run
# ---------------------------------------------------------------------------
def _stage_layer1(st):
    if runstate.stage_done(st, "layer1"):
        log.skip("Stage 1/3 already done (%s) -- skipping Layer 1."
                 % runstate.fmt_time(runstate.stage_record(st, "layer1").get("finished")))
        return
    log.stage(1, 3, runstate.STAGE_TITLES["layer1"])
    L1.ensure_decompiler_limit()
    stats = _sum_l1_patch(L1.patch_all())
    runstate.mark_stage(st, "layer1", stats)
    log.ok("Layer 1: rewrote %d indirect jump(s) across %d function(s) "
           "(%d refused, %d unresolved)."
           % (stats["patched"], stats["functions"],
              stats["refused"], stats["unresolved"]))


def _stage_layer2(st):
    if runstate.stage_done(st, "layer2"):
        log.skip("Stage 2/3 already done (%s) -- skipping Layer 2."
                 % runstate.fmt_time(runstate.stage_record(st, "layer2").get("finished")))
        return
    log.stage(2, 3, runstate.STAGE_TITLES["layer2"])
    res = L2.unflatten_all(do_apply=True)
    stats = {"unflattened": res.get("unflattened", 0),
             "folded_only": res.get("folded_only", 0),
             "skipped": len(res.get("skipped", []))}
    runstate.mark_stage(st, "layer2", stats)
    log.ok("Layer 2: unflattened %d function(s), opaque-folded %d, skipped %d."
           % (stats["unflattened"], stats["folded_only"], stats["skipped"]))


def _stage_layer3(st):
    if runstate.stage_done(st, "layer3"):
        log.skip("Stage 3/3 already done (%s) -- skipping Layer 3."
                 % runstate.fmt_time(runstate.stage_record(st, "layer3").get("finished")))
        return
    log.stage(3, 3, runstate.STAGE_TITLES["layer3"])
    res = L3.annotate_all(apply=True)
    stats = {"functions": res.get("funcs", 0), "calls": res.get("calls", 0),
             "resolved": res.get("resolved", 0), "distinct": res.get("distinct", 0)}
    runstate.mark_stage(st, "layer3", stats)
    log.ok("Layer 3: annotated %d of %d indirect call(s) (%d distinct API(s)) "
           "across %d function(s)."
           % (stats["resolved"], stats["calls"],
              stats["distinct"], stats["functions"]))


def full_run():
    """Apply Layer 1 + Layer 2 + Layer 3 in one resilient, idempotent pass."""
    log.banner("CFF Deobfuscator v%s -- FULL RUN (modifies the database)" % __version__)
    st = runstate.load()

    if runstate.is_complete(st):
        log.warn("This database has already been fully deobfuscated on %s."
                 % runstate.fmt_time(st.get("updated")))
        log.warn("Nothing to do. (To force a re-run, reset the state first.)")
        _print_recorded_summary(st)
        return st

    if runstate.any_done(st):
        log.info("Resuming a previous run -- completed stages will be skipped.")

    t0 = time.time()
    _stage_layer1(st)
    _stage_layer2(st)
    _stage_layer3(st)

    log.banner("FULL RUN COMPLETE (%.1fs)" % (time.time() - t0))
    _print_recorded_summary(st)
    log.info("Tip: re-running is safe -- a completed database is detected and "
             "left untouched.")
    return st


# ---------------------------------------------------------------------------
# dry run
# ---------------------------------------------------------------------------
def dry_run():
    """Report what each layer would do. Read-only -- never writes the IDB."""
    log.banner("CFF Deobfuscator v%s -- DRY RUN (report only, no changes)" % __version__)
    st = runstate.load()
    if runstate.is_complete(st):
        log.info("State: already fully deobfuscated on %s."
                 % runstate.fmt_time(st.get("updated")))
    elif runstate.any_done(st):
        done = [s for s in runstate.STAGES if runstate.stage_done(st, s)]
        log.info("State: partial run recorded (done: %s)." % ", ".join(done))
    else:
        log.info("State: never processed.")
    log.info("Numbers below reflect the database's CURRENT contents; on an "
             "un-deobfuscated IDB Layer 2/3 figures are estimates.")

    t0 = time.time()

    log.stage(1, 3, "Layer 1 -- flattened-function discovery (read-only)")
    l1 = _sum_l1_report(L1.report_all())
    log.info("Layer 1: %d flattened function(s); %d resolvable indirect jump(s), "
             "%d unresolved." % (l1["functions"], l1["resolvable"], l1["unresolved"]))

    log.stage(2, 3, "Layer 2 -- unflattening recoverability (read-only)")
    l2reports = L2.report_all()
    clean = sum(1 for r in l2reports if r.get("clean"))
    log.info("Layer 2: %d flattened function(s); %d fully recoverable."
             % (len(l2reports), clean))

    log.stage(3, 3, "Layer 3 -- import / API call resolution (read-only)")
    res = L3.annotate_all(apply=False)
    log.info("Layer 3: would annotate %d of %d indirect call(s) (%d distinct "
             "API(s)) across %d function(s)."
             % (res.get("resolved", 0), res.get("calls", 0),
                res.get("distinct", 0), res.get("funcs", 0)))

    log.banner("DRY RUN COMPLETE (%.1fs)" % (time.time() - t0))
    log.info("No changes were made. Use the full run to apply patches and "
             "annotations.")
    return {"layer1": l1,
            "layer2": {"flattened": len(l2reports), "clean": clean},
            "layer3": res}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _print_recorded_summary(st):
    log.line("")
    log.line("  Recorded results:")
    for name in runstate.STAGES:
        rec = runstate.stage_record(st, name)
        if not rec.get("done"):
            log.line("    - %-7s : not done" % name)
            continue
        stats = rec.get("stats", {})
        parts = ", ".join("%s=%s" % (k, v) for k, v in sorted(stats.items()))
        log.line("    - %-7s : %s  (%s)"
                 % (name, parts or "done", runstate.fmt_time(rec.get("finished"))))
