"""Persistent, netnode-backed run state for the CFF deobfuscator.

The deobfuscation passes byte-patch the database, which is *not* safely
repeatable: running Layer 2 a second time over an already-unflattened function
could wire up a wrong edge. To stay resilient against repeated runs we record
what has already been done in a private netnode and consult it before patching:

  * a *completed* stage is skipped on the next full run (so a run that was
    interrupted after Layer 1 resumes cleanly at Layer 2 instead of re-patching);
  * once all stages are complete the full run is a graceful no-op.

State is a small JSON blob; if it is missing or unreadable we treat the IDB as
never processed.
"""

import json
import time

from . import __version__

_NODE_NAME = "$ cff-deobfuscator"   # '$' => private, not shown in the names list
_BLOB_TAG = "M"
_SCHEMA = 1

# Ordered deobfuscation stages. The keys double as the netnode record keys.
STAGES = ("layer1", "layer2", "layer3")
STAGE_TITLES = {
    "layer1": "Layer 1 -- indirect-jump de-indirection",
    "layer2": "Layer 2 -- control-flow unflattening",
    "layer3": "Layer 3 -- import / API call annotation",
}


def _now():
    return int(time.time())


def fmt_time(epoch):
    if not epoch:
        return "?"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except Exception:
        return str(epoch)


def _node(create=False):
    import ida_netnode
    n = ida_netnode.netnode()
    if not n.create(_NODE_NAME) and create:
        # create() returns False when it already existed -- that is fine, the
        # node is still bound; `create` flag here only documents intent.
        pass
    return n


def _empty():
    return {"schema": _SCHEMA, "version": __version__,
            "created": None, "updated": None, "stages": {}}


def load():
    """Return the stored state dict, or a fresh empty one."""
    try:
        raw = _node().getblob(0, _BLOB_TAG)
    except Exception:
        raw = None
    if not raw:
        return _empty()
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        d = json.loads(raw)
    except Exception:
        return _empty()
    if not isinstance(d, dict) or "stages" not in d:
        return _empty()
    return d


def save(d):
    d["updated"] = _now()
    if not d.get("created"):
        d["created"] = d["updated"]
    try:
        buf = json.dumps(d).encode("utf-8")
        _node(create=True).setblob(buf, 0, _BLOB_TAG)
    except Exception:
        pass


def stage_record(d, name):
    return d.get("stages", {}).get(name) or {}


def stage_done(d, name):
    return bool(stage_record(d, name).get("done"))


def mark_stage(d, name, stats):
    """Record `name` as completed (with its summary stats) and persist."""
    d.setdefault("stages", {})[name] = {
        "done": True, "finished": _now(), "stats": stats or {}}
    save(d)
    return d


def is_complete(d):
    return all(stage_done(d, s) for s in STAGES)


def any_done(d):
    return any(stage_done(d, s) for s in STAGES)


def reset():
    """Forget all recorded state (the IDB itself is left untouched)."""
    try:
        _node().kill()
    except Exception:
        pass
