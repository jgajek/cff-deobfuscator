"""
cff.layer2 - Layer 2 (control-flow unflattening) for the CFF sample.

Layer 1 (cff.layer1) rewrites every reachable indirect dispatch jump
into a direct jump, so each obfuscated function becomes a real CFG: a state
machine with

  * a per-function 32-bit STATE VARIABLE (a stack slot),
  * a DISPATCHER: a signed binary-search compare tree over the state
    (`cmp eax, IMM ; jg/jle` interior nodes, `cmp eax, STATE ; jz/jnz` leaves),
  * REAL BLOCKS, each reached from a leaf, that do work and then write the
    NEXT state (an imm32 for an unconditional edge, or a cmov-selected choice
    of two imm32 for a conditional edge) before jumping back to the dispatcher.

Layer 2 recovers the original control flow:

  1. Identify the state variable and build the backbone map
     {state_value -> real block head}.
  2. Resolve, per real block, the next state(s) it writes -- reusing the
     Layer-1 emulator (`Emu`) so cross-block register hand-offs and the
     per-function decode keys are handled concretely. A block is classified as
     UNCONDITIONAL (one next state), CONDITIONAL (two next states selected by a
     recovered compare), or TERMINAL (returns).
  3. (backends, separate) rewrite the CFG: redirect each block straight to its
     real successor(s) and remove the dispatcher scaffolding.

This module is read-only for the analysis stage (StateMachine / PerHopResolver).
The byte-patch backend (PerHopPatcher) lives below and is opt-in.
"""

import re
import time

import idc
import idautils
import ida_funcs
import ida_bytes
import ida_ua
import ida_nalt
import ida_segment

from . import layer1 as L1


U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF

# Conditional-jump mnemonics (used to find dispatcher leaf branches).
_JCC = set(
    "jo jno js jns je jz jne jnz jb jnae jc jnb jae jnc jbe jna ja jnbe "
    "jl jnge jge jnl jle jng jg jnle jp jpe jnp jpo".split()
)
# Interior (navigation) vs leaf (match) condition codes in the compare tree.
_LEAF_TAKEN = ("jz", "je")        # match == taken edge
_LEAF_FALLTHROUGH = ("jnz", "jne")  # match == fall-through edge

# Condition-code inverse, for emitting the branch that selects the other state.
_CC_INVERT = {
    "o": "no", "no": "o", "s": "ns", "ns": "s", "e": "ne", "ne": "e",
    "z": "nz", "nz": "z", "b": "ae", "c": "nc", "nae": "nb", "ae": "b",
    "nb": "nae", "nc": "c", "be": "a", "na": "nbe", "a": "be", "nbe": "na",
    "l": "ge", "nge": "nl", "ge": "l", "nl": "nge", "le": "g", "ng": "nle",
    "g": "le", "nle": "ng", "p": "np", "pe": "po", "np": "p", "po": "pe",
}


def _flag_neutral(mn):
    """True for instructions that do not modify flags (so a cmp/test can be
    separated from its consuming jcc/cmov by them)."""
    return mn in ("mov", "movzx", "movsx", "movsxd", "lea", "nop", "push",
                  "pop", "xchg", "bswap", "prefetcht0")


# ---------------------------------------------------------------------------
# state-machine structural analysis (read-only)
# ---------------------------------------------------------------------------
class StateMachine(object):
    """Identify the state variable, the dispatcher compare tree, and the
    backbone map {state_value -> real block head} for one function."""

    def __init__(self, func_ea):
        f = ida_funcs.get_func(func_ea)
        if f is None:
            raise ValueError("no function at %#x" % func_ea)
        self.FS = f.start_ea
        self.FE = f.end_ea
        self.name = idc.get_func_name(self.FS)
        self.state_op = None     # printed operand text of the state slot
        self.state_reg = None    # register the dispatcher loads the state into
        self.backbone = {}       # state value -> real block head ea
        self.tree_cmps = set()   # addresses of dispatcher leaf/interior compares
        self.state_loads = set() # addresses of `mov state_reg, state_op`
        self._detect_state_var()
        if self.state_reg is not None:
            self._build_backbone()

    # --- state variable detection (value-based) ---
    def _detect_state_var(self):
        # The dispatcher compares the STATE REGISTER against a large set of
        # imm32 constants (the binary-search tree); the real blocks store those
        # same constants as the NEXT state. We therefore identify the state
        # register purely by VALUE overlap: the register whose `cmp reg, imm32`
        # comparand set overlaps most with the set of imm32 values written to
        # memory. This is robust to how the state slot is addressed -- a fixed
        # stack operand (`mov [rbp+x], imm`) in small functions, or a pointer
        # register cached from the stack (`mov rax,[rbp+x]; mov [rax], imm`) and
        # a global+key buffer in the large ones. The old operand-text match only
        # handled the former and silently missed every large function.
        cmp_imms = {}
        store_vals = set()
        for h in idautils.Heads(self.FS, self.FE):
            mn = idc.print_insn_mnem(h)
            if (mn == "cmp" and idc.get_operand_type(h, 0) == idc.o_reg
                    and idc.get_operand_type(h, 1) == idc.o_imm):
                r = idc.print_operand(h, 0)
                cmp_imms.setdefault(r, set()).add(idc.get_operand_value(h, 1) & U32)
            elif (mn == "mov"
                  and idc.get_operand_type(h, 0) in (idc.o_displ, idc.o_phrase,
                                                     idc.o_mem)
                  and idc.get_operand_type(h, 1) == idc.o_imm):
                store_vals.add(idc.get_operand_value(h, 1) & U32)
        best = (0, None)
        for r, imms in cmp_imms.items():
            inter = len(imms & store_vals)
            if inter > best[0]:
                best = (inter, r)
        if best[0] >= 3:
            self.state_reg = best[1]

    def _is_state_load(self, ea):
        return (idc.print_insn_mnem(ea) == "mov"
                and idc.print_operand(ea, 0) == self.state_reg
                and idc.print_operand(ea, 1) == self.state_op)

    def _is_tree_cmp(self, ea):
        return (idc.print_insn_mnem(ea) == "cmp"
                and idc.print_operand(ea, 0) == self.state_reg
                and idc.get_operand_type(ea, 1) == idc.o_imm)

    def _next_jcc(self, h):
        a = idc.next_head(h, self.FE)
        for _ in range(8):
            if a == idc.BADADDR:
                return None
            mn = idc.print_insn_mnem(a)
            if mn in _JCC:
                return a
            if mn in ("cmp", "test"):
                return None
            if not _flag_neutral(mn):
                return None
            a = idc.next_head(a, self.FE)
        return None

    # --- backbone map ---
    def _build_backbone(self):
        # Each dispatcher leaf `cmp eax, STATE ; jz/jnz T` maps STATE -> real
        # block: jz/je takes the match edge (T); jnz/jne falls through.
        # Interior `jg/jle` nodes only navigate and are skipped. A `cmp eax,imm`
        # only counts as a dispatcher node if a tree jcc consumes it -- this
        # excludes incidental real conditionals that compare the state register
        # (e.g. `cmp eax, -1 ; ... ; cmovz`).
        _tree_jcc = set(_LEAF_TAKEN) | set(_LEAF_FALLTHROUGH) | {
            "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
            "jnle", "jnl", "jnge", "jng", "jnbe", "jnb", "jnae", "jna"}
        for h in idautils.Heads(self.FS, self.FE):
            # the dispatcher reloads the state into the state register from
            # memory (`mov eax, [slot]` / `mov eax, [global+key]`); record those
            # so block scans know where the dispatcher begins.
            if (idc.print_insn_mnem(h) == "mov"
                    and idc.print_operand(h, 0) == self.state_reg
                    and idc.get_operand_type(h, 1) in (idc.o_displ, idc.o_phrase,
                                                       idc.o_mem)):
                self.state_loads.add(h)
            if not self._is_tree_cmp(h):
                continue
            jcc = self._next_jcc(h)
            if jcc is None:
                continue
            mn = idc.print_insn_mnem(jcc)
            if mn not in _tree_jcc:
                continue
            self.tree_cmps.add(h)
            state = idc.get_operand_value(h, 1) & U32
            if mn in _LEAF_TAKEN:
                self.backbone[state] = idc.get_operand_value(jcc, 0)
            elif mn in _LEAF_FALLTHROUGH:
                self.backbone[state] = idc.next_head(jcc, self.FE)
        # Drop incidental char/byte comparisons that reuse the state register.
        # A genuine dispatcher leaf owns a UNIQUE head, and real state constants
        # are random 32-bit values; when several states map to one head, the
        # small (< 0x10000) ones are data compares -- e.g. a JSON parser's
        # `cmp eax, 0x20` (space) sharing the state register -- not states. This
        # leaves the real (large) state that owns the head intact.
        head_count = {}
        for hd in self.backbone.values():
            head_count[hd] = head_count.get(hd, 0) + 1
        for s in [s for s, hd in self.backbone.items()
                  if head_count[hd] > 1 and s < 0x10000]:
            del self.backbone[s]

    def looks_flattened(self):
        # A real CFF dispatcher maps each state to its own block; a plain
        # switch/jump table (e.g. a byte field with several cases sharing a
        # target) collapses many states onto few heads. Require both enough
        # states and enough DISTINCT target heads to avoid that false positive.
        if self.state_reg is None or len(self.backbone) < 3:
            return False
        return len(set(self.backbone.values())) >= 3


# ---------------------------------------------------------------------------
# recovered-CFG link description
# ---------------------------------------------------------------------------
class Link(object):
    """One recovered next-state STORE site (a `mov [state_slot], X`).

    Each is block-private: the contiguous run from the store through its inline
    decode tail belongs to exactly one block, so it can be rewritten in place.

    kind == 'uncond'  : single edge -> backbone[next_state].
    kind == 'cond'    : two edges; when `cc` holds (at `cmp_ea`) -> true_state,
                        else -> false_state (a cmov-selected store).
    """

    def __init__(self, store_ea, kind, **kw):
        self.store_ea = store_ea
        self.kind = kind
        self.next_state = kw.get("next_state")  # uncond
        self.true_state = kw.get("true_state")  # cond
        self.false_state = kw.get("false_state")
        self.cc = kw.get("cc")                  # cond: cc selecting true_state
        self.cmp_ea = kw.get("cmp_ea")          # cond: the governing compare
        self.cmov_ea = kw.get("cmov_ea")        # cond: the selecting cmov

    def __repr__(self):
        if self.kind == "uncond":
            return "<uncond @%#x -> %#x>" % (self.store_ea, self.next_state)
        return ("<cond @%#x: %s @%#x ? %#x : %#x>"
                % (self.store_ea, self.cc, self.cmp_ea,
                   self.true_state, self.false_state))


# ---------------------------------------------------------------------------
# small x86 encoders
# ---------------------------------------------------------------------------
import struct

# cc -> the low opcode byte of the 0F-prefixed near jcc (0F 8x).
_JCC_OP = {
    "o": 0x80, "no": 0x81, "b": 0x82, "c": 0x82, "nae": 0x82,
    "nb": 0x83, "nc": 0x83, "ae": 0x83, "z": 0x84, "e": 0x84,
    "nz": 0x85, "ne": 0x85, "be": 0x86, "na": 0x86, "nbe": 0x87,
    "a": 0x87, "s": 0x88, "ns": 0x89, "p": 0x8A, "pe": 0x8A,
    "np": 0x8B, "po": 0x8B, "l": 0x8C, "nge": 0x8C, "nl": 0x8D,
    "ge": 0x8D, "le": 0x8E, "ng": 0x8E, "nle": 0x8F, "g": 0x8F,
}


def _enc_jmp(at, target):
    disp = target - (at + 5)
    if disp < -0x80000000 or disp > 0x7FFFFFFF:
        return None
    return b"\xE9" + struct.pack("<i", disp)


def _enc_jcc(at, cc, target):
    op = _JCC_OP.get(cc)
    if op is None:
        return None
    disp = target - (at + 6)
    if disp < -0x80000000 or disp > 0x7FFFFFFF:
        return None
    return bytes((0x0F, op)) + struct.pack("<i", disp)


# ---------------------------------------------------------------------------
# Opaque-predicate folding
#
# Removing the dispatcher (Backend A) leaves each real block topped with the
# obfuscator's opaque-predicate gadgets. The recurring shape here is the
# parity identity
#
#     lea  Rb, [Ga-1]     ; Rb = g-1
#     imul Rb, Ga         ; Rb = g*(g-1)
#     test Rb, 1          ; ZF = !(g*(g-1) & 1)
#     jz/jnz  T
#
# g*(g-1) (a product of consecutive integers) is ALWAYS even, so the test
# always sets ZF=1: every `jz` is unconditionally taken and every `jnz` is
# unconditionally not taken -- regardless of g. This is an algebraic certainty,
# not a value guess, so rewriting the branch is provably semantics-preserving:
#   * jz/je  -> `jmp T`   (the edge that was always taken)
#   * jnz/jne-> NOPs      (fall through; the jump was never taken)
# The now-dead parity computation feeds nothing and Hex-Rays drops it, so the
# spurious while()/if() opaque clutter disappears and real control flow shows.
# ---------------------------------------------------------------------------
class OpaqueFolder(object):
    _JCC = ("jz", "je", "jnz", "jne")

    def __init__(self, ea):
        f = ida_funcs.get_func(ea)
        self.FS, self.FE = f.start_ea, f.end_ea

    def _match(self, j):
        """If `j` is a parity-identity branch, return (taken, target); else None."""
        mn = idc.print_insn_mnem(j)
        if mn not in self._JCC:
            return None
        t = idc.prev_head(j, self.FS)
        if idc.print_insn_mnem(t) != "test":
            return None
        if (idc.get_operand_type(t, 1) != idc.o_imm
                or (idc.get_operand_value(t, 1) & 0xFF) != 1):
            return None
        rb = L1._canon_reg(idc.print_operand(t, 0))
        if rb is None:
            return None
        # imul Rb, Ga
        a = idc.prev_head(t, self.FS)
        imul = None
        for _ in range(3):
            if a == idc.BADADDR:
                break
            if (idc.print_insn_mnem(a) == "imul"
                    and L1._canon_reg(idc.print_operand(a, 0)) == rb):
                imul = a
                break
            a = idc.prev_head(a, self.FS)
        if imul is None:
            return None
        ga = L1._canon_reg(idc.print_operand(imul, 1))
        # lea Rb, [Ga-1]
        a = idc.prev_head(imul, self.FS)
        lea = None
        for _ in range(3):
            if a == idc.BADADDR:
                break
            if (idc.print_insn_mnem(a) == "lea"
                    and L1._canon_reg(idc.print_operand(a, 0)) == rb):
                lea = a
                break
            a = idc.prev_head(a, self.FS)
        if lea is None:
            return None
        if (idc.get_operand_value(lea, 1) & U64) != U64:   # displacement must be -1
            return None
        # confirm the lea base register is Ga (operand text "[<ga>...")
        optxt = idc.print_operand(lea, 1)
        base = optxt.split("[", 1)[-1].replace("]", "")
        for sep in ("+", "-"):
            base = base.split(sep, 1)[0]
        if L1._canon_reg(base.strip()) != ga:
            return None
        taken = mn in ("jz", "je")
        target = idc.get_operand_value(j, 0) if taken else idc.next_head(j, self.FE)
        return taken, target

    def plan(self):
        plans = []   # (ea, new_bytes)
        for h in idautils.Heads(self.FS, self.FE):
            m = self._match(h)
            if m is None:
                continue
            taken, target = m
            size = idc.get_item_size(h)
            if not taken:
                plans.append((h, b"\x90" * size))
                continue
            if target is None or target == idc.BADADDR:
                continue
            if size == 2:
                disp = target - (h + 2)
                if disp < -0x80 or disp > 0x7F:
                    continue
                code = b"\xEB" + struct.pack("<b", disp)
            else:
                code = _enc_jmp(h, target)
                if code is None:
                    continue
                code = code + b"\x90" * (size - len(code))
            plans.append((h, code))
        return plans

    def apply(self):
        plans = self.plan()
        for ea, code in plans:
            ida_bytes.patch_bytes(ea, code)
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(code))
        for ea, code in plans:
            a, endp = ea, ea + len(code)
            while a < endp:
                if ida_ua.create_insn(a) == 0:
                    break
                a += idc.get_item_size(a)
        import ida_funcs as _f
        import ida_hexrays
        _f.del_func(self.FS)
        _f.add_func(self.FS, self.FE)
        try:
            ida_hexrays.mark_cfunc_dirty(self.FS)
        except Exception:
            pass
        return {"folded": len(plans)}


def fold_opaques(ea, do_apply=True):
    fo = OpaqueFolder(ea)
    if not do_apply:
        return {"would_fold": len(fo.plan())}
    return fo.apply()


def fold_opaques_all(do_apply=True):
    """Fold parity-identity opaque predicates in every function. Safe to run on
    its own (the transform is an algebraic certainty), e.g. to clean opaque
    clutter out of functions already unflattened by a previous run."""
    total = 0
    touched = 0
    for ea in idautils.Functions():
        try:
            r = fold_opaques(ea, do_apply=do_apply)
        except Exception:
            continue
        n = r.get("folded", r.get("would_fold", 0))
        if n:
            touched += 1
            total += n
    _msg("[layer2] opaque fold: %d gadget(s) in %d function(s)\n"
         % (total, touched))
    return {"folded": total, "functions": touched}


# ===========================================================================
# Emulator-driven CFG resolver (Resolver)
#
# The Resolver EMULATES each real block to its successor, so it resolves
# cross-block conditionals concretely and excludes dead gadgets. The active
# Layer-2 backend (PerHopResolver / PerHopPatcher, further below) reuses this
# class for its decode-parameter recovery (em0 / slots / trust / sslot).
#
# Key techniques (all validated against the sample):
#   * memory-modelling emulator (EmuM): sentinel rsp + the per-function decode
#     key make the stack state slot and the global state buffer concrete, so the
#     dispatcher's `cmp state, IMM` tree reads the value the block just stored.
#   * relay-transparent walk: per-edge decode/relay gadgets are passed through;
#     resolution stops only at the next real WORK block, a ret, or the tree.
#   * TAINT GUARD: a conditional is folded (its opaque always-taken side chosen)
#     ONLY when the governing compare reads trusted memory (the state slot / the
#     decode-key globals). A compare that reads real program data forks into TWO
#     successors -- this is what distinguishes an opaque predicate from a genuine
#     data-dependent branch and stops real edges being silently dropped.
#   * state dedup: identical (ip, registers) machine states are visited once, so
#     forking cannot blow up.
#
# A function is patched only when its LIVE work graph (reachable from a single
# prologue-derived entry) is fully clean: no unresolved leaves and every edge
# has a private, in-range patch anchor. Otherwise it is left at Layer 1.
# ---------------------------------------------------------------------------
_EMU_FLAGSET = set("cmp test add sub and or xor inc dec neg imul mul shl shr "
                   "sar bt adc sbb".split())
_SENT_RSP = 0x0000700000000000
_SENT_KEY = 0x0000680000000000   # live-in decode key (e.g. r15): sentinel slot


def _osz(ea, n):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)
    s = ida_ua.get_dtype_size(insn.ops[n].dtype)
    return s if s in (1, 2, 4, 8, 16) else 0


_VOL64 = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
_MOVLIKE = ("mov", "movzx", "movsx", "movsxd")
_NO_DST = ("cmp", "test", "push", "pop", "nop", "call", "ret", "retn",
           "leave", "jmp")


class EmuM(L1.Emu):
    """Layer-1 emulator extended with a write-through memory model and a
    register/memory TAINT model.

    `wmem` records concrete stores. `trust` is the set of address ranges (the
    state slot plus decode-key globals) whose reads are dispatcher/opaque
    machinery rather than real program data. `rt`/`mt` track, per register and
    per memory slot, whether a value is derived from real (untrusted) program
    data. `ftaint` is set when the last flag-setting instruction tested such a
    value: a conditional branch is then a GENUINE program branch (the resolver
    must fork) rather than an opaque/dispatch predicate (which folds to one
    concrete direction). Taint propagation is essential because the real branch
    decision is usually loaded into a register well before the `cmp`/`jcc`."""

    def __init__(self, regs, wmem, trust):
        L1.Emu.__init__(self, regs)
        self.wmem = wmem
        self.trust = trust
        self.ftaint = False
        self.rt = {}        # canonical 64-bit reg name -> tainted?
        self.mt = {}        # (addr, size) -> tainted?

    def clone(self):
        e = EmuM(list(self.r), dict(self.wmem), self.trust)
        e.ftaint = self.ftaint
        e.rt = dict(self.rt)
        e.mt = dict(self.mt)
        return e

    def trusted(self, a):
        for lo, hi in self.trust:
            if lo <= a < hi:
                return True
        return False

    def memrd(self, a, sz):
        if sz not in (1, 2, 4, 8, 16):
            return None
        for q in (sz, 4, 8):
            if (a, q) in self.wmem:
                return self.wmem[(a, q)] & ((1 << (sz * 8)) - 1)
        try:
            b = ida_bytes.get_bytes(int(a) & U64, sz)
        except Exception:
            return None
        return int.from_bytes(b, "little") if b and len(b) >= sz else None

    def srcval(self, ea, n):
        t = idc.get_operand_type(ea, n)
        if t in (idc.o_displ, idc.o_phrase, idc.o_mem):
            a = self.mem(ea, n)
            return self.memrd(a, _osz(ea, n)) if a is not None else None
        return L1.Emu.srcval(self, ea, n)

    # -- taint -----------------------------------------------------------
    def _otaint(self, ea, n):
        """Is operand n tainted (derived from real program data)?"""
        t = idc.get_operand_type(ea, n)
        if t in (idc.o_imm, idc.o_void, idc.o_near, idc.o_far):
            return False
        if t == idc.o_reg:
            c = L1._canon_reg(idc.print_operand(ea, n))
            return self.rt.get(c, False) if c else True
        if t in (idc.o_displ, idc.o_phrase, idc.o_mem):
            a = self.mem(ea, n)
            if a is None:
                return True
            k = (a, _osz(ea, n))
            if k in self.mt:
                return self.mt[k]
            return not self.trusted(a)
        return False

    def _addrtaint(self, ea, n):
        """Taint of the address expression of operand n (for lea)."""
        m = re.search(r'\[(.*)\]', idc.print_operand(ea, n).split(':')[-1])
        if not m:
            return False
        for tok in m.group(1).replace('-', '+').split('+'):
            tok = tok.strip().split('*')[0].strip()
            if tok in L1._N2I and self.rt.get(L1._canon_reg(tok), False):
                return True
        return False

    def _taint_dst(self, ea, mn):
        if (not mn or mn[0] == "j" or mn in _NO_DST):
            return
        d0 = idc.get_operand_type(ea, 0)
        if d0 not in (idc.o_reg, idc.o_displ, idc.o_phrase, idc.o_mem):
            return
        if mn == "lea":
            st = self._addrtaint(ea, 1)
        elif mn == "xor" and (idc.print_operand(ea, 0)
                              == idc.print_operand(ea, 1)):
            st = False
        elif mn in _MOVLIKE:
            st = self._otaint(ea, 1)
        else:
            st = self._otaint(ea, 0) or self._otaint(ea, 1)
        if d0 == idc.o_reg:
            c = L1._canon_reg(idc.print_operand(ea, 0))
            if c:
                self.rt[c] = st
        else:
            a = self.mem(ea, 0)
            if a is not None:
                self.mt[(a, _osz(ea, 0))] = st

    def do(self, ea):
        mn = idc.print_insn_mnem(ea)
        # value semantics
        if mn == "push":
            self.r[L1._N2I["rsp"][0]] = (self.rr("rsp") - 8) & U64
        elif mn == "mov" and idc.get_operand_type(ea, 0) in (idc.o_displ,
                                                             idc.o_phrase,
                                                             idc.o_mem):
            a = self.mem(ea, 0)
            v = self.srcval(ea, 1)
            sz = _osz(ea, 0)
            if a is not None and v is not None and sz:
                self.wmem[(a, sz)] = v & ((1 << (sz * 8)) - 1)
            elif a is not None:
                for q in (1, 2, 4, 8):
                    self.wmem.pop((a, q), None)
        else:
            L1.Emu.step(self, ea)
        # taint semantics
        if mn in _EMU_FLAGSET:
            self.ftaint = self._otaint(ea, 0) or self._otaint(ea, 1)
        self._taint_dst(ea, mn)


def _detect_params(sm):
    """Recover the per-function decode of the state buffer: the dispatcher reads
    the state via `mov Rb, cs:off_BASE ; mov state_reg, [Rb + Rkey]`. Returns
    (base_global_ea, key_register_name) or (None, None)."""
    for h in idautils.Heads(sm.FS, sm.FE):
        if (idc.print_insn_mnem(h) == "mov"
                and idc.get_operand_type(h, 1) == idc.o_phrase):
            txt = idc.print_operand(h, 1).strip("[]")
            parts = [x.strip() for x in txt.split("+")]
            if len(parts) != 2:
                continue
            pj = idc.prev_head(h, sm.FS)
            braw = brreg = None
            for _ in range(3):
                if (idc.print_insn_mnem(pj) == "mov"
                        and idc.get_operand_type(pj, 1) == idc.o_mem
                        and idc.print_operand(pj, 0) in parts):
                    brreg = idc.print_operand(pj, 0)
                    braw = idc.get_operand_value(pj, 1)
                    break
                pj = idc.prev_head(pj, sm.FS)
            if braw is None:
                continue
            return braw, [x for x in parts if x != brreg][0]
    return None, None


def _detect_dynslot_ptrs(sm):
    """Pointer registers that address the state slot in the dynamic stack-slot
    family (no global decode params). The state cell is reached register-
    indirect after the pointer is set to rsp (`mov rax,rsp; mov [rax],<state>`),
    so the obfuscator's `mov [reg(+disp)], imm(in backbone)` stores reveal the
    pointer register(s). Returns the set of canonical register names referenced
    in those store address expressions (empty when the family does not match)."""
    ptrs = set()
    for h in idautils.Heads(sm.FS, sm.FE):
        if (idc.print_insn_mnem(h) == "mov"
                and idc.get_operand_type(h, 0) in (idc.o_phrase, idc.o_displ)
                and idc.get_operand_type(h, 1) == idc.o_imm
                and (idc.get_operand_value(h, 1) & U32) in sm.backbone):
            m = re.search(r"\[(.*)\]", idc.print_operand(h, 0).split(":")[-1])
            if not m:
                continue
            for tok in m.group(1).replace("-", "+").split("+"):
                tok = tok.strip().split("*")[0].strip()
                if tok in L1._N2I:
                    ptrs.add(L1._canon_reg(tok))
    return ptrs


def _contig_region(sm, start_ea):
    """Largest block-private contiguous byte run from start_ea up to and
    including the first unconditional terminator, refusing to cross any byte
    reachable from outside the run or any dispatcher instruction."""
    included = set()
    a = start_ea
    prev = None
    end = start_ea
    while a != idc.BADADDR and a < sm.FE:
        if a != start_ea:
            refs = list(idautils.CodeRefsTo(a, 1))
            if any(x not in included and x != prev for x in refs):
                break
            if a in sm.state_loads or a in sm.tree_cmps:
                break
        sz = idc.get_item_size(a)
        mn = idc.print_insn_mnem(a)
        included.add(a)
        end = a + sz
        if mn == "jmp" or mn.startswith("ret"):
            break
        prev = a
        a = a + sz
    return start_ea, end - start_ea


def _cave_region():
    """Trailing free padding at the end of the executable CODE segment, usable
    as a trampoline cave. Compilers align the section end with a run of 0xFF (or
    int3) bytes that is undefined and unreferenced; we hand trampolines out of
    it low-to-high, so the still-0xFF tail always reflects the remaining free
    space. Returns (free_start, seg_end) or (None, None)."""
    import ida_segment
    seg = None
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if (s.perm & ida_segment.SEGPERM_EXEC
                and ida_segment.get_segm_class(s) == "CODE"):
            seg = s
    if seg is None:
        return None, None
    # Free space = the trailing run of alignment padding (0xFF / int3 0xCC).
    # Such padding may be either still-undefined OR defined as a data array
    # (e.g. `dq dup(?)`) by auto-analysis -- both are reclaimable. We must,
    # however, never eat into a previously-emitted trampoline: those are real
    # instructions, so we stop at the first byte that belongs to a *code* item
    # (even if that instruction happens to end in a 0xFF displacement byte).
    e = seg.end_ea
    a = e - 1
    while a > seg.start_ea:
        if ida_bytes.get_byte(a) not in (0xFF, 0xCC):
            break
        if ida_bytes.is_code(ida_bytes.get_flags(idc.get_item_head(a))):
            break
        a -= 1
    start = a + 1
    if e - start < 16:
        return None, None
    return start, e


class Resolver(object):
    """Emulate every real block to its successor(s) and build the live work
    graph. Read-only; reused by PerHopResolver for decode-parameter recovery."""

    MAX_DEPTH = 1200

    def __init__(self, sm):
        self.sm = sm
        init = list(L1.FunctionResolver(sm.FS).init)
        self.base_ea, self.keyreg = _detect_params(sm)
        self.gslot = None
        self.dynslot = False
        if self.base_ea is not None and sm.state_reg is not None:
            self.ok = True
            kv = init[L1._N2I[self.keyreg][0]]
            if kv is None:
                # The per-function decode key lives in keyreg as a `mov keyreg,
                # imm64` in the prologue (e.g. `mov r14, 0E8C9B80A967F76A4h`).
                # L1's init does not always capture it; recover it directly so the
                # global state slot (base_content + key) is the real address.
                kr = L1._canon_reg(self.keyreg)
                for h in idautils.Heads(sm.FS, sm.FE):
                    if (idc.print_insn_mnem(h) == "mov"
                            and idc.get_operand_type(h, 0) == idc.o_reg
                            and L1._canon_reg(idc.print_operand(h, 0)) == kr
                            and idc.get_operand_type(h, 1) == idc.o_imm):
                        kv = idc.get_operand_value(h, 1) & U64
                        break
                if kv is None:
                    kv = _SENT_KEY
                init[L1._N2I[self.keyreg][0]] = kv
            bc = idc.get_qword(self.base_ea)
            self.gslot = (bc + kv) & U64
            op = (idc.get_qword(self.base_ea + 8) + kv) & U64
            jt = (idc.get_qword(self.base_ea + 16) + kv) & U64
            # The jump table is a contiguous block in ONE segment (.data). The
            # 0x200000 span is only an upper bound on its size; left unclipped it
            # spills past the segment into adjacent .bss program data, wrongly
            # marking real runtime flags (e.g. a reentrancy guard byte) as
            # trusted dispatcher memory -- their reads then fold to the static
            # filler instead of forking a genuine conditional. Clip to the
            # table's own segment so only the table is trusted.
            jt_hi = jt + 0x200000
            _jseg = ida_segment.getseg(jt)
            if _jseg is not None:
                jt_hi = min(jt_hi, _jseg.end_ea)
            self.trust = [(self.gslot, self.gslot + 4), (op, op + 8),
                          (jt, jt_hi)]
            self.em0 = EmuM(list(init), {}, self.trust)
            self.em0.r[L1._N2I["rsp"][0]] = _SENT_RSP
            # optional stack mirror slot (small functions store the state there)
            self.sslot = None
            for h in idautils.Heads(sm.FS, sm.FE):
                if (idc.print_insn_mnem(h) == "mov"
                        and idc.get_operand_type(h, 0) == idc.o_displ
                        and idc.get_operand_type(h, 1) == idc.o_imm
                        and (idc.get_operand_value(h, 1) & U32) in sm.backbone):
                    self.sslot = self.em0.mem(h, 0)
                    if self.sslot is not None:
                        self.trust.append((self.sslot, self.sslot + 4))
                    break
            self.slots = [self.gslot] + ([self.sslot]
                                         if self.sslot is not None else [])
        else:
            # Dynamic stack-slot family: no global decode params; the state lives
            # in a stack cell addressed through a pointer register set to rsp
            # (`mov rax,rsp; mov [rax],<state>`). Seed rsp AND that pointer with
            # the rsp sentinel so the cell has a concrete, consistent address --
            # then the (stack-mirror) slot machinery below applies unchanged.
            ptrs = _detect_dynslot_ptrs(sm)
            if not ptrs or sm.state_reg is None:
                self.ok = False
                return
            self.dynslot = True
            self.trust = []
            self.em0 = EmuM(list(init), {}, self.trust)
            self.em0.r[L1._N2I["rsp"][0]] = _SENT_RSP
            for pr in ptrs:
                if pr in L1._N2I:
                    self.em0.r[L1._N2I[pr][0]] = _SENT_RSP
            # Resolve every state-cell address from the seeded pointer(s): these
            # ARE the slots. (Several stores may share one cell; dedup.)
            slots = []
            for h in idautils.Heads(sm.FS, sm.FE):
                if (idc.print_insn_mnem(h) == "mov"
                        and idc.get_operand_type(h, 0) in (idc.o_phrase,
                                                           idc.o_displ)
                        and idc.get_operand_type(h, 1) == idc.o_imm
                        and (idc.get_operand_value(h, 1) & U32) in sm.backbone):
                    ad = self.em0.mem(h, 0)
                    if ad is not None and ad not in slots:
                        slots.append(ad)
            for ad in slots:
                self.trust.append((ad, ad + 4))
            self.slots = slots
            self.sslot = slots[0] if slots else None
            self.ok = bool(slots)
            if not self.ok:
                return
        self.WORK = {S: h for S, h in sm.backbone.items()
                     if not self._is_relay(h)}
        self.WH = {h: S for S, h in self.WORK.items()}
        self.tree = set(sm.tree_cmps)
        self.outs = {}        # state -> resolve() result
        self.entry = None
        self.live = set()

    def _is_relay(self, h):
        if self.keyreg is None:        # dynamic stack-slot family: no key relays
            return False
        if (idc.print_insn_mnem(h) != "mov"
                or idc.get_operand_type(h, 1) != idc.o_mem):
            return False
        nh = idc.next_head(h, self.sm.FE)
        return (idc.print_insn_mnem(nh) == "mov"
                and idc.get_operand_type(nh, 1) == idc.o_phrase
                and self.keyreg in idc.print_operand(nh, 1))

    def _nextstate(self, e, curS):
        bb = self.sm.backbone
        for sl in self.slots:
            v = e.memrd(sl, 4)
            if v is not None and v != curS and v in bb:
                return v
        for sl in self.slots:
            v = e.memrd(sl, 4)
            if v in bb:
                return v
        return None

    def _walk(self, start_ea, e_init, home_state):
        """Forking emulation from start_ea. `home_state` is the work state we
        are resolving FROM (None for the prologue/entry probe). Returns an outs
        dict: int next-state -> list[(firstjmp_ea, fork_chain)], plus 'ret' /
        'bad'. fork_chain is the tuple of (jcc_ea, 't'|'f') real branches taken
        on that path -- one element for a simple conditional, several for a
        nested-conditional (switch/else-if) state."""
        sm = self.sm
        home_head = self.WORK.get(home_state) if home_state is not None else None
        outs = {}
        stack = [(start_ea, e_init, 0, None, ())]
        seen = set()
        while stack:
            a, e, d, fj, fc = stack.pop()
            # The dispatch state lives in MEMORY (the state slot), not in a
            # register, so it must be part of the visited key -- otherwise a
            # revisit to a tree/relay address with a coincidentally-equal
            # register snapshot but a different pending state is wrongly pruned,
            # dropping the path to the real successor.
            k = (a, tuple(e.r), tuple(e.memrd(sl, 4) for sl in self.slots))
            if k in seen:
                continue
            seen.add(k)
            if d > self.MAX_DEPTH:
                outs.setdefault("bad", [])
                continue
            if a != home_head and a in self.WH:
                outs.setdefault(self.WH[a], []).append((fj, fc))
                continue
            mn = idc.print_insn_mnem(a)
            if mn in ("ret", "retn"):
                outs.setdefault("ret", [])
                continue
            if a in self.tree:
                v = self._nextstate(e, home_state)
                if v is not None:
                    stack.append((sm.backbone[v], e, d + 1, fj, fc))
                    continue
                outs.setdefault("bad", [])
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    stack.append((idc.get_operand_value(a, 0), e, d + 1,
                                  fj if fj is not None else a, fc))
                    continue
                v = e.rr(idc.print_operand(a, 0))
                if v is not None and sm.FS <= v < sm.FE:
                    stack.append((v, e, d + 1, fj, fc))
                    continue
                outs.setdefault("bad", [])
                continue
            if mn and mn[0] == "j" and mn != "jmp":
                c = e.cond(mn[1:])
                if c is None or e.ftaint:        # genuine branch -> fork
                    e2 = e.clone()
                    stack.append((idc.get_operand_value(a, 0), e, d + 1, fj,
                                  fc + ((a, "t"),)))
                    stack.append((idc.next_head(a, sm.FE), e2, d + 1, fj,
                                  fc + ((a, "f"),)))
                    continue
                tgt = idc.get_operand_value(a, 0) if c else idc.next_head(a, sm.FE)
                stack.append((tgt, e, d + 1, fj, fc))
                continue
            if mn.startswith("cmov"):
                c = e.cond(mn[4:])
                if c is None or e.ftaint:
                    # genuine data-dependent selection of the next state: fork,
                    # recording the cmov as a decision node so the patcher can
                    # realise it as a real branch (cc-true = cmov applied).
                    e2 = e.clone()
                    v = e.srcval(a, 1)
                    if v is not None:
                        e.wr(idc.print_operand(a, 0), v)
                    nh = idc.next_head(a, sm.FE)
                    stack.append((nh, e, d + 1, fj, fc + ((a, "t"),)))
                    stack.append((nh, e2, d + 1, fj, fc + ((a, "f"),)))
                    continue
                if c:
                    v = e.srcval(a, 1)
                    if v is not None:
                        e.wr(idc.print_operand(a, 0), v)
                stack.append((idc.next_head(a, sm.FE), e, d + 1, fj, fc))
                continue
            if mn == "call":
                if not L1._is_reg_transparent_call(a):
                    for i in L1._VOL:
                        e.r[i] = None
                    for c in _VOL64:        # return value is real program data
                        e.rt[c] = True
                stack.append((idc.next_head(a, sm.FE), e, d + 1, fj, fc))
                continue
            e.do(a)
            stack.append((idc.next_head(a, sm.FE), e, d + 1, fj, fc))
        return outs

    def _seed(self, S):
        e = self.em0.clone()
        e.wr(self.sm.state_reg, S)
        for sl in self.slots:
            e.wmem[(sl, 4)] = S
        return e

    def _covers_all(self, S):
        """True if every work state is reachable from S over recovered edges."""
        seen = set()
        st = [S]
        while st:
            x = st.pop()
            if x in seen or x not in self.WORK:
                continue
            seen.add(x)
            for k in self.outs.get(x, {}):
                if isinstance(k, int):
                    st.append(k)
        return len(seen) == len(self.WORK)

    def _find_entry(self):
        """Entry detection is purely graph-based: the recovered work->work edge
        set has exactly one source with no in-edges (indegree 0), and it reaches
        every work state. This is robust where prologue emulation is not (the
        computed-goto family enters via opaque math the prologue probe cannot
        fold, and the stack-slot family establishes rbp only inside the
        prologue). Real branches must already fork correctly (taint guard) or
        the false-edge target would masquerade as a second indegree-0 root."""
        indeg = {S: 0 for S in self.WORK}
        for S in self.WORK:
            for k in self.outs.get(S, {}):
                if isinstance(k, int):
                    indeg[k] = indeg.get(k, 0) + 1
        roots = [S for S in self.WORK if indeg.get(S, 0) == 0
                 and self._covers_all(S)]
        if len(roots) == 1:
            return roots[0], self._anchor_for(roots[0])
        # entry sits inside a loop (no indegree-0 node): accept only if a single
        # work state reaches all others.
        allc = [S for S in self.WORK if self._covers_all(S)]
        if len(allc) == 1:
            return allc[0], self._anchor_for(allc[0])
        return None, None

    def _anchor_for(self, entry):
        """The prologue's last direct jump before it falls into the dispatcher --
        redirecting it straight to the entry head removes the initial dispatch
        ladder. Best-effort: emulate the prologue (folding opaque predicates)
        from FS, returning the first near `jmp` reached. None -> no prologue
        redirect (the dispatcher is still entered once, harmlessly)."""
        sm = self.sm
        e = self.em0.clone()
        a = sm.FS
        steps = 0
        while a != idc.BADADDR and sm.FS <= a < sm.FE and steps < 600:
            steps += 1
            if a in self.tree or a in self.WH:
                return None
            mn = idc.print_insn_mnem(a)
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    return a
                v = e.rr(idc.print_operand(a, 0))
                if v is None or not (sm.FS <= v < sm.FE):
                    return None
                a = v
                continue
            if mn and mn[0] == "j":
                c = e.cond(mn[1:])
                if c is None:
                    return None
                a = idc.get_operand_value(a, 0) if c else idc.next_head(a, sm.FE)
                continue
            if mn in ("ret", "retn"):
                return None
            if mn == "call":
                if not L1._is_reg_transparent_call(a):
                    for i in L1._VOL:
                        e.r[i] = None
                a = idc.next_head(a, sm.FE)
                continue
            e.do(a)
            a = idc.next_head(a, sm.FE)
        return None

    def analyze(self):
        """Resolve every work state, find the entry, and compute the live set.
        Sets self.outs, self.entry, self.live."""
        if not self.ok:
            return self
        for S in self.WORK:
            self.outs[S] = self._walk(self.WORK[S], self._seed(S), S)
        self.entry, self.entry_anchor = self._find_entry()
        # live = reachable from entry over int successors
        if self.entry is not None:
            st = [self.entry]
            while st:
                x = st.pop()
                if x in self.live or x not in self.WORK:
                    continue
                self.live.add(x)
                for k in self.outs.get(x, {}):
                    if isinstance(k, int) and k not in self.live:
                        st.append(k)
        return self

    def is_clean(self):
        """True only when the function is FULLY accounted for:
          * a single prologue-derived entry,
          * every work block reachable from it (live == work), and
          * no live block has an unresolved ('bad') leaf.
        Requiring full work coverage is deliberately conservative: if any work
        block is unreachable in the recovered graph, an edge may have been
        dropped, so exit-redirect would leave a live dispatcher behind (observed
        on nss_decrypt: 20/26 live -> residual flattening). Such functions are
        left at Layer 1 rather than partially -- and possibly wrongly -- patched.
        """
        if not self.ok or self.entry is None or not self.live:
            return False
        if len(self.live) != len(self.WORK):
            return False
        for S in self.live:
            if "bad" in self.outs.get(S, {}):
                return False
        return True

    def edges(self, S):
        return {k: v for k, v in self.outs.get(S, {}).items()
                if isinstance(k, int)}

    def report(self):
        cond = sum(1 for S in self.live if len(self.edges(S)) > 1)
        return {"name": self.sm.name, "states": len(self.sm.backbone),
                "work": len(self.WORK), "live": len(self.live),
                "cond": cond, "entry": self.entry, "clean": self.is_clean()}


# ---------------------------------------------------------------------------
# Per-hop (relay-aware) resolver + patcher  -- the chosen Layer-2 backend
#
# Insight that makes this both simpler and more robust than the transitive
# Resolver above: every backbone state V's block WRITES its immediate successor
# state into the state slot (a 32-bit constant = unconditional, or a tainted
# cmov-selected pair = conditional) and then re-enters the dispatcher. So we
# resolve each state ONE HOP -- emulate from backbone[V], folding the opaque
# dispatcher navigation concretely (the state value is known, so every nav
# compare/cmov is invariant) and forking only on TAINTED (real) decisions, until
# the path reaches the first state-slot write.
#
# Proven on the sample: within a single hop NO path crosses a dispatcher compare
# (the navigation that routed us to backbone[V] already happened; the next nav is
# the NEXT hop, after the write). Therefore patching the write site
#   store  -> jmp backbone[succ]                      (unconditional)
#   cmov   -> jcc cc,backbone[t] ; jmp backbone[f]    (conditional)
# redirects the block straight to its real successor head and the entire
# dispatcher tree becomes dead once every live block is redirected.
#
# Crucially, each hop patch is LOCALLY EQUIVALENT to what the dispatcher would
# have done, so it is correct in isolation: we may patch the edges we can prove
# and leave any hard/compound block dispatching through the still-intact tree
# (a small, correct residual) instead of refusing the whole function.
# ---------------------------------------------------------------------------
class PerHopResolver(object):
    """Resolve every backbone state to its immediate successor(s) and write
    site. Read-only; drives PerHopPatcher."""

    MAX_STEPS = 40000        # emulated instructions per hop
    MAX_FORKS = 2000         # tainted branch forks per hop
    HOP_SECONDS = 2.0        # wall-clock budget per hop
    FUNC_SECONDS = 45.0      # wall-clock budget per function

    def __init__(self, sm):
        self.sm = sm
        b = Resolver(sm)            # reuse decode-param recovery (em0/slots/trust)
        self.ok = b.ok
        self._b = b
        self.res = {}               # state -> classification dict
        self.S0 = None
        self.s0_site = None
        self.live = set()
        if not self.ok:
            return
        self.em0 = b.em0
        self.slots = b.slots
        self.bb = sm.backbone
        self.head2state = {h: S for S, h in sm.backbone.items()}
        self.tree = set(sm.tree_cmps)
        self.store_sites, self.slot_dests = self._find_store_sites()
        # The stack-mirror family writes its real next state to a stack slot and
        # then routes through the global `jmp rax` dispatch; its store IS the
        # answer, so following the computed goto would skip past the store and
        # mis-read a relay head. The jump-table family has no stack mirror -- its
        # next block is reached ONLY through the computed goto -- so only there do
        # we follow an indirect jmp concretely (the table is in EmuM's trusted
        # range). This gate keeps the proven stack-family results intact.
        self.follow_ijmp = b.sslot is None
        self.dynslot = b.dynslot
        self._pz_cache = {}

    def _parity_zf(self, a):
        """True if the branch/cmov at `a` is gated by the obfuscator's parity
        opaque predicate, whose flag is *provably* ZF=1 regardless of the
        (tainted) state value.

        The gadget is `lea Rd,[Rs-1]; imul Rd,Rs; ... test Rd8,1; <cc>`: Rd holds
        (x-1)*x, a product of consecutive integers, which is always even, so
        `test Rd,1` always clears the low bit (ZF=1). Recognising this lets the
        hop fold the always-taken branch instead of forking its impossible arm
        (which would leave the state register non-concrete and explode the whole
        compare tree). Returns True when the parity gadget is matched, else None.
        Purely structural -> sound independent of emulated values."""
        if a in self._pz_cache:
            return self._pz_cache[a]
        res = None
        fs = None
        p = a
        for _ in range(6):                       # nearest preceding flag setter
            p = idc.prev_head(p, self.sm.FS)
            if p == idc.BADADDR or p < self.sm.FS:
                break
            if idc.print_insn_mnem(p) in _EMU_FLAGSET:
                fs = p
                break
        if (fs is not None and idc.print_insn_mnem(fs) == "test"
                and idc.get_operand_type(fs, 0) == idc.o_reg
                and idc.get_operand_type(fs, 1) == idc.o_imm
                and (idc.get_operand_value(fs, 1) & 0xFF) == 1):
            reg = L1._canon_reg(idc.print_operand(fs, 0))
            q = fs
            for _ in range(8):                   # the imul that built that reg
                q = idc.prev_head(q, self.sm.FS)
                if q == idc.BADADDR or q < self.sm.FS:
                    break
                if (idc.print_insn_mnem(q) == "imul"
                        and idc.get_operand_type(q, 0) == idc.o_reg
                        and L1._canon_reg(idc.print_operand(q, 0)) == reg):
                    mul = L1._canon_reg(idc.print_operand(q, 1))
                    t = q
                    for _ in range(6):           # the `lea Rd,[mul-1]` before it
                        t = idc.prev_head(t, self.sm.FS)
                        if t == idc.BADADDR or t < self.sm.FS:
                            break
                        if (idc.print_insn_mnem(t) == "lea"
                                and L1._canon_reg(idc.print_operand(t, 0)) == reg):
                            ex = self._memexpr(t, 1)
                            if ex and ex.endswith("-1") and L1._canon_reg(
                                    ex[:-2]) == mul:
                                res = True
                            break
                    break
        self._pz_cache[a] = res
        return res

    @staticmethod
    def _memexpr(ea, n):
        """The bracketed address expression of a memory operand, normalised
        (size prefix and segment stripped) so the same slot accessed via the
        same register form compares equal regardless of operand width."""
        t = idc.print_operand(ea, n)
        m = re.search(r"\[(.*)\]", t.split(":")[-1])
        return m.group(1).replace(" ", "") if m else None

    def _find_store_sites(self):
        """Locate state-slot writes structurally (pointer-agnostic):
          * unconditional: `mov [slot], imm` with imm in the backbone -- this
            also reveals the slot's destination expression(s);
          * conditional:   `mov [slot], reg` to one of those same expressions
            (the cmov-selected next state).
        Returns (sites, slot_dests) where sites maps ea -> ('imm', value) or
        ('reg', src_reg)."""
        sm = self.sm
        sites = {}
        dests = set()
        for h in idautils.Heads(sm.FS, sm.FE):
            if (idc.print_insn_mnem(h) == "mov"
                    and idc.get_operand_type(h, 0) in (idc.o_displ, idc.o_phrase,
                                                       idc.o_mem)
                    and idc.get_operand_type(h, 1) == idc.o_imm
                    and (idc.get_operand_value(h, 1) & U32) in self.bb):
                sites[h] = ("imm", idc.get_operand_value(h, 1) & U32)
                d = self._memexpr(h, 0)
                if d:
                    dests.add(d)
        if dests:
            for h in idautils.Heads(sm.FS, sm.FE):
                if (idc.print_insn_mnem(h) == "mov"
                        and idc.get_operand_type(h, 0) in (idc.o_displ,
                                                           idc.o_phrase,
                                                           idc.o_mem)
                        and idc.get_operand_type(h, 1) == idc.o_reg
                        and h not in sites
                        and self._memexpr(h, 0) in dests):
                    sites[h] = ("reg", L1._canon_reg(idc.print_operand(h, 1)))
        return sites, dests

    def _seed(self, S):
        return self._b._seed(S)

    def _hop(self, start, e0):
        """Forking emulation from `start` to each path's first state-slot write.
        Returns (paths, flags); paths = list of (value, store_ea, chain) where
        chain is the tuple of (decision_ea, 't'|'f') taken on tainted branches.
        Bounded by step/state/wall-clock budgets so a pathological block can
        never hang IDA -- exceeding any budget yields a 'toolong' flag and the
        block is left dispatching."""
        sm = self.sm
        slots = set(self.slots)
        # Each stack entry carries its own visited-address set: a path stops at
        # any back-edge (a real intra-block loop) instead of unrolling it. We do
        # NOT need to execute real loops to find the next state-store/decision,
        # and unrolling a tainted loop would fork without bound. `seen` prunes
        # identical (address, decision-chain) fork states across paths.
        stack = [(start, e0, (), set())]
        seen = set()
        paths = []
        flags = set()
        steps = 0
        forks = 0
        dl = time.time() + self.HOP_SECONDS
        while stack and steps < self.MAX_STEPS:
            steps += 1
            if (steps & 0x3ff) == 0 and time.time() > dl:
                flags.add("toolong")
                break
            if forks > self.MAX_FORKS:
                flags.add("toolong")
                break
            a, e, dec, vis = stack.pop()
            if a in vis:                 # loop back-edge: do not unroll
                continue
            # Merge paths that reach the same address with the same register and
            # slot state: their forward behaviour is identical, so this collapses
            # reconverging opaque/real branches (preventing 2^n blow-up) while
            # keeping genuinely divergent cmov-selected paths distinct (their
            # registers differ). Per-path `vis` already bounds loops, so a
            # value-based key here can no longer be defeated by loop counters.
            sk = (a, tuple(e.r), tuple(e.memrd(sl, 4) for sl in self.slots))
            if sk in seen:
                continue
            seen.add(sk)
            vis.add(a)
            if a == idc.BADADDR or not (sm.FS <= a < sm.FE):
                flags.add("bad")
                continue
            mn = idc.print_insn_mnem(a)
            # Stop at this block's OWN state-store (work block): the next state.
            st = self.store_sites.get(a)
            if st is not None:
                if st[0] == "imm":
                    v = st[1]
                else:
                    rv = e.rr(st[1])
                    v = (rv & U32) if rv is not None else None
                # Reg-store sites are matched by address-expression, but the same
                # slot pointer register is reused for ordinary data writes in the
                # jump-table family (`mov [rcx], eax`). A genuine conditional
                # state store writes a backbone value; if the resolved value is
                # not one, this is real work aliasing the slot expression -- keep
                # walking instead of recording a poisoned store.
                if (not self.follow_ijmp or st[0] == "imm"
                        or (v is not None and v in self.bb)):
                    paths.append((v, a, dec, "s"))
                    continue
            if (mn == "mov" and idc.get_operand_type(a, 0)
                    in (idc.o_displ, idc.o_phrase, idc.o_mem)):
                addr = e.mem(a, 0)
                if addr in slots:
                    if idc.get_operand_type(a, 1) == idc.o_imm:
                        v = idc.get_operand_value(a, 1) & U32
                    else:
                        rv = e.rr(idc.print_operand(a, 1))
                        v = (rv & U32) if rv is not None else None
                    # Jump-table family false-positive guard: a real pointer can
                    # alias the (concrete) state-slot address, so a normal data
                    # write `mov [rcx], eax` would masquerade as a state store and
                    # poison the block. A genuine state store always writes a
                    # backbone value, so when the resolved value is not one, treat
                    # this as ordinary work and keep walking to the real store.
                    if (not self.follow_ijmp) or (v is not None and v in self.bb):
                        paths.append((v, a, dec, "s"))
                        continue
                elif self.follow_ijmp:
                    # The jump-table family reloads the slot pointer from a stack
                    # cell (`mov rcx,[rbp+x]; mov [rcx],eax`), so neither the
                    # concrete address nor the `[rcx]` expression is a catalogued
                    # slot dest -- yet a store whose value is a backbone state is
                    # unambiguously a state store (states are random 32-bit
                    # constants; a data write holding one by chance is impossible
                    # in practice). Record it so a genuine cmov-selected
                    # conditional store through an un-catalogued pointer is not
                    # walked past into the dispatcher (which would explode).
                    if idc.get_operand_type(a, 1) == idc.o_imm:
                        sv = idc.get_operand_value(a, 1) & U32
                    elif idc.get_operand_type(a, 1) == idc.o_reg:
                        rv = e.rr(idc.print_operand(a, 1))
                        sv = (rv & U32) if rv is not None else None
                    else:
                        sv = None
                    if sv is not None and sv in self.bb:
                        paths.append((sv, a, dec, "s"))
                        continue
            # Stop at the NEXT backbone head reached without an own store: this
            # block is a pure-nav relay; its successor is that head. (Composition
            # later collapses such relays so work edges skip straight past them.)
            if a != start and a in self.head2state:
                paths.append((self.head2state[a], a, dec, "h"))
                continue
            if mn in ("ret", "retn"):
                flags.add("ret")
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    stack.append((idc.get_operand_value(a, 0), e, dec, vis))
                    continue
                # Computed-goto (jump-table) dispatch: `... jmp rax`. The table
                # lives in EmuM's trusted range (per-function base + key), so the
                # target register is concretely resolvable once the opaque offset
                # math is folded and any real offset-select has forked. If it
                # resolves into this function, FOLLOW it -- this is exactly how
                # the second obfuscation topology routes between real blocks.
                # Only when it cannot be resolved (genuinely data-dependent on a
                # value we do not model) do we flag it unresolved and leave the
                # block dispatching (partial, never a wrong patch).
                if self.follow_ijmp:
                    v = e.rr(idc.print_operand(a, 0))
                    if v is not None and sm.FS <= (v & U64) < sm.FE:
                        stack.append((v & U64, e, dec, vis))
                        continue
                flags.add("ijmp")
                continue
            if mn and mn[0] == "j":
                c = e.cond(mn[1:])
                if c is None or e.ftaint:
                    # Parity opaque: ZF is provably 1, so the branch is
                    # deterministic regardless of the tainted state value.
                    if (self.follow_ijmp or self.dynslot) and self._parity_zf(a):
                        take = mn[1:] in ("z", "e")
                        tgt = (idc.get_operand_value(a, 0) if take
                               else idc.next_head(a, sm.FE))
                        stack.append((tgt, e, dec, vis))
                        continue
                    forks += 1
                    e2 = e.clone()
                    stack.append((idc.get_operand_value(a, 0), e,
                                  dec + ((a, "t"),), vis))
                    stack.append((idc.next_head(a, sm.FE), e2,
                                  dec + ((a, "f"),), set(vis)))
                    continue
                tgt = idc.get_operand_value(a, 0) if c else idc.next_head(a,
                                                                          sm.FE)
                oth = idc.next_head(a, sm.FE) if c else idc.get_operand_value(a,
                                                                             0)
                if tgt in vis and oth not in vis:
                    tgt = oth            # concrete bounded loop: take the exit
                stack.append((tgt, e, dec, vis))
                continue
            if mn.startswith("cmov"):
                c = e.cond(mn[4:])
                if c is None or e.ftaint:
                    v = e.srcval(a, 1)
                    # Parity opaque (`(x-1)*x` is always even): the controlling
                    # ZF is provably 1, so the cmov is deterministic even though
                    # the state value is tainted. Fold it instead of forking the
                    # impossible arm -- otherwise the dead offset-select left in a
                    # register stays live and explodes the compare tree.
                    if (self.follow_ijmp or self.dynslot) and self._parity_zf(a):
                        if mn[4:] in ("z", "e") and v is not None:
                            e.wr(idc.print_operand(a, 0), v)
                        stack.append((idc.next_head(a, sm.FE), e, dec, vis))
                        continue
                    # Jump-table family: an opaque fake-set-state selector picks
                    # between the real next-state (already in the destination) and
                    # a decoy value that is NOT a backbone state (a table offset
                    # left in a register by the dead dispatcher-decode). Per the
                    # obfuscator's design the non-state arm is the never-taken
                    # opaque-false branch ("fake set state" gadget): collapsing to
                    # the real state is sound and avoids forking the decoy into the
                    # dispatcher (which would corrupt the state slot and explode).
                    # A GENUINE 2-way state conditional has BOTH arms in the
                    # backbone, so it still forks below. Gated to follow_ijmp, so
                    # the stack/compare-tree families are byte-identical.
                    if self.follow_ijmp and v is not None:
                        dst = idc.print_operand(a, 0)
                        d = e.rr(dst)
                        vbb = (v & U32) in self.bb
                        dbb = d is not None and (d & U32) in self.bb
                        if dbb and not vbb:        # real state already in dst
                            stack.append((idc.next_head(a, sm.FE), e, dec, vis))
                            continue
                        if vbb and not dbb:        # real state is the source
                            e.wr(dst, v)
                            stack.append((idc.next_head(a, sm.FE), e, dec, vis))
                            continue
                    forks += 1
                    e2 = e.clone()
                    if v is not None:
                        e.wr(idc.print_operand(a, 0), v)
                    nh = idc.next_head(a, sm.FE)
                    stack.append((nh, e, dec + ((a, "t"),), vis))
                    stack.append((nh, e2, dec + ((a, "f"),), set(vis)))
                    continue
                if c:
                    v = e.srcval(a, 1)
                    if v is not None:
                        e.wr(idc.print_operand(a, 0), v)
                stack.append((idc.next_head(a, sm.FE), e, dec, vis))
                continue
            if mn == "call":
                if not L1._is_reg_transparent_call(a):
                    for i in L1._VOL:
                        e.r[i] = None
                    for cn in _VOL64:
                        e.rt[cn] = True
                stack.append((idc.next_head(a, sm.FE), e, dec, vis))
                continue
            e.do(a)
            stack.append((idc.next_head(a, sm.FE), e, dec, vis))
        if steps >= self.MAX_STEPS:
            flags.add("toolong")
        return paths, flags

    def _classify(self, paths, flags):
        """Reduce one hop's paths to an edge: unconditional, a clean 2-way
        conditional (single tainted cmov, both arms hitting the same store), a
        terminal ret, or unresolved (multi/bad -- left dispatching)."""
        bb = self.bb
        real = [p for p in paths if p[0] in bb]
        realvals = set(p[0] for p in real)
        if "toolong" in flags:
            return {"kind": "bad", "succ": list(realvals)}
        # A reachable jump-table dispatcher (computed goto) is not modelled here;
        # refuse the block so it is left dispatching rather than mis-routed.
        if "ijmp" in flags and not realvals:
            return {"kind": "bad", "succ": []}
        if not realvals:
            return {"kind": "ret" if "ret" in flags else "bad", "succ": []}
        marks = set(p[3] for p in real)
        if len(realvals) == 1:
            v = next(iter(realvals))
            # Pure-nav relay: reached the next head with no own store.
            if "s" not in marks:
                return {"kind": "relay", "succ": [v]}
            site = None
            for val, ea, dec, mk in real:
                if val == v and mk == "s":
                    site = ea
                    if not dec:
                        break
            return {"kind": "uncond", "succ": [v], "site": site}
        if len(realvals) == 2:
            # Jump-table family: the two successors are reached THROUGH the
            # computed goto (head marks), distinguished by a single tainted
            # offset-select. Handle separately so the stack-family path below
            # stays byte-identical.
            if self.follow_ijmp:
                return self._jt_cond(real, sorted(realvals))
            # only clean cmov-store conditionals are realised; conditional relays
            # (two heads via tainted nav) are left to the dispatcher.
            real = [p for p in real if p[3] == "s"]
            realvals = set(p[0] for p in real)
            if len(realvals) != 2:
                return {"kind": "multi", "succ": sorted(realvals)}
            # per-value, intersect path direction-maps to the choices the value
            # ALWAYS makes; the lone node the two values disagree on is the real
            # discriminator. Require it to be a cmov whose two arms share one
            # store (so no real work is skipped by hard-branching there).
            vdir = {}
            store = {}
            for v in realvals:
                common = None
                sts = set()
                for val, ea, dec, mk in real:
                    if val != v:
                        continue
                    sts.add(ea)
                    d = dict(dec)
                    if common is None:
                        common = d
                    else:
                        common = {k: common[k] for k in common
                                  if k in d and d[k] == common[k]}
                vdir[v] = common or {}
                store[v] = sts
            v1, v2 = sorted(realvals)
            shared = set(vdir[v1]) & set(vdir[v2])
            disc = [n for n in shared if vdir[v1][n] != vdir[v2][n]]
            if len(disc) != 1:
                return {"kind": "multi", "succ": [v1, v2]}
            D = disc[0]
            if not idc.print_insn_mnem(D).startswith("cmov"):
                return {"kind": "multi", "succ": [v1, v2]}
            if store[v1] != store[v2] or len(store[v1]) != 1:
                return {"kind": "multi", "succ": [v1, v2]}
            t_val = v1 if vdir[v1][D] == "t" else v2
            f_val = v2 if t_val == v1 else v1
            return {"kind": "cond", "succ": [v1, v2], "disc": D,
                    "t": t_val, "f": f_val}
        return {"kind": "multi", "succ": sorted(realvals)}

    def _jt_cond(self, real, vv):
        """Jump-table family conditional: the two successors are reached through
        the computed goto and differ on exactly one tainted decision -- the
        `cmov`/`jcc` that selects the table offset for the real branch. Recover
        that discriminator from the per-value path decision-chains; realise a
        clean 2-way edge, otherwise leave the block dispatching."""
        v1, v2 = vv
        vdir = {}
        for v in (v1, v2):
            common = None
            for val, ea, dec, mk in real:
                if val != v:
                    continue
                d = dict(dec)
                common = d if common is None else {
                    k: common[k] for k in common if k in d and d[k] == common[k]}
            vdir[v] = common or {}
        shared = set(vdir[v1]) & set(vdir[v2])
        disc = [n for n in shared if vdir[v1][n] != vdir[v2][n]]
        if len(disc) != 1:
            return {"kind": "multi", "succ": [v1, v2]}
        D = disc[0]
        mn = idc.print_insn_mnem(D)
        if not (mn.startswith("cmov") or (mn and mn[0] == "j")):
            return {"kind": "multi", "succ": [v1, v2]}
        t_val = v1 if vdir[v1][D] == "t" else v2
        f_val = v2 if t_val == v1 else v1
        return {"kind": "cond", "succ": [v1, v2], "disc": D,
                "t": t_val, "f": f_val, "jt": True}

    def _find_s0(self):
        """Recover the entry state by tracing the prologue's control flow (the
        dispatcher-init code can sit at a HIGH address, after the work blocks, so
        a linear scan is wrong). Seed the slot uninitialised, fold the opaque
        dispatcher concretely, follow jumps, and stop at the first state-store
        site -- the prologue's initial-state write. Returns (state, anchor):
        patching `anchor` -> jmp backbone[state] sends the prologue straight to
        the entry block. A head reached with no store yields (state, None)."""
        sm = self.sm
        e = self.em0.clone()
        for sl in self.slots:
            e.wmem[(sl, 4)] = 0xffffffff
        bbh = {h: S for S, h in self.bb.items()}
        a = sm.FS
        vis = set()
        steps = 0
        while a != idc.BADADDR and sm.FS <= a < sm.FE and steps < 6000:
            steps += 1
            if a in vis:
                return None, None
            vis.add(a)
            st = self.store_sites.get(a)
            if st is not None:
                v = st[1] if st[0] == "imm" else e.rr(st[1])
                if v is not None and (v & U32) in self.bb:
                    return v & U32, a
                return None, None
            if a in bbh:
                return bbh[a], None
            mn = idc.print_insn_mnem(a)
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    a = idc.get_operand_value(a, 0)
                    continue
                v = e.rr(idc.print_operand(a, 0))
                if v is not None and sm.FS <= v < sm.FE:
                    a = v
                    continue
                return None, None
            if mn and mn[0] == "j":
                c = e.cond(mn[1:])
                if c is None:
                    return None, None
                a = idc.get_operand_value(a, 0) if c else idc.next_head(a, sm.FE)
                continue
            if mn in ("ret", "retn"):
                return None, None
            if mn == "call":
                if not L1._is_reg_transparent_call(a):
                    for i in L1._VOL:
                        e.r[i] = None
                a = idc.next_head(a, sm.FE)
                continue
            e.do(a)
            a = idc.next_head(a, sm.FE)
        return None, None

    def _covers(self, S, succ):
        seen = set()
        st = [S]
        while st:
            x = st.pop()
            if x in seen or x not in self.bb:
                continue
            seen.add(x)
            for s in succ.get(x, []):
                st.append(s)
        return len(seen) == len(self.bb)

    def _graph_entry(self):
        """Fallback when there is no prologue imm store (the global family seeds
        the slot via a pointer register): the recovered edge graph has a single
        indegree-0 root that reaches every state. No prologue anchor -- the
        dispatcher is entered once, harmlessly, then never again."""
        work = [V for V in self.bb
                if self.res.get(V, {}).get("kind") != "relay"]
        # Only RESOLVED edges (uncond/cond) define the real flow. A multi/bad
        # block is left dispatching, and its speculative successor list (a block
        # whose computed goto we could not fold may "reach" every leaf) would
        # otherwise give every state indegree>=1 and erase the entry root. Treat
        # such unresolved blocks as sinks for root-finding.
        succ = {V: (self.csucc(V)
                    if self.res.get(V, {}).get("kind") in (
                        "uncond", "cond", "nway")
                    else [])
                for V in work}
        indeg = {V: 0 for V in work}
        for V in work:
            for s in succ[V]:
                if s in indeg:
                    indeg[s] += 1

        def covers(S):
            seen = set()
            st = [S]
            while st:
                x = st.pop()
                if x in seen or x not in succ:
                    continue
                seen.add(x)
                for s in succ[x]:
                    st.append(s)
            return len(seen) == len(work)
        roots = [V for V in work if indeg[V] == 0 and covers(V)]
        if len(roots) == 1:
            return roots[0]
        allc = [V for V in work if covers(V)]
        if len(allc) == 1:
            return allc[0]
        return None

    def _final(self, S):
        """Follow a chain of pure-nav relay states to the first non-relay state,
        so work edges are composed straight past the dispatcher's relays."""
        seen = set()
        while (S in self.bb and self.res.get(S, {}).get("kind") == "relay"
               and S not in seen):
            seen.add(S)
            succ = self.res[S].get("succ")
            if not succ:
                break
            S = succ[0]
        return S

    def csucc(self, V):
        """Composed successors of a non-relay state (relays collapsed away)."""
        r = self.res.get(V, {})
        if r.get("kind") in ("uncond", "cond", "nway", "multi", "bad"):
            return [self._final(s) for s in r.get("succ", [])]
        return []

    def _is_terminal_ret(self, V):
        """A genuine 'ret' state is a real function epilogue: from its head every
        path reaches a `retn` (or another backbone head) without passing a
        computed/indirect `jmp reg`. A jump-table dispatcher that merely *folds*
        to the epilogue (the second obfuscation topology -- e.g. win_impl_init)
        has such a reachable indirect jump, so it is NOT a clean ret and must not
        be patched away as one (its real successors would be lost)."""
        sm = self.sm
        seen = set()
        stack = [self.bb[V]]
        n = 0
        while stack and n < 4000:
            a = stack.pop()
            n += 1
            if a in seen or not (sm.FS <= a < sm.FE):
                continue
            seen.add(a)
            mn = idc.print_insn_mnem(a)
            if mn in ("ret", "retn"):
                continue
            if a != self.bb[V] and a in self.head2state:
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    stack.append(idc.get_operand_value(a, 0))
                    continue
                return False                 # reachable computed goto
            if mn and mn[0] == "j":
                stack.append(idc.get_operand_value(a, 0))
                stack.append(idc.next_head(a, sm.FE))
                continue
            stack.append(idc.next_head(a, sm.FE))
        return n < 4000

    def _nway_direct(self, V):
        """A 'multi' (>2-way) block is BENIGN when its branch is the program's
        OWN logic (e.g. a character classifier) that ALREADY targets backbone
        heads through direct control flow -- no dispatcher indirection is left on
        any arm. Such a block needs NO patch: the decompiler can already follow
        every edge, so leaving it untouched is trivially sound (we never modify
        it) and it must not block an otherwise-clean function.

        Static DFS from the head, following only near jmps and BOTH arms of every
        jcc, stopping at backbone heads (the successors) and rets. Returns the set
        of successor states when every reachable control transfer is direct; None
        if a computed/indirect `jmp reg`/`jmp [mem]` is reachable (the dispatch is
        still live there, so the block is genuinely unresolved -> stays multi)."""
        sm = self.sm
        head = self.bb[V]
        seen = set()
        stack = [head]
        heads = set()
        n = 0
        while stack and n < 8000:
            a = stack.pop()
            n += 1
            if a in seen or not (sm.FS <= a < sm.FE):
                continue
            seen.add(a)
            if a != head and a in self.head2state:
                heads.add(self.head2state[a])
                continue
            mn = idc.print_insn_mnem(a)
            if mn in ("ret", "retn"):
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    stack.append(idc.get_operand_value(a, 0))
                    continue
                return None                      # reachable computed goto
            if mn and mn[0] == "j":
                stack.append(idc.get_operand_value(a, 0))
                stack.append(idc.next_head(a, sm.FE))
                continue
            stack.append(idc.next_head(a, sm.FE))
        if n >= 8000:
            return None
        return heads

    def analyze(self):
        if not self.ok:
            return self
        dl = time.time() + self.FUNC_SECONDS
        for V in self.bb:
            if time.time() > dl:
                # Out of budget: leave the rest dispatching (marked unresolved).
                self.res[V] = {"kind": "bad", "succ": []}
                continue
            self.res[V] = self._classify(*self._hop(self.bb[V], self._seed(V)))
        # A 'ret' that is really a jump-table dispatcher folded to the epilogue is
        # a hybrid (second topology); refuse it so the function is reported
        # unfinished rather than silently patched into a decoy.
        for V in self.bb:
            if (self.res[V].get("kind") == "ret"
                    and not self._is_terminal_ret(V)):
                self.res[V] = {"kind": "bad", "succ": []}
        # A 'multi' (>2-way) block whose real branch already reaches backbone
        # heads through direct control flow is benign (the program's own logic);
        # mark it 'nway' so it counts as resolved and does not block the function.
        # We emit no patch for it, so this can never corrupt anything.
        #
        # Only the jump-table family has such benign N-way program branches (e.g.
        # a JSON character classifier). In the stack/dynamic-slot families a block
        # ALWAYS re-enters through the shared compare-tree dispatcher, whose own
        # branches reach every head -- _nway_direct would then mis-read that as a
        # direct N-way fan-out and falsely "resolve" a still-dispatching block.
        # So gate this reclassification to follow_ijmp.
        if self.follow_ijmp:
            for V in self.bb:
                if self.res[V].get("kind") == "multi":
                    hd = self._nway_direct(V)
                    if hd and len(hd) >= 2:
                        self.res[V] = {"kind": "nway", "succ": sorted(hd)}
        self.work = [V for V in self.bb
                     if self.res.get(V, {}).get("kind") != "relay"]
        self.S0, self.s0_site = self._find_s0()
        if self.S0 is not None:
            self.S0 = self._final(self.S0)
        if self.S0 is None:
            self.S0 = self._graph_entry()
            self.s0_site = None
        if self.S0 is not None:
            seen = set()
            st = [self.S0]
            while st:
                x = st.pop()
                if x in seen or x not in self.bb:
                    continue
                seen.add(x)
                for s in self.csucc(x):
                    st.append(s)
            self.live = seen
        return self

    def _patchable(self, V):
        return self.res.get(V, {}).get("kind") in (
            "uncond", "cond", "ret", "nway")

    def _block_calls(self, head):
        """Count real (non-stack-probe) calls reachable from a block head by
        static intra-function flow (near jmps + both conditional arms)."""
        sm = self.sm
        seen = set()
        stack = [head]
        n = 0
        while stack and len(seen) < 4000:
            a = stack.pop()
            if a in seen or not (sm.FS <= a < sm.FE):
                continue
            seen.add(a)
            mn = idc.print_insn_mnem(a)
            if mn == "call":
                t = idc.get_operand_value(a, 0)
                nm = idc.get_func_name(t) if t else ""
                if "chkstk" not in (nm or ""):
                    n += 1
            if mn in ("ret", "retn"):
                continue
            if a != head and a in self.head2state:
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) == idc.o_near:
                    stack.append(idc.get_operand_value(a, 0))
                continue
            if mn and mn[0] == "j":
                stack.append(idc.get_operand_value(a, 0))
                stack.append(idc.next_head(a, sm.FE))
                continue
            stack.append(idc.next_head(a, sm.FE))
        return n

    def is_decoy(self):
        """Detect a jump-table 'decoy' entry: the recovered live path does NO
        real work (zero non-probe calls) yet a large unreached work component is
        full of real calls. This is the signature of the SECOND obfuscation
        topology (a jump-table/computed-goto dispatcher) whose real body the
        compare-tree resolver cannot follow -- e.g. win_impl_init, whose 6-state
        path returns immediately while its 50 unreached states hold 48 calls.
        Such a function must NOT be patched (it would be reduced to a stub)."""
        if not self.live:
            return False
        live_calls = sum(self._block_calls(self.bb[V]) for V in self.live)
        if live_calls:
            return False
        dead = [V for V in getattr(self, "work", [])
                if V not in self.live]
        dead_calls = sum(self._block_calls(self.bb[V]) for V in dead)
        return dead_calls >= 8

    def is_clean(self):
        """Clean = entry found and every LIVE (reachable) state resolves to a
        patchable edge. Backbone states that are not reachable from the entry are
        the obfuscator's opaque-false gadget blocks (fake set-state / jump
        gadgets); they are never executed and Hex-Rays drops them once the live
        edges are direct, so full backbone coverage is NOT required for a clean
        unflattening -- only that nothing reachable is left dispatching. A
        jump-table decoy entry is never clean (its real body is unreachable)."""
        if not self.ok or self.S0 is None or not self.live:
            return False
        if self.is_decoy():
            return False
        # An impure dispatcher (hoisted side-effects in the compare tree) cannot
        # be unflattened by edge rewriting without dropping those instructions,
        # so it is not a clean recovery (see _impure_nodes / unflatten_function).
        if self._impure_nodes():
            return False
        return all(self._patchable(V) for V in self.live)

    def _impure_nodes(self):
        """Dispatcher compare-tree nodes that carry a SIDE-EFFECT: a write to a
        register other than the state register, wedged between a
        `cmp state_reg, imm` and its controlling jcc.

        The obfuscator sometimes hoists real instructions -- API-argument or
        decode-key setup such as `mov rdx, r12` -- into the binary-search
        dispatcher, so they execute as a side effect of *routing* rather than
        inside the work block. Our normal unflattening collapses each block
        straight to `backbone[next_state]`, which BYPASSES the dispatcher and
        therefore drops these instructions; the work block then runs with the
        wrong register state (e.g. a blinded API pointer computed from leftover
        opaque math instead of the real key). A function whose dispatcher has
        any such node cannot be safely unflattened by edge rewriting alone, so
        it is left dispatching (correctness-first; see unflatten_function).

        Cached. Returns {cmp_ea: [side_effect_ea, ...]}."""
        cache = getattr(self, "_impure_cache", None)
        if cache is not None:
            return cache
        sm = self.sm
        sc = L1._canon_reg(sm.state_reg)
        out = {}
        for c in sm.tree_cmps:
            jcc = sm._next_jcc(c)
            if jcc is None:
                continue
            se = []
            a = idc.next_head(c, sm.FE)
            while a != idc.BADADDR and a < jcc:
                if (idc.get_operand_type(a, 0) == idc.o_reg
                        and L1._canon_reg(idc.print_operand(a, 0)) != sc):
                    se.append(a)
                a = idc.next_head(a, sm.FE)
            if se:
                out[c] = se
        self._impure_cache = out
        return out

    def report(self):
        cond = sum(1 for V in self.live
                   if self.res.get(V, {}).get("kind") == "cond")
        nway = sum(1 for V in self.live
                   if self.res.get(V, {}).get("kind") == "nway")
        unres = [V for V in self.live if not self._patchable(V)]
        imp = self._impure_nodes()
        return {"name": self.sm.name, "states": len(self.bb),
                "work": len(getattr(self, "work", self.bb)),
                "live": len(self.live),
                "cond": cond, "nway": nway,
                "entry": self.S0, "clean": self.is_clean(),
                "decoy": self.is_decoy(),
                "impure": len(imp),
                "impure_instrs": sum(len(v) for v in imp.values()),
                "unresolved": len(unres)}


class PerHopPatcher(object):
    """Realise a PerHopResolver's edges as byte patches at the state-write site.
    Every patch is independently correct, so unresolved blocks are simply left
    dispatching (partial, but never wrong)."""

    def __init__(self, resolver):
        self.r = resolver
        self.sm = resolver.sm

    def _uncond_anchor(self, site):
        """For an unconditional state edge whose store `site` is too tight for a
        5-byte jmp, walk back over the dead state-value computation that precedes
        it -- register-only writes (mov/cmov/lea/...) and their flag-setters, all
        block-private -- and return the earliest such anchor. These instructions
        only produce the state constant the dispatcher consumes; once we branch
        direct they are all dead, so overwriting them is sound. Stops at the
        first memory write, call, branch, or externally-entered byte (so any real
        work or a foreign jump target before the selection is preserved). Returns
        `site` unchanged when nothing earlier is safe."""
        sm = self.sm
        anchor = site
        p = site
        for _ in range(16):
            q = idc.prev_head(p, sm.FS)
            if q == idc.BADADDR or q < sm.FS:
                break
            # p must be entered only by falling through from q (block-private);
            # and p must not itself be a dispatcher decode site.
            if any(x != q for x in idautils.CodeRefsTo(p, 1)):
                break
            if p in sm.state_loads or p in sm.tree_cmps:
                break
            mn = idc.print_insn_mnem(q)
            if mn not in _EMU_FLAGSET:
                # restrict to the state-selection vocabulary (constant loads,
                # conditional moves, and the slot-pointer load) writing a
                # register -- never arithmetic, which could be real live-out
                # work, nor any memory write / call / branch.
                if not (mn == "mov" or mn.startswith("cmov")
                        or mn in ("movzx", "movsx", "lea")):
                    break
                if (idc.get_operand_type(q, 0) != idc.o_reg
                        or "[" in idc.print_operand(q, 0)):
                    break
            anchor = q
            p = q
        return anchor

    def _emit_uncond(self, site, succ_head, used):
        anchor = site
        code = _enc_jmp(anchor, succ_head)
        if code is None:
            return None, "uncond-range"
        rs, room = _contig_region(self.sm, anchor)
        if rs != anchor or len(code) > room:
            # store site too tight; reclaim the dead state-value selection.
            anchor = self._uncond_anchor(site)
            if anchor == site:
                return None, "uncond-noroom"
            code = _enc_jmp(anchor, succ_head)
            if code is None:
                return None, "uncond-range"
            rs, room = _contig_region(self.sm, anchor)
            if rs != anchor or len(code) > room:
                return None, "uncond-noroom"
        code = code + b"\x90" * (room - len(code))
        if used.get(anchor, code) != code:
            return None, "anchor-collision"
        return (anchor, code), None

    def _cmov_anchor(self, D):
        """For a cmov discriminator whose own contiguous region is too tight for
        `jcc+jmp` (11 bytes), return an EARLIER anchor: the instruction right
        after the compare/test that set the cmov's flags. This is sound only when
        every instruction between that anchor and the cmov is a dead write to the
        cmov's own destination register (the obfuscator's `mov dst, false_state`
        load), so overwriting them loses nothing, AND the controlling flags still
        come from that same compare (mov never touches flags). Gives the room a
        tight cmov site lacks (e.g. `test;mov dst,K;cmov dst,reg;mov [slot],dst`
        -> 11 bytes from the mov). Returns D unchanged when no safe extension."""
        sm = self.sm
        if idc.get_operand_type(D, 0) != idc.o_reg:
            return D
        # The cmov's own dst and (register) src hold the two dead state constants
        # ("mov dst,K_false; mov src,K_true; cmov dst,src"); loads into either are
        # safe to overwrite, since after unflattening both registers are dead.
        allowed = {L1._canon_reg(idc.print_operand(D, 0))}
        if idc.get_operand_type(D, 1) == idc.o_reg:
            allowed.add(L1._canon_reg(idc.print_operand(D, 1)))
        fs = None
        p = D
        for _ in range(8):
            p = idc.prev_head(p, sm.FS)
            if p == idc.BADADDR or p < sm.FS:
                break
            if idc.print_insn_mnem(p) in _EMU_FLAGSET:
                fs = p
                break
        if fs is None:
            return D
        anchor = idc.next_head(fs, sm.FE)
        if anchor == D or not (sm.FS <= anchor < D):
            return D
        # anchor must be block-private (only the compare flows into it)
        if any(x != fs for x in idautils.CodeRefsTo(anchor, 1)):
            return D
        if anchor in sm.state_loads or anchor in sm.tree_cmps:
            return D
        # every instruction in [anchor, D) must be a dead write to a cmov reg
        a = anchor
        while a < D:
            if (idc.print_insn_mnem(a) != "mov"
                    or idc.get_operand_type(a, 0) != idc.o_reg
                    or L1._canon_reg(idc.print_operand(a, 0)) not in allowed
                    or idc.get_operand_type(a, 1) not in (idc.o_reg, idc.o_imm)):
                return D
            a = idc.next_head(a, sm.FE)
        return anchor

    def _emit_cond_at(self, anchor, cc, head_t, head_f, used):
        jcc = _enc_jcc(anchor, cc, head_t)
        if jcc is None:
            return None, "cond-range"
        jmp = _enc_jmp(anchor + len(jcc), head_f)
        if jmp is None:
            return None, "cond-range"
        rs, room = _contig_region(self.sm, anchor)
        code = jcc + jmp
        if rs != anchor or len(code) > room:
            return None, "cond-noroom"
        code = code + b"\x90" * (room - len(code))
        if used.get(anchor, code) != code:
            return None, "anchor-collision"
        return (anchor, code), None

    def _reaches_cmov(self, tgt, D):
        """True if a short chain of near jmps from `tgt` lands on the shared cmov
        gadget `D` (states reach the gadget by `jmp D`, sometimes via one or two
        relay jmps)."""
        a = tgt
        for _ in range(4):
            if a == D:
                return True
            if idc.print_insn_mnem(a) != "jmp" \
                    or idc.get_operand_type(a, 0) != idc.o_near:
                return False
            a = idc.get_operand_value(a, 0)
        return a == D

    def _state_cond_anchor(self, V, D):
        """For a cond whose discriminator cmov `D` is a SHARED gadget that several
        states reach by `jmp D`, the real per-state decision lives in V's OWN
        block: `<flag-setter>; mov dst,F; mov src,T; jmp <gadget->D>` where dst/src
        are D's cmov operands and F/T are state constants that become dead once we
        branch directly. Return that block-private anchor (the first dead mov after
        the flag-setter), so jcc+jmp can be emitted in the reclaimed F/T-load
        bytes; None when V's block has no such shared-gadget tail."""
        sm, r = self.sm, self.r
        if (not idc.print_insn_mnem(D).startswith("cmov")
                or idc.get_operand_type(D, 0) != idc.o_reg):
            return None
        dst = L1._canon_reg(idc.print_operand(D, 0))
        allowed = {dst}
        if idc.get_operand_type(D, 1) == idc.o_reg:
            allowed.add(L1._canon_reg(idc.print_operand(D, 1)))
        # block-private DFS from V's head to find the jmp that enters the gadget
        head = r.bb[V]
        seen = set()
        stack = [head]
        jmp_site = None
        while stack:
            a = stack.pop()
            if a in seen or not (sm.FS <= a < sm.FE):
                continue
            seen.add(a)
            if a != head and a in r.head2state:
                continue
            mn = idc.print_insn_mnem(a)
            if mn in ("ret", "retn"):
                continue
            if mn == "jmp":
                if idc.get_operand_type(a, 0) != idc.o_near:
                    continue
                tgt = idc.get_operand_value(a, 0)
                if self._reaches_cmov(tgt, D):
                    if jmp_site is not None and jmp_site != a:
                        return None        # ambiguous; refuse
                    jmp_site = a
                else:
                    stack.append(tgt)
                continue
            if mn and mn[0] == "j":
                stack.append(idc.get_operand_value(a, 0))
                stack.append(idc.next_head(a, sm.FE))
                continue
            stack.append(idc.next_head(a, sm.FE))
        if jmp_site is None:
            return None
        # nearest preceding flag-setter; [anchor, jmp_site] must be dead movs to
        # the cmov's own dst/src registers (the F/T state loads we overwrite)
        fs = None
        p = jmp_site
        for _ in range(8):
            p = idc.prev_head(p, sm.FS)
            if p == idc.BADADDR or p < sm.FS:
                break
            if idc.print_insn_mnem(p) in _EMU_FLAGSET:
                fs = p
                break
        if fs is None:
            return None
        anchor = idc.next_head(fs, sm.FE)
        if not (sm.FS <= anchor <= jmp_site):
            return None
        if any(x != fs for x in idautils.CodeRefsTo(anchor, 1)):
            return None
        if anchor in sm.state_loads or anchor in sm.tree_cmps:
            return None
        a = anchor
        while a < jmp_site:
            if (idc.print_insn_mnem(a) != "mov"
                    or idc.get_operand_type(a, 0) != idc.o_reg
                    or L1._canon_reg(idc.print_operand(a, 0)) not in allowed
                    or idc.get_operand_type(a, 1) not in (idc.o_reg, idc.o_imm)):
                return None
            a = idc.next_head(a, sm.FE)
        return anchor

    def _alloc_cave(self, n):
        """Hand out `n` bytes from the .text trailing padding cave, low-to-high.
        The high-water mark is seeded (lazily, per plan) from the current free
        run, so repeated plans of the same function return identical addresses
        and successive functions never overlap. Returns the start ea or None."""
        if self._cave_hwm is None:
            s, e = _cave_region()
            if s is None:
                return None
            self._cave_hwm, self._cave_end = s, e
        at = self._cave_hwm
        if at + n > self._cave_end:
            return None
        self._cave_hwm = at + n
        return at

    def _orcmov_chain(self, D):
        """Detect an OR-of-cmov chain ending at discriminator `D`:
            mov dst, F_imm ; [fs] cmov dst,src ; fs ; cmov dst,src ; ... ;
            mov [slot], dst
        where every cmov shares dst & src (so the stored value is `src` when ANY
        condition fires, else the default constant `F_imm`). This cannot be
        expressed by overwriting the tight cmov bytes; instead we relocate the
        whole decision to a code cave. Returns (anchor, ops, f_imm): `anchor` is
        the `mov dst,F_imm`; `ops` is the ordered cave recipe -- ('jcc',cc) per
        cmov, ('copy',ea,sz) per intervening flag-setter, ('jmp_f',) terminator;
        `f_imm` is the default state constant. None when the structure does not
        match (so single-cmov conds keep their normal inline handling)."""
        sm = self.sm
        if (not idc.print_insn_mnem(D).startswith("cmov")
                or idc.get_operand_type(D, 0) != idc.o_reg
                or idc.get_operand_type(D, 1) != idc.o_reg):
            return None
        dst = L1._canon_reg(idc.print_operand(D, 0))
        src = L1._canon_reg(idc.print_operand(D, 1))
        anchor = None
        f_imm = None
        p = D
        for _ in range(16):
            p = idc.prev_head(p, sm.FS)
            if p == idc.BADADDR or p < sm.FS:
                return None
            mn = idc.print_insn_mnem(p)
            if (mn == "mov" and idc.get_operand_type(p, 0) == idc.o_reg
                    and L1._canon_reg(idc.print_operand(p, 0)) == dst
                    and idc.get_operand_type(p, 1) == idc.o_imm):
                anchor = p
                f_imm = idc.get_operand_value(p, 1) & U32
                break
            if mn in _EMU_FLAGSET:
                continue
            if (mn.startswith("cmov")
                    and idc.get_operand_type(p, 0) == idc.o_reg
                    and L1._canon_reg(idc.print_operand(p, 0)) == dst
                    and idc.get_operand_type(p, 1) == idc.o_reg
                    and L1._canon_reg(idc.print_operand(p, 1)) == src):
                continue
            return None
        if anchor is None:
            return None
        # the whole chain [anchor, D] must be block-private (no foreign entry)
        prev = anchor
        a = idc.next_head(anchor, sm.FE)
        while a <= D:
            if any(x != prev for x in idautils.CodeRefsTo(a, 1)):
                return None
            prev = a
            a = idc.next_head(a, sm.FE)
        # forward walk -> cave recipe up to the store of dst
        ops = []
        ncmov = 0
        a = idc.next_head(anchor, sm.FE)
        store = None
        while a < sm.FE:
            mn = idc.print_insn_mnem(a)
            if (mn.startswith("cmov")
                    and idc.get_operand_type(a, 0) == idc.o_reg
                    and L1._canon_reg(idc.print_operand(a, 0)) == dst
                    and idc.get_operand_type(a, 1) == idc.o_reg
                    and L1._canon_reg(idc.print_operand(a, 1)) == src):
                ops.append(("jcc", mn[4:]))
                ncmov += 1
            elif mn in _EMU_FLAGSET:
                # only relocate position-independent flag-setters (reg / rbp- or
                # reg-relative memory); a rip-relative compare would break.
                if (idc.get_operand_type(a, 0) == idc.o_mem
                        or idc.get_operand_type(a, 1) == idc.o_mem):
                    return None
                ops.append(("copy", a, idc.get_item_size(a)))
            elif (mn == "mov"
                  and idc.get_operand_type(a, 0) in (idc.o_phrase, idc.o_displ,
                                                     idc.o_mem)
                  and idc.get_operand_type(a, 1) == idc.o_reg
                  and L1._canon_reg(idc.print_operand(a, 1)) == dst):
                store = a
                break
            else:
                return None
            a = idc.next_head(a, sm.FE)
        if store is None or ncmov < 2:
            return None
        ops.append(("jmp_f",))
        return anchor, ops, f_imm

    def _emit_cond_cave(self, D, head_t, head_f, used):
        """Realise an OR-of-cmov cond via a code-cave trampoline: patch the
        chain's `mov dst,F` anchor with `jmp cave`, and emit the full decision
        (`jcc T` per condition, with intervening compares copied verbatim, then
        `jmp F`) in the cave. The cave is appended as a function tail in apply(),
        so Hex-Rays decompiles it as part of the function. Returns the anchor
        patch (anchor, code) and records the cave bytes/ tail on self, or None."""
        sm, r = self.sm, self.r
        ch = self._orcmov_chain(D)
        if ch is None:
            return None
        anchor, ops, f_imm = ch
        # sanity: the default (F) arm must map to head_f
        if r.bb.get(r._final(f_imm)) != head_f:
            return None
        size = sum(6 if op[0] == "jcc" else (op[2] if op[0] == "copy" else 5)
                   for op in ops)
        cave = self._alloc_cave(size)
        if cave is None:
            return None
        buf = b""
        off = cave
        for op in ops:
            if op[0] == "jcc":
                c = _enc_jcc(off, op[1], head_t)
            elif op[0] == "copy":
                c = idc.get_bytes(op[1], op[2])
            else:
                c = _enc_jmp(off, head_f)
            if c is None:
                return None
            buf += c
            off += len(c)
        jc = _enc_jmp(anchor, cave)
        if jc is None:
            return None
        rs, room = _contig_region(sm, anchor)
        if rs != anchor or len(jc) > room or anchor in used:
            return None
        anchor_code = jc + b"\x90" * (room - len(jc))
        self._extra.append((cave, buf, "orcmov-cave %#x" % anchor))
        self._cave_tails.append((cave, cave + len(buf)))
        return (anchor, anchor_code)

    def _emit_cond(self, D, head_t, head_f, used, V=None):
        mn = idc.print_insn_mnem(D)
        if not mn.startswith("cmov"):
            # Only cmov discriminators are realised by overwriting; a real jcc
            # that already targets the heads is handled (no-op) in plan().
            return None, "cond-notcmov"
        cc = mn[4:]
        # Try the tight cmov site first so every function that already patched
        # stays byte-identical; only when it lacks room fall back to the earlier
        # flag-aware anchor (which reclaims the dead state-value load's bytes).
        got, err = self._emit_cond_at(D, cc, head_t, head_f, used)
        if err == "cond-noroom":
            anchor = self._cmov_anchor(D)
            if anchor != D:
                got2, err2 = self._emit_cond_at(anchor, cc, head_t, head_f, used)
                if not err2:
                    return got2, None
            # Shared-gadget cond: D is reached by `jmp D` from several states, so
            # it has no per-state room of its own. Patch in V's own block at the
            # decision it set up before jumping into the shared cmov.
            if V is not None:
                sa = self._state_cond_anchor(V, D)
                if sa is not None:
                    got3, err3 = self._emit_cond_at(sa, cc, head_t, head_f, used)
                    if not err3:
                        return got3, None
            # OR-of-cmov chain (>=2 cmovs select one true value, default false):
            # no inline anchor can hold the multi-condition test; relocate the
            # whole decision to a code cave reached by `jmp cave`.
            got4 = self._emit_cond_cave(D, head_t, head_f, used)
            if got4 is not None:
                return got4, None
        return got, err

    def plan(self):
        r, bb = self.r, self.r.bb
        patches = []
        refused = []
        used = {}
        # per-plan code-cave state (relocation trampolines + their func tails)
        self._extra = []
        self._cave_tails = []
        self._cave_hwm = None
        self._cave_end = None
        if r.s0_site is not None and r.S0 in bb:
            got, err = self._emit_uncond(r.s0_site, bb[r.S0], used)
            if got:
                used[got[0]] = got[1]
                patches.append((got[0], got[1], "entry %#x" % r.S0))
            else:
                refused.append(("entry", err))
        for V in sorted(r.live):
            c = r.res.get(V, {})
            kind = c.get("kind")
            if kind in ("ret", "nway"):
                # ret: nothing to redirect. nway: the block's real >2-way branch
                # already targets backbone heads directly, so it needs no patch.
                continue
            if kind == "uncond":
                site = c.get("site")
                if site is None:
                    refused.append((V, "uncond-nosite"))
                    continue
                got, err = self._emit_uncond(site, bb[r._final(c["succ"][0])],
                                             used)
            elif kind == "cond":
                D = c["disc"]
                ht = bb[r._final(c["t"])]
                hf = bb[r._final(c["f"])]
                mnD = idc.print_insn_mnem(D)
                # Already-direct real jcc: the discriminator is the program's own
                # conditional branch whose existing targets are EXACTLY the two
                # successor heads (taken -> t, fall-through -> f). The edge is
                # already materialised in the bytes, so no patch is needed --
                # emitting one here would only risk a range/room refusal that
                # would (via the safety gate) needlessly skip the whole function.
                if (mnD and mnD[0] == "j" and not mnD.startswith("cmov")
                        and idc.get_operand_value(D, 0) == ht
                        and idc.next_head(D, self.sm.FE) == hf):
                    continue
                got, err = self._emit_cond(D, ht, hf, used, V)
            else:
                refused.append((V, kind))
                continue
            if err:
                refused.append((V, err))
                continue
            used[got[0]] = got[1]
            patches.append((got[0], got[1],
                            "%s %#x" % (kind, V)))
        patches.extend(self._extra)
        return patches, refused

    def apply(self):
        patches, refused = self.plan()
        if not patches:
            return {"patched": 0, "refused": refused}
        for ea, code, _ in patches:
            ida_bytes.patch_bytes(ea, code)
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(code))
        for ea, code, _ in patches:
            a, end = ea, ea + len(code)
            while a < end:
                if ida_ua.create_insn(a) == 0:
                    break
                a += idc.get_item_size(a)
        ida_funcs.del_func(self.sm.FS)
        ida_funcs.add_func(self.sm.FS, self.sm.FE)
        # Attach any relocation caves as function tails so Hex-Rays decompiles
        # the trampolines as part of the function (the `jmp cave` would otherwise
        # read as a tail call). Done after add_func, which only covers FS..FE.
        for cs, ce in getattr(self, "_cave_tails", []):
            pfn = ida_funcs.get_func(self.sm.FS)
            if pfn is not None:
                ida_funcs.append_func_tail(pfn, cs, ce)
        if getattr(self, "_cave_tails", None):
            try:
                import ida_auto
                ida_auto.auto_wait()
            except Exception:
                pass
            # appending a tail after add_func leaves any prior pseudocode cached;
            # invalidate it so the trampoline is not shown as a stale JUMPOUT.
            try:
                import ida_hexrays
                ida_hexrays.mark_cfunc_dirty(self.sm.FS)
            except Exception:
                pass
        return {"patched": len(patches), "refused": refused,
                "caves": len(getattr(self, "_cave_tails", []))}


# ---------------------------------------------------------------------------
# orchestration: discover, report, and unflatten across the whole binary
# (Backend A, the chosen byte-patch backend)
# ---------------------------------------------------------------------------
def _msg(s):
    try:
        import ida_kernwin
        ida_kernwin.msg(s)
    except Exception:
        print(s, end="")


def analyze_function(ea):
    """Read-only analysis for one function. Returns (sm, resolver, report).
    `resolver` is None when the function is not a flattened state machine."""
    sm = StateMachine(ea)
    if not sm.looks_flattened():
        return sm, None, {"name": sm.name, "flattened": False}
    r = PerHopResolver(sm)
    if not r.ok:
        return sm, None, {"name": sm.name, "flattened": True,
                          "recover_ok": False,
                          "recover_reason": "no decode params"}
    r.analyze()
    rep = r.report()
    rep["flattened"] = True
    rep["recover_ok"] = True
    return sm, r, rep


def _is_clean(rep):
    """Fully recoverable: a single prologue entry and a live work graph with no
    unresolved leaves (the Resolver's clean verdict)."""
    return bool(rep.get("flattened") and rep.get("recover_ok")
                and rep.get("clean"))


def iter_flattened(funcs=None):
    import idautils
    if funcs is None:
        funcs = list(idautils.Functions())
    for ea in funcs:
        try:
            sm = StateMachine(ea)
        except Exception:
            continue
        if sm.looks_flattened():
            yield ea


def report_all():
    """Read-only sweep: classify every flattened function. Returns a list of
    per-function reports and prints a summary."""
    import idautils
    funcs = list(idautils.Functions())
    reports = []
    t0 = time.time()
    flat = list(iter_flattened(funcs))
    _msg("[layer2] %d flattened function(s) found\n" % len(flat))
    for i, ea in enumerate(flat):
        try:
            _sm, _r, rep = analyze_function(ea)
        except Exception as e:
            rep = {"name": idc.get_func_name(ea), "flattened": True,
                   "error": str(e)}
        rep["ea"] = ea
        rep["clean"] = _is_clean(rep)
        reports.append(rep)
        _msg("[layer2] (%d/%d) %-32s %s\n"
             % (i + 1, len(flat), rep.get("name", "?"), _short(rep)))
    clean = sum(1 for r in reports if r.get("clean"))
    partial = sum(1 for r in reports
                  if not r.get("clean") and r.get("recover_ok")
                  and r.get("live", 0) > 0)
    _msg("[layer2] %d/%d fully recoverable, %d partially recoverable (%.1fs)\n"
         % (clean, len(reports), partial, time.time() - t0))
    return reports


def _short(rep):
    if rep.get("error"):
        return "ERROR: " + rep["error"]
    if not rep.get("flattened"):
        return "not flattened"
    if not rep.get("recover_ok"):
        return "recover failed: %s" % rep.get("recover_reason")
    if rep.get("impure"):
        tag = ("skip(impure: %d dispatcher side-effect instr(s) -> left "
               "dispatching)" % rep.get("impure_instrs", 0))
    else:
        tag = "CLEAN" if rep.get("clean") else "skip(unclean)"
    return ("states=%d work=%d live=%d cond=%d entry=%s %s"
            % (rep.get("states", 0), rep.get("work", 0), rep.get("live", 0),
               rep.get("cond", 0),
               ("%#x" % rep["entry"]) if rep.get("entry") else "None", tag))


def unflatten_function(ea, do_apply=True):
    """Recover and (optionally) byte-patch one function.

    Correctness-first: a function is patched ONLY when its live work graph is
    fully clean (single prologue entry, no unresolved leaves) AND every live
    edge has a private, in-range patch anchor. Otherwise it is left untouched at
    Layer 1 -- we never emit a partial rewrite that could wire up a wrong edge.
    """
    sm, r, rep = analyze_function(ea)
    rep["ea"] = ea
    if not rep.get("flattened"):
        rep["applied"] = False
        rep["skip_reason"] = "not flattened"
        return rep
    if not rep.get("recover_ok"):
        # We cannot recover the real CFG for this function (e.g. the
        # opaque-predicate + dynamic stack-slot family has no global decode
        # params), but it is still a flattened state machine riddled with
        # always-invariant opaque-predicate branch gadgets. Folding those is
        # always sound -- it removes only branches proven dead by the g*(g-1)
        # identity -- and on this family it alone collapses the decoy dispatch
        # maze and every spurious goto, leaving a small readable state loop.
        # So we fall back to opaque-folding rather than leaving the function
        # fully obfuscated.
        rep["applied"] = False
        rep["recovered"] = False
        if do_apply:
            rep["folded"] = OpaqueFolder(ea).apply().get("folded", 0)
            rep["skip_reason"] = ("recover failed (%s); opaque-folded %d "
                                  "predicate(s) instead"
                                  % (rep.get("recover_reason"), rep["folded"]))
        else:
            rep["would_fold"] = len(OpaqueFolder(ea).plan())
            rep["skip_reason"] = ("recover failed (%s); would opaque-fold %d "
                                  "predicate(s)"
                                  % (rep.get("recover_reason"),
                                     rep["would_fold"]))
        return rep
    if rep.get("entry") is None or not rep.get("live"):
        rep["applied"] = False
        rep["skip_reason"] = "no entry / empty live graph"
        return rep
    if r.is_decoy():
        rep["applied"] = False
        rep["decoy"] = True
        rep["skip_reason"] = ("jump-table decoy entry (live path does no work; "
                              "real body behind a computed-goto dispatcher)")
        return rep
    # Impure dispatcher: the binary-search tree carries hoisted side-effects
    # (real `mov`/`lea` into argument/key registers wedged between a state
    # compare and its jcc, e.g. `mov rdx, r12`). Unflattening rewrites each
    # block straight to its successor head, bypassing the dispatcher -- which
    # would silently drop those instructions and deliver the wrong register
    # state to the work blocks (mis-resolved API calls, broken decompilation).
    # Recovering them needs side-effect replay (planned Layer-2 work); until
    # then we refuse to collapse the edges and leave the function dispatching,
    # opaque-folding the dead parity gadgets for readability (always sound).
    imp = r._impure_nodes()
    if imp:
        nse = sum(len(v) for v in imp.values())
        rep["applied"] = False
        rep["impure"] = len(imp)
        rep["impure_instrs"] = nse
        if do_apply:
            rep["folded"] = OpaqueFolder(ea).apply().get("folded", 0)
            rep["skip_reason"] = (
                "dispatcher has %d impure node(s) carrying %d hoisted "
                "side-effect instruction(s) (e.g. argument/key setup like "
                "`mov rdx, r12`); collapsing edges would bypass them, so the "
                "function is left dispatching; opaque-folded %d predicate(s) "
                "instead" % (len(imp), nse, rep["folded"]))
        else:
            rep["would_fold"] = len(OpaqueFolder(ea).plan())
            rep["skip_reason"] = (
                "dispatcher has %d impure node(s) carrying %d hoisted "
                "side-effect instruction(s); would leave dispatching and "
                "opaque-fold %d predicate(s)"
                % (len(imp), nse, rep["would_fold"]))
        return rep
    # Jump-table family: the computed-goto dispatcher is SHARED by every state,
    # so a single unresolved block keeps the whole compare tree (and thus the
    # flattening) reachable -- partial patches then produce a worse hybrid than
    # the original. Only patch this family when fully clean; otherwise leave it
    # at Layer 1. (The stack-mirror family dispatches per-block, so it still
    # benefits from partial patching and is not gated here.)
    if r.follow_ijmp and not r.is_clean():
        rep["applied"] = False
        rep["skip_reason"] = ("jump-table family only partially resolved "
                              "(%d live states, %d unresolved); shared "
                              "computed-goto dispatcher would stay live, "
                              "left at Layer 1"
                              % (len(r.live),
                                 sum(1 for V in r.live if not r._patchable(V))))
        return rep
    bk = PerHopPatcher(r)
    plans, refused = bk.plan()
    rep["plan_count"] = len(plans)
    rep["plan_refused"] = refused
    # Jump-table family: every edge must get a real patch, because the shared
    # computed-goto dispatcher stays live if ANY block is left dispatching (see
    # the is_clean() gate above). is_clean() is kind-based, so it accepts a block
    # whose edge cannot actually be encoded (no private in-range anchor -- e.g. a
    # cmov-cond with real work wedged between the state-store and the dispatch,
    # which needs instruction relocation we do not do). Catch that here so the
    # function is left whole at Layer 1 instead of partially patched into a
    # worse hybrid. (The stack-mirror family dispatches per block, so partial
    # patching is still safe and beneficial -- it is not gated.)
    if r.follow_ijmp and refused:
        rep["applied"] = False
        rep["skip_reason"] = ("jump-table family: %d live edge(s) have no "
                              "private in-range patch anchor (real work between "
                              "the state-store and dispatch needs instruction "
                              "relocation); left at Layer 1 to avoid a partial "
                              "hybrid" % len(refused))
        return rep
    # Each hop patch is independently correct (locally equivalent to the
    # dispatcher's own routing), so we apply every edge we can prove and leave
    # any unresolved block dispatching through the still-intact tree -- a small,
    # correct residual rather than refusing the whole function.
    if not plans:
        rep["applied"] = False
        rep["skip_reason"] = "no patchable edge (refused=%d)" % len(refused)
        return rep
    if do_apply:
        res = bk.apply()
        rep["applied"] = True
        rep["patched"] = res["patched"]
        rep["caves"] = res.get("caves", 0)
        # Fold the always-invariant opaque-predicate branch gadgets so Hex-Rays
        # does not show the dead parity tests as spurious if()/while() clutter.
        rep["folded"] = OpaqueFolder(ea).apply().get("folded", 0)
    else:
        rep["applied"] = False
        rep["would_patch"] = len(plans)
        rep["would_fold"] = len(OpaqueFolder(ea).plan())
    rep["fully"] = rep.get("clean", False)
    rep["partial"] = not rep["fully"]
    return rep


def unflatten_all(do_apply=True):
    """Unflatten every cleanly-recoverable flattened function."""
    flat = list(iter_flattened())
    _msg("[layer2] unflattening %d flattened function(s)\n" % len(flat))
    # Make sure even the largest de-flattened function can be decompiled
    # afterwards (Hex-Rays' default MAX_FUNCSIZE is only 64 KB).
    try:
        biggest = max((ida_funcs.get_func(ea).end_ea
                       - ida_funcs.get_func(ea).start_ea) for ea in flat)
        L1.ensure_decompiler_limit(biggest + 0x1000)
    except Exception:
        pass
    t0 = time.time()
    done = 0
    folded_only = 0
    skipped = []
    for i, ea in enumerate(flat):
        try:
            rep = unflatten_function(ea, do_apply=do_apply)
        except Exception as e:
            skipped.append((idc.get_func_name(ea), "exception: %s" % e))
            _msg("[layer2] (%d/%d) %-32s EXCEPTION %s\n"
                 % (i + 1, len(flat), idc.get_func_name(ea), e))
            continue
        if rep.get("applied"):
            done += 1
            _msg("[layer2] (%d/%d) %-32s patched %d blocks\n"
                 % (i + 1, len(flat), rep["name"], rep.get("patched", 0)))
        elif rep.get("folded"):
            # Could not unflatten, but stripped the opaque-predicate maze --
            # still a real, sound improvement for the obfuscated family.
            folded_only += 1
            _msg("[layer2] (%d/%d) %-32s opaque-folded %d predicate(s)\n"
                 % (i + 1, len(flat), rep.get("name"), rep.get("folded")))
        else:
            skipped.append((rep.get("name"), rep.get("skip_reason")))
            _msg("[layer2] (%d/%d) %-32s SKIP (%s)\n"
                 % (i + 1, len(flat), rep.get("name"), rep.get("skip_reason")))
    _msg("[layer2] done: %d unflattened, %d opaque-folded, %d skipped (%.1fs)\n"
         % (done, folded_only, len(skipped), time.time() - t0))
    return {"unflattened": done, "folded_only": folded_only, "skipped": skipped}
