"""
cff.layer1  --  CFF Layer 1: indirect-jump de-indirection for IDA Pro 9.x

This is the "de-indirection" pass for the control-flow-flattening obfuscator seen in
FortiEndpoint_Patch.exe. Each flattened function ends every basic block with a decode
gadget that computes a jump target into a per-function key/table and then does
`jmp <reg>`. The decompiler dead-ends at the first such indirect jump, so almost the
entire function is invisible.

Layer 1 statically resolves each `jmp <reg>` to its concrete target with a small,
read-only x86-64 micro-emulator and (optionally) rewrites the gadget tail in place to a
direct `jmp <target>` so Hex-Rays can see the whole (still-flattened) function. Turning
the flattened state machine back into structured control flow is Layer 2 (separate).

DESIGN NOTES
------------
* Read-only by default. `analyze()` never modifies the database; it only reports.
* `patch()` is opt-in and gated by hard safety checks. It only ever
  overwrites confirmed dead decode-tail bytes (add/mov/lea/nop) and only when the target
  is in-function, on an instruction head, and not a real compiler switch table.
* The emulator FAILS SAFE: when a value or a conditional-move predicate is unknown it
  yields None (unresolved) rather than fabricating a target. Resolved targets are therefore
  trustworthy.

DECOMPILER SIZE LIMIT (MAX_FUNCSIZE)
-----------------------------------
Flattened functions stay physically huge after Layer 1 (the dispatcher/state-machine
bloat is still there -- chromium_extract is ~330 KB). That exceeds Hex-Rays' default
MAX_FUNCSIZE guard of 64 KB, so those functions fail to decompile with MERR_FUNCSIZE
(error -29). This module auto-raises the limit (see ensure_decompiler_limit) on plugin
load and before patch_all. NOTE: MAX_FUNCSIZE=0 does NOT mean "unlimited" -- it must be
an explicit KB value. The override is per-session (Hex-Rays does not persist it to the
IDB), so it is re-applied every time the plugin loads.

This module is normally driven by the CFF Deobfuscator plugin
(cff.orchestrator), but its functions can also be used directly from IDA's
Python console:

    from cff import layer1 as L1

    L1.report("reg_read_str")    # read-only report on one function
    L1.report_all()              # read-only report on every flattened function
    L1.patch("reg_read_str")     # rewrite jumps for one function (modifies IDB)
    L1.patch_all()               # rewrite jumps for every flattened function
"""

import re
import time

import idc
import idaapi
import idautils
import ida_ua
import ida_bytes
import ida_funcs
import ida_auto
import ida_nalt
import ida_kernwin

try:
    import ida_hexrays
    _HAS_HEXRAYS = True
except Exception:
    _HAS_HEXRAYS = False

U64 = (1 << 64) - 1

# ---------------------------------------------------------------------------
# register file model
# ---------------------------------------------------------------------------
_R64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def _build_regmap():
    # name -> (index, width_bytes, is_high_byte)
    m = {}
    for i, n in enumerate(_R64):
        m[n] = (i, 8, 0)
    for i, n in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                          + ['r%dd' % i for i in range(8, 16)]):
        m[n] = (i, 4, 0)
    for i, n in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
                          + ['r%dw' % i for i in range(8, 16)]):
        m[n] = (i, 2, 0)
    for i, n in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil']
                          + ['r%db' % i for i in range(8, 16)]):
        m[n] = (i, 1, 0)
    for n, t in {'ah': (0, 1, 1), 'ch': (1, 1, 1),
                 'dh': (2, 1, 1), 'bh': (3, 1, 1)}.items():
        m[n] = t
    return m


_N2I = _build_regmap()

# mnemonics that may appear inside a decode gadget
_GADGET_MNEMS = {'mov', 'lea', 'imul', 'test', 'cmp', 'add', 'sub', 'and', 'or',
                 'xor', 'nop', 'movzx', 'movsxd', 'movsx', 'shl', 'sal', 'shr', 'sar'}

# mnemonics that are safe to overwrite as a dead decode tail
_TAIL_SAFE = {'add', 'mov', 'lea', 'nop'}

# Win64 volatile (caller-saved) registers, clobbered across a `call`.
# Indices into the register file: rax rcx rdx r8 r9 r10 r11.
_VOL = [0, 1, 2, 8, 9, 10, 11]

# Mnemonics whose only architectural effect is to overwrite operand-0's register
# (plus flags). When such an instruction is the *dead decode writer* of a jump
# target register, it is safe to DROP to reclaim space for a direct jmp.
_DROP_WRITER_MNEMS = {'mov', 'lea', 'add', 'sub', 'or', 'and', 'xor', 'imul',
                      'movzx', 'movsx', 'movsxd', 'shl', 'sal', 'shr', 'sar',
                      'rol', 'ror', 'neg', 'not', 'inc', 'dec', 'bswap'}

# Live instructions we may relocate must not depend on the flags we are about to
# drop, so flag-reading instructions are never relocated.
_FLAG_READER_PREFIXES = ('cmov', 'set', 'j')
_FLAG_READER_MNEMS = {'adc', 'sbb', 'rcl', 'rcr'}


def _canon_reg(name):
    """Map any sub-register name (eax/r11d/al/...) to its 64-bit canonical form."""
    t = _N2I.get(name)
    return _R64[t[0]] if t else None


_REG_ALIASES = {}
for _an, _at in _N2I.items():
    _REG_ALIASES.setdefault(_R64[_at[0]], set()).add(_an)


def _writes_reg0(ea, creg):
    """True if `ea`'s destination (operand 0) is the canonical register creg."""
    return (idc.get_operand_type(ea, 0) == idc.o_reg
            and _canon_reg(idc.print_operand(ea, 0)) == creg)


def _is_droppable_writer(ea, creg):
    """A dead decode writer of creg that is safe to delete (only touches creg+flags)."""
    mn = idc.print_insn_mnem(ea)
    if not (mn in _DROP_WRITER_MNEMS or mn.startswith('cmov')):
        return False
    return _writes_reg0(ea, creg)


def _reloc_safe(ea, creg):
    """True if `ea` can be copied verbatim to a different address without changing
    meaning: position-independent (no rip-relative/absolute mem, no branch), not a
    stack/flow op, doesn't read creg, and doesn't consume flags we may drop."""
    mn = idc.print_insn_mnem(ea)
    if not mn or mn[0] == 'j' or mn in (
            'call', 'ret', 'retn', 'leave', 'push', 'pop', 'int3', 'iret', 'iretq'):
        return False
    if mn in _FLAG_READER_MNEMS or any(mn.startswith(p) for p in _FLAG_READER_PREFIXES):
        return False
    n = 0
    while True:
        t = idc.get_operand_type(ea, n)
        if t == idc.o_void:
            break
        if t in (idc.o_mem, idc.o_far, idc.o_near):   # rip-relative / absolute / branch
            return False
        n += 1
        if n > 7:
            break
    aliases = _REG_ALIASES.get(creg, {creg})
    ops = ' '.join(idc.print_operand(ea, k) for k in range(n)).lower()
    return not any(re.search(r'\b' + re.escape(al) + r'\b', ops) for al in aliases)


def _mask(w):
    return (1 << (w * 8)) - 1


# ---------------------------------------------------------------------------
# read-only x86-64 micro-emulator (only what decode gadgets need)
# ---------------------------------------------------------------------------
class Emu(object):
    def __init__(self, regs):
        self.r = list(regs)   # 16 entries, each int or None
        self.f = {}           # flag dict or empty (= unknown)

    def rr(self, nm):
        if nm not in _N2I:
            return None
        i, w, hi = _N2I[nm]
        v = self.r[i]
        if v is None:
            return None
        return (v >> 8) & 0xff if hi else v & _mask(w)

    def wr(self, nm, val):
        if nm not in _N2I:
            return
        i, w, hi = _N2I[nm]
        cur = self.r[i] or 0
        if val is None:
            self.r[i] = None
            return
        if w == 8:
            self.r[i] = val & U64
        elif w == 4:
            self.r[i] = val & 0xffffffff       # 32-bit writes zero the upper bits
        elif w == 2:
            self.r[i] = (cur & ~0xffff) | (val & 0xffff)
        elif hi:
            self.r[i] = (cur & ~0xff00) | ((val & 0xff) << 8)
        else:
            self.r[i] = (cur & ~0xff) | (val & 0xff)

    def mem(self, ea, n):
        """Compute the effective address of memory operand n (or None)."""
        if idc.get_operand_type(ea, n) == idc.o_mem:
            return idc.get_operand_value(ea, n)
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
        addr = insn.ops[n].addr
        m = re.search(r'\[(.*)\]', idc.print_operand(ea, n).split(':')[-1])
        if m:
            for tok in m.group(1).replace('-', '+-').split('+'):
                tok = tok.strip()
                if not tok:
                    continue
                neg = tok.startswith('-')
                tok = tok.lstrip('-')
                sc = 1
                if '*' in tok:
                    tok, scs = tok.split('*')
                    sc = int(scs)
                    tok = tok.strip()
                if tok in _N2I:
                    v = self.rr(tok)
                    if v is None:
                        return None
                    addr += (-v if neg else v) * sc
        return addr & U64

    def srcval(self, ea, n):
        t = idc.get_operand_type(ea, n)
        if t == idc.o_reg:
            return self.rr(idc.print_operand(ea, n))
        if t == idc.o_imm:
            return idc.get_operand_value(ea, n) & U64
        a = self.mem(ea, n)
        if a is None:
            return None
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
        sz = ida_ua.get_dtype_size(insn.ops[n].dtype)
        b = ida_bytes.get_bytes(a, sz)
        if not b or len(b) < sz:
            return None
        return int.from_bytes(b, 'little')

    def setf_sub(self, a, b, w):
        if a is None or b is None:
            self.f = {}
            return
        mm = _mask(w)
        a &= mm
        b &= mm
        res = (a - b) & mm
        bits = w * 8
        sa = (a >> (bits - 1)) & 1
        sb = (b >> (bits - 1)) & 1
        sr = (res >> (bits - 1)) & 1
        self.f = {'zf': res == 0, 'sf': sr, 'cf': a < b,
                  'of': (sa != sb) and (sa != sr),
                  'pf': bin(res & 0xff).count('1') % 2 == 0}

    def setf_and(self, a, b, w):
        if a is None or b is None:
            self.f = {}
            return
        res = (a & b) & _mask(w)
        bits = w * 8
        self.f = {'zf': res == 0, 'sf': (res >> (bits - 1)) & 1, 'cf': 0,
                  'of': 0, 'pf': bin(res & 0xff).count('1') % 2 == 0}

    def cond(self, cc):
        f = self.f
        if not f:
            return None
        z = f.get('zf'); sf = f.get('sf'); of = f.get('of')
        cf = f.get('cf'); pf = f.get('pf')
        T = {'z': z, 'e': z, 'nz': not z, 'ne': not z,
             's': sf, 'ns': not sf, 'c': cf, 'b': cf, 'nc': not cf, 'ae': not cf,
             'o': of, 'no': not of, 'p': pf, 'pe': pf, 'np': not pf, 'po': not pf,
             'l': (sf != of), 'ge': (sf == of), 'le': (z or (sf != of)),
             'g': ((not z) and (sf == of)), 'be': (cf or z),
             'a': ((not cf) and (not z)),
             'nge': (sf != of), 'nl': (sf == of), 'ng': (z or (sf != of)),
             'nle': ((not z) and (sf == of)), 'nb': not cf, 'nae': cf,
             'nbe': ((not cf) and (not z)), 'na': (cf or z)}
        return T.get(cc)

    def step(self, ea):
        mn = idc.print_insn_mnem(ea)
        dr = idc.get_operand_type(ea, 0) == idc.o_reg
        o0 = idc.print_operand(ea, 0)
        if mn == 'mov':
            if dr:
                self.wr(o0, self.srcval(ea, 1))
        elif mn in ('movsxd', 'movsx'):
            if dr:
                v = self.srcval(ea, 1)
                if v is not None:
                    insn = ida_ua.insn_t()
                    ida_ua.decode_insn(insn, ea)
                    sw = ida_ua.get_dtype_size(insn.ops[1].dtype)
                    if (v >> (sw * 8 - 1)) & 1:
                        v = (v - (1 << (sw * 8))) & U64
                self.wr(o0, v)
        elif mn == 'movzx':
            if dr:
                self.wr(o0, self.srcval(ea, 1))
        elif mn == 'lea':
            if dr:
                self.wr(o0, self.mem(ea, 1))
        elif mn in ('add', 'sub', 'and', 'or', 'xor', 'imul'):
            if not dr:
                return
            w = _N2I[o0][1]
            # `xor x,x` / `sub x,x` zero the register regardless of its (possibly
            # unknown) prior value -- recognise this before the None short-circuit.
            if (mn in ('xor', 'sub')
                    and idc.get_operand_type(ea, 1) == idc.o_reg
                    and idc.print_operand(ea, 1) == o0):
                self.setf_and(0, 0, w)   # ZF=1, others clear (matches xor/sub self)
                self.wr(o0, 0)
                return
            a = self.rr(o0)
            b = self.srcval(ea, 1)
            if a is None or b is None:
                if mn == 'sub':
                    self.setf_sub(a, b, w)
                self.wr(o0, None)
                return
            if mn == 'add':
                r = a + b
            elif mn == 'sub':
                r = a - b
                self.setf_sub(a, b, w)
            elif mn == 'and':
                r = a & b
                self.setf_and(a, b, w)
            elif mn == 'or':
                r = a | b
            elif mn == 'xor':
                r = 0 if idc.print_operand(ea, 1) == o0 else a ^ b
            else:
                r = a * b
            self.wr(o0, r & U64)
        elif mn in ('shl', 'sal', 'shr', 'sar'):
            if not dr:
                return
            a = self.rr(o0)
            b = self.srcval(ea, 1)
            if a is None or b is None:
                self.wr(o0, None)
                return
            if mn in ('shl', 'sal'):
                r = a << b
            elif mn == 'shr':
                r = a >> b
            else:
                w = _N2I[o0][1]
                bits = w * 8
                r = a >> b
                if (a >> (bits - 1)) & 1:
                    r |= ((1 << bits) - 1) & ~((1 << (bits - b)) - 1)
            self.wr(o0, r & U64)
        elif mn == 'cmp':
            self.setf_sub(self.srcval(ea, 0), self.srcval(ea, 1),
                          _N2I[o0][1] if dr else 4)
        elif mn == 'test':
            self.setf_and(self.srcval(ea, 0), self.srcval(ea, 1),
                          _N2I[o0][1] if dr else 4)
        elif mn.startswith('cmov'):
            if dr:
                c = self.cond(mn[4:])
                if c:
                    self.wr(o0, self.srcval(ea, 1))
                elif c is None:
                    self.wr(o0, None)        # unknown predicate -> fail safe
        elif mn.startswith('set'):
            if dr:
                c = self.cond(mn[3:])
                self.wr(o0, (1 if c else 0) if c is not None else None)


# ---------------------------------------------------------------------------
# per-function resolver
# ---------------------------------------------------------------------------
class FunctionResolver(object):
    def __init__(self, func_ea):
        f = ida_funcs.get_func(func_ea)
        if f is None:
            raise ValueError("no function at %#x" % func_ea)
        self.func = f
        self.FS = f.start_ea
        self.FE = f.end_ea
        self.name = idc.get_func_name(self.FS)
        self.init = self._scan_init()

    # entry-block register initialisation (mov reg,imm  and  lea reg,global)
    def _scan_init(self):
        init = [None] * 16
        ea = self.FS
        cnt = 0
        while ea < self.FE and cnt < 120:
            mn = idc.print_insn_mnem(ea)
            if idc.get_operand_type(ea, 0) == idc.o_reg:
                nm = idc.print_operand(ea, 0)
                if nm in _N2I:
                    if mn == 'mov' and idc.get_operand_type(ea, 1) == idc.o_imm:
                        init[_N2I[nm][0]] = idc.get_operand_value(ea, 1) & U64
                    elif mn == 'lea' and idc.get_operand_type(ea, 1) in (
                            idc.o_mem, idc.o_displ, idc.o_near):
                        v = idc.get_operand_value(ea, 1)
                        if v and v != idc.BADADDR:
                            init[_N2I[nm][0]] = v & U64
            if self._is_ijmp(ea):
                break
            cnt += 1
            ea = idc.next_head(ea, self.FE)
        return init

    @staticmethod
    def _is_ijmp(ea):
        return (idc.print_insn_mnem(ea) == 'jmp'
                and idc.get_operand_type(ea, 0) == idc.o_reg)

    # walk backwards over the contiguous decode-gadget instructions
    def gadget_start(self, j):
        a = j
        for _ in range(120):
            p = idc.prev_head(a, self.FS)
            if p == idc.BADADDR or p < self.FS:
                break
            pm = idc.print_insn_mnem(p)
            if pm in _GADGET_MNEMS or pm.startswith('cmov') or pm.startswith('set'):
                a = p
                continue
            if pm and pm[0] == 'j' and pm != 'jmp':       # opaque conditional branch
                tgt = idc.get_operand_value(p, 0)
                if a <= tgt <= j:
                    a = p
                    continue
                break
            break
        return a

    def resolve(self, j):
        em = Emu(self.init)
        a = self.gadget_start(j)
        budget = 0
        while budget < 800:
            budget += 1
            if a == j:
                return em.rr(idc.print_operand(j, 0))
            mn = idc.print_insn_mnem(a)
            if mn == 'jmp':
                if idc.get_operand_type(a, 0) == idc.o_near:
                    a = idc.get_operand_value(a, 0)
                    continue
                return None
            if mn and mn[0] == 'j':                        # conditional branch
                c = em.cond(mn[1:])
                if c is None:
                    return None
                a = idc.get_operand_value(a, 0) if c else idc.next_head(a, self.FE)
                continue
            em.step(a)
            a = idc.next_head(a, self.FE)
        return None

    def iter_ijmps(self):
        ea = self.FS
        while ea < self.FE:
            if self._is_ijmp(ea):
                yield ea
            ea = idc.next_head(ea, self.FE)

    # legacy single-block resolution (kept for reference / debugging).
    # Resolves each indirect jump in isolation; cannot follow register hand-offs
    # across basic blocks, so it under-resolves on functions that pass alternate
    # decode offsets in registers (e.g. chromium_extract). Prefer analyze().
    def analyze_singleblock(self):
        t0 = time.time()
        resolved = {}      # jmp_ea -> target
        unresolved = []
        switch = []
        oob = []
        not_head = []
        for j in self.iter_ijmps():
            if ida_nalt.get_switch_info(j) is not None:
                switch.append(j)
                continue
            t = self.resolve(j)
            if t is None:
                unresolved.append(j)
                continue
            if not (self.FS <= t < self.FE):
                oob.append((j, t))
                continue
            if not _is_insn_head(t):
                not_head.append((j, t))
                continue
            resolved[j] = t
        return {
            'name': self.name, 'start': self.FS, 'end': self.FE,
            'resolved': resolved, 'unresolved': unresolved,
            'switch': switch, 'oob': oob, 'not_head': not_head,
            'seconds': time.time() - t0,
        }

    # CFG-guided fixpoint resolution (inter-block dataflow). Read-only.
    #
    # Emulates from the entry, carrying a per-edge register state, following
    # resolved jumps to discover new blocks, and merging register states at
    # join points (differing registers become unknown). Conditional branches
    # whose predicate is known are followed precisely; unknown predicates fork
    # both ways. Volatile registers are invalidated across calls. Iterates to a
    # fixpoint. Only blocks actually reachable from the entry are explored, so
    # dead false-branch gadgets are naturally excluded.
    MAX_ITERS = 16_000_000

    def analyze(self):
        from collections import deque
        t0 = time.time()
        FS, FE = self.FS, self.FE
        init = tuple(self.init)

        def merge(a, b):
            return tuple(a[i] if a[i] == b[i] else None for i in range(16))

        visited = {}            # block-start ea -> merged in-state
        resolved = {}           # ijmp ea -> set(targets)
        switch = set()
        reachable = set()       # every executed instruction ea
        ijmp_seen = set()       # reachable indirect (register) jumps
        work = deque([(FS, init)])
        iters = 0
        while work and iters < self.MAX_ITERS:
            ea, st = work.popleft()
            if ea in visited:
                m = merge(visited[ea], st)
                if m == visited[ea]:
                    continue
                visited[ea] = m
                st = m
            else:
                visited[ea] = st
            em = Emu(list(st))
            cur = ea
            while True:
                iters += 1
                if iters >= self.MAX_ITERS or cur < FS or cur >= FE:
                    break
                reachable.add(cur)
                mn = idc.print_insn_mnem(cur)
                t0op = idc.get_operand_type(cur, 0)
                nx = idc.next_head(cur, FE)
                if mn == 'jmp':
                    if t0op == idc.o_reg:
                        ijmp_seen.add(cur)
                        if ida_nalt.get_switch_info(cur) is not None:
                            switch.add(cur)
                            break
                        tv = em.rr(idc.print_operand(cur, 0))
                        if tv is not None and FS <= tv < FE:
                            resolved.setdefault(cur, set()).add(tv)
                            work.append((tv, tuple(em.r)))
                        break
                    elif t0op == idc.o_near:
                        work.append((idc.get_operand_value(cur, 0), tuple(em.r)))
                        break
                    else:
                        break
                if mn.startswith('ret') or mn == 'int3':
                    break
                if mn and mn[0] == 'j' and mn != 'jmp':
                    c = em.cond(mn[1:])
                    tt = idc.get_operand_value(cur, 0)
                    if (c is True or c is None) and FS <= tt < FE:
                        work.append((tt, tuple(em.r)))
                    if c is False or c is None:
                        work.append((nx, tuple(em.r)))
                    break
                if mn == 'call':
                    if not _is_reg_transparent_call(cur):
                        for i in _VOL:
                            em.r[i] = None
                    cur = nx
                    continue
                em.step(cur)
                cur = nx

        conflicts = {ea: sorted(s) for ea, s in resolved.items() if len(s) > 1}
        not_head = []
        good = {}
        for ea, s in resolved.items():
            if len(s) > 1:
                continue
            t = next(iter(s))
            if not _is_insn_head(t):
                not_head.append((ea, t))
                continue
            good[ea] = t
        nothead_set = {ea for ea, _ in not_head}
        unresolved = [j for j in ijmp_seen
                      if j not in good and j not in switch
                      and j not in conflicts and j not in nothead_set]
        return {
            'name': self.name, 'start': FS, 'end': FE,
            'resolved': good, 'unresolved': unresolved, 'switch': sorted(switch),
            'conflicts': conflicts, 'not_head': not_head, 'oob': [],
            'reachable': len(reachable), 'iters': iters,
            'hit_cap': iters >= self.MAX_ITERS,
            'seconds': time.time() - t0,
        }


def _is_insn_head(ea):
    fl = ida_bytes.get_flags(ea)
    return ida_bytes.is_code(fl) and idc.get_item_head(ea) == ea


# Stack-probe / alloca helpers preserve all general-purpose registers (they only
# adjust RSP and flags). A normal `call` clobbers Win64 volatiles, but treating
# chkstk/alloca that way wrongly destroys decode keys/offsets held live across the
# probe -- which is exactly how the obfuscator straddles a gadget over chkstk.
_TRANSPARENT_CALL_SUBSTRINGS = ('chkstk', 'alloca')


def _is_reg_transparent_call(ea):
    if idc.get_operand_type(ea, 0) != idc.o_near:
        return False
    nm = (idc.get_func_name(idc.get_operand_value(ea, 0)) or '').lower()
    return any(s in nm for s in _TRANSPARENT_CALL_SUBSTRINGS)


# ---------------------------------------------------------------------------
# patcher
# ---------------------------------------------------------------------------
class Patcher(object):
    def __init__(self, resolver):
        self.r = resolver

    def _tail_span(self, j):
        """Return (span_start, total_bytes) of the dead decode tail to overwrite,
        or (None, 0) if it cannot be safely determined.

        We extend backwards from the jmp over add/mov/lea/nop instructions until we
        have at least 5 bytes (room for E9 rel32). Every instruction in the span must
        be tail-safe; otherwise we refuse (return None)."""
        jend = j + idc.get_item_size(j)
        span = j
        guard = 0
        while (jend - span) < 5 and guard < 4:
            p = idc.prev_head(span, self.r.FS)
            if p == idc.BADADDR:
                break
            if idc.print_insn_mnem(p) not in _TAIL_SAFE:
                break
            span = p
            guard += 1
        total = jend - span
        if total < 5:
            return None, 0
        a = span
        while a < j:
            if idc.print_insn_mnem(a) not in _TAIL_SAFE:
                return None, 0
            a = idc.next_head(a, jend)
        return span, total

    def _plan_reloc(self, j, tgt):
        """Fallback plan for jumps whose dead decode writer is separated from the
        `jmp` by live, must-preserve instructions (e.g. argument/state setup like
        `mov r8,[rbp+..]` / `xor r11d,r11d` straddling the gadget).

        Walk backward from the jmp: instructions that merely recompute the jump
        register are DROPPED to reclaim space; everything else is preserved and
        relocated downward, after which we append a direct `jmp tgt`. Returns
        (start_ea, new_bytes) covering exactly [start_ea, jmp_end) or None if it
        cannot be done safely.
        """
        import struct
        creg = _canon_reg(idc.print_operand(j, 0))
        if creg is None:
            return None
        jmp_end = j + idc.get_item_size(j)
        preserved = []                      # (bytes,) of live instrs, address order
        a = j
        for _ in range(24):
            p = idc.prev_head(a, self.r.FS)
            if p == idc.BADADDR or p < self.r.FS:
                return None
            if _is_droppable_writer(p, creg):
                # Drop p; see whether reclaiming it (and anything already dropped)
                # leaves room for the preserved tail + a 5-byte direct jmp.
                start = p
                body = b''.join(preserved)
                region = jmp_end - start
                if len(body) + 5 <= region:
                    disp = tgt - (start + len(body) + 5)
                    if disp < -0x80000000 or disp > 0x7fffffff:
                        return None
                    nb = body + b'\xe9' + struct.pack('<i', disp)
                    nb += b'\x90' * (region - len(nb))
                    return start, nb
                a = p
                continue
            # Not a droppable writer -> it is live; must preserve & relocate it.
            if not _reloc_safe(p, creg):
                return None
            preserved.insert(0, ida_bytes.get_bytes(p, idc.get_item_size(p)))
            a = p
        return None

    def _plan_patch(self, j, tgt):
        """Unified patch plan: simple in-place tail rewrite if possible, else a
        relocation rewrite. Returns (start_ea, new_bytes) or None to refuse."""
        import struct
        span, total = self._tail_span(j)
        if span is not None:
            disp = tgt - (span + 5)
            if -0x80000000 <= disp <= 0x7fffffff:
                return span, b'\xe9' + struct.pack('<i', disp) + b'\x90' * (total - 5)
        return self._plan_reloc(j, tgt)

    def _can_promote(self, tgt):
        """A `not_head` target is often real code that is only hidden because no
        direct edge reaches it yet (so IDA left the bytes as data / misaligned).
        Verify -- non-destructively -- that `tgt` is in-function and decodes to a
        valid instruction. Returns the instruction length (0 = do not promote)."""
        if not (self.r.FS <= tgt < self.r.FE):
            return 0
        if _is_insn_head(tgt):
            return 0
        insn = ida_ua.insn_t()
        return ida_ua.decode_insn(insn, tgt)

    def _count_heads(self):
        """Number of instruction heads in [FS, FE) -- a cheap proxy for 'how much
        of the function is disassembled'. Used to detect whether a patch round
        revealed previously-hidden code (which would warrant another round)."""
        FS, FE = self.r.FS, self.r.FE
        n = 0
        ea = FS
        while ea != idc.BADADDR and ea < FE:
            n += 1
            ea = idc.next_head(ea, FE)
        return n

    def _patch_round(self):
        """Resolve + patch once.

        Returns (patched_list, refused_list, report, revealed) where `revealed`
        is True if reanalysis turned new bytes into code (i.e. a further round
        could resolve jumps that were previously invisible)."""
        rep = self.r.analyze()
        patched = []
        refused = []
        # Resolved jumps, plus `not_head` jumps whose target is real-but-hidden
        # code we can promote (materialize) once we give it a direct edge.
        work = dict(rep['resolved'])
        materialize = {}
        for j, tgt in rep['not_head']:
            ln = self._can_promote(tgt)
            if ln > 0:
                work[j] = tgt
                materialize[tgt] = ln
        done_nothead = set()
        for j, tgt in work.items():
            plan = self._plan_patch(j, tgt)
            if plan is None:
                refused.append(j)
                continue
            if tgt in materialize:
                # Turn the hidden target bytes into a real instruction head so the
                # new direct edge lands on a head and the listing realigns.
                ida_bytes.del_items(tgt, ida_bytes.DELIT_SIMPLE, materialize[tgt])
                ida_ua.create_insn(tgt)
                done_nothead.add(j)
            span, code = plan
            total = len(code)
            ida_bytes.patch_bytes(span, code)
            # Fix up ONLY this patch site: clear the stale items the old gadget
            # left behind and re-decode the new jmp + nop padding. This keeps
            # reanalysis O(#patches) instead of O(function size), which matters
            # for large functions (a whole-function re-disassembly can exceed
            # the host's per-call time budget).
            ida_bytes.del_items(span, ida_bytes.DELIT_SIMPLE, total)
            a = span
            endp = span + total
            while a < endp:
                ln = ida_ua.create_insn(a)
                a += ln if ln > 0 else 1
            patched.append((span, tgt))
        # Report the post-patch residual: drop the not_head entries we promoted.
        rep['not_head'] = [(j, t) for (j, t) in rep['not_head'] if j not in done_nothead]
        revealed = False
        if patched:
            before = self._count_heads()
            self._reanalyze()
            revealed = self._count_heads() != before
        return patched, refused, rep, revealed

    def patch(self, decompile=True, verbose=True, max_rounds=5):
        # Iterate: each patched round can turn previously-undisassembled gadget
        # bodies into code (revealed by the new direct edges), which a further
        # round can then resolve. Converges when a round patches nothing new.
        all_patched = []
        last_rep = None
        rounds = 0
        for rounds in range(1, max_rounds + 1):
            patched, refused, rep, revealed = self._patch_round()
            last_rep = rep
            all_patched.extend(patched)
            # Stop once a round either patches nothing or reveals no new code:
            # the fixpoint analysis already resolves everything reachable in the
            # current disassembly, so another round only helps if patching
            # exposed previously-hidden gadget bodies.
            if not patched or not revealed:
                break
        result = dict(last_rep)
        result['patched'] = all_patched
        result['refused'] = refused
        result['rounds'] = rounds
        if verbose:
            self._print_patch(result)
        if all_patched and _HAS_HEXRAYS:
            if decompile:
                self._decompile_preview()
        return result

    def _reanalyze(self):
        # Patch sites were already re-decoded individually in _patch_round, so
        # here we only need to rebuild the function object (the new direct edges
        # can change the CFG) and let auto-analysis settle. We pin the function
        # bounds to the original [FS, FE) so flow that is temporarily broken by a
        # still-unresolved indirect jump can't truncate the function.
        FS, FE = self.r.FS, self.r.FE
        ida_funcs.del_func(FS)
        ida_ua.create_insn(FS)
        ida_funcs.add_func(FS, FE)
        ida_auto.plan_and_wait(FS, FE)

    def _decompile_preview(self):
        try:
            ensure_decompiler_limit(verbose=False)
            ida_hexrays.mark_cfunc_dirty(self.r.FS)
            cf = ida_hexrays.decompile(self.r.FS)
            if cf:
                txt = str(cf)
                print("  decompiled lines: %d" % txt.count("\n"))
            else:
                print("  decompile returned None")
        except Exception as ex:
            print("  decompile error: %r" % ex)

    @staticmethod
    def _print_patch(r):
        print("[patch] %-26s patched=%d refused=%d rounds=%d (final: resolved=%d "
              "switch=%d conflicts=%d not_head=%d unresolved=%d reachable=%d)" % (
                  r['name'], len(r['patched']), len(r['refused']), r.get('rounds', 1),
                  len(r['resolved']), len(r['switch']), len(r.get('conflicts', {})),
                  len(r['not_head']), len(r['unresolved']), r.get('reachable', 0)))


# ---------------------------------------------------------------------------
# discovery + module-level entry points
# ---------------------------------------------------------------------------
def _resolve_target_func(name_or_ea):
    if isinstance(name_or_ea, str):
        ea = idc.get_name_ea_simple(name_or_ea)
        if ea == idc.BADADDR:
            raise ValueError("no symbol named %r" % name_or_ea)
        return ea
    return int(name_or_ea)


def find_flattened_functions(min_ijmps=8):
    """Heuristic: a function is flattened if it contains many `jmp <reg>`."""
    out = []
    for fea in idautils.Functions():
        f = ida_funcs.get_func(fea)
        if f is None:
            continue
        cnt = 0
        ea = f.start_ea
        while ea < f.end_ea:
            if (idc.print_insn_mnem(ea) == 'jmp'
                    and idc.get_operand_type(ea, 0) == idc.o_reg):
                cnt += 1
                if cnt >= min_ijmps:
                    break
            ea = idc.next_head(ea, f.end_ea)
        if cnt >= min_ijmps:
            out.append(fea)
    return out


def _print_report(r):
    cap = "  *HIT ITER CAP*" if r.get('hit_cap') else ""
    print("[report] %-26s resolved=%-5d unresolved=%-4d switch=%-3d conflicts=%-3d "
          "not_head=%-3d reachable=%-6d %.1fs%s" % (
              r['name'], len(r['resolved']), len(r['unresolved']),
              len(r['switch']), len(r.get('conflicts', {})),
              len(r['not_head']), r.get('reachable', 0), r['seconds'], cap))


_DECOMP_LIMIT_RAISED = False


def ensure_decompiler_limit(min_kb=None, verbose=True, force=False):
    """Raise Hex-Rays' MAX_FUNCSIZE so large de-flattened functions can decompile.

    De-flattened functions remain physically huge, exceeding the decompiler's default
    64 KB guard (failures show up as MERR_FUNCSIZE / error -29). We bump the limit to
    cover the binary's largest function (plus margin). Caveat: MAX_FUNCSIZE=0 is treated
    as 0 KB, not "unlimited", so we always set an explicit value. The setting is
    per-session and is not written to the IDB, so it is re-applied on every plugin load.
    """
    global _DECOMP_LIMIT_RAISED
    if not _HAS_HEXRAYS:
        return None
    if _DECOMP_LIMIT_RAISED and not force and min_kb is None:
        return None
    if min_kb is None:
        biggest = 0
        for fea in idautils.Functions():
            f = ida_funcs.get_func(fea)
            if f is not None:
                biggest = max(biggest, f.end_ea - f.start_ea)
        min_kb = biggest // 1024 + 64           # cover the largest function + margin
    target_kb = max(int(min_kb), 256)
    try:
        ida_hexrays.change_hexrays_config("MAX_FUNCSIZE = %d" % target_kb)
        _DECOMP_LIMIT_RAISED = True
        if verbose:
            print("[cff] Hex-Rays MAX_FUNCSIZE set to %d KB (default is 64 KB) so large "
                  "de-flattened functions can decompile." % target_kb)
        return target_kb
    except Exception as ex:
        print("[cff] could not raise MAX_FUNCSIZE: %r" % ex)
        return None


def report(name_or_ea):
    """Read-only: resolve and print a summary for one function. Returns the report."""
    r = FunctionResolver(_resolve_target_func(name_or_ea)).analyze()
    _print_report(r)
    return r


def _run_over_flattened(worker, header, min_ijmps=8):
    """Run worker(func_ea)->result over every flattened function, showing a
    cancelable progress dialog. Returns (results, cancelled, elapsed_seconds).

    Cancellation is checked between functions only, so the database is never left
    mid-function: already-processed functions are complete and independent."""
    funcs = find_flattened_functions(min_ijmps)
    n = len(funcs)
    results = []
    cancelled = False
    if n == 0:
        print("[cff] no flattened functions found (min_ijmps=%d)" % min_ijmps)
        return results, cancelled, 0.0
    t0 = time.time()
    ida_kernwin.show_wait_box("%s" % header)
    try:
        for i, fea in enumerate(funcs, 1):
            if ida_kernwin.user_cancelled():
                cancelled = True
                break
            name = idc.get_func_name(fea) or ("%#x" % fea)
            ida_kernwin.replace_wait_box("%s\n[%d/%d]  %s" % (header, i, n, name))
            try:
                results.append(worker(fea))
            except Exception as ex:
                print("[cff] %#x (%s) FAILED: %r" % (fea, name, ex))
    finally:
        ida_kernwin.hide_wait_box()
    return results, cancelled, time.time() - t0


def _report_one(fea):
    r = FunctionResolver(fea).analyze()
    _print_report(r)
    return r


def report_all(min_ijmps=8):
    """Read-only: resolve and print a summary for every flattened function."""
    reps, cancelled, secs = _run_over_flattened(
        _report_one, "CFF Layer 1: analyzing flattened functions", min_ijmps)
    tot = sum(len(x['resolved']) for x in reps)
    un = sum(len(x['unresolved']) for x in reps)
    sw = sum(len(x['switch']) for x in reps)
    nh = sum(len(x['not_head']) for x in reps)
    cf = sum(len(x.get('conflicts', {})) for x in reps)
    print("-" * 78)
    print("[report] %sfunctions=%d  resolved=%d  unresolved=%d  switch=%d  "
          "not_head=%d  conflicts=%d  (%.1fs)" % (
              "CANCELLED -- " if cancelled else "", len(reps), tot, un, sw, nh, cf, secs))
    return reps


def patch(name_or_ea, decompile=True):
    """Modifies the IDB: rewrite resolved indirect jumps in one function."""
    res = FunctionResolver(_resolve_target_func(name_or_ea))
    return Patcher(res).patch(decompile=decompile)


def patch_all(min_ijmps=8):
    """Modifies the IDB: rewrite resolved indirect jumps in every flattened function."""
    ensure_decompiler_limit()
    results, cancelled, secs = _run_over_flattened(
        lambda fea: Patcher(FunctionResolver(fea)).patch(decompile=False),
        "CFF Layer 1: patching flattened functions", min_ijmps)
    pat = sum(len(r['patched']) for r in results)
    ref = sum(len(r['refused']) for r in results)
    un = sum(len(r['unresolved']) for r in results)
    nh = sum(len(r['not_head']) for r in results)
    sw = sum(len(r['switch']) for r in results)
    cf = sum(len(r.get('conflicts', {})) for r in results)
    print("-" * 78)
    print("[patch] %sfunctions=%d  patched=%d  refused=%d  unresolved=%d  "
          "not_head=%d  switch=%d  conflicts=%d  (%.1fs)" % (
              "CANCELLED -- " if cancelled else "", len(results), pat, ref, un, nh, sw, cf, secs))
    if cf:
        print("[patch] WARNING: %d conflicting resolutions were skipped (left as indirect)." % cf)
    return results

