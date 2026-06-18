"""Layer 3 -- obfuscated import / library-call resolution.

The obfuscator hides every external/library call behind an additive blind:

    mov  rax, cs:off_GLOBAL        ; off_GLOBAL holds (target - key)
    add  rax, KEYREG               ; KEYREG holds a large per-binary key constant
    call rax                       ; -> real target  (e.g. sqlite3_step)

or, with a level of indirection through a resolved pointer slot:

    mov  rax, cs:off_GLOBAL
    add  rax, KEYREG               ; rax now points at the IAT/pointer slot
    mov  rax, [rax]                ; rax = real target
    call rax

The key register is one of a handful of `mov reg, imm64` constants set in the
prologue (e.g. r15 = 5BF5367E05DE00B for the sqlite family, r13 for the state
decode).  Because each key is a loop-invariant constant, the call target is a
pure function of statically-known data and can be recovered without execution.

This module performs a bounded backward constant-resolution from each indirect
call operand, computes the concrete target, maps it to a symbol (a .text
function or an __imp_ IAT thunk), and annotates the call site.
"""

import re
import idc
import idautils
import ida_funcs
import ida_segment
import ida_bytes
import ida_name

U64 = (1 << 64) - 1

# 32-bit (and smaller) sub-register -> canonical 64-bit name.
_SUB = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi",
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
}
for _i in range(8, 16):
    _SUB["r%dd" % _i] = "r%d" % _i
    _SUB["r%dw" % _i] = "r%d" % _i
    _SUB["r%db" % _i] = "r%d" % _i

_REGS = set(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] +
            ["r%d" % i for i in range(8, 16)])

_MAX_BACK = 800          # instructions scanned backward per def lookup
_MAX_DEPTH = 64          # recursion guard


def _cn(reg):
    reg = reg.strip()
    return _SUB.get(reg, reg)


def seg_tag(a):
    s = ida_segment.getseg(a)
    if not s:
        return None
    return "%s/%s" % (ida_segment.get_segm_name(s),
                      ida_segment.get_segm_class(s))


def _is_code(a):
    s = ida_segment.getseg(a)
    return bool(s) and ida_segment.get_segm_class(s) == "CODE"


def _parse_mem(txt):
    """Parse a bracketed memory operand into (regs, disp). Returns
    (list_of_(reg,scale), disp_int) or None. Segment prefixes stripped."""
    m = re.search(r"\[([^\]]+)\]", txt)
    if not m:
        return None
    inner = m.group(1).split(":")[-1].replace(" ", "")
    inner = inner.replace("-", "+-")
    regs = []
    disp = 0
    for tok in inner.split("+"):
        if not tok:
            continue
        sign = 1
        if tok.startswith("-"):
            sign = -1
            tok = tok[1:]
            if not tok:
                continue
        if "*" in tok:
            rg, sc = tok.split("*")
            regs.append((_cn(rg), int(sc, 0)))
            continue
        if re.fullmatch(r"[0-9A-Fa-f]+h", tok):
            disp += sign * int(tok[:-1], 16)
        elif tok.startswith("0x"):
            disp += sign * int(tok, 16)
        elif re.fullmatch(r"[0-9]+", tok):
            disp += sign * int(tok, 10)
        elif re.fullmatch(r"[0-9A-Fa-f]+", tok):
            disp += sign * int(tok, 16)
        else:
            regs.append((_cn(tok), 1))
    return regs, disp


_FLOWBREAK = ("jmp", "ret", "retn", "int3")


class Blind(object):
    """A value of the form (base + unknown_additive_key). The key is one of the
    per-binary blind constants; it is pinned only when the value is constrained
    -- a memory dereference (address must be mapped) or the call transfer
    (target must be code/import)."""
    __slots__ = ("base",)

    def __init__(self, base):
        self.base = base & U64

    def __repr__(self):
        return "Blind(%016x)" % self.base


def _pin(base, keys, want_code):
    """Choose the key so that base+key satisfies the constraint. want_code:
    final target must be in CODE/import; else just a mapped (readable) addr.
    Returns the resolved address or None."""
    named = None
    mapped = None
    for k in keys:
        t = (base + k) & U64
        if want_code:
            if _valid_target(t):
                return t
            if mapped is None and _is_code(t):
                mapped = t
        else:
            if ida_segment.getseg(t) is not None:
                if mapped is None:
                    mapped = t
                if _looks_ptr_slot(t):
                    return t
    return mapped


def _looks_ptr_slot(ea):
    s = ida_segment.getseg(ea)
    if not s:
        return False
    cls = ida_segment.get_segm_class(s)
    if cls not in ("DATA", "XTRN", "BSS"):
        return False
    return True


class Emu(object):
    """Constant emulator with blind-key values; folds the additive/deref import
    blind. Unknown -> None (propagates)."""

    def __init__(self, keys):
        self.r = {}        # canonical reg -> int | Blind | None
        self.m = {}        # frame slot (base,disp) -> value
        self.keys = keys

    def get(self, reg):
        return self.r.get(_cn(reg))

    def set(self, reg, val):
        self.r[_cn(reg)] = val

    def _addr(self, a, n):
        """(addr_or_slotkey, is_slot, ok) for a memory operand, pinning a blind
        base register against the 'mapped address' constraint."""
        t = idc.get_operand_type(a, n)
        if t == idc.o_mem:
            return idc.get_operand_value(a, n), False, True
        if t in (idc.o_displ, idc.o_phrase):
            p = _parse_mem(idc.print_operand(a, n))
            if not p:
                return None, False, False
            regs, disp = p
            frame = [rg for rg, sc in regs if rg in ("rbp", "rsp") and sc == 1]
            other = [(rg, sc) for rg, sc in regs if rg not in ("rbp", "rsp")]
            if frame and not other:
                return (frame[0], disp), True, True
            total = disp
            blindbase = None
            for rg, sc in regs:
                v = self.r.get(rg)
                if isinstance(v, Blind) and sc == 1 and blindbase is None:
                    blindbase = v.base
                    continue
                if not isinstance(v, int):
                    return None, False, False
                total += v * sc
            if blindbase is not None:
                ad = _pin((blindbase + total) & U64, self.keys, False)
                return (ad, False, True) if ad is not None else (None, False, False)
            return total & U64, False, True
        return None, False, False

    def load(self, a, n):
        addr, is_slot, ok = self._addr(a, n)
        if not ok:
            return None
        if is_slot:
            return self.m.get(addr)
        return idc.get_qword(addr) & U64

    def _src(self, a, n):
        t = idc.get_operand_type(a, n)
        if t == idc.o_imm:
            return idc.get_operand_value(a, n) & U64
        if t == idc.o_reg:
            return self.get(idc.print_operand(a, n))
        return self.load(a, n)

    def step(self, a):
        mn = idc.print_insn_mnem(a)
        if not mn:
            return
        t0 = idc.get_operand_type(a, 0)
        if mn in ("mov", "movzx", "movsx", "movsxd"):
            if t0 == idc.o_reg:
                self.set(idc.print_operand(a, 0), self._src(a, 1))
            elif t0 in (idc.o_displ, idc.o_phrase, idc.o_mem):
                addr, is_slot, ok = self._addr(a, 0)
                if ok and is_slot:
                    self.m[addr] = self._src(a, 1)
            return
        if mn == "lea":
            if t0 == idc.o_reg:
                addr, is_slot, ok = self._addr(a, 1)
                self.set(idc.print_operand(a, 0),
                         None if (not ok or is_slot) else addr)
            return
        if mn in ("add", "sub"):
            if t0 == idc.o_reg:
                b = self.get(idc.print_operand(a, 0))
                c = self._src(a, 1)
                # `add base, KEYREG` where the key register is a carried (out of
                # trace) blind constant -> turn the concrete base into a blind.
                if (mn == "add" and isinstance(b, int) and c is None
                        and idc.get_operand_type(a, 1) == idc.o_reg):
                    self.set(idc.print_operand(a, 0), Blind(b))
                    return
                self.set(idc.print_operand(a, 0), self._addsub(mn, b, c))
            return
        if mn == "xor" and t0 == idc.o_reg \
                and idc.get_operand_type(a, 1) == idc.o_reg \
                and _cn(idc.print_operand(a, 0)) == _cn(idc.print_operand(a, 1)):
            self.set(idc.print_operand(a, 0), 0)
            return
        if mn == "call":
            for v in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                self.r[v] = None
            return
        if t0 == idc.o_reg and mn not in ("cmp", "test", "push", "nop"):
            self.set(idc.print_operand(a, 0), None)

    def _addsub(self, mn, b, c):
        # a key register added to a concrete base -> a blind value
        if isinstance(b, int) and isinstance(c, Blind):
            b, c = c, b
        if isinstance(b, Blind):
            if isinstance(c, int):
                return Blind((b.base + c) if mn == "add" else (b.base - c))
            return None
        if isinstance(b, int) and isinstance(c, int):
            # a large 'add reg, KEY' from a concrete base is a blind too, but we
            # only know KEY is large; treat any add of a big constant as concrete
            return ((b + c) if mn == "add" else (b - c)) & U64
        return None


class Resolver(object):
    def __init__(self, func_ea):
        f = ida_funcs.get_func(func_ea)
        self.f = f
        self.fs = f.start_ea
        self.fe = f.end_ea
        self._cache = {}
        self._keys = None
        self._consts = None

    def const_regs(self):
        """Registers that are effectively constant across the whole function
        (every definition is `mov reg, <same imm>`). These carry the stable
        blind keys (e.g. r12/r13). Such a register's value can be seeded at any
        call site."""
        if self._consts is not None:
            return self._consts
        val = {}
        bad = set()
        for h in idautils.Heads(self.fs, self.fe):
            t0 = idc.get_operand_type(h, 0)
            if t0 != idc.o_reg:
                continue
            reg = _cn(idc.print_operand(h, 0))
            if reg not in _REGS:
                continue
            mn = idc.print_insn_mnem(h)
            # push reads the reg (no write); pop restores the saved value -- both
            # preserve the prologue-set constant across the body, so neither one
            # invalidates constancy (the obfuscator save/restores its key regs).
            if mn in ("push", "pop"):
                continue
            if mn == "mov" and idc.get_operand_type(h, 1) == idc.o_imm:
                v = idc.get_operand_value(h, 1) & U64
                if v <= 0xFFFFFFFF:
                    bad.add(reg)
                elif reg in val and val[reg] != v:
                    bad.add(reg)
                else:
                    val[reg] = v
            else:
                bad.add(reg)
        self._consts = {r: v for r, v in val.items() if r not in bad}
        return self._consts

    def _pred(self, a):
        """The unique execution predecessor of instruction `a`, following
        unconditional near jumps (incl. the `jmp $+5` no-op) backward. Returns
        the predecessor ea, or None if it is not unique / not an unconditional
        edge (a merge or conditional join -- stop the local trace there)."""
        p = idc.prev_head(a, self.fs)
        if p != idc.BADADDR and p >= self.fs:
            mn = idc.print_insn_mnem(p)
            if mn not in _FLOWBREAK:
                # falls through into a -- but only if nothing else jumps to a
                jsrc = [x for x in idautils.CodeRefsTo(a, 0)]
                if not jsrc:
                    return p
                return None
            if mn == "jmp" and idc.get_operand_type(p, 0) == idc.o_near \
                    and idc.get_operand_value(p, 0) == a:
                return p          # jmp $+5 no-op straight into a
        # a is a jump target: take the sole near-jmp that reaches it
        jsrc = [x for x in idautils.CodeRefsTo(a, 0)
                if self.fs <= x < self.fe
                and idc.print_insn_mnem(x) == "jmp"
                and idc.get_operand_type(x, 0) == idc.o_near]
        if len(jsrc) == 1:
            return jsrc[0]
        return None

    def _trace(self, ea):
        """Instruction addresses in execution order leading up to (excluding)
        the call at ea, following the unique unconditional-jump chain back."""
        seq = []
        a = ea
        seen = set()
        for _ in range(_MAX_BACK):
            p = self._pred(a)
            if p is None or p in seen:
                break
            seen.add(p)
            seq.append(p)
            a = p
        seq.reverse()
        return seq

    # -- backward constant resolution ------------------------------------
    def reg_val(self, reg, at, depth=0):
        reg = _cn(reg)
        if depth > _MAX_DEPTH:
            return None
        a = at
        for _ in range(_MAX_BACK):
            a = idc.prev_head(a, self.fs)
            if a == idc.BADADDR or a < self.fs:
                return None
            mn = idc.print_insn_mnem(a)
            if not mn:
                continue
            if mn == "call":
                # a volatile reg cannot survive a call; only resolve callee-saved
                if reg in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                    return None
                continue
            if (idc.get_operand_type(a, 0) == idc.o_reg
                    and _cn(idc.print_operand(a, 0)) == reg):
                return self._def_val(a, reg, depth)
        return None

    def _def_val(self, a, reg, depth):
        mn = idc.print_insn_mnem(a)
        t1 = idc.get_operand_type(a, 1)
        if mn == "mov":
            if t1 == idc.o_imm:
                return idc.get_operand_value(a, 1) & U64
            if t1 == idc.o_reg:
                return self.reg_val(idc.print_operand(a, 1), a, depth + 1)
            if t1 == idc.o_mem:
                return idc.get_qword(idc.get_operand_value(a, 1)) & U64
            if t1 in (idc.o_displ, idc.o_phrase):
                ad = self.mem_addr(a, 1, depth + 1)
                if ad is None:
                    return self.stack_val(a, 1, a, depth + 1)
                return idc.get_qword(ad) & U64
            return None
        if mn == "lea":
            return self.mem_addr(a, 1, depth + 1)
        if mn in ("add", "sub"):
            b = self.reg_val(reg, a, depth + 1)
            if b is None:
                return None
            if t1 == idc.o_imm:
                d = idc.get_operand_value(a, 1)
                return ((b + d) if mn == "add" else (b - d)) & U64
            if t1 == idc.o_reg:
                c = self.reg_val(idc.print_operand(a, 1), a, depth + 1)
                if c is None:
                    return None
                return ((b + c) if mn == "add" else (b - c)) & U64
            if t1 == idc.o_mem:
                c = idc.get_qword(idc.get_operand_value(a, 1)) & U64
                return ((b + c) if mn == "add" else (b - c)) & U64
            return None
        if mn in ("xor",) and t1 == idc.o_reg and \
                _cn(idc.print_operand(a, 1)) == reg:
            return 0
        return None

    def mem_addr(self, a, n, depth):
        """Concrete address of a [base+index*scale+disp] operand, or None if
        a component register is not statically known (e.g. a real stack frame
        pointer)."""
        p = _parse_mem(idc.print_operand(a, n))
        if p is None:
            return None
        regs, disp = p
        total = disp
        for rg, sc in regs:
            if rg in ("rbp", "rsp"):
                return None       # genuine frame slot -> not a constant address
            v = self.reg_val(rg, a, depth + 1)
            if v is None:
                return None
            total += v * sc
        return total & U64

    def stack_val(self, a, n, at, depth):
        """Resolve a value read from a frame slot [rbp/rsp+disp] by finding the
        nearest preceding write to the same slot."""
        txt = idc.print_operand(a, n)
        p = _parse_mem(txt)
        if p is None:
            return None
        regs, disp = p
        base = None
        for rg, sc in regs:
            if rg in ("rbp", "rsp") and sc == 1:
                base = rg
            else:
                return None
        if base is None:
            return None
        slot = (base, disp)
        b = at
        for _ in range(_MAX_BACK):
            b = idc.prev_head(b, self.fs)
            if b == idc.BADADDR or b < self.fs:
                return None
            if idc.print_insn_mnem(b) != "mov":
                continue
            if idc.get_operand_type(b, 0) not in (idc.o_displ, idc.o_phrase):
                continue
            pp = _parse_mem(idc.print_operand(b, 0))
            if pp is None:
                continue
            rr2, dd = pp
            if len(rr2) != 1 or rr2[0] != (base, 1) or dd != disp:
                continue
            t1 = idc.get_operand_type(b, 1)
            if t1 == idc.o_reg:
                return self.reg_val(idc.print_operand(b, 1), b, depth + 1)
            if t1 == idc.o_imm:
                return idc.get_operand_value(b, 1) & U64
            return None
        return None

    # -- global anchor + deref structure --------------------------------
    def _start_reg(self, ea):
        """The register/expression the call actually transfers to, and the
        extra deref the call instruction itself implies."""
        ot = idc.get_operand_type(ea, 0)
        if ot == idc.o_reg:
            return _cn(idc.print_operand(ea, 0)), 0
        m = re.search(r"\[([^\]]+)\]", idc.print_operand(ea, 0))
        if m:
            inner = m.group(1).split(":")[-1].replace(" ", "")
            if inner in _REGS or _cn(inner) in _REGS:
                return _cn(inner), 1
        return None, 0

    def anchor(self, ea):
        """Follow the single-definition chain backward from the call's target
        register to the encoded global it derives from. Returns
        (global_addr, deref_level) where deref_level is how many memory
        dereferences are applied to (global + key) before control transfers.
        One frame-slot relay is followed. Returns (None, _) on failure."""
        reg, deref = self._start_reg(ea)
        if reg is None:
            return None, 0
        at = ea
        relayed = False
        for _ in range(_MAX_BACK):
            a = idc.prev_head(at, self.fs)
            if a == idc.BADADDR or a < self.fs:
                return None, deref
            at = a
            if (idc.get_operand_type(a, 0) != idc.o_reg
                    or _cn(idc.print_operand(a, 0)) != reg):
                continue
            mn = idc.print_insn_mnem(a)
            t1 = idc.get_operand_type(a, 1)
            if mn == "mov":
                if t1 == idc.o_mem:
                    return idc.get_operand_value(a, 1), deref   # mov reg, cs:off
                if t1 == idc.o_reg:
                    reg = _cn(idc.print_operand(a, 1))
                    continue
                if t1 in (idc.o_displ, idc.o_phrase):
                    p = _parse_mem(idc.print_operand(a, 1))
                    if p and any(rg in ("rbp", "rsp") for rg, _ in p[0]):
                        if relayed:
                            return None, deref
                        relayed = True
                        src = self._slot_src(a, 1)
                        if src is None:
                            return None, deref
                        reg, a2 = src
                        at = a2
                        continue
                    # mov reg, [reg2 (+idx)] -> a real deref of the chain
                    inner = self._mem_base_reg(a, 1)
                    if inner is None:
                        return None, deref
                    reg = inner
                    deref += 1
                    continue
                return None, deref
            if mn == "add":
                # add reg, key  /  add reg, imm  -- the key is folded later
                continue
            if mn == "lea":
                inner = self._mem_base_reg(a, 1)
                if inner is None:
                    return None, deref
                reg = inner
                continue
            return None, deref
        return None, deref

    def _mem_base_reg(self, a, n):
        p = _parse_mem(idc.print_operand(a, n))
        if not p:
            return None
        cand = [rg for rg, _ in p[0] if rg not in ("rbp", "rsp")]
        if len(cand) >= 1:
            return cand[0]
        return None

    def _slot_src(self, a, n):
        """Find the write that defines the frame slot read at (a,n); return
        (src_reg, write_ea) when the slot is set from a register."""
        p = _parse_mem(idc.print_operand(a, n))
        if not p:
            return None
        regs, disp = p
        base = None
        for rg, sc in regs:
            if rg in ("rbp", "rsp") and sc == 1:
                base = rg
            else:
                return None
        if base is None:
            return None
        b = a
        for _ in range(_MAX_BACK):
            b = idc.prev_head(b, self.fs)
            if b == idc.BADADDR or b < self.fs:
                return None
            if idc.print_insn_mnem(b) != "mov":
                continue
            if idc.get_operand_type(b, 0) not in (idc.o_displ, idc.o_phrase):
                continue
            pp = _parse_mem(idc.print_operand(b, 0))
            if not pp or len(pp[0]) != 1 or pp[0][0] != (base, 1) or pp[1] != disp:
                continue
            if idc.get_operand_type(b, 1) == idc.o_reg:
                return _cn(idc.print_operand(b, 1)), b
            return None
        return None

    def call_target(self, ea):
        """Concretely fold the indirect-call target by emulating the straight
        line run up to the call. The additive/deref import blind is built from
        inline immediates, so a local forward pass resolves it exactly."""
        if self._keys is None:
            self._keys = collect_keys()
        e = Emu(self._keys)
        e.r.update(self.const_regs())
        for a in self._trace(ea):
            e.step(a)
        ot = idc.get_operand_type(ea, 0)
        if ot == idc.o_reg:
            v = e.get(idc.print_operand(ea, 0))
        elif ot in (idc.o_displ, idc.o_phrase, idc.o_mem):
            v = e.load(ea, 0)
        else:
            return None
        if isinstance(v, Blind):
            return _pin(v.base, self._keys, True)
        return v

    def resolve(self, keys=None):
        """All indirect calls -> list of dicts."""
        self._keys = keys if keys is not None else collect_keys()
        out = []
        for h in idautils.Heads(self.fs, self.fe):
            if idc.print_insn_mnem(h) != "call":
                continue
            if idc.get_operand_type(h, 0) == idc.o_near:
                continue
            tgt = self.call_target(h)
            name = sym_for(tgt) if tgt is not None else None
            out.append({"ea": h, "op": idc.print_operand(h, 0),
                        "target": tgt, "name": name})
        return out


_KEYS_CACHE = None


def collect_keys(refresh=False):
    """All large (>32-bit) immediate constants moved into 64-bit registers
    anywhere in the image -- the candidate additive keys. Cached."""
    global _KEYS_CACHE
    if _KEYS_CACHE is not None and not refresh:
        return _KEYS_CACHE
    keys = set()
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        for h in idautils.Heads(f.start_ea, f.end_ea):
            if (idc.print_insn_mnem(h) == "mov"
                    and idc.get_operand_type(h, 0) == idc.o_reg
                    and idc.get_operand_type(h, 1) == idc.o_imm):
                v = idc.get_operand_value(h, 1) & U64
                if v > 0xFFFFFFFF:
                    keys.add(v)
    _KEYS_CACHE = keys
    return keys


def _valid_target(ea):
    """A 'good' resolved target: a function start or a named import/thunk.
    Returns the name, else None."""
    if ea is None or ida_segment.getseg(ea) is None:
        return None
    nm = ida_name.get_name(ea)
    if _is_code(ea):
        f = ida_funcs.get_func(ea)
        if f and f.start_ea == ea and nm:
            return nm
        return None
    # data: an IAT/pointer slot -> deref to the import name
    if nm and nm.startswith("__imp_"):
        return nm
    q = idc.get_qword(ea) & U64
    qn = ida_name.get_name(q)
    if qn and (qn.startswith("__imp_") or (_is_code(q) and ida_funcs.get_func(q)
               and ida_funcs.get_func(q).start_ea == q)):
        return qn
    return None


_BLIND_SLOT_CACHE = None
_BLIND_MAP_CACHE = None
_BLIND_KEYS_CACHE = None


def _blinded_slot_values(refresh=False):
    """Every distinct *blinded directory value* in the image: the qword stored at
    a `cs:off_*` data slot that is loaded by a `mov reg, cs:off` and is itself a
    large (>32-bit) non-address constant. These are the `V` of the import/call
    blind `target = V + KEY`. Cached. Returns {value: [slot_ea, ...]}."""
    global _BLIND_SLOT_CACHE
    if _BLIND_SLOT_CACHE is not None and not refresh:
        return _BLIND_SLOT_CACHE
    vals = {}
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        for h in idautils.Heads(f.start_ea, f.end_ea):
            if idc.print_insn_mnem(h) != "mov":
                continue
            if idc.get_operand_type(h, 0) != idc.o_reg:
                continue
            if idc.get_operand_type(h, 1) != idc.o_mem:
                continue
            off = idc.get_operand_value(h, 1)
            if ida_segment.getseg(off) is None:
                continue
            q = idc.get_qword(off) & U64
            if q <= 0xFFFFFFFF or ida_segment.getseg(q) is not None:
                continue
            vals.setdefault(q, []).append(off)
    _BLIND_SLOT_CACHE = vals
    return vals


def build_blind_map(refresh=False, min_family=4):
    """Resolve the additive-blind directory values to symbol names *key-agnostically*.

    The call/data blind is `target = V + KEY`, where V is a static directory
    value (see `_blinded_slot_values`) and KEY is a loop-invariant per-family key
    register. Many keys are large prologue immediates (`collect_keys`), but some
    are inherited/computed and never appear as a literal. Rather than recover KEY
    at each call site (which the flattening dispatch + stack relay defeats), we
    pin KEY once per *family*: a key that maps >= `min_family` distinct directory
    values onto valid targets is the family's real key. Each value then folds to
    a single target wherever its slot is loaded, regardless of how far the call
    is from the load.

    Returns {V: name}. Cached. Also caches the confirmed key set."""
    global _BLIND_MAP_CACHE, _BLIND_KEYS_CACHE
    if _BLIND_MAP_CACHE is not None and not refresh:
        return _BLIND_MAP_CACHE
    vals = list(_blinded_slot_values(refresh).keys())
    keys = collect_keys(refresh)
    # confirmed family keys: a literal key that validly resolves several values.
    confirmed = {}
    for k in keys:
        c = 0
        for v in vals:
            if _valid_target((v + k) & U64):
                c += 1
        if c >= min_family:
            confirmed[k] = c
    bmap = {}
    for v in vals:
        found = {}
        for k in confirmed:
            nm = _valid_target((v + k) & U64)
            if nm:
                found[k] = nm
        if not found:
            continue
        if len(found) == 1:
            bmap[v] = next(iter(found.values()))
        else:
            # extremely rare; prefer the higher-confidence (larger) family.
            bk = max(found, key=lambda kk: confirmed[kk])
            bmap[v] = found[bk]
    _BLIND_MAP_CACHE = bmap
    _BLIND_KEYS_CACHE = confirmed
    return bmap


def _blind_name_for_obj(ea):
    """If `ea` is a data slot whose stored qword is a known blinded directory
    value, return the symbol the blind resolves to (key-agnostic)."""
    if ea is None or ida_segment.getseg(ea) is None:
        return None
    if _is_code(ea):
        return None
    q = idc.get_qword(ea) & U64
    return build_blind_map().get(q)


def sym_for(ea):
    """Map a resolved target address to a human name. Handles:
       * a .text function           -> its name
       * an __imp_ IAT pointer slot  -> the import name (deref)
       * a direct import thunk       -> its name"""
    if ea is None:
        return None
    nm = ida_name.get_name(ea)
    if nm and not nm.startswith(("unk_", "byte_", "off_", "dword_", "qword_",
                                 "loc_", "sub_")):
        return nm
    if _is_code(ea):
        f = ida_funcs.get_func(ea)
        if f and f.start_ea == ea:
            return ida_name.get_name(ea) or ("sub_%X" % ea)
        if f:
            return "%s+0x%X" % (ida_name.get_name(f.start_ea), ea - f.start_ea)
    # maybe a pointer slot in .idata/.data -> deref
    s = ida_segment.getseg(ea)
    if s:
        q = idc.get_qword(ea) & U64
        qn = ida_name.get_name(q)
        if qn:
            return qn
    return nm or None


def _named_import(ea):
    """If `ea` is a *named import pointer slot*, return the API name. Covers the
    runtime-filled .bss slots IDA labels `p_<API>` (filled by the loader at run
    time, so their qword contents are 0xFF here) and classic `__imp_<API>` IAT
    thunks. These are the addresses the additive/deref blind ultimately selects;
    because the slot itself carries the name, the call is resolvable even though
    its run-time contents are not statically present."""
    if ea is None:
        return None
    s = ida_segment.getseg(ea)
    if s is None:
        return None
    nm = ida_name.get_name(ea)
    if not nm:
        return None
    if nm.startswith("p_"):
        return nm[2:]
    if nm.startswith("__imp_"):
        return nm[6:]
    return None


import ida_hexrays


def _fold(e):
    """Constant-fold a Hex-Rays expression to a 64-bit value, or None. Mirrors
    the on-disk semantics of the import blind: an `off_` data symbol used as a
    value is the qword stored there; pointer derefs read memory; +/-/* are
    folded. Cross-variable cases are handled by the caller substituting a
    variable's single constant definition."""
    if e is None:
        return None
    op = e.op
    if op == ida_hexrays.cot_num:
        return e.numval() & U64
    if op == ida_hexrays.cot_cast:
        return _fold(e.x)
    if op == ida_hexrays.cot_obj:
        ea = e.obj_ea
        if _is_code(ea):
            return ea & U64
        if ida_segment.getseg(ea) is None:
            return None
        return idc.get_qword(ea) & U64
    if op == ida_hexrays.cot_ref:
        if e.x.op == ida_hexrays.cot_obj:
            return e.x.obj_ea & U64
        return None
    if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub, ida_hexrays.cot_mul):
        a = _fold(e.x)
        b = _fold(e.y)
        if a is None or b is None:
            return None
        if op == ida_hexrays.cot_add:
            return (a + b) & U64
        if op == ida_hexrays.cot_sub:
            return (a - b) & U64
        return (a * b) & U64
    if op == ida_hexrays.cot_ptr:
        a = _fold(e.x)
        if a is None or ida_segment.getseg(a) is None:
            return None
        sz = getattr(e, "ptrsize", 8)
        return (idc.get_qword(a) if sz == 8 else idc.get_wide_dword(a)) & U64
    return None


class _CallVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, vardefs, ptrdefs):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.hits = []
        self.vardefs = vardefs      # idx -> rhs of  vN = rhs
        self.ptrdefs = ptrdefs      # idx -> rhs of  *vN = rhs

    def _fold_var(self, e, depth=0):
        if e is None or depth > 8:
            return None
        v = _fold(e)
        if v is not None:
            return v
        op = e.op
        if op == ida_hexrays.cot_cast:
            return self._fold_var(e.x, depth + 1)
        if op == ida_hexrays.cot_var:
            d = self.vardefs.get(e.v.idx)
            return self._fold_var(d, depth + 1) if d is not None else None
        # *vN  where the buffer vN points to was set by  *vN = <decoded ptr>
        if op == ida_hexrays.cot_ptr and e.x.op == ida_hexrays.cot_var:
            d = self.ptrdefs.get(e.x.v.idx)
            if d is not None:
                return self._fold_var(d, depth + 1)
        if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub):
            a = self._fold_var(e.x, depth + 1)
            b = self._fold_var(e.y, depth + 1)
            if a is not None and b is not None:
                return ((a + b) if op == ida_hexrays.cot_add
                        else (a - b)) & U64
            return None
        if op == ida_hexrays.cot_ptr:
            a = self._fold_var(e.x, depth + 1)
            if a is not None and ida_segment.getseg(a) is not None:
                sz = getattr(e, "ptrsize", 8)
                return (idc.get_qword(a) if sz == 8
                        else idc.get_wide_dword(a)) & U64
        return None

    def _scan_slot(self, e, depth=0):
        """Search the call-target expression for a dereferenced *named import
        slot* and return its API name. The blind ultimately loads the function
        pointer out of such a slot (`*slot`, possibly + an unblind key); the
        slot address folds to a `p_`/`__imp_` label even when its run-time
        contents are absent. Returns the name, else None."""
        if e is None or depth > 12:
            return None
        if e.op == ida_hexrays.cot_ptr:
            a = self._fold_var(e.x)
            nm = _named_import(a)
            if nm:
                return nm
            if e.x.op == ida_hexrays.cot_var:
                d = self.ptrdefs.get(e.x.v.idx)
                r = self._scan_slot(d, depth + 1) if d is not None else None
                if r:
                    return r
        for c in (getattr(e, "x", None), getattr(e, "y", None),
                  getattr(e, "z", None)):
            if c is not None:
                r = self._scan_slot(c, depth + 1)
                if r:
                    return r
        return None

    def _scan_blind(self, e, depth=0):
        """Search the call-target expression for an `off_*` data object whose
        stored qword is a known additive-blind directory value, and return the
        symbol it resolves to. Key-agnostic: it does not matter what (inherited /
        computed) key register the obfuscator adds -- the directory value alone
        determines the target. Follows single-assignment variable defs."""
        if e is None or depth > 12:
            return None
        if e.op == ida_hexrays.cot_obj:
            nm = _blind_name_for_obj(e.obj_ea)
            if nm:
                return nm
        if e.op == ida_hexrays.cot_var:
            d = self.vardefs.get(e.v.idx)
            if d is not None:
                return self._scan_blind(d, depth + 1)
        for c in (getattr(e, "x", None), getattr(e, "y", None),
                  getattr(e, "z", None)):
            if c is not None:
                r = self._scan_blind(c, depth + 1)
                if r:
                    return r
        return None

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call and e.x.op != ida_hexrays.cot_obj:
            self.hits.append((e.ea, self._fold_var(e.x),
                              self._scan_slot(e.x) or self._scan_blind(e.x)))
        return 0


def _collect_vardefs(cf):
    """Single-assignment maps:
       vardefs[idx]  = rhs of   vN = rhs
       ptrdefs[idx]  = rhs of  *vN = rhs   (buffer the pointer points at)."""
    defs = {}
    multi = set()
    pdefs = {}
    pmulti = set()

    class A(ida_hexrays.ctree_visitor_t):
        def __init__(s):
            ida_hexrays.ctree_visitor_t.__init__(s, ida_hexrays.CV_FAST)

        def visit_expr(s, e):
            if e.op == ida_hexrays.cot_asg:
                lhs = e.x
                if lhs.op == ida_hexrays.cot_var:
                    idx = lhs.v.idx
                    if idx in defs:
                        multi.add(idx)
                    else:
                        defs[idx] = e.y
                elif lhs.op == ida_hexrays.cot_ptr \
                        and lhs.x.op == ida_hexrays.cot_var:
                    idx = lhs.x.v.idx
                    if idx in pdefs:
                        pmulti.add(idx)
                    else:
                        pdefs[idx] = e.y
            return 0

    A().apply_to(cf.body, None)
    vardefs = {i: d for i, d in defs.items() if i not in multi}
    ptrdefs = {i: d for i, d in pdefs.items() if i not in pmulti}
    return vardefs, ptrdefs


def resolve_ctree(func_ea):
    """Resolve indirect call targets via the decompiler ctree (folds the import
    blind that Hex-Rays has already partially simplified). Returns list of
    (call_ea, target_ea_or_None)."""
    try:
        cf = ida_hexrays.decompile(func_ea)
    except Exception:
        return []
    if cf is None:
        return []
    vardefs, ptrdefs = _collect_vardefs(cf)
    v = _CallVisitor(vardefs, ptrdefs)
    v.apply_to(cf.body, None)
    out = []
    for cea, t, slot in v.hits:
        name = (sym_for(t) if t is not None else None) or slot
        out.append({"ea": cea, "target": t, "name": name})
    return out


def resolve_dir_loads(func_ea, cregs=None):
    """Resolve the obfuscated import references via the import-directory
    peephole -- the mechanism that covers the runtime-filled .bss table.

    Every external call / library data reference is emitted as a two-step blind:

        mov  R, cs:off_dir         ; R = directory value V (a 64-bit blind in
                                   ;     .data; V is not itself a valid address)
        mov/lea R, [R + BASE]      ; address (V + BASE) = the import slot

    BASE is a loop-invariant per-binary key register (r12/r13/... set once in
    the prologue, preserved across push/pop). The selected slot is a named
    import pointer -- a runtime-filled `.bss` `p_<API>` slot (whose contents the
    OS loader fills, so they are absent statically) or a static `.data`/IAT
    thunk that derefs to a real function. Because BASE and V are statically
    known, the slot -- and therefore the API -- is recovered without execution.

    Returns {load_insn_ea: api_name}. The annotation lands on the directory
    load, which sits immediately next to its (pointer-relayed) call site.
    """
    f = ida_funcs.get_func(func_ea)
    if not f:
        return {}
    if cregs is None:
        cregs = Resolver(func_ea).const_regs()
    if not cregs:
        return {}
    out = {}
    for h in idautils.Heads(f.start_ea, f.end_ea):
        if idc.print_insn_mnem(h) != "mov":
            continue
        if idc.get_operand_type(h, 0) != idc.o_reg:
            continue
        if idc.get_operand_type(h, 1) != idc.o_mem:
            continue
        V = idc.get_qword(idc.get_operand_value(h, 1)) & U64
        # directory values are 64-bit blinds, never a mapped pointer themselves
        if V <= 0xFFFFFFFF or ida_segment.getseg(V) is not None:
            continue
        R = _cn(idc.print_operand(h, 0))
        nh = idc.next_head(h, f.end_ea)
        if idc.print_insn_mnem(nh) not in ("mov", "lea"):
            continue
        if idc.get_operand_type(nh, 1) not in (idc.o_phrase, idc.o_displ):
            continue
        p = _parse_mem(idc.print_operand(nh, 1))
        if not p:
            continue
        regs, disp = p
        if R not in [rg for rg, sc in regs if sc == 1]:
            continue
        base = None
        for rg, sc in regs:
            if rg != R and sc == 1 and rg in cregs:
                base = cregs[rg]
        if base is None:
            continue
        slot = (V + base + disp) & U64
        nm = _named_import(slot) or _valid_target(slot)
        if nm:
            out[h] = nm
    return out


def resolve_blind_loads(func_ea):
    """Resolve every blinded directory load (`mov reg, cs:off` where the stored
    qword is a known additive-blind value) to its symbol via the family-key map.

    This recovers the import/internal call references the call-target folders
    miss: the flattening dispatch and the `call [rbp+slot]` relay separate the
    directory load from the transfer, so a per-call backward trace never reaches
    the load -- but the load itself is unambiguous once the family key is pinned.
    Returns {load_insn_ea: name}, annotated next to the recovered reference."""
    f = ida_funcs.get_func(func_ea)
    if not f:
        return {}
    bmap = build_blind_map()
    if not bmap:
        return {}
    out = {}
    for h in idautils.Heads(f.start_ea, f.end_ea):
        if idc.print_insn_mnem(h) != "mov":
            continue
        if idc.get_operand_type(h, 0) != idc.o_reg:
            continue
        if idc.get_operand_type(h, 1) != idc.o_mem:
            continue
        off = idc.get_operand_value(h, 1)
        if ida_segment.getseg(off) is None:
            continue
        nm = bmap.get(idc.get_qword(off) & U64)
        if nm:
            out[h] = nm
    return out


def resolve_function(func_ea, keys=None):
    return Resolver(func_ea).resolve(keys)


def resolve_combined(func_ea, keys=None, use_ctree=True):
    """Union of the assembly-trace resolver and the decompiler-ctree folder,
    keyed by call ea. The asm pass folds inline-key blinds; the ctree pass adds
    cross-block buffer-relayed pointers Hex-Rays has simplified."""
    by_ea = {}
    for it in Resolver(func_ea).resolve(keys):
        by_ea[it["ea"]] = it.get("name")
    if use_ctree:
        try:
            for it in resolve_ctree(func_ea):
                ea = it["ea"]
                if it["name"] and not by_ea.get(ea):
                    by_ea[ea] = it["name"]
        except Exception:
            pass
    # Import-directory peephole: recovers the runtime-filled .bss imports the
    # call-target folders cannot (their slot contents are absent statically).
    # Annotates the directory-load site, adjacent to the pointer-relayed call.
    try:
        for ea, nm in resolve_dir_loads(func_ea).items():
            if nm and not by_ea.get(ea):
                by_ea[ea] = nm
    except Exception:
        pass
    # Family-key blind map: resolves the directory loads whose key register is
    # inherited/computed (never a local literal), which the trace folders miss.
    try:
        for ea, nm in resolve_blind_loads(func_ea).items():
            if nm and not by_ea.get(ea):
                by_ea[ea] = nm
    except Exception:
        pass
    return by_ea


class _CallStmtVisitor(ida_hexrays.ctree_visitor_t):
    """Collect every call expression together with the address and kind of the
    ctree STATEMENT that physically contains it.

    Hex-Rays anchors a user comment to a (ea, item-preciser) pair and dumps it
    into a trailing `/* Orphan comments */` block whenever that pair matches no
    item in the regenerated ctree. The raw `call` instruction address is a poor
    anchor here: the obfuscator splits the blinded target load from the call, so
    Hex-Rays reassigns or drops the call's address (most call-instruction EAs
    appear in neither the eamap nor the statement boundaries). The enclosing
    statement, by contrast, is always a real ctree item with a stable address,
    so anchoring there never orphans."""

    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.calls = []

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            sea, sop = idc.BADADDR, None
            for i in range(len(self.parents) - 1, -1, -1):
                p = self.parents[i]
                if p.is_expr():
                    continue
                sea, sop = p.ea, p.op
                break
            self.calls.append((e.ea, sea, sop))
        return 0


# Statement kinds where an end-of-statement (ITP_SEMI) comment anchor is valid.
# A call embedded in a control header (if/while/for/switch condition) has no
# such anchor, so we leave those to the disassembly comment only rather than
# emit an orphan.
_SEMI_OK = None


def _set_pseudo_cmts(func_ea, ea2name):
    """Attach the resolved API names as Hex-Rays pseudocode comments (and
    disassembly comments) so the decompiled indirect calls read clearly.

    Disassembly comments land on the call/load instruction itself (always a real
    address -> reliable, full coverage). Pseudocode comments are anchored to the
    enclosing ctree statement (never the call-instruction address, which usually
    does not survive into the ctree) so Hex-Rays never orphans them. Names are
    resolved ON the ctree and merged per statement so several calls on one line
    are all reported."""
    global _SEMI_OK
    if _SEMI_OK is None:
        _SEMI_OK = {ida_hexrays.cit_expr, ida_hexrays.cit_return}
    # 1) disassembly comments -- keyed by instruction ea (reliable).
    for ea, name in ea2name.items():
        if not name or ea == idc.BADADDR:
            continue
        tag = "-> %s" % name
        cur = idc.get_cmt(ea, 0) or ""
        if tag not in cur:
            idc.set_cmt(ea, tag, 0)
    # 2) pseudocode comments -- anchored to enclosing statements.
    try:
        cf = ida_hexrays.decompile(func_ea)
    except Exception:
        cf = None
    if cf is None:
        return
    # Names available on ctree call expressions (ctree-native eas anchor cleanly;
    # the asm map contributes the calls whose ea happens to match exactly).
    ctmap = {}
    try:
        for it in resolve_ctree(func_ea):
            if it.get("name"):
                ctmap[it["ea"]] = it["name"]
    except Exception:
        pass
    vis = _CallStmtVisitor()
    vis.apply_to(cf.body, None)
    # Clear EVERY stale `-> ` annotation already stored for this function,
    # whatever its (ea, itp) -- older runs anchored on the raw call address
    # (which orphans) and a resolve pass with different coverage cannot re-find
    # those exact keys. Iterate the actual user-comment store so none are missed.
    uc = cf.user_cmts
    stale = []
    it = uc.begin()
    while it != uc.end():
        cm = uc.second(it)
        if str(cm).lstrip().startswith("->"):
            tl0 = uc.first(it)
            stale.append((tl0.ea, tl0.itp))
        it = uc.next(it)
    for ea, itp in stale:
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = itp
        cf.set_user_cmt(tl, "")
    # Merge resolved names per enclosing statement.
    anchors = {}
    for cea, sea, sop in vis.calls:
        if sea == idc.BADADDR or sop not in _SEMI_OK:
            continue
        name = ctmap.get(cea) or ea2name.get(cea)
        if not name:
            continue
        lst = anchors.setdefault(sea, [])
        if name not in lst:
            lst.append(name)
    for sea, names in anchors.items():
        tag = " ".join("-> %s" % n for n in names)
        tl = ida_hexrays.treeloc_t()
        tl.ea = sea
        tl.itp = ida_hexrays.ITP_SEMI
        cf.set_user_cmt(tl, tag)
    cf.save_user_cmts()


def annotate_function(func_ea, apply=False, keys=None, use_ctree=True):
    """Resolve and (optionally) annotate each recovered call site (both
    disassembly and pseudocode). Returns (resolved, total)."""
    by_ea = resolve_combined(func_ea, keys, use_ctree)
    resolved = {ea: nm for ea, nm in by_ea.items() if nm and ea != idc.BADADDR}
    if apply:
        _set_pseudo_cmts(func_ea, resolved)
    return len(resolved), len(by_ea)


def annotate_all(apply=True, use_ctree=False):
    """Resolve obfuscated import/library calls across the whole image and
    annotate each recovered call site. ctree is off by default for speed (it
    requires decompiling every function); enable for maximum recall."""
    keys = collect_keys()
    funcs = 0
    total = 0
    resolved = 0
    names = {}
    for fea in idautils.Functions():
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        if not any(idc.print_insn_mnem(h) == "call"
                   and idc.get_operand_type(h, 0) != idc.o_near
                   for h in idautils.Heads(f.start_ea, f.end_ea)):
            continue
        funcs += 1
        by_ea = resolve_combined(fea, keys, use_ctree)
        hit = {ea: nm for ea, nm in by_ea.items() if nm and ea != idc.BADADDR}
        total += len(by_ea)
        resolved += len(hit)
        for nm in hit.values():
            names[nm] = names.get(nm, 0) + 1
        # Always annotate (not gated on `hit`): _set_pseudo_cmts resolves names
        # on the ctree itself and clears stale `-> ` comments. Functions whose
        # calls resolve only via the ctree have an empty asm `hit` yet still need
        # both the inline anchoring and the orphan cleanup.
        if apply:
            _set_pseudo_cmts(fea, hit)
    return {"funcs": funcs, "calls": total, "resolved": resolved,
            "distinct": len(names), "names": names}
