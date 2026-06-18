#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
cff_string_decoder.py -- recover the obfuscated string pool from
``FortiEndpoint_Patch.exe`` (and binaries built with the same protector).

Two complementary recovery modes are provided, mirroring the way the malware
itself locates and decodes its strings:

* ``ida``  -- *faithful* recovery.  Run from inside IDA Pro (``File > Script
  file...`` or the console).  The module enumerates every function, replays the
  malware's own pointer arithmetic (``base_global +/- key`` folded by Hex-Rays),
  runs the verified decoder, and writes the plaintext back into the database as
  repeatable comments.  This mode produces *exact* blob start addresses and has
  effectively no false positives, but only sees strings that are referenced by
  statically-resolvable pointer arithmetic.

* ``scan`` -- *exhaustive* recovery.  Run as a normal Python script against the
  PE on disk (only ``pefile`` is required).  Every offset in ``.rdata`` is run
  through the decoder; clean hits are kept and the one-character "shift echoes"
  inherent to repeating-key XOR are collapsed away.  This mode recovers the
  whole pool (including the statically-linked SQLite/CRT literals that share the
  same encoding) at the cost of occasionally approximate start offsets.

The string cipher
-----------------
Each protected string is stored as a self-contained blob::

    [ key : 29 bytes ][ ciphertext : N bytes ][ 0x00 ]

and the plaintext is simply::

    plaintext[i] = ciphertext[i] XOR key[i % 29]

The 29-byte repeating key is prepended to *every* blob, so no global key table
is needed and each blob decodes independently.  This was reverse-engineered from
the decoder routine ``sub_14008B050`` (and its per-function clones); the long
chain of rotates/multiplies in that routine collapses algebraically to the XOR
above.

Usage
-----
Standalone (recover the entire pool from the executable)::

    python cff_string_decoder.py scan FortiEndpoint_Patch.exe -o strings.txt
    python cff_string_decoder.py scan FortiEndpoint_Patch.exe --json strings.json --min-len 6

Inside IDA (faithful recovery + database annotation)::

    # IDA Python console / Script file
    import cff_string_decoder as d
    d.run_ida(annotate=True, out_json=r"C:\\temp\\cff_strings.json")
"""

from __future__ import annotations

import argparse
import json
import sys

KEYLEN = 29
MAXLEN = 4096


# --------------------------------------------------------------------------- #
# core cipher
# --------------------------------------------------------------------------- #
def decode_blob(buf, off, lo=None, hi=None, max_len=MAXLEN):
    """Decode one blob whose 29-byte key starts at ``buf[off]``.

    Returns the plaintext ``bytes`` (without the terminating NUL) or ``None`` if
    the candidate does not look like a valid, NUL-terminated blob.
    """
    n = len(buf)
    if lo is None:
        lo = 0
    if hi is None:
        hi = n
    if off < lo or off + KEYLEN >= hi:
        return None
    key = buf[off:off + KEYLEN]
    out = bytearray()
    i = 0
    while off + KEYLEN + i < hi:
        b = buf[off + KEYLEN + i] ^ key[i % KEYLEN]
        if b == 0:
            return bytes(out)
        out.append(b)
        i += 1
        if i > max_len:
            return None
    return None  # ran off the end without a NUL terminator


# Characters that legitimately appear in this malware's strings (format
# specifiers, paths, registry keys, GUIDs, SQL, ...).
_TEXT_EXTRA = frozenset(b" \t\r\n.,:;/\\_-%@#&*()[]{}<>+='\"!?|$~^`")


def looks_texty(s, min_len=6, ratio=0.85):
    """Heuristic: does ``s`` look like a real (printable) string?"""
    if len(s) < min_len:
        return False
    if any(not (9 <= c <= 13 or 32 <= c <= 126) for c in s):
        return False
    good = sum(
        1
        for c in s
        if 48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in _TEXT_EXTRA
    )
    return good >= int(ratio * len(s))


# --------------------------------------------------------------------------- #
# standalone scan mode
# --------------------------------------------------------------------------- #
def _read_rdata(path):
    import pefile

    pe = pefile.PE(path, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00") == b".rdata":
            return image_base + sec.VirtualAddress, bytearray(sec.get_data())
    raise RuntimeError(".rdata section not found")


def _collapse_shift_echoes(hits):
    """Collapse the shift echoes produced by repeating-key XOR.

    A blob at start ``P`` with plaintext length ``L`` occupies the byte span
    ``[P, P + 29 + L]``.  Every neighbouring offset that still decodes cleanly
    (``P+1`` -> ``S[1:]``, ``P-3`` -> a few coincidental leading bytes + ``S``,
    ...) shares that same span end, so all echoes of one blob fall into a single
    overlapping cluster.  Real blobs never overlap, so the next genuine string
    starts beyond the span and opens a new cluster.  We keep the longest member
    of each cluster as its representative.
    """
    keep = []
    cluster = []
    cluster_end = -1
    for addr, s in sorted(hits):
        span_end = addr + KEYLEN + len(s)
        if cluster and addr <= cluster_end:
            cluster.append((addr, s))
            cluster_end = max(cluster_end, span_end)
        else:
            if cluster:
                keep.append(max(cluster, key=lambda t: (len(t[1]), -t[0])))
            cluster = [(addr, s)]
            cluster_end = span_end
    if cluster:
        keep.append(max(cluster, key=lambda t: (len(t[1]), -t[0])))
    return keep


def scan_pe(path, min_len=6, ratio=0.85, collapse=True):
    base, data = _read_rdata(path)
    n = len(data)
    hits = []
    for off in range(n - KEYLEN - 1):
        s = decode_blob(data, off)
        if s is not None and looks_texty(s, min_len=min_len, ratio=ratio):
            hits.append((base + off, s))
    # map back to plain (addr, bytes) keyed on absolute address for collapse
    if collapse:
        hits = _collapse_shift_echoes(hits)
    return sorted(hits)


# --------------------------------------------------------------------------- #
# faithful IDA mode
# --------------------------------------------------------------------------- #
def run_ida(annotate=True, out_json=None, max_funcs=None):
    """Faithful recovery from inside IDA Pro. Returns ``{addr: text}``."""
    import re

    import ida_bytes
    import ida_hexrays
    import idaapi
    import idautils
    import idc

    ida_hexrays.init_hexrays_plugin()
    rd = idaapi.get_segm_by_name(".rdata")
    lo, hi = rd.start_ea, rd.end_ea
    mask = 0xFFFFFFFFFFFFFFFF

    def gbuf(ea, size):
        b = ida_bytes.get_bytes(ea, size)
        return b if b else b""

    def decode_at(ptr):
        if not (lo <= ptr < hi - KEYLEN):
            return None
        key = gbuf(ptr, KEYLEN)
        if len(key) < KEYLEN:
            return None
        out = bytearray()
        i = 0
        while ptr + KEYLEN + i < hi:
            b = ida_bytes.get_byte(ptr + KEYLEN + i) ^ key[i % KEYLEN]
            if b == 0:
                break
            out.append(b)
            i += 1
            if i > MAXLEN:
                return None
        else:
            return None
        if not looks_texty(bytes(out), min_len=4, ratio=0.55):
            return None
        return bytes(out)

    def gval(name):
        try:
            return ida_bytes.get_qword(int(name.split("_", 1)[1], 16))
        except Exception:
            return None

    re_base = re.compile(r"(\bv\d+)\s*=\s*(off_[0-9A-Fa-f]+|qword_[0-9A-Fa-f]+)\s*;")
    re_doff = re.compile(
        r"(\bv\d+)\s*=\s*(off_[0-9A-Fa-f]+|qword_[0-9A-Fa-f]+)\s*([-+])\s*0x([0-9A-Fa-f]+)\s*;"
    )
    re_dv = re.compile(r"(\bv\d+)\s*=\s*(v\d+)\s*([-+])\s*0x([0-9A-Fa-f]+)\s*;")
    re_uoff = re.compile(r"(off_[0-9A-Fa-f]+|qword_[0-9A-Fa-f]+)\s*([-+])\s*0x([0-9A-Fa-f]+)")
    re_uv = re.compile(r"(\bv\d+)\s*([-+])\s*0x([0-9A-Fa-f]+)")

    def candidates(txt):
        val = {}
        for _ in range(8):
            changed = False
            for m in re_base.finditer(txt):
                v = gval(m.group(2))
                if v is not None and val.get(m.group(1)) != v:
                    val[m.group(1)] = v
                    changed = True
            for m in re_doff.finditer(txt):
                b = gval(m.group(2))
                if b is None:
                    continue
                r = (b - int(m.group(4), 16)) if m.group(3) == "-" else (b + int(m.group(4), 16))
                r &= mask
                if val.get(m.group(1)) != r:
                    val[m.group(1)] = r
                    changed = True
            for m in re_dv.finditer(txt):
                if m.group(2) in val:
                    b = val[m.group(2)]
                    r = (b - int(m.group(4), 16)) if m.group(3) == "-" else (b + int(m.group(4), 16))
                    r &= mask
                    if val.get(m.group(1)) != r:
                        val[m.group(1)] = r
                        changed = True
            if not changed:
                break
        out = set()
        for m in re_uoff.finditer(txt):
            b = gval(m.group(1))
            if b is None:
                continue
            out.add(((b - int(m.group(3), 16)) if m.group(2) == "-" else (b + int(m.group(3), 16))) & mask)
        for m in re_uv.finditer(txt):
            if m.group(1) in val:
                b = val[m.group(1)]
                out.add(((b - int(m.group(3), 16)) if m.group(2) == "-" else (b + int(m.group(3), 16))) & mask)
        out.update(val.values())
        return out

    found = {}
    funcs = list(idautils.Functions())
    if max_funcs:
        funcs = funcs[:max_funcs]
    for ea in funcs:
        try:
            txt = str(ida_hexrays.decompile(ea))
        except Exception:
            continue
        for ptr in candidates(txt):
            s = decode_at(ptr)
            if s is None:
                continue
            text = s.decode("latin1")
            found[ptr] = text
            if annotate:
                ida_bytes.set_cmt(ptr, "xstr: " + text, 1)
    if out_json:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump({hex(k): v for k, v in sorted(found.items())}, fh, indent=2)
    print("[cff] faithful recovery: %d strings" % len(found))
    return found


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("scan", help="exhaustive XOR-29 sweep of a PE on disk")
    sp.add_argument("pe", help="path to the target executable")
    sp.add_argument("-o", "--out", help="write decoded strings to this text file")
    sp.add_argument("--json", help="write decoded strings to this JSON file")
    sp.add_argument("--min-len", type=int, default=6, help="minimum plaintext length (default 6)")
    sp.add_argument("--ratio", type=float, default=0.85, help="minimum printable/texty ratio (default 0.85)")
    sp.add_argument("--no-collapse", action="store_true", help="keep one-char shift echoes")

    args = ap.parse_args(argv)

    if args.mode == "scan":
        hits = scan_pe(args.pe, min_len=args.min_len, ratio=args.ratio, collapse=not args.no_collapse)
        lines = ["0x%010x  %s" % (a, s.decode("latin1")) for a, s in hits]
        text = "\n".join(lines)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump({hex(a): s.decode("latin1") for a, s in hits}, fh, indent=2)
        if not args.out and not args.json:
            print(text)
        print("\n[cff] %d strings recovered" % len(hits), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
