# CFF Deobfuscator

A standalone IDA Pro plugin that reverses **control-flow flattening (CFF)** on
x86-64 binaries in one resilient, multi-pass shot. It turns flattened,
indirect-dispatch functions back into readable control flow and labels the
obfuscated import / API calls so Hex-Rays output is meaningful again.

> **Scope:** this is a *targeted* deobfuscator. Its pattern matchers were
> reverse-engineered from one specific protector — the obfuscator in the
> `FortiEndpoint_Patch.exe` sample (see [Sample](#sample) for hashes). The
> multi-pass framework is generic and reusable, but the gadget/dispatcher/import
> shapes it recognizes are specific to that protector. Expect it to work on
> binaries from the **same** toolchain, not on arbitrary CFF. See
> [Scope: generic vs. sample-specific](#scope-generic-vs-sample-specific).

> **Documentation:** for an in-depth, novice-friendly field guide to the
> obfuscation and how each layer undoes it — with worked examples and diagrams —
> see [`docs/CFF-DEOBFUSCATOR.md`](docs/CFF-DEOBFUSCATOR.md).
>
> **Malware analysis:** a full capability/behavior report for the sample,
> produced from the deobfuscated database, is in
> [`docs/MALWARE-ANALYSIS-FortiEndpoint_Patch.md`](docs/MALWARE-ANALYSIS-FortiEndpoint_Patch.md).
> Its string-obfuscation section is backed by the standalone string recovery
> tool [`plugins/ida/cff_string_decoder.py`](plugins/ida/cff_string_decoder.py).

## What it does

The plugin runs three deobfuscation layers in order:

| Layer | Purpose |
| --- | --- |
| **Layer 1 — de-indirection** | Statically resolves each CFF decode gadget's `jmp <reg>` to its concrete target and rewrites it as a direct jump, so Hex-Rays can see whole (still-flattened) functions. |
| **Layer 2 — unflattening** | Recovers the real control-flow graph of each flattened state machine and byte-patches the dispatcher away, then folds the leftover opaque-predicate gadgets. |
| **Layer 3 — import annotation** | Resolves the additively-blinded import / library calls (`mov reg, cs:off; add reg, key; call reg`) and annotates each recovered call site in both the disassembly and the pseudocode. |

### Resilient and idempotent

The passes byte-patch the database, which is not safely repeatable. The plugin
records its progress in a private netnode, so:

- a **completed** database is detected and a second full run is a graceful no-op
  (it will not re-patch and corrupt state);
- an **interrupted** run resumes at the first incomplete stage instead of
  redoing finished ones.

### Two actions only

Both appear under **Edit > Plugins** (and in the plugin's own run dialog):

- **CFF Deobfuscator: Dry run (report only)** — read-only. Reports what each
  layer would do against the database's current state. Never writes.
- **CFF Deobfuscator: Full run (patch + annotate)** — applies all three layers
  (asks for confirmation first, since it modifies the IDB).

Progress and a final summary are printed to the **Output** window.

## Scope: generic vs. sample-specific

The **framework is generic**; the **recognizers are not**. Roughly, least → most
specific:

| Component | Generic / reusable | Specific to this protector |
| --- | --- | --- |
| Orchestration | Multi-pass driver, netnode idempotency / run-state, dry-run vs full-run split, console reporting, "resolve by emulation, refuse rather than guess, only overwrite provably-dead bytes" discipline | — |
| **Layer 1** | Constant micro-emulation to resolve computed `jmp <reg>` | Decode-gadget mnemonic set, "safe-to-overwrite" tail mnemonics (`add/mov/lea/nop`), Win64 volatile-register assumptions |
| **Layer 2** | The opaque-predicate fold is algebraically sound in general | 32-bit state variable in a stack slot; dispatcher as a **signed binary-search compare tree** (`cmp eax, IMM; jg/jle` interior, `cmp eax, STATE; jz/jnz` leaves); the **parity gadget** `lea Rd,[Rs-1]; imul Rd,Rs; test Rd,1; jz/jnz`; the direct vs. computed (jump-table) back-edge encodings |
| **Layer 3** | Keys are **discovered dynamically** (`collect_keys` + family-consistency in `build_blind_map`), not hardcoded | The additive-blind call scheme `mov reg, cs:off; add reg, KEY; call reg`; `.bss` runtime-filled imports labeled `p_<API>` / `__imp_<API>` |

A different flattener (e.g. an OLLVM-style switch dispatcher) would not match
Layer 2/3; Layer 1 is the most likely to transfer. To retarget the plugin to
another protector you would swap in new matchers for the items in the right-hand
column while keeping the entire left-hand column unchanged.

## Sample

The plugin was developed and validated against a single sample:

| | |
| --- | --- |
| File name | `FortiEndpoint_Patch.exe` |
| Type | PE32+ executable, x86-64 (console), 18 sections |
| Size | 4,019,070 bytes |
| MD5 | `338662fd0c4d750a0ba203a32b59f081` |
| SHA-1 | `17e771c78430cc67e71d4547f8996a1a488e9d3f` |
| SHA-256 | `0da123adf9251957a4b850a3f6bd6a753dd4892be176a84a18450e899534cc5e` |

> This is a malware/obfuscated sample — handle it only in an isolated analysis
> environment.

## Requirements

- IDA Pro 9.0–9.3 with the **Hex-Rays x86-64 decompiler**.
- A 64-bit (x86-64) target. No third-party Python packages are required.

## Installation

The plugin itself lives in [`plugins/ida/`](plugins/ida/).

### Option A — automated installer (recommended)

```bash
cd plugins/ida
python3 install.py
```

This copies the plugin into your IDA user plugins directory
(`$IDAUSR/plugins/cff-deobfuscator/`, defaulting to `%APPDATA%\Hex-Rays\IDA Pro`
on Windows or `~/.idapro` on Linux/macOS). Restart IDA and the plugin is
discovered automatically via its `ida-plugin.json` descriptor.

```bash
python3 install.py --dir "/path/to/ida/userdir"   # custom IDA user dir
python3 install.py --uninstall                     # remove a previous install
```

### Option B — manual copy (self-contained folder)

The `plugins/ida/` folder is a self-contained IDA plugin (it contains
`ida-plugin.json`). Copy its contents into a folder in your IDA user `plugins`
directory, e.g.:

```
~/.idapro/plugins/cff-deobfuscator/
    ida-plugin.json
    cff_deobfuscator.py
    cff/
```

Keep `cff_deobfuscator.py`, `ida-plugin.json`, and the `cff/` package together
in the same directory. Restart IDA.

### Option C — load once without installing

In IDA: **File > Script file…** and select `plugins/ida/cff_deobfuscator.py`.
The plugin adds its own directory to `sys.path`, so the `cff/` package is found
as long as it sits next to the entry script.

## Usage

1. Open the (analyzed) target database in IDA.
2. **Edit > Plugins > CFF Deobfuscator: Dry run** to preview the workload.
3. **Edit > Plugins > CFF Deobfuscator: Full run** to apply it; confirm the
   prompt. Watch the Output window for stage-by-stage progress.
4. Re-running the full run on the same database is safe — it reports that the
   work is already done and makes no changes.

All patches are normal IDB edits and are undoable; the recorded run-state lives
in a private netnode and does not alter your analysis.

### Driving the engines from the console (optional)

The layers are plain libraries and can be called directly:

```python
from cff import orchestrator
orchestrator.dry_run()      # read-only report
orchestrator.full_run()     # full patch + annotate pass

from cff import layer1 as L1, layer2 as L2, imports as L3
L1.patch_all()              # Layer 1 only
L2.unflatten_all()          # Layer 2 only
L3.annotate_all(apply=True) # Layer 3 only

from cff import runstate
runstate.reset()            # forget recorded progress (IDB is left untouched)
```

## Layout

```
plugins/ida/
    cff_deobfuscator.py   IDA plugin entry (PLUGIN_ENTRY, the two menu actions)
    cff_string_decoder.py standalone XOR-29 string recovery (IDA + offline modes)
    ida-plugin.json       Plugin Manager descriptor
    install.py            Cross-platform installer / uninstaller
    cff/
        orchestrator.py   dry_run() / full_run() multi-pass driver
        runstate.py       netnode-backed idempotency state
        log.py            console banners / status
        layer1.py         Layer 1 engine (de-indirection)
        layer2.py         Layer 2 engine (unflattening)
        imports.py        Layer 3 engine (import / API resolver)
docs/
    CFF-DEOBFUSCATOR.md   in-depth field guide (obfuscation + deobfuscation)
    MALWARE-ANALYSIS-FortiEndpoint_Patch.md   capability/behavior analysis report
```

## String recovery tool

[`plugins/ida/cff_string_decoder.py`](plugins/ida/cff_string_decoder.py) recovers
the sample's obfuscated string pool (a 29-byte repeating-XOR scheme; see §2.1 of
the analysis report). It has two modes:

```bash
# offline: sweep the .rdata pool straight from the PE (only `pefile` needed)
python3 plugins/ida/cff_string_decoder.py scan FortiEndpoint_Patch.exe -o strings.txt
```

```python
# inside IDA: faithful recovery (exact addresses) + write plaintext as comments
import cff_string_decoder as d
d.run_ida(annotate=True, out_json=r"C:\temp\cff_strings.json")
```
