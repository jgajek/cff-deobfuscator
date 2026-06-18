"""CFF Deobfuscator -- a multi-pass IDA Pro deobfuscation engine.

The package bundles the three deobfuscation layers as plain libraries and a
thin orchestrator that drives them in one resilient, idempotent pass:

    layer1   -- resolve & rewrite CFF indirect (`jmp <reg>`) dispatch so
                Hex-Rays can see whole (still-flattened) functions.
    layer2   -- recover the real control flow of flattened state machines and
                byte-patch the dispatcher away.
    imports  -- resolve the obfuscated import / library calls and annotate
                each recovered call site (Layer 3).

The user-facing entry point is the `cff_deobfuscator` IDA plugin, which calls
`cff.orchestrator.dry_run()` / `cff.orchestrator.full_run()`.
"""

__version__ = "1.0.0"
