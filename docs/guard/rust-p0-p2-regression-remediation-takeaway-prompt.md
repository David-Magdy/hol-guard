# Takeaway prompt: maintain the HOL Guard Rust P0-P2 regression boundary

Work from the latest `hashgraph-online/hol-guard:release/3.0`. Never merge `release/3.0` into `main` as part of this work.

Before changing Rust runtime, PreToolUse/PostToolUse adapters, command extensions, command patterns, package firewall, package shims, archive/decoder code, filesystem/path code, security rules, packaging, or native workflows:

1. Run `uv run python ci/rust_migration_regression_audit.py`.
2. Run `uv run python ci/run_rust_migration_regression.py --mode pr`.
3. Run locked Rust formatting, Clippy with warnings denied, and workspace tests.
4. Preserve the machine-readable ownership contract. Do not restore a retired Python evaluator or fallback.
5. Preserve package-bound native discovery. Do not search `PATH` or download a runtime.
6. Preserve every action severity, approval floor, public reason code, output-withholding rule, extension, and command pattern unless a separate security-reviewed product change intentionally changes it.
7. Treat uncertain, malformed, stale, oversized, exhausted, or integrity-invalid security input as fail closed. Never convert it to an implicit clean or allow.
8. Keep diagnostics aggregate-only. Never record raw commands, prompts, tool output, file contents, full paths, destinations, environment values, credentials, tokens, proofs, or arbitrary exception text.
9. Do not lower a regression baseline merely to make CI green. A baseline decrease requires evidence that coverage moved or became redundant, plus equivalent replacement tests in the same pull request.
10. Complete the GitHub review loop, resolve every valid comment, rerun affected tests, and merge only the exact reviewed green head into `release/3.0`.

Done means the permanent audit has zero blocking findings, all retained security and DX suites pass, no temporary migration artifact remains, and `main` remains untouched.
