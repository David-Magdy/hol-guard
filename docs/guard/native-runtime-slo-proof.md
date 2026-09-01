# Native runtime SLO proof

`scripts/bench_guard_native_installed_slo.py` measures the installed daemon
adapter through its hook ingress to the harness decision. It uses the declared
installed route matrix (13 harnesses and 21 PreToolUse/PostToolUse routes),
synthetic safe fixtures, and bounded aggregate output. It never writes command
text, prompts, tool output, paths, tokens, or response bodies to evidence.

The fixed contract is: at least 99% resident routing; zero safe-corpus
fail-safe decisions; warm p95 at most 20 ms; 250 KiB, 1 MiB, and 5 MiB p95 at
most 50, 120, and 350 ms; cold one-shot p95 at most 100 ms; readiness p95 at
most 250 ms; and 16-request p99 at most 100 ms with no errors. A 64-request
run must complete or return bounded fail-safe responses.

Native wheel CI runs the no-environment installed-wheel probe and the enforced
adapter SLO. Windows remains outside this wave. The stress script exposes
bounded thread, descriptor, and RSS aggregates. CI runs its `--enforce-soak`
profile for 100,000 requests over a populated 250,000-receipt store; local
checks use a small request count.

Example proof after installing a version-matched native wheel:

```sh
runtime=$(uv run --no-sync python -c 'from codex_plugin_scanner.guard.native_runtime import native_runtime_status; status = native_runtime_status(); assert status.identity is not None; print(status.identity.path)')
uv run --no-sync python scripts/bench_guard_native_installed_slo.py \
  --runtime "$runtime" \
  --warm-iterations 2 --cold-iterations 2 --recovery-iterations 2 \
  --readiness-samples 2 --enforce
```

Aggregate JSON is bounded by `scripts/native_slo_contract.py`; the contract
sanitizer is tested independently and is applied immediately before printing
or writing evidence.
