# Takeaway Prompt: Continue HOL Guard 3.0 Code-Quality Remediation

Continue the code-quality program in `hashgraph-online/hol-guard` on the current `release/3.0` head.

Read these files first:

1. `docs/guard/release-3-code-quality-hardening-prd.md`
2. `docs/guard/release-3-code-quality-hardening-todo.md`
3. `docs/guard/release-3-code-quality-audit.md`
4. `ci/code-quality-baseline.json`
5. `scripts/ci/code_quality_audit.py`

The first implementation pass already:

- reduced exact Python copy groups from 48 to one intentional standalone-tool mirror
- removed all identified temporary delivery workflows and staged patch artifacts
- fixed semver `0.x` caret matching
- preserved all managed-install context fields during update and uninstall repair
- added bounded, no-follow, owner-only private daemon file reads
- made directory synchronization propagate real I/O failures
- installed a CI ratchet for oversized files, long functions, complexity, duplicates, silent broad exceptions, parse failures, and temporary residue

Your task is to complete the next unchecked, highest-priority coherent cluster in the TODO. Do not attempt a repository-wide rewrite. Pick one subsystem or one tightly related function family, characterize it, remediate it, and run it through GitHub review and CI end to end.

Required operating rules:

- Target `release/3.0`, never `main`.
- Start from the latest target head and avoid overwriting concurrent work.
- Treat the generated audit as an inventory, not proof that every flagged item is defective.
- Add characterization tests before changing a large or security-sensitive function.
- Preserve CLI, daemon, adapter, policy, MDM, package, receipt, and runtime behavior.
- Preserve fail-closed behavior, stable reason codes, and audit receipts.
- Preserve owner-only permissions, no-follow semantics, bounded reads, file identity checks, path containment, and durable persistence.
- Preserve command authorization, package integrity, provenance, and containment behavior.
- Keep helpers narrowly owned. Do not create a generic utilities module.
- Preserve existing private names as aliases when removing them would create needless compatibility risk.
- Do not hand-edit generated dashboard assets.
- Do not add temporary workflows with repository write permissions.
- Do not increase any value in `ci/code-quality-baseline.json`.
- Do not refresh the baseline to make a failing change pass.
- Regenerate `docs/guard/release-3-code-quality-audit.md` only from the audit script.
- Update the TODO with exact completed work and verified remaining work.
- Run Ruff, Ruff format, BasedPyright, focused tests, and all affected repository contract suites.
- Open a pull request against `release/3.0`, resolve every CI and review finding, and merge only after the exact reviewed head is green.

Recommended next cluster:

- Characterize and decompose daemon HTTP routing in `src/codex_plugin_scanner/guard/daemon/server.py`, beginning with one route family rather than both `do_GET` and `do_POST` at once.

For that cluster:

1. Map the selected routes, authentication gates, request limits, response schemas, reason codes, and side effects.
2. Add or strengthen route-level characterization tests.
3. Extract a typed route handler module with no server-global mutation.
4. Leave `_GuardDaemonHandler` as thin transport orchestration.
5. Preserve loopback binding, authority-file validation, body limits, timeout behavior, privacy guarantees, and fail-closed defaults.
6. Run the code-quality audit and demonstrate that no baseline value increased.
7. Include before/after line count and complexity for the exact functions changed.
8. Record all validation commands and outcomes in the pull-request body.

Do not declare completion based only on local tests. Completion requires a merged pull request to `release/3.0` with all required checks green and all review threads resolved.
