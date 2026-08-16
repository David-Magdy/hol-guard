# TODO: HOL Guard 3.0 Code-Quality Hardening

This checklist implements `release-3-code-quality-hardening-prd.md`. The generated exhaustive inventory is `release-3-code-quality-audit.md`.

## A. Repository-wide discovery

- [x] Pin the audit to the exact `release/3.0` source snapshot.
- [x] Enumerate supported code and configuration roots.
- [x] Exclude dependency trees, virtual environments, caches, and bytecode.
- [x] Distinguish production, test, tooling, and workflow files.
- [x] Distinguish generated files from handwritten files.
- [x] Count all supported code files.
- [x] Record every file over 500 lines.
- [x] Parse non-test, non-generated Python with the standard library AST.
- [x] Record every Python function at least 100 lines.
- [x] Estimate and record every Python function at complexity 30 or higher.
- [x] Normalize function names, decorators, docstrings, and locations for exact-copy detection.
- [x] Record exact-copy groups of at least eight lines.
- [x] Record silent bare, `BaseException`, and `Exception` handlers.
- [x] Detect Python parse failures.
- [x] Detect temporary workflow and staged patch residue.
- [x] Generate a complete Markdown audit.
- [x] Generate a machine-readable JSON baseline.
- [x] Compare pre-remediation and post-remediation metrics with the same algorithm.

## B. Exact-copy remediation

### Package and artifact identity

- [x] Consolidate package content identity calculation.
- [x] Consolidate package reauthentication safety validation.
- [x] Consolidate package manifest JSON loading.
- [x] Consolidate package integrity extraction.
- [x] Consolidate package executable target parsing.
- [x] Consolidate package name normalization.
- [x] Consolidate stable artifact identity helpers.
- [x] Preserve existing private symbols as aliases where tests or adjacent modules rely on them.

### Containment and runtime evidence

- [x] Consolidate containment result proof construction.
- [x] Consolidate contained execution environment construction.
- [x] Consolidate containment health checks.
- [x] Consolidate workspace binding validation.
- [x] Consolidate contained command directory handling.
- [x] Consolidate tool-decision scanner evidence construction.
- [x] Consolidate runtime package evidence helpers.
- [x] Consolidate data-flow sink construction without replacing the existing data-flow module.
- [x] Consolidate monotonic and UTC time helpers.

### Command modeling

- [x] Consolidate plain-command candidate checks.
- [x] Consolidate executable resolution.
- [x] Consolidate command argument-shape validation.
- [x] Consolidate ordered string deduplication.
- [x] Preserve exact command authorization behavior.
- [x] Preserve fail-closed handling for malformed command input.

### Adapters and workspace state

- [x] Consolidate adapter hook payload helpers.
- [x] Consolidate adapter state and backup file handling.
- [x] Consolidate workspace override precedence.
- [x] Consolidate inventory snapshot defaults.
- [x] Consolidate ecosystem JSON loading.
- [x] Preserve adapter-specific paths, capabilities, and payload contracts.

### MDM and durable I/O

- [x] Consolidate cross-platform MDM file locks.
- [x] Consolidate Windows directory and attribute helpers.
- [x] Consolidate directory `fsync` behavior.
- [x] Consolidate file identity helpers.
- [x] Preserve standalone release-manifest script independence.
- [x] Document the remaining intentional no-follow reader mirror.

### General shared behavior

- [x] Consolidate integer coercion.
- [x] Consolidate stable JSON serialization.
- [x] Consolidate path and symlink security checks.
- [x] Consolidate stat identity comparison.
- [x] Consolidate scanner JSON formatting.
- [x] Consolidate saved approval validation.
- [x] Reduce exact-copy groups from 48 to 1.
- [x] Reduce copied function instances from 104 to 2.
- [x] Add a CI rule preventing any new or growing exact-copy group.

## C. Concrete edge-case fixes

### Semver trust matching

- [x] Reproduce the `^0.0.3` accepting `0.0.4` defect.
- [x] Implement one shared semver range parser and matcher.
- [x] Support exact versions.
- [x] Support wildcard specifications.
- [x] Support inequality clauses.
- [x] Support tilde ranges.
- [x] Support caret ranges with correct `0.x` semantics.
- [x] Support OR clauses.
- [x] Reject prerelease versions unless explicitly supported by policy.
- [x] Fail closed on malformed specifications.
- [x] Update all three trust-matching consumers.
- [x] Add focused regression tests.

### Managed-install context preservation

- [x] Identify field-by-field context reconstruction in update and uninstall paths.
- [x] Replace reconstruction with `dataclasses.replace`.
- [x] Preserve executable overrides.
- [x] Preserve explicit home override state.
- [x] Preserve explicit workspace override state.
- [x] Preserve future dataclass fields by default.
- [x] Validate persisted workspace paths.
- [x] Handle malformed NUL-containing paths safely.
- [x] Add focused regression tests.

### Private daemon file reads

- [x] Create a bounded private-file reader.
- [x] Open with no-follow semantics where supported.
- [x] Require a regular file.
- [x] Require expected ownership.
- [x] Require owner-only permissions.
- [x] Bound authentication reads to 4 KiB.
- [x] Bound state and pending reads to 64 KiB.
- [x] Compare descriptor and path identity.
- [x] Detect file replacement during a read.
- [x] Detect parent-path instability.
- [x] Decode strict UTF-8.
- [x] Apply the helper to daemon manager authentication.
- [x] Apply the helper to daemon discovery state.
- [x] Apply the helper to the bounded CLI hook bridge.
- [x] Add symlink, permissions, replacement, oversize, and decode tests.

### Durable directory synchronization

- [x] Create one portable directory synchronization helper.
- [x] Ignore only unsupported directory synchronization errors.
- [x] Propagate real I/O failures.
- [x] Apply it to command correlation persistence.
- [x] Apply it to hook integrity persistence.
- [x] Apply it to MDM harness coverage persistence.
- [x] Apply it to MDM removal persistence.
- [x] Apply it to MDM health lease persistence.
- [x] Add success, unsupported, and real-failure tests.

## D. Release-tree hygiene

- [x] Remove staged Rust patch fragments.
- [x] Remove staged base64 delivery fragments.
- [x] Remove the one-shot daemon edge integration script.
- [x] Remove daemon cleanup shepherd workflow.
- [x] Remove daemon final-tree shepherd workflow.
- [x] Remove daemon source-fix shepherd workflow.
- [x] Remove all `tmp-*` delivery workflows.
- [x] Remove the temporary code-quality source export workflow from the final tree.
- [x] Confirm no release behavior depends on the removed assets.
- [x] Add permanent audit rejection for equivalent residue.
- [x] Keep repository write permissions out of replacement audit logic.

## E. CI and documentation

- [x] Add `scripts/ci/code_quality_audit.py`.
- [x] Keep the audit implementation itself under 500 lines by splitting AST and report modules.
- [x] Add `scripts/ci/code_quality_ast.py`.
- [x] Add `scripts/ci/code_quality_report.py`.
- [x] Add `ci/code-quality-baseline.json`.
- [x] Add generated exhaustive audit documentation.
- [x] Add this PRD.
- [x] Add this TODO.
- [x] Add the continuation takeaway prompt.
- [x] Add audit unit tests.
- [x] Add the audit to the primary CI quality job.
- [x] Reject new handwritten files over 500 lines.
- [x] Reject growth in existing handwritten files over 500 lines.
- [x] Reject new or growing functions at least 100 lines.
- [x] Reject new or growing functions at complexity 30 or higher.
- [x] Reject new or growing exact-copy groups.
- [x] Reject new silent broad exception handlers.
- [x] Reject Python parse failures.
- [x] Reject temporary delivery residue.
- [x] Allow debt reductions without requiring a baseline edit.
- [x] Treat generated files as inventory but not handwritten debt.

## F. Verification completed in the implementation branch

- [x] Compile all new and changed Python modules.
- [x] Run focused semver tests.
- [x] Run focused managed-install context tests.
- [x] Run focused private-file I/O tests.
- [x] Run focused durable I/O tests.
- [x] Run code-quality audit tests.
- [x] Run representative adapter tests.
- [x] Run command capability and command queue tests.
- [x] Run runtime policy and decision tests.
- [x] Run package evidence and package intent tests.
- [x] Run shell command modeling tests.
- [x] Run inventory and skill documentation tests.
- [x] Run representative MDM tests.
- [x] Run source-view and policy bundle tests.
- [x] Record 731 local passes and four platform-specific skips across affected surfaces.
- [ ] Require Ruff lint and format checks in GitHub Actions.
- [ ] Require BasedPyright at error level in GitHub Actions.
- [ ] Require all applicable sharded, compatibility, Rust, dashboard, packaging, adapter, MDM, and release checks in GitHub Actions.
- [ ] Resolve every pull-request review thread.
- [ ] Merge only after the exact reviewed head is green.

## G. Remaining decomposition backlog

The complete backlog is generated in `release-3-code-quality-audit.md`. These tasks must be completed in bounded follow-up pull requests. A task is not complete merely because code moved. It is complete only when behavior is characterized, the extraction has a narrow responsibility, and all relevant security contracts pass.

### Priority 0: daemon and runtime control planes

- [ ] Characterize every branch of `_GuardDaemonHandler.do_GET` before extraction.
- [ ] Characterize every branch of `_GuardDaemonHandler.do_POST` before extraction.
- [ ] Extract request authentication from daemon routing without changing reason codes.
- [ ] Extract bounded request-body parsing without changing limits.
- [ ] Extract dashboard/static routes from API routes.
- [ ] Extract local device and health routes.
- [ ] Extract policy and approval routes.
- [ ] Extract cloud command and synchronization routes.
- [ ] Preserve loopback-only binding and authority-file requirements.
- [ ] Reduce `daemon/server.py` below its current 8,837-line baseline incrementally.
- [ ] Characterize `runtime.runner.guard_run` stage by stage.
- [ ] Characterize `runtime.runner.sync_receipts` success, retry, and failure behavior.
- [ ] Extract receipt collection, validation, serialization, and upload stages.
- [ ] Extract containment preparation from runtime execution.
- [ ] Extract post-execution evidence assembly.
- [ ] Preserve policy ordering, reason codes, and audit receipts.
- [ ] Reduce `runtime/runner.py` below its current 6,435-line baseline incrementally.

### Priority 0: hook evaluation

- [ ] Characterize `_evaluate_runtime_artifact_hook` for every supported artifact and failure mode.
- [ ] Extract payload normalization.
- [ ] Extract artifact discovery.
- [ ] Extract scanner and package evidence collection.
- [ ] Extract policy lookup and decision combination.
- [ ] Extract approval resolution.
- [ ] Extract response rendering.
- [ ] Keep fail-closed behavior for malformed or ambiguous artifacts.
- [ ] Bring `_evaluate_runtime_artifact_hook` below 100 lines through typed orchestration stages.
- [ ] Characterize `_run_hook_generic_payload` for all harnesses.
- [ ] Reuse the same stage boundaries where semantics are genuinely shared.
- [ ] Keep harness-specific payload and response contracts separate.
- [ ] Bring `_run_hook_generic_payload` below 100 lines.

### Priority 1: supply-chain evaluation

- [ ] Separate ecosystem lockfile parsing from policy evaluation.
- [ ] Separate package identity from execution planning.
- [ ] Separate scanner evidence collection from decision aggregation.
- [ ] Split `supply_chain_package_eval.py` by ecosystem-neutral responsibilities.
- [ ] Split `local_supply_chain.py` by discovery, evaluation, remediation, and persistence.
- [ ] Preserve offline behavior and bounded execution.
- [ ] Preserve package integrity and provenance checks.
- [ ] Preserve fail-closed behavior for malformed lockfiles and manifests.
- [ ] Reduce each file without introducing parser divergence.

### Priority 1: update and repair

- [ ] Characterize `run_guard_update` success, no-op, rollback, partial failure, and recovery paths.
- [ ] Extract update planning.
- [ ] Extract artifact acquisition and verification.
- [ ] Extract installation execution.
- [ ] Extract rollback and recovery.
- [ ] Extract managed-install repair.
- [ ] Preserve executable, home, workspace, and MDM context.
- [ ] Bring `run_guard_update` below 100 lines.
- [ ] Split `update_commands.py` below its current baseline.

### Priority 1: policy and approval persistence

- [ ] Characterize `resolve_policy_decision_lookup` precedence and fallback behavior.
- [ ] Extract source loading, normalization, matching, and result construction.
- [ ] Preserve fail-closed behavior and reason codes.
- [ ] Characterize `apply_approval_resolution` for allow, deny, expiry, mismatch, and tamper cases.
- [ ] Separate approval validation from persistence and policy application.
- [ ] Split `approvals.py` by lifecycle responsibility.
- [ ] Keep owner-only persistence and integrity requirements unchanged.

### Priority 2: proxy and dashboard boundaries

- [ ] Characterize `RuntimeMcpGuardProxy._handle_package_request` across package managers and transport failures.
- [ ] Extract request parsing, package evidence, policy, execution, and response stages.
- [ ] Preserve proxy timeout, size, and fail-closed behavior.
- [ ] Split `runtime_mcp.py` by transport and policy responsibility.
- [ ] Split `dashboard/src/guard-api.ts` into typed endpoint domains.
- [ ] Preserve API route names, payload schemas, and error handling.
- [ ] Keep generated dashboard assets out of handwritten remediation.

### Priority 2: silent broad exception review

- [ ] Review all 36 entries in the generated audit.
- [ ] Label each as fail-safe, best-effort cleanup, compatibility boundary, or defect.
- [ ] Add a comment or focused test for every intentionally retained handler.
- [ ] Narrow exception types where evidence supports it.
- [ ] Add logging or stable reason codes where silent failure harms diagnosis without leaking data.
- [ ] Never convert a fail-closed path into fail-open behavior.
- [ ] Reduce the baseline only after subsystem tests pass.

### Priority 3: test-suite organization

- [ ] Split `tests/test_guard_runtime.py` by runtime capability while preserving markers and fixtures.
- [ ] Split `tests/test_guard_cli.py` by command domain.
- [ ] Split other test files over 2,000 lines by behavior rather than arbitrary size.
- [ ] Preserve protected test inventory contracts.
- [ ] Preserve test node IDs where release tooling depends on them.
- [ ] Avoid duplicating fixtures during a split.
- [ ] Keep each split independently collectable across supported Python versions.

## H. Rules for every follow-up

- [ ] Select one bounded subsystem or one coherent duplicate family.
- [ ] Add characterization tests before semantic refactoring.
- [ ] Preserve public and private compatibility surfaces unless an intentional change is documented.
- [ ] Preserve fail-closed behavior.
- [ ] Preserve file ownership, permissions, no-follow, bounded-read, and containment invariants.
- [ ] Preserve command and package authorization semantics.
- [ ] Do not introduce a generic `utils.py` dumping ground.
- [ ] Do not raise any code-quality baseline value.
- [ ] Do not refresh the baseline to bypass a failure.
- [ ] Regenerate the exhaustive audit after remediation.
- [ ] Run focused tests plus all affected contract suites.
- [ ] Resolve all review findings before merge.
