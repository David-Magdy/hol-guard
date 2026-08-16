# PRD: HOL Guard 3.0 Code-Quality Hardening

## Document status

- Target branch: `release/3.0`
- Delivery branch: `refactor/release-3-code-quality-hardening`
- Scope: pre-release structural quality, correctness, and security-preserving remediation
- Authoritative inventory: `docs/guard/release-3-code-quality-audit.md`
- Permanent enforcement baseline: `ci/code-quality-baseline.json`

## 1. Executive summary

HOL Guard 3.0 has grown across Python, Rust, TypeScript, shell, packaging, MDM, adapters, daemon services, and CI. The release branch contains mature functionality and broad platform coverage, but it also accumulated exact copy-paste implementations, very large modules, long and complex functions, duplicated security-sensitive file handling, and temporary delivery workflows that should not remain in a release branch.

This program improves quality without attempting an unsafe repository-wide rewrite. The implementation has four parts:

1. Inventory every supported code and configuration file and publish the complete findings.
2. Remove exact production Python function copies by moving shared behavior behind narrow helpers while keeping existing private call points as compatibility aliases where needed.
3. Fix concrete edge defects discovered during the audit, with regression tests.
4. Add a CI ratchet that prevents new or growing structural debt while the remaining large-file and complexity backlog is reduced in bounded follow-up changes.

The ratchet deliberately distinguishes an issue candidate from a proven defect. A file over 500 lines, a function over 100 lines, a complexity score over 30, or a broad exception boundary requires review, but none is changed only to improve a metric. Security and behavioral equivalence take priority over churn.

## 2. Baseline and outcome

The same AST-based audit was run against the original branch snapshot and the remediated tree.

| Metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Code/config files scanned | 2,197 | 2,213 | +16 shared modules, tests, and audit assets |
| Files over 500 lines | 326 | 322 | -4 |
| Handwritten files over 500 lines | 313 | 309 | -4 |
| Generated files over 500 lines | 13 | 13 | unchanged |
| Production/tooling Python functions | 11,578 | 11,534 | -44 |
| Python functions at least 100 lines | 247 | 247 | unchanged and ratcheted |
| Python functions at complexity 30+ | 154 | 154 | unchanged and ratcheted |
| Exact Python function-copy groups | 48 | 1 | -47 |
| Functions in exact-copy groups | 104 | 2 | -102 |
| Silent broad exception handlers | 36 | 36 | unchanged and ratcheted |
| Forbidden one-shot delivery artifacts | 18 | 0 | -18 |
| Python parse errors | 0 | 0 | unchanged |

The one remaining exact-copy group is intentional. `scripts/mdm/generate-release-manifest.py` is a standalone release tool that must retain a local no-follow reader instead of importing the installed HOL Guard package. The production copy remains in `guard/mdm/manifest.py`. Both are security-sensitive and covered by tests.

## 3. Goals

### 3.1 Required outcomes

- Produce a deterministic inventory of files over 500 lines.
- Produce a deterministic inventory of Python functions at least 100 lines.
- Produce a deterministic inventory of Python functions with estimated cyclomatic complexity of at least 30.
- Detect normalized exact Python function copies of at least eight lines.
- Detect silent broad exception handlers for review.
- Identify and reject temporary delivery workflows and staged patch artifacts on the release branch.
- Consolidate exact copies where doing so preserves behavior and security boundaries.
- Preserve existing imports and private call points when changing all callers would create unnecessary regression risk.
- Fix concrete edge cases found during the audit.
- Add focused regression tests for each correctness or security fix.
- Prevent all audited debt classes from growing in future pull requests.
- Keep generated artifacts distinct from handwritten source so generated size does not block ordinary work.

### 3.2 Non-goals

- Rewriting every file over 500 lines in one pull request.
- Changing public CLI, daemon, adapter, policy, MDM, or runtime contracts.
- Replacing deliberate fail-safe or best-effort exception handling without subsystem-specific evidence.
- Changing generated dashboard bundles by hand.
- Reducing complexity through semantic rewrites that lack characterization tests.
- Introducing a new runtime dependency for code-quality analysis.
- Relaxing existing security checks, file-permission requirements, containment proofs, policy behavior, or fail-closed paths.

## 4. Audit methodology

### 4.1 File inventory

The audit scans code and configuration under:

- `.github/workflows`
- `action`
- `ci`
- `dashboard`
- `devcontainer-features`
- `distributions`
- `fuzzers`
- `guarded-repository`
- `integrations`
- `rust`
- `scripts`
- `src`
- `tests`

It includes Python, Rust, TypeScript, JavaScript, shell, PowerShell, Swift, HTML, CSS, TOML, YAML, and installer source. It excludes dependency trees, virtual environments, caches, and Python bytecode.

Generated dashboard assets and lockfiles are marked separately. They remain visible in the report but do not create a handwritten-file ratchet failure.

### 4.2 Python structural analysis

The audit parses non-test, non-generated Python with the standard library AST. For every function it records:

- repository path and qualified name
- start and end line
- line count
- estimated cyclomatic complexity
- normalized AST digest

The normalized digest removes the function name, decorators, location metadata, and leading docstring. Functions with the same digest are exact structural copies even when their names differ.

### 4.3 Broad exception review

The audit records bare, `BaseException`, and `Exception` handlers whose bodies silently pass, continue, break, or return `None`. These are review candidates, not automatic defects. HOL Guard contains legitimate best-effort cleanup and fail-safe boundaries, so the ratchet blocks new instances but does not rewrite existing ones without local evidence.

### 4.4 CI ratchet

`ci/code-quality-baseline.json` records the current accepted identities and measurements. CI fails when a change:

- introduces a new handwritten file over 500 lines
- makes an existing oversized handwritten file longer
- introduces a new function at least 100 lines
- makes an existing long function longer
- introduces a new function at complexity 30 or higher
- increases an existing complex function's complexity
- introduces or grows an exact-copy group
- introduces another silent broad exception handler
- introduces a Python parse failure
- restores temporary delivery residue

Debt can decrease without baseline edits. A baseline refresh is only appropriate after verified remediation, never to make a failing change pass.

## 5. Findings

### 5.1 Exact copy-paste implementations

The original snapshot contained 48 exact groups across 104 function instances. The repeated behavior included:

- package content identity and reauthentication checks
- scanner evidence construction
- managed-install context reconstruction
- adapter inventory snapshots
- containment result proofs
- daemon authority-file validation
- semver trust-range matching
- command-shape checks
- Poetry, uv, and Cargo lock parsing
- integer coercion and stable JSON formatting
- durable directory synchronization
- package identity, integrity, and executable-target parsing
- workspace override precedence
- state and backup file helpers
- MDM cross-platform locks and Windows path handling
- command correlation, timestamps, stat identity, ordered deduplication, and ecosystem JSON loading

These copies were consolidated into narrow common modules. Existing private names are aliases, static methods, or partials where retaining the old symbol reduces regression risk.

### 5.2 Files over 500 lines

The complete list of 322 files is in the generated audit. The highest-risk handwritten production hotspots are:

| Lines | File | Primary risk |
| ---: | --- | --- |
| 8,837 | `guard/daemon/server.py` | HTTP routing, authentication, policy, cloud, dashboard, and lifecycle concerns in one module |
| 6,435 | `guard/runtime/runner.py` | runtime orchestration, receipts, containment, synchronization, and policy flow |
| 4,996 | `guard/runtime/supply_chain_package_eval.py` | ecosystem parsing, evidence, policy, and execution paths |
| 4,436 | `guard/local_supply_chain.py` | installation, dependency, scanner, and remediation orchestration |
| 4,281 | `dashboard/src/guard-api.ts` | broad client contract and endpoint surface |
| 3,899 | `guard/proxy/runtime_mcp.py` | proxy transport, package interception, evidence, and policy decisions |
| 2,936 | `guard/daemon/manager.py` | process lifecycle, state, authentication, upgrades, and recovery |
| 2,885 | `guard/cli/render.py` | many unrelated presentation contracts |
| 2,792 | `guard/cli/update_commands.py` | update, repair, rollback, context reconstruction, and platform handling |
| 2,667 | `guard/approvals.py` | approval persistence, validation, resolution, and policy application |

Large test files are also reported. They should be split by behavior only when fixtures and collection identities can remain stable.

### 5.3 Long and complex functions

The largest immediate decomposition candidates are:

| Lines | Complexity | Function |
| ---: | ---: | --- |
| 1,036 | 205 | `commands_hook_runtime_eval._evaluate_runtime_artifact_hook` |
| 743 | 132 | `consumer.service.evaluate_detection` |
| 708 | 126 | `commands_hook_generic._run_hook_generic_payload` |
| 578 | 108 | `runtime.runner.sync_receipts` |
| 574 | 53 | `runtime_mcp.RuntimeMcpGuardProxy._handle_package_request` |
| 554 | 122 | `update_commands.run_guard_update` |
| 551 | 74 | `StorePolicyMixin.resolve_policy_decision_lookup` |
| 550 | 150 | `_GuardDaemonHandler.do_POST` |
| 543 | 22 | `StoreConnectionSchemaMixin._initialize_schema` |
| 534 | 102 | `runtime.runner.guard_run` |

The implementation does not split these blindly. Each requires characterization tests and a bounded extraction plan because these functions enforce security policy, persistence, or transport behavior.

### 5.4 Temporary delivery residue

The branch contained 18 one-shot assets, including temporary workflow files, shepherd workflows, staged patch fragments, and an integration script. Several workflows had repository write permissions and automated pushes. These are valid during a coordinated delivery but are inappropriate permanent release assets. They have been removed, and the permanent audit prevents equivalent residue from returning.

### 5.5 Edge cases fixed

#### Node semver trust ranges

Three implementations of caret range matching diverged from npm-compatible `0.x` semantics. In particular, `^0.0.3` could accept `0.0.4`. Trust checks now share one parser and matcher that handles `0.0.x`, `0.x`, prerelease rejection, wildcards, exact versions, inequalities, tilde, caret, and OR clauses consistently. Malformed specifications fail closed.

#### Managed-install repair context

Update and uninstall flows reconstructed a managed-install context field by field. New fields could silently disappear during repair, including executable overrides and explicit home/workspace override flags. Reconstruction now uses `dataclasses.replace`, preserving all existing fields while changing only the intended paths. Persisted workspace values are validated before use.

#### Daemon authority-file reads

Authentication and state readers previously repeated path checks around ordinary file reads, leaving room for unbounded reads and check/use drift. The shared private-file reader now:

- opens with no-follow semantics where supported
- requires a regular file
- validates owner-only permissions and expected ownership
- bounds the number of bytes read
- verifies descriptor and path identity
- rejects parent-path instability
- rejects changes during the read
- decodes strict UTF-8

Authentication material is capped at 4 KiB. State and pending metadata use explicit 64 KiB limits.

#### Durable directory synchronization

Several MDM and integrity writers duplicated directory `fsync` logic and swallowed every `OSError`. The common implementation ignores only platform-reported unsupported operations and propagates real I/O failures, preserving durability guarantees instead of masking disk or filesystem errors.

## 6. Implementation architecture

### 6.1 Shared helpers

The remediation adds narrowly scoped modules instead of a generic utilities dumping ground. Representative modules include:

- `guard/private_file_io.py`
- `guard/durable_io.py`
- `guard/containment_execution_support.py`
- `guard/tool_decision_evidence.py`
- `guard/managed_install_context.py`
- `guard/runtime/node_semver.py`
- `guard/runtime/package_evidence_common.py`
- `guard/runtime/command_candidate_common.py`
- `guard/mdm/file_lock.py`
- `guard/mdm/windows_support.py`
- `guard/adapters/hook_payloads.py`
- `guard/adapters/state_files.py`
- `guard/adapters/workspace_overrides.py`
- `guard/path_security.py`
- `guard/file_identity.py`
- `guard/artifact_identity.py`
- `guard/stable_json.py`

Helpers own one invariant or representation. They do not create new cross-layer dependencies or make policy decisions on behalf of callers.

### 6.2 Compatibility strategy

Where a private function is imported by tests or adjacent modules, the old name remains bound to the shared implementation. This provides one implementation without requiring a large call-site migration. Compatibility aliases are not wrappers with copied logic.

### 6.3 Security strategy

- Security-sensitive helpers validate at the lowest reusable boundary.
- File operations use descriptors, bounded reads, explicit modes, identity checks, and strict decoding.
- Malformed trust or policy input fails closed.
- No helper broadens accepted command forms, package versions, paths, or permissions.
- No temporary workflow retains repository write authority.
- Existing policy, containment, receipt, MDM, and adapter behavior remains under its existing tests.

## 7. Functional requirements

### FR-1: Deterministic audit

Given the same repository tree and Python version, the audit must produce stable identities, sorted output, and a stable baseline.

### FR-2: No third-party runtime dependency

The audit must run with the standard library inside the existing development environment.

### FR-3: Exact-copy remediation

No new exact Python function-copy group of eight or more lines may be introduced. The single accepted standalone release-tool mirror may not grow or gain another instance.

### FR-4: Size and complexity ratchet

No handwritten oversized file, long function, or high-complexity function may be introduced or made worse.

### FR-5: Exception ratchet

No new silent broad exception handler may be introduced. Existing handlers require subsystem-specific review before removal.

### FR-6: Release-tree hygiene

Temporary workflows, shepherd workflows, staged patch directories, and one-shot integration scripts must be absent.

### FR-7: Behavior preservation

All affected adapter, CLI, policy, package, MDM, daemon, containment, and runtime test contracts must remain green.

### FR-8: Security preservation

No refactor may weaken file ownership, permission, path containment, command authorization, package integrity, authentication, fail-closed, or auditability behavior.

## 8. Test and verification plan

### 8.1 Focused regression tests

- semver caret and malformed-range behavior
- managed-install context preservation and malformed persisted paths
- bounded private reads, symlink rejection, file replacement, oversize rejection, and permission checks
- durable directory synchronization and error propagation
- code-quality audit detection and ratchet behavior

### 8.2 Existing contract suites

Representative suites cover:

- adapters and inventory
- command capability and queue authorization
- runtime policy and decisions
- package evidence and package intent
- shell command modeling
- source views and policy bundles
- MDM lifecycle and platform behavior
- skill and documentation contracts

At implementation time, 731 tests passed locally with four platform-specific skips across these affected surfaces. Repository CI remains authoritative for full lint, type, compatibility, and sharded test coverage.

### 8.3 CI requirements

- Ruff lint and format checks
- BasedPyright at error level
- code-quality baseline check
- protected test inventory and duplicate-test reporting
- full Python 3.12 sharded suite
- Python compatibility contracts
- applicable Rust, dashboard, adapter, MDM, and packaging workflows

## 9. Rollout and rollback

### Rollout

1. Merge through a pull request targeting `release/3.0`.
2. Require all repository checks and review threads to pass.
3. Keep the audit baseline in the same commit as the implementation.
4. Use the generated audit as the source of truth for later bounded refactors.

### Rollback

The change is designed as pure extraction plus focused defect fixes. If a regression is found:

1. Revert the affected helper adoption and its tests together.
2. Do not restore temporary workflows or staged patch artifacts.
3. Do not refresh the baseline upward.
4. Retain any independent security fix unless evidence shows it caused the regression.

## 10. Follow-up sequencing

The remaining backlog must be reduced in small, reviewable units. Recommended order:

1. Split daemon HTTP routing from `daemon/server.py` without changing authentication or response contracts.
2. Extract receipt synchronization stages from `runtime/runner.py` behind typed inputs and outputs.
3. Decompose runtime artifact hook evaluation by detection, evidence, policy, approval, and rendering stages.
4. Decompose generic hook handling using the same stage boundaries.
5. Separate ecosystem parsing from package policy in `supply_chain_package_eval.py`.
6. Separate update planning, execution, rollback, and repair in `update_commands.py`.
7. Review the 36 silent broad exception handlers one subsystem at a time.
8. Split test megafiles only after preserving fixtures, markers, node IDs where required, and protected inventory contracts.

Every follow-up must reduce or preserve the baseline, never increase it.
