# HOL Guard Rust Safety Kernel 3.0 PRD

Status: canonical specification for `release/3.0`.

## Objective

Complete the existing Rust runtime program by moving deterministic, latency-sensitive `PreToolUse` analysis into the verified resident native runtime while keeping HOL Guard a Python package. Rust owns strict decoding, bounded command and tool-call normalization, exactness, effect analysis, path classification, and native action and approval floors. Python keeps harness compatibility, policy administration, approvals, exceptions, receipts, durable workflow state, cloud and MDM synchronization, presentation, diagnosis, repair, and the named unsupported-platform and emergency rollback paths.

## Decision contract

The final action and approval requirement are always the more restrictive native or Python values. An authenticated native pause or deny cannot be weakened by Python. Native allow is valid only for exact, fully identity-bound, release-gated requests. Unsupported, ambiguous, malformed, overloaded, timed-out, unauthenticated, incompatible, crashed, or mismatched native analysis follows the machine-readable fail-safe matrix and never becomes a silent allow.

## Required scope

- Complete authenticated protocol v2, strict limits, fixed workers, bounded queues, lifecycle capacity, serving-generation binding, ephemeral authentication material, prewarm, asynchronous single-flight recovery, backoff, circuit breaking, bounded one-shot recovery, and bounded Python fallback.
- Add exact bounded models for POSIX shell, PowerShell, Windows CMD, common language launchers, package tools, version-control tools, network clients, data tools, containers, clusters, infrastructure tools, cloud tools, MCP calls, and Guard administration.
- Add a versioned privacy-safe effect model covering sensitive reads, outbound transfer, process and package execution, writes and removal, permissions and persistence, repository mutation, data-store mutation, infrastructure mutation, elevated execution, and Guard tampering.
- Add non-downgradable native action and approval floors, deterministic reason codes, policy and corpus identity, cross-language fixtures, differential and mutation parity, and staged shadow, pause/deny, then exact-allow rollout.
- Qualify real installed wheels on Ubuntu 22.04/24.04 x64, macOS Intel/Apple Silicon, Windows x64, CPython 3.10 through 3.14, pip, pipx, uv, offline install, update, downgrade, reinstall, rollback, Desktop, and managed deployment.
- Add one stable native status model, `hol-guard runtime status --json`, `hol-guard doctor --native`, idempotent repair, aggregate-only metrics, privacy-safe support bundles, and local and managed kill switches.
- Remove replaced Python hot-path code and dependencies only after static, dynamic, installed-wheel, unsupported-platform, and rollback proof.
- Add Rust dependency, license, SBOM, provenance, published-byte, fuzz, mixed-load, restart, resource, 100,000-request soak, leak, performance, and independent-review gates.

## Quality gates

- Approved high-impact corpus: 100% pause or deny and zero unsafe downgrade.
- Exact safe corpus: false pause below 0.5%.
- Warm native PreToolUse: p95 at most 10 ms and p99 at most 25 ms on documented Tier 1 reference hardware.
- Cold native analysis: p95 at most 100 ms; resident readiness at most 250 ms.
- Exact modeled requests: at least 2x adapter-to-decision p95 improvement over the Python reference path.
- Sensitive hook inputs and policy material never appear in durable outputs or uploaded artifacts.
- Every retained fallback is named, reachable, and exercised in CI.

## Non-goals

Do not replace the Python package, move product control-plane workflows into Rust, execute user commands in Rust, partially interpret unsupported syntax and call it exact, or merge `release/3.0` into `main` during this program.

## Completion

Completion requires every item in `rust-safety-kernel-pretool-todo.md` and every incorporated item in `rust-runtime-hardening-todo.md` to pass on the exact release head, reviewed work merged only into `release/3.0`, and a signed alpha whose package artifacts, native wheels, container, SBOM, provenance, release assets, and tag bind to that exact merge commit.
