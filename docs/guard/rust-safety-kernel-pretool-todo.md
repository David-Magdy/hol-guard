# HOL Guard Rust Safety Kernel 3.0 TODO

Status: canonical execution checklist for `release/3.0`.

All unchecked work in `rust-runtime-hardening-todo.md` remains required. This checklist adds PreToolUse and groups the final program gates. Do not merge `release/3.0` into `main` during this work.

- [x] Add the combined PostToolUse and PreToolUse PRD.
- [ ] Inventory current Python and Rust ownership, capabilities, workflows, callers, and installed package contents.
- [ ] Complete the resident protocol, admission limits, worker queues, lifecycle reservation, health capacity, generation tracking, restart, backoff, rotation, circuit, and bounded fallback behavior.
- [ ] Add versioned language-neutral PreToolUse request, response, parser, effect, policy, and corpus contracts.
- [ ] Add exact bounded native parsing for supported shell, structured tool-call, package, version-control, network, data, container, cluster, infrastructure, cloud, MCP, and Guard-administration surfaces.
- [ ] Mark unsupported or ambiguous input as inexact and cover exact and inexact cases with golden, differential, and mutation tests.
- [ ] Add privacy-safe native effects plus native action and approval floors.
- [ ] Combine native and Python results using the more restrictive value and limit native positive authority to exact release-gated requests.
- [ ] Qualify real wheels on Tier 1 operating systems, CPython 3.10 through 3.14, supported installers, offline flows, update and rollback, Desktop, and managed deployment.
- [ ] Add one native status model, runtime status and doctor commands, idempotent repair, aggregate-only metrics, support-bundle privacy, and local and managed rollback controls.
- [ ] Move shared fixtures to language-neutral files and remove replaced Python hot-path code and dependencies only after caller, installed-wheel, unsupported-platform, and rollback proof.
- [ ] Add dependency, license, SBOM, provenance, published-byte, fuzz, mixed-load, recovery, soak, leak, performance, and independent-review gates.
- [ ] Run PreToolUse native analysis in Tier 1 shadow, prove parity, enable non-downgradable restrictive outcomes, then enable exact release-gated positive outcomes.
- [ ] Preserve eligible PostToolUse default `auto`, explicit `off`, and the named Python fallback.
- [ ] Reconcile and check every incorporated item in `rust-runtime-hardening-todo.md`.
- [ ] Run the complete final matrix on the exact release head.
- [ ] Merge reviewed work only into `release/3.0`.
- [ ] Publish and install a signed alpha whose tag and all release artifacts bind to the exact merge commit.
- [ ] Reconcile superseded Rust branches without deleting required audit evidence.

Completion requires every item above and in the previous Rust TODO to be truthfully checked, all documented correctness, privacy, performance, cross-platform, assurance, rollback, and publication gates to pass, and `release/3.0` into remain unmerged into `main`.
