# HOL Guard Rust P0-P2 regression remediation PRD

Status: implemented remediation specification for `release/3.0`.

## Problem

The Rust migration moved deterministic local enforcement into the bundled native runtime, but the release tree still contained temporary patch-transfer material and a temporary workflow from the migration process. That residue could trigger unrelated CI failures, preserve obsolete patch state, and make the reviewed source of truth ambiguous.

The repository also had strong individual test suites without one executable gate proving that the complete migration still preserves all of the following together:

- the Rust-only ownership boundary for migrated P0-P2 evaluators;
- every retained security regression family;
- command extensions and command-pattern behavior;
- package firewall and package-shim behavior;
- archive, decoding, filesystem, path, and integrity behavior;
- native packaging, installed-artifact, provenance, fuzz, and security workflows;
- developer autonomy and the existing low-risk command path.

A future refactor could therefore remove a test family, restore a retired Python evaluator, introduce unsafe Rust, add runtime download or PATH discovery, or accidentally leave another transfer workflow without one clearly named pull-request gate failing.

## Goals

1. Remove all obsolete Rust transfer payloads and temporary migration workflows from the release tree.
2. Add a privacy-safe executable ownership and regression audit.
3. Ratchet the current test inventory for native runtime, command extensions and patterns, package/supply-chain, filesystem integrity, security regressions, and installed artifacts.
4. Run the retained P0-P2 test surface through one reproducible command.
5. Preserve every existing security action, approval floor, extension, command pattern, package rule, reason code, and developer-safe path.
6. Keep Python as the product control plane without restoring a second production evaluator.
7. Keep all work isolated to `release/3.0`; do not merge the release branch into `main`.

## Non-goals

- Changing policy outcomes or approval defaults.
- Broadening native authority.
- Reintroducing a Python runtime fallback.
- Replacing the existing focused Rust, CodeQL, security, fuzz, native-wheel, or publication workflows.
- Logging commands, prompts, paths, package content, secrets, environment values, or arbitrary exceptions.

## Requirements

### R1. Release-tree hygiene

The release tree must contain no `.github/rust-required-*` transfer chunks and no temporary Rust apply, export, transfer, or bundle workflow. A permanent contract test must reject their return.

### R2. Ownership drift prevention

The audit must load the machine-readable Rust/Python ownership contract and fail when a retired file or symbol returns. A missing or malformed ownership contract is blocking.

### R3. Rust safety boundary

The audit must fail on first-party unsafe Rust or unexpected network-capable code outside the authenticated local resident transport. Native runtime discovery must remain package-bound, with no PATH search or runtime download.

### R4. Security and DX coverage ratchet

The current test inventory is the minimum floor for:

- native runtime and resident lifecycle;
- command extensions, command patterns, and PreToolUse parsing;
- package firewall, package shims, manifests, lockfiles, archives, and supply-chain scanning;
- path, filesystem, symlink, hashing, and integrity checks;
- secrets, prompt injection, destructive operations, tampering, approvals, and policy;
- installed wheels, packaging, publication, SBOM, provenance, and artifacts.

A reduction requires an explicit baseline update in the same reviewed change.

### R5. Umbrella regression runner

A cross-platform runner must discover and execute the retained P0-P2 test files without hard-coding a stale list. Pull requests run the normal corpus; scheduled CI runs the expanded corpus.

### R6. Privacy

Reports contain only stable codes, counts, relative paths, and digests. They never include file contents, raw commands, prompts, output, paths outside the repository, secrets, environment values, tokens, proofs, or exception text.

## Acceptance criteria

- The permanent audit reports zero blocking findings on the exact reviewed tree.
- Rust formatting, Clippy with warnings denied, and all Rust workspace tests pass.
- The complete discovered migration/security regression corpus passes.
- Existing extension and command-pattern suites remain present at or above the ratcheted count.
- Package-shim and supply-chain suites remain present at or above the ratcheted count.
- No retired Python evaluator is present.
- No temporary migration asset remains.
- Existing CodeQL, security, fuzz, wheel, and publication workflow families remain present.
- `release/3.0` remains separate from `main`.
