# HOL Guard Rust P0-P2 regression remediation TODO

Target: `release/3.0`

- [x] Remove obsolete `.github/rust-required-*` transfer payloads.
- [x] Remove temporary Rust apply/export/transfer workflows from the release tree.
- [x] Add a permanent test that rejects temporary migration residue.
- [x] Load and enforce the Rust/Python ownership contract.
- [x] Reject the return of retired Python files and symbols.
- [x] Reject first-party unsafe Rust.
- [x] Reject unexpected native network capability outside the authenticated local resident transport.
- [x] Reject PATH-based or downloaded runtime selection.
- [x] Inventory native-runtime tests.
- [x] Inventory command-extension and command-pattern tests.
- [x] Inventory package-firewall, package-shim, manifest, lockfile, archive, and supply-chain tests.
- [x] Inventory filesystem, path, hashing, symlink, and integrity tests.
- [x] Inventory secrets, prompt injection, destructive action, tampering, approval, and policy tests.
- [x] Inventory installed-wheel, packaging, publication, SBOM, provenance, and artifact tests.
- [x] Commit the current category counts as a no-decrease baseline.
- [x] Ratchet the current command/extension source-module inventory.
- [x] Ratchet the current ownership-contract inventory.
- [x] Add a cross-platform migration regression runner.
- [x] Add pull-request and scheduled GitHub Actions coverage.
- [x] Keep audit output aggregate-only and repository-relative.
- [x] Add adversarial tests for temporary assets, retired Python symbols, unsafe Rust, coverage removal, and report privacy.
- [x] Preserve existing policy actions, approval floors, reason codes, extensions, and command patterns.
- [x] Preserve Rust-required fail-closed behavior without a Python evaluator fallback.
- [x] Keep the remediation isolated to `release/3.0`.
