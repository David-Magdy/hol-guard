# HOL Guard Secrets V2 final validation requirements

The exact pull-request head must pass the protected release preflight before dependency installation, the focused V2 contract and claim-gate tests, the release-toolchain tests, Ruff, basedpyright, the test-suite ratchet, Security Gates, CodeQL, cross-platform tests, and package build checks.

The contract is fail-closed for skipped work, truncation, degradation, errors, empty requested-reference sets, and incomplete requested-reference coverage. None of those states may produce a clean outcome. Raw-value key spellings and all other prohibited sensitive payload fields are rejected recursively before serialization.

Public parity remains disabled unless the checked-in claim policy explicitly enables it and exact release-commit evidence satisfies every required capability at the declared minimum state.
