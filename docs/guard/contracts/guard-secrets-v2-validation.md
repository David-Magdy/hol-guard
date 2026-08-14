# HOL Guard Secrets V2 validation boundary

This document records the executable release boundary for the versioned Secrets contracts.

A public parity claim is denied unless the checked-in capability policy enables it and every required capability has exact release-commit evidence at or above the declared minimum state. The release preflight loads the dependency-free contract module directly, validates the capability, product-boundary, source-capability, and reason-code manifests, and records the successful gate command digest and source commit in the release toolchain SBOM.

Coverage is fail-closed. Clean is invalid when work is partial, degraded, truncated, skipped, errored, has no requested references, or has not completed every requested reference. Serializable evidence rejects raw credentials, raw values, source content, prompts, tool output, authorization material, provider response bodies, and absolute local paths.

The authoritative checks are the focused V2 contract and release-gate tests, the release-toolchain tests, Ruff, basedpyright, the test-suite ratchet, Security Gates, CodeQL, cross-platform tests, and the protected publish preflight on the exact pull-request head.
