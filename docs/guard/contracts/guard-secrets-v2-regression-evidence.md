# HOL Guard Secrets V2 false-clean regression evidence

The V2 coverage contract rejects a clean result when any requested work is missing or ambiguous. The exact pull-request head is required to prove all of the following through executable tests:

- raw-value field spellings are rejected at direct and nested serialization boundaries;
- skipped work requires an explicit partial result and cannot be clean;
- an empty requested-reference set requires an explicit partial result and cannot be clean;
- non-partial coverage must complete every requested reference;
- truncation, degradation, scanner errors, and incomplete reference coverage remain fail-closed;
- the dependency-free release preflight validates all authoritative manifests before dependency installation and records the successful gate digest and exact source commit in the release toolchain SBOM.

This document contains no raw credentials, source excerpts, local absolute paths, prompts, tool output, provider response bodies, or authorization material.
