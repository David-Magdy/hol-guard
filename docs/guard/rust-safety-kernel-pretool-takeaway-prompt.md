# Takeaway Prompt: Complete the HOL Guard Rust Safety Kernel 3.0 Program

Complete `docs/guard/rust-safety-kernel-pretool-prd.md`, `docs/guard/rust-safety-kernel-pretool-todo.md`, and every remaining item in `docs/guard/rust-runtime-hardening-todo.md` in `hashgraph-online/hol-guard`.

Work from the latest `release/3.0`, target reviewed work only to `release/3.0`, and never merge that branch into `main`.

HOL Guard remains a Python package. Rust is the resident deterministic data plane for strict decoding, bounded command and structured tool-call normalization, exactness, effect analysis, path classification, and native action and approval floors. Python remains the control plane for harness compatibility, policy administration, approvals, exceptions, receipts, durable workflow state, cloud and MDM synchronization, CLI/dashboard/Desktop presentation, diagnosis, repair, and named unsupported-platform and emergency rollback paths.

Always combine native and Python decisions using the more restrictive action and approval requirement. An authenticated native restrictive result cannot be weakened. Native positive authority is limited to exact, fully identity-bound, release-gated requests. Unsupported, ambiguous, malformed, overloaded, timed-out, unauthenticated, incompatible, crashed, or mismatched native analysis must follow the fail-safe matrix and never become a silent positive result.

Finish protocol v2, supervision, PreToolUse models for supported shells and tool families, the privacy-safe effect model, non-downgradable action and approval floors, Tier 1 installed-wheel qualification, status and doctor commands, repair, rollback controls, Python hot-path cleanup, dependency and artifact verification, fuzz, mixed-load and recovery tests, a 100,000-request leak-free soak, performance gates, and independent review.

Required release thresholds include complete approved high-impact coverage with zero unsafe downgrade, exact safe-corpus false pause below 0.5%, warm native PreToolUse p95 at most 10 ms and p99 at most 25 ms, cold p95 at most 100 ms, resident readiness at most 250 ms, and at least 2x adapter-to-decision p95 improvement for exact modeled requests.

Use synthetic fixtures for sensitive cases and ensure hook inputs and policy material never appear in durable outputs or uploaded artifacts. Every fallback must be named, reachable, and exercised in CI.

Inspect the current repository before editing. Reconcile useful prior Rust branches without copying stale files over newer release changes. Implement in reviewable dependency-ordered batches, run focused tests during development, run the complete exact-head matrix before merge, resolve every review and CI failure without weakening gates, merge only into `release/3.0`, and publish a signed alpha whose tag and all artifacts bind to the exact merge commit. Continue until both Rust TODOs are truthfully complete and the published alpha is independently installed and verified.
