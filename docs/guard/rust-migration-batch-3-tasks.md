# Rust Authority Migration Batch 3: Tasks T201-T220

Base branch: `main`

Invariant: the completed Rust authority migration is permanently enforced by source ownership gates, real-binary integration, release packaging checks, documentation, and repository hygiene.

- [ ] T201 Rebase the final batch onto merged authority batches 1 and 2.
- [ ] T202 Add a canonical Rust authority ownership manifest.
- [ ] T203 Add a source gate rejecting Python PreToolUse semantic evaluation.
- [ ] T204 Add a source gate rejecting supported PostToolUse Python fallback.
- [ ] T205 Add a source gate rejecting strict-mode terminology and configuration.
- [ ] T206 Add a source gate requiring native policy snapshot activation.
- [ ] T207 Add a source gate requiring bundled runtime identity verification.
- [ ] T208 Add an always-on workflow covering every production Guard runtime path.
- [ ] T209 Expand CI triggers across adapters, daemon, runtime, policy, store, and packaging.
- [ ] T210 Run compiled PreToolUse real-binary integration in the ownership workflow.
- [ ] T211 Run compiled PostToolUse real-binary integration in the ownership workflow.
- [ ] T212 Run resident differential and mutation integration in the ownership workflow.
- [ ] T213 Run native release performance gates in the ownership workflow.
- [ ] T214 Run installed native-wheel execution proof.
- [ ] T215 Update the all-harness architecture documentation to Rust authority.
- [ ] T216 Update the harness support documentation to remove legacy Python authority claims.
- [ ] T217 Remove temporary migration workflows, probes, and delivery residue.
- [ ] T218 Run local integration tests against the exact pull-request head.
- [ ] T219 Address every actionable review comment and resolve every review thread.
- [ ] T220 Merge only after CI/CD, Security Gates, CodeQL, adversarial review, and release proof pass.
