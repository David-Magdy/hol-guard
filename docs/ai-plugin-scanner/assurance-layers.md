# AI Plugin Scanner layered assurance

The scanner does not use a single green **safe** result. It produces independent evidence for the security questions that can actually be tested.

## Evidence layers

| Layer | What is tested | Strongest valid claim | Important limitation |
| --- | --- | --- | --- |
| Static adversarial analysis | Source, manifests, skills, MCP configuration, package scripts, encoded content, cross-signal correlations | Supported content was inspected under the reported budgets and rules | Static analysis cannot prove runtime behavior or absence of every vulnerability |
| Archive safety | ZIP and TAR entry paths, links, encryption, nesting, entry count, expanded size, compression ratio | Supported archives were enumerated without extracting them to the host | Encrypted, unsupported, over-budget, or deeply nested content remains partial |
| Native and WebAssembly | Magic/header structure, platform hardening metadata, complete hashes, bounded ASCII and UTF-16 strings, sensitive capability classes | The scanner identified supported executable formats and review-relevant indicators | Header and string analysis is not full disassembly, decompilation, or proof of behavior |
| Publisher provenance | Exact artifact digest, DSSE envelope, in-toto subject binding, Ed25519 signature, consumer-controlled trust root | The exact artifact was signed by a key trusted by the consumer | A self-contained signature proves integrity, not publisher identity |
| Bounded runtime assurance | Immutable OCI image, no network, read-only target/root, dropped capabilities, non-root user, resource bounds, syscall trace | The exact artifact was observed under the recorded containment and trace coverage | A partial or missing trace cannot support a complete runtime claim |

Each layer reports its own status, analyzer, coverage percentage, evidence digest, findings, and limitations. `complete` means the supported procedure finished. It does not mean the artifact is universally safe. `verified` is reserved for cryptographically or operationally verified claims.

## Rust acceleration

`rust/scanner-kernel` accelerates deterministic traversal, streaming SHA-256, executable-format recognition, platform hardening extraction, and bounded string classification. The Python bridge validates the Rust protocol before accepting results. Malformed, unordered, unsafe, or root-mismatched output is rejected. A deterministic Python implementation remains available for platforms without the kernel.

The Rust kernel never executes target files and never returns their contents. It emits paths, sizes, hashes, format metadata, hardening markers, and capability classes only.

## Runtime detonation

Runtime execution is never part of a normal scan. Operators must explicitly invoke:

```text
plugin-scanner-assure detonate ./extension \
  --engine docker \
  --image registry.example.com/hol/guard-detonator@sha256:<digest> \
  --evidence-dir /secure/output \
  --trace \
  -- python plugin.py
```

The command rejects mutable image tags. It disables networking, mounts the extension read-only, uses a read-only container root, drops every Linux capability, enables `no-new-privileges`, runs as UID/GID 65534, sets process, memory, CPU, file-size, and file-descriptor limits, and writes evidence only to a separate mount. A runtime layer is `verified` only when all mandatory controls and complete syscall traces are present and the evidence target digest matches the current artifact.

## Provenance trust

An embedded public key can prove that an attestation was not modified after signing, but an attacker can generate both the key and signature. The scanner therefore reports a valid embedded-key envelope as `self-attested`. It reports `verified` only when the key ID exists in a consumer-controlled trusted keyring supplied outside the extension.

## Cloud and registry ingestion

`extension-security-evidence.v2` is canonical, digest-bound, bounded to 2 MiB, and privacy-reduced. Uploads require a credential-free HTTPS endpoint, reject redirects, use an idempotency key equal to the evidence digest, cap the response body, and never forward a bearer token to another origin.

An ingestion service should additionally enforce tenant authentication, replay-safe idempotency, schema validation, digest uniqueness, artifact-to-evidence binding, retention, immutable audit history, and authorization on every read. Registry UI should render layer status separately and must not translate `complete` into `safe`.

## Quality gates

The CI gate runs:

- Rust formatting, Clippy, unit tests, and release build.
- Python compilation and focused assurance tests.
- A common-vector malicious corpus and hard-negative corpus.
- Precision, recall, F1, and median-latency thresholds.
- Archive traversal, links, bombs, nested archives, and no-host-extraction tests.
- Native-format and sensitive-capability tests.
- DSSE trusted versus self-attested identity tests.
- OCI sandbox-control and runtime-evidence completeness tests.
- Determinism, secret non-disclosure, symlink escape, invalid UTF-8, and coverage-limit tests.

The corpus is a regression floor, not a statement that every attack is represented forever. New real-world evasions should be converted into minimized permanent fixtures.
