# Canary Commons

Canary Commons is a public, synthetic, defanged evaluation corpus for AI-agent security surfaces. It is designed for repeatable testing and research, not exploit delivery.

`corpus.v1.json` is the reviewed compact source. `export.py` deterministically expands it into exactly 100 `canary-commons/v1` cases:

- 25 documentation cases
- 20 pull-request and issue cases
- 20 MCP cases
- 15 skill cases
- 10 package/install cases
- 10 memory/workspace cases

The split is stratified by category: 80 train and 20 held-out cases. Held-out labels remain published because this is a transparent evaluation corpus, not a secret benchmark. Consumers that need blind evaluation should copy the held-out inputs into an access-controlled benchmark process before training or tuning against them.

Every case contains an expected `allow`, `review`, or `block` outcome, a reason code, a benchmark-family mapping, explicit limitations, and safety flags. Examples use placeholders, `.invalid` domains, `hxxps://` defanging, synthetic secrets, and non-executable test strings.

## Generate JSONL

```bash
python canary-commons/export.py
```

The exporter writes `canary-commons/cases.v1.jsonl` deterministically from the reviewed source file.

## Safety boundary

Cases must not contain live credentials, live malicious infrastructure, weaponized payloads, runnable destructive scripts, doxxing/PII, or instructions whose value depends on actually compromising a system. A case may contain a dangerous-looking string only when it is clearly synthetic/defanged and the corpus marks `executable=false`.

Expected outcomes are test-policy expectations for the exact excerpt. They are not claims that all semantically related attacks should receive the same product decision in every harness or policy.

## Benchmark mapping

`benchmark_family` provides a stable family label that external benchmark runners can map into their own scenario IDs. Canary Commons does not claim that a benchmark run happened merely because a case has mapping metadata.

See `CONTRIBUTING.md` for the reviewed contribution and safety process.
