# OWASP Agentic Skills Top 10 mapping

HOL Guard maintains a conservative reference mapping between selected scanner
findings and the OWASP Agentic Skills Top 10 (AST10).

This integration is **not** an OWASP compliance, certification, endorsement, or
coverage claim. Scanner evidence and standards associations are intentionally
kept separate.

## Pinned source

The mapping is based on the OWASP `www-project-agentic-skills-top-10` repository:

- Version label: `1.0 (2026 Edition)`
- Pinned revision: `9faab9ae8d1f0dd132603264a50a679f94b6e955`
- Source document: `top10.md`

A source update must be reviewed before the pinned revision or mappings change.

## Risk catalog

| ID | Risk |
| --- | --- |
| AST01 | Malicious Skills |
| AST02 | Supply Chain Compromise |
| AST03 | Over-Privileged Skills |
| AST04 | Insecure Metadata |
| AST05 | Untrusted External Instructions |
| AST06 | Weak Isolation |
| AST07 | Update Drift |
| AST08 | Poor Scanning |
| AST09 | No Governance |
| AST10 | Cross-Platform Reuse |

## Initial rule mappings

The first version intentionally maps only scanner rules with a narrow, reviewable
association:

| HOL Guard rule | AST10 association | Rationale |
| --- | --- | --- |
| `SECURITY_MD_MISSING` | AST09 | Missing security-reporting guidance is a governance gap. |
| `RISKY_APPROVAL_DEFAULT` | AST03, AST06 | Default approval bypass or unrestricted sandboxing increases privilege and weakens isolation. |

All other rules return `unmapped`. `unmapped` means only that HOL Guard has not
encoded a conservative AST10 association for that rule. It does not lower the
finding's HOL Guard severity or importance.

## Evidence model

`codex_plugin_scanner.standards.owasp_agentic_skills.evidence_record()` emits two
independent dimensions:

1. `finding.state`: `detected`, `not_detected`, or `not_tested`.
2. `mapping.status`: `mapped` or `unmapped`, with zero or more AST10 risks.

This separation prevents statements such as "AST03 passed" when HOL Guard only
observed one scanner signal associated with AST03.

Example:

```json
{
  "schema": "hol.guard.owasp-agentic-skills.v1",
  "finding": {
    "rule_id": "SECURITY_MD_MISSING",
    "state": "detected"
  },
  "mapping": {
    "status": "mapped",
    "risks": [
      {"id": "AST09", "name": "No Governance"}
    ]
  }
}
```

The actual payload also includes the pinned source revision and a disclaimer.

## Maintenance rules

- Never change a scanner verdict because of an AST10 mapping.
- Never infer coverage from a missing finding.
- Never map a new HOL Guard rule from its name alone; review the detection
  semantics and the pinned OWASP risk text.
- Keep MCP-protocol-only findings `unmapped` unless the same rule also applies to
  an agentic skill boundary documented by AST10.
- Treat OWASP source changes as data migrations: pin a new revision, review the
  risk names/semantics, update tests, and record the change.
- Public upstream feedback follows the contribution channel requested by the
  OWASP project for the active publication cycle.
