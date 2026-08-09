# HOL Guarded Repository Action

This composite GitHub Action runs the current HOL Guard scanner against a repository, emits SARIF, creates a sanitized scan-evidence artifact, and asks GitHub to produce signed provenance for that artifact.

If verification registration is enabled, the action also sends the sanitized evidence to the HOL Guard verifier together with a short-lived GitHub OIDC token bound to the evidence digest. The verifier can then issue an expiring public badge or keep the evidence private.

## What “Guarded Repository” means

> Guarded Repository means this commit completed a versioned HOL Guard repository scan under the recorded configuration and produced a GitHub-signed provenance attestation. It does not mean vulnerability-free and does not prove runtime protection.

Do not shorten this into “secure repository,” “Guard-protected repository,” or any claim that a repository scan proves local runtime enforcement.

## Caller permissions

Minimum permissions when SARIF upload is disabled:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
```

If `upload_sarif: true`, also grant:

```yaml
  security-events: write
```

No repository write permission, issue permission, pull-request permission, package permission, or long-lived signing secret is required.

## Example

Pin the action to a reviewed HOL Guard commit or immutable release ref in production.

```yaml
- name: Guard repository scan and attestation
  id: guard
  uses: hashgraph-online/hol-guard/guarded-repository@FULL_COMMIT_SHA
  with:
    profile: strict-security
    fail_on_severity: critical
    upload_sarif: true
    visibility: public

- name: Show verification URL
  if: steps.guard.outputs.verification_status == 'verified'
  run: echo "${{ steps.guard.outputs.verification_url }}"
```

## Outputs

The action exposes scanner score/grade/severity/counts, the SARIF path, the sanitized evidence path and digest, the GitHub attestation URL, and the HOL Guard verification/badge URLs when registration succeeds.

The portal evidence payload intentionally does not contain scanner findings, file paths, repository source content, prompts, commands, credentials, actor identity, or private workflow inputs.

## Public and private evidence

- `visibility: private` records verification without creating a public badge or public evidence page.
- `visibility: public` allows the verifier to expose the sanitized scan metadata and an expiring verification badge.
- The GitHub artifact attestation binds the sanitized evidence file digest to the GitHub Actions identity that produced it. It does not upload the repository source code to HOL.

## Expiry and renewal

A badge represents one commit and one scan. The HOL verifier assigns a bounded expiry. Run the action again on a newer commit to create a fresh verification; do not treat an expired badge as current evidence.
