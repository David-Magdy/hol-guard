# HOL Guarded Repository

HOL Guarded Repository runs the current HOL Guard scanner against a repository, emits SARIF, creates sanitized scan evidence, and asks GitHub to produce signed provenance for that evidence.

Public or private verification at `hol.org` is available only through the trusted reusable workflow in `.github/workflows/guarded-repository.yml`. That lets the verifier require GitHub's `job_workflow_ref` claim for the HOL-owned workflow instead of trusting any caller-controlled workflow.

## What “Guarded Repository” means

> Guarded Repository means this commit completed a versioned HOL Guard repository scan under the recorded configuration and produced a GitHub-signed provenance attestation. It does not mean vulnerability-free and does not prove runtime protection.

Do not shorten this into “secure repository,” “Guard-protected repository,” or any claim that a repository scan proves local runtime enforcement.

## Recommended usage

Call the reusable workflow. During the 3.0 alpha cycle, `release/3.0` is the supported workflow ref. Pin an immutable reviewed release or commit when one is available for production use.

```yaml
name: Guarded Repository

on:
  push:
  pull_request:

jobs:
  guard:
    permissions:
      contents: read
      id-token: write
      attestations: write
      security-events: write
    uses: hashgraph-online/hol-guard/.github/workflows/guarded-repository.yml@release/3.0
    with:
      profile: strict-security
      fail_on_severity: critical
      upload_sarif: true
      visibility: public
```

The reusable workflow checks out the caller repository with credentials disabled, runs the scanner, optionally uploads SARIF, creates GitHub provenance for the sanitized evidence file, then requests an OIDC token whose audience is bound to that evidence digest before registration.

## Caller permissions

The trusted reusable workflow requires:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  security-events: write
```

`security-events: write` is used only for the optional SARIF upload step. No repository-content write permission, issue permission, pull-request permission, package permission, or long-lived signing secret is required.

## Direct composite-action usage

`guarded-repository/action.yml` remains reusable for scan + SARIF + GitHub provenance without portal registration. Its `register_verification` input defaults to `false`.

Do not enable portal registration from a direct caller workflow. The verifier intentionally requires the HOL Guard reusable workflow identity and rejects arbitrary caller workflows even when their GitHub OIDC token is otherwise valid.

## Outputs

The workflow exposes scanner score and grade plus the HOL Guard verification and badge URLs when registration succeeds. The composite action additionally exposes severity/counts, the SARIF path, sanitized evidence path and digest, and GitHub attestation URL.

The portal evidence payload intentionally does not contain scanner findings, file paths, repository source content, prompts, commands, credentials, actor identity, or private workflow inputs.

## Public and private evidence

- `visibility: private` records verification without creating a public badge or public evidence page.
- `visibility: public` exposes only sanitized scan metadata and an expiring verification badge.
- The GitHub provenance attestation covers the sanitized evidence file, not the repository source archive.

## Expiry and renewal

A verification represents one commit and one scan. The HOL verifier expires it seven days after the scan evidence was generated. Run the workflow again on a newer commit to create a fresh verification; do not treat an expired badge as current evidence.
