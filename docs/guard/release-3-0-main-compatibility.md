# `main` to `release/3.0` compatibility matrix

## Pinned inputs

| Ref | Commit |
| --- | --- |
| `origin/main` | `8810399a8004ec4be3e448487ee03fe6be59e67f` |
| PR #1901 starting head (`release/3.1`) | `62b95808a2a2d79970053ab7d428031fca503efa` |
| merge base | `8810399a8004ec4be3e448487ee03fe6be59e67f` |

The pinned `main` commit is already an ancestor of the PR starting head: zero main-only commits and 282 release-only commits. The required ancestry merge is therefore already represented without a conflict resolution or synthetic merge commit. The release-only product identity is migrated semantically from 3.1 to 3.0 in PR #1901.

## Strategy

Preserve the PR starting head, apply the 3.0 identity cutover as a focused commit, and verify the affected release, compatibility, MDM, and security contracts. GitHub CI owns exhaustive suite validation.

## Current result

- No `main`-only commit requires forward-porting at the pinned inputs.
- The PR head already contains the pinned `main` history.
- The release identity cutover changes only product-release semantics; dependency versions remain unchanged.
- The 3.0 train remains alpha-only and publication still requires the protected branch, exact expected SHA, and workflow gates.

## Contract preservation

- Keep policy, receipt, runtime-session, protection, approval, extension-control, attestation, daemon/tray, Cloud sync, and dashboard contracts.
- Do not broaden containment eligibility or reinterpret isolation as approval.
- Harnesses that cannot enforce authenticated local decisions remain degraded or unsupported for mandatory assurance.
- See `release-3-0-compatibility-evidence.md` for focused compatibility proof.

## Verification gates

Run focused tests for every changed subsystem, then lint and packaging checks. GitHub CI owns exhaustive suite validation through the PR review loop. No release, publication, deployment, or policy activation is authorized by this document.
