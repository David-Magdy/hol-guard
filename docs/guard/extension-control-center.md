# Extension Control Center

The Extension Control Center is the canonical local security subsystem behind the user-facing **Protection Center**. The product UI describes extensions as protection modules and defaults to local status, what Guard protects, why a decision happened, and the next safe action. Canonical extension IDs, permission IDs, detector rules, authority health, provenance, and digests remain available through Advanced and Developer disclosure.

Control semantics, precedence, migration rules, and non-goals are defined in [ADR 0004](adr/0004-extension-control-center-semantics.md). The daemon registry and protected extension-control authority remain the source of truth; the dashboard does not maintain a parallel policy registry.

## Routes

- `/extensions` — Protection Center overview
- `/extensions/:extensionId` — canonical protection-module detail route
- legacy allowlisted detail/query state remains compatible where supported

Only bounded view state belongs in the URL. Dashboard sessions, approval secrets, proof IDs, command text, and local paths do not.

## Protection settings

The friendly settings UI is a presentation layer over the canonical extension-control resolver. It does not introduce a second policy language.

- **Use recommended** maps to the canonical inherited local state.
- **Block matching actions** adds a local block.
- **Allow when Guard would otherwise permit** adds a local allow only where immutable detector and organization minimums still permit it.
- **Recommended**, **Balanced**, and **Strict local** are local draft presets. They do not apply until the user reviews the server-computed outcome and authenticates the exact mutation.
- Organization-managed blocks, required protections, immutable detector severity, and minimum protection floors cannot be weakened locally.
- Emergency Lockdown remains dominant.

Every settings mutation is previewed server-side from the current registry, dependencies, organization policy, and authority revision. The apply operation requires the exact one-use proof bound to that reviewed change. Stale revisions or catalogs require a new review rather than a silent rebase.

## Presentation model

Protection Center uses three presentation densities over the same enforcement contracts:

- **Simple** — local status, protection areas, modules in use, recommended protections, recent redacted decisions, and safe next actions.
- **Advanced** — troubleshooting, protection settings, rule/capability explanations, and explicit local configuration.
- **Developer** — canonical IDs, rule metadata, provenance layers, digests, and implementation details for debugging or integrations.

Changing presentation density never changes policy or daemon requests.

## Local and Cloud boundary

Local Guard remains the enforcement authority on the device. Local interception, policy evaluation, approvals, local receipts, recovery, Test Lab evaluation, and current-device protection do not depend on a paid Cloud plan. Guard Cloud adds continuity, synchronization, durable history, advanced evidence/search, and team or organization coordination without redefining whether the local device is protected.
