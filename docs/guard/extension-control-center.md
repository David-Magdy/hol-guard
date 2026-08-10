# Extension Control Center

The Extension Control Center is the canonical local security subsystem behind the user-facing **Protection Center**. The product UI describes extensions as protection modules and starts with local protection status, what needs attention, and the next safe action. Canonical extension IDs, permission IDs, detector rules, authority health, and provenance remain available through Advanced and Developer disclosure without becoming the default mental model.

Control semantics, precedence, migration rules, and non-goals are defined in [ADR 0004](adr/0004-extension-control-center-semantics.md). The daemon registry and protected extension-control authority remain the source of truth; the dashboard does not maintain a parallel policy registry.

## Routes

- `/extensions` — Protection Center overview
- `/extensions/:extensionId` — canonical protection-module detail route
- legacy allowlisted detail/query state remains compatible where supported

Only bounded view state belongs in the URL. Dashboard sessions, approval secrets, proof IDs, command text, and local paths do not.

## Presentation model

Protection Center uses three presentation densities over the same canonical data and enforcement contracts:

- **Simple** — local status, protection areas, modules in use, recommended protections, recent redacted decisions, and safe next actions.
- **Advanced** — troubleshooting, explicit protection controls, rule/capability explanations, and local policy configuration.
- **Developer** — canonical IDs, rule metadata, provenance layers, digests, and other implementation details needed for debugging or integration work.

Changing presentation density never changes policy or daemon requests.

## Local and Cloud boundary

Local Guard remains the enforcement authority on the device. Local interception, policy evaluation, approvals, local receipts, recovery, Test Lab evaluation, and current-device protection do not depend on a paid Cloud plan. Guard Cloud adds continuity, synchronization, durable history, advanced evidence/search, and team or organization coordination without redefining whether the local device is protected.

## Safety invariants

- detector severity and minimum protection floors are immutable from the dashboard
- local settings cannot weaken signed organization blocks
- Emergency Lockdown remains dominant
- authority failures remain fail-closed
- mutations use server-side preview plus an exact one-use approval proof
- stale revisions or catalogs must be reviewed again rather than silently rebased
- command text and local paths are never placed in URLs or Cloud marketing telemetry
