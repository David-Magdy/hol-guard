# Extension Control Center

The Extension Control Center is the local dashboard surface for inspecting canonical command extensions, permissions, and stable detector rules.

Control semantics, precedence, migration rules, and non-goals are defined in [ADR 0004](adr/0004-extension-control-center-semantics.md). The daemon registry and protected extension-control authority remain the source of truth; the dashboard does not maintain a parallel policy registry.

## Batch 1 routes

- `/extensions` — extension overview
- `/extensions/:extensionId` — canonical detail route
- safe query state: `tab`, `q`, `risk`, `state`, `configurable`, `source`, `deprecated`, `type`, `sort`, and `rule`

Only allowlisted, bounded view state belongs in the URL. Dashboard sessions, approval secrets, proof IDs, command text, and local paths do not.

Batch 1 provides read-only canonical drill-down below the existing broad extension capability control. Permission mutation, scoped rule treatment, simulation, activity, and rollback are introduced only in their gated implementation batches.
