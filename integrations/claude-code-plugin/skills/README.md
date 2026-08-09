# Skills

- `setup`: explicit, user-invoked installation/initialization workflow for the `hol-guard` package.
- `status`: read-only verification of Guard CLI and local protection state.

Both skills disable model-initiated invocation so the plugin cannot install software or change Guard state just because Claude thinks security setup might be useful.
