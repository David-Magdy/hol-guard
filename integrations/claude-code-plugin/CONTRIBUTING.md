# Contributing

Keep this package thin.

- Do not duplicate HOL Guard runtime scanning, policy, approval, or receipt logic here.
- Runtime protection belongs in the `hol-guard` package and its Claude Code adapter.
- This directory should contain only Claude plugin metadata, setup/management skills, and marketplace-specific documentation needed to distribute the existing Guard integration.
- Any security claim must be backed by `hol-guard status` or the core harness support contract, not by presence of this plugin alone.
