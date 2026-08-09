# Security boundary

The Claude plugin is a distribution and setup surface. It is not the enforcement engine.

The `hol-guard` package owns:

- Claude Code native hook installation and repair
- pre-tool policy decisions
- package, skill, plugin, MCP, prompt-injection, secret, and command-risk evaluation
- approval handling
- local receipts and optional cloud synchronization

This separation prevents the marketplace package and the core runtime from drifting into two different policy implementations.
