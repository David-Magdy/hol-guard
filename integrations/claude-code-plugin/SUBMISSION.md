# Claude community marketplace submission

Use Anthropic's documented plugin submission form after this package passes local validation.

Submission source:

- Repository: `https://github.com/hashgraph-online/hol-guard`
- Plugin path: `integrations/claude-code-plugin`
- Plugin name: `hol-guard`
- License: Apache-2.0
- Homepage: `https://hol.org/guard`

Pre-submit checks:

```bash
claude plugin validate ./integrations/claude-code-plugin --strict
pytest -q tests/test_claude_code_marketplace_plugin.py
```

Review notes:

- The plugin does not auto-install software or silently mutate Claude Code settings.
- `/hol-guard:setup` is manual-only and requests user approval before installing `hol-guard` via the documented `pipx` path.
- The actual runtime integration remains in the core HOL Guard package and is installed by `hol-guard init`.
- Local protection does not require Guard Cloud.

External adoption starts only after Anthropic accepts the plugin into a public Claude marketplace. An internal HOL Guard commit or PR is not adoption.
