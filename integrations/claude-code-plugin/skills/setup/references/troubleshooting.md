# Setup troubleshooting

If `pipx` is not installed, stop rather than selecting another package manager automatically. Point the user to the HOL Guard install documentation at https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/get-started.md.

If `hol-guard init` reports degraded Claude Code protection, use `hol-guard status` to identify the failed layer. Do not edit Claude settings by hand from this plugin unless the core HOL Guard documentation explicitly instructs that repair path.
