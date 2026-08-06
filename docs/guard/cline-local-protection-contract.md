# Cline local protection contract

HOL Guard can protect Cline through native file hooks and Cline's AgentPlugin runtime. The adapter uses the same Guard policy engine, approval center, receipts, MCP firewall, and local daemon as every other supported harness.

## Supported Cline surfaces

| Surface | Guard transport | Protection level |
| --- | --- | --- |
| Cline CLI / Core | AgentPlugin when available | Pre-tool blocking plus post-tool output mediation |
| Cline VS Code | Native Cline hooks by default | Pre-tool blocking; post-tool observation |
| Cline JetBrains | Detection only until a live pre-tool proof is recorded | Unverified |
| Cline MCP servers | Guard MCP proxy for eligible local stdio servers | MCP request/tool policy |

Cline plugin support is selected automatically for CLI-only installations. IDE installations default to native hooks because that is the broadest documented compatibility boundary. Guard never marks a transport fully active from file presence alone: runtime proof must be observed.

## Install

```bash
hol-guard apps connect cline
```

The default `auto` behavior selects one enforcement transport and may also install the Guard Cline launcher plus MCP protection where applicable. Guard does not intentionally run both managed Cline enforcement transports once the selected transport has live proof.

Useful aliases are `cline`, `cline-cli`, and `cline-vscode`.

## Native hook behavior

Guard installs global Cline hooks under Cline's supported global hooks directory. On macOS and Linux the hooks use canonical extensionless executable names. On Windows the adapter installs canonical PowerShell hook files that delegate to an isolated Guard-owned Python worker.

`PreToolUse` is the enforcement boundary. It evaluates the requested action before Cline executes it. If Guard is unavailable, times out, receives malformed input, receives contradictory typed/compatibility payloads, or cannot safely classify an action-bearing tool call, the bridge returns a Cline cancellation response rather than silently allowing the action.

Cline's `run_commands` tool can contain multiple independent commands. Guard evaluates those commands independently. It does not concatenate them into invented shell syntax.

`PostToolUse` native hooks are observation-only. They can record evidence and add context for a future model turn, but they do not provide a reliable model-visible output replacement boundary.

## AgentPlugin behavior

The managed Cline plugin uses Cline's typed runtime hooks:

- `beforeTool` sends the exact action to Guard and returns a skip result when Guard blocks it or evaluation cannot complete safely.
- `afterTool` sends the result to Guard. A blocked or unreviewable result is replaced with an error result before it can continue through the plugin-mediated runtime path.
- Safe reviewed output may replace the original output when Guard returns a reviewed replacement.
- The original tool metadata is preserved when output is replaced.

The plugin is installed as a normal Cline plugin package under Cline's global plugin directory and contains no separate policy engine.

## Runtime proof

Guard records separate, bounded proof records for:

- native `PreToolUse`
- native `PostToolUse`
- plugin load
- plugin `beforeTool`
- plugin `afterTool`

Synthetic installation canaries prove only the generated bridge contract. They do not count as live Cline runtime proof. A protection status becomes ready only after the required live proof has been observed and the managed files still match their recorded integrity digests.

Run:

```bash
hol-guard apps test cline
```

If proof is missing or stale, run a safe Cline tool action and test again.

## MCP protection

Guard discovers Cline MCP settings from current Cline settings locations and recognized legacy IDE storage locations. Eligible local stdio servers are routed through Guard's existing MCP proxy. Remote HTTP servers are preserved rather than rewritten by this adapter.

Before changing an MCP settings file, Guard stores the exact original text in its managed state. Disconnect restores that text only when the current settings file still matches the Guard-managed version. If the user edited the file after Guard changed it, Guard retains the file and reports that manual reconciliation is required instead of overwriting the user's changes.

## Non-destructive behavior

Guard does not overwrite user-owned Cline hooks or plugins. If Cline's canonical hook slot is already occupied by an unmanaged hook on a surface where the host supports only one hook in that slot, installation stops and reports the conflict.

Managed Cline hook, plugin, and MCP files are integrity-bound. Modified or replaced managed files are reported as broken protection and are not silently trusted.

## Known boundaries

- Native Cline `PostToolUse` does not provide post-tool output replacement. Use the plugin transport for that guarantee.
- JetBrains is not reported as protected until its live integration behavior is proven.
- Cline itself can change hook/plugin schemas between releases. Guard therefore keeps current and compatibility payload handling explicit and rejects contradictory security-relevant fields.
- Protection applies to Cline actions that cross a supported hook, plugin, launcher, package, or MCP boundary. Actions outside those boundaries cannot be represented as protected without runtime evidence.
