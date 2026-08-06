"""Runtime registration for the Cline harness protection contract."""

from __future__ import annotations

from . import contracts

CLINE_CONTRACT = contracts.HarnessProtectionContract(
    harness="cline",
    install_aliases=("cline", "cline-cli", "cline-vscode"),
    config_paths=(
        "~/.cline/hooks/",
        "~/.cline/plugins/",
        "~/.cline/data/settings/cline_mcp_settings.json",
        "~/.cline/settings/cline_mcp_settings.json",
        "~/Documents/Cline/Hooks/",
        "~/Documents/Cline/Plugins/",
    ),
    event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "file_write", "tool_result", "network_request"),
    native_approval=False,
    browser_fallback=True,
    resume_support=False,
    known_blind_spots=(
        "Native Cline PostToolUse hooks are observation-only and cannot replace a result already returned to the model; "
        "full post-tool output mediation requires the Guard-managed Cline plugin transport. JetBrains protection is "
        "reported as unverified until a live pre-tool deny proof is observed."
    ),
    smoke_command="hol-guard apps test cline --json",
    surface_capabilities=("auto", "hooks", "plugin", "cli", "all"),
    supported_actions=(
        "connect:auto",
        "connect:hooks",
        "connect:plugin",
        "connect:cli",
        "connect:all",
        "test:auto",
        "test:hooks",
        "test:plugin",
        "test:cli",
        "test:all",
        "repair:auto",
        "repair:hooks",
        "repair:plugin",
        "repair:cli",
        "repair:all",
        "disconnect:auto",
        "disconnect:hooks",
        "disconnect:plugin",
        "disconnect:cli",
        "disconnect:all",
    ),
    docs_path="docs/guard/cline-local-protection-contract.md",
    icon_label="Cline",
)


def register_cline_contract() -> None:
    """Expose Cline through existing contract/setup projections exactly once."""

    if not any(item.harness == "cline" for item in contracts.HARNESS_CONTRACTS):
        contracts.HARNESS_CONTRACTS = (*contracts.HARNESS_CONTRACTS, CLINE_CONTRACT)
    contracts._DISPLAY_NAMES["cline"] = "Cline"  # pyright: ignore[reportPrivateUsage]
    contracts._CONTRACT_BY_ALIAS["cline"] = CLINE_CONTRACT  # pyright: ignore[reportPrivateUsage]
    for alias in CLINE_CONTRACT.install_aliases:
        contracts._CONTRACT_BY_ALIAS[alias] = CLINE_CONTRACT  # pyright: ignore[reportPrivateUsage]


register_cline_contract()

__all__ = ["CLINE_CONTRACT", "register_cline_contract"]
