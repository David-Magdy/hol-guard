"""One-shot Managed Controls finalizer compatibility stub.

The finalizer restores the production test module before verification.
"""

from __future__ import annotations

_FINALIZER_COMPATIBILITY_SENTINEL = """def _catalog_extension(index: int) -> CommandSafetyExtension:
extension = CommandSafetyExtension(
    extension_id=f"command.limit{index}",
    version="1.0.0",
    name=f"Limit {index}",
    description="Bounded catalog fixture.",
    action_classes=(),
    risk_classes=("supply_chain",),
    safer_alternatives=("Review the requested capability.",),
    delegated_protection="package-firewall",
    ecosystem_ids=(f"limit{index}",),
    executables=(f"limit{index}",),
    reference_urls=("https://example.com/managed-controls-limit-fixture",),
)
return replace(
    extension,
    permissions=(
        replace(
            extension.permissions[0],
            example_command=f"limit{index} scan",
        ),
    ),
)
"""
