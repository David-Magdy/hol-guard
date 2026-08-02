"""Coordinate bounded supply-chain recovery steps without hiding partial failures."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

_LOGGER = logging.getLogger(__name__)

RepairStep = Callable[[], object]
ActivationStep = Callable[[], tuple[int, Mapping[str, object]]]


def coordinate_supply_chain_repair(
    *,
    repair_package_shims: RepairStep,
    activate_runtime: ActivationStep,
    sync_intelligence: RepairStep,
) -> dict[str, object]:
    """Run every independent recovery step and return an honest aggregate result."""

    completed_steps: list[str] = []
    failed_steps: list[dict[str, str]] = []

    try:
        _ = repair_package_shims()
        completed_steps.append("package_shims")
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: package_shims")
        failed_steps.append(
            {
                "step": "package_shims",
                "message": "Guard could not repair every detected package tool.",
            }
        )

    try:
        status, response = activate_runtime()
        if status >= 400:
            message = response.get("message")
            raise RuntimeError(message if isinstance(message, str) else "activation failed")
        completed_steps.append("runtime_activation")
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: runtime_activation")
        failed_steps.append(
            {
                "step": "runtime_activation",
                "message": "Guard could not finish package protection activation.",
            }
        )

    try:
        _ = sync_intelligence()
        completed_steps.append("intelligence_sync")
    except Exception:
        _LOGGER.exception("Supply-chain repair step failed: intelligence_sync")
        failed_steps.append(
            {
                "step": "intelligence_sync",
                "message": "Guard could not refresh supply-chain intelligence.",
            }
        )

    repaired = not failed_steps
    if repaired:
        message = "Supply-chain protection restored and refreshed."
    elif completed_steps:
        message = "Guard fixed part of supply-chain protection. Retry to finish the remaining steps."
    else:
        message = "Guard could not complete supply-chain repair. Retry here to continue safely."
    return {
        "repaired": repaired,
        "completed_steps": completed_steps,
        "failed_steps": failed_steps,
        "message": message,
    }


__all__ = ["coordinate_supply_chain_repair"]
