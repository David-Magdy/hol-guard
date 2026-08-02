"""Whole-command decision metadata for compound runtime artifacts."""

from __future__ import annotations

from pathlib import Path

from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.command_evaluation import evaluate_command
from ..runtime.command_model import CanonicalCommand


def compound_command_decision_metadata(
    command_text: str,
    *,
    canonical_command: CanonicalCommand,
    workspace: Path | None,
    home_dir: Path,
) -> dict[str, object]:
    evaluation = evaluate_command(
        command_text,
        canonical_command=canonical_command,
        cwd=workspace,
        home_dir=home_dir,
    )
    return {
        "command_action_floor": evaluation.decision_plane.action,
        "command_decision_plane": effect_decision_to_dict(evaluation.decision_plane),
    }
