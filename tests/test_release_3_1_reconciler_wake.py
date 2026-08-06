"""Contract for immediate release/3.1 reconciliation wake-ups."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wake-release-3.1-reconciler.yml"


def test_ci_completion_dispatches_only_the_reconciler() -> None:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert value[True]["workflow_run"]["workflows"] == ["CI"]
    assert value[True]["workflow_run"]["types"] == ["completed"]
    assert value["permissions"] == {"actions": "write", "contents": "read"}
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/workflows/reconcile-release-3.1-alpha.yml/dispatches" in text
    assert 'json.dumps({"ref": "main"})' in text
    assert "id-token: write" not in text
    assert "pypa/gh-action-pypi-publish" not in text


def test_manual_issue_wake_is_explicitly_scoped() -> None:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert value[True]["issues"] == {"types": ["opened"]}
    condition = value["jobs"]["wake"]["if"]
    assert "github.event_name == 'issues'" in condition
    assert "startsWith(github.event.issue.title, '[release-reconcile]')" in condition
