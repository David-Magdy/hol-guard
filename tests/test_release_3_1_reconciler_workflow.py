"""Contracts for backfilling missed release/3.1 alpha publications."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "reconcile-release-3.1-alpha.yml"


def workflow() -> dict[object, object]:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_reconciler_runs_on_default_branch_schedule() -> None:
    value = workflow()
    assert value[True]["schedule"] == [{"cron": "*/5 * * * *"}]
    assert "workflow_dispatch" in value[True]


def test_reconciler_has_only_actions_write_for_dispatch() -> None:
    jobs = workflow()["jobs"]
    assert jobs["reconcile"]["permissions"] == {"contents": "read", "actions": "write"}
    assert jobs["validate"].get("permissions") is None


def test_reconciler_processes_one_commit_per_run() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "Select oldest unpublished release/3.1 commit" in text
    assert "reserved_alpha_missing_from_pypi" in text
    assert "untagged_release_commit" in text
    assert text.count("workflow dispatch returned HTTP") == 1


def test_reconciler_refuses_to_overlap_active_publish_dispatch() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'for status in ("queued", "in_progress")' in text
    assert "publisher_{status}" in text


def test_reconciler_dispatches_existing_trusted_publish_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/workflows/publish.yml/dispatches" in text
    assert '"release_channel": "alpha"' in text
    assert '"release_train": "3.1"' in text
    assert '"release_version": os.environ["VERSION"]' in text
    assert '"expected_sha": os.environ["SOURCE_SHA"]' in text


def test_reconciler_does_not_receive_pypi_identity_token() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "id-token: write" not in text
    assert "environment: pypi" not in text
    assert "pypa/gh-action-pypi-publish" not in text
