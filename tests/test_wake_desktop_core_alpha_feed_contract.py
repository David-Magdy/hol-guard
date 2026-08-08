from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wake-desktop-core-alpha-feed.yml"


def test_push_wake_is_scoped_to_main_and_dispatch_only() -> None:
    payload = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    trigger = payload[True]
    assert trigger["push"]["branches"] == ["main"]
    assert trigger["push"]["paths"] == [".github/workflows/wake-desktop-core-alpha-feed.yml"]
    job = payload["jobs"]["wake"]
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/workflows/desktop-core-alpha-feed.yml/dispatches" in text
    assert "id-token: write" not in text
    assert "pypa/gh-action-pypi-publish" not in text
