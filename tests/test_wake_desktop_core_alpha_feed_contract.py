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
    steps = job["steps"]
    assert len(steps) == 1
    step = steps[0]
    assert step["name"] == "Dispatch feed producer"
    assert "uses" not in step
    assert set(step) == {"name", "env", "run"}
    assert set(step["env"]) == {"GH_TOKEN", "REPOSITORY"}
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert step["env"]["REPOSITORY"] == "${{ github.repository }}"

    run = step["run"]
    assert "actions/workflows/desktop-core-alpha-feed.yml/dispatches" in run
    assert "id-token: write" not in WORKFLOW.read_text(encoding="utf-8")
    assert "pypa/gh-action-pypi-publish" not in WORKFLOW.read_text(encoding="utf-8")
