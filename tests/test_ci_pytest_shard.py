from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_shard.py"
SPEC = importlib.util.spec_from_file_location("pytest_shard", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pytest_shard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pytest_shard)


def test_ci_shards_cover_every_test_file_once_and_deterministically() -> None:
    expected = pytest_shard.discover_test_files(ROOT)
    shards = pytest_shard.build_test_shards(ROOT, 4)

    assert shards == pytest_shard.build_test_shards(ROOT, 4)
    assert all(shards)
    assert sorted(path for shard in shards for path in shard) == expected
    assert sum(len(shard) for shard in shards) == len(set().union(*map(set, shards)))


def test_ci_workflow_cancels_stale_runs_and_uses_precomputed_affinity_shards() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    plan_job = workflow.split("  test-plan:\n", maxsplit=1)[1].split("\n  tests:", maxsplit=1)[0]
    tests_job = workflow.split("  tests:\n", maxsplit=1)[1].split(
        "\n  duration-manifest-candidate:", maxsplit=1
    )[0]

    assert "cancel-in-progress: true" in workflow
    assert "CI_UV_CACHE_DEPENDENCY_GLOB" in workflow
    assert "**/pyproject.toml" not in workflow
    assert "--shard-count 64" in plan_job
    assert "build_pytest_shard_plan.py" in plan_job
    assert "needs: test-plan" in tests_job
    assert "name: pytest-shard-plan" in tests_job
    assert "shard-%02d.txt" in tests_job
    assert "python scripts/ci/pytest_shard.py" not in tests_job
    assert 'test "${#reports[@]}" -eq 64' in workflow
    assert "name: ci (3.12)" in workflow
    assert "needs: [quality, test-plan, tests, compatibility]" in workflow
