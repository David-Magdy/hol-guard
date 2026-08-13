from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.pytest_duration_manifest import node_id_digest
from scripts.ci.pytest_parallel import (
    load_parallel_plan,
    write_merged_duration_report,
    write_parallel_plan,
)
from scripts.ci.pytest_shard import prepare_parallel_pytest_wrapper, select_parallel_worker_nodes


def _duration_map(nodes: list[str]) -> dict[str, float]:
    return {node_id_digest(node): float(index + 1) for index, node in enumerate(nodes)}


def test_parallel_plan_covers_every_node_once_and_is_deterministic() -> None:
    nodes = [f"tests/test_example.py::test_{index}" for index in range(64)]
    durations = _duration_map(nodes)

    first = [
        shard
        for runner_index in range(4)
        for shard in select_parallel_worker_nodes(
            nodes,
            runner_index=runner_index,
            runner_count=4,
            workers_per_runner=4,
            durations=durations,
        )
    ]
    second = [
        shard
        for runner_index in range(4)
        for shard in select_parallel_worker_nodes(
            nodes,
            runner_index=runner_index,
            runner_count=4,
            workers_per_runner=4,
            durations=durations,
        )
    ]

    assert first == second
    flattened = [node for shard in first for node in shard]
    assert sorted(flattened) == sorted(nodes)
    assert len(flattened) == len(set(flattened))
    loads = [sum(durations[node_id_digest(node)] for node in shard) for shard in first]
    assert max(loads) - min(loads) <= max(durations.values())


def test_parallel_plan_round_trips_with_isolated_worker_nodes(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    nodes = [["tests/a.py::test_a"], ["tests/b.py::test_b"]]
    write_parallel_plan(
        plan_path,
        root=tmp_path,
        runner_index=0,
        runner_count=2,
        workers_per_runner=2,
        worker_nodes=nodes,
        planned_at_monotonic=1.0,
        budget_seconds=10.0,
    )

    plan = load_parallel_plan(plan_path)

    assert plan["root"] == tmp_path.resolve()
    assert plan["worker_nodes"] == nodes
    assert plan["budget_seconds"] == 10.0


def test_shard_wrapper_points_at_valid_parallel_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    root = Path(__file__).resolve().parents[1]
    wrapper = prepare_parallel_pytest_wrapper(
        root=root,
        runner_index=3,
        runner_count=16,
        worker_nodes=[
            ["tests/a.py::test_a"],
            ["tests/b.py::test_b"],
            ["tests/c.py::test_c"],
            ["tests/d.py::test_d"],
        ],
        planned_at_monotonic=1.0,
    )

    assert wrapper.is_file()
    assert "run_parallel_plan" in wrapper.read_text(encoding="utf-8")
    plan = load_parallel_plan(wrapper.with_name("plan.json"))
    assert plan["runner_index"] == 3
    assert plan["workers_per_runner"] == 4


def test_duration_reports_merge_into_existing_runner_schema(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    output = tmp_path / "merged.json"
    first.write_text(
        json.dumps({"schema_version": 1, "node_durations_seconds": {"tests/a.py::test_a": 1.5}}),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps({"schema_version": 1, "node_durations_seconds": {"tests/b.py::test_b": 2.5}}),
        encoding="utf-8",
    )

    write_merged_duration_report([first, second], output)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "node_durations_seconds": {
            "tests/a.py::test_a": 1.5,
            "tests/b.py::test_b": 2.5,
        },
    }


def test_duration_report_merge_rejects_duplicate_nodes(tmp_path: Path) -> None:
    reports = []
    for index in range(2):
        path = tmp_path / f"report-{index}.json"
        path.write_text(
            json.dumps({"schema_version": 1, "node_durations_seconds": {"tests/a.py::test_a": 1.0}}),
            encoding="utf-8",
        )
        reports.append(path)

    with pytest.raises(ValueError, match="duplicate pytest duration entry"):
        write_merged_duration_report(reports, tmp_path / "merged.json")
