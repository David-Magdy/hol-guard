from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.ci.build_pytest_shard_plan import (
    _load_current_durations,
    _split_file_nodes,
    apply_file_duration_floors,
    build_affinity_node_shards,
    load_file_duration_floors,
    node_file,
    write_shard_plan,
)
from scripts.ci.pytest_duration_manifest import node_id_digest, write_duration_manifest


def _durations(nodes: list[str], *, seconds: float = 1.0) -> dict[str, float]:
    return {node_id_digest(node_id): seconds for node_id in nodes}


def test_affinity_plan_covers_every_node_once_and_is_deterministic() -> None:
    nodes = [
        f"tests/test_{file_index}.py::test_{test_index}"
        for file_index in range(8)
        for test_index in range(8)
    ]
    durations = _durations(nodes)

    first, first_loads = build_affinity_node_shards(nodes, 4, durations)
    second, second_loads = build_affinity_node_shards(nodes, 4, durations)

    assert first == second
    assert first_loads == second_loads
    flattened = [node_id for shard in first for node_id in shard]
    assert sorted(flattened) == sorted(nodes)
    assert len(flattened) == len(set(flattened))
    owning_shards = {
        file_path: {
            shard_index
            for shard_index, shard in enumerate(first)
            if any(node_file(node_id) == file_path for node_id in shard)
        }
        for file_path in {node_file(node_id) for node_id in nodes}
    }
    assert all(len(shard_indexes) == 1 for shard_indexes in owning_shards.values())


def test_affinity_plan_splits_only_an_oversized_file() -> None:
    large = [f"tests/test_large.py::test_{index}" for index in range(24)]
    small = [f"tests/test_small_{index}.py::test_one" for index in range(6)]
    nodes = large + small
    durations = _durations(nodes)

    shards, loads = build_affinity_node_shards(nodes, 6, durations)

    large_owners = {
        shard_index
        for shard_index, shard in enumerate(shards)
        if any(node_file(node_id) == "tests/test_large.py" for node_id in shard)
    }
    assert 1 < len(large_owners) < 6
    assert max(loads) - min(loads) <= 1.0


def test_oversized_file_chunks_reserve_headroom_below_the_shard_target() -> None:
    nodes = [f"tests/test_large.py::test_{index}" for index in range(20)]
    estimates = {node_id: 1.0 for node_id in nodes}

    groups = _split_file_nodes("tests/test_large.py", nodes, estimates, 10.0)

    assert len(groups) == 3
    assert max(group_load for _, _, _, group_load in groups) == 7.0


def test_duration_sources_merge_conservative_node_maxima(tmp_path: Path) -> None:
    observed_at = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
    first = tmp_path / "first.json.gz"
    second = tmp_path / "second.json.gz"
    write_duration_manifest(
        first,
        {
            "tests/test_a.py::test_a": 1.0,
            "tests/test_b.py::test_b": 4.0,
        },
        observed_at,
    )
    write_duration_manifest(
        second,
        {
            "tests/test_a.py::test_a": 3.0,
            "tests/test_c.py::test_c": 2.0,
        },
        observed_at,
    )

    durations, used = _load_current_durations([first, first, second], 28)

    assert used is True
    assert durations == {
        node_id_digest("tests/test_a.py::test_a"): 3.0,
        node_id_digest("tests/test_b.py::test_b"): 4.0,
        node_id_digest("tests/test_c.py::test_c"): 2.0,
    }


def test_reviewed_file_duration_floors_scale_only_underestimated_files(tmp_path: Path) -> None:
    floor_path = tmp_path / "floors.json"
    floor_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "file_duration_floor_seconds": {
                    "tests/test_a.py": 12.0,
                    "tests/test_missing.py": 7.0,
                },
            }
        ),
        encoding="utf-8",
    )
    nodes = [
        "tests/test_a.py::test_one",
        "tests/test_a.py::test_two",
        "tests/test_b.py::test_one",
    ]

    adjusted = apply_file_duration_floors(
        {nodes[0]: 2.0, nodes[1]: 4.0, nodes[2]: 8.0},
        nodes,
        load_file_duration_floors(floor_path),
    )

    assert adjusted == {nodes[0]: 4.0, nodes[1]: 8.0, nodes[2]: 8.0}


def test_affinity_plan_rejects_duplicate_or_invalid_nodes() -> None:
    with pytest.raises(ValueError, match="unique"):
        build_affinity_node_shards(
            ["tests/test_a.py::test_a", "tests/test_a.py::test_a"],
            1,
            {},
        )
    with pytest.raises(ValueError, match="invalid pytest node"):
        build_affinity_node_shards(["outside/test_a.py::test_a"], 1, {})
    with pytest.raises(ValueError, match="invalid pytest node"):
        build_affinity_node_shards(["tests/test_a.py::test_a\ninjected"], 1, {})


def test_write_shard_plan_emits_response_files_and_metadata(tmp_path: Path) -> None:
    shards = [
        ["tests/test_a.py::test_a"],
        ["tests/test_b.py::test_b", "tests/test_b.py::test_c"],
    ]

    write_shard_plan(
        tmp_path,
        shards=shards,
        estimated_loads=[1.25, 2.5],
        manifest_used=True,
    )

    assert (tmp_path / "shard-00.txt").read_text(encoding="utf-8") == "tests/test_a.py::test_a\n"
    assert (tmp_path / "shard-01.txt").read_text(encoding="utf-8") == (
        "tests/test_b.py::test_b\ntests/test_b.py::test_c\n"
    )
    response_nodes = [
        node_id
        for response_file in sorted(tmp_path.glob("shard-*.txt"))
        for node_id in response_file.read_text(encoding="utf-8").splitlines()
    ]
    assert response_nodes == [node_id for shard in shards for node_id in shard]
    assert len(response_nodes) == len(set(response_nodes))
    assert json.loads((tmp_path / "plan.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "shard_count": 2,
        "node_count": 3,
        "duration_manifest_used": True,
        "estimated_target_seconds": 1.875,
        "estimated_max_seconds": 2.5,
        "estimated_spread_seconds": 1.25,
        "estimated_load_seconds": [1.25, 2.5],
        "node_counts": [1, 2],
        "file_counts": [1, 1],
    }
