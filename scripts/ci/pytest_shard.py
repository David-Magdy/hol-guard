#!/usr/bin/env python3
"""Select deterministic, duration-balanced pytest work for CI."""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast

import pytest

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.pytest_duration_manifest import load_duration_manifest, node_id_digest
from scripts.ci.pytest_parallel import (
    DEFAULT_PLAN_BUDGET_SECONDS,
    DEFAULT_WORKERS_PER_RUNNER,
    write_parallel_plan,
)

UNKNOWN_NODE_DURATION_SECONDS = 1.0


class _CollectionSession(Protocol):
    items: list[pytest.Item]


class _Arguments(Protocol):
    shard_count: int
    shard_index: int
    granularity: str
    duration_manifest: Path | None
    max_manifest_age_days: int


class _NodeCollector:
    def __init__(self) -> None:
        self.node_ids: list[str] = []

    def pytest_collection_finish(self, session: _CollectionSession) -> None:
        self.node_ids = sorted(item.nodeid for item in session.items)


def discover_test_files(root: Path) -> list[Path]:
    return sorted(path for path in (root / "tests").rglob("test_*.py") if path.is_file())


def build_test_shards(root: Path, shard_count: int) -> list[list[Path]]:
    if shard_count < 1:
        raise ValueError("shard_count must be positive")

    files = discover_test_files(root)
    if shard_count > len(files):
        raise ValueError("shard_count cannot exceed the number of test files")

    shards: list[list[Path]] = [[] for _ in range(shard_count)]
    weights = [0] * shard_count
    weighted_files = sorted(
        ((path.stat().st_size, path) for path in files),
        key=lambda item: (-item[0], item[1].as_posix()),
    )
    for weight, path in weighted_files:
        shard_index = min(range(shard_count), key=lambda index: (weights[index], index))
        shards[shard_index].append(path)
        weights[shard_index] += weight

    for shard in shards:
        shard.sort()
    return shards


def discover_test_nodes(root: Path) -> list[str]:
    collector = _NodeCollector()
    result = pytest.main(
        [str(root / "tests"), "--collect-only", "-p", "no:terminal"],
        plugins=[collector],
    )
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {result}")
    return collector.node_ids


def build_node_shards(
    node_ids: list[str], shard_count: int, durations: Mapping[str, float] | None = None
) -> list[list[str]]:
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if shard_count > len(node_ids):
        raise ValueError("shard_count cannot exceed the number of test nodes")
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("test node ids must be unique")
    if durations is None:
        ordered = sorted(node_ids)
        return [ordered[index::shard_count] for index in range(shard_count)]

    estimates = _estimate_node_durations(node_ids, durations)
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    loads = [0.0] * shard_count
    for node_id in sorted(node_ids, key=lambda node: (-estimates[node], node)):
        shard_index = min(range(shard_count), key=lambda index: (loads[index], index))
        shards[shard_index].append(node_id)
        loads[shard_index] += estimates[node_id]
    for shard in shards:
        shard.sort()
    return shards


def _estimate_node_durations(node_ids: list[str], durations: Mapping[str, float]) -> dict[str, float]:
    known_node_ids = set(node_ids)
    known = sorted(
        duration for node_id in known_node_ids if (duration := durations.get(node_id_digest(node_id), 0.0)) > 0
    )
    fallback = max(UNKNOWN_NODE_DURATION_SECONDS, known[(len(known) - 1) // 2] if known else 0.0)
    return {node_id: durations.get(node_id_digest(node_id), fallback) for node_id in node_ids}


def _load_current_durations(path: Path, max_age_days: int) -> dict[str, float] | None:
    try:
        return load_duration_manifest(
            path,
            now=datetime.now(timezone.utc),
            max_age=timedelta(days=max_age_days),
        )
    except (OSError, ValueError) as exc:
        print(f"pytest duration manifest unavailable; using equal-weight fallback: {exc}", file=sys.stderr)
        return None


def select_parallel_worker_nodes(
    node_ids: list[str],
    *,
    runner_index: int,
    runner_count: int,
    workers_per_runner: int,
    durations: Mapping[str, float],
) -> list[list[str]]:
    """Return the globally balanced worker shards owned by one matrix runner."""

    if runner_count < 1:
        raise ValueError("runner_count must be positive")
    if workers_per_runner < 1:
        raise ValueError("workers_per_runner must be positive")
    if runner_index < 0 or runner_index >= runner_count:
        raise ValueError("runner_index must be between zero and runner_count - 1")
    shards = build_node_shards(node_ids, runner_count * workers_per_runner, durations)
    start = runner_index * workers_per_runner
    selected = shards[start : start + workers_per_runner]
    if len(selected) != workers_per_runner or any(not shard for shard in selected):
        raise ValueError("every local pytest worker must own at least one test node")
    flattened = [node_id for shard in selected for node_id in shard]
    if len(flattened) != len(set(flattened)):
        raise ValueError("local pytest worker shards must not overlap")
    return selected


def prepare_parallel_pytest_wrapper(
    *,
    root: Path,
    runner_index: int,
    runner_count: int,
    worker_nodes: list[list[str]],
    planned_at_monotonic: float,
) -> Path:
    """Write the immutable plan and one outer pytest wrapper file."""

    runner_temp = Path(os.environ.get("RUNNER_TEMP", root / ".guard-ci-tmp"))
    plan_dir = runner_temp / f"hol-guard-pytest-plan-{runner_index}"
    plan_path = plan_dir / "plan.json"
    wrapper_path = plan_dir / "test_guard_ci_parallel_wrapper.py"
    write_parallel_plan(
        plan_path,
        root=root,
        runner_index=runner_index,
        runner_count=runner_count,
        workers_per_runner=DEFAULT_WORKERS_PER_RUNNER,
        worker_nodes=worker_nodes,
        planned_at_monotonic=planned_at_monotonic,
        budget_seconds=DEFAULT_PLAN_BUDGET_SECONDS,
    )
    wrapper_path.write_text(
        "from pathlib import Path\n"
        "from scripts.ci.pytest_parallel import run_parallel_plan\n\n"
        "def test_guard_ci_parallel_wrapper() -> None:\n"
        f"    run_parallel_plan(Path({str(plan_path)!r}))\n",
        encoding="utf-8",
    )
    return wrapper_path


def select_test_files(root: Path, shard_index: int, shard_count: int) -> list[Path]:
    if shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard_index must be between zero and shard_count - 1")
    return build_test_shards(root, shard_count)[shard_index]


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--shard-count", type=int, required=True)
    _ = parser.add_argument("--shard-index", type=int, required=True)
    _ = parser.add_argument("--granularity", choices=("file", "node"), default="file")
    _ = parser.add_argument("--duration-manifest", type=Path)
    _ = parser.add_argument("--max-manifest-age-days", type=int, default=28)
    args = cast(_Arguments, cast(object, parser.parse_args()))

    root = Path(__file__).resolve().parents[2]
    if args.granularity == "node":
        planned_at = time.monotonic()
        durations = None
        if args.duration_manifest is not None:
            durations = _load_current_durations(args.duration_manifest, args.max_manifest_age_days)
        if durations is None:
            raise ValueError("node-level CI parallelism requires a current duration manifest")
        nodes = discover_test_nodes(root)
        worker_nodes = select_parallel_worker_nodes(
            nodes,
            runner_index=args.shard_index,
            runner_count=args.shard_count,
            workers_per_runner=DEFAULT_WORKERS_PER_RUNNER,
            durations=durations,
        )
        wrapper = prepare_parallel_pytest_wrapper(
            root=root,
            runner_index=args.shard_index,
            runner_count=args.shard_count,
            worker_nodes=worker_nodes,
            planned_at_monotonic=planned_at,
        )
        print(wrapper)
    else:
        for path in select_test_files(root, args.shard_index, args.shard_count):
            print(path.relative_to(root).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
