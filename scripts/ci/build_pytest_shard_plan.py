#!/usr/bin/env python3
"""Collect pytest once and emit deterministic duration-balanced shard files."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.pytest_duration_manifest import load_duration_manifest, node_id_digest
from scripts.ci.pytest_shard import discover_test_nodes

PLAN_SCHEMA_VERSION = 1
FILE_DURATION_FLOOR_SCHEMA_VERSION = 1
UNKNOWN_NODE_DURATION_SECONDS = 1.0
MAX_UNSPLIT_FILE_TARGET_MULTIPLIER = 1.05
OVERSIZED_FILE_CHUNK_TARGET_MULTIPLIER = 0.98


class _Arguments(Protocol):
    shard_count: int
    duration_manifest: Path
    max_manifest_age_days: int
    output_directory: Path


def node_file(node_id: str) -> str:
    """Return and validate the repository-relative file that owns a pytest node."""

    if "\n" in node_id or "\r" in node_id or "\x00" in node_id:
        raise ValueError(f"invalid pytest node id: {node_id!r}")
    path = node_id.split("::", maxsplit=1)[0]
    if not path.startswith("tests/") or not path.endswith(".py"):
        raise ValueError(f"invalid pytest node id: {node_id!r}")
    return path


def estimate_node_durations(node_ids: Sequence[str], durations: Mapping[str, float]) -> dict[str, float]:
    """Map collected node IDs to current estimates with a conservative fallback."""

    known = sorted(
        duration
        for node_id in node_ids
        if (duration := durations.get(node_id_digest(node_id), 0.0)) > 0
    )
    fallback = max(
        UNKNOWN_NODE_DURATION_SECONDS,
        known[(len(known) - 1) // 2] if known else 0.0,
    )
    return {
        node_id: float(durations.get(node_id_digest(node_id), fallback))
        for node_id in node_ids
    }


def load_file_duration_floors(path: Path) -> dict[str, float]:
    """Load reviewed per-file duration floors used to retain observed long-tail evidence."""

    payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(payload, dict) or payload.get("schema_version") != FILE_DURATION_FLOOR_SCHEMA_VERSION:
        raise ValueError("unsupported pytest file duration floor schema")
    values = payload.get("file_duration_floor_seconds")
    if not isinstance(values, dict):
        raise ValueError("pytest file duration floors require file_duration_floor_seconds")
    floors: dict[str, float] = {}
    for file_path, value in values.items():
        if not isinstance(file_path, str):
            raise ValueError("pytest file duration floor has an invalid file path")
        node_file(f"{file_path}::duration-floor")
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"pytest file duration floor is invalid for {file_path!r}")
        floors[file_path] = float(value)
    return dict(sorted(floors.items()))


def apply_file_duration_floors(
    estimates: Mapping[str, float],
    node_ids: Sequence[str],
    floors: Mapping[str, float],
) -> dict[str, float]:
    """Scale a file's node estimates proportionally when reviewed evidence is higher."""

    adjusted = dict(estimates)
    by_file: dict[str, list[str]] = defaultdict(list)
    for node_id in node_ids:
        by_file[node_file(node_id)].append(node_id)
    for file_path, floor_seconds in floors.items():
        file_nodes = by_file.get(file_path, [])
        if not file_nodes:
            continue
        current_seconds = sum(adjusted[node_id] for node_id in file_nodes)
        if current_seconds <= 0:
            raise ValueError(f"pytest estimates are non-positive for {file_path!r}")
        if current_seconds >= floor_seconds:
            continue
        multiplier = floor_seconds / current_seconds
        for node_id in file_nodes:
            adjusted[node_id] *= multiplier
    return adjusted


def _split_file_nodes(
    file_path: str,
    node_ids: Sequence[str],
    estimates: Mapping[str, float],
    target_seconds: float,
) -> list[tuple[str, int, list[str], float]]:
    total = sum(estimates[node_id] for node_id in node_ids)
    split_count = 1
    if total > target_seconds * MAX_UNSPLIT_FILE_TARGET_MULTIPLIER:
        chunk_target = target_seconds * OVERSIZED_FILE_CHUNK_TARGET_MULTIPLIER
        split_count = min(len(node_ids), max(1, math.ceil(total / chunk_target)))

    chunks: list[list[str]] = [[] for _ in range(split_count)]
    loads = [0.0] * split_count
    for node_id in sorted(node_ids, key=lambda node: (-estimates[node], node)):
        index = min(range(split_count), key=lambda item: (loads[item], item))
        chunks[index].append(node_id)
        loads[index] += estimates[node_id]

    return [
        (file_path, index, sorted(chunk), loads[index])
        for index, chunk in enumerate(chunks)
        if chunk
    ]


def build_affinity_node_shards(
    node_ids: Sequence[str],
    shard_count: int,
    durations: Mapping[str, float],
    file_duration_floors: Mapping[str, float] | None = None,
) -> tuple[list[list[str]], list[float]]:
    """Balance by duration while keeping each test file together when practical."""

    nodes = list(node_ids)
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if shard_count > len(nodes):
        raise ValueError("shard_count cannot exceed the number of test nodes")
    if len(nodes) != len(set(nodes)):
        raise ValueError("test node ids must be unique")

    estimates = estimate_node_durations(nodes, durations)
    if file_duration_floors:
        estimates = apply_file_duration_floors(estimates, nodes, file_duration_floors)
    target_seconds = sum(estimates.values()) / shard_count
    by_file: dict[str, list[str]] = defaultdict(list)
    for node_id in nodes:
        by_file[node_file(node_id)].append(node_id)

    groups: list[tuple[str, int, list[str], float]] = []
    for file_path, file_nodes in sorted(by_file.items()):
        groups.extend(_split_file_nodes(file_path, file_nodes, estimates, target_seconds))

    shards: list[list[str]] = [[] for _ in range(shard_count)]
    loads = [0.0] * shard_count
    for file_path, group_index, group_nodes, group_load in sorted(
        groups,
        key=lambda group: (-group[3], group[0], group[1]),
    ):
        _ = file_path, group_index
        shard_index = min(range(shard_count), key=lambda index: (loads[index], index))
        shards[shard_index].extend(group_nodes)
        loads[shard_index] += group_load

    if any(not shard for shard in shards):
        raise ValueError("every pytest shard must contain at least one test node")
    for shard in shards:
        shard.sort()

    flattened = [node_id for shard in shards for node_id in shard]
    if len(flattened) != len(nodes) or set(flattened) != set(nodes):
        raise ValueError("pytest shard plan must cover every collected node exactly once")
    return shards, loads


def write_shard_plan(
    output_directory: Path,
    *,
    shards: Sequence[Sequence[str]],
    estimated_loads: Sequence[float],
    manifest_used: bool,
) -> None:
    """Write one response file per shard plus reviewable plan metadata."""

    if len(shards) != len(estimated_loads) or not shards:
        raise ValueError("shards and estimated loads must be non-empty and aligned")
    output_directory.mkdir(parents=True, exist_ok=True)
    width = max(2, len(str(len(shards) - 1)))
    for index, shard in enumerate(shards):
        path = output_directory / f"shard-{index:0{width}d}.txt"
        path.write_text("\n".join(shard) + "\n", encoding="utf-8")

    target_seconds = sum(estimated_loads) / len(estimated_loads)
    metadata = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "shard_count": len(shards),
        "node_count": sum(len(shard) for shard in shards),
        "duration_manifest_used": manifest_used,
        "estimated_target_seconds": round(target_seconds, 6),
        "estimated_max_seconds": round(max(estimated_loads), 6),
        "estimated_spread_seconds": round(max(estimated_loads) - min(estimated_loads), 6),
        "estimated_load_seconds": [round(load, 6) for load in estimated_loads],
        "node_counts": [len(shard) for shard in shards],
        "file_counts": [len({node_file(node_id) for node_id in shard}) for shard in shards],
    }
    (output_directory / "plan.json").write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _load_current_durations(paths: Sequence[Path], max_age_days: int) -> tuple[dict[str, float], bool]:
    """Merge valid reviewed and trusted manifests, retaining conservative maxima."""

    merged: dict[str, float] = {}
    loaded = 0
    seen: set[Path] = set()
    for path in paths:
        normalized = path.resolve()
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            durations = load_duration_manifest(
                path,
                now=datetime.now(timezone.utc),
                max_age=timedelta(days=max_age_days),
            )
        except (OSError, ValueError) as exc:
            print(
                f"pytest duration manifest unavailable at {path}; ignoring it: {exc}",
                file=sys.stderr,
            )
            continue
        loaded += 1
        for node_digest, duration in durations.items():
            merged[node_digest] = max(merged.get(node_digest, 0.0), duration)
    if loaded == 0:
        print(
            "pytest duration manifests unavailable; using deterministic equal-weight planning",
            file=sys.stderr,
        )
    return dict(sorted(merged.items())), loaded > 0


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--shard-count", type=int, required=True)
    _ = parser.add_argument("--duration-manifest", type=Path, required=True)
    _ = parser.add_argument("--max-manifest-age-days", type=int, default=28)
    _ = parser.add_argument("--output-directory", type=Path, required=True)
    args = cast(_Arguments, cast(object, parser.parse_args()))

    root = Path(__file__).resolve().parents[2]
    reviewed_manifest = root / "ci" / "pytest-duration-manifest.json.gz"
    reviewed_file_floors = root / "ci" / "pytest-file-duration-floors.json"
    durations, manifest_used = _load_current_durations(
        [args.duration_manifest, reviewed_manifest],
        args.max_manifest_age_days,
    )
    file_duration_floors = load_file_duration_floors(reviewed_file_floors)
    nodes = discover_test_nodes(root)
    shards, loads = build_affinity_node_shards(
        nodes,
        args.shard_count,
        durations,
        file_duration_floors,
    )
    write_shard_plan(
        args.output_directory,
        shards=shards,
        estimated_loads=loads,
        manifest_used=manifest_used,
    )
    print(
        json.dumps(
            {
                "shards": len(shards),
                "nodes": len(nodes),
                "manifest_used": manifest_used,
                "estimated_min_seconds": round(min(loads), 3),
                "estimated_max_seconds": round(max(loads), 3),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
