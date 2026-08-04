from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, final

from ..runtime.shell_command_wrappers import is_trusted_absolute_command_path

_MIN_WORKERS = 2
_MAX_WORKERS = 16
_MAX_INITIAL_WORKERS = 8
_MIN_INITIAL_WORKERS = 4
_PRESSURE_SECONDS = 10.0
_IDLE_SECONDS = 300.0
_SPAWN_INTERVAL_SECONDS = 1.0
_QUEUE_P95_SCALE_THRESHOLD_SECONDS = 0.2
_CPU_SCALE_CEILING = 0.8
_FAILURE_RATE_SCALE_CEILING = 0.01
_MEMORY_FLOOR_BYTES = 512 * 1024 * 1024
_MEMORY_CAP_BYTES = 1536 * 1024 * 1024


def initial_hook_worker_target(cpu_count: int | None = None) -> int:
    available = cpu_count if cpu_count is not None else (os.cpu_count() or _MIN_INITIAL_WORKERS)
    return min(_MAX_INITIAL_WORKERS, max(_MIN_INITIAL_WORKERS, available))


def default_hook_worker_memory_ceiling(physical_memory_bytes: int) -> int:
    if physical_memory_bytes <= 0:
        raise ValueError("physical_memory_bytes must be positive")
    return min(_MEMORY_CAP_BYTES, max(_MEMORY_FLOOR_BYTES, physical_memory_bytes // 5))


def physical_memory_bytes() -> int | None:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        return None
    total = page_size * page_count
    return total if total > 0 else None


def process_cpu_ratio() -> float | None:
    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):
        return None
    processors = os.cpu_count() or 1
    return max(0.0, load / processors)


def process_tree_rss_bytes(process_ids: tuple[int, ...]) -> int | None:
    root_process_ids = {process_id for process_id in process_ids if process_id > 0}
    if not root_process_ids or os.name == "nt":
        return None
    located_ps = shutil.which("ps")
    if located_ps is None:
        return None
    ps_path = Path(located_ps)
    if not ps_path.is_absolute() or not is_trusted_absolute_command_path(
        ps_path,
        cwd=Path.cwd(),
        home_dir=Path.home(),
    ):
        return None
    try:
        result = subprocess.run(
            [ps_path, "-axo", "pid=,ppid=,rss="],
            check=False,
            capture_output=True,
            text=True,
            timeout=0.2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    process_rows: list[tuple[int, int, int]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            process_rows.append((int(fields[0]), int(fields[1]), int(fields[2])))
        except ValueError:
            continue
    included_process_ids = set(root_process_ids)
    while True:
        descendants = {
            process_id
            for process_id, parent_process_id, _rss_kib in process_rows
            if parent_process_id in included_process_ids
        }
        expanded = included_process_ids | descendants
        if expanded == included_process_ids:
            break
        included_process_ids = expanded
    rss_kib = sum(
        rss_kib for process_id, _parent_process_id, rss_kib in process_rows if process_id in included_process_ids
    )
    return rss_kib * 1024


def validate_hook_worker_limit(value: int) -> int:
    if not _MIN_WORKERS <= value <= _MAX_WORKERS:
        raise ValueError("hook worker limit must be between 2 and 16")
    return value


@dataclass(frozen=True, slots=True)
class HookProcessLoad:
    queue_p95_seconds: float
    queued: int
    cpu_ratio: float | None
    rss_bytes: int | None
    failure_rate: float


class HookProcessStats(TypedDict):
    configured: int
    workers: int
    ready: int
    busy: int
    target: int
    timeouts: int
    failures: int
    restarts: int
    decisions: dict[str, int]
    reason_codes: dict[str, int]


@final
class HookProcessCapacityPolicy:
    def __init__(
        self,
        *,
        initial_target: int,
        maximum_target: int = _MAX_WORKERS,
        memory_ceiling_bytes: int,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._target = validate_hook_worker_limit(initial_target)
        self._maximum_target = validate_hook_worker_limit(maximum_target)
        if self._target > self._maximum_target:
            raise ValueError("initial hook worker target exceeds maximum")
        if memory_ceiling_bytes <= 0:
            raise ValueError("hook worker memory ceiling must be positive")
        self._memory_ceiling_bytes = memory_ceiling_bytes
        self._monotonic = monotonic
        self._pressure_since: float | None = None
        self._idle_since: float | None = None
        self._last_scale_up = float("-inf")

    @property
    def target(self) -> int:
        return self._target

    def observe(self, load: HookProcessLoad) -> int:
        now = self._monotonic()
        pressured = (
            load.queued > 0
            and load.queue_p95_seconds > _QUEUE_P95_SCALE_THRESHOLD_SECONDS
            and load.cpu_ratio is not None
            and load.cpu_ratio < _CPU_SCALE_CEILING
            and load.rss_bytes is not None
            and load.rss_bytes < self._memory_ceiling_bytes
            and load.failure_rate < _FAILURE_RATE_SCALE_CEILING
        )
        if pressured:
            self._idle_since = None
            if self._pressure_since is None:
                self._pressure_since = now
            if (
                now - self._pressure_since >= _PRESSURE_SECONDS
                and now - self._last_scale_up >= _SPAWN_INTERVAL_SECONDS
                and self._target < self._maximum_target
            ):
                self._target += 1
                self._last_scale_up = now
            return self._target

        self._pressure_since = None
        if load.queued == 0:
            if self._idle_since is None:
                self._idle_since = now
            elif now - self._idle_since >= _IDLE_SECONDS and self._target > _MIN_WORKERS:
                self._target -= 1
                self._idle_since = now
        else:
            self._idle_since = None
        return self._target


@final
class AdaptiveHookProcessCapacity:
    def __init__(
        self,
        *,
        initial_target: int,
        maximum_target: int,
        memory_ceiling_bytes: int | None,
        cpu_ratio_provider: Callable[[], float | None],
    ):
        physical_memory = physical_memory_bytes()
        ceiling = (
            memory_ceiling_bytes
            if memory_ceiling_bytes is not None
            else default_hook_worker_memory_ceiling(physical_memory or (4 * 1024 * 1024 * 1024))
        )
        self._policy = HookProcessCapacityPolicy(
            initial_target=initial_target,
            maximum_target=maximum_target,
            memory_ceiling_bytes=ceiling,
        )
        self._cpu_ratio_provider = cpu_ratio_provider
        self._queue_p95_seconds = 0.0
        self._queued = 0
        self._lock = threading.Lock()

    def observe_load(self, *, queue_p95_ms: float, queued: int) -> None:
        with self._lock:
            self._queue_p95_seconds = max(0.0, queue_p95_ms / 1000.0)
            self._queued = max(0, queued)

    def refresh(self, *, failure_rate: float, rss_bytes: int | None) -> int:
        cpu_ratio = self._cpu_ratio_provider()
        with self._lock:
            return self._policy.observe(
                HookProcessLoad(
                    queue_p95_seconds=self._queue_p95_seconds,
                    queued=self._queued,
                    cpu_ratio=cpu_ratio,
                    rss_bytes=rss_bytes,
                    failure_rate=failure_rate,
                )
            )


__all__ = [
    "AdaptiveHookProcessCapacity",
    "HookProcessCapacityPolicy",
    "HookProcessLoad",
    "HookProcessStats",
    "default_hook_worker_memory_ceiling",
    "initial_hook_worker_target",
    "physical_memory_bytes",
    "process_cpu_ratio",
    "process_tree_rss_bytes",
    "validate_hook_worker_limit",
]
