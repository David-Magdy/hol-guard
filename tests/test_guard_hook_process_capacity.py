from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_capacity as capacity_module
from codex_plugin_scanner.guard.daemon.hook_process_capacity import (
    HookProcessCapacityPolicy,
    HookProcessLoad,
    default_hook_worker_memory_ceiling,
    initial_hook_worker_target,
    process_tree_rss_bytes,
    validate_hook_worker_limit,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _load(
    *,
    queued: int = 1,
    queue_p95: float = 0.201,
    cpu: float | None = 0.79,
    rss: int | None = 1,
    failures: float = 0.009,
) -> HookProcessLoad:
    return HookProcessLoad(
        queue_p95_seconds=queue_p95,
        queued=queued,
        cpu_ratio=cpu,
        rss_bytes=rss,
        failure_rate=failures,
    )


@pytest.mark.parametrize(
    ("cpu_count", "expected"),
    [(1, 4), (4, 4), (8, 8), (64, 8)],
)
def test_initial_target_follows_cpu_budget(cpu_count: int, expected: int) -> None:
    assert initial_hook_worker_target(cpu_count) == expected


def test_worker_limit_accepts_only_two_through_sixteen() -> None:
    assert validate_hook_worker_limit(2) == 2
    assert validate_hook_worker_limit(16) == 16
    with pytest.raises(ValueError, match="between 2 and 16"):
        _ = validate_hook_worker_limit(1)
    with pytest.raises(ValueError, match="between 2 and 16"):
        _ = validate_hook_worker_limit(17)


def test_default_memory_ceiling_applies_floor_and_cap() -> None:
    assert default_hook_worker_memory_ceiling(1024**3) == 512 * 1024**2
    assert default_hook_worker_memory_ceiling(8 * 1024**3) == 1536 * 1024**2


def test_process_tree_rss_includes_nested_worker_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_table = "\n".join(
        (
            "10 1 100",
            "11 10 50",
            "12 11 25",
            "99 1 1000",
        )
    )
    monkeypatch.setattr(capacity_module.shutil, "which", lambda _name: "/usr/bin/ps")
    monkeypatch.setattr(capacity_module, "is_trusted_absolute_command_path", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        capacity_module.subprocess,
        "run",
        lambda *_args, **_kwargs: capacity_module.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=process_table,
            stderr="",
        ),
    )

    assert process_tree_rss_bytes((10,)) == 175 * 1024


def test_process_tree_rss_rejects_path_shadowed_ps(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadowed_ps = tmp_path / "ps"
    shadowed_ps.write_text("#!/bin/sh\n", encoding="utf-8")
    shadowed_ps.chmod(0o755)
    monkeypatch.setattr(capacity_module.shutil, "which", lambda _name: str(shadowed_ps))
    monkeypatch.setattr(
        capacity_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("untrusted ps must not execute"),
    )

    assert process_tree_rss_bytes((10,)) is None


def test_scale_up_requires_ten_continuous_seconds_and_one_second_spacing() -> None:
    clock = _Clock()
    policy = HookProcessCapacityPolicy(
        initial_target=4,
        maximum_target=16,
        memory_ceiling_bytes=100,
        monotonic=clock,
    )
    assert policy.observe(_load()) == 4
    clock.now = 9.999
    assert policy.observe(_load()) == 4
    clock.now = 10.0
    assert policy.observe(_load()) == 5
    clock.now = 10.999
    assert policy.observe(_load()) == 5
    clock.now = 11.0
    assert policy.observe(_load()) == 6


@pytest.mark.parametrize(
    "load",
    [
        _load(queue_p95=0.2),
        _load(cpu=0.8),
        _load(rss=100),
        _load(failures=0.01),
        _load(cpu=None),
        _load(rss=None),
    ],
)
def test_scale_up_requires_every_resource_threshold(load: HookProcessLoad) -> None:
    clock = _Clock()
    policy = HookProcessCapacityPolicy(
        initial_target=4,
        memory_ceiling_bytes=100,
        monotonic=clock,
    )
    assert policy.observe(load) == 4
    clock.now = 20
    assert policy.observe(load) == 4


def test_scale_down_waits_five_idle_minutes() -> None:
    clock = _Clock()
    policy = HookProcessCapacityPolicy(
        initial_target=8,
        memory_ceiling_bytes=100,
        monotonic=clock,
    )
    assert policy.observe(_load(queued=0)) == 8
    clock.now = 299.999
    assert policy.observe(_load(queued=0)) == 8
    clock.now = 300
    assert policy.observe(_load(queued=0)) == 7
