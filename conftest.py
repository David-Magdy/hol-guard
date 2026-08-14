"""Repository-level pytest safeguards for process-isolated regressions."""

from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest


_PACKAGE_SHIM_SQLITE_LOCK_TEST = (
    "tests/test_guard_package_shims.py::test_package_manager_shim_waits_out_transient_store_writer_lock"
)
_PI_BLOCKED_RUNTIME_REVIEW_TEST = (
    "tests/test_guard_surface_server.py::TestGuardSurfaceServer::"
    "test_guard_daemon_pi_hook_endpoint_returns_blocked_runtime_review_payload"
)


@pytest.fixture(autouse=True)
def _spawn_package_shim_sqlite_lock_holder(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid forking the SQLite lock holder from pytest's multithreaded process."""
    if request.node.nodeid != _PACKAGE_SHIM_SQLITE_LOCK_TEST:
        return

    context = multiprocessing.get_context("spawn")
    module = request.node.module
    monkeypatch.setattr(module, "Event", context.Event)
    monkeypatch.setattr(module, "Process", context.Process)


@pytest.fixture(autouse=True)
def _bound_pi_blocked_runtime_review_worker_startup(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run the single-review endpoint contract with one isolated worker."""
    if request.node.nodeid != _PI_BLOCKED_RUNTIME_REVIEW_TEST:
        return

    from codex_plugin_scanner.guard.daemon import hook_process_runner, server

    def _single_worker_runner(*, guard_home: Path | None = None) -> hook_process_runner.HookProcessRunner:
        return hook_process_runner.HookProcessRunner(
            guard_home=guard_home,
            process_limit=1,
        )

    monkeypatch.setattr(server, "HookProcessRunner", _single_worker_runner)
