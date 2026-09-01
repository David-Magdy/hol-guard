from __future__ import annotations

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler


def test_hook_ingress_body_budget_remains_one_megabyte() -> None:
    assert _GuardDaemonHandler._MAX_BODY_BYTES == 1_000_000
