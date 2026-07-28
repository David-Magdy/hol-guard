from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import recovery_worker
from codex_plugin_scanner.guard.daemon import server as server_module


def test_invalid_remaining_seconds_falls_back_to_valid_milliseconds() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": "invalid",
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 1.25  # pyright: ignore[reportPrivateUsage]
    assert "guard_remaining_seconds" not in payload
    assert "guard_remaining_ms" not in payload


@pytest.mark.parametrize("invalid_seconds", (float("nan"), float("inf"), float("-inf")))
def test_nonfinite_remaining_seconds_falls_back_to_valid_milliseconds(invalid_seconds: float) -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": invalid_seconds,
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 1.25  # pyright: ignore[reportPrivateUsage]


def test_valid_remaining_seconds_consumes_millisecond_fallback() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": 2.0,
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 2.0  # pyright: ignore[reportPrivateUsage]
    assert "guard_remaining_ms" not in payload


def test_boolean_deadline_hints_use_default() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": True,
        "guard_remaining_ms": False,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == (  # pyright: ignore[reportPrivateUsage]
        server_module._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )


def test_recovery_worker_clears_its_claim_when_recovery_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    cleared: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        recovery_worker,
        "recover_guard_daemon_after_hook_failure",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("recovery failed")),
    )
    monkeypatch.setattr(
        recovery_worker,
        "clear_guard_daemon_recovery_reservation",
        lambda home, *, token: cleared.append((home, token)) or True,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recovery_worker",
            str(guard_home),
            str(tmp_path),
            "transport-failure",
            "recovery-token",
        ],
    )

    with pytest.raises(RuntimeError, match="recovery failed"):
        recovery_worker.main()

    assert cleared == [(guard_home, "recovery-token")]
