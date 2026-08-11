from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_model import review_command_model_native
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
    resident_service_starts,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="resident native service is POSIX-only in this wave")


def _runtime_from_environment() -> Path:
    value = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert value, "HOL_GUARD_NATIVE_BINARY is required for resident integration"
    return Path(value).resolve(strict=True)


def test_command_model_reuses_version_matched_resident_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime_from_environment()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    close_resident_native_runtimes()
    with tempfile.TemporaryDirectory(prefix="hgr-", dir="/tmp") as short_tmp:
        guard_home = Path(short_tmp) / "guard-home"
        guard_home.mkdir(mode=0o700)
        try:
            first = review_command_model_native("git status --short", guard_home=guard_home)
            second = review_command_model_native("printf 'a|b' | grep b", guard_home=guard_home)
            assert first is not None
            assert first["confidence"] == "exact"
            assert first["segments"][0]["executable"] == "git"
            assert second is not None
            assert second["confidence"] == "exact"
            assert [segment["pipeline_index"] for segment in second["segments"]] == [0, 1]

            status = native_runtime_status()
            assert status.identity is not None
            assert status.capabilities is not None
            assert "resident-command-model-shadow-v1" in status.capabilities.features
            assert (
                resident_service_starts(
                    executable=runtime,
                    identity_sha256=status.identity.sha256,
                    guard_home=guard_home,
                )
                == 1
            )
        finally:
            close_resident_native_runtimes()


def test_complex_command_remains_non_authoritative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    close_resident_native_runtimes()
    try:
        model = review_command_model_native("echo $(uname) > out.txt", guard_home=guard_home)
        assert model is not None
        assert model["confidence"] == "uncertain"
        assert model["segments"] == []
        assert model["uncertainty_reason"]
    finally:
        close_resident_native_runtimes()


def test_command_model_bridge_is_disabled_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    assert review_command_model_native("git status", guard_home=guard_home) is None
