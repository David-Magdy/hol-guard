"""Runtime assurance sandbox policy tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.runtime_assurance import (
    RUNTIME_EVIDENCE_SCHEMA,
    SandboxError,
    SandboxPlan,
    build_sandbox_command,
    validate_runtime_evidence,
)


def _plan(tmp_path: Path, **changes) -> SandboxPlan:
    values = {
        "engine": "docker",
        "image": "registry.example.com/hol/guard-detonator@sha256:" + "a" * 64,
        "target": tmp_path / "target",
        "command": ("python", "plugin.py"),
        "output_dir": tmp_path / "evidence",
        "timeout_seconds": 20,
        "memory_megabytes": 512,
        "cpu_limit": 1.0,
        "pids_limit": 64,
        "trace_syscalls": True,
    }
    values.update(changes)
    values["target"].mkdir(parents=True, exist_ok=True)
    return SandboxPlan(**values)


def test_sandbox_command_contains_every_mandatory_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shutil.which", lambda _engine: "/usr/bin/docker")

    command = build_sandbox_command(_plan(tmp_path))
    rendered = "\n".join(command)

    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--user=65534:65534" in command
    assert "--ipc=none" in command
    assert any(value.startswith("--pids-limit=") for value in command)
    assert any(value.startswith("--memory=") for value in command)
    assert any(value.startswith("--cpus=") for value in command)
    assert "/workspace,readonly" in rendered
    assert "/evidence,rw" in rendered
    assert "strace" in command
    assert "trace=%file,%network,%process,%creds" in command


def test_mutable_image_reference_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _engine: "/usr/bin/docker")

    with pytest.raises(SandboxError, match="immutable"):
        build_sandbox_command(_plan(tmp_path, image="registry.example.com/hol/guard-detonator:latest"))


def test_evidence_output_cannot_be_inside_untrusted_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shutil.which", lambda _engine: "/usr/bin/docker")
    target = tmp_path / "target"
    target.mkdir()

    with pytest.raises(SandboxError, match="must not be inside"):
        build_sandbox_command(_plan(tmp_path, target=target, output_dir=target / "evidence"))


def test_runtime_evidence_requires_digest_controls_and_complete_trace() -> None:
    digest = "b" * 64
    evidence = {
        "schemaVersion": RUNTIME_EVIDENCE_SCHEMA,
        "targetDigest": digest,
        "controls": {
            "networkDisabled": True,
            "readOnlyRoot": True,
            "readOnlyTarget": True,
            "allCapabilitiesDropped": True,
            "noNewPrivileges": True,
            "nonRootUser": True,
            "resourceLimits": True,
        },
        "trace": {"complete": True},
    }

    assert validate_runtime_evidence(evidence, target_digest=digest) == ("verified", ())
    status, limitations = validate_runtime_evidence(
        {**evidence, "trace": {"complete": False}},
        target_digest=digest,
    )
    assert status == "partial"
    assert limitations
    status, limitations = validate_runtime_evidence(
        {**evidence, "controls": {**evidence["controls"], "networkDisabled": False}},
        target_digest=digest,
    )
    assert status == "failed"
    assert any("networkDisabled" in limitation for limitation in limitations)
    assert validate_runtime_evidence(evidence, target_digest="c" * 64)[0] == "failed"
