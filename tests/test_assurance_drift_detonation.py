"""Longitudinal drift and sandbox plan security tests."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.assurance.detonation import (
    DetonationError,
    build_plan,
    validate_observation,
)
from codex_plugin_scanner.assurance.drift import build_baseline, compare_baseline, validate_baseline
from codex_plugin_scanner.assurance.models import canonical_json_bytes


def _baseline(*, capability: tuple[str, ...] = (), control: tuple[str, ...] = ()):
    return build_baseline(
        artifact_digest="1" * 64,
        files=({"path": "plugin.py", "sha256": "2" * 64, "mode": 420, "size": 10},),
        dependencies=(),
        native_artifacts=(),
        capabilities=capability,
        security_controls=control,
    )


def test_baseline_digest_tamper_is_rejected() -> None:
    baseline = _baseline()
    validate_baseline(baseline)
    baseline["artifact_digest"] = "3" * 64
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_baseline(baseline)


def test_new_capability_and_removed_control_require_reapproval() -> None:
    before = _baseline(control=("policy.sandbox",))
    after = _baseline(capability=("credential-store",), control=())
    drift = compare_baseline(before, after)
    assert drift["changed"] is True
    assert drift["requires_reapproval"] is True
    assert drift["security_regressions"]["new_capabilities"] == ["credential-store"]
    assert drift["security_regressions"]["removed_security_controls"] == ["policy.sandbox"]


def test_detonation_plan_requires_immutable_image_and_no_shell_joining(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    with pytest.raises(DetonationError, match="immutable"):
        build_plan(tmp_path, image="scanner:latest", command=("python", "plugin.py"))
    plan = build_plan(
        tmp_path,
        image=f"registry.example/scanner@sha256:{'a' * 64}",
        command=("python", "plugin.py", "argument with spaces"),
    )
    arguments = list(plan.container_arguments)
    assert "--network=none" in arguments
    assert "--read-only" in arguments
    assert "--cap-drop=ALL" in arguments
    assert "--security-opt=no-new-privileges:true" in arguments
    assert any(value.startswith("--mount=") and value.endswith("readonly") for value in arguments)
    assert arguments[-1] == "argument with spaces"
    assert "sh -c" not in " ".join(arguments)


def test_detonation_observation_is_bound_to_plan(tmp_path: Path) -> None:
    plan = build_plan(
        tmp_path,
        image=f"registry.example/scanner@sha256:{'a' * 64}",
        command=("true",),
    )
    unsigned = {
        "schema_version": "hol-guard.detonation-observation.v1",
        "plan_digest": plan.plan_digest,
        "observed_at": "2026-08-16T00:00:00+00:00",
        "runtime": "docker",
        "return_code": 0,
        "timed_out": False,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_ms": 1,
    }
    observation = {
        **unsigned,
        "observation_digest": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }
    validate_observation(observation, expected_plan_digest=plan.plan_digest)
    tampered = copy.deepcopy(observation)
    tampered["return_code"] = 1
    with pytest.raises(DetonationError, match="digest mismatch"):
        validate_observation(tampered, expected_plan_digest=plan.plan_digest)
