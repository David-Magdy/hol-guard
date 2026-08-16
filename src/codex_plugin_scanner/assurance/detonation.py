"""Immutable, no-network container detonation plans and bounded observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import canonical_json_bytes


DIGESTED_IMAGE_RE = re.compile(r"^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$")
ALLOWED_RUNTIMES = frozenset({"docker", "podman"})


class DetonationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DetonationLimits:
    timeout_seconds: int = 30
    memory: str = "256m"
    cpus: str = "0.5"
    pids: int = 64
    file_descriptors: int = 256
    output_bytes: int = 1_048_576
    tmpfs_size: str = "64m"

    def validate(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 600:
            raise DetonationError("timeout_seconds must be between 1 and 600")
        if self.pids <= 0 or self.pids > 4096:
            raise DetonationError("pids must be between 1 and 4096")
        if self.file_descriptors <= 0 or self.file_descriptors > 65_536:
            raise DetonationError("file_descriptors must be between 1 and 65536")
        if self.output_bytes <= 0 or self.output_bytes > 64 * 1024 * 1024:
            raise DetonationError("output_bytes is outside the allowed range")


@dataclass(frozen=True, slots=True)
class DetonationPlan:
    schema_version: str
    runtime: str
    image: str
    artifact_root: str
    command: tuple[str, ...]
    container_arguments: tuple[str, ...]
    limits: DetonationLimits
    network: str
    root_filesystem: str
    user: str
    security_options: tuple[str, ...]
    plan_digest: str

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["command"] = list(self.command)
        payload["container_arguments"] = list(self.container_arguments)
        payload["security_options"] = list(self.security_options)
        return payload


@dataclass(frozen=True, slots=True)
class DetonationObservation:
    schema_version: str
    plan_digest: str
    observed_at: str
    runtime: str
    return_code: int | None
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    observation_digest: str

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


def build_plan(
    artifact_root: Path,
    *,
    image: str,
    command: tuple[str, ...],
    runtime: str = "docker",
    limits: DetonationLimits | None = None,
    seccomp_profile: Path | None = None,
    use_gvisor: bool = False,
) -> DetonationPlan:
    limits = limits or DetonationLimits()
    limits.validate()
    if runtime not in ALLOWED_RUNTIMES:
        raise DetonationError("runtime must be docker or podman")
    if not DIGESTED_IMAGE_RE.fullmatch(image):
        raise DetonationError("detonation image must use an immutable sha256 digest")
    resolved = artifact_root.resolve(strict=True)
    if not resolved.is_dir():
        raise DetonationError("artifact root must be a directory")
    if not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        raise DetonationError("command must be a non-empty argument vector")
    if len(command) > 128 or sum(len(item) for item in command) > 16_384:
        raise DetonationError("command exceeds bounded plan limits")

    arguments = [
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--memory={limits.memory}",
        f"--cpus={limits.cpus}",
        f"--pids-limit={limits.pids}",
        f"--ulimit=nofile={limits.file_descriptors}:{limits.file_descriptors}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_size}",
        "--user=65534:65534",
        "--workdir=/extension",
        f"--mount=type=bind,src={resolved},dst=/extension,readonly",
    ]
    security_options = ["no-new-privileges:true"]
    if seccomp_profile is not None:
        profile = seccomp_profile.resolve(strict=True)
        if not profile.is_file():
            raise DetonationError("seccomp profile must be a file")
        arguments.append(f"--security-opt=seccomp={profile}")
        security_options.append(f"seccomp:{profile}")
    if use_gvisor:
        if runtime != "docker":
            raise DetonationError("gVisor runtime selection is supported only for docker plans")
        arguments.append("--runtime=runsc")
        security_options.append("runtime:runsc")
    arguments.append(image)
    arguments.extend(command)

    unsigned: dict[str, Any] = {
        "schema_version": "hol-guard.detonation-plan.v1",
        "runtime": runtime,
        "image": image,
        "artifact_root": str(resolved),
        "command": list(command),
        "container_arguments": arguments,
        "limits": asdict(limits),
        "network": "none",
        "root_filesystem": "read-only",
        "user": "65534:65534",
        "security_options": security_options,
    }
    plan_digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return DetonationPlan(
        schema_version="hol-guard.detonation-plan.v1",
        runtime=runtime,
        image=image,
        artifact_root=str(resolved),
        command=command,
        container_arguments=tuple(arguments),
        limits=limits,
        network="none",
        root_filesystem="read-only",
        user="65534:65534",
        security_options=tuple(security_options),
        plan_digest=plan_digest,
    )


def execute_plan(plan: DetonationPlan) -> DetonationObservation:
    _validate_plan_integrity(plan)
    runtime_path = shutil.which(plan.runtime)
    if runtime_path is None:
        raise DetonationError(f"container runtime not found: {plan.runtime}")
    started = datetime.now(timezone.utc)
    timed_out = False
    return_code: int | None
    try:
        completed = subprocess.run(
            [runtime_path, *plan.container_arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=plan.limits.timeout_seconds,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        return_code = None
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
    ended = datetime.now(timezone.utc)
    stdout_truncated = len(stdout) > plan.limits.output_bytes
    stderr_truncated = len(stderr) > plan.limits.output_bytes
    stdout = stdout[: plan.limits.output_bytes]
    stderr = stderr[: plan.limits.output_bytes]
    unsigned: dict[str, Any] = {
        "schema_version": "hol-guard.detonation-observation.v1",
        "plan_digest": plan.plan_digest,
        "observed_at": ended.isoformat(),
        "runtime": plan.runtime,
        "return_code": return_code,
        "timed_out": timed_out,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "duration_ms": max(0, int((ended - started).total_seconds() * 1000)),
    }
    digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return DetonationObservation(observation_digest=digest, **unsigned)


def validate_observation(observation: object, *, expected_plan_digest: str) -> None:
    if not isinstance(observation, dict):
        raise DetonationError("detonation observation must be an object")
    if observation.get("schema_version") != "hol-guard.detonation-observation.v1":
        raise DetonationError("unsupported detonation observation schema")
    if observation.get("plan_digest") != expected_plan_digest:
        raise DetonationError("detonation observation is not bound to the expected plan")
    digest = observation.get("observation_digest")
    if not isinstance(digest, str):
        raise DetonationError("detonation observation digest is missing")
    unsigned = dict(observation)
    unsigned.pop("observation_digest", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != digest:
        raise DetonationError("detonation observation digest mismatch")


def _validate_plan_integrity(plan: DetonationPlan) -> None:
    payload = plan.to_payload()
    expected = payload.pop("plan_digest")
    actual = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    if expected != actual:
        raise DetonationError("detonation plan digest mismatch")
    if plan.network != "none" or plan.root_filesystem != "read-only":
        raise DetonationError("detonation plan weakened mandatory isolation")
    joined = "\n".join(plan.container_arguments)
    required = (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "readonly",
        "--user=65534:65534",
    )
    if any(value not in joined for value in required):
        raise DetonationError("detonation plan is missing a mandatory isolation control")


def write_plan(path: Path, plan: DetonationPlan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_payload(), indent=2, sort_keys=True), encoding="utf-8")
