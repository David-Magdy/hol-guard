"""Explicitly opt-in, bounded runtime assurance for known extension commands.

This module never executes a scanned artifact during a normal static scan. It
constructs and validates an OCI sandbox plan, then runs only when a caller
explicitly invokes the detonation command with an immutable image digest.
"""

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

RUNTIME_EVIDENCE_SCHEMA = "extension-runtime-evidence.v1"
_IMAGE_DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_ALLOWED_ENGINES = frozenset({"docker", "podman"})


class SandboxError(ValueError):
    """Raised when a runtime assurance request violates sandbox policy."""


@dataclass(frozen=True, slots=True)
class SandboxPlan:
    engine: str
    image: str
    target: Path
    command: tuple[str, ...]
    output_dir: Path | None = None
    timeout_seconds: int = 20
    memory_megabytes: int = 512
    cpu_limit: float = 1.0
    pids_limit: int = 64
    file_size_megabytes: int = 64
    trace_syscalls: bool = False


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    evidence: dict[str, Any]
    stdout: str
    stderr: str


def _validate_plan(plan: SandboxPlan) -> SandboxPlan:
    engine = plan.engine.strip().lower()
    if engine not in _ALLOWED_ENGINES:
        raise SandboxError("runtime assurance requires Docker or Podman")
    binary = shutil.which(engine)
    if binary is None:
        raise SandboxError(f"{engine} is not installed")
    if not _IMAGE_DIGEST_RE.fullmatch(plan.image):
        raise SandboxError("sandbox image must be pinned to an immutable sha256 digest")
    target = plan.target.resolve()
    if not target.is_dir():
        raise SandboxError("sandbox target must be an existing directory")
    if not plan.command or len(plan.command) > 128:
        raise SandboxError("sandbox command must contain between 1 and 128 arguments")
    if any(not item or "\x00" in item or len(item) > 8192 for item in plan.command):
        raise SandboxError("sandbox command contains an invalid argument")
    if not 1 <= plan.timeout_seconds <= 300:
        raise SandboxError("sandbox timeout must be between 1 and 300 seconds")
    if not 64 <= plan.memory_megabytes <= 4096:
        raise SandboxError("sandbox memory must be between 64 and 4096 MiB")
    if not 0.1 <= plan.cpu_limit <= 4.0:
        raise SandboxError("sandbox CPU limit must be between 0.1 and 4.0")
    if not 8 <= plan.pids_limit <= 512:
        raise SandboxError("sandbox process limit must be between 8 and 512")
    if not 1 <= plan.file_size_megabytes <= 1024:
        raise SandboxError("sandbox file-size limit must be between 1 and 1024 MiB")
    output = plan.output_dir.resolve() if plan.output_dir else None
    if output is not None:
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        if output == target or output.is_relative_to(target):
            raise SandboxError("runtime evidence output must not be inside the untrusted target")
    return SandboxPlan(
        engine=engine,
        image=plan.image,
        target=target,
        command=plan.command,
        output_dir=output,
        timeout_seconds=plan.timeout_seconds,
        memory_megabytes=plan.memory_megabytes,
        cpu_limit=plan.cpu_limit,
        pids_limit=plan.pids_limit,
        file_size_megabytes=plan.file_size_megabytes,
        trace_syscalls=plan.trace_syscalls,
    )


def build_sandbox_command(plan: SandboxPlan) -> tuple[str, ...]:
    """Build a fail-closed OCI command for the validated plan."""

    validated = _validate_plan(plan)
    command: list[str] = [
        validated.engine,
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={validated.pids_limit}",
        f"--memory={validated.memory_megabytes}m",
        f"--cpus={validated.cpu_limit:g}",
        "--user=65534:65534",
        "--ipc=none",
        "--uts=private",
        "--mount",
        f"type=bind,src={validated.target},dst=/workspace,readonly",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--workdir=/workspace",
        "--ulimit",
        f"fsize={validated.file_size_megabytes * 1024}:{validated.file_size_megabytes * 1024}",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "nproc=64:64",
    ]
    if validated.output_dir is not None:
        command.extend(
            (
                "--mount",
                f"type=bind,src={validated.output_dir},dst=/evidence,rw",
            )
        )
    command.append(validated.image)
    if validated.trace_syscalls:
        if validated.output_dir is None:
            raise SandboxError("syscall tracing requires a separate evidence output directory")
        command.extend(
            (
                "strace",
                "-ff",
                "-qq",
                "-e",
                "trace=%file,%network,%process,%creds",
                "-o",
                "/evidence/syscalls",
                "--",
            )
        )
    command.extend(validated.command)
    return tuple(command)


def _bounded_text(data: bytes, limit: int = 256 * 1024) -> tuple[str, bool]:
    truncated = len(data) > limit
    value = data[:limit].decode("utf-8", errors="replace")
    return value, truncated


def _target_digest(target: Path) -> str:
    hasher = hashlib.sha256()
    excluded = {".git", "node_modules", ".venv", "venv", "target", "dist", "build", "__pycache__"}
    for path in sorted(item for item in target.rglob("*") if item.is_file() and not item.is_symlink()):
        relative = path.relative_to(target)
        if any(part in excluded for part in relative.parts):
            continue
        hasher.update(relative.as_posix().encode("utf-8"))
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
        except OSError:
            hasher.update(b"[unreadable]")
    return hasher.hexdigest()


def _trace_inventory(output_dir: Path | None) -> tuple[list[dict[str, Any]], bool]:
    if output_dir is None:
        return [], False
    traces: list[dict[str, Any]] = []
    trace_files = sorted(output_dir.glob("syscalls*"))
    total_bytes = 0
    for path in trace_files[:256]:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        total_bytes += len(data)
        if total_bytes > 16 * 1024 * 1024:
            return traces, False
        text = data.decode("utf-8", errors="replace")
        traces.append(
            {
                "file": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "networkCalls": text.count("connect(") + text.count("sendto("),
                "processCalls": text.count("execve(") + text.count("clone(") + text.count("fork("),
                "writeCalls": text.count("openat(") + text.count("rename(") + text.count("unlink("),
            }
        )
    return traces, bool(trace_files)


def run_sandbox(plan: SandboxPlan) -> SandboxExecution:
    """Execute an explicitly requested command inside the validated OCI sandbox."""

    validated = _validate_plan(plan)
    command = build_sandbox_command(validated)
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=validated.timeout_seconds,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return_code: int | None = completed.returncode
        timed_out = False
        stdout_bytes = completed.stdout
        stderr_bytes = completed.stderr
    except subprocess.TimeoutExpired as exc:
        return_code = None
        timed_out = True
        stdout_bytes = exc.stdout or b""
        stderr_bytes = exc.stderr or b""
    stdout, stdout_truncated = _bounded_text(stdout_bytes)
    stderr, stderr_truncated = _bounded_text(stderr_bytes)
    traces, trace_complete = _trace_inventory(validated.output_dir)
    controls = {
        "networkDisabled": True,
        "readOnlyRoot": True,
        "readOnlyTarget": True,
        "allCapabilitiesDropped": True,
        "noNewPrivileges": True,
        "nonRootUser": True,
        "resourceLimits": True,
        "separateWritableEvidenceMount": validated.output_dir is not None,
    }
    evidence: dict[str, Any] = {
        "schemaVersion": RUNTIME_EVIDENCE_SCHEMA,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "startedAt": started_at,
        "targetDigest": _target_digest(validated.target),
        "engine": validated.engine,
        "image": validated.image,
        "commandDigest": hashlib.sha256(json.dumps(list(validated.command)).encode("utf-8")).hexdigest(),
        "controls": controls,
        "outcome": {
            "returnCode": return_code,
            "timedOut": timed_out,
            "stdoutSha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
            "stdoutTruncated": stdout_truncated,
            "stderrTruncated": stderr_truncated,
        },
        "trace": {
            "requested": validated.trace_syscalls,
            "complete": trace_complete if validated.trace_syscalls else False,
            "files": traces,
        },
        "plan": {
            **asdict(validated),
            "target": str(validated.target),
            "output_dir": str(validated.output_dir) if validated.output_dir else None,
            "command": list(validated.command),
        },
    }
    return SandboxExecution(evidence=evidence, stdout=stdout, stderr=stderr)


def validate_runtime_evidence(payload: object, *, target_digest: str) -> tuple[str, tuple[str, ...]]:
    """Validate runtime evidence and return its assurance status and limitations."""

    if not isinstance(payload, dict) or payload.get("schemaVersion") != RUNTIME_EVIDENCE_SCHEMA:
        return "failed", ("Runtime evidence schema is unsupported.",)
    if payload.get("targetDigest") != target_digest:
        return "failed", ("Runtime evidence does not match the current target digest.",)
    controls = payload.get("controls")
    if not isinstance(controls, dict):
        return "failed", ("Runtime evidence does not describe sandbox controls.",)
    required = (
        "networkDisabled",
        "readOnlyRoot",
        "readOnlyTarget",
        "allCapabilitiesDropped",
        "noNewPrivileges",
        "nonRootUser",
        "resourceLimits",
    )
    missing = tuple(name for name in required if controls.get(name) is not True)
    trace = payload.get("trace")
    trace_complete = isinstance(trace, dict) and trace.get("complete") is True
    if missing:
        return "failed", tuple(f"Required sandbox control was not proven: {name}." for name in missing)
    if not trace_complete:
        return "partial", ("Execution was contained, but syscall trace completeness was not proven.",)
    return "verified", ()
