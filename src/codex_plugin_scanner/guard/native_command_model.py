"""Shadow-only Python bridge to the native command model.

This module never makes a PreToolUse decision. It exists to exercise and compare
the native parser through the same version-matched resident runtime used by the
PostToolUse path. Python remains authoritative until later rollout gates land.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resident import resident_native_request

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_SEGMENTS = 128
_MAX_TOKENS = 2_048
_REQUIRED_FEATURE = "pre-tool-command-model-shadow-v1"
_RESIDENT_FEATURE = "resident-command-model-shadow-v1"


def _decode_command_model(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    normalized_text = payload.get("normalized_text")
    dialect = payload.get("dialect")
    transport = payload.get("transport")
    provenance = payload.get("extraction_provenance")
    wrapper_chain = payload.get("wrapper_chain")
    segments = payload.get("segments")
    confidence = payload.get("confidence")
    uncertainty_reason = payload.get("uncertainty_reason")
    path_overridden = payload.get("path_overridden")
    parser_profile = payload.get("parser_profile")
    if (
        not isinstance(normalized_text, str)
        or not isinstance(dialect, str)
        or not isinstance(transport, str)
        or not isinstance(provenance, str)
        or not isinstance(wrapper_chain, list)
        or not all(isinstance(value, str) for value in wrapper_chain)
        or not isinstance(segments, list)
        or len(segments) > _MAX_SEGMENTS
        or confidence not in {"exact", "uncertain"}
        or uncertainty_reason is not None
        and not isinstance(uncertainty_reason, str)
        or not isinstance(path_overridden, bool)
        or not isinstance(parser_profile, str)
    ):
        return None

    total_tokens = 0
    for segment in segments:
        if not isinstance(segment, dict):
            return None
        tokens = segment.get("tokens")
        arguments = segment.get("arguments")
        environment_names = segment.get("environment_names")
        segment_wrappers = segment.get("wrapper_chain")
        executable = segment.get("executable")
        span = segment.get("span")
        pipeline_index = segment.get("pipeline_index")
        if (
            not isinstance(segment.get("text"), str)
            or not isinstance(tokens, list)
            or not all(isinstance(value, str) for value in tokens)
            or not isinstance(arguments, list)
            or not all(isinstance(value, str) for value in arguments)
            or not isinstance(environment_names, list)
            or not all(isinstance(value, str) for value in environment_names)
            or not isinstance(segment_wrappers, list)
            or not all(isinstance(value, str) for value in segment_wrappers)
            or executable is not None
            and not isinstance(executable, str)
            or not isinstance(segment.get("path_overridden"), bool)
            or not isinstance(segment.get("execution_context"), str)
            or not isinstance(pipeline_index, int)
            or pipeline_index < 0
            or not isinstance(span, dict)
            or span.get("source") != "normalized"
            or not isinstance(span.get("start"), int)
            or not isinstance(span.get("end"), int)
            or span["start"] < 0
            or span["end"] < span["start"]
        ):
            return None
        total_tokens += len(tokens)
        if total_tokens > _MAX_TOKENS:
            return None
    return payload


def _request_payload(
    command: str,
    *,
    dialect: str,
    transport: str,
    extraction_provenance: str,
) -> tuple[dict[str, str], bytes] | None:
    request = {
        "command": command,
        "dialect": dialect,
        "transport": transport,
        "extraction_provenance": extraction_provenance,
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    return request, encoded


def review_command_model_native(
    command: str,
    *,
    guard_home: Path,
    dialect: str = "posix",
    transport: str = "shell_string",
    extraction_provenance: str = "guard-shell",
    timeout_seconds: float = 0.25,
) -> dict[str, Any] | None:
    """Return native command-model evidence in explicit shadow/force modes only."""
    status = native_runtime_status()
    if (
        status.mode not in {"shadow", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _REQUIRED_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return None
    prepared = _request_payload(
        command,
        dialect=dialect,
        transport=transport,
        extraction_provenance=extraction_provenance,
    )
    if prepared is None:
        return None
    request, request_bytes = prepared
    timeout_seconds = min(timeout_seconds, 1.0)
    environment = _isolated_environment()

    if _RESIDENT_FEATURE in status.capabilities.features:
        resident_envelope = json.dumps(
            {"operation": "command_model", "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        resident_output = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=guard_home,
            environment=environment,
            payload=resident_envelope,
            timeout_seconds=timeout_seconds,
        )
        if resident_output is not None:
            try:
                decoded = _decode_command_model(json.loads(resident_output))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if decoded is not None:
                return decoded

    result = run_isolated_hook_process(
        (str(status.identity.path), "command-model", "--stdin"),
        input_text=request_bytes.decode("utf-8"),
        cwd=status.identity.path.parent,
        environment=environment,
        timeout_seconds=timeout_seconds,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
        return None
    try:
        return _decode_command_model(json.loads(result.stdout))
    except json.JSONDecodeError:
        return None


__all__ = ["review_command_model_native"]
