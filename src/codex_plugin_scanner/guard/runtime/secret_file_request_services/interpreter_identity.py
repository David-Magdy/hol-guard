"""Python interpreter identity resolution."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..interpreter_options import shell_interpreter_command_payload as _shell_interpreter_command_payload
from ..shell_execution_context import (
    ShellExecutionContext,
    model_shell_execution_context,
    validate_shell_execution_segment,
)
from .constants_core import _SHELL_COMMAND_STRING_INTERPRETERS
from .github_shell_capabilities import _shell_command_substitution_payloads
from .interpreter_launch import (
    _ambiguous_python_evidence_from_tokens,
    _normalized_interpreter_cwd,
    _python_interpreter_executable_identity,
    _shell_launch_candidate,
    _without_interpreter_reuse_nonces,
)
from .request_artifacts import _normalized_shell_command_name
from .shell_static_safety import _is_python_interpreter_command
from .shell_tokenization import _shell_command_token_without_attached_redirection, _split_shell_parts


def _python_interpreter_executable_identities(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    environment: dict[str, str] | None = None,
    workspace_root: Path | None = None,
    execution_context: ShellExecutionContext | None = None,
    depth: int = 0,
) -> tuple[dict[str, object], ...]:
    """Resolve exact Python tokens without executing candidate interpreters."""

    initial_cwd = _normalized_interpreter_cwd(cwd)
    root = _normalized_interpreter_cwd(workspace_root or cwd)
    inherited_environment = dict(os.environ if environment is None else environment)
    if depth > 8:
        return _ambiguous_python_evidence_from_tokens(
            _split_shell_parts(command_text),
            cwd=initial_cwd,
            environment=inherited_environment,
            workspace_root=root,
            home_dir=home_dir,
            reason="nested_shell_depth_exceeded",
        )

    execution_context = execution_context or model_shell_execution_context(
        command_text,
        cwd=initial_cwd,
        workspace_root=root,
    )
    evidence: list[dict[str, object]] = []
    for context_segment in execution_context.segments:
        if context_segment.directory_operation is not None:
            continue
        segment_cwd, context_reason = validate_shell_execution_segment(execution_context, context_segment)
        if segment_cwd is None or context_reason is not None:
            evidence.extend(
                _ambiguous_python_evidence_from_tokens(
                    list(context_segment.tokens),
                    cwd=initial_cwd,
                    environment=inherited_environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    reason=context_reason or "interpreter_cwd_unresolved",
                )
            )
            continue
        candidate = _shell_launch_candidate(
            list(context_segment.tokens),
            cwd=segment_cwd,
            environment=inherited_environment,
        )
        if candidate is None:
            evidence.extend(
                _ambiguous_python_evidence_from_tokens(
                    list(context_segment.tokens),
                    cwd=segment_cwd,
                    environment=inherited_environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    reason="interpreter_wrapper_unresolved",
                )
            )
            continue
        raw_token = _shell_command_token_without_attached_redirection(candidate.tokens[candidate.command_index]).strip()
        if _is_python_interpreter_command(raw_token):
            evidence.append(
                _python_interpreter_executable_identity(
                    raw_token,
                    cwd=candidate.effective_cwd,
                    environment=candidate.environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    resolution_reason=candidate.resolution_reason,
                )
            )
        command_name = _normalized_shell_command_name(raw_token)
        if command_name in _SHELL_COMMAND_STRING_INTERPRETERS:
            payload = _shell_interpreter_command_payload(
                list(candidate.tokens),
                candidate.command_index,
            )
            if payload is not None:
                evidence.extend(
                    _python_interpreter_executable_identities(
                        payload.script_text,
                        cwd=candidate.effective_cwd,
                        home_dir=home_dir,
                        environment=candidate.environment,
                        workspace_root=root,
                        depth=depth + 1,
                    )
                )
    for payload in _shell_command_substitution_payloads(command_text):
        evidence.extend(
            _python_interpreter_executable_identities(
                payload,
                cwd=initial_cwd,
                home_dir=home_dir,
                environment=inherited_environment,
                workspace_root=root,
                depth=depth + 1,
            )
        )
    unique: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in evidence:
        stable_item = _without_interpreter_reuse_nonces(item)
        key = json.dumps(stable_item, sort_keys=True, separators=(",", ":"), default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return tuple(unique)


__all__ = [
    "_python_interpreter_executable_identities",
]
