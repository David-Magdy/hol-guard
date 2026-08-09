"""Python interpreter and pytest configuration trust."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from ..false_positive_rules import fd_arg_requests_exec
from ..pytest_config import PYTEST_CONFIG_PATH_INVALID, PytestConfigAssessment, combine_pytest_config_assessments
from ..shell_command_wrappers import is_trusted_absolute_command_path
from ..shell_execution_context import ShellExecutionContext, validate_shell_execution_segment
from .constants_core import _FIND_EXEC_ACTION_FLAGS, _TRUSTED_INTERPRETER_INSTALL_ROOTS
from .constants_patterns import _PYTEST_COMMAND_NAMES, _PYTEST_COMMAND_RUNNER_SUBCOMMANDS, _PYTEST_EXECUTOR_COMMANDS
from .credential_exfiltration import _local_shell_script_payloads
from .github_pr_body_safety import _shell_heredoc_payloads
from .github_pr_expansion import _is_pytest_python_interpreter_command
from .github_shell_capabilities import (
    _env_split_string_payloads,
    _iter_shell_pipelines,
    _shell_command_scripts,
    _shell_command_substitution_payloads,
)
from .network_upload_detection import (
    _command_uses_curl_stdin_heredoc,
    _curl_segment_reads_config_from_stdin,
    _curl_segment_uses_file_upload,
    _segment_uses_network_file_upload,
)
from .pytest_config_safety import _pytest_config_assessment
from .pytest_target_detection import (
    _pytest_args_from_argument_sequence,
    _pytest_args_from_runner_argument_sequence,
    _segment_targets_pytest,
    _shell_command_targets_pytest,
)
from .python_pytest_entrypoints import _pytest_args_from_python
from .request_artifacts import _normalized_shell_command_name
from .shell_stdin_sources import _shell_pipeline_stdin_payloads, _shell_pipeline_stdin_uses_local_file
from .shell_tokenization import _shell_segment_primary_command, _split_shell_parts


def _contains_shell_network_file_upload(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _curl_stdin_config_uses_file_upload(
        normalized,
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    ):
        return True
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            if _segment_uses_network_file_upload(
                segment,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                stdin_uses_local_file=_shell_pipeline_stdin_uses_local_file(
                    pipeline,
                    index,
                    cwd=cwd,
                    home_dir=home_dir,
                ),
            ):
                return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_network_file_upload(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_network_file_upload(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_network_file_upload(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_network_file_upload(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _curl_stdin_config_uses_file_upload(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> bool:
    heredoc_payloads = _shell_heredoc_payloads(command_text)
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            command_name, command_index = _shell_segment_primary_command(segment)
            if command_name != "curl" or command_index is None:
                continue
            segment_args = segment[command_index + 1 :]
            pipeline_stdin_payloads = _shell_pipeline_stdin_payloads(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
            )
            pipeline_stdin_uses_local_file = _shell_pipeline_stdin_uses_local_file(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
            )
            if pipeline_stdin_payloads and _curl_segment_uses_file_upload(
                segment_args,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                stdin_config_payloads=pipeline_stdin_payloads,
                stdin_uses_local_file=pipeline_stdin_uses_local_file,
            ):
                return True
            if (
                heredoc_payloads
                and not pipeline_stdin_payloads
                and _curl_segment_reads_config_from_stdin(segment_args)
                and _command_uses_curl_stdin_heredoc(command_text)
                and _curl_segment_uses_file_upload(
                    segment_args,
                    cwd=cwd,
                    home_dir=home_dir,
                    stdin_config_payloads=tuple((payload, cwd) for payload in heredoc_payloads),
                )
            ):
                return True
    return False


def _pytest_config_assessment_for_command(
    command_text: str,
    *,
    cwd: Path | None,
    execution_context: ShellExecutionContext,
) -> PytestConfigAssessment:
    if cwd is None:
        return PytestConfigAssessment((), False, True, (PYTEST_CONFIG_PATH_INVALID,), None)
    assessments: list[PytestConfigAssessment] = []
    for context_segment in execution_context.segments:
        if context_segment.directory_operation is not None:
            continue
        segment = list(context_segment.tokens)
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if not _segment_targets_pytest(segment, command_name, command_index):
            continue
        segment_cwd, reason_code = validate_shell_execution_segment(execution_context, context_segment)
        if segment_cwd is None or reason_code is not None:
            assessments.append(
                PytestConfigAssessment((), False, True, (reason_code or PYTEST_CONFIG_PATH_INVALID,), None)
            )
            continue
        pytest_args = _pytest_args_from_segment(segment, command_index)
        assessments.append(
            _pytest_config_assessment(segment_cwd, pytest_args)
            if pytest_args is not None
            else PytestConfigAssessment((), False, True, (PYTEST_CONFIG_PATH_INVALID,), None)
        )
    if not assessments and _shell_command_targets_pytest(command_text):
        assessments.append(_pytest_config_assessment(cwd, []))
    return combine_pytest_config_assessments(assessments)


def _pytest_args_from_segment(segment: list[str], command_index: int) -> list[str] | None:
    command_name = _normalized_shell_command_name(segment[command_index])
    command_args = segment[command_index + 1 :]
    if command_name in _PYTEST_COMMAND_NAMES:
        return command_args
    if _is_pytest_python_interpreter_command(command_name):
        return _pytest_args_from_python(command_args)
    if command_name == "uvx" or command_name in _PYTEST_EXECUTOR_COMMANDS:
        return _pytest_args_from_argument_sequence(command_args)
    runner_subcommands = _PYTEST_COMMAND_RUNNER_SUBCOMMANDS.get(command_name)
    if runner_subcommands is not None:
        for index, token in enumerate(command_args):
            if token in runner_subcommands:
                return _pytest_args_from_runner_argument_sequence(command_name, command_args[index + 1 :])
        return None
    if command_name == "find":
        for index, token in enumerate(command_args):
            if token in _FIND_EXEC_ACTION_FLAGS:
                return _pytest_args_from_argument_sequence(command_args[index + 1 :])
        return None
    if command_name == "fd":
        for index, token in enumerate(command_args):
            if fd_arg_requests_exec(token):
                return _pytest_args_from_argument_sequence(command_args[index + 1 :])
        return None
    return None


def _python_interpreter_trust(
    raw_token: str,
    *,
    identity: dict[str, object],
    workspace_root: Path,
    home_dir: Path | None,
    resolution_reason: str | None,
) -> str:
    status = str(identity.get("status") or "unknown")
    if resolution_reason is not None and not _interpreter_token_has_path(raw_token):
        return "ambiguous"
    if status in {"unresolved", "unreadable", "path_unreadable"}:
        return "missing"
    if status == "not_executable":
        return "non_executable"
    if status != "verified":
        return "ambiguous" if status in {"foreign_platform_path", "invalid_path", "path_changed"} else "unknown"
    raw_launch_path = identity.get("launch_path")
    canonical_path = identity.get("path")
    if not isinstance(raw_launch_path, str) or not isinstance(canonical_path, str):
        return "unknown"
    launch_path = Path(raw_launch_path)
    canonical = Path(canonical_path)
    try:
        guard_launch = Path(sys.executable).expanduser().absolute()
        guard_canonical = guard_launch.resolve(strict=True)
    except (OSError, RuntimeError):
        guard_launch = Path(sys.executable).expanduser().absolute()
        guard_canonical = guard_launch
    if canonical == guard_canonical and (
        launch_path in {guard_launch, guard_canonical} or launch_path.parent == guard_launch.parent
    ):
        return "trusted_guard"
    if _interpreter_path_is_within(launch_path, workspace_root):
        return "workspace_local"
    if home_dir is not None and _interpreter_path_is_within(launch_path, home_dir):
        return "user_controlled"
    if os.name == "nt":
        return "user_controlled"
    if any(
        _interpreter_path_is_within(launch_path, trusted_root) for trusted_root in _TRUSTED_INTERPRETER_INSTALL_ROOTS
    ) and _interpreter_identity_path_chain_is_stable(identity):
        return "trusted_system"
    try:
        if is_trusted_absolute_command_path(launch_path, cwd=workspace_root, home_dir=home_dir):
            return "trusted_system"
    except (OSError, RuntimeError):
        pass
    return "user_controlled"


def _interpreter_identity_path_chain_is_stable(identity: dict[str, object]) -> bool:
    path_chain = identity.get("path_chain")
    if not isinstance(path_chain, list) or not path_chain:
        return False
    for item in path_chain:
        if not isinstance(item, dict):
            return False
        mode = item.get("mode")
        if not isinstance(mode, int) or mode & 0o022:
            return False
    return True


def _interpreter_token_has_path(raw_token: str) -> bool:
    normalized = raw_token.strip()
    return (
        "/" in normalized
        or "\\" in normalized
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or normalized.startswith("//")
    )


def _interpreter_path_is_within(path: Path, root: Path) -> bool:
    try:
        path.absolute().relative_to(root.absolute())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


__all__ = [
    "_contains_shell_network_file_upload",
    "_curl_stdin_config_uses_file_upload",
    "_interpreter_identity_path_chain_is_stable",
    "_interpreter_path_is_within",
    "_interpreter_token_has_path",
    "_pytest_args_from_segment",
    "_pytest_config_assessment_for_command",
    "_python_interpreter_trust",
]
