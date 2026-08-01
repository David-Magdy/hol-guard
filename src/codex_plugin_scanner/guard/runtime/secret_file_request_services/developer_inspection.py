"""Low-risk developer inspection classification."""

from __future__ import annotations

import os
from pathlib import Path

from ..compound_git_inspection import is_low_risk_compound_git_inspection, is_low_risk_git_inspection_segment
from ..direct_vitest import direct_local_typescript_execution_context
from ..false_positive_rules import (
    fd_arg_requests_exec,
    fd_args_follow_symlinks,
    fd_exec_token_is_plain_sed,
    fd_search_targets,
    split_fd_args_and_exec,
)
from ..github_capability_interaction import github_capability_requires_confirmation
from ..shell_execution_context import ShellExecutionContext, model_shell_execution_context
from .constants_core import (
    _FIND_EXEC_ACTION_FLAGS,
    _FIND_EXEC_PLACEHOLDER_TARGET,
    _FIND_EXEC_TERMINATOR_TOKENS,
    _READ_ONLY_LOOKUP_COMMANDS,
    _READ_ONLY_LOOKUP_FILTERS,
    _READ_ONLY_SEARCH_EXECUTION_FLAGS,
    _SAFE_STATIC_SHELL_COMMANDS,
)
from .constants_patterns import _FIND_PATH_VALUE_PREDICATES
from .docker_requests import shell_execution_context_starts_with_literal_cd
from .github_shell_capabilities import classify_github_shell_capabilities
from .local_read_operands import _local_read_operands_resolve_safely, _search_file_operand_tokens
from .read_only_filters import (
    _read_only_lookup_arg_is_redirection,
    _read_only_lookup_filter_segment_is_safe,
    _read_only_lookup_head_tail_args_are_safe,
    _read_only_lookup_sed_args_are_safe,
    _read_only_lookup_target_is_safe,
)
from .shell_static_safety import (
    _is_python_interpreter_command,
    _leading_literal_cd_workspace_root,
    _path_text_is_within_root,
    _safe_cli_metadata_segment_is_safe,
    _script_interpreter_texts,
    _script_is_read_only_observer,
    _shell_syntax_check_segment_is_safe,
    _shell_token_escapes_root,
    _shell_token_has_command_substitution,
    _without_safe_inspection_redirections,
)
from .shell_tokenization import _shell_segment_primary_command


def _low_risk_compound_developer_execution_context(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recognize one inspection chain after optional delay handling."""

    initial_root = cwd or home_dir
    context = model_shell_execution_context(
        command_text,
        cwd=initial_root,
        workspace_root=initial_root,
        home_dir=home_dir,
    )
    workspace_root = _leading_literal_cd_workspace_root(context, home_dir=home_dir)
    if workspace_root is not None and workspace_root != home_dir.resolve():
        context = model_shell_execution_context(
            command_text,
            cwd=workspace_root,
            workspace_root=workspace_root,
            home_dir=home_dir,
        )
    starts_with_literal_cd = shell_execution_context_starts_with_literal_cd(context)
    if not starts_with_literal_cd and cwd is None:
        return None
    if is_low_risk_compound_git_inspection(context):
        return context
    typescript_context = direct_local_typescript_execution_context(
        command_text,
        cwd=cwd,
        home_dir=home_dir,
    )
    if typescript_context is not None:
        return typescript_context
    github_assessment = classify_github_shell_capabilities(command_text, home_dir=home_dir)
    github_is_low_risk = github_assessment is not None and not github_capability_requires_confirmation(
        github_assessment
    )
    inspection_root = context.workspace_root or home_dir
    saw_inspection = False
    first_inspection_segment = 1 if starts_with_literal_cd else 0
    for segment in context.segments[first_inspection_segment:]:
        if any(
            control not in {"&&", "||", "|", ";", "\n"} for control in (*segment.control_before, *segment.control_after)
        ):
            return None
        command_name, command_index = _shell_segment_primary_command(list(segment.tokens))
        if command_name is None or command_index is None:
            return None
        args = _without_safe_inspection_redirections(list(segment.tokens[command_index + 1 :]))
        if args is None:
            return None
        segment_root = segment.effective_cwd or home_dir
        safe_pipe_filter = (
            command_name in _READ_ONLY_LOOKUP_FILTERS
            and segment.control_before == ("|",)
            and _read_only_lookup_filter_segment_is_safe(command_name, args, home_dir=segment_root)
        )
        root_checked_args = (
            list(_search_file_operand_tokens(command_name, args))
            if safe_pipe_filter and command_name in {"grep", "egrep", "fgrep"}
            else args
        )
        if not _path_text_is_within_root(os.fspath(segment_root), inspection_root):
            return None
        if any(_shell_token_escapes_root(arg, cwd=segment_root, root=inspection_root) for arg in root_checked_args):
            return None
        if segment.directory_operation is not None:
            continue
        if command_name == "git" and is_low_risk_git_inspection_segment(segment):
            saw_inspection = True
            continue
        if command_name == "gh" and github_is_low_risk:
            saw_inspection = True
            continue
        if _safe_cli_metadata_segment_is_safe(command_name, args, cwd=segment_root):
            saw_inspection = True
            continue
        if (
            command_name in _READ_ONLY_LOOKUP_COMMANDS
            and _read_only_lookup_primary_segment_is_safe(
                command_name,
                args,
                home_dir=segment_root,
            )
            and _local_read_operands_resolve_safely(
                command_name,
                args,
                cwd=segment_root,
                root=inspection_root,
            )
        ):
            saw_inspection = True
            continue
        if safe_pipe_filter:
            continue
        if (
            command_name == "wc"
            and args
            and all(
                arg in {"-c", "-l", "-w"}
                or (not arg.startswith("-") and not _shell_token_has_command_substitution(arg))
                for arg in args
            )
        ):
            saw_inspection = True
            continue
        if (
            command_name == "sort"
            and segment.control_before == ("|",)
            and all(arg in {"-n", "-r", "-u"} for arg in args)
        ):
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(args):
            continue
        if _shell_syntax_check_segment_is_safe(command_name, args):
            saw_inspection = True
            continue
        if _is_read_only_observer_interpreter_command(command_name):
            scripts = list(_script_interpreter_texts(list(segment.tokens)))
            if scripts and all(_script_is_read_only_observer(script) for script in scripts):
                saw_inspection = True
                continue
        return None
    return context if saw_inspection else None


def _read_only_lookup_primary_segment_is_safe(command: str, args: list[str], *, home_dir: Path | None) -> bool:
    if command == "sed":
        return _read_only_lookup_sed_args_are_safe(args, require_target=True, home_dir=home_dir)
    if command in {"head", "tail"}:
        return _read_only_lookup_head_tail_args_are_safe(args, require_target=True, home_dir=home_dir)
    if command == "cat":
        if args == [".git"]:
            return True
        return _read_only_lookup_plain_targets_are_safe(args, allow_dirs=False, home_dir=home_dir)
    if command == "ls":
        return _read_only_lookup_ls_args_are_safe(args, home_dir=home_dir)
    if command == "pwd":
        return all(arg in {"-L", "-P"} for arg in args)
    if command == "date":
        return _read_only_lookup_date_args_are_safe(args)
    if command in {"grep", "egrep", "fgrep", "rg"}:
        return _read_only_lookup_search_args_are_safe(command, args, home_dir=home_dir)
    if command == "fd":
        return _read_only_lookup_fd_args_are_safe(args, home_dir=home_dir)
    if command == "find":
        return _read_only_lookup_find_args_are_safe(args, home_dir=home_dir)
    return False


def _read_only_lookup_date_args_are_safe(args: list[str]) -> bool:
    if not args:
        return True
    saw_format = False
    for arg in args:
        if arg in {"-u", "--utc", "--universal"}:
            continue
        if arg.startswith("+") and len(arg) <= 256 and "\n" not in arg:
            if saw_format:
                return False
            saw_format = True
            continue
        return False
    return True


def _read_only_lookup_plain_targets_are_safe(
    args: list[str],
    *,
    allow_dirs: bool,
    home_dir: Path | None = None,
) -> bool:
    targets: list[str] = []
    after_options = False
    for arg in args:
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "-":
            return False
        if arg.startswith("-"):
            continue
        targets.append(arg)
    return all(_read_only_lookup_target_is_safe(target, allow_dirs=allow_dirs, home_dir=home_dir) for target in targets)


def _read_only_lookup_ls_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    return _read_only_lookup_plain_targets_are_safe(args, allow_dirs=True, home_dir=home_dir)


def _read_only_lookup_search_args_are_safe(
    command: str,
    args: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    execution_flags = _READ_ONLY_SEARCH_EXECUTION_FLAGS.get(command, frozenset())
    if any(arg in execution_flags or any(arg.startswith(f"{flag}=") for flag in execution_flags) for arg in args):
        return False
    targets = [arg for arg in args if arg and not arg.startswith("-")]
    return len(targets) < 2 or all(
        _read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in targets[1:]
    )


def _read_only_lookup_fd_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    if any(fd_arg_requests_exec(arg) for arg in args):
        return _fd_exec_sed_read_only_args_are_safe(args, home_dir=home_dir)
    targets = fd_search_targets(args)
    if targets is None:
        return False
    if not targets:
        return True
    return all(_read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in targets)


def _fd_exec_sed_read_only_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    parsed = split_fd_args_and_exec(args)
    if parsed is None:
        return False
    fd_args, exec_parts = parsed
    if not exec_parts or not fd_exec_token_is_plain_sed(exec_parts[0]):
        return False
    if exec_parts.count("{}") != 1:
        return False
    sed_args = [arg for arg in exec_parts[1:] if arg != "{}"]
    fd_targets = fd_search_targets(fd_args)
    if fd_targets is None or not fd_targets:
        return False
    return all(
        _read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in fd_targets
    ) and _read_only_lookup_sed_args_are_safe(
        sed_args,
        require_target=False,
        home_dir=home_dir,
    )


def _read_only_lookup_find_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if any(_read_only_lookup_arg_is_redirection(arg) for arg in args):
        return False
    if _find_args_use_write_or_unsafe_exec_action(args):
        return False
    leading_paths: list[str] = []
    for arg in args:
        if arg.startswith("-"):
            break
        if arg:
            leading_paths.append(arg)
    if not leading_paths:
        return False
    return all(_read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in leading_paths)


def _find_args_use_write_or_unsafe_exec_action(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in _FIND_PATH_VALUE_PREDICATES and index + 1 < len(args):
            index += 2
            continue
        if arg in {"-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}:
            return True
        if arg in _FIND_EXEC_ACTION_FLAGS:
            if index + 1 >= len(args):
                return True
            command_name = Path(args[index + 1]).name.lower()
            exec_args: list[str] = []
            exec_index = index + 2
            while exec_index < len(args) and args[exec_index] not in _FIND_EXEC_TERMINATOR_TOKENS:
                exec_args.append(args[exec_index])
                exec_index += 1
            is_safe_builtin = command_name in {"echo", "printf", "true", "false", "test", "["}
            is_read_only_sed = command_name == "sed" and _find_exec_sed_args_are_read_only(exec_args)
            if not is_safe_builtin and not is_read_only_sed:
                return True
            index = exec_index + 1 if exec_index < len(args) else exec_index
            continue
        index += 1
    return False


def _find_exec_sed_args_are_read_only(args: list[str]) -> bool:
    normalized_args = [_FIND_EXEC_PLACEHOLDER_TARGET if arg == "{}" else arg for arg in args]
    return _read_only_lookup_sed_args_are_safe(normalized_args, require_target=True)


def _static_shell_segment_is_safe(args: list[str]) -> bool:
    return all(_static_shell_arg_is_safe(arg) for arg in args)


def _static_shell_arg_is_safe(arg: str) -> bool:
    if "`" in arg or "$(" in arg or "<(" in arg or ">(" in arg:
        return False
    return "$" not in arg.replace("$?", "")


def _is_read_only_observer_interpreter_command(command_name: str) -> bool:
    return _is_python_interpreter_command(command_name)


__all__ = [
    "_fd_exec_sed_read_only_args_are_safe",
    "_find_args_use_write_or_unsafe_exec_action",
    "_find_exec_sed_args_are_read_only",
    "_is_read_only_observer_interpreter_command",
    "_low_risk_compound_developer_execution_context",
    "_read_only_lookup_date_args_are_safe",
    "_read_only_lookup_fd_args_are_safe",
    "_read_only_lookup_find_args_are_safe",
    "_read_only_lookup_ls_args_are_safe",
    "_read_only_lookup_plain_targets_are_safe",
    "_read_only_lookup_primary_segment_is_safe",
    "_read_only_lookup_search_args_are_safe",
    "_static_shell_arg_is_safe",
    "_static_shell_segment_is_safe",
]
