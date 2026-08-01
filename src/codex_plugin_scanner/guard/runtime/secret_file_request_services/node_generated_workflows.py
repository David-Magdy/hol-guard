"""Generated Node workflow and inline evaluation safety."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..false_positive_rules import fd_arg_requests_exec
from .constants_patterns import (
    _NODE_INLINE_EVAL_FLAGS,
    _NODE_OPTION_FLAGS_WITH_VALUE,
    _SAFE_NODE_GENERATED_FILE_ROOTS,
    _SINGLE_NODE_HEREDOC_PATTERN,
)
from .developer_inspection import _fd_exec_sed_read_only_args_are_safe, _find_args_use_write_or_unsafe_exec_action
from .github_pr_body_safety import _path_text_looks_sensitive
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command, _split_shell_parts
from .typescript_graphql_safety import (
    _SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN,
    _contains_destructive_node_inline_script,
    _contains_shell_expansion,
    _graphql_query_file_substitution_refs,
    _graphql_workflow_field_arg_is_safe,
    _strip_shell_quotes,
)


def _looks_like_safe_graphql_query_file_workflow(command_text: str) -> bool:
    match = _SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN.match(command_text)
    if match is None:
        return False
    target_path = _strip_shell_quotes(match.group("path").strip())
    if (
        not target_path.endswith(".graphql")
        or _path_text_looks_sensitive(target_path)
        or _contains_shell_expansion(target_path)
        or not _looks_like_temporary_pr_threads_query_path(target_path)
    ):
        return False
    body = match.group("body").strip()
    if not re.search(r"\bquery\b", body) or re.search(r"\bmutation\b|\bsubscription\b", body):
        return False
    rest = match.group("rest").strip()
    if not rest.startswith("gh api graphql "):
        return False
    if re.search(r"(?:;|&|\|\||\||>|<|\n)", rest):
        return False
    rest_without_allowed_query_refs = rest
    for ref in _graphql_query_file_substitution_refs(target_path):
        rest_without_allowed_query_refs = rest_without_allowed_query_refs.replace(ref, "")
    if "$(" in rest_without_allowed_query_refs or "`" in rest_without_allowed_query_refs:
        return False
    return _graphql_workflow_rest_args_are_safe(rest, target_path)


def _graphql_workflow_rest_args_are_safe(rest: str, target_path: str) -> bool:
    parts = _split_shell_parts(rest)
    if parts[:3] != ["gh", "api", "graphql"]:
        return False
    saw_query_arg = False
    index = 3
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return False
        if token in {"-F", "--field", "-f", "--raw-field"}:
            if index + 1 >= len(parts):
                return False
            if not _graphql_workflow_field_arg_is_safe(parts[index + 1], target_path):
                return False
            if parts[index + 1].startswith("query="):
                saw_query_arg = True
            index += 2
            continue
        if token.startswith("--field=") or token.startswith("--raw-field="):
            value = token.split("=", 1)[1]
        elif (token.startswith("-F") and len(token) > 2) or (token.startswith("-f") and len(token) > 2):
            value = token[2:]
        else:
            return False
        if not _graphql_workflow_field_arg_is_safe(value, target_path):
            return False
        if value.startswith("query="):
            saw_query_arg = True
        index += 1
    return saw_query_arg


def _looks_like_temporary_pr_threads_query_path(path_text: str) -> bool:
    normalized = os.path.normpath(path_text.replace("\\", "/")).replace("\\", "/")
    basename = os.path.basename(normalized)
    if basename != "pr-threads-query.graphql":
        return False
    if not normalized.startswith("/"):
        return False
    if os.path.exists(normalized):
        return False
    _temp_groups: tuple[frozenset[str], ...] = (
        frozenset({"/tmp/", "/private/tmp/"}),
        frozenset({"/var/tmp/", "/private/var/tmp/"}),
        frozenset({"/var/folders/", "/private/var/folders/"}),
    )

    def _temp_group_index(lowered: str) -> int:
        for idx, group in enumerate(_temp_groups):
            if any(lowered.startswith(prefix) for prefix in group):
                return idx
        return -1

    literal_group = _temp_group_index(normalized.lower())
    if literal_group == -1:
        return False
    resolved_lowered = os.path.realpath(normalized).replace("\\", "/").lower()
    return _temp_group_index(resolved_lowered) == literal_group


def _contains_destructive_node_inline_eval(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "node" or command_index is None:
            continue
        if _segment_contains_destructive_node_inline_eval(segment[command_index + 1 :]):
            return True
    return False


def _find_or_fd_uses_write_or_exec_action(parts: list[str], *, home_dir: Path | None = None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if (
            command_name == "find"
            and command_index is not None
            and _find_args_use_write_or_unsafe_exec_action(segment[command_index + 1 :])
        ):
            return True
        if (
            command_name == "fd"
            and command_index is not None
            and any(fd_arg_requests_exec(arg) for arg in segment[command_index + 1 :])
            and not _fd_exec_sed_read_only_args_are_safe(segment[command_index + 1 :], home_dir=home_dir)
        ):
            return True
    return False


def _single_node_heredoc_script(command_text: str) -> str | None:
    match = _SINGLE_NODE_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    args = match.group("args").strip()
    if args not in {"", "-"}:
        return None
    script_text = match.group("body").strip()
    return script_text or None


def _node_string_assignments(script_text: str) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for _ in range(3):
        changed = False
        for line in script_text.splitlines():
            assignment = _node_string_assignment_from_line(line)
            if assignment is None:
                continue
            name, raw_value = assignment
            expanded_value = _node_expand_template_value(raw_value, assignments)
            if assignments.get(name) != expanded_value:
                assignments[name] = expanded_value
                changed = True
        if not changed:
            break
    return assignments


def _node_string_assignment_from_line(line: str) -> tuple[str, str] | None:
    stripped_line = line.strip().rstrip(";")
    for prefix in ("const ", "let ", "var "):
        if not stripped_line.startswith(prefix):
            continue
        rest = stripped_line[len(prefix) :].lstrip()
        name_end = 0
        while name_end < len(rest) and (rest[name_end].isalnum() or rest[name_end] in {"_", "$"}):
            name_end += 1
        if name_end == 0:
            return None
        name = rest[:name_end]
        remainder = rest[name_end:].lstrip()
        if not remainder.startswith("="):
            return None
        value = remainder[1:].lstrip()
        if not value:
            return None
        quote = value[0]
        if quote not in {"'", '"', "`"}:
            return None
        literal = _read_js_quoted_literal(value, quote)
        if literal is None:
            return None
        return name, literal
    return None


def _read_js_quoted_literal(value: str, quote: str) -> str | None:
    result: list[str] = []
    index = 1
    escape_next = False
    while index < len(value):
        character = value[index]
        if escape_next:
            result.append(character)
            escape_next = False
            index += 1
            continue
        if character == "\\":
            escape_next = True
            index += 1
            continue
        if character == quote:
            return "".join(result)
        result.append(character)
        index += 1
    return None


def _node_expand_template_value(value: str, assignments: dict[str, str]) -> str:
    expanded = value
    for name, assigned_value in assignments.items():
        expanded = expanded.replace("${" + name + "}", assigned_value)
    return expanded


def _js_string_literal_text(value: str) -> str | None:
    if len(value) < 2 or value[0] != value[-1] or value[0] not in {"'", '"', "`"}:
        return None
    return value[1:-1]


def _node_generated_path_has_safe_root(path_text: str) -> bool:
    lowered = path_text.lower()
    return lowered.startswith(_SAFE_NODE_GENERATED_FILE_ROOTS)


def _node_template_placeholders_are_safe_filename_fragments(path_text: str) -> bool:
    index = 0
    while index < len(path_text):
        start = path_text.find("${", index)
        if start == -1:
            return True
        end = path_text.find("}", start + 2)
        if end == -1:
            return False
        placeholder = path_text[start + 2 : end].strip()
        if not _node_template_placeholder_is_safe_filename_fragment(placeholder):
            return False
        index = end + 1
    return True


def _node_template_placeholder_is_safe_filename_fragment(placeholder: str) -> bool:
    if not placeholder.startswith("String(") or ".padStart(" not in placeholder:
        return False
    lowered = placeholder.lower()
    if any(token in lowered for token in ("process", "require", "env", "import", "fs", "path", "child")):
        return False
    numeric_prefix, _separator, padding_suffix = placeholder.partition(".padStart(")
    if any(character in numeric_prefix for character in ("'", '"', "\\", "`", "[", "]")):
        return False
    return not any(character in padding_suffix for character in ("/", "\\", "`", "[", "]"))


def _node_path_without_template_placeholders(path_text: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(path_text):
        start = path_text.find("${", index)
        if start == -1:
            result.append(path_text[index:])
            break
        result.append(path_text[index:start])
        end = path_text.find("}", start + 2)
        if end == -1:
            result.append(path_text[start:])
            break
        result.append("x")
        index = end + 1
    return "".join(result)


def _is_combined_node_inline_eval_flag(token: str) -> bool:
    return token in {"-pe", "-ep"}


def _segment_contains_destructive_node_inline_eval(segment_args: list[str]) -> bool:
    lowered_args = [arg.lower() for arg in segment_args]
    index = 0
    while index < len(lowered_args):
        token = lowered_args[index]
        if token == "--":
            break
        if token in _NODE_INLINE_EVAL_FLAGS and index + 1 < len(lowered_args):
            if token in {"-p", "--print"} and lowered_args[index + 1].startswith("-"):
                index += 1
                continue
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if _is_combined_node_inline_eval_flag(token) and index + 1 < len(lowered_args):
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if token.startswith("--eval="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("--print="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("-e") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token.startswith("-p") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token in _NODE_OPTION_FLAGS_WITH_VALUE and index + 1 < len(lowered_args):
            index += 2
            continue
        if not token.startswith("-"):
            break
        index += 1
    return False


__all__ = [
    "_contains_destructive_node_inline_eval",
    "_find_or_fd_uses_write_or_exec_action",
    "_graphql_workflow_rest_args_are_safe",
    "_is_combined_node_inline_eval_flag",
    "_js_string_literal_text",
    "_looks_like_safe_graphql_query_file_workflow",
    "_looks_like_temporary_pr_threads_query_path",
    "_node_expand_template_value",
    "_node_generated_path_has_safe_root",
    "_node_path_without_template_placeholders",
    "_node_string_assignment_from_line",
    "_node_string_assignments",
    "_node_template_placeholder_is_safe_filename_fragment",
    "_node_template_placeholders_are_safe_filename_fragments",
    "_read_js_quoted_literal",
    "_segment_contains_destructive_node_inline_eval",
    "_single_node_heredoc_script",
]
