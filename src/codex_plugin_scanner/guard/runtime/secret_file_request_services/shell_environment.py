"""Shell environment assignment parsing."""

from __future__ import annotations

from .interpreter_observers import _shell_env_assignment_key


def _is_shell_env_assignment_token(token: str) -> bool:
    name, separator, _ = token.partition("=")
    if separator != "=" or not name:
        return False
    if name.endswith("+"):
        name = name[:-1]
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(character.isalnum() or character == "_" for character in name[1:])


def _shell_env_assignment_targets_key(token: str, env_key: str) -> bool:
    return _shell_env_assignment_key(token) == env_key.upper()


def _is_shell_command_flag(value: str) -> bool:
    if value == "-c":
        return True
    if not value.startswith("-"):
        return False
    flag_characters = value[1:]
    return bool(flag_characters) and set(flag_characters) <= {"c", "l"}


__all__ = [
    "_is_shell_command_flag",
    "_is_shell_env_assignment_token",
    "_shell_env_assignment_targets_key",
]
