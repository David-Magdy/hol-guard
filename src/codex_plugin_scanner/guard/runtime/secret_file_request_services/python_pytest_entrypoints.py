"""Python and pytest entry-point recognition."""

from __future__ import annotations

from .constants_core import _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES


def _python_segment_targets_module(args: list[str], module_root: str) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return False
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return module.split(".", 1)[0] == module_root
        if arg.startswith("-m") and len(arg) > 2:
            return arg[2:].split(".", 1)[0] == module_root
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _pytest_args_from_python(command_args: list[str]) -> list[str] | None:
    index = 0
    while index < len(command_args):
        token = command_args[index]
        if token == "-m" and index + 1 < len(command_args):
            return command_args[index + 2 :] if command_args[index + 1].split(".", 1)[0] == "pytest" else None
        if token.startswith("-m") and len(token) > 2:
            return command_args[index + 1 :] if token[2:].split(".", 1)[0] == "pytest" else None
        if token in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        index += 1
    return None


__all__ = [
    "_pytest_args_from_python",
    "_python_segment_targets_module",
]
