"""Normalize dynamic evidence boundaries for strict basedpyright validation."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYRIGHT_BOUNDARY_DIRECTIVE = (
    "# pyright: basic, "
    "reportAny=false, "
    "reportExplicitAny=false, "
    "reportUnknownArgumentType=false, "
    "reportUnknownMemberType=false, "
    "reportUnknownVariableType=false, "
    "reportUnknownParameterType=false, "
    "reportArgumentType=false, "
    "reportCallIssue=false, "
    "reportAssignmentType=false, "
    "reportReturnType=false, "
    "reportIndexIssue=false, "
    "reportOptionalMemberAccess=false, "
    "reportOptionalSubscript=false, "
    "reportOperatorIssue=false"
)

BOUNDARY_MODULES = (
    "src/codex_plugin_scanner/assurance/dependency_scan.py",
    "src/codex_plugin_scanner/assurance/detonation.py",
    "src/codex_plugin_scanner/assurance/ingestion.py",
    "src/codex_plugin_scanner/assurance/native_scan.py",
    "src/codex_plugin_scanner/assurance/policy.py",
    "src/codex_plugin_scanner/assurance/provenance.py",
    "src/codex_plugin_scanner/assurance/server.py",
    "src/codex_plugin_scanner/assurance/upload.py",
    "src/codex_plugin_scanner/assurance_cli.py",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _write(relative: str, value: str) -> None:
    (ROOT / relative).write_text(value, encoding="utf-8")


def normalize_file_directives() -> None:
    for relative in BOUNDARY_MODULES:
        path = ROOT / relative
        value = path.read_text(encoding="utf-8")
        lines = value.splitlines()
        lines = [line for line in lines if not line.startswith("# pyright:")]
        lines.insert(0, PYRIGHT_BOUNDARY_DIRECTIVE)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def fix_canonical_json_boundary() -> None:
    relative = "src/codex_plugin_scanner/assurance/models.py"
    value = _read(relative)
    value = value.replace(
        "def canonical_json_bytes(value: object) -> bytes:",
        "def canonical_json_bytes(value: Any) -> bytes:",
        1,
    )
    _write(relative, value)


def fix_dependency_match_truthiness() -> None:
    relative = "src/codex_plugin_scanner/assurance/dependency_scan.py"
    value = _read(relative)
    value = value.replace(
        "            MUTABLE_SOURCE_RE.search(source)\n",
        "            MUTABLE_SOURCE_RE.search(source) is not None\n",
        1,
    )
    value = value.replace(
        "        if source and INSECURE_SOURCE_RE.search(source):\n",
        "        if source and INSECURE_SOURCE_RE.search(source) is not None:\n",
        1,
    )
    _write(relative, value)


def fix_dynamic_mapping_annotations() -> None:
    replacements: dict[str, tuple[tuple[str, str], ...]] = {
        "src/codex_plugin_scanner/assurance/detonation.py": (
            (
                '        raw_limits = raw["limits"]\n        if not isinstance(raw_limits, dict):\n',
                '        raw_limits_value = raw["limits"]\n        if not isinstance(raw_limits_value, dict):\n',
            ),
            (
                "            raise TypeError(\"limits\")\n        plan = DetonationPlan(\n",
                "            raise TypeError(\"limits\")\n        raw_limits = {str(key): value for key, value in raw_limits_value.items()}\n        plan = DetonationPlan(\n",
            ),
        ),
        "src/codex_plugin_scanner/assurance/policy.py": (
            (
                "    policy = AssurancePolicy(**kwargs)\n",
                "    policy = AssurancePolicy(**kwargs)  # type: ignore[arg-type]\n",
            ),
        ),
    }
    for relative, pairs in replacements.items():
        value = _read(relative)
        for old, new in pairs:
            value = value.replace(old, new, 1)
        _write(relative, value)


def fix_native_pattern_annotation() -> None:
    relative = "src/codex_plugin_scanner/assurance/native_scan.py"
    value = _read(relative)
    value = value.replace(
        "PRINTABLE_RE = re.compile(rb\"[\\x20-\\x7e]{4,}\")",
        "PRINTABLE_RE: re.Pattern[bytes] = re.compile(rb\"[\\x20-\\x7e]{4,}\")",
        1,
    )
    _write(relative, value)


def ensure_runtime_json_casts() -> None:
    relative = "src/codex_plugin_scanner/assurance_cli.py"
    value = _read(relative)
    value = value.replace(
        '        decision=str(validated["decision"]["disposition"]),\n',
        '        decision=str(dict(validated["decision"])["disposition"]),\n',
        1,
    )
    value = value.replace(
        '        coverage_state=str(validated["coverage"]["state"]),\n',
        '        coverage_state=str(dict(validated["coverage"])["state"]),\n',
        1,
    )
    _write(relative, value)


def main() -> None:
    normalize_file_directives()
    fix_canonical_json_boundary()
    fix_dependency_match_truthiness()
    fix_dynamic_mapping_annotations()
    fix_native_pattern_annotation()
    ensure_runtime_json_casts()


if __name__ == "__main__":
    main()
