"""Finish, normalize, and clean the layered scanner assurance implementation."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, value: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding="utf-8")


def patch_content_scan() -> None:
    path = "src/codex_plugin_scanner/assurance/content_scan.py"
    text = read(path)
    reverse = '            r"(?:eval|exec|Function|system|spawn|Popen).{0,160}(?:base64\\.(?:b64decode|decodebytes)|Buffer\\.from\\([^\\n]*base64|atob\\()",\n'
    if reverse not in text:
        anchor = '            r"(?:base64\\.(?:b64decode|decodebytes)|Buffer\\.from\\([^\\n]*base64|atob\\().{0,160}(?:eval|exec|Function|system|spawn|Popen)",\n'
        if anchor not in text:
            raise RuntimeError("obfuscated execution rule anchor missing")
        text = text.replace(anchor, anchor + reverse, 1)
    write(path, text)


def patch_drift() -> None:
    path = "src/codex_plugin_scanner/assurance/drift.py"
    text = read(path)
    text = text.replace(
        "    endpoints: tuple[str, ...],\n    commands: tuple[str, ...],\n    lifecycle_scripts: tuple[str, ...],\n    security_controls: tuple[str, ...],\n",
        "    endpoints: tuple[str, ...] = (),\n    commands: tuple[str, ...] = (),\n    lifecycle_scripts: tuple[str, ...] = (),\n    security_controls: tuple[str, ...] = (),\n",
        1,
    )
    text = text.replace(
        '''        if not isinstance(payload.get(field_name), list):
            if not isinstance(payload.get(field_name), list):
                raise DriftError(f"baseline {field_name} must be an array")
''',
        '''        if not isinstance(payload.get(field_name), list):
            raise DriftError(f"baseline {field_name} must be an array")
''',
    )
    old_changed = '        "changed": approved["artifact_digest"] != current["artifact_digest"],\n'
    new_changed = '''        "changed": approved["artifact_digest"] != current["artifact_digest"] or bool(
            added_files
            or removed_files
            or modified_files
            or added_dependencies
            or removed_dependencies
            or changed_dependencies
            or added_native
            or removed_native
            or changed_native
            or added_capabilities
            or removed_capabilities
            or added_endpoints
            or removed_endpoints
            or added_commands
            or removed_commands
            or added_scripts
            or removed_scripts
            or removed_controls
            or added_controls
        ),
'''
    text = text.replace(old_changed, new_changed, 1)
    if '"security_regressions": {' not in text:
        anchor = '''        "security_controls": {"added": added_controls, "removed": removed_controls},
    }
'''
        addition = '''        "security_controls": {"added": added_controls, "removed": removed_controls},
        "security_regressions": {
            "new_capabilities": added_capabilities,
            "new_endpoints": added_endpoints,
            "new_commands": added_commands,
            "new_lifecycle_scripts": added_scripts,
            "removed_security_controls": removed_controls,
            "new_native_artifacts": added_native,
            "changed_native_artifacts": changed_native,
            "new_dependencies": added_dependencies,
            "changed_dependencies": changed_dependencies,
            "executable_file_changes": executable_changes,
        },
    }
'''
        if anchor not in text:
            raise RuntimeError("drift payload anchor missing")
        text = text.replace(anchor, addition, 1)
    write(path, text)


def patch_surface_scan() -> None:
    path = "src/codex_plugin_scanner/assurance/surface_scan.py"
    text = read(path)
    if "def _redacted_command_digest" not in text:
        anchor = "\ndef _package_runner_target_pinned(value: str) -> bool:\n"
        helper = '''
def _redacted_command_digest(command: str) -> str:
    return f"sha256:{hashlib.sha256(command.encode()).hexdigest()}"


def _package_runner_target_pinned(value: str) -> bool:
'''
        if anchor not in text:
            raise RuntimeError("surface command digest anchor missing")
        text = text.replace(anchor, helper, 1)
    write(path, text)


def patch_policy_test() -> None:
    path = "tests/test_assurance_policy_ingestion.py"
    text = read(path)
    anchor = 'def _benign_report(tmp_path: Path) -> dict[str, object]:\n'
    if anchor in text:
        block = text.split(anchor, 1)[1][:180]
        if "tmp_path.mkdir(parents=True, exist_ok=True)" not in block:
            text = text.replace(anchor, anchor + "    tmp_path.mkdir(parents=True, exist_ok=True)\n", 1)
    write(path, text)

