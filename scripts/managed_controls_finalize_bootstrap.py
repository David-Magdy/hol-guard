"""One-shot finalizer for Managed Controls batch 02.

This helper exists only to repair and verify the already-open pull request. The
workflow deletes it before committing the production result.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_ROOT = ROOT / ".managed-controls-bootstrap"
API_PATH = (
    ROOT
    / "src"
    / "codex_plugin_scanner"
    / "guard"
    / "daemon"
    / "extension_control_api.py"
)
SERVER_PATH = (
    ROOT
    / "src"
    / "codex_plugin_scanner"
    / "guard"
    / "daemon"
    / "server.py"
)
LIMITS_TEST_PATH = ROOT / "tests" / "test_managed_controls_limits.py"
WIRE_TEST_PATH = ROOT / "tests" / "test_guard_extension_control_catalog_wire.py"
PACKAGE_PATH = ROOT / "dashboard" / "package.json"
DECISION_REPORT_PATH = (
    ROOT
    / "tests"
    / "fixtures"
    / "guard-command-corpus"
    / "decision-diff-report.json"
)

API_OLD = """        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        if len(serialized) > MAX_CATALOG_PAYLOAD_BYTES:
"""
API_NEW = """        wire_body = json.dumps(payload).encode("utf-8")
        if len(wire_body) > MAX_CATALOG_PAYLOAD_BYTES:
"""

SERVER_OLD = """        if parsed.path == "/v1/extension-controls/catalog":
            self._write_json(
                self._daemon_server().extension_control_api.catalog(),
                extra_headers={"Cache-Control": "no-store"},
            )
            return
"""
SERVER_NEW = """        if parsed.path == "/v1/extension-controls/catalog":
            try:
                catalog = self._daemon_server().extension_control_api.catalog()
            except ExtensionControlApiError as error:
                self._write_json(error.to_payload(), status=error.status)
                return
            self._write_json(catalog, extra_headers={"Cache-Control": "no-store"})
            return
"""

LIMITS_OLD = """def _catalog_extension(index: int) -> CommandSafetyExtension:
    return CommandSafetyExtension(
        extension_id=f"command.limit{index}",
        version="1.0.0",
        name=f"Limit {index}",
        description="Bounded catalog fixture.",
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=("Review the requested capability.",),
        delegated_protection="package-firewall",
        ecosystem_ids=(f"limit{index}",),
        executables=(f"limit{index}",),
        reference_urls=("https://example.com/managed-controls-limit-fixture",),
    )
"""
LIMITS_NEW = """def _catalog_extension(index: int) -> CommandSafetyExtension:
    extension = CommandSafetyExtension(
        extension_id=f"command.limit{index}",
        version="1.0.0",
        name=f"Limit {index}",
        description="Bounded catalog fixture.",
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=("Review the requested capability.",),
        delegated_protection="package-firewall",
        ecosystem_ids=(f"limit{index}",),
        executables=(f"limit{index}",),
        reference_urls=("https://example.com/managed-controls-limit-fixture",),
    )
    return replace(
        extension,
        permissions=(
            replace(
                extension.permissions[0],
                example_command=f"limit{index} scan",
            ),
        ),
    )
"""


def _run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)  # noqa: S603


def _restore(target: Path, backup_name: str) -> None:
    backup = BACKUP_ROOT / backup_name
    if not backup.is_file():
        raise SystemExit(f"missing bootstrap backup: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(backup, target)


def _replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    if new in source:
        return
    if old not in source:
        raise SystemExit(f"expected source block not found in {path}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    _run("git", "config", "user.name", "github-actions[bot]")
    _run(
        "git",
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
    )

    if not WIRE_TEST_PATH.is_file():
        raise SystemExit("the workflow did not create the wire-contract test")
    wire_test_source = WIRE_TEST_PATH.read_text(encoding="utf-8")
    WIRE_TEST_PATH.unlink()

    _run("git", "fetch", "origin", "release/3.0")
    _run("git", "merge", "-X", "ours", "--no-edit", "origin/release/3.0")

    _restore(API_PATH, "extension_control_api.py")
    _restore(SERVER_PATH, "server.py")
    _restore(LIMITS_TEST_PATH, "test_managed_controls_limits.py")
    _restore(PACKAGE_PATH, "dashboard-package.json")

    _replace_once(API_PATH, API_OLD, API_NEW)
    _replace_once(SERVER_PATH, SERVER_OLD, SERVER_NEW)
    _replace_once(LIMITS_TEST_PATH, LIMITS_OLD, LIMITS_NEW)
    WIRE_TEST_PATH.write_text(wire_test_source, encoding="utf-8")

    _run(
        sys.executable,
        "tests/guard_command_decision_diff.py",
        "--write",
    )
    if not DECISION_REPORT_PATH.is_file():
        raise SystemExit("decision-diff report was not generated")

    for workflow in (
        ".github/workflows/managed-controls-finalize.yml",
        ".github/workflows/managed-controls-workflow-hotfix.yml",
        ".github/workflows/managed-controls-batch02-final-fix.yml",
    ):
        (ROOT / workflow).unlink(missing_ok=True)

    shutil.rmtree(BACKUP_ROOT)
    Path(__file__).unlink()

    # Stage the one-shot bootstrap deletion, restored production sources,
    # decision evidence, and temporary workflow cleanup. Later workflow steps
    # add the rebuilt dashboard bundle and refreshed ratchet before committing.
    _run("git", "add", "-A")
    _run("git", "diff", "--cached", "--check")


if __name__ == "__main__":
    main()
