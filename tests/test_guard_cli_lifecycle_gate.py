from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import (
    enforce_lifecycle_gate,
    lifecycle_gate_requirement,
)


@pytest.mark.parametrize(
    ("attributes", "action"),
    [
        ({"guard_command": "install", "harness": "codex"}, "install"),
        ({"guard_command": "uninstall", "all": True}, "uninstall"),
        ({"guard_command": "update"}, "update"),
        ({"guard_command": "apps", "apps_command": "connect", "harness": "pi"}, "apps.connect"),
        ({"guard_command": "bootstrap"}, "bootstrap.install"),
        ({"guard_command": "init"}, "init.install"),
        ({"guard_command": "disconnect", "source": "default"}, "disconnect"),
        ({"guard_command": "device", "device_command": "rotate"}, "device.rotate"),
        ({"guard_command": "commands", "commands_command": "approve", "job_id": "job-1"}, "commands.approve"),
        ({"guard_command": "daemon", "daemon_command": "stop"}, "daemon.stop"),
        ({"guard_command": "trust", "trust_command": "reset"}, "trust.reset"),
        ({"guard_command": "doctor", "repair": True}, "doctor.repair"),
    ],
)
def test_lifecycle_gate_classifies_security_mutations(
    attributes: dict[str, object],
    action: str,
) -> None:
    requirement = lifecycle_gate_requirement(argparse.Namespace(**attributes))

    assert requirement is not None
    assert requirement.action == action


@pytest.mark.parametrize(
    "attributes",
    [
        {"guard_command": "install", "dry_run": True},
        {"guard_command": "apps", "apps_command": "test", "harness": "pi"},
        {"guard_command": "bootstrap", "skip_install": True},
        {"guard_command": "init", "skip_apps": True},
        {"guard_command": "device", "device_command": "show"},
        {"guard_command": "commands", "commands_command": "status"},
        {"guard_command": "daemon", "daemon_command": "repair"},
        {"guard_command": "daemon", "daemon_command": "status"},
        {"guard_command": "trust", "trust_command": "status"},
        {"guard_command": "doctor", "repair": False},
        {"guard_command": "mdm", "mdm_command": "deactivate"},
    ],
)
def test_lifecycle_gate_exempts_read_only_dry_run_and_recovery(
    attributes: dict[str, object],
) -> None:
    assert lifecycle_gate_requirement(argparse.Namespace(**attributes)) is None


def test_lifecycle_gate_warns_and_allows_when_protection_is_disabled(tmp_path: Path) -> None:
    error_stream = io.StringIO()

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="uninstall", harness="codex"),
        guard_home=tmp_path,
        error_stream=error_stream,
    )

    warning = error_stream.getvalue()
    assert "Security recommendation" in warning
    assert "approval password or Authenticator" in warning
    assert "hol-guard dashboard" in warning


def test_lifecycle_gate_requires_fresh_password_when_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )

    def wrong_password_prompt(_guard_home: Path, *, use_cooldown: bool = True) -> ApprovalGateInput:
        del use_cooldown
        return ApprovalGateInput(password="wrong password")

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", wrong_password_prompt)

    with pytest.raises(ApprovalGateError, match="invalid"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="daemon", daemon_command="stop"),
            guard_home=tmp_path,
        )


def test_lifecycle_gate_accepts_valid_password_and_binds_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )

    def valid_password_prompt(_guard_home: Path, *, use_cooldown: bool = True) -> ApprovalGateInput:
        del use_cooldown
        return ApprovalGateInput(password=password)

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", valid_password_prompt)

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="install", harness="codex"),
        guard_home=tmp_path,
    )
