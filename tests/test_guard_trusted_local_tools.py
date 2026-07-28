from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.trusted_local_tools import local_tool_approval_eligibility


def _write_event(
    path: Path,
    *,
    workspace: Path,
    command: str,
    call_id: str,
    policy_action: str | None = None,
) -> None:
    payload: dict[str, object] = {
        "session_id": "trusted-local-tool",
        "turn_id": call_id,
        "cwd": str(workspace),
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-sol",
        "permission_mode": "bypassPermissions",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": call_id,
    }
    if policy_action is not None:
        payload["policy_action"] = policy_action
    _ = path.write_text(json.dumps(payload))


def _json_object(value: str) -> dict[str, object]:
    parsed = cast(object, json.loads(value))
    assert isinstance(parsed, Mapping)
    return dict(cast(Mapping[str, object], parsed))


def _run_hook(*, guard_home: Path, workspace: Path, event_path: Path) -> int:
    return main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--event-file",
            str(event_path),
        ]
    )


@pytest.fixture
def local_tool_workspace(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool = workspace / "xads.mjs"
    _ = tool.write_text("export const version = 1;\n")
    return workspace, tool


def test_local_tool_eligibility_is_digest_bound_and_read_only(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, tool = local_tool_workspace
    command = (
        "node xads.mjs request --method=GET --path=/stats "
        "--query='entity=PROMOTED_TWEET&start_time=2026-07-28T13:00:00Z'"
    )
    first = local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace)
    assert first is not None
    assert first.tool_name == "xads.mjs"
    assert first.capability == "request"
    assert first.read_only_reason == "http_get"

    varied = local_tool_approval_eligibility(
        command.replace("13:00:00Z", "20:00:00Z"),
        cwd=workspace,
        home_dir=workspace,
    )
    assert varied is not None
    assert varied.tool_identity_hash == first.tool_identity_hash

    changed_options = local_tool_approval_eligibility(
        command + " --granularity=TOTAL",
        cwd=workspace,
        home_dir=workspace,
    )
    assert changed_options is not None
    assert changed_options.tool_identity_hash != first.tool_identity_hash

    _ = tool.write_text("export const version = 2;\n")
    changed = local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace)
    assert changed is not None
    assert changed.tool_identity_hash != first.tool_identity_hash


def test_local_tool_eligibility_supports_verified_jq_output_processing(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, _tool = local_tool_workspace
    eligibility = local_tool_approval_eligibility(
        (
            "node xads.mjs request --method=GET --path=/stats "
            + "--query='start_time=2026-07-28T13:00:00Z' | "
            + "jq '[.data[] | {id, impressions: (.metrics.impressions[0] // 0)}]'"
        ),
        cwd=workspace,
        home_dir=workspace,
    )
    assert eligibility is not None
    assert eligibility.capability == "request"
    assert eligibility.read_only_reason == "http_get"
    changed_filter = local_tool_approval_eligibility(
        "node xads.mjs request --method=GET --path=/stats | jq '.data[0]'",
        cwd=workspace,
        home_dir=workspace,
    )
    assert changed_filter is not None
    assert changed_filter.tool_identity_hash != eligibility.tool_identity_hash


@pytest.mark.parametrize(
    "command",
    (
        "node xads.mjs request --method=POST --path=/campaigns",
        "node xads.mjs request --method=POST --method=GET --path=/campaigns",
        "node xads.mjs delete --method=GET --path=/campaigns/1",
        "node xads.mjs request --method=GET --path=/stats; touch marker",
        "node xads.mjs request --method=GET --path=/stats > result.json",
        "node xads.mjs request --method=GET --path=/stats --output=result.json",
        "node xads.mjs request --method=GET --path=/stats --write",
        "TOKEN=value node xads.mjs request --method=GET --path=/stats",
        "node -e 'process.stdout.write(\"safe\")' request --method=GET",
    ),
)
def test_local_tool_trust_rejects_mutations_and_shell_expansion(
    local_tool_workspace: tuple[Path, Path],
    command: str,
) -> None:
    workspace, _tool = local_tool_workspace
    assert local_tool_approval_eligibility(command, cwd=workspace, home_dir=workspace) is None


def test_local_tool_trust_rejects_jq_file_inputs(
    local_tool_workspace: tuple[Path, Path],
) -> None:
    workspace, _tool = local_tool_workspace
    assert (
        local_tool_approval_eligibility(
            "node xads.mjs request --method=GET --path=/stats | jq -f filter.jq",
            cwd=workspace,
            home_dir=workspace,
        )
        is None
    )
    assert (
        local_tool_approval_eligibility(
            "node xads.mjs request --method=GET --path=/stats | jq '.data' /path/to/secret",
            cwd=workspace,
            home_dir=workspace,
        )
        is None
    )


def test_local_tool_trust_allows_variable_read_queries_and_invalidates_changed_bytes(
    tmp_path: Path,
    local_tool_workspace: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, tool = local_tool_workspace
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "config.toml").write_text(
        'mode = "enforce"\nsecurity_level = "balanced"\ndefault_action = "require-reapproval"\n'
    )
    monkeypatch.setenv("CODEX_MANAGED_BY_BUN", "1")

    def schedule_daemon(_guard_home: Path, **_kwargs: object) -> str:
        return "http://127.0.0.1:4455"

    def unavailable_daemon(_guard_home: Path) -> object:
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr(guard_commands_module, "schedule_guard_daemon_ensure", schedule_daemon)
    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", unavailable_daemon)

    first_event = tmp_path / "first.json"
    _write_event(
        first_event,
        workspace=workspace,
        command="node xads.mjs request --method=GET --path=/stats --query='start_time=2026-07-28T13:00:00Z'",
        call_id="first",
    )
    assert _run_hook(guard_home=guard_home, workspace=workspace, event_path=first_event) == 0
    first_payload = _json_object(capsys.readouterr().out)
    first_hook_output = cast(Mapping[str, object], first_payload["hookSpecificOutput"])
    assert first_hook_output["permissionDecision"] == "deny"

    store = GuardStore(guard_home)
    pending = store.list_approval_requests(limit=5)
    assert len(pending) == 1
    assert pending[0]["artifact_type"] == "tool_action_request"
    approval = cast(Mapping[str, object], pending[0]["local_tool_approval"])
    assert approval["eligible"] is True
    assert approval["capability"] == "request"
    assert approval["allowed_targets"] == ["capability", "version"]

    with pytest.raises(ValueError, match="local_tool_approval_cannot_be_remembered"):
        apply_approval_resolution(
            store=store,
            request_id=str(pending[0]["request_id"]),
            action="allow",
            scope="artifact",
            workspace=str(workspace),
            reason="invalid mixed approval",
            now="2026-07-28T21:00:00+00:00",
            persist_policy=True,
            local_tool_grant_target="capability",
            local_tool_grant_duration="version",
        )

    with pytest.raises(ValueError, match="mixed_temporary_grant_modes"):
        apply_approval_resolution(
            store=store,
            request_id=str(pending[0]["request_id"]),
            action="allow",
            scope="artifact",
            workspace=str(workspace),
            reason="invalid mixed approval",
            now="2026-07-28T21:00:00+00:00",
            mcp_grant_target="server",
            mcp_grant_duration="1h",
            local_tool_grant_target="capability",
            local_tool_grant_duration="version",
        )

    resolved = apply_approval_resolution(
        store=store,
        request_id=str(pending[0]["request_id"]),
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="trusted local analytics client",
        now="2026-07-28T21:00:00+00:00",
        local_tool_grant_target="capability",
        local_tool_grant_duration="version",
    )
    local_tool_grant = cast(Mapping[str, object], resolved["local_tool_grant"])
    assert local_tool_grant["expires_at"] is None

    varied_event = tmp_path / "varied.json"
    _write_event(
        varied_event,
        workspace=workspace,
        command="node xads.mjs request --method=GET --path=/stats --query='start_time=2026-07-28T20:00:00Z'",
        call_id="varied",
    )
    assert _run_hook(guard_home=guard_home, workspace=workspace, event_path=varied_event) == 0
    assert capsys.readouterr().out == ""

    explicit_review_event = tmp_path / "explicit-review.json"
    _write_event(
        explicit_review_event,
        workspace=workspace,
        command="node xads.mjs request --method=GET --path=/stats",
        call_id="explicit-review",
        policy_action="require-reapproval",
    )
    assert (
        _run_hook(
            guard_home=guard_home,
            workspace=workspace,
            event_path=explicit_review_event,
        )
        == 0
    )
    explicit_review_payload = _json_object(capsys.readouterr().out)
    explicit_hook_output = cast(
        Mapping[str, object],
        explicit_review_payload["hookSpecificOutput"],
    )
    assert explicit_hook_output["permissionDecision"] == "deny"

    _ = tool.write_text("export const version = 2;\n")
    changed_event = tmp_path / "changed.json"
    _write_event(
        changed_event,
        workspace=workspace,
        command="node xads.mjs request --method=GET --path=/stats --query='start_time=2026-07-28T20:00:00Z'",
        call_id="changed",
    )
    assert _run_hook(guard_home=guard_home, workspace=workspace, event_path=changed_event) == 0
    changed_payload = _json_object(capsys.readouterr().out)
    changed_hook_output = cast(Mapping[str, object], changed_payload["hookSpecificOutput"])
    assert changed_hook_output["permissionDecision"] == "deny"
