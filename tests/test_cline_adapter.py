from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.cline_bridge import (
    cline_control_from_guard_output,
    plugin_after_tool_replacement,
)
from codex_plugin_scanner.guard.adapters.cline_hook_payload import ClinePayloadError, normalize_cline_payload
from codex_plugin_scanner.guard.adapters.cline_hooks import _hook_source, _slot_for_event
from codex_plugin_scanner.guard.adapters.cline_mcp import (
    detect_cline_mcp,
    install_cline_mcp_proxies,
    restore_cline_mcp_proxies,
)
from codex_plugin_scanner.guard.adapters.cline_plugin import _plugin_source
from codex_plugin_scanner.guard.runtime.actions import action_envelope_harnesses


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _fake_guard(path: Path) -> Path:
    script = path / "fake_guard.py"
    script.write_text(
        '''from __future__ import annotations
import json, os, sys
payload = json.load(sys.stdin)
log = os.environ.get("CLINE_TEST_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\\n")
text = json.dumps(payload, sort_keys=True)
if "MALFORMED" in text:
    print("not-json")
elif "BLOCK_ME" in text or "SECRET_OUTPUT" in text:
    print(json.dumps({"decision":"block","reason":"blocked by test"}))
else:
    print(json.dumps({"decision":"allow"}))
''',
        encoding="utf-8",
    )
    return script


def _run_generated_hook(source: str, tmp_path: Path, payload: dict[str, object], *, env=None):
    hook = tmp_path / "PreToolUse"
    hook.write_text(source, encoding="utf-8")
    hook.chmod(0o755)
    return subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        check=False,
    )


def _run_plugin(source: str, tmp_path: Path, expression: str, *, env=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for the generated Cline plugin contract")
    plugin = tmp_path / "cline-plugin.mjs"
    plugin.write_text(source, encoding="utf-8")
    script = (
        'import { pathToFileURL } from "node:url";'
        f'const plugin=(await import(pathToFileURL({json.dumps(str(plugin))}).href)).default;'
        f'const result=await ({expression});'
        'console.log(JSON.stringify(result));'
    )
    return subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        check=False,
    )


def test_cline_adapter_registry_and_aliases() -> None:
    adapter = get_adapter("cline")
    assert isinstance(adapter, ClineHarnessAdapter)
    assert get_adapter("cline-cli") is adapter
    assert get_adapter("cline-vscode") is adapter
    assert "cline" in {item.harness for item in list_adapters()}
    assert "cline" in action_envelope_harnesses()


def test_cline_contract_exposes_release_surfaces() -> None:
    contract = get_adapter("cline").setup_contract()
    assert contract.display_name == "Cline"
    assert contract.surface_capabilities == ("auto", "hooks", "plugin", "cli", "all")
    assert contract.docs_path == "docs/guard/cline-local-protection-contract.md"
    assert contract.coverage.browser_fallback is True


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected_type"),
    [
        ("run_commands", {"commands": ["echo ok"]}, "shell_command"),
        ("read_files", {"files": [{"path": ".env"}]}, "file_read"),
        ("editor", {"path": "src/app.py", "content": "x"}, "file_write"),
        ("apply_patch", {"patch": "*** Update File: src/app.py"}, "file_write"),
        ("use_mcp_tool", {"server_name": "demo", "tool_name": "write"}, "mcp_tool"),
    ],
)
def test_cline_typed_tool_payloads_normalize(tool_name: str, tool_input: dict[str, object], expected_type: str) -> None:
    envelope = normalize_cline_payload(
        {
            "hookName": "PreToolUse",
            "tool_call": {"id": "call-1", "name": tool_name, "input": tool_input},
        },
        workspace="/workspace",
        home_dir="/home/test",
    )
    assert envelope.harness == "cline"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == expected_type


def test_cline_parallel_commands_are_not_falsely_serialized() -> None:
    envelope = normalize_cline_payload(
        {
            "hookName": "PreToolUse",
            "tool_call": {
                "id": "call-1",
                "name": "run_commands",
                "input": {"commands": ["echo one", "echo two"]},
            },
        }
    )
    assert envelope.command == 'cline-parallel:["echo one","echo two"]'
    assert ";" not in envelope.command


def test_cline_current_and_legacy_payload_conflict_fails_closed() -> None:
    with pytest.raises(ClinePayloadError):
        normalize_cline_payload(
            {
                "hookName": "PreToolUse",
                "tool_call": {"name": "run_commands", "input": {"commands": ["echo current"]}},
                "preToolUse": {
                    "toolName": "run_commands",
                    "parameters": {"commands": json.dumps(["echo legacy"])},
                },
            }
        )


def test_cline_legacy_parameter_map_decodes_json_values() -> None:
    envelope = normalize_cline_payload(
        {
            "hookName": "PreToolUse",
            "preToolUse": {
                "toolName": "read_files",
                "parameters": {"files": json.dumps([{"path": ".env"}, {"path": "README.md"}])},
            },
        }
    )
    assert ".env" in envelope.target_paths
    assert "README.md" in envelope.target_paths


def test_cline_precompact_paths_are_not_dereferenced(tmp_path: Path) -> None:
    marker = tmp_path / "context.json"
    marker.write_text("secret", encoding="utf-8")
    envelope = normalize_cline_payload(
        {
            "hookName": "PreCompact",
            "preCompact": {"contextJsonPath": str(marker), "contextRawPath": str(marker)},
        }
    )
    assert envelope.event_name == "PreCompact"
    assert envelope.target_paths == ()


def test_native_bridge_fails_closed_on_missing_or_malformed_output() -> None:
    assert cline_control_from_guard_output("", event_name="PreToolUse")["cancel"] is True
    assert cline_control_from_guard_output("not json", event_name="PreToolUse")["cancel"] is True
    assert cline_control_from_guard_output('{"decision":"allow"}', event_name="PreToolUse")["cancel"] is False


def test_plugin_after_tool_replaces_blocked_or_unreviewable_output() -> None:
    blocked = plugin_after_tool_replacement('{"decision":"block","reason":"secret found"}')
    assert blocked == {"result": {"output": "secret found", "isError": True}}
    malformed = plugin_after_tool_replacement("not json")
    assert malformed is not None
    assert malformed["result"]["isError"] is True


def test_native_pretool_hook_blocks_when_guard_is_unavailable(tmp_path: Path) -> None:
    context = _context(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[str(tmp_path / "missing-guard")])
    result = _run_generated_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"paths": ["README.md"]}}},
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["cancel"] is True


def test_native_pretool_hook_fans_out_parallel_commands(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard = _fake_guard(tmp_path)
    log = tmp_path / "guard-log.jsonl"
    env = {**os.environ, "CLINE_TEST_LOG": str(log)}
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_generated_hook(
        source,
        tmp_path,
        {
            "hookName": "PreToolUse",
            "tool_call": {
                "id": "1",
                "name": "run_commands",
                "input": {"commands": ["echo safe", "BLOCK_ME"]},
            },
        },
        env=env,
    )
    output = json.loads(result.stdout)
    assert output["cancel"] is True
    logged = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [item["tool_call"]["input"]["command"] for item in logged] == ["echo safe", "BLOCK_ME"]


def test_native_pretool_hook_rejects_oversized_payload_before_guard(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_generated_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"x": "a" * (1024 * 1024)}}},
    )
    assert json.loads(result.stdout)["cancel"] is True


def test_native_hook_slot_never_overwrites_user_owned_hooks(tmp_path: Path) -> None:
    root = tmp_path / "hooks"
    root.mkdir()
    (root / "PreToolUse").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    slot = _slot_for_event(root, "PreToolUse")
    assert slot.name == "PreToolUse.py"
    (root / "PreToolUse.py").write_text("print('mine')\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _slot_for_event(root, "PreToolUse")


def test_generated_plugin_syntax_and_pretool_block(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required")
    plugin_path = tmp_path / "syntax.mjs"
    plugin_path.write_text(source, encoding="utf-8")
    syntax = subprocess.run([node, "--check", str(plugin_path)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr
    result = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"run_commands"},input:{commands:["echo safe","BLOCK_ME"]}})',
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["skip"] is True
    assert output["reason"] == "blocked by test"


def test_generated_plugin_aftertool_withholds_blocked_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])
    result = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{source:"test"}}})',
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["result"]["isError"] is True
    assert output["result"]["output"] == "blocked by test"
    assert output["result"]["metadata"] == {"source": "test"}


def test_cline_mcp_proxy_install_and_restore_round_trip(tmp_path: Path) -> None:
    context = _context(tmp_path)
    settings = context.home_dir / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    settings.parent.mkdir(parents=True)
    original = {
        "mcpServers": {
            "local": {"command": "node", "args": ["server.js"], "env": {"TOKEN": "secret"}},
            "remote": {"url": "https://example.invalid/mcp"},
        }
    }
    original_text = json.dumps(original, indent=2) + "\n"
    settings.write_text(original_text, encoding="utf-8")

    detection = detect_cline_mcp(context)
    assert {artifact.name for artifact in detection.artifacts} == {"local", "remote"}
    installed = install_cline_mcp_proxies(context)
    assert installed["managed_servers"] == ["local"]
    assert installed["skipped_remote_servers"] == ["remote"]
    managed = json.loads(settings.read_text(encoding="utf-8"))
    assert managed["mcpServers"]["local"]["command"] == sys.executable
    assert "mcp-proxy" in managed["mcpServers"]["local"]["args"]
    assert managed["mcpServers"]["remote"] == original["mcpServers"]["remote"]

    restored = restore_cline_mcp_proxies(context)
    assert restored["complete"] is True
    assert settings.read_text(encoding="utf-8") == original_text


def test_cline_mcp_restore_does_not_clobber_user_edits(tmp_path: Path) -> None:
    context = _context(tmp_path)
    settings = context.home_dir / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}), encoding="utf-8")
    install_cline_mcp_proxies(context)
    managed = json.loads(settings.read_text(encoding="utf-8"))
    managed["userChange"] = True
    settings.write_text(json.dumps(managed), encoding="utf-8")
    restored = restore_cline_mcp_proxies(context)
    assert restored["complete"] is False
    assert str(settings) in restored["retained_modified"]
    assert json.loads(settings.read_text(encoding="utf-8"))["userChange"] is True
