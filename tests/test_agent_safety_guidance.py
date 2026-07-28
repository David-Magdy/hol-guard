from __future__ import annotations

from pathlib import Path
from typing import final

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.agent_safety_guidance import install_agent_safety_guidance
from codex_plugin_scanner.guard.cli import install_commands
from codex_plugin_scanner.guard.store import GuardStore


def test_install_agent_safety_guidance_preserves_user_content_and_is_idempotent(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text("# My instructions\n\n- Preserve this rule.\n", encoding="utf-8")
    agents_path.chmod(0o600)

    first = install_agent_safety_guidance(home_dir)
    first_agents = agents_path.read_text(encoding="utf-8")
    safety = (home_dir / ".hol-support" / "SAFETY.md").read_text(encoding="utf-8")
    second = install_agent_safety_guidance(home_dir)

    assert first["status"] == "installed"
    assert first["changed"] is True
    assert "# My instructions" in first_agents
    assert "- Preserve this rule." in first_agents
    assert first_agents.count("BEGIN HOL GUARD SAFETY GUIDANCE") == 1
    assert "`~/.hol-support/SAFETY.md`" in first_agents
    assert agents_path.stat().st_mode & 0o777 == 0o600
    assert "Use one semantic action per tool call." in safety
    assert "Do not reshape commands to conceal those effects." in safety
    assert second == {
        "status": "installed",
        "changed": False,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }


def test_install_agent_safety_guidance_replaces_only_managed_block(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text(
        """\
User rule.

<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->
stale pointer
<!-- END HOL GUARD SAFETY GUIDANCE -->

Final user rule.
""",
        encoding="utf-8",
    )

    result = install_agent_safety_guidance(home_dir)
    updated = agents_path.read_text(encoding="utf-8")

    assert result["status"] == "installed"
    assert "User rule." in updated
    assert "Final user rule." in updated
    assert "stale pointer" not in updated
    assert updated.count("BEGIN HOL GUARD SAFETY GUIDANCE") == 1


def test_install_agent_safety_guidance_refuses_symlinked_agents_file(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    protected_target = tmp_path / "protected.md"
    agents_path.parent.mkdir(parents=True)
    _ = protected_target.write_text("do not change\n", encoding="utf-8")
    agents_path.symlink_to(protected_target)

    result = install_agent_safety_guidance(home_dir)

    assert result["status"] == "needs_attention"
    assert result["reason_code"] == "agent_safety_guidance_write_failed"
    assert protected_target.read_text(encoding="utf-8") == "do not change\n"
    assert not (home_dir / ".hol-support" / "SAFETY.md").exists()


def test_install_agent_safety_guidance_refuses_incomplete_managed_block(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    original = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->\nuser-edited text\n"
    _ = agents_path.write_text(original, encoding="utf-8")

    result = install_agent_safety_guidance(home_dir)

    assert result["status"] == "needs_attention"
    assert result["reason_code"] == "agent_safety_guidance_write_failed"
    assert agents_path.read_text(encoding="utf-8") == original


def test_successful_harness_install_attaches_agent_safety_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @final
    class FakeAdapter:
        harness = "codex"

        @staticmethod
        def install(_context: HarnessContext) -> dict[str, object]:
            return {"config_path": "~/.codex/config.toml"}

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )

    def fake_get_adapter(_harness: str) -> FakeAdapter:
        return FakeAdapter()

    monkeypatch.setattr(install_commands, "get_adapter", fake_get_adapter)

    payload = install_commands.apply_managed_install(
        "install",
        "opencode",
        False,
        context,
        GuardStore(context.guard_home),
        str(workspace_dir),
        "2026-07-28T00:00:00Z",
    )

    assert payload["agent_safety_guidance"] == {
        "status": "installed",
        "changed": True,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }
    assert (home_dir / ".codex" / "AGENTS.md").is_file()
    assert (home_dir / ".hol-support" / "SAFETY.md").is_file()
