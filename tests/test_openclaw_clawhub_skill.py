from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "integrations" / "openclaw-clawhub" / "hol-guard" / "SKILL.md"


def test_clawhub_skill_is_manual_install_companion() -> None:
    text = SKILL.read_text(encoding="utf-8")

    assert "name: hol-guard" in text
    assert "user-invocable: true" in text
    assert "disable-model-invocation: true" in text
    assert "pipx install hol-guard" in text
    assert "hol-guard init" in text
    assert "hol-guard status" in text
    assert "explicit approval" in text
    assert "Installing this skill alone does not mean runtime protection is active" in text
    assert "Guard Cloud is optional" in text


def test_clawhub_skill_does_not_duplicate_runtime_hook_logic() -> None:
    text = SKILL.read_text(encoding="utf-8")

    assert "hol-guard init` owns the real OpenClaw integration" in text
    assert "Do not manually rewrite OpenClaw configuration" in text
