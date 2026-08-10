from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "integrations" / "openclaw-clawhub" / "hol-guard" / "SKILL.md"


def test_clawhub_skill_is_manual_install_companion() -> None:
    frontmatter, body = SKILL.read_text(encoding="utf-8").split("\n---\n", 1)

    assert frontmatter.startswith("---\nname: hol-guard")
    assert "user-invocable: true" in frontmatter
    assert "disable-model-invocation: true" in frontmatter
    assert body.index("Start with read-only checks") < body.index("## Install or initialize")
    assert "stop after `hol-guard status`" in body
    assert body.index("explicit approval") < body.index("pipx install hol-guard")
    assert body.index("pipx install hol-guard") < body.index("hol-guard init")
    assert "Installing this skill alone does not mean runtime protection is active" in body
    assert "Guard Cloud is optional" in body


def test_clawhub_skill_does_not_duplicate_runtime_hook_logic() -> None:
    text = SKILL.read_text(encoding="utf-8")

    assert "hol-guard init` owns the real OpenClaw integration" in text
    assert "Do not manually rewrite OpenClaw configuration" in text
