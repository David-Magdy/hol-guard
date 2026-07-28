"""Install concise agent guidance that reduces avoidable Guard reviews."""

from __future__ import annotations

import re
from pathlib import Path

from .codex_hook_integrity import CodexHookIntegrityError, atomic_write_text

_AGENTS_RELATIVE_PATH = Path(".codex") / "AGENTS.md"
_SAFETY_RELATIVE_PATH = Path(".hol-support") / "SAFETY.md"
_MANAGED_BEGIN = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->"
_MANAGED_END = "<!-- END HOL GUARD SAFETY GUIDANCE -->"
_MANAGED_BLOCK = f"""\
{_MANAGED_BEGIN}
## HOL Guard

- Before planning shell, Git, package, filesystem, or remote actions, read `~/.hol-support/SAFETY.md`.
- Follow that guide to avoid unnecessary approval prompts without bypassing HOL Guard.
{_MANAGED_END}
"""
_SAFETY_GUIDANCE = """\
# HOL Guard Agent Safety

Use these command-shaping rules to reduce avoidable Guard reviews while preserving review for genuinely sensitive work.

## Plan clear actions

- Use one semantic action per tool call. Prefer the tool's working-directory option over changing directories
  in a shell chain.
- Use complete, exact paths. Do not use ellipses, placeholder fragments, or unresolved shell expansions
  in executable commands.
- Keep errors visible. Do not suppress diagnostics or trim output until the underlying action succeeds.
- Separate inspection from mutation so Guard and the user can verify the target before it changes.
- If Guard pauses an action, do not automatically retry equivalent spellings. Wait for approval or choose
  a safer operation.

## Prefer bounded operations

- Use read-only Git inspection before writes. Do not rewrite history, discard changes, or delete branches
  without explicit authorization.
- For filesystem changes, name one exact destination and avoid overwrite flags. For symbolic links, verify
  the source and destination separately, then create one link without replacing an existing path.
- For package work, state the package manager, workspace, package, and version explicitly. Use the repository
  lockfile flow and never pipe a downloaded installer into a shell.
- For remote work, state the host and destination explicitly. Keep file transfer, remote execution, and local
  cleanup as separate actions.
- Never read secret files, credential stores, or environment files unless the user explicitly authorizes
  the exact access. Never send local file contents to an untrusted destination.

## Keep review where it matters

Guard review is expected for destructive changes, permission or security changes, credential access, remote
execution, releases, deployments, and other actions with material side effects.

Do not reshape commands to conceal those effects.
"""
_MANAGED_PATTERN = re.compile(rf"(?ms)^{re.escape(_MANAGED_BEGIN)}\n.*?^{re.escape(_MANAGED_END)}\n?")


def install_agent_safety_guidance(home_dir: Path) -> dict[str, object]:
    """Install the support guide and its managed global AGENTS.md pointer."""

    agents_path = home_dir / _AGENTS_RELATIVE_PATH
    safety_path = home_dir / _SAFETY_RELATIVE_PATH
    try:
        _require_safe_parent(agents_path.parent)
        _require_safe_parent(safety_path.parent)
        existing_agents = _read_regular_text(agents_path)
        updated_agents = _upsert_managed_block(existing_agents)
        existing_safety = _read_regular_text(safety_path)
        agents_changed = updated_agents != existing_agents
        safety_changed = existing_safety != _SAFETY_GUIDANCE
        if safety_changed:
            atomic_write_text(safety_path, _SAFETY_GUIDANCE, mode=0o644)
        if agents_changed:
            atomic_write_text(agents_path, updated_agents, mode=_existing_mode(agents_path))
    except (CodexHookIntegrityError, OSError, UnicodeError, ValueError) as error:
        return {
            "status": "needs_attention",
            "changed": False,
            "reason_code": "agent_safety_guidance_write_failed",
            "message": str(error),
        }
    return {
        "status": "installed",
        "changed": agents_changed or safety_changed,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }


def _require_safe_parent(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError(f"Guard refused to use a non-directory support path: {path.name}")
    path.mkdir(parents=True, exist_ok=True)


def _read_regular_text(path: Path) -> str:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Guard refused to replace a non-regular support file: {path.name}")
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _existing_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777 if path.exists() else 0o644


def _upsert_managed_block(existing: str) -> str:
    begin_count = existing.count(_MANAGED_BEGIN)
    end_count = existing.count(_MANAGED_END)
    if begin_count != end_count:
        raise ValueError("Guard found an incomplete managed safety guidance block")
    cleaned = _MANAGED_PATTERN.sub("", existing).rstrip()
    prefix = f"{cleaned}\n\n" if cleaned else ""
    return f"{prefix}{_MANAGED_BLOCK}"


__all__ = ["install_agent_safety_guidance"]
