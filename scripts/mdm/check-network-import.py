#!/usr/bin/env python3
"""Emit a redacted import sentinel for the enterprise networking module."""

from __future__ import annotations

import os
from pathlib import Path


def _safe_token(value: str) -> str:
    return "".join(character if character.isalnum() or character in {"-", "_", "."} else "-" for character in value)[:80]


def main() -> int:
    token = "ok"
    try:
        from codex_plugin_scanner.guard.mdm import network  # noqa: F401
    except ModuleNotFoundError as exc:
        token = f"missing-{_safe_token(exc.name or 'unknown')}"
    except ImportError:
        token = "import-error"
    except Exception:
        token = "unexpected-error"
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"result={token}\n")
    Path("mdm-import-sentinel.txt").write_text(f"{token}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
