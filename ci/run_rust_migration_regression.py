#!/usr/bin/env python3
"""Run retained Rust P0-P2, extension, command-pattern, and security tests."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence

PR_PATTERN = re.compile(
    r"(?:rust|native|resident|command|extension|pattern|pretool|pre_tool|posttool|post_tool|"
    r"package|shim|supply[_-]?chain|archive|decode|path|filesystem|secret|prompt|destruct|"
    r"tamper|security|approval|policy|wheel|publish|artifact)",
    re.IGNORECASE,
)
SMOKE_PATTERN = re.compile(
    r"(?:rust_migration_regression|native_runtime|command_(?:extension|pattern)|"
    r"guard_command|guard_package|package_shim)",
    re.IGNORECASE,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover(root: Path, mode: str) -> list[str]:
    candidates: set[Path] = set()
    for base_name in ("tests", "ci/native_runtime"):
        base = root / base_name
        if base.is_dir():
            candidates.update(base.rglob("test*.py"))
    selected: list[str] = []
    pattern = SMOKE_PATTERN if mode == "smoke" else PR_PATTERN
    for path in sorted(candidates):
        relative = path.relative_to(root).as_posix()
        if pattern.search(relative):
            selected.append(relative)
            continue
        if mode == "full":
            source = path.read_text(encoding="utf-8", errors="ignore")[:16_000]
            if PR_PATTERN.search(source):
                selected.append(relative)
    return selected


def run_pytest(root: Path, files: Sequence[str], batch_size: int) -> int:
    if not files:
        raise RuntimeError("no Rust migration regression tests were discovered")
    for offset in range(0, len(files), batch_size):
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short", *files[offset : offset + batch_size]],
            cwd=root,
            check=False,
        )
        if completed.returncode:
            return completed.returncode
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "pr", "full"), default="pr")
    parser.add_argument("--batch-size", type=int, default=80)
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args(argv)
    if args.batch_size < 1 or args.batch_size > 200:
        parser.error("--batch-size must be between 1 and 200")
    root = repo_root()
    files = discover(root, args.mode)
    payload = {"schema_version": 1, "mode": args.mode, "test_file_count": len(files), "files": files}
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        output = args.manifest if args.manifest.is_absolute() else root / args.manifest
        output.write_text(serialized, encoding="utf-8")
    if args.list_only:
        sys.stdout.write(serialized)
        return 0
    return run_pytest(root, files, args.batch_size)


if __name__ == "__main__":
    raise SystemExit(main())
