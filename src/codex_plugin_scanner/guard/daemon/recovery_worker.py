"""Detached daemon recovery worker for bounded harness hooks."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

from .manager import GuardDaemonHookFailureKind, recover_guard_daemon_after_hook_failure


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    guard_home, home_dir, raw_failure_kind = sys.argv[1:]
    failure_kind: GuardDaemonHookFailureKind
    if raw_failure_kind not in {
        "authenticated-control-plane-failure",
        "overload",
        "transport-failure",
    }:
        return 2
    failure_kind = cast(GuardDaemonHookFailureKind, raw_failure_kind)
    _ = recover_guard_daemon_after_hook_failure(
        Path(guard_home),
        home_dir=Path(home_dir),
        failure_kind=failure_kind,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
