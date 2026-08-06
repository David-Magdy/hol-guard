"""Bounded preflight command entrypoint for broad local scan safety."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from .commands_support_interaction import _emit, _run_consumer_scan_with_mode


def _unsafe_broad_preflight_target(target: Path, *, home_dir: Path) -> bool:
    """Reject roots that make an omitted/`.` preflight traverse an entire account or filesystem."""

    try:
        resolved_target = target.resolve()
        resolved_home = home_dir.resolve()
    except (OSError, RuntimeError):
        return True
    filesystem_root = Path(resolved_target.anchor).resolve()
    return resolved_target in {resolved_home, filesystem_root}


def _run_guard_safe_preflight_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Run preflight without recursively scanning a whole home directory by accident."""

    del input_text
    raw_target = str(getattr(args, "target", ".") or ".")
    try:
        target = Path(raw_target).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        print(f"Error: unable to resolve preflight target: {error}", file=sys.stderr)
        return 2
    if _unsafe_broad_preflight_target(target, home_dir=Path.home()):
        message = "Choose a project directory or file instead of scanning your entire home directory or filesystem root."
        if bool(getattr(args, "json", False)):
            print(
                json.dumps(
                    {
                        "error": "preflight_target_too_broad",
                        "message": message,
                    },
                    sort_keys=True,
                ),
                file=output_stream or sys.stdout,
            )
        else:
            print(f"Error: {message}", file=sys.stderr)
        return 2

    payload = _run_consumer_scan_with_mode(
        target,
        intended_harness=getattr(args, "harness", None),
        cisco_mode=args.cisco_mode,
    )
    _emit("preflight", payload, getattr(args, "json", False))
    if getattr(args, "enforce", False):
        install_verdict = payload.get("install_verdict")
        if isinstance(install_verdict, dict) and str(install_verdict.get("action")) != "allow":
            return 2
    return 0


__all__ = ["_run_guard_safe_preflight_command", "_unsafe_broad_preflight_target"]
