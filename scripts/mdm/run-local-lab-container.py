#!/usr/bin/env python3
"""Build and run the portable MDM contract lab without network access."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Final

_REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
_DOCKERFILE: Final = _REPOSITORY_ROOT / "scripts" / "mdm" / "Dockerfile.local-lab"
_DEFAULT_IMAGE: Final = "hol-guard-mdm-local-lab:local"


def _docker_build_command(image: str) -> list[str]:
    return ["docker", "build", "--tag", image, "--file", str(_DOCKERFILE), str(_REPOSITORY_ROOT)]


def _docker_run_command(image: str) -> list[str]:
    source_mount = f"type=bind,src={_REPOSITORY_ROOT},dst=/hol-guard-source,readonly"
    return [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--mount",
        source_mount,
        image,
        "--json",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=_DEFAULT_IMAGE, help="container image tag for the local lab")
    parser.add_argument("--skip-build", action="store_true", help="run an already-built local lab image")
    parser.add_argument("--dry-run", action="store_true", help="print the Docker commands without executing them")
    args = parser.parse_args()

    build_command = _docker_build_command(args.image)
    run_command = _docker_run_command(args.image)
    if args.dry_run:
        print(json.dumps({"build": build_command, "run": run_command}, sort_keys=True))
        return 0

    if not args.skip_build:
        subprocess.run(build_command, check=True)
    return subprocess.run(run_command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
