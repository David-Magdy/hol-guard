"""Atheris target for bounded archive and encoded-content inspection."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from codex_plugin_scanner.assurance import ScanBudget, run_assurance_checks


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    if len(data) > 1024 * 1024:
        return
    with tempfile.TemporaryDirectory(prefix="hol-guard-assurance-fuzz-") as temporary:
        root = Path(temporary)
        (root / "payload.zip").write_bytes(data)
        run_assurance_checks(
            root,
            ScanBudget(
                max_files=64,
                max_hashed_bytes=2 * 1024 * 1024,
                max_text_file_bytes=128 * 1024,
                max_total_text_bytes=256 * 1024,
                max_archive_bytes=1024 * 1024,
            ),
        )


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
