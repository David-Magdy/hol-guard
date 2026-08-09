"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from __future__ import annotations

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.frozen_codex_runtime import (
    install_frozen_codex_runtime,
    run_frozen_internal_command,
)

if __name__ == "__main__":
    install_frozen_codex_runtime()
    internal_exit_code = run_frozen_internal_command()
    raise SystemExit(main() if internal_exit_code is None else internal_exit_code)
