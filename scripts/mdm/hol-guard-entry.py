"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from __future__ import annotations

from codex_plugin_scanner.guard.frozen_daemon_runtime import install_frozen_daemon_runtime

if __name__ == "__main__":
    install_frozen_daemon_runtime()

    from codex_plugin_scanner.guard.frozen_codex_runtime import (
        install_frozen_codex_runtime,
        run_frozen_internal_command,
    )

    install_frozen_codex_runtime()
    internal_exit_code = run_frozen_internal_command()
    if internal_exit_code is not None:
        raise SystemExit(internal_exit_code)

    from codex_plugin_scanner.cli import main

    raise SystemExit(main())
