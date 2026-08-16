"""Installed-wheel proof that eligible PostToolUse uses Rust by default."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_runtime import (
    native_mode,
    native_runtime_health,
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest


def _request(root: Path, text: str, request_id: str) -> HookReviewRequest:
    guard_home = root / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": text}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=root,
        home_dir=root,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
    )


def _synthetic_github_token() -> str:
    return "".join(("gh", "p_", "c" * 30))


def _short_temp_parent() -> str | None:
    """Keep Unix resident socket paths below platform sun_path limits."""
    if os.name == "nt":
        return None
    candidate = Path("/tmp")
    return str(candidate) if candidate.is_dir() else None


def main() -> int:
    assert "HOL_GUARD_NATIVE" not in os.environ
    assert "HOL_GUARD_NATIVE_BINARY" not in os.environ
    assert native_mode() == "auto"

    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (Path.cwd() / "src" / "codex_plugin_scanner").resolve()
    assert not package_path.is_relative_to(source_package), package_path

    status = native_runtime_status()
    assert status.mode == "auto"
    assert status.available and status.compatible, status
    assert status.reason == "native_ready"
    assert status.identity is not None
    assert status.capabilities is not None

    with tempfile.TemporaryDirectory(prefix="hg-auto-", dir=_short_temp_parent()) as temporary:
        root = Path(temporary)
        try:
            clean = review_post_tool_native(
                _request(root, "const value = 1;\n", "default-auto-clean"),
                observe_mode=False,
            )
            assert clean is not None
            assert clean.decision == "allow"
            assert clean.reason_code == "output_scan_allow"

            secret = review_post_tool_native(
                _request(root, _synthetic_github_token(), "default-auto-secret"),
                observe_mode=False,
            )
            assert secret is not None
            assert secret.decision == "deny"
            assert secret.reason_code == "output_secret_match"

            health = native_runtime_health(root / "guard-home")
            assert health.state == "healthy", health
            assert health.reason == "native_ready", health
            assert health.resident_failures == 0, health
            assert health.oneshot_failures == 0, health
            assert health.starts == 1, health
        finally:
            close_resident_native_runtimes()

    os.environ["HOL_GUARD_NATIVE"] = "off"
    try:
        assert native_mode() == "off"
        disabled = native_runtime_status()
        assert disabled.mode == "off"
        assert disabled.reason == "native_disabled"
    finally:
        del os.environ["HOL_GUARD_NATIVE"]

    print(
        json.dumps(
            {
                "default_mode": "auto",
                "runtime_reason": status.reason,
                "target": status.capabilities.target,
                "rollback": "off",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
