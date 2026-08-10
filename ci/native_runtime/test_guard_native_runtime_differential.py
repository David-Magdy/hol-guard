from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_runtime import parity_signature, review_post_tool_native
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookSourceFileRef
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _NATIVE_BINARY, reason="compiled native runtime is required")


def _secret_token() -> str:
    return "".join(("gh", "p_")) + "d" * 30


def _engine(store: GuardStore) -> HookReviewEngine:
    return HookReviewEngine(
        store=store,
        scanner=ContentScanner(),
        cache=HookDecisionCache(store),
        config_loader=lambda guard_home, workspace: load_guard_config(guard_home, workspace=workspace),
    )


def _inline_request(
    *,
    tmp_path: Path,
    payload: dict[str, object],
    request_id: str,
) -> HookReviewRequest:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={"hook_event_name": "PostToolUse", **payload},
        payload_kind="inline",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _source_request(*, tmp_path: Path, relative_path: str, text: str, request_id: str) -> HookReviewRequest:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    path = tmp_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    source_ref = HookSourceFileRef(
        version=1,
        path=relative_path,
        output_sha256=sha256_text(text),
        output_chars=len(text),
        tool_input_path=relative_path,
    )
    return HookReviewRequest(
        harness="pi",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": relative_path},
            "guard_source_ref": {
                "version": 1,
                "path": relative_path,
                "output_sha256": source_ref.output_sha256,
                "output_chars": source_ref.output_chars,
                "tool_input_path": relative_path,
            },
        },
        payload_kind="source_file_ref",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=guard_home,
        source_scope="project",
        source_ref=source_ref,
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _assert_parity(request: HookReviewRequest) -> None:
    store = GuardStore(request.guard_home)
    python_response = _engine(store).review(request)
    native_response = review_post_tool_native(request, observe_mode=False)
    assert native_response is not None
    assert parity_signature(native_response) == parity_signature(python_response), (
        native_response,
        python_response,
    )


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("clean-small", {"tool_response": [{"type": "text", "text": "const value = 1;\n"}]}),
        ("empty", {"tool_response": ""}),
        (
            "multi-field-clean",
            {"stdout": "build complete\n", "stderr": "", "result": [{"type": "text", "text": "ok"}]},
        ),
        (
            "docs-placeholder",
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "docs/example.md"},
                "tool_response": [{"type": "text", "text": "token = placeholder-only\n"}],
            },
        ),
        (
            "large-clean",
            {"tool_response": [{"type": "text", "text": "const x = 1;\n" * 15_000}]},
        ),
    ],
)
def test_compiled_native_inline_allow_parity(tmp_path: Path, name: str, payload: dict[str, object]) -> None:
    try:
        _assert_parity(_inline_request(tmp_path=tmp_path, payload=payload, request_id=name))
    finally:
        close_resident_native_runtimes()


def test_compiled_native_inline_secret_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _inline_request(
                tmp_path=tmp_path,
                payload={"stdout": "ok", "stderr": _secret_token()},
                request_id="inline-secret",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_clean_source_read_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _source_request(
                tmp_path=tmp_path,
                relative_path="src/example.ts",
                text="export const value = 1;\n",
                request_id="source-clean",
            )
        )
    finally:
        close_resident_native_runtimes()


def test_compiled_native_secret_source_read_parity(tmp_path: Path) -> None:
    try:
        _assert_parity(
            _source_request(
                tmp_path=tmp_path,
                relative_path="src/private.ts",
                text=f"export const value = '{_secret_token()}';\n",
                request_id="source-secret",
            )
        )
    finally:
        close_resident_native_runtimes()
