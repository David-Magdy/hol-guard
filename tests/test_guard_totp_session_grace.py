"""Regression coverage for bounded TOTP reauthentication grace."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    require_approval_decision,
    update_settings,
)
from codex_plugin_scanner.guard.totp import totp_code_at_counter

PASSWORD = "correct-password"
ENROLLMENT_NOW = "2026-04-11T00:00:00+00:00"
FIRST_APPROVAL_NOW = "2026-04-11T00:00:31+00:00"
SESSION_A = "dashboard-session-a"
SESSION_B = "dashboard-session-b"


def _counter(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() // 30)


def _extract_secret(otpauth_uri: str) -> str:
    values = parse_qs(urlparse(otpauth_uri).query).get("secret")
    if not values:
        raise AssertionError("otpauth URI did not include a secret")
    return values[0]


def _enable_totp(guard_home: Path) -> str:
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    enrollment = begin_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="test-device",
        now=ENROLLMENT_NOW,
    )
    secret = _extract_secret(str(enrollment["otpauth_uri"]))
    enrollment_code = totp_code_at_counter(secret=secret, counter=_counter(ENROLLMENT_NOW))
    confirm_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=enrollment_code),
        now=ENROLLMENT_NOW,
    )
    return secret


def _approve(
    guard_home: Path,
    *,
    session_nonce: str | None,
    subject: str,
    now: str,
    code: str | None,
):
    return require_approval_decision(
        guard_home,
        action="allow",
        scope="artifact",
        subject=subject,
        session_nonce=session_nonce,
        approval_gate_input=ApprovalGateInput(totp_code=code),
        now=now,
    )


def test_totp_recent_auth_reuses_same_session_without_reaccepting_code(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    secret = _enable_totp(guard_home)
    code = totp_code_at_counter(secret=secret, counter=_counter(FIRST_APPROVAL_NOW))

    first = _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:first",
        now=FIRST_APPROVAL_NOW,
        code=code,
    )
    second = _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:second",
        now="2026-04-11T00:00:45+00:00",
        code=None,
    )
    repeated_code = _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:third",
        now="2026-04-11T00:00:50+00:00",
        code=code,
    )

    assert first is not None and first.totp_verified is True
    assert second is not None and second.totp_verified is True
    assert repeated_code is not None and repeated_code.totp_verified is True
    assert second.session_nonce == SESSION_A
    assert repeated_code.session_nonce == SESSION_A


def test_totp_recent_auth_does_not_cross_sessions(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    secret = _enable_totp(guard_home)
    code = totp_code_at_counter(secret=secret, counter=_counter(FIRST_APPROVAL_NOW))
    _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:first",
        now=FIRST_APPROVAL_NOW,
        code=code,
    )

    with pytest.raises(ApprovalGateError) as missing_code:
        _approve(
            guard_home,
            session_nonce=SESSION_B,
            subject="approval-request:second",
            now="2026-04-11T00:00:45+00:00",
            code=None,
        )
    assert missing_code.value.code == "approval_gate_totp_required"

    with pytest.raises(ApprovalGateError) as replayed_code:
        _approve(
            guard_home,
            session_nonce=SESSION_B,
            subject="approval-request:third",
            now="2026-04-11T00:00:45+00:00",
            code=code,
        )
    assert replayed_code.value.code == "approval_gate_totp_invalid"


def test_totp_recent_auth_expires_without_sliding_extension(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    secret = _enable_totp(guard_home)
    code = totp_code_at_counter(secret=secret, counter=_counter(FIRST_APPROVAL_NOW))
    _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:first",
        now=FIRST_APPROVAL_NOW,
        code=code,
    )
    _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:second",
        now="2026-04-11T00:01:15+00:00",
        code=None,
    )

    with pytest.raises(ApprovalGateError) as expired:
        _approve(
            guard_home,
            session_nonce=SESSION_A,
            subject="approval-request:third",
            now="2026-04-11T00:01:31+00:00",
            code=None,
        )
    assert expired.value.code == "approval_gate_totp_required"


def test_totp_approval_request_reuses_daemon_process_session(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    secret = _enable_totp(guard_home)
    code = totp_code_at_counter(secret=secret, counter=_counter(FIRST_APPROVAL_NOW))

    first = _approve(
        guard_home,
        session_nonce=None,
        subject="approval-request:first",
        now=FIRST_APPROVAL_NOW,
        code=code,
    )
    second = _approve(
        guard_home,
        session_nonce=None,
        subject="approval-request:second",
        now="2026-04-11T00:00:45+00:00",
        code=None,
    )

    assert first is not None and first.totp_verified is True
    assert second is not None and second.totp_verified is True
    assert first.session_nonce == second.session_nonce


def test_totp_recent_auth_tampering_fails_closed(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    secret = _enable_totp(guard_home)
    code = totp_code_at_counter(secret=secret, counter=_counter(FIRST_APPROVAL_NOW))
    _approve(
        guard_home,
        session_nonce=SESSION_A,
        subject="approval-request:first",
        now=FIRST_APPROVAL_NOW,
        code=code,
    )

    state_path = guard_home / "approval-gate.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    recent_auth = state["totp_recent_auth"]
    assert isinstance(recent_auth, dict)
    recent_auth["expires_at"] = "2026-04-11T01:00:00+00:00"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ApprovalGateError) as tampered:
        _approve(
            guard_home,
            session_nonce=SESSION_A,
            subject="approval-request:second",
            now="2026-04-11T00:00:45+00:00",
            code=None,
        )
    assert tampered.value.code == "approval_gate_totp_required"
