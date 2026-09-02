from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import IO

import pytest
from native_hook_client_support import (
    _invoke,
    _push_snapshot,
    _request,
    _result,
    _state_files,
    _terminate_process,
    _terminate_state_process,
    _write_forged_state,
)
from native_hook_client_support import native_runtime as _native_runtime_fixture  # noqa: F401


def test_native_hook_client_reuses_one_authenticated_generation(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    first = _invoke(runtime, state_dir, request)
    second = _invoke(runtime, state_dir, request)
    assert first["schema"] == "guard-hook-edge-result.v2"
    assert first["authority"] == "rust"
    assert first["harness"] == "claude-code"
    assert first["event_name"] == "PreToolUse"
    assert _result(first)["minimum_action"] == "allow"
    assert second == first
    assert len(_state_files(state_dir)) == 1


def test_native_resident_stop_is_idempotent_after_verified_shutdown(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _invoke(runtime, state_dir, _request(runtime, tmp_path))
    command = (str(runtime), "resident-stop", "--state-dir", str(state_dir))

    first = subprocess.run(command, check=False, capture_output=True, timeout=3)
    assert first.returncode == 0
    second = subprocess.run(command, check=False, capture_output=True, timeout=3)
    assert second.returncode == 0
    assert len(_state_files(state_dir)) == 1


def test_separate_process_stop_reaps_supervisor_and_serving_process(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """A resident starter that stays alive must reap its stopped supervisor."""
    if os.name == "nt":
        pytest.skip("the local PID disappearance probe is POSIX-only")

    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _push_snapshot(runtime, state_dir, request)
    stream = subprocess.Popen(
        (str(runtime), "resident-client-stream", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert stream.stdin is not None
        stream.stdin.write(len(request).to_bytes(4, "big") + request)
        stream.stdin.flush()
        response = _read_stream_frame(stream)
        assert response["authority"] == "rust"

        state_files = _state_files(state_dir)
        assert len(state_files) == 1
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        process_id = state["process_id"]
        supervisor_id = state["owner_process_id"]
        assert isinstance(process_id, int) and process_id > 0
        assert isinstance(supervisor_id, int) and supervisor_id > 0
        assert process_id != stream.pid
        assert supervisor_id != stream.pid

        command = (str(runtime), "resident-stop", "--state-dir", str(state_dir))
        first = subprocess.run(command, check=False, capture_output=True, timeout=3)
        assert first.returncode == 0
        _wait_for_pid_disappearance(process_id)
        _wait_for_pid_disappearance(supervisor_id)

        second = subprocess.run(command, check=False, capture_output=True, timeout=3)
        assert second.returncode == 0
    finally:
        if stream.stdin is not None:
            stream.stdin.close()
        try:
            stream.wait(timeout=3)
        except subprocess.TimeoutExpired:
            stream.kill()
            stream.wait(timeout=3)


@pytest.mark.skipif(os.name == "nt", reason="the endpoint and lock probe is POSIX-only")
def test_hard_killed_resident_client_stream_contains_supervisor_and_serving_process(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    # Install the policy snapshot before opening the stream, then retire the
    # bootstrap resident. The stream's first request must create the managed
    # generation itself so its PID/identity is the supervisor's parent.
    _push_snapshot(runtime, state_dir, request)
    stopped = subprocess.run(
        (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert stopped.returncode == 0
    stream = subprocess.Popen(
        (str(runtime), "resident-client-stream", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert stream.stdin is not None
        stream.stdin.write(len(request).to_bytes(4, "big") + request)
        stream.stdin.flush()
        response = _read_stream_frame(stream)
        assert response["authority"] == "rust"

        state_file = _state_files(state_dir)[0]
        state = json.loads(state_file.read_text(encoding="utf-8"))
        serving_process_id = state["process_id"]
        supervisor_process_id = state["owner_process_id"]
        endpoint = state["endpoint"]
        assert isinstance(serving_process_id, int) and serving_process_id > 0
        assert isinstance(supervisor_process_id, int) and supervisor_process_id > 0
        assert isinstance(endpoint, str) and endpoint
        assert serving_process_id != stream.pid
        assert supervisor_process_id != stream.pid

        # SIGKILL leaves no opportunity for the stream to close its own
        # descriptors. The package-bound supervisor must observe the exact
        # parent identity disappearing and contain the managed serving tree.
        stream.kill()
        stream.wait(timeout=3)
        _wait_for_pid_disappearance(supervisor_process_id)
        _wait_for_pid_disappearance(serving_process_id)
        _wait_for_path_disappearance(Path(endpoint))
        _assert_managed_scope_locks_are_free(state_file.parent)
    finally:
        if stream.poll() is None:
            stream.kill()
            stream.wait(timeout=3)


@pytest.mark.skipif(os.name == "nt", reason="the endpoint and lock probe is POSIX-only")
def test_hard_killed_client_stream_does_not_contain_existing_one_shot_resident(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    initial_response = _invoke(runtime, state_dir, request)
    initial_state_file = _state_files(state_dir)[0]
    initial_state = json.loads(initial_state_file.read_text(encoding="utf-8"))
    initial_identity = tuple(initial_state[field] for field in ("generation", "process_id", "owner_process_id"))

    stream = subprocess.Popen(
        (str(runtime), "resident-client-stream", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert stream.stdin is not None
        stream.stdin.write(len(request).to_bytes(4, "big") + request)
        stream.stdin.flush()
        assert _read_stream_frame(stream) == initial_response

        stream.kill()
        stream.wait(timeout=3)
        surviving_state_files = _state_files(state_dir)
        assert len(surviving_state_files) == 1
        surviving_state = json.loads(surviving_state_files[0].read_text(encoding="utf-8"))
        assert surviving_state_files[0].name == initial_state_file.name
        assert (
            tuple(surviving_state[field] for field in ("generation", "process_id", "owner_process_id"))
            == initial_identity
        )

        followup_response = _invoke(runtime, state_dir, request)
        assert followup_response == initial_response
        final_state_files = _state_files(state_dir)
        assert len(final_state_files) == 1
        final_state = json.loads(final_state_files[0].read_text(encoding="utf-8"))
        assert (
            tuple(final_state[field] for field in ("generation", "process_id", "owner_process_id")) == initial_identity
        )
    finally:
        if stream.poll() is None:
            stream.kill()
            stream.wait(timeout=3)


def _read_stream_frame(stream: subprocess.Popen[bytes]) -> dict[str, object]:
    assert stream.stdout is not None
    header = _read_stream_bytes(stream.stdout, 4)
    length = int.from_bytes(header, "big")
    assert 0 < length <= 16 * 1024 * 1024
    return json.loads(_read_stream_bytes(stream.stdout, length))


def _read_stream_bytes(stream: IO[bytes], length: int) -> bytes:
    selector = selectors.DefaultSelector()
    selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + 3
    output = bytearray()
    try:
        while len(output) < length:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "timed out waiting for resident stream response"
            assert selector.select(remaining), "resident stream response was not readable"
            chunk = os.read(stream.fileno(), length - len(output))
            assert chunk, "resident stream closed before its response completed"
            output.extend(chunk)
    finally:
        selector.close()
    return bytes(output)


def _wait_for_pid_disappearance(process_id: int) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if not _pid_is_live(process_id):
            return
        time.sleep(0.01)
    raise AssertionError(f"process {process_id} remained present after resident stop")


def _pid_is_live(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

    status = subprocess.run(
        ("ps", "-o", "stat=", "-p", str(process_id)),
        check=False,
        capture_output=True,
        text=True,
        timeout=1,
    )
    if status.returncode != 0 or not status.stdout.strip():
        return False
    return not status.stdout.strip().startswith("Z")


def _wait_for_path_disappearance(path: Path) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if not path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"managed endpoint remained present after parent death: {path}")


def _assert_managed_scope_locks_are_free(scope: Path) -> None:
    import fcntl

    directory_fd = os.open(scope, os.O_RDONLY)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(directory_fd)
        raise AssertionError("managed resident directory lock remained held") from error
    try:
        marker_path = scope / "managed-resident-owner.v1.lock"
        with marker_path.open("r+") as marker:
            try:
                fcntl.flock(marker.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise AssertionError("managed resident marker lock remained held") from error
    finally:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
        os.close(directory_fd)


def test_release_resident_starts_without_authority_and_rejects_approval(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path, default_action="review")
    ordinary = _invoke(runtime, state_dir, request)
    assert ordinary["authority"] == "rust"
    assert _result(ordinary)["minimum_action"] == "review"

    envelope = json.loads(request)
    approval_request = json.dumps(
        {
            "operation": "approval_challenge",
            "request": {
                "schema": "guard-native-approval-challenge-request.v3",
                "version": 3,
                "envelope": envelope,
            },
        },
        separators=(",", ":"),
    ).encode()
    result = subprocess.run(
        (str(runtime), "resident-client", "--stdin", str(state_dir)),
        input=approval_request,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["error"] == "native_approval_signing_authority_unavailable"


def test_native_hook_client_rejects_self_authenticated_forged_state(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    _write_forged_state(runtime, state_dir)
    response = _invoke(runtime, state_dir, _request(runtime, tmp_path))
    assert response["authority"] == "rust"
    assert _result(response)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1


def test_native_hook_client_recovers_after_exact_managed_process_exit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    initial_state = _state_files(state_dir)[0]
    _terminate_state_process(initial_state)
    recovered = _invoke(runtime, state_dir, request)
    assert _result(recovered)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1
    assert _state_files(state_dir)[0].name != initial_state.name


def test_native_hook_client_recovers_after_supervisor_exit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    _invoke(runtime, state_dir, request)
    initial_state = _state_files(state_dir)[0]
    state = json.loads(initial_state.read_text(encoding="utf-8"))
    owner_process_id = state["owner_process_id"]
    assert isinstance(owner_process_id, int) and owner_process_id > 0
    _terminate_process(owner_process_id)
    recovered = _invoke(runtime, state_dir, request)
    assert _result(recovered)["minimum_action"] == "allow"
    assert len(_state_files(state_dir)) == 1
    assert _state_files(state_dir)[0].name != initial_state.name


def test_native_hook_client_restart_budget_opens_circuit(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path)
    observed_generations: set[int] = set()
    for generation_index in range(3):
        response = _invoke(runtime, state_dir, request)
        assert response["authority"] == "rust"
        state_files = _state_files(state_dir)
        assert len(state_files) == 1
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        generation = state["generation"]
        assert isinstance(generation, int)
        observed_generations.add(generation)
        assert len(observed_generations) == generation_index + 1
        _terminate_state_process(state_files[-1])
    blocked = subprocess.run(
        (str(runtime), "hook-client", "--stdin", str(state_dir)),
        input=request,
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert blocked.returncode != 0
    assert b"native_resident_restart_circuit_open" in blocked.stderr
