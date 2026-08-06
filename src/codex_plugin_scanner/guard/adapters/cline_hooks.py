"""Managed native Cline hook installation and health proofs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .guard_cli_attestation import resolve_attested_guard_cli

_MANAGED_MARKER = "HOL_GUARD_MANAGED_CLINE_HOOK_V1"
_SCHEMA_VERSION = 1
_MAX_HOOK_INPUT_BYTES = 1024 * 1024
_MAX_HOOK_DEPTH = 48
_HOOK_TIMEOUT_SECONDS = 12
_PROOF_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
_NATIVE_EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "TaskStart",
    "TaskError",
    "SessionShutdown",
)
_SUPPORTED_SUFFIXES = ("", ".py")


def cline_hook_roots(context: HarnessContext) -> tuple[Path, ...]:
    """Return supported global Cline hook roots in preferred order."""

    return (
        context.home_dir / ".cline" / "hooks",
        context.home_dir / "Documents" / "Cline" / "Hooks",
    )


def _state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "native-hooks-state.json"


def _proof_path(context: HarnessContext, event_name: str) -> Path:
    return context.guard_home / "managed" / "cline" / "proofs" / f"native-{event_name.lower()}.json"


def _safe_parent(path: Path, *, home_dir: Path) -> None:
    """Reject symlinked or obviously unsafe managed hook destinations."""

    resolved_home = home_dir.resolve(strict=False)
    resolved_parent = path.parent.resolve(strict=False)
    if not resolved_parent.is_relative_to(resolved_home):
        raise RuntimeError("Cline hook destination is outside the configured home directory")
    current = path.parent
    while current != resolved_home and current != current.parent:
        if current.exists() and current.is_symlink():
            raise RuntimeError(f"Cline hook parent is a symlink: {current}")
        current = current.parent
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"Cline hook destination is a symlink: {path}")


def _is_managed_source(source: str) -> bool:
    return _MANAGED_MARKER in source


def _is_managed_file(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        return _is_managed_source(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return False


def _slot_for_event(root: Path, event_name: str) -> Path:
    """Select a Cline-recognized filename without overwriting user hooks."""

    for suffix in _SUPPORTED_SUFFIXES:
        candidate = root / f"{event_name}{suffix}"
        if not candidate.exists() or _is_managed_file(candidate):
            return candidate
    raise RuntimeError(
        f"Cline already has user-owned {event_name} hook slots in {root}; Guard will not overwrite them"
    )


def _atomic_write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    if executable and os.name != "nt":
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    os.replace(temporary, path)


def _hook_source(
    context: HarnessContext,
    *,
    event_name: str,
    guard_cli: list[str],
) -> str:
    proof_path = _proof_path(context, event_name)
    blocking = event_name == "PreToolUse"
    return f'''#!/usr/bin/env python3
# {_MANAGED_MARKER}
# schema_version={_SCHEMA_VERSION}
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

EVENT = {event_name!r}
BLOCKING = {blocking!r}
MAX_BYTES = {_MAX_HOOK_INPUT_BYTES}
MAX_DEPTH = {_MAX_HOOK_DEPTH}
TIMEOUT_SECONDS = {_HOOK_TIMEOUT_SECONDS}
GUARD_CLI = {guard_cli!r}
PROOF_PATH = Path({str(proof_path)!r})


def emit(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\\n")
    sys.stdout.flush()


def fail(message):
    if BLOCKING:
        emit({{"cancel": True, "errorMessage": message, "contextModification": message}})
    else:
        emit({{"cancel": False, "contextModification": "HOL Guard hook diagnostic: " + message}})


def bounded_depth(value):
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            return False
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return True


def extract_json(stdout):
    text = stdout.strip()
    if not text:
        return None
    for candidate in [text, *reversed([line.strip() for line in text.splitlines() if line.strip()])]:
        if not candidate.startswith("{{"):
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def reason(payload):
    for key in ("reason", "stopReason", "review_hint", "systemMessage", "message", "error"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    specific = payload.get("hookSpecificOutput")
    if isinstance(specific, dict):
        for key in ("permissionDecisionReason", "additionalContext"):
            value = specific.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        decision = specific.get("decision")
        if isinstance(decision, dict):
            value = decision.get("message")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "HOL Guard blocked this action."


def blocks(payload):
    if payload.get("blocked") is True or payload.get("continue") is False:
        return True
    decision = payload.get("decision")
    if isinstance(decision, str) and decision.lower() in {{"deny", "block", "ask"}}:
        return True
    action = payload.get("policy_action", payload.get("policyAction"))
    if isinstance(action, str) and action.lower() in {{"review", "require-reapproval", "sandbox-required", "block"}}:
        return True
    specific = payload.get("hookSpecificOutput")
    if isinstance(specific, dict):
        permission = specific.get("permissionDecision")
        if isinstance(permission, str) and permission.lower() in {{"deny", "block", "ask"}}:
            return True
        nested = specific.get("decision")
        if isinstance(nested, dict):
            behavior = nested.get("behavior")
            if isinstance(behavior, str) and behavior.lower() in {{"deny", "block", "ask"}}:
                return True
    return False


def guard_payloads(payload):
    if EVENT != "PreToolUse":
        return [payload]
    current = payload.get("tool_call")
    legacy = payload.get("preToolUse")
    current_name = current.get("name") if isinstance(current, dict) else None
    legacy_name = legacy.get("toolName") if isinstance(legacy, dict) else None
    name = current_name or legacy_name
    if name != "run_commands":
        return [payload]
    raw_input = current.get("input") if isinstance(current, dict) else None
    if raw_input is None and isinstance(legacy, dict):
        raw_input = legacy.get("parameters")
    if isinstance(raw_input, dict):
        commands = raw_input.get("commands", raw_input.get("command", raw_input.get("cmd")))
    else:
        commands = raw_input
    if isinstance(commands, str):
        try:
            decoded = json.loads(commands)
        except json.JSONDecodeError:
            decoded = commands
        commands = decoded
    if isinstance(commands, str):
        commands = [commands]
    if not isinstance(commands, list):
        return [payload]
    normalized = []
    for command in commands:
        if isinstance(command, dict):
            command = command.get("command", command.get("cmd"))
        if not isinstance(command, str) or not command.strip():
            continue
        child = dict(payload)
        child.pop("preToolUse", None)
        child["tool_call"] = {{
            "id": current.get("id", "") if isinstance(current, dict) else "",
            "name": "run_command",
            "input": {{"command": command}},
        }}
        normalized.append(child)
    return normalized or [payload]


def write_proof():
    try:
        PROOF_PATH.parent.mkdir(parents=True, exist_ok=True)
        source = "synthetic" if os.environ.get("HOL_GUARD_CLINE_CANARY") == "1" else "cline"
        payload = {{"schema_version": 1, "event": EVENT, "source": source, "timestamp": time.time()}}
        temporary = PROOF_PATH.with_name(PROOF_PATH.name + ".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.replace(temporary, PROOF_PATH)
    except OSError:
        pass


def main():
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        fail("HOL Guard rejected an oversized Cline hook request.")
        return 0
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("HOL Guard could not parse the Cline hook request safely.")
        return 0
    if not isinstance(payload, dict) or not bounded_depth(payload):
        fail("HOL Guard rejected an invalid Cline hook request.")
        return 0
    guard = None
    denied = False
    why = "HOL Guard blocked this action."
    for guard_payload in guard_payloads(payload):
        try:
            result = subprocess.run(
                [*GUARD_CLI, "--harness", "cline", "--json"],
                input=json.dumps(guard_payload),
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            fail("HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed.")
            return 0
        guard = extract_json(result.stdout)
        if guard is None:
            fail("HOL Guard returned an invalid decision; this Cline action was not allowed to proceed.")
            return 0
        if blocks(guard):
            denied = True
            why = reason(guard)
            break
    write_proof()
    if BLOCKING:
        emit({{"cancel": denied, "errorMessage": why if denied else "", "contextModification": why if denied else ""}})
    else:
        emit({{"cancel": False, "contextModification": why if denied else ""}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _load_state(context: HarnessContext) -> dict[str, object]:
    try:
        payload = json.loads(_state_path(context).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_state(context: HarnessContext, payload: dict[str, object]) -> None:
    state_path = _state_path(context)
    _atomic_write(state_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def install_cline_hooks(context: HarnessContext) -> dict[str, object]:
    """Install Guard-owned Cline file hooks without overwriting user files."""

    attested = resolve_attested_guard_cli(context)
    guard_cli = [*attested.command, "guard", "hook"]
    root = cline_hook_roots(context)[0]
    _safe_parent(root / "PreToolUse", home_dir=context.home_dir)
    root.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    digests: dict[str, str] = {}
    for event_name in _NATIVE_EVENTS:
        slot = _slot_for_event(root, event_name)
        _safe_parent(slot, home_dir=context.home_dir)
        source = _hook_source(context, event_name=event_name, guard_cli=guard_cli)
        _atomic_write(slot, source, executable=True)
        paths[event_name] = str(slot)
        digests[event_name] = sha256(source.encode("utf-8")).hexdigest()
    state = {
        "schema_version": _SCHEMA_VERSION,
        "transport": "hooks",
        "root": str(root),
        "paths": paths,
        "sha256": digests,
        "guard_cli_identity": attested.manifest_payload(),
    }
    _write_state(context, state)
    canary = run_cline_hook_canary(context)
    return {
        "transport": "hooks",
        "managed_hooks_root": str(root),
        "managed_hook_paths": paths,
        "managed_hook_sha256": digests,
        "guard_cli_identity": attested.manifest_payload(),
        "synthetic_canary": canary,
        "post_tool_output_mediation": "observation-only",
    }


def run_cline_hook_canary(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    paths = state.get("paths")
    if not isinstance(paths, dict):
        return {"ok": False, "reason": "managed_hook_state_missing"}
    path_value = paths.get("PreToolUse")
    if not isinstance(path_value, str):
        return {"ok": False, "reason": "pretool_hook_missing"}
    path = Path(path_value)
    if not _is_managed_file(path):
        return {"ok": False, "reason": "pretool_hook_not_guard_owned"}
    payload = {
        "hookName": "PreToolUse",
        "taskId": "hol-guard-cline-canary",
        "workspaceRoots": [str(context.workspace_dir or context.home_dir)],
        "preToolUse": {"toolName": "read_files", "parameters": {"paths": "[]"}},
    }
    env = dict(os.environ)
    env["HOL_GUARD_CLINE_CANARY"] = "1"
    try:
        result = subprocess.run(
            [str(path)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=_HOOK_TIMEOUT_SECONDS + 2,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    try:
        output = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        output = None
    return {
        "ok": result.returncode == 0 and isinstance(output, dict) and isinstance(output.get("cancel"), bool),
        "return_code": result.returncode,
        "valid_json": isinstance(output, dict),
    }


def _proof_state(context: HarnessContext, event_name: str) -> dict[str, object]:
    path = _proof_path(context, event_name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "fresh": False, "live": False}
    timestamp = payload.get("timestamp") if isinstance(payload, dict) else None
    fresh = isinstance(timestamp, (int, float)) and time.time() - float(timestamp) <= _PROOF_MAX_AGE_SECONDS
    return {
        "present": True,
        "fresh": fresh,
        "live": fresh and payload.get("source") == "cline",
        "event": event_name,
    }


def cline_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """Verify hook ownership, integrity, canary contract, and live host proof."""

    state = _load_state(context)
    paths = state.get("paths")
    digests = state.get("sha256")
    integrity_ok = isinstance(paths, dict) and isinstance(digests, dict)
    missing: list[str] = []
    modified: list[str] = []
    if integrity_ok:
        for event_name in _NATIVE_EVENTS:
            path_value = paths.get(event_name)
            digest_value = digests.get(event_name)
            if not isinstance(path_value, str) or not isinstance(digest_value, str):
                missing.append(event_name)
                continue
            path = Path(path_value)
            if not path.is_file() or not _is_managed_file(path):
                missing.append(event_name)
                continue
            try:
                actual = sha256(path.read_bytes()).hexdigest()
            except OSError:
                missing.append(event_name)
                continue
            if actual != digest_value:
                modified.append(event_name)
    pretool = _proof_state(context, "PreToolUse")
    posttool = _proof_state(context, "PostToolUse")
    canary = run_cline_hook_canary(context) if integrity_ok and not missing and not modified else {"ok": False}
    return {
        "installed": bool(integrity_ok and not missing),
        "integrity_ok": bool(integrity_ok and not missing and not modified),
        "synthetic_canary_ok": canary.get("ok") is True,
        "live_pretool_proof": pretool,
        "live_posttool_proof": posttool,
        "pretool_blocking_proven": pretool.get("live") is True,
        "posttool_observation_proven": posttool.get("live") is True,
        "post_tool_output_mediation": "observation-only",
        "missing_events": missing,
        "modified_events": modified,
        "ready": bool(
            integrity_ok
            and not missing
            and not modified
            and canary.get("ok") is True
            and pretool.get("live") is True
        ),
    }


def uninstall_cline_hooks(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    paths = state.get("paths")
    removed: list[str] = []
    retained: list[str] = []
    if isinstance(paths, dict):
        for value in paths.values():
            if not isinstance(value, str):
                continue
            path = Path(value)
            if not path.exists():
                continue
            if _is_managed_file(path):
                try:
                    path.unlink()
                    removed.append(str(path))
                except OSError:
                    retained.append(str(path))
            else:
                retained.append(str(path))
    state_path = _state_path(context)
    if not retained and state_path.is_file():
        state_path.unlink()
    return {
        "transport": "hooks",
        "removed": removed,
        "retained_modified_or_unowned": retained,
        "complete": not retained,
    }


__all__ = [
    "cline_hook_roots",
    "cline_native_hook_state",
    "install_cline_hooks",
    "run_cline_hook_canary",
    "uninstall_cline_hooks",
]
