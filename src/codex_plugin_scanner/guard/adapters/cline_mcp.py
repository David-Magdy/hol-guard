"""Cline MCP discovery, Guard proxying, and conservative restoration."""

from __future__ import annotations

import json
import os
import sys
from hashlib import sha256
from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from .base import HarnessContext
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    proxy_process_env,
)


def _cline_dir(context: HarnessContext) -> Path:
    configured = os.environ.get("CLINE_DIR", "").strip()
    return Path(configured).expanduser() if configured else context.home_dir / ".cline"


def cline_mcp_settings_candidates(context: HarnessContext) -> tuple[Path, ...]:
    """Return current and legacy Cline MCP settings paths without executing Cline."""

    explicit = os.environ.get("CLINE_MCP_SETTINGS_PATH", "").strip()
    cline_dir = _cline_dir(context)
    home = context.home_dir
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    paths.extend(
        (
            cline_dir / "data" / "settings" / "cline_mcp_settings.json",
            cline_dir / "settings" / "cline_mcp_settings.json",
            home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            home / ".config" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            home / "AppData" / "Roaming" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        )
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return tuple(unique)


def _json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _servers_object(payload: dict[str, object]) -> tuple[str, dict[str, object]]:
    for key in ("mcpServers", "mcp"):
        value = payload.get(key)
        if isinstance(value, dict):
            return key, {str(name): config for name, config in value.items() if isinstance(name, str)}
    return "mcpServers", {}


def _string_env(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        key.strip(): item
        for key, item in value.items()
        if isinstance(key, str) and key.strip() and isinstance(item, str)
    }


def detect_cline_mcp(context: HarnessContext) -> HarnessDetection:
    artifacts: list[GuardArtifact] = []
    found: list[str] = []
    for path in cline_mcp_settings_candidates(context):
        if not path.is_file():
            continue
        payload = _json_object(path)
        if not payload:
            continue
        found.append(str(path))
        _server_key, servers = _servers_object(payload)
        for name, raw in servers.items():
            if not isinstance(raw, dict):
                continue
            command = raw.get("command")
            args_value = raw.get("args")
            args = tuple(item for item in args_value if isinstance(item, str)) if isinstance(args_value, list) else ()
            url = raw.get("url") or raw.get("endpoint")
            transport = raw.get("type") or raw.get("transport")
            environment = _string_env(raw.get("env", raw.get("environment")))
            raw_headers = raw.get("headers")
            headers = (
                {key: value for key, value in raw_headers.items() if isinstance(key, str) and isinstance(value, str)}
                if isinstance(raw_headers, dict)
                else {}
            )
            normalized_transport = (
                str(transport).strip().lower()
                if isinstance(transport, str) and transport.strip()
                else ("http" if isinstance(url, str) and url.strip() else "stdio")
            )
            metadata = enrich_mcp_server_metadata(
                {
                    "name": name,
                    "env": environment,
                    "env_keys": sorted(environment),
                    "headers_keys": sorted(headers),
                    "enabled": raw.get("disabled") is not True,
                    "guard_managed_proxy": is_guard_proxy_command(
                        command if isinstance(command, str) else None,
                        args,
                    ),
                },
                command=command if isinstance(command, str) else None,
                args=args,
                url=url if isinstance(url, str) else None,
                transport=normalized_transport,
                configured_headers=headers,
            )
            artifacts.append(
                enrich_artifact_with_mcp_skill_firewall(
                    GuardArtifact(
                        artifact_id=f"cline:global:{name}",
                        name=name,
                        harness="cline",
                        artifact_type="mcp_server",
                        source_scope="global",
                        config_path=str(path),
                        command=command if isinstance(command, str) else None,
                        args=args,
                        url=url if isinstance(url, str) else None,
                        transport=normalized_transport,
                        metadata=metadata,
                    )
                )
            )
    return HarnessDetection(
        harness="cline",
        installed=bool(found),
        command_available=False,
        config_paths=tuple(found),
        artifacts=tuple(artifacts),
        warnings=(),
    )


def _backup_root(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "mcp-backups"


def _backup_path(context: HarnessContext, config_path: Path) -> Path:
    digest = sha256(str(config_path.resolve(strict=False)).encode("utf-8")).hexdigest()[:16]
    return _backup_root(context) / f"{digest}.json"


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _proxy_entry(context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
    args = proxy_cli_args(
        proxy_command="mcp-proxy",
        guard_home=str(context.guard_home),
        server=server,
        home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
    )
    entry: dict[str, object] = {
        "command": sys.executable,
        "args": args,
        "type": "stdio",
    }
    env = merge_guard_launcher_env(proxy_process_env(server.env))
    if env:
        entry["env"] = env
    return entry


def install_cline_mcp_proxies(context: HarnessContext) -> dict[str, object]:
    detection = detect_cline_mcp(context)
    by_path: dict[str, list[ManagedMcpServer]] = {}
    for server in managed_stdio_servers(detection):
        by_path.setdefault(server.config_path, []).append(server)
    changed: list[str] = []
    managed_servers: list[str] = []
    skipped_remote = [
        artifact.name
        for artifact in detection.artifacts
        if artifact.artifact_type == "mcp_server"
        and artifact.command is None
        and isinstance(artifact.url, str)
        and artifact.url.strip()
    ]
    for path_text, servers in by_path.items():
        path = Path(path_text)
        resolved_home = context.home_dir.resolve(strict=False)
        if not path.resolve(strict=False).is_relative_to(resolved_home):
            continue
        original_bytes = path.read_bytes()
        payload = _json_object(path)
        key, entries = _servers_object(payload)
        backup_path = _backup_path(context, path)
        if not backup_path.exists():
            backup_payload = {
                "schema_version": 1,
                "config_path": str(path),
                "original_sha256": _sha(original_bytes),
                "original_text": original_bytes.decode("utf-8"),
                "managed_sha256": None,
            }
            _atomic_write_bytes(backup_path, (json.dumps(backup_payload, sort_keys=True) + "\n").encode("utf-8"))
        for server in servers:
            if server.name not in entries or not isinstance(entries[server.name], dict):
                continue
            entries[server.name] = _proxy_entry(context, server)
            managed_servers.append(server.name)
        payload[key] = entries
        managed_bytes = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        _atomic_write_bytes(path, managed_bytes)
        backup_payload = _json_object(backup_path)
        backup_payload["managed_sha256"] = _sha(managed_bytes)
        _atomic_write_bytes(backup_path, (json.dumps(backup_payload, sort_keys=True) + "\n").encode("utf-8"))
        changed.append(str(path))
    return {
        "changed_config_paths": changed,
        "managed_servers": sorted(dict.fromkeys(managed_servers)),
        "skipped_remote_servers": sorted(dict.fromkeys(skipped_remote)),
        "backup_root": str(_backup_root(context)),
    }


def cline_mcp_proxy_state(context: HarnessContext) -> dict[str, object]:
    backup_root = _backup_root(context)
    records: list[dict[str, object]] = []
    ready = True
    if backup_root.is_dir():
        for backup_path in sorted(backup_root.glob("*.json")):
            backup = _json_object(backup_path)
            config_value = backup.get("config_path")
            managed_sha = backup.get("managed_sha256")
            current_sha = None
            if isinstance(config_value, str) and Path(config_value).is_file():
                try:
                    current_sha = _sha(Path(config_value).read_bytes())
                except OSError:
                    pass
            matched = isinstance(managed_sha, str) and current_sha == managed_sha
            ready = ready and matched
            records.append(
                {
                    "config_path": config_value,
                    "managed_integrity_ok": matched,
                }
            )
    return {
        "configured": bool(records),
        "ready": ready if records else True,
        "configs": records,
    }


def restore_cline_mcp_proxies(context: HarnessContext) -> dict[str, object]:
    restored: list[str] = []
    retained: list[str] = []
    backup_root = _backup_root(context)
    if not backup_root.is_dir():
        return {"restored": restored, "retained_modified": retained, "complete": True}
    for backup_path in sorted(backup_root.glob("*.json")):
        backup = _json_object(backup_path)
        config_value = backup.get("config_path")
        original_text = backup.get("original_text")
        managed_sha = backup.get("managed_sha256")
        if not isinstance(config_value, str) or not isinstance(original_text, str):
            retained.append(str(backup_path))
            continue
        path = Path(config_value)
        if path.is_file():
            try:
                current_sha = _sha(path.read_bytes())
            except OSError:
                retained.append(str(path))
                continue
            if not isinstance(managed_sha, str) or current_sha != managed_sha:
                retained.append(str(path))
                continue
        _atomic_write_bytes(path, original_text.encode("utf-8"))
        restored.append(str(path))
        backup_path.unlink()
    if not retained:
        try:
            backup_root.rmdir()
        except OSError:
            pass
    return {"restored": restored, "retained_modified": retained, "complete": not retained}


__all__ = [
    "cline_mcp_proxy_state",
    "cline_mcp_settings_candidates",
    "detect_cline_mcp",
    "install_cline_mcp_proxies",
    "restore_cline_mcp_proxies",
]
