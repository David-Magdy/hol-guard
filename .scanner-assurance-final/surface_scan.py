# pyright: basic
"""Extension manifest, MCP, endpoint, command, and capability surface analysis."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


URL_RE = re.compile(r"https?://[^\s\"'<>)}\]]{1,2048}", re.IGNORECASE)
SHELL_LAUNCHERS = frozenset({"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"})
PACKAGE_RUNNERS = frozenset({"npx", "pnpx", "bunx", "uvx", "pipx"})
SECRET_ENV_RE = re.compile(r"(?i)(?:token|secret|password|api[_-]?key|private[_-]?key|credential)")
PATH_ENV_RE = re.compile(r"(?i)^(?:PATH|PYTHONPATH|NODE_PATH|LD_PRELOAD|DYLD_INSERT_LIBRARIES)$")
DANGEROUS_CAPABILITIES = {
    "filesystem:write": "filesystem-write",
    "filesystem:all": "filesystem-write",
    "network:all": "outbound-network",
    "shell": "process-execution",
    "process": "process-execution",
    "credentials": "credential-store",
    "clipboard": "input-capture",
    "screen": "input-capture",
    "camera": "input-capture",
    "microphone": "input-capture",
    "admin": "privilege-escalation",
    "root": "privilege-escalation",
    "docker": "container-control",
}


@dataclass(frozen=True, slots=True)
class SurfaceResult:
    findings: tuple[SecurityFinding, ...]
    capabilities: tuple[str, ...]
    endpoints: tuple[str, ...]
    commands: tuple[str, ...]
    security_controls: tuple[str, ...]
    complete: bool


def scan_surfaces(root: Path) -> SurfaceResult:
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    endpoints: set[str] = set()
    commands: set[str] = set()
    controls: set[str] = set()
    complete = True

    candidates = (
        root / ".mcp.json",
        root / "mcp.json",
        root / ".codex-plugin" / "plugin.json",
        root / "plugin.json",
        root / "manifest.json",
        root / "claude_desktop_config.json",
        root / "opencode.json",
    )
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
        except (OSError, json.JSONDecodeError, ValueError):
            findings.append(
                _finding(
                    "ASSURANCE_SECURITY_CONFIG_INVALID",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "configuration",
                    "Security-relevant configuration is invalid",
                    "A manifest or MCP configuration cannot be parsed unambiguously.",
                    "Fix the JSON document and validate it against a strict schema before distribution.",
                    relative,
                )
            )
            complete = False
            continue
        _walk_payload(
            payload,
            path=relative,
            findings=findings,
            capabilities=capabilities,
            endpoints=endpoints,
            commands=commands,
            controls=controls,
        )

    for path in (root / "pyproject.toml", root / "Cargo.toml"):
        if not path.is_file():
            continue
        try:
            payload = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        _walk_payload(
            payload,
            path=path.relative_to(root).as_posix(),
            findings=findings,
            capabilities=capabilities,
            endpoints=endpoints,
            commands=commands,
            controls=controls,
        )

    for endpoint in sorted(endpoints):
        parsed = _split_endpoint(endpoint)
        if parsed is None:
            continue
        scheme, host, _port, _path = parsed
        if scheme == "http":
            findings.append(
                _finding(
                    "ASSURANCE_MCP_INSECURE_ENDPOINT",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "mcp-security",
                    "MCP or plugin endpoint uses plaintext HTTP",
                    "The endpoint does not authenticate the server or protect traffic in transit.",
                    "Use HTTPS with certificate and hostname verification.",
                    None,
                    {"endpoint_sha256": hashlib.sha256(endpoint.encode()).hexdigest()},
                )
            )
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            severity = Severity.LOW if address.is_loopback else Severity.HIGH
            findings.append(
                _finding(
                    "ASSURANCE_MCP_NONPUBLIC_ENDPOINT",
                    severity,
                    Confidence.HIGH,
                    "mcp-security",
                    "MCP endpoint targets non-public address space",
                    "The endpoint targets loopback, private, link-local, reserved, or multicast address space.",
                    "Require an explicit managed destination allowlist and isolate the connector from sensitive networks.",
                    None,
                    {"endpoint_sha256": hashlib.sha256(endpoint.encode()).hexdigest()},
                )
            )

    return SurfaceResult(
        findings=tuple(_dedupe(findings)),
        capabilities=tuple(sorted(capabilities)),
        endpoints=tuple(sorted(endpoints)),
        commands=tuple(sorted(commands)),
        security_controls=tuple(sorted(controls)),
        complete=complete,
    )


def _walk_payload(
    value: object,
    *,
    path: str,
    findings: list[SecurityFinding],
    capabilities: set[str],
    endpoints: set[str],
    commands: set[str],
    controls: set[str],
    key_path: tuple[str, ...] = (),
    depth: int = 0,
) -> None:
    if depth > 64:
        findings.append(
            _finding(
                "ASSURANCE_CONFIG_DEPTH_LIMIT",
                Severity.MEDIUM,
                Confidence.HIGH,
                "configuration",
                "Configuration nesting limit reached",
                "A security-relevant configuration is too deeply nested for safe processing.",
                "Reduce nesting and validate against a strict schema.",
                path,
            )
        )
        return
    if isinstance(value, dict):
        command_value = _first_key(value, {"command", "cmd", "executable"})
        argument_value = _first_key(value, {"args", "arguments"})
        if command_value is not None:
            combined: object = command_value
            if isinstance(argument_value, list):
                if isinstance(command_value, str):
                    prefix: list[object] = [command_value]
                elif isinstance(command_value, list):
                    prefix = list(command_value)
                else:
                    prefix = []
                combined = [*prefix, *argument_value]
            _inspect_command(combined, path, findings, capabilities, commands)

        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            next_path = (*key_path, key)
            if lowered in {"command", "cmd", "executable"}:
                pass
            elif lowered in {"args", "arguments"} and isinstance(item, list):
                rendered = " ".join(str(part) for part in item if isinstance(part, (str, int, float)))
                if rendered:
                    commands.add(_redacted_command_digest(rendered))
            elif lowered in {"url", "uri", "endpoint", "baseurl", "base_url"} and isinstance(item, str):
                _collect_endpoints(item, endpoints, capabilities)
            elif lowered in {"permissions", "capabilities", "scopes", "tools"}:
                _inspect_capabilities(item, path, findings, capabilities)
            elif lowered in {
                "approval",
                "approvals",
                "sandbox",
                "security",
                "policy",
                "tls",
                "allowlist",
                "denylist",
            }:
                controls.add(".".join(next_path))
            elif lowered in {"cwd", "workingdirectory", "working_directory"} and isinstance(item, str):
                _inspect_working_directory(item, path, findings)
            elif lowered in {"env", "environment"} and isinstance(item, dict):
                _inspect_environment(item, path, findings, capabilities)
            _walk_payload(
                item,
                path=path,
                findings=findings,
                capabilities=capabilities,
                endpoints=endpoints,
                commands=commands,
                controls=controls,
                key_path=next_path,
                depth=depth + 1,
            )
    elif isinstance(value, list):
        for item in value[:100_000]:
            _walk_payload(
                item,
                path=path,
                findings=findings,
                capabilities=capabilities,
                endpoints=endpoints,
                commands=commands,
                controls=controls,
                key_path=key_path,
                depth=depth + 1,
            )
    elif isinstance(value, str):
        _collect_endpoints(value, endpoints, capabilities)


def _inspect_command(
    value: object,
    path: str,
    findings: list[SecurityFinding],
    capabilities: set[str],
    commands: set[str],
) -> None:
    if isinstance(value, list):
        parts = [str(item) for item in value]
    elif isinstance(value, str):
        try:
            parts = shlex.split(value, posix=True)
        except ValueError:
            parts = [value]
    else:
        return
    if not parts:
        return
    rendered = " ".join(parts)
    command_digest = hashlib.sha256(rendered.encode()).hexdigest()
    commands.add(f"sha256:{command_digest}")
    executable = Path(parts[0]).name.lower()
    capabilities.add("process-execution")
    if executable in SHELL_LAUNCHERS:
        findings.append(
            _finding(
                "ASSURANCE_MCP_SHELL_LAUNCHER",
                Severity.HIGH,
                Confidence.HIGH,
                "mcp-security",
                "MCP server launches through a shell",
                "Shell launchers widen parsing and command-injection risk.",
                "Launch a fixed executable with a validated argument vector and no shell.",
                path,
                {"command_sha256": command_digest},
            )
        )

    runner_parts = parts
    if executable in SHELL_LAUNCHERS and "-c" in parts:
        index = parts.index("-c")
        if index + 1 < len(parts):
            try:
                runner_parts = shlex.split(parts[index + 1], posix=True)
            except ValueError:
                runner_parts = [parts[index + 1]]
    runner_executable = Path(runner_parts[0]).name.lower() if runner_parts else ""
    if runner_executable in PACKAGE_RUNNERS:
        package = next((part for part in runner_parts[1:] if not part.startswith("-")), "")
        if package and not _package_runner_target_pinned(package):
            findings.append(
                _finding(
                    "ASSURANCE_MCP_MUTABLE_PACKAGE_RUNNER",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "mcp-security",
                    "MCP server uses an unpinned package runner",
                    "The package runner can resolve different code at installation or launch time.",
                    "Pin an exact package version and verify its lock and provenance.",
                    path,
                    {"command_sha256": command_digest},
                )
            )
    lowered_command = rendered.lower()
    if any(
        token in lowered_command
        for token in (
            "--no-sandbox",
            "--disable-web-security",
            "--dangerously-skip-permissions",
            "--trust-all",
            "--insecure",
            "--no-check-certificate",
        )
    ):
        findings.append(
            _finding(
                "ASSURANCE_MCP_SECURITY_BYPASS_FLAG",
                Severity.CRITICAL,
                Confidence.HIGH,
                "mcp-security",
                "MCP command disables a security boundary",
                "The command line contains a flag that bypasses sandbox, permission, or transport controls.",
                "Remove the bypass and fail closed when the required security control is unavailable.",
                path,
                {"command_sha256": command_digest},
            )
        )


def _inspect_environment(
    environment: dict[object, object],
    path: str,
    findings: list[SecurityFinding],
    capabilities: set[str],
) -> None:
    for env_key, env_value in environment.items():
        key = str(env_key)
        if SECRET_ENV_RE.search(key) and isinstance(env_value, str) and env_value:
            findings.append(
                _finding(
                    "ASSURANCE_MCP_INLINE_SECRET",
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    "credential-exposure",
                    "MCP configuration embeds a credential",
                    "A credential-shaped environment value is embedded directly in configuration.",
                    "Use a scoped secret reference and never place secret bytes in model-visible configuration.",
                    path,
                    {"key_sha256": hashlib.sha256(key.encode()).hexdigest()},
                )
            )
            capabilities.add("credential-store")
        if PATH_ENV_RE.fullmatch(key) and isinstance(env_value, str) and env_value:
            findings.append(
                _finding(
                    "ASSURANCE_MCP_EXECUTION_ENV_OVERRIDE",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "mcp-security",
                    "MCP configuration overrides an execution search or loader path",
                    "Search-path and dynamic-loader environment overrides can redirect execution to attacker-controlled code.",
                    "Use an immutable executable path and remove loader/search-path overrides.",
                    path,
                    {"key_sha256": hashlib.sha256(key.encode()).hexdigest()},
                )
            )


def _inspect_working_directory(value: str, path: str, findings: list[SecurityFinding]) -> None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or normalized == ".." or normalized.startswith("../"):
        findings.append(
            _finding(
                "ASSURANCE_MCP_UNSAFE_WORKING_DIRECTORY",
                Severity.MEDIUM,
                Confidence.HIGH,
                "mcp-security",
                "MCP command uses an unsafe working directory",
                "The command can execute outside the extension root or depends on an absolute host path.",
                "Use a validated path contained inside the extension root.",
                path,
                {"path_sha256": hashlib.sha256(value.encode()).hexdigest()},
            )
        )


def _inspect_capabilities(
    value: object,
    path: str,
    findings: list[SecurityFinding],
    capabilities: set[str],
) -> None:
    raw_values: list[str] = []
    if isinstance(value, str):
        raw_values = [value]
    elif isinstance(value, list):
        raw_values = [str(item) for item in value if isinstance(item, (str, int, float))]
    elif isinstance(value, dict):
        raw_values = [str(key) for key, enabled in value.items() if enabled not in (False, None, "deny")]
    for raw in raw_values:
        lowered = raw.lower().strip()
        mapped = next(
            (capability for marker, capability in DANGEROUS_CAPABILITIES.items() if marker in lowered),
            lowered,
        )
        if mapped:
            capabilities.add(mapped)
        if mapped in {
            "credential-store",
            "input-capture",
            "privilege-escalation",
            "container-control",
            "process-execution",
            "filesystem-write",
        }:
            findings.append(
                _finding(
                    "ASSURANCE_ELEVATED_CAPABILITY",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "capability",
                    "Extension requests an elevated capability",
                    "The extension declares a capability that can materially affect host confidentiality or integrity.",
                    "Require explicit managed approval and restrict the capability to the smallest resource set.",
                    path,
                    {"capability": mapped},
                )
            )


def _collect_endpoints(value: str, endpoints: set[str], capabilities: set[str]) -> None:
    for match in URL_RE.findall(value):
        canonical = _canonical_endpoint(match)
        if canonical is not None:
            endpoints.add(canonical)
            capabilities.add("outbound-network")


def _canonical_endpoint(value: str) -> str | None:
    parsed = _split_endpoint(value)
    if parsed is None:
        return None
    scheme, host, port, path = parsed
    default_port = 80 if scheme == "http" else 443
    authority = host if port in {None, default_port} else f"{host}:{port}"
    return f"{scheme}://{authority}{path}"


def _split_endpoint(value: str) -> tuple[str, str, int | None, str] | None:
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    path = parsed.path or "/"
    return scheme, host, port, path


def _package_runner_target_pinned(value: str) -> bool:
    if value.startswith("@"):
        separator = value.rfind("@")
        return separator > 0 and bool(
            re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value[separator + 1 :])
        )
    if "@" not in value:
        return False
    _, version = value.rsplit("@", 1)
    return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version))


def _first_key(value: dict[object, object], keys: set[str]) -> object | None:
    for key, item in value.items():
        if str(key).lower() in keys:
            return item
    return None


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _finding(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    title: str,
    description: str,
    remediation: str,
    path: str | None,
    metadata: dict[str, Any] | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        locations=(EvidenceLocation(path=path),) if path else (),
        metadata=metadata or {},
    ).with_fingerprint()


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
