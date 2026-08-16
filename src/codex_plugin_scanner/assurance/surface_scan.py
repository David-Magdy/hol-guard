"""Extension manifest, MCP, endpoint, command, and capability surface analysis."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


URL_RE = re.compile(r"https?://[^\s\"'<>)}\]]{1,2048}", re.IGNORECASE)
SHELL_LAUNCHERS = frozenset({"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"})
PACKAGE_RUNNERS = frozenset({"npx", "pnpx", "bunx", "uvx", "pipx"})
SECRET_ENV_RE = re.compile(r"(?i)(?:token|secret|password|api[_-]?key|private[_-]?key|credential)")
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
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            findings.append(
                _finding(
                    "ASSURANCE_SECURITY_CONFIG_INVALID",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "configuration",
                    "Security-relevant configuration is invalid",
                    "A manifest or MCP configuration cannot be parsed.",
                    "Fix the JSON document before the extension is distributed.",
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
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme == "http":
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
        host = parsed.hostname
        if host:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and not address.is_global and not address.is_loopback:
                findings.append(
                    _finding(
                        "ASSURANCE_MCP_PRIVATE_ENDPOINT",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        "mcp-security",
                        "MCP endpoint targets a non-public address",
                        "A remote endpoint targets private, link-local, reserved, or multicast address space.",
                        "Require an explicit managed allowlist and isolate the connector from sensitive networks.",
                        None,
                        {"endpoint_sha256": hashlib.sha256(endpoint.encode()).hexdigest()},
                    )
                )

    return SurfaceResult(
        findings=tuple({finding.fingerprint: finding for finding in findings}.values()),
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
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            next_path = (*key_path, key)
            if lowered in {"command", "cmd", "executable"}:
                _inspect_command(item, path, findings, capabilities, commands)
            elif lowered in {"args", "arguments"} and isinstance(item, list):
                rendered = " ".join(str(part) for part in item if isinstance(part, (str, int, float)))
                if rendered:
                    commands.add(_redacted_command_digest(rendered))
            elif lowered in {"url", "uri", "endpoint", "baseurl", "base_url"} and isinstance(item, str):
                for match in URL_RE.findall(item):
                    endpoints.add(match)
                    capabilities.add("outbound-network")
            elif lowered in {"permissions", "capabilities", "scopes", "tools"}:
                _inspect_capabilities(item, path, findings, capabilities)
            elif lowered in {"approval", "approvals", "sandbox", "security", "policy", "tls"}:
                controls.add(".".join(next_path))
            elif lowered in {"env", "environment"} and isinstance(item, dict):
                for env_key, env_value in item.items():
                    if SECRET_ENV_RE.search(str(env_key)) and isinstance(env_value, str) and env_value:
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
                                {"key_sha256": hashlib.sha256(str(env_key).encode()).hexdigest()},
                            )
                        )
                        capabilities.add("credential-store")
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
        for endpoint in URL_RE.findall(value):
            endpoints.add(endpoint)


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
    commands.add(_redacted_command_digest(rendered))
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
                {"command_sha256": hashlib.sha256(rendered.encode()).hexdigest()},
            )
        )
    if executable in PACKAGE_RUNNERS:
        package = next((part for part in parts[1:] if not part.startswith("-")), "")
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
                    {"command_sha256": hashlib.sha256(rendered.encode()).hexdigest()},
                )
            )
    if any(token in rendered.lower() for token in ("--no-sandbox", "--disable-web-security", "--dangerously-skip-permissions", "--trust-all")):
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
                {"command_sha256": hashlib.sha256(rendered.encode()).hexdigest()},
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


def _package_runner_target_pinned(value: str) -> bool:
    if value.startswith("@"):
        separator = value.rfind("@")
        return separator > 0 and bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value[separator + 1 :]))
    if "@" not in value:
        return False
    _, version = value.rsplit("@", 1)
    return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version))


def _redacted_command_digest(command: str) -> str:
    return f"sha256:{hashlib.sha256(command.encode()).hexdigest()}"


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
