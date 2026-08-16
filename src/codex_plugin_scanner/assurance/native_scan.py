"""Native executable and WebAssembly analysis with an optional Rust hot path."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


NATIVE_MAGIC_NAMES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\x00asm", "wasm"),
    (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xce\xfa\xed\xfe", "mach-o"),
    (b"\xfe\xed\xfa\xcf", "mach-o"),
    (b"\xcf\xfa\xed\xfe", "mach-o"),
    (b"\xca\xfe\xba\xbe", "mach-o-fat"),
    (b"\xbe\xba\xfe\xca", "mach-o-fat"),
)

SUSPICIOUS_IMPORTS: dict[str, tuple[Severity, str, str]] = {
    "ptrace": (Severity.HIGH, "anti-analysis", "Process tracing or anti-debugging"),
    "process_vm_writev": (Severity.CRITICAL, "process-injection", "Cross-process memory write"),
    "VirtualAllocEx": (Severity.CRITICAL, "process-injection", "Remote process allocation"),
    "WriteProcessMemory": (Severity.CRITICAL, "process-injection", "Remote process memory write"),
    "CreateRemoteThread": (Severity.CRITICAL, "process-injection", "Remote thread creation"),
    "SetWindowsHookEx": (Severity.CRITICAL, "input-capture", "Global input hook"),
    "GetAsyncKeyState": (Severity.CRITICAL, "input-capture", "Keyboard state capture"),
    "dlopen": (Severity.MEDIUM, "dynamic-loading", "Dynamic library loading"),
    "LoadLibrary": (Severity.MEDIUM, "dynamic-loading", "Dynamic library loading"),
    "system": (Severity.HIGH, "process-execution", "Shell command execution"),
    "popen": (Severity.HIGH, "process-execution", "Shell command execution"),
    "WinExec": (Severity.HIGH, "process-execution", "Process execution"),
    "ShellExecute": (Severity.HIGH, "process-execution", "Shell execution"),
    "RegSetValue": (Severity.HIGH, "persistence", "Registry modification"),
    "CreateService": (Severity.HIGH, "persistence", "Service creation"),
    "chmod": (Severity.MEDIUM, "filesystem", "Permission modification"),
    "setuid": (Severity.CRITICAL, "privilege-escalation", "Identity elevation"),
    "capset": (Severity.CRITICAL, "privilege-escalation", "Linux capability modification"),
    "socket": (Severity.LOW, "network", "Network socket access"),
    "connect": (Severity.MEDIUM, "network", "Outbound network connection"),
    "getaddrinfo": (Severity.LOW, "network", "DNS resolution"),
}

SUSPICIOUS_STRINGS: dict[bytes, tuple[Severity, str, str]] = {
    b"169.254.169.254": (Severity.CRITICAL, "cloud-metadata", "Cloud metadata endpoint"),
    b"metadata.google.internal": (Severity.CRITICAL, "cloud-metadata", "Cloud metadata endpoint"),
    b"/var/run/docker.sock": (Severity.CRITICAL, "container-control", "Docker control socket"),
    b"/run/containerd/containerd.sock": (Severity.CRITICAL, "container-control", "Containerd control socket"),
    b"/etc/sudoers": (Severity.CRITICAL, "privilege-escalation", "Sudo policy path"),
    b".ssh/id_rsa": (Severity.CRITICAL, "credential-store", "SSH private key path"),
    b".aws/credentials": (Severity.CRITICAL, "credential-store", "AWS credential path"),
    b"Login Data": (Severity.HIGH, "credential-store", "Browser login database"),
    b"wallet.dat": (Severity.HIGH, "credential-store", "Wallet database"),
    b"/proc/self/mem": (Severity.HIGH, "anti-analysis", "Raw process memory path"),
    b"LD_PRELOAD": (Severity.HIGH, "persistence", "Dynamic linker injection"),
    b"DYLD_INSERT_LIBRARIES": (Severity.HIGH, "persistence", "Mach-O library injection"),
    b"powershell -enc": (Severity.HIGH, "obfuscation", "Encoded PowerShell execution"),
}


@dataclass(frozen=True, slots=True)
class NativeResult:
    summary: dict[str, Any]
    findings: tuple[SecurityFinding, ...]
    capabilities: tuple[str, ...]
    rust_used: bool
    complete: bool


def detect_native_format(prefix: bytes) -> str | None:
    for magic, name in NATIVE_MAGIC_NAMES:
        if prefix.startswith(magic):
            return name
    return None


def scan_native_file(path: Path, relative_path: str, limits: ScanLimits) -> NativeResult:
    if path.stat().st_size > limits.max_file_bytes:
        return _incomplete(relative_path, "Native artifact exceeds the configured analysis limit.")
    engine = _find_engine()
    if engine is not None:
        result = _run_rust_engine(engine, path, relative_path, limits)
        if result is not None:
            return result
    try:
        data = path.read_bytes()
    except OSError:
        return _incomplete(relative_path, "Native artifact could not be read.")
    return scan_native_bytes(data, relative_path, limits)


def scan_native_bytes(data: bytes, display_path: str, limits: ScanLimits) -> NativeResult:
    engine = _find_engine()
    if engine is not None:
        result = _run_rust_engine_stdin(engine, data, display_path, limits)
        if result is not None:
            return result
    return _python_fallback(data, display_path, limits)


def _find_engine() -> Path | None:
    configured = os.environ.get("HOL_GUARD_SCANNER_ENGINE")
    candidates = [Path(configured)] if configured else []
    discovered = shutil.which("hol-guard-scanner-engine")
    if discovered:
        candidates.append(Path(discovered))
    repository_candidate = Path(__file__).resolve().parents[3] / "target" / "release" / "hol-guard-scanner-engine"
    candidates.append(repository_candidate)
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        except OSError:
            continue
    return None


def _run_rust_engine(
    engine: Path,
    path: Path,
    display_path: str,
    limits: ScanLimits,
) -> NativeResult | None:
    command = [
        str(engine),
        "inspect",
        "--path",
        str(path.resolve()),
        "--display-path",
        display_path,
        "--max-bytes",
        str(limits.max_file_bytes),
        "--max-strings",
        str(limits.max_native_strings),
    ]
    return _execute_engine(command, None, display_path, limits)


def _run_rust_engine_stdin(
    engine: Path,
    data: bytes,
    display_path: str,
    limits: ScanLimits,
) -> NativeResult | None:
    if len(data) > limits.max_file_bytes:
        return None
    command = [
        str(engine),
        "inspect",
        "--stdin",
        "--display-path",
        display_path,
        "--max-bytes",
        str(limits.max_file_bytes),
        "--max-strings",
        str(limits.max_native_strings),
    ]
    return _execute_engine(command, data, display_path, limits)


def _execute_engine(
    command: list[str],
    input_bytes: bytes | None,
    display_path: str,
    limits: ScanLimits,
) -> NativeResult | None:
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=limits.rust_timeout_seconds,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > 4 * 1024 * 1024:
        return None
    try:
        payload = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return _from_engine_payload(payload, display_path)


def _from_engine_payload(payload: object, display_path: str) -> NativeResult | None:
    if not isinstance(payload, dict) or payload.get("schema_version") != "hol-guard.scanner-engine.v1":
        return None
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return None
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    for item in raw_findings:
        if not isinstance(item, dict):
            return None
        try:
            severity = Severity(str(item["severity"]))
            confidence = Confidence(str(item.get("confidence", "high")))
            capability = str(item.get("capability", ""))
            finding = SecurityFinding(
                rule_id=str(item["rule_id"]),
                severity=severity,
                confidence=confidence,
                category=str(item["category"]),
                title=str(item["title"]),
                description=str(item["description"]),
                remediation=str(item["remediation"]),
                locations=(
                    EvidenceLocation(
                        path=display_path,
                        symbol=str(item["symbol"]) if item.get("symbol") else None,
                    ),
                ),
                source="rust-scanner-engine",
                metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata", {}), dict) else {},
            ).with_fingerprint()
        except (KeyError, ValueError, TypeError):
            return None
        findings.append(finding)
        if capability:
            capabilities.add(capability)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return NativeResult(
        summary=dict(summary),
        findings=tuple(findings),
        capabilities=tuple(sorted(capabilities)),
        rust_used=True,
        complete=bool(payload.get("complete", True)),
    )


def _python_fallback(data: bytes, display_path: str, limits: ScanLimits) -> NativeResult:
    fmt = detect_native_format(data[:16])
    if fmt is None:
        return _incomplete(display_path, "File does not have a recognized native or WebAssembly header.")
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    summary: dict[str, Any] = {
        "format": fmt,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "engine": "python-fallback",
        "signature": {"present": None, "verified": False, "reason": "not evaluated by fallback parser"},
    }
    summary.update(_minimal_header_summary(data, fmt))

    string_budget = min(len(data), limits.max_native_string_bytes)
    searchable = data[:string_budget]
    for needle, (severity, capability, label) in SUSPICIOUS_STRINGS.items():
        if needle.lower() not in searchable.lower():
            continue
        findings.append(
            _native_finding(
                "ASSURANCE_NATIVE_SUSPICIOUS_STRING",
                severity,
                capability,
                f"Native artifact references {label}",
                "A sensitive endpoint, path, or execution marker is embedded in the native artifact.",
                "Confirm the behavior through source review and sandbox observation, then remove unjustified access.",
                display_path,
                metadata={"indicator_sha256": hashlib.sha256(needle.lower()).hexdigest()},
            )
        )
        capabilities.add(capability)

    lower = searchable.lower()
    for symbol, (severity, capability, label) in SUSPICIOUS_IMPORTS.items():
        encoded = symbol.encode("ascii", errors="ignore").lower()
        if encoded not in lower:
            continue
        findings.append(
            _native_finding(
                "ASSURANCE_NATIVE_SENSITIVE_IMPORT",
                severity,
                capability,
                f"Native artifact exposes {label}",
                "A security-sensitive API name is present in the binary. The fallback parser cannot prove reachability.",
                "Use the Rust parser and sandbox observation to validate reachability, then remove unnecessary capability.",
                display_path,
                symbol=symbol,
            )
        )
        capabilities.add(capability)

    if _looks_packed(searchable, fmt):
        findings.append(
            _native_finding(
                "ASSURANCE_NATIVE_PACKING_OR_OBFUSCATION",
                Severity.HIGH,
                "obfuscation",
                "Native artifact appears packed or obfuscated",
                "Packing markers or an unusually sparse import surface reduce static-review confidence.",
                "Provide reproducible, unpacked builds and signed provenance.",
                display_path,
            )
        )
        capabilities.add("obfuscation")

    findings.append(
        _native_finding(
            "ASSURANCE_NATIVE_FALLBACK_LIMITATION",
            Severity.MEDIUM,
            "native-analysis",
            "Native artifact was not structurally parsed by the Rust engine",
            "The Python fallback uses bounded header and indicator analysis, not full disassembly or control-flow recovery.",
            "Build hol-guard-scanner-engine and require it in managed policy for native artifacts.",
            display_path,
        )
    )
    return NativeResult(
        summary=summary,
        findings=tuple(_dedupe(findings)),
        capabilities=tuple(sorted(capabilities)),
        rust_used=False,
        complete=False,
    )


def _minimal_header_summary(data: bytes, fmt: str) -> dict[str, Any]:
    try:
        if fmt == "elf" and len(data) >= 20:
            bits = 64 if data[4] == 2 else 32 if data[4] == 1 else None
            endian = "little" if data[5] == 1 else "big" if data[5] == 2 else None
            machine = int.from_bytes(data[18:20], endian or "little")
            return {"bits": bits, "endian": endian, "machine": machine}
        if fmt == "pe" and len(data) >= 64:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0] if pe_offset + 6 <= len(data) else None
            return {"machine": machine}
        if fmt == "wasm" and len(data) >= 8:
            return {"version": int.from_bytes(data[4:8], "little")}
        if fmt.startswith("mach-o") and len(data) >= 8:
            return {"magic": data[:4].hex()}
    except (IndexError, struct.error):
        return {"header_parse_error": True}
    return {}


def _looks_packed(data: bytes, fmt: str) -> bool:
    markers = (b"UPX0", b"UPX1", b"UPX!", b"MPRESS", b"Themida", b"ASPack", b"VMProtect")
    if any(marker.lower() in data.lower() for marker in markers):
        return True
    if fmt == "pe" and data.count(b"\x00") / max(1, len(data)) < 0.02:
        return True
    return False


def _native_finding(
    rule_id: str,
    severity: Severity,
    capability: str,
    title: str,
    description: str,
    remediation: str,
    path: str,
    *,
    symbol: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityFinding:
    values = {"capability": capability, **(metadata or {})}
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH if symbol is not None else Confidence.MEDIUM,
        category="native-analysis",
        title=title,
        description=description,
        remediation=remediation,
        locations=(EvidenceLocation(path=path, symbol=symbol),),
        metadata=values,
    ).with_fingerprint()


def _incomplete(path: str, description: str) -> NativeResult:
    finding = _native_finding(
        "ASSURANCE_NATIVE_ANALYSIS_INCOMPLETE",
        Severity.HIGH,
        "native-analysis",
        "Native analysis is incomplete",
        description,
        "Review the artifact independently or increase a managed bound after capacity review.",
        path,
    )
    return NativeResult(
        summary={"format": None, "engine": "none", "signature": {"present": None, "verified": False}},
        findings=(finding,),
        capabilities=("native-analysis",),
        rust_used=False,
        complete=False,
    )


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
