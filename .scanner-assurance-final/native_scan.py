# pyright: basic
"""Bounded native and WebAssembly analysis with an optional Rust hot path."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
WASM_MAGIC = b"\x00asm"
MACHO_MAGICS: dict[bytes, tuple[str, str]] = {
    b"\xfe\xed\xfa\xce": ("mach-o", "big"),
    b"\xce\xfa\xed\xfe": ("mach-o", "little"),
    b"\xfe\xed\xfa\xcf": ("mach-o", "big"),
    b"\xcf\xfa\xed\xfe": ("mach-o", "little"),
    b"\xca\xfe\xba\xbe": ("mach-o-fat", "big"),
    b"\xbe\xba\xfe\xca": ("mach-o-fat", "little"),
    b"\xca\xfe\xba\xbf": ("mach-o-fat64", "big"),
    b"\xbf\xba\xfe\xca": ("mach-o-fat64", "little"),
}
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
ENGINE_SCHEMA = "hol-guard.scanner-engine.v1"
MAX_ENGINE_OUTPUT_BYTES = 16 * 1024 * 1024

SENSITIVE_INDICATORS: tuple[tuple[bytes, str, Severity, str], ...] = (
    (b"/var/run/docker.sock", "container-control", Severity.CRITICAL, "Docker socket access"),
    (b"/run/podman/podman.sock", "container-control", Severity.CRITICAL, "Podman socket access"),
    (b"169.254.169.254", "cloud-metadata", Severity.CRITICAL, "Cloud metadata service access"),
    (b"metadata.google.internal", "cloud-metadata", Severity.CRITICAL, "Cloud metadata service access"),
    (b"CreateRemoteThread", "process-injection", Severity.CRITICAL, "Remote process injection API"),
    (b"WriteProcessMemory", "process-injection", Severity.CRITICAL, "Remote process memory write API"),
    (b"ptrace", "process-injection", Severity.HIGH, "Process tracing API"),
    (b"SetWindowsHookEx", "input-capture", Severity.CRITICAL, "Global input hook API"),
    (b"GetAsyncKeyState", "input-capture", Severity.CRITICAL, "Keyboard state capture API"),
    (b"Chrome/Login Data", "credential-store", Severity.CRITICAL, "Browser credential database path"),
    (b"Login Data", "credential-store", Severity.HIGH, "Browser credential database indicator"),
    (b"keychain", "credential-store", Severity.HIGH, "Credential store indicator"),
    (b"Credential Manager", "credential-store", Severity.HIGH, "Credential store indicator"),
    (b"LD_PRELOAD", "persistence", Severity.HIGH, "Dynamic loader injection indicator"),
    (b"DYLD_INSERT_LIBRARIES", "persistence", Severity.HIGH, "Dynamic loader injection indicator"),
    (b"crontab", "persistence", Severity.HIGH, "Cron persistence indicator"),
    (b"schtasks", "persistence", Severity.HIGH, "Scheduled task persistence indicator"),
    (b"LaunchAgents", "persistence", Severity.HIGH, "LaunchAgent persistence indicator"),
    (b"ShellExecute", "process-execution", Severity.HIGH, "Shell execution API"),
    (b"CreateProcess", "process-execution", Severity.HIGH, "Process creation API"),
    (b"WinExec", "process-execution", Severity.HIGH, "Command execution API"),
    (b"system(", "process-execution", Severity.HIGH, "Shell execution function"),
    (b"popen(", "process-execution", Severity.HIGH, "Process pipe function"),
    (b"InternetOpen", "outbound-network", Severity.MEDIUM, "Windows network API"),
    (b"WinHttpOpen", "outbound-network", Severity.MEDIUM, "Windows HTTP API"),
    (b"socket", "outbound-network", Severity.LOW, "Socket API indicator"),
    (b"SSL_VERIFY_NONE", "tls-bypass", Severity.HIGH, "TLS verification bypass"),
    (b"CURLOPT_SSL_VERIFYPEER", "tls-bypass", Severity.MEDIUM, "TLS verification control"),
)


@dataclass(frozen=True, slots=True)
class NativeResult:
    summary: dict[str, Any]
    findings: tuple[SecurityFinding, ...]
    capabilities: tuple[str, ...]
    rust_used: bool
    complete: bool


def detect_native_format(prefix: bytes) -> str | None:
    if prefix.startswith(ELF_MAGIC):
        return "elf"
    if prefix.startswith(PE_MAGIC):
        return "pe"
    if prefix.startswith(WASM_MAGIC):
        return "wasm"
    for magic, (format_name, _byte_order) in MACHO_MAGICS.items():
        if prefix.startswith(magic):
            return format_name
    return None


def scan_native_file(path: Path, display_path: str, limits: ScanLimits) -> NativeResult:
    try:
        size = path.stat().st_size
    except OSError:
        return _error_result(display_path, "Native artifact could not be statted.")
    digest = _hash_file(path)
    engine = _find_engine()
    if engine is not None:
        result = _run_engine_file(engine, path, display_path, limits, expected_digest=digest, size=size)
        if result is not None:
            return result
    try:
        with path.open("rb") as handle:
            data = handle.read(limits.max_file_bytes + 1)
    except OSError:
        return _error_result(display_path, "Native artifact could not be read.")
    truncated = len(data) > limits.max_file_bytes or size > limits.max_file_bytes
    return _fallback_result(
        data[: limits.max_file_bytes],
        display_path,
        full_digest=digest,
        full_size=size,
        complete=not truncated,
        engine_available=engine is not None,
    )


def scan_native_bytes(data: bytes, display_path: str, limits: ScanLimits) -> NativeResult:
    digest = hashlib.sha256(data).hexdigest()
    engine = _find_engine()
    if engine is not None:
        with tempfile.TemporaryDirectory(prefix="hol-guard-native-") as directory:
            temporary = Path(directory) / "artifact.bin"
            temporary.write_bytes(data)
            result = _run_engine_file(
                engine,
                temporary,
                display_path,
                limits,
                expected_digest=digest,
                size=len(data),
            )
            if result is not None:
                return result
    truncated = len(data) > limits.max_file_bytes
    return _fallback_result(
        data[: limits.max_file_bytes],
        display_path,
        full_digest=digest,
        full_size=len(data),
        complete=not truncated,
        engine_available=engine is not None,
    )


def _run_engine_file(
    engine: Path,
    path: Path,
    display_path: str,
    limits: ScanLimits,
    *,
    expected_digest: str,
    size: int,
) -> NativeResult | None:
    command = [
        str(engine),
        "inspect",
        "--path",
        str(path),
        "--display-path",
        display_path,
        "--max-bytes",
        str(limits.max_file_bytes),
        "--max-strings",
        str(limits.max_native_strings),
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=limits.native_timeout_seconds,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > MAX_ENGINE_OUTPUT_BYTES:
        return None
    try:
        payload = json.loads(
            completed.stdout.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != ENGINE_SCHEMA:
        return None
    summary = payload.get("summary")
    raw_findings = payload.get("findings")
    raw_capabilities = payload.get("capabilities")
    if not isinstance(summary, dict) or not isinstance(raw_findings, list) or not isinstance(raw_capabilities, list):
        return None
    digest = summary.get("sha256")
    if digest != expected_digest or not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        return None
    if int(summary.get("size", -1)) != size:
        return None
    signature = summary.get("signature")
    if not isinstance(signature, dict):
        signature = {}
    signature = {
        "present": bool(signature.get("present", False)),
        "verified": False,
        "verification": "not-performed",
        "note": "A signature directory or load command is not cryptographic verification.",
    }
    summary = dict(summary)
    summary["signature"] = signature
    summary["rust_used"] = True
    summary["analysis_limit_bytes"] = limits.max_file_bytes
    findings: list[SecurityFinding] = []
    for item in raw_findings[: limits.max_findings]:
        parsed = _parse_engine_finding(item, display_path)
        if parsed is not None:
            findings.append(parsed)
    capabilities = sorted(
        {str(item) for item in raw_capabilities if isinstance(item, str) and item}
    )
    complete = bool(payload.get("complete", True))
    return NativeResult(
        summary=summary,
        findings=tuple(_dedupe(findings)),
        capabilities=tuple(capabilities),
        rust_used=True,
        complete=complete,
    )


def _fallback_result(
    data: bytes,
    display_path: str,
    *,
    full_digest: str,
    full_size: int,
    complete: bool,
    engine_available: bool,
) -> NativeResult:
    format_name = detect_native_format(data[:8]) or "unknown-native"
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    indicator_names: list[str] = []
    lowered = data.lower()
    for needle, capability, severity, label in SENSITIVE_INDICATORS:
        if needle.lower() not in lowered:
            continue
        capabilities.add(capability)
        indicator_names.append(label)
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_NATIVE_SENSITIVE_INDICATOR",
                severity=severity,
                confidence=Confidence.MEDIUM,
                category="native-security",
                title=label,
                description="A bounded native string indicator matched a security-sensitive behavior. It does not prove reachability.",
                remediation="Review the native artifact structurally and dynamically in an isolated environment before approval.",
                locations=(EvidenceLocation(path=display_path),),
                metadata={
                    "indicator_sha256": hashlib.sha256(needle).hexdigest(),
                    "format": format_name,
                },
            ).with_fingerprint()
        )
    strings = PRINTABLE_RE.findall(data)
    entropy = _entropy(data)
    high_entropy = entropy >= 7.3 and len(data) >= 4096
    if high_entropy:
        capabilities.add("obfuscation")
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_NATIVE_HIGH_ENTROPY",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="native-security",
                title="Native artifact has high entropy",
                description="High entropy can indicate compression, encryption, or packing and reduces static transparency.",
                remediation="Require unpacked reproducible sources, signed provenance, and sandbox observation.",
                locations=(EvidenceLocation(path=display_path),),
                metadata={"entropy": round(entropy, 4)},
            ).with_fingerprint()
        )
    findings.append(
        SecurityFinding(
            rule_id="ASSURANCE_NATIVE_FALLBACK_LIMITATION",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="coverage",
            title="Native artifact used the bounded fallback analyzer",
            description=(
                "The Rust structural parser was unavailable or rejected its result. "
                "The fallback identifies magic bytes and bounded string indicators only."
            ),
            remediation="Build and run the reviewed Rust scanner engine and require it for native artifacts under strict policy.",
            locations=(EvidenceLocation(path=display_path),),
            metadata={"engine_detected": engine_available},
        ).with_fingerprint()
    )
    summary: dict[str, Any] = {
        "format": format_name,
        "architecture": _fallback_architecture(data, format_name),
        "sha256": full_digest,
        "size": full_size,
        "analyzed_bytes": len(data),
        "sections": [],
        "imports": [],
        "exports": [],
        "mitigations": {},
        "entropy": round(entropy, 4),
        "packing": {"suspected": high_entropy, "reason": "high-entropy" if high_entropy else None},
        "indicator_count": len(indicator_names),
        "printable_string_count": len(strings),
        "signature": {
            "present": _signature_structure_present(data, format_name),
            "verified": False,
            "verification": "not-performed",
            "note": "Presence is not cryptographic verification.",
        },
        "rust_used": False,
    }
    return NativeResult(
        summary=summary,
        findings=tuple(_dedupe(findings)),
        capabilities=tuple(sorted(capabilities)),
        rust_used=False,
        complete=complete and False,
    )


def _parse_engine_finding(value: object, display_path: str) -> SecurityFinding | None:
    if not isinstance(value, dict):
        return None
    try:
        severity = Severity(str(value.get("severity", "medium")))
        confidence = Confidence(str(value.get("confidence", "medium")))
    except ValueError:
        return None
    rule_id = value.get("rule_id")
    title = value.get("title")
    description = value.get("description")
    remediation = value.get("remediation")
    category = value.get("category", "native-security")
    if not all(isinstance(item, str) and item for item in (rule_id, title, description, remediation, category)):
        return None
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        locations=(EvidenceLocation(path=display_path),),
        source="rust-native-engine",
        metadata=dict(metadata),
    ).with_fingerprint()


def _find_engine() -> Path | None:
    configured = os.environ.get("HOL_GUARD_SCANNER_ENGINE")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    package_root = Path(__file__).resolve().parents[3]
    candidates.extend(
        (
            package_root / "rust" / "scanner-engine" / "target" / "release" / _engine_name(),
            package_root / "rust" / "scanner-engine" / "target" / "debug" / _engine_name(),
        )
    )
    discovered = shutil.which(_engine_name())
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    return None


def _engine_name() -> str:
    return "hol-guard-scanner-engine.exe" if os.name == "nt" else "hol-guard-scanner-engine"


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    before = path.stat()
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if before.st_dev != opened.st_dev or before.st_ino != opened.st_ino:
            raise OSError("file identity changed before native hashing")
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise OSError("file changed while native hashing")
    return hasher.hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _fallback_architecture(data: bytes, format_name: str) -> str:
    if format_name == "elf" and len(data) > 5:
        return "64-bit" if data[4] == 2 else "32-bit" if data[4] == 1 else "unknown"
    if format_name == "wasm":
        return "wasm32-or-wasm64"
    return "unknown"


def _signature_structure_present(data: bytes, format_name: str) -> bool:
    if format_name == "pe":
        return b"Authenticode" in data or b"WIN_CERTIFICATE" in data
    if format_name.startswith("mach-o"):
        return b"LC_CODE_SIGNATURE" in data
    return False


def _error_result(display_path: str, description: str) -> NativeResult:
    finding = SecurityFinding(
        rule_id="ASSURANCE_NATIVE_READ_FAILED",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="coverage",
        title="Native artifact could not be analyzed",
        description=description,
        remediation="Rerun from an immutable readable snapshot and require independent native review.",
        locations=(EvidenceLocation(path=display_path),),
    ).with_fingerprint()
    return NativeResult(
        summary={
            "format": "unknown",
            "signature": {"present": False, "verified": False, "verification": "not-performed"},
            "rust_used": False,
        },
        findings=(finding,),
        capabilities=(),
        rust_used=False,
        complete=False,
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
