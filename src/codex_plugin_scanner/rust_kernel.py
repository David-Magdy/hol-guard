"""Verified bridge to the optional Rust scanner inventory kernel.

The Rust kernel accelerates deterministic traversal, hashing, binary magic
classification, and bounded string extraction. The Python implementation is a
fail-closed compatibility fallback and intentionally follows the same output
contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

KERNEL_PROTOCOL = "hol-guard-scanner-kernel.v1"
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_FILE_HASH_LIMIT = 64 * 1024 * 1024
DEFAULT_STRING_SCAN_LIMIT = 2 * 1024 * 1024

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        "target",
        "dist",
        "build",
        "__pycache__",
    }
)

_INDICATOR_NEEDLES: tuple[tuple[str, str], ...] = (
    ("169.254.169.254", "cloud-metadata"),
    ("metadata.google.internal", "cloud-metadata"),
    ("/var/run/docker.sock", "container-socket"),
    ("docker_engine", "container-socket"),
    ("/.aws/credentials", "credential-store"),
    (".aws\\credentials", "credential-store"),
    ("login data", "browser-credential-store"),
    ("wallet.dat", "wallet-store"),
    ("keychain", "credential-store"),
    ("credential manager", "credential-store"),
    ("createprocess", "process-execution"),
    ("winexec", "process-execution"),
    ("system(", "process-execution"),
    ("popen(", "process-execution"),
    ("execve", "process-execution"),
    ("writeprocessmemory", "process-injection"),
    ("createremotethread", "process-injection"),
    ("process_vm_writev", "process-injection"),
    ("ptrace", "process-injection"),
    ("launchagents", "persistence"),
    ("currentversion\\run", "persistence"),
    ("/etc/cron", "persistence"),
    ("systemd", "persistence"),
    ("stratum+tcp", "crypto-mining"),
    ("xmrig", "crypto-mining"),
    ("getasynckeystate", "input-capture"),
    ("setwindowshookex", "input-capture"),
)


@dataclass(frozen=True, slots=True)
class InventoryRecord:
    """One deterministic inventory record returned by the scanner kernel."""

    path: str
    kind: str
    size: int
    sha256: str | None = None
    format: str | None = None
    executable: bool = False
    symlink_target: str | None = None
    symlink_escapes_root: bool = False
    indicators: tuple[str, ...] = ()
    hardening: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class KernelResult:
    """Validated inventory response from Rust or the Python fallback."""

    protocol: str
    engine: str
    root: str
    records: tuple[InventoryRecord, ...]
    files_seen: int
    bytes_hashed: int
    truncated: bool
    excluded_directories: int = 0
    errors: tuple[str, ...] = ()


def _safe_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise ValueError("kernel returned an unsafe relative path")
    return candidate.as_posix()


def _validate_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("kernel returned an invalid SHA-256 value")
    int(value, 16)
    return value.lower()


def _record_from_payload(payload: dict[str, Any]) -> InventoryRecord:
    path = _safe_relative_path(str(payload.get("path", "")))
    kind = str(payload.get("kind", "unknown"))
    size = int(payload.get("size", 0))
    if size < 0:
        raise ValueError("kernel returned a negative file size")
    indicators = payload.get("indicators", [])
    hardening = payload.get("hardening", [])
    if not isinstance(indicators, list) or not all(isinstance(item, str) for item in indicators):
        raise ValueError("kernel returned invalid indicators")
    if not isinstance(hardening, list) or not all(isinstance(item, str) for item in hardening):
        raise ValueError("kernel returned invalid hardening metadata")
    return InventoryRecord(
        path=path,
        kind=kind,
        size=size,
        sha256=_validate_hash(payload.get("sha256")),
        format=str(payload["format"]) if payload.get("format") else None,
        executable=bool(payload.get("executable", False)),
        symlink_target=str(payload["symlinkTarget"]) if payload.get("symlinkTarget") else None,
        symlink_escapes_root=bool(payload.get("symlinkEscapesRoot", False)),
        indicators=tuple(sorted(set(indicators))),
        hardening=tuple(sorted(set(hardening))),
        error=str(payload["error"]) if payload.get("error") else None,
    )


def _validate_kernel_payload(payload: object, expected_root: Path) -> KernelResult:
    if not isinstance(payload, dict):
        raise ValueError("kernel output must be a JSON object")
    if payload.get("protocol") != KERNEL_PROTOCOL:
        raise ValueError("kernel protocol mismatch")
    records_payload = payload.get("records")
    if not isinstance(records_payload, list):
        raise ValueError("kernel records must be an array")
    records = tuple(_record_from_payload(item) for item in records_payload if isinstance(item, dict))
    paths = [record.path for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("kernel records are not uniquely and deterministically ordered")
    root = Path(str(payload.get("root", ""))).resolve()
    if root != expected_root.resolve():
        raise ValueError("kernel root does not match the requested scan root")
    files_seen = int(payload.get("filesSeen", len(records)))
    bytes_hashed = int(payload.get("bytesHashed", 0))
    if files_seen < 0 or bytes_hashed < 0:
        raise ValueError("kernel returned invalid counters")
    errors_payload = payload.get("errors", [])
    errors = tuple(str(item) for item in errors_payload) if isinstance(errors_payload, list) else ()
    return KernelResult(
        protocol=KERNEL_PROTOCOL,
        engine="rust",
        root=str(root),
        records=records,
        files_seen=files_seen,
        bytes_hashed=bytes_hashed,
        truncated=bool(payload.get("truncated", False)),
        excluded_directories=int(payload.get("excludedDirectories", 0)),
        errors=errors,
    )


def _candidate_kernel_paths() -> tuple[Path, ...]:
    candidates: list[Path] = []
    configured = os.environ.get("HOL_GUARD_SCANNER_KERNEL")
    if configured:
        candidates.append(Path(configured).expanduser())
    package_root = Path(__file__).resolve().parents[2]
    binary_name = "hol-guard-scanner-kernel.exe" if os.name == "nt" else "hol-guard-scanner-kernel"
    candidates.extend(
        (
            package_root / "rust" / "scanner-kernel" / "target" / "release" / binary_name,
            package_root / "rust" / "scanner-kernel" / "target" / "debug" / binary_name,
            Path.cwd() / "rust" / "scanner-kernel" / "target" / "release" / binary_name,
            Path.cwd() / "target" / "release" / binary_name,
        )
    )
    return tuple(dict.fromkeys(path.resolve() for path in candidates))


def find_kernel() -> Path | None:
    """Return the first trusted, executable scanner-kernel candidate."""

    for path in _candidate_kernel_paths():
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if not stat.S_ISREG(mode):
            continue
        if os.name != "nt" and not os.access(path, os.X_OK):
            continue
        if mode & stat.S_IWOTH:
            continue
        return path
    return None


def _run_rust_kernel(root: Path, *, max_files: int, max_bytes: int) -> KernelResult:
    kernel = find_kernel()
    if kernel is None:
        raise FileNotFoundError("Rust scanner kernel is not installed")
    command = (
        str(kernel),
        "scan",
        str(root),
        "--max-files",
        str(max_files),
        "--max-bytes",
        str(max_bytes),
    )
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if completed.returncode != 0:
        error = completed.stderr.strip()[:500]
        raise RuntimeError(f"Rust scanner kernel failed: {error or completed.returncode}")
    if len(completed.stdout.encode("utf-8")) > 64 * 1024 * 1024:
        raise ValueError("Rust scanner kernel output exceeded the protocol limit")
    return _validate_kernel_payload(json.loads(completed.stdout), root)


def _classify_magic(prefix: bytes, suffix: str) -> str:
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"MZ"):
        return "pe"
    if prefix[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        return "mach-o"
    if prefix.startswith(b"\x00asm"):
        return "wasm"
    if prefix.startswith(b"PK\x03\x04"):
        return "zip"
    if prefix.startswith(b"\x1f\x8b"):
        return "gzip"
    if prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if prefix.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if suffix in {".tar", ".tgz", ".tbz", ".txz"}:
        return "archive"
    if b"\x00" in prefix[:4096]:
        return "binary"
    return "text"


def _extract_indicators(data: bytes) -> tuple[str, ...]:
    printable = bytearray()
    strings: list[str] = []
    for value in data:
        if 32 <= value <= 126 or value in {9, 10, 13}:
            printable.append(value)
        else:
            if len(printable) >= 5:
                strings.append(printable.decode("ascii", errors="ignore"))
            printable.clear()
    if len(printable) >= 5:
        strings.append(printable.decode("ascii", errors="ignore"))
    haystack = "\n".join(strings).lower()
    return tuple(sorted({label for needle, label in _INDICATOR_NEEDLES if needle in haystack}))


def _hash_file(path: Path, *, byte_limit: int) -> tuple[str | None, int, str | None]:
    hasher = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                read += len(chunk)
                if read > byte_limit:
                    return None, read, "file-hash-limit"
                hasher.update(chunk)
    except OSError as exc:
        return None, read, f"read-error:{exc.__class__.__name__}"
    return hasher.hexdigest(), read, None


def _walk_python(root: Path, *, max_files: int, max_bytes: int) -> KernelResult:
    root = root.resolve()
    pending = [root]
    records: list[InventoryRecord] = []
    files_seen = 0
    bytes_hashed = 0
    truncated = False
    excluded_directories = 0
    errors: list[str] = []

    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"directory-read:{directory.name}:{exc.__class__.__name__}")
            continue
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                errors.append("path-escaped-root")
                continue
            if entry.is_symlink():
                target: str | None
                escapes = False
                try:
                    target = os.readlink(path)
                    resolved_target = (path.parent / target).resolve()
                    escapes = not resolved_target.is_relative_to(root)
                except OSError as exc:
                    target = None
                    errors.append(f"symlink-read:{relative}:{exc.__class__.__name__}")
                records.append(
                    InventoryRecord(
                        path=relative,
                        kind="symlink",
                        size=0,
                        symlink_target=target,
                        symlink_escapes_root=escapes,
                    )
                )
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name in _EXCLUDED_DIRECTORIES:
                    excluded_directories += 1
                    continue
                child_directories.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                records.append(InventoryRecord(path=relative, kind="special", size=0, error="unsupported-file-type"))
                continue
            files_seen += 1
            if files_seen > max_files or bytes_hashed >= max_bytes:
                truncated = True
                break
            try:
                size = path.stat().st_size
                mode = path.stat().st_mode
                with path.open("rb") as handle:
                    prefix = handle.read(min(DEFAULT_STRING_SCAN_LIMIT, max(4096, size)))
            except OSError as exc:
                records.append(
                    InventoryRecord(
                        path=relative,
                        kind="file",
                        size=0,
                        error=f"read-error:{exc.__class__.__name__}",
                    )
                )
                continue
            format_name = _classify_magic(prefix, path.suffix.lower())
            hash_value, hashed, error = _hash_file(path, byte_limit=min(DEFAULT_FILE_HASH_LIMIT, max_bytes))
            bytes_hashed += hashed
            indicators = _extract_indicators(prefix) if format_name in {"elf", "pe", "mach-o", "wasm", "binary"} else ()
            hardening: tuple[str, ...] = ()
            if format_name == "elf" and len(prefix) > 18:
                hardening = ("pie-candidate",) if prefix[16:18] in {b"\x03\x00", b"\x00\x03"} else ()
            records.append(
                InventoryRecord(
                    path=relative,
                    kind="file",
                    size=size,
                    sha256=hash_value,
                    format=format_name,
                    executable=bool(mode & 0o111) or format_name in {"elf", "pe", "mach-o", "wasm"},
                    indicators=indicators,
                    hardening=hardening,
                    error=error,
                )
            )
        if truncated:
            break
        pending.extend(reversed(child_directories))

    records.sort(key=lambda record: record.path)
    return KernelResult(
        protocol=KERNEL_PROTOCOL,
        engine="python",
        root=str(root),
        records=tuple(records),
        files_seen=files_seen,
        bytes_hashed=bytes_hashed,
        truncated=truncated,
        excluded_directories=excluded_directories,
        errors=tuple(errors),
    )


def scan_inventory(
    root: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    require_rust: bool = False,
) -> KernelResult:
    """Inventory ``root`` with Rust when available and a verified Python fallback.

    A malformed or untrusted Rust response never replaces the fallback. When
    ``require_rust`` is true, any Rust unavailability or protocol failure is
    surfaced to the caller instead of silently changing engines.
    """

    resolved = Path(root).resolve()
    if not resolved.is_dir():
        raise NotADirectoryError(resolved)
    if max_files <= 0 or max_files > 1_000_000:
        raise ValueError("max_files must be between 1 and 1,000,000")
    if max_bytes <= 0 or max_bytes > 32 * 1024 * 1024 * 1024:
        raise ValueError("max_bytes is outside the supported range")
    try:
        return _run_rust_kernel(resolved, max_files=max_files, max_bytes=max_bytes)
    except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        if require_rust:
            raise
    return _walk_python(resolved, max_files=max_files, max_bytes=max_bytes)
