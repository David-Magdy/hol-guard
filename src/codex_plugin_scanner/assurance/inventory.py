"""Deterministic, bounded extension inventory without following unsafe links."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .limits import ScanLimits
from .models import CoverageGap, Severity


EXCLUDED_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "target",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    path: Path
    relative_path: str
    size: int
    mode: int
    kind: str
    sha256: str | None
    readable: bool


@dataclass(frozen=True, slots=True)
class InventoryResult:
    entries: tuple[InventoryEntry, ...]
    artifact_digest: str
    total_bytes: int
    gaps: tuple[CoverageGap, ...]
    limit_reached: bool


def build_inventory(root: Path, limits: ScanLimits) -> InventoryResult:
    limits.validate()
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ValueError(f"scan target is not a directory: {root}")

    entries: list[InventoryEntry] = []
    gaps: list[CoverageGap] = []
    total_bytes = 0
    limit_reached = False
    digest = hashlib.sha256()

    for current, directory_names, file_names in os.walk(resolved_root, topdown=True, followlinks=False):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            relative = candidate.relative_to(resolved_root).as_posix()
            if name in EXCLUDED_NAMES:
                continue
            try:
                info = candidate.lstat()
            except OSError:
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_DIRECTORY_UNREADABLE",
                        severity=Severity.MEDIUM,
                        description="A directory could not be inspected.",
                        path=relative,
                    )
                )
                continue
            if stat.S_ISLNK(info.st_mode):
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_DIRECTORY_SYMLINK",
                        severity=Severity.MEDIUM,
                        description="Directory symlinks are not followed during assurance scans.",
                        path=relative,
                    )
                )
                continue
            safe_directories.append(name)
        directory_names[:] = safe_directories

        for name in sorted(file_names):
            if len(entries) >= limits.max_files or total_bytes >= limits.max_total_bytes:
                limit_reached = True
                break
            candidate = current_path / name
            relative = candidate.relative_to(resolved_root).as_posix()
            try:
                info = candidate.lstat()
            except OSError:
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_UNREADABLE",
                        severity=Severity.MEDIUM,
                        description="A file could not be statted.",
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, 0, 0, "unreadable", None, False)
                )
                continue

            if stat.S_ISLNK(info.st_mode):
                try:
                    target = candidate.resolve(strict=False)
                    within = target == resolved_root or resolved_root in target.parents
                except (OSError, RuntimeError):
                    within = False
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_SYMLINK" if within else "INVENTORY_SYMLINK_ESCAPE",
                        severity=Severity.LOW if within else Severity.HIGH,
                        description=(
                            "File symlinks are inventoried but not dereferenced."
                            if within
                            else "A file symlink resolves outside the scan root."
                        ),
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, info.st_size, info.st_mode, "symlink", None, False)
                )
                continue
            if not stat.S_ISREG(info.st_mode):
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_SPECIAL_FILE",
                        severity=Severity.HIGH,
                        description="Special files are not read by the scanner.",
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, info.st_size, info.st_mode, "special", None, False)
                )
                continue

            total_bytes += info.st_size
            if info.st_size > limits.max_file_bytes:
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_OVERSIZED",
                        severity=Severity.MEDIUM,
                        description="A file exceeds the configured per-file analysis limit.",
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, info.st_size, info.st_mode, "regular", None, False)
                )
                continue

            try:
                file_digest = _hash_file(candidate, expected_size=info.st_size)
            except OSError:
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_READ_FAILED",
                        severity=Severity.MEDIUM,
                        description="A file changed or became unreadable while hashing.",
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, info.st_size, info.st_mode, "regular", None, False)
                )
                continue

            digest.update(relative.encode("utf-8", errors="surrogateescape"))
            digest.update(b"\0")
            digest.update(str(info.st_mode & 0o7777).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(info.st_size).encode("ascii"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(file_digest))
            entries.append(
                InventoryEntry(candidate, relative, info.st_size, info.st_mode, "regular", file_digest, True)
            )
        if limit_reached:
            break

    if limit_reached:
        gaps.append(
            CoverageGap(
                code="INVENTORY_LIMIT_REACHED",
                severity=Severity.HIGH,
                description="Inventory limits were reached before the complete tree was inspected.",
            )
        )

    return InventoryResult(
        entries=tuple(entries),
        artifact_digest=digest.hexdigest(),
        total_bytes=total_bytes,
        gaps=tuple(gaps),
        limit_reached=limit_reached,
    )


def _hash_file(path: Path, *, expected_size: int) -> str:
    hasher = hashlib.sha256()
    read_bytes = 0
    with path.open("rb", buffering=0) as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            read_bytes += len(chunk)
    if read_bytes != expected_size:
        raise OSError("file size changed while hashing")
    return hasher.hexdigest()
