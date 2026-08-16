# pyright: basic
"""Deterministic, bounded extension inventory without following unsafe links."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    """Inventory every reachable entry and bind complete regular-file bytes to SHA-256."""

    limits.validate()
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ValueError(f"scan target is not a directory: {root}")

    entries: list[InventoryEntry] = []
    gaps: list[CoverageGap] = []
    total_bytes = 0
    limit_reached = False
    digest = hashlib.sha256()
    digest.update(b"hol-guard-extension-artifact-v1\0")

    for current, directory_names, file_names in os.walk(
        resolved_root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            relative = candidate.relative_to(resolved_root).as_posix()
            if name in EXCLUDED_NAMES:
                _update_digest(digest, relative, 0, 0, "excluded-directory", None)
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
                _update_digest(digest, relative, 0, 0, "unreadable-directory", None)
                continue
            if stat.S_ISLNK(info.st_mode):
                target = _read_link(candidate)
                target_digest = hashlib.sha256(
                    target.encode("utf-8", errors="surrogateescape")
                ).hexdigest()
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_DIRECTORY_SYMLINK",
                        severity=Severity.MEDIUM,
                        description="Directory symlinks are digest-bound but never followed.",
                        path=relative,
                    )
                )
                _update_digest(
                    digest,
                    relative,
                    info.st_mode,
                    info.st_size,
                    "directory-symlink",
                    target_digest,
                )
                continue
            safe_directories.append(name)
        directory_names[:] = safe_directories

        for name in sorted(file_names):
            if len(entries) >= limits.max_files:
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
                entries.append(InventoryEntry(candidate, relative, 0, 0, "unreadable", None, False))
                _update_digest(digest, relative, 0, 0, "unreadable", None)
                continue

            if stat.S_ISLNK(info.st_mode):
                target = _read_link(candidate)
                target_digest = hashlib.sha256(
                    target.encode("utf-8", errors="surrogateescape")
                ).hexdigest()
                within = _link_resolves_within(candidate, resolved_root)
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_SYMLINK" if within else "INVENTORY_SYMLINK_ESCAPE",
                        severity=Severity.LOW if within else Severity.HIGH,
                        description=(
                            "File symlinks are digest-bound but not dereferenced."
                            if within
                            else "A file symlink resolves outside the scan root."
                        ),
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(
                        candidate,
                        relative,
                        info.st_size,
                        info.st_mode,
                        "symlink",
                        target_digest,
                        False,
                    )
                )
                _update_digest(
                    digest,
                    relative,
                    info.st_mode,
                    info.st_size,
                    "symlink",
                    target_digest,
                )
                continue

            if not stat.S_ISREG(info.st_mode):
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_SPECIAL_FILE",
                        severity=Severity.HIGH,
                        description="Special files are metadata-bound but never read.",
                        path=relative,
                    )
                )
                entries.append(
                    InventoryEntry(candidate, relative, info.st_size, info.st_mode, "special", None, False)
                )
                _update_digest(digest, relative, info.st_mode, info.st_size, "special", None)
                continue

            if total_bytes + info.st_size > limits.max_total_bytes:
                limit_reached = True
                break
            total_bytes += info.st_size
            if info.st_size > limits.max_file_bytes:
                gaps.append(
                    CoverageGap(
                        code="INVENTORY_FILE_OVERSIZED",
                        severity=Severity.MEDIUM,
                        description=(
                            "A file exceeds the semantic-analysis limit. Its complete bytes remain bound "
                            "to the artifact digest."
                        ),
                        path=relative,
                    )
                )
            try:
                file_digest = _hash_stable_file(candidate, info)
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
                _update_digest(digest, relative, info.st_mode, info.st_size, "unstable-regular", None)
                continue

            _update_digest(
                digest,
                relative,
                info.st_mode,
                info.st_size,
                "regular",
                file_digest,
            )
            entries.append(
                InventoryEntry(
                    candidate,
                    relative,
                    info.st_size,
                    info.st_mode,
                    "regular",
                    file_digest,
                    True,
                )
            )
        if limit_reached:
            break

    if limit_reached:
        gaps.append(
            CoverageGap(
                code="INVENTORY_LIMIT_REACHED",
                severity=Severity.HIGH,
                description="Inventory limits were reached before the complete tree was digest-bound.",
            )
        )
        digest.update(b"\0INCOMPLETE-INVENTORY")

    return InventoryResult(
        entries=tuple(entries),
        artifact_digest=digest.hexdigest(),
        total_bytes=total_bytes,
        gaps=tuple(gaps),
        limit_reached=limit_reached,
    )


def _hash_stable_file(path: Path, before: os.stat_result) -> str:
    hasher = hashlib.sha256()
    read_bytes = 0
    with path.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        if not _same_identity(before, opened):
            raise OSError("file identity changed before hashing")
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            read_bytes += len(chunk)
    after = path.lstat()
    if read_bytes != before.st_size or not _same_identity(before, after):
        raise OSError("file changed while hashing")
    return hasher.hexdigest()


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _update_digest(
    digest: Any,
    relative: str,
    mode: int,
    size: int,
    kind: str,
    content_digest: str | None,
) -> None:
    digest.update(relative.encode("utf-8", errors="surrogateescape"))
    digest.update(b"\0")
    digest.update(str(mode & 0o177777).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(size).encode("ascii"))
    digest.update(b"\0")
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    if content_digest is not None:
        digest.update(bytes.fromhex(content_digest))
    digest.update(b"\0")


def _read_link(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "<unreadable-link>"


def _link_resolves_within(path: Path, root: Path) -> bool:
    try:
        target = path.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return target == root or root in target.parents
