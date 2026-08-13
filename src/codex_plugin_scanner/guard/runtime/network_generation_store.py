"""Crash-safe, monotonic storage for signed network policy generations."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from codex_plugin_scanner.guard.runtime.network_authority import (
    CompiledNetworkPolicy,
    NetworkAuthorityError,
    NetworkAuthorityReason,
    SignedNetworkGeneration,
    canonical_json_bytes,
    verify_signed_generation,
)

_POINTER_SCHEMA: Final = "guard.network-generation-pointer.v1"
_JOURNAL_SCHEMA: Final = "guard.network-generation-journal.v1"
_MAX_STATE_BYTES: Final = 4 * 1024 * 1024
_MAX_JOURNAL_ENTRIES: Final = 4096


@dataclass(frozen=True, slots=True)
class InstalledNetworkGeneration:
    policy: CompiledNetworkPolicy
    envelope_digest: str
    artifact_path: Path
    installed_at_epoch_s: int


class NetworkGenerationStore:
    """Persist signed generations without permitting rollback or silent recovery."""

    def __init__(
        self,
        root: Path,
        *,
        trusted_keys: Mapping[str, bytes],
        lock_timeout_seconds: float = 10.0,
    ) -> None:
        self.root = root
        self.trusted_keys = dict(trusted_keys)
        self.lock_timeout_seconds = lock_timeout_seconds
        self.generations_dir = root / "generations"
        self.pointer_path = root / "current.json"
        self.journal_path = root / "journal.json"
        self.lock_path = root / ".install.lock"

    def install(
        self,
        envelope: SignedNetworkGeneration | bytes | str | Mapping[str, object],
        *,
        installed_at_epoch_s: int | None = None,
    ) -> InstalledNetworkGeneration:
        signed = envelope if isinstance(envelope, SignedNetworkGeneration) else SignedNetworkGeneration.from_json(envelope)
        envelope_bytes = canonical_json_bytes(signed.to_json())
        envelope_digest = hashlib.sha256(envelope_bytes).hexdigest()
        installed_at = int(time.time()) if installed_at_epoch_s is None else installed_at_epoch_s
        if installed_at < 0:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network generation installation time cannot be negative",
            )

        self._prepare_root()
        with _exclusive_private_lock(self.lock_path, timeout_seconds=self.lock_timeout_seconds):
            current = self._load_pointer(optional=True)
            if current is not None and current["envelope_digest"] == envelope_digest:
                installed = self._load_current_locked()
                return InstalledNetworkGeneration(
                    policy=installed.policy,
                    envelope_digest=installed.envelope_digest,
                    artifact_path=installed.artifact_path,
                    installed_at_epoch_s=installed.installed_at_epoch_s,
                )

            minimum_generation = int(current["generation"]) if current is not None else 0
            expected_previous_digest = str(current["policy_digest"]) if current is not None else None
            policy = verify_signed_generation(
                signed,
                trusted_keys=self.trusted_keys,
                minimum_generation=minimum_generation,
                expected_previous_digest=expected_previous_digest,
            )
            artifact_name = f"{policy.generation:020d}-{policy.policy_digest}.json"
            artifact_path = self.generations_dir / artifact_name
            self._write_generation_artifact(artifact_path, envelope_bytes)
            journal = self._append_journal(
                generation=policy.generation,
                policy_digest=policy.policy_digest,
                authority_digest=policy.authority_digest,
                envelope_digest=envelope_digest,
                artifact_name=artifact_name,
                installed_at_epoch_s=installed_at,
            )
            pointer = {
                "schema": _POINTER_SCHEMA,
                "generation": policy.generation,
                "policy_digest": policy.policy_digest,
                "authority_digest": policy.authority_digest,
                "envelope_digest": envelope_digest,
                "artifact": artifact_name,
                "installed_at_epoch_s": installed_at,
                "journal_tail_digest": journal[-1]["entry_digest"],
            }
            _atomic_private_write(self.pointer_path, canonical_json_bytes(pointer))
            return InstalledNetworkGeneration(
                policy=policy,
                envelope_digest=envelope_digest,
                artifact_path=artifact_path,
                installed_at_epoch_s=installed_at,
            )

    def load_current(self) -> InstalledNetworkGeneration | None:
        self._prepare_root()
        with _exclusive_private_lock(self.lock_path, timeout_seconds=self.lock_timeout_seconds):
            if not self.pointer_path.exists():
                return None
            return self._load_current_locked()

    def _load_current_locked(self) -> InstalledNetworkGeneration:
        pointer = self._load_pointer(optional=False)
        assert pointer is not None
        journal = self._load_journal()
        if not journal or journal[-1]["entry_digest"] != pointer["journal_tail_digest"]:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation pointer is not bound to the durable journal tail",
            )
        artifact_name = cast(str, pointer["artifact"])
        artifact_path = self.generations_dir / artifact_name
        if artifact_path.parent != self.generations_dir or "/" in artifact_name or "\\" in artifact_name:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation pointer contains an unsafe artifact path",
            )
        envelope_bytes = _read_private_file(artifact_path)
        envelope_digest = hashlib.sha256(envelope_bytes).hexdigest()
        if envelope_digest != pointer["envelope_digest"]:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "installed network generation artifact digest does not match the pointer",
            )
        policy = verify_signed_generation(
            envelope_bytes,
            trusted_keys=self.trusted_keys,
            minimum_generation=int(pointer["generation"]) - 1,
            expected_previous_digest=(
                cast(str | None, journal[-1]["previous_policy_digest"])
                if len(journal) > 1
                else None
            ),
        )
        if (
            policy.generation != pointer["generation"]
            or policy.policy_digest != pointer["policy_digest"]
            or policy.authority_digest != pointer["authority_digest"]
        ):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "installed network generation metadata is inconsistent",
            )
        return InstalledNetworkGeneration(
            policy=policy,
            envelope_digest=envelope_digest,
            artifact_path=artifact_path,
            installed_at_epoch_s=int(pointer["installed_at_epoch_s"]),
        )

    def _prepare_root(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.generations_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _assert_private_directory(self.root)
        _assert_private_directory(self.generations_dir)

    def _write_generation_artifact(self, path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            existing = _read_private_file(path)
            if existing != content:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "an immutable network generation artifact already exists with different bytes",
                )
            return
        except OSError as exc:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation artifact could not be created safely",
            ) from exc
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        _fsync_directory(path.parent)

    def _load_pointer(self, *, optional: bool) -> dict[str, object] | None:
        if not self.pointer_path.exists():
            if optional:
                return None
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation pointer is missing",
            )
        pointer = _read_json_object(self.pointer_path)
        expected = {
            "schema",
            "generation",
            "policy_digest",
            "authority_digest",
            "envelope_digest",
            "artifact",
            "installed_at_epoch_s",
            "journal_tail_digest",
        }
        _require_exact_fields(pointer, expected)
        if pointer.get("schema") != _POINTER_SCHEMA:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation pointer schema is unsupported",
            )
        _require_positive_int(pointer.get("generation"), field="generation")
        _require_digest(pointer.get("policy_digest"), field="policy_digest")
        _require_digest(pointer.get("authority_digest"), field="authority_digest")
        _require_digest(pointer.get("envelope_digest"), field="envelope_digest")
        _require_digest(pointer.get("journal_tail_digest"), field="journal_tail_digest")
        _require_nonnegative_int(pointer.get("installed_at_epoch_s"), field="installed_at_epoch_s")
        if not isinstance(pointer.get("artifact"), str) or not pointer["artifact"]:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation pointer artifact name is invalid",
            )
        return pointer

    def _append_journal(
        self,
        *,
        generation: int,
        policy_digest: str,
        authority_digest: str,
        envelope_digest: str,
        artifact_name: str,
        installed_at_epoch_s: int,
    ) -> list[dict[str, object]]:
        journal = self._load_journal(optional=True)
        if len(journal) >= _MAX_JOURNAL_ENTRIES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation journal reached its bounded entry ceiling",
            )
        previous_entry_digest = cast(str | None, journal[-1]["entry_digest"]) if journal else None
        previous_policy_digest = cast(str | None, journal[-1]["policy_digest"]) if journal else None
        entry_without_digest = {
            "sequence": len(journal) + 1,
            "generation": generation,
            "policy_digest": policy_digest,
            "authority_digest": authority_digest,
            "envelope_digest": envelope_digest,
            "artifact": artifact_name,
            "installed_at_epoch_s": installed_at_epoch_s,
            "previous_entry_digest": previous_entry_digest,
            "previous_policy_digest": previous_policy_digest,
        }
        entry = {
            **entry_without_digest,
            "entry_digest": hashlib.sha256(canonical_json_bytes(entry_without_digest)).hexdigest(),
        }
        journal.append(entry)
        _atomic_private_write(
            self.journal_path,
            canonical_json_bytes({"schema": _JOURNAL_SCHEMA, "entries": journal}),
        )
        return journal

    def _load_journal(self, *, optional: bool = False) -> list[dict[str, object]]:
        if not self.journal_path.exists():
            if optional:
                return []
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation journal is missing",
            )
        payload = _read_json_object(self.journal_path)
        _require_exact_fields(payload, {"schema", "entries"})
        if payload.get("schema") != _JOURNAL_SCHEMA or not isinstance(payload.get("entries"), list):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation journal schema is invalid",
            )
        raw_entries = cast(list[object], payload["entries"])
        if len(raw_entries) > _MAX_JOURNAL_ENTRIES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation journal exceeds its entry ceiling",
            )
        entries: list[dict[str, object]] = []
        previous_entry_digest: str | None = None
        previous_policy_digest: str | None = None
        previous_generation = 0
        for index, raw_entry in enumerate(raw_entries, start=1):
            if not isinstance(raw_entry, Mapping):
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation journal entry is not an object",
                )
            entry = dict(cast(Mapping[str, object], raw_entry))
            expected = {
                "sequence",
                "generation",
                "policy_digest",
                "authority_digest",
                "envelope_digest",
                "artifact",
                "installed_at_epoch_s",
                "previous_entry_digest",
                "previous_policy_digest",
                "entry_digest",
            }
            _require_exact_fields(entry, expected)
            if entry.get("sequence") != index:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation journal sequence is not contiguous",
                )
            generation = _require_positive_int(entry.get("generation"), field="generation")
            if generation <= previous_generation:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.GENERATION_ROLLBACK,
                    "network generation journal contains a rollback",
                )
            if entry.get("previous_entry_digest") != previous_entry_digest:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation journal hash chain is broken",
                )
            if entry.get("previous_policy_digest") != previous_policy_digest:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.GENERATION_CHAIN_MISMATCH,
                    "network generation journal policy chain is broken",
                )
            entry_digest = _require_digest(entry.get("entry_digest"), field="entry_digest")
            entry_without_digest = {key: value for key, value in entry.items() if key != "entry_digest"}
            expected_digest = hashlib.sha256(canonical_json_bytes(entry_without_digest)).hexdigest()
            if entry_digest != expected_digest:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation journal entry digest is invalid",
                )
            previous_entry_digest = entry_digest
            previous_policy_digest = _require_digest(entry.get("policy_digest"), field="policy_digest")
            _require_digest(entry.get("authority_digest"), field="authority_digest")
            _require_digest(entry.get("envelope_digest"), field="envelope_digest")
            _require_nonnegative_int(entry.get("installed_at_epoch_s"), field="installed_at_epoch_s")
            if not isinstance(entry.get("artifact"), str) or not entry["artifact"]:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation journal artifact name is invalid",
                )
            previous_generation = generation
            entries.append(entry)
        return entries


@contextmanager
def _exclusive_private_lock(path: Path, *, timeout_seconds: float) -> Iterator[None]:
    if timeout_seconds <= 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network generation lock timeout must be positive",
        )
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation lock could not be opened safely",
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or _wrong_owner(info) or _permissive_mode(info):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network generation lock is not private and owner-controlled",
            )
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                _try_lock(descriptor)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise NetworkAuthorityError(
                        NetworkAuthorityReason.STATE_UNSAFE,
                        "network generation lock acquisition timed out",
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            _unlock(descriptor)
    finally:
        os.close(descriptor)


def _try_lock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError from exc
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _read_json_object(path: Path) -> dict[str, object]:
    raw = _read_private_file(path)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network generation state contains duplicate JSON keys",
                )
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except NetworkAuthorityError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation state is not valid UTF-8 JSON",
        ) from exc
    if not isinstance(payload, dict):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation state must be a JSON object",
        )
    return cast(dict[str, object], payload)


def _read_private_file(path: Path) -> bytes:
    _assert_private_regular_file(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation state could not be read",
        ) from exc
    if len(raw) > _MAX_STATE_BYTES:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation state exceeds its byte ceiling",
        )
    return raw


def _atomic_private_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_private_directory(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation directory cannot be inspected",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or _wrong_owner(info) or _permissive_mode(info):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation directory must be private and owner-controlled",
        )


def _assert_private_regular_file(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation file cannot be inspected",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or _wrong_owner(info)
        or _permissive_mode(info)
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation file must be private, regular, and owner-controlled",
        )


def _wrong_owner(info: os.stat_result) -> bool:
    getuid = getattr(os, "getuid", None)
    return getuid is not None and info.st_uid != getuid()


def _permissive_mode(info: os.stat_result) -> bool:
    return os.name != "nt" and bool(info.st_mode & 0o077)


def _require_exact_fields(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network generation state fields do not match the schema",
        )


def _require_positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) <= 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            f"network generation {field} must be a positive integer",
        )
    return cast(int, value)


def _require_nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) < 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            f"network generation {field} must be a non-negative integer",
        )
    return cast(int, value)


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            f"network generation {field} must be a SHA-256 digest",
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            f"network generation {field} must be a SHA-256 digest",
        ) from exc
    if raw.hex() != value:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            f"network generation {field} must be a lowercase SHA-256 digest",
        )
    return value


__all__: Sequence[str] = (
    "InstalledNetworkGeneration",
    "NetworkGenerationStore",
)
