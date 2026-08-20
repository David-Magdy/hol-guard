from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def test_concurrent_first_use_creates_one_key_and_preserves_both_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stores = (EncryptedFileSecretStore(tmp_path), EncryptedFileSecretStore(tmp_path))
    original = EncryptedFileSecretStore._atomic_write_bytes
    key_writes = 0
    counter_lock = threading.Lock()
    start = threading.Barrier(3)

    def delayed_write(self: EncryptedFileSecretStore, path: Path, payload: bytes, mode: int) -> None:
        nonlocal key_writes
        if path == self.key_path:
            with counter_lock:
                key_writes += 1
            time.sleep(0.05)
        original(self, path, payload, mode)

    monkeypatch.setattr(EncryptedFileSecretStore, "_atomic_write_bytes", delayed_write)
    errors: list[BaseException] = []

    def writer(index: int) -> None:
        try:
            start.wait()
            stores[index].set_secret(f"secret-{index}", f"value-{index}")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert key_writes == 1
    reopened = EncryptedFileSecretStore(tmp_path)
    assert reopened.get_secret("secret-0") == "value-0"
    assert reopened.get_secret("secret-1") == "value-1"


def test_invalid_existing_vault_key_fails_closed_without_rotation(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True)
    key_path = secrets_dir / "key.bin"
    key_path.write_bytes(b"")

    store = EncryptedFileSecretStore(tmp_path)
    with pytest.raises(RuntimeError, match="key is empty"):
        store.set_secret("authority", "value")

    assert key_path.read_bytes() == b""
