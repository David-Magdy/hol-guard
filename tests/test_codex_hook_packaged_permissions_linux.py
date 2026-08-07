from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from codex_plugin_scanner.guard.codex_hook_manifest import CodexHookManifestSpec, build_authenticated_hook_manifest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and permission semantics are required")


def _site_packages_file(tmp_path: Path, name: str = "codex_daemon_hook_bridge.py") -> Path:
    path = (
        tmp_path
        / "venv"
        / "lib"
        / "python3.12"
        / "site-packages"
        / "codex_plugin_scanner"
        / "guard"
        / "adapters"
        / name
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# packaged fixture\n", encoding="utf-8")
    path.chmod(0o664)
    return path


def test_packaged_bridge_accepts_private_group_write_in_site_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _site_packages_file(tmp_path)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: True)

    metadata = validate_regular_file(bridge, role="bridge", executable_required=False)

    assert metadata.st_uid == os.getuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o664


def test_packaged_bridge_rejects_shared_group_write_in_site_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _site_packages_file(tmp_path)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: False)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(bridge, role="bridge", executable_required=False)

    assert error.value.reason == "codex_hook_bridge_permissions_unsafe"


def test_non_package_bridge_still_rejects_group_write_even_for_private_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = tmp_path / "codex_daemon_hook_bridge.py"
    bridge.write_text("# unpackaged fixture\n", encoding="utf-8")
    bridge.chmod(0o664)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: True)

    with pytest.raises(CodexHookIntegrityError, match="writable by another user") as error:
        validate_regular_file(bridge, role="bridge", executable_required=False)

    assert error.value.reason == "codex_hook_bridge_permissions_unsafe"


def test_manifest_build_accepts_private_group_pipx_style_packaged_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda owner_uid, group_gid: True)
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text('model = "gpt-5"\n', encoding="utf-8")
    config_path.chmod(0o600)

    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o755)

    package_root = tmp_path / "venv" / "lib" / "python3.12" / "site-packages" / "codex_plugin_scanner"
    roles = (
        "bridge",
        "bridge_runtime",
        "fallback_entrypoint",
        "daemon_entrypoint",
        "daemon_manager",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    )
    packaged_files: list[tuple[str, Path]] = []
    for role in roles:
        path = package_root / f"{role}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {role}\n", encoding="utf-8")
        path.chmod(0o664)
        packaged_files.append((role, path))

    manifest = build_authenticated_hook_manifest(
        CodexHookManifestSpec(
            guard_home=guard_home,
            home_dir=home_dir,
            runtime_guard_home=guard_home,
            workspace_dir=None,
            config_path=config_path,
            interpreter_path=interpreter,
            package_version="test",
            packaged_file_paths=tuple(packaged_files),
            fallback_argv=(str(interpreter), "-c", "pass"),
            daemon_start_argv=(str(interpreter), "-c", "pass"),
            event_bindings=(),
        )
    )

    identities = manifest["packaged_files"]
    assert isinstance(identities, list)
    assert len(identities) == len(roles)
    assert all(isinstance(identity, dict) and identity["mode"] == 0o664 for identity in identities)
