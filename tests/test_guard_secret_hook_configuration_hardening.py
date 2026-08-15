from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.git_subprocess import configured_hooks_path
from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook
from codex_plugin_scanner.guard.secrets.setup_diagnostics import inspect_secrets_setup


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    assert _git(root, "init").returncode == 0
    return root


def test_global_custom_hooks_path_is_detected_and_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    hooks = tmp_path / "global-hooks"
    (home / ".gitconfig").write_text(
        f"[core]\n\thooksPath = {hooks.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)

    assert configured_hooks_path(root) is True
    with pytest.raises(ValueError, match="custom"):
        install_precommit_hook(root)
    report = inspect_secrets_setup(root)
    standard = next(check for check in report.checks if check.code == "standard_hooks_path")
    assert standard.status == "warn"
    assert not hooks.exists()


def test_included_global_custom_hooks_path_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    included = home / "hooks.inc"
    included.write_text(
        f"[core]\n\thooksPath = {(tmp_path / 'included-hooks').as_posix()}\n",
        encoding="utf-8",
    )
    (home / ".gitconfig").write_text(
        f"[include]\n\tpath = {included.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)

    assert configured_hooks_path(root) is True
    with pytest.raises(ValueError, match="custom"):
        install_precommit_hook(root)


def test_ambient_config_injection_is_refused_even_when_value_is_not_disclosed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    injected_path = tmp_path / "ambient-hooks"
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(injected_path))

    assert configured_hooks_path(root) is True
    with pytest.raises(ValueError, match="environment-controlled"):
        install_precommit_hook(root)
    report = inspect_secrets_setup(root)
    serialized = str(report.to_public_dict())
    assert str(injected_path) not in serialized
    assert not injected_path.exists()


def test_clean_environment_uses_standard_hooks_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for key in tuple(os.environ):
        if key.startswith("GIT_CONFIG"):
            monkeypatch.delenv(key, raising=False)

    assert configured_hooks_path(root) is False
