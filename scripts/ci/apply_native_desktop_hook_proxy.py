#!/usr/bin/env python3
"""Apply the native Desktop hook-proxy integration with exact anchors."""

from pathlib import Path

BRIDGE = Path("src/codex_plugin_scanner/guard/adapters/bounded_cli_hook_bridge.py")
TESTS = Path("tests/test_bounded_cli_hook_bridge.py")

text = BRIDGE.read_text(encoding="utf-8")

replacements = [
    (
        "import stat\nimport sys\n",
        "import stat\nimport subprocess\nimport sys\n",
    ),
    (
        '_FROZEN_OPTIONAL_PATH_FLAGS = frozenset({"--home", "--workspace"})\n\n\n',
        '''_FROZEN_OPTIONAL_PATH_FLAGS = frozenset({"--home", "--workspace"})
_DESKTOP_PROXY_ENV = "HOL_GUARD_DESKTOP_HOOK_PROXY"
_DESKTOP_PROXY_COMMAND = "__guard-hook-proxy"


def _codesign_team(path: Path) -> str | None:
    """Return a verified Apple TeamIdentifier without importing the Desktop runtime."""

    verify = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0:
        return None
    display = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if display.returncode != 0:
        return None
    for line in display.stderr.splitlines():
        team = line.strip().removeprefix("TeamIdentifier=")
        if team != line.strip() and team and team != "not set":
            return team
    return None


def _trusted_desktop_hook_proxy(python_executable: str) -> str | None:
    """Return the native Desktop proxy only when its platform identity is trusted.

    The variable is accepted only from a frozen Core launched by Desktop. On
    macOS both executables must carry the same verified Apple TeamIdentifier.
    On Linux the proxy must be the exact AppImage path inherited by the Core
    process. Other platforms keep using the internal frozen bridge until an
    equivalent platform trust check is implemented.
    """

    if not bool(getattr(sys, "frozen", False)) or os.environ.get("HOL_GUARD_DESKTOP") != "1":
        return None
    raw = os.environ.get(_DESKTOP_PROXY_ENV)
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        return None
    try:
        raw_metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if stat.S_ISLNK(raw_metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return None
    if not os.access(resolved, os.X_OK):
        return None
    if os.name != "nt" and (
        metadata.st_uid not in {os.getuid(), 0} or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        return None

    core = Path(python_executable)
    if sys.platform == "darwin":
        try:
            core = core.resolve(strict=True)
        except OSError:
            return None
        proxy_team = _codesign_team(resolved)
        core_team = _codesign_team(core)
        if proxy_team is not None and proxy_team == core_team:
            return str(resolved)
        if (
            os.environ.get("HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE") == "1"
            and proxy_team is None
            and core_team is None
        ):
            return str(resolved)
        return None

    if sys.platform.startswith("linux"):
        appimage = os.environ.get("APPIMAGE")
        if appimage:
            try:
                trusted_appimage = Path(appimage).resolve(strict=True)
            except OSError:
                return None
            return str(resolved) if resolved == trusted_appimage else None
        if os.environ.get("HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE") == "1":
            return str(resolved)
        return None
    return None


''',
    ),
    (
        '''    if frozen_launcher:
        return (
            python_executable,
            _FROZEN_BRIDGE_COMMAND,
            json.dumps(config, ensure_ascii=True, separators=(",", ":")),
        )
''',
        '''    if frozen_launcher:
        config_json = json.dumps(config, ensure_ascii=True, separators=(",", ":"))
        desktop_proxy = _trusted_desktop_hook_proxy(python_executable)
        if desktop_proxy is not None:
            return desktop_proxy, _DESKTOP_PROXY_COMMAND, config_json
        return python_executable, _FROZEN_BRIDGE_COMMAND, config_json
''',
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected one bridge anchor, found {count}: {old[:100]!r}")
    text = text.replace(old, new, 1)

BRIDGE.write_text(text, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
anchor = '''def test_frozen_fallback_runs_supported_cli_subcommand_without_python_flags(
'''
addition = '''def test_frozen_hook_command_prefers_trusted_native_desktop_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy",
        lambda executable: "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard",
    )
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable="/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )

    assert command[0] == "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard"
    assert command[1] == "__guard-hook-proxy"
    config = json.loads(command[2])
    assert config["python_executable"].endswith("/hol-guard")
    assert config["frozen_launcher"] is True


def test_untrusted_native_proxy_falls_back_to_internal_frozen_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy",
        lambda executable: None,
    )
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable="/app/hol-guard",
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )

    assert command[:2] == ("/app/hol-guard", "__guard-bounded-hook")


@pytest.mark.skipif(not bounded_cli_hook_bridge.sys.platform.startswith("linux"), reason="Linux trust contract")
def test_linux_proxy_requires_exact_appimage_and_private_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proxy = tmp_path / "HOL-Guard.AppImage"
    proxy.write_text("proxy", encoding="utf-8")
    proxy.chmod(0o755)
    core = tmp_path / "hol-guard"
    core.write_text("core", encoding="utf-8")
    core.chmod(0o755)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setenv("APPIMAGE", str(proxy))

    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy(str(core)) == str(proxy.resolve())

    proxy.chmod(0o777)
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy(str(core)) is None


'''
count = tests.count(anchor)
if count != 1:
    raise SystemExit(f"Expected one test anchor, found {count}")
tests = tests.replace(anchor, addition + anchor, 1)
TESTS.write_text(tests, encoding="utf-8")
