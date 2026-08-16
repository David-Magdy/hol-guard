#!/usr/bin/env python3
"""Bind the macOS Desktop proxy to the exact signed file executed by the hook."""

from pathlib import Path

bridge_path = Path("src/codex_plugin_scanner/guard/adapters/bounded_cli_hook_bridge.py")
text = bridge_path.read_text(encoding="utf-8")
start = text.index("def _trusted_desktop_hook_proxy(")
end = text.index("\ndef _assert_loopback_http_url", start)
replacement = r'''_DESKTOP_PROXY_LAUNCH_SCRIPT = r"""
set -eu
proxy=$1
expected_team=$2
config=$3
fallback=$4
fallback_bridge() {
  exec "$fallback" __guard-bounded-hook "$config"
}
exec 3<"$proxy" || fallback_bridge
fd_identity=$(/usr/bin/stat -f '%d:%i' /dev/fd/3 2>/dev/null) || fallback_bridge
path_identity=$(/usr/bin/stat -f '%d:%i' "$proxy" 2>/dev/null) || fallback_bridge
[ "$fd_identity" = "$path_identity" ] || fallback_bridge
/usr/bin/codesign --verify --strict --verbose=2 "$proxy" >/dev/null 2>&1 || fallback_bridge
actual_team=$(
  /usr/bin/codesign --display --verbose=4 "$proxy" 2>&1 \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
    | /usr/bin/head -n 1
)
if [ "$expected_team" = "adhoc-e2e" ]; then
  [ "${HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE:-}" = "1" ] || fallback_bridge
  [ -z "$actual_team" ] || fallback_bridge
else
  [ "$actual_team" = "$expected_team" ] || fallback_bridge
fi
path_after=$(/usr/bin/stat -f '%d:%i' "$proxy" 2>/dev/null) || fallback_bridge
[ "$fd_identity" = "$path_after" ] || fallback_bridge
exec /dev/fd/3 __guard-hook-proxy "$config"
""".strip()


def _trusted_desktop_hook_proxy_command(
    python_executable: str,
    config_json: str,
) -> tuple[str, ...] | None:
    """Return an fd-bound signed macOS proxy command or retain the Core bridge.

    Linux intentionally stays on the internal frozen bridge. AppImage path
    variables are caller-controlled and are not accepted as executable
    provenance. The macOS launcher opens the proxy before validation, compares
    the open descriptor with the validated path before and after codesign, and
    executes that same descriptor through /dev/fd/3. A path replacement can
    therefore only trigger the verified Core fallback, never execute unchecked
    bytes.
    """

    if (
        sys.platform != "darwin"
        or not bool(getattr(sys, "frozen", False))
        or os.environ.get("HOL_GUARD_DESKTOP") != "1"
    ):
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
        core = Path(python_executable).resolve(strict=True)
    except OSError:
        return None
    if stat.S_ISLNK(raw_metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return None
    if not os.access(resolved, os.X_OK):
        return None
    if metadata.st_uid not in {os.getuid(), 0} or stat.S_IMODE(metadata.st_mode) & 0o022:
        return None

    proxy_team = _codesign_team(resolved)
    core_team = _codesign_team(core)
    expected_team: str | None
    if proxy_team is not None and proxy_team == core_team:
        expected_team = proxy_team
    elif (
        os.environ.get("HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE") == "1"
        and proxy_team is None
        and core_team is None
    ):
        expected_team = "adhoc-e2e"
    else:
        expected_team = None
    if expected_team is None:
        return None

    return (
        "/bin/sh",
        "-c",
        _DESKTOP_PROXY_LAUNCH_SCRIPT,
        "hol-guard-desktop-proxy",
        str(resolved),
        expected_team,
        config_json,
        str(core),
    )

'''
text = text[:start] + replacement + text[end + 1 :]
old = '''        desktop_proxy = _trusted_desktop_hook_proxy(python_executable)
        if desktop_proxy is not None:
            return desktop_proxy, _DESKTOP_PROXY_COMMAND, config_json
'''
new = '''        desktop_proxy = _trusted_desktop_hook_proxy_command(python_executable, config_json)
        if desktop_proxy is not None:
            return desktop_proxy
'''
if text.count(old) != 1:
    raise SystemExit("Expected one frozen proxy command anchor")
text = text.replace(old, new, 1)
bridge_path.write_text(text, encoding="utf-8")

test_path = Path("tests/test_bounded_cli_hook_bridge.py")
tests = test_path.read_text(encoding="utf-8")
start = tests.index("def test_frozen_hook_command_prefers_trusted_native_desktop_proxy(")
end = tests.index("\ndef test_frozen_fallback_runs_supported_cli_subcommand_without_python_flags", start)
replacement = r'''def test_frozen_hook_command_prefers_fd_bound_signed_macos_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    expected = (
        "/bin/sh",
        "-c",
        "verified-launcher",
        "hol-guard-desktop-proxy",
        "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard",
        "TEAMID",
        "config",
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    )
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy_command",
        lambda executable, config: (*expected[:-2], config, executable),
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

    assert command[:6] == expected[:6]
    config = json.loads(command[6])
    assert config["python_executable"].endswith("/hol-guard")
    assert config["frozen_launcher"] is True
    assert command[7].endswith("/hol-guard")


def test_untrusted_native_proxy_falls_back_to_internal_frozen_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy_command",
        lambda executable, config: None,
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


def test_linux_never_uses_caller_controlled_appimage_as_proxy_provenance(
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
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "linux")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setenv("APPIMAGE", str(proxy))

    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None


def test_macos_launcher_binds_codesign_validation_to_the_executed_descriptor() -> None:
    launcher = bounded_cli_hook_bridge._DESKTOP_PROXY_LAUNCH_SCRIPT
    assert 'exec 3<"$proxy"' in launcher
    assert "/usr/bin/stat -f '%d:%i' /dev/fd/3" in launcher
    assert "/usr/bin/codesign --verify --strict" in launcher
    assert 'path_after=$(/usr/bin/stat -f' in launcher
    assert 'exec /dev/fd/3 __guard-hook-proxy "$config"' in launcher
    assert 'exec "$fallback" __guard-bounded-hook "$config"' in launcher


'''
tests = tests[:start] + replacement + tests[end + 1 :]
test_path.write_text(tests, encoding="utf-8")
