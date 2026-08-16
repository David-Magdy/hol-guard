#!/usr/bin/env python3
"""Replace the provisional Desktop hook-proxy launcher with the reviewed contract."""

from __future__ import annotations

import re
from pathlib import Path

BRIDGE = Path("src/codex_plugin_scanner/guard/adapters/bounded_cli_hook_bridge.py")
TESTS = Path("tests/test_bounded_cli_hook_bridge.py")

bridge = BRIDGE.read_text(encoding="utf-8")
bridge = bridge.replace('_DESKTOP_PROXY_COMMAND = "__guard-hook-proxy"\n', "")

replacement = r'''_DESKTOP_PROXY_FALLBACK_EXIT = 125


_DESKTOP_PROXY_LAUNCH_SCRIPT = r"""
set -u
proxy=$1
expected_team=$2
bundle=$3
config=$4
fallback=$5
fallback_bridge() {
  exec "$fallback" __guard-bounded-hook "$config"
}
verify_team() {
  candidate=$1
  /usr/bin/codesign --verify --strict --verbose=2 "$candidate" >/dev/null 2>&1 || return 1
  actual_team=$(
    /usr/bin/codesign --display --verbose=4 "$candidate" 2>&1 \
      | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
      | /usr/bin/head -n 1
  ) || return 1
  [ -n "$actual_team" ] || return 1
  [ "$actual_team" != "not set" ] || return 1
  [ "$actual_team" = "$expected_team" ]
}
[ -x "$proxy" ] && [ ! -L "$proxy" ] || fallback_bridge
[ -x "$fallback" ] && [ ! -L "$fallback" ] || fallback_bridge
[ -d "$bundle" ] && [ ! -L "$bundle" ] || fallback_bridge
proxy_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
verify_team "$bundle" || fallback_bridge
verify_team "$proxy" || fallback_bridge
verify_team "$fallback" || fallback_bridge
proxy_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
[ "$proxy_before" = "$proxy_after" ] || fallback_bridge
[ "$fallback_before" = "$fallback_after" ] || fallback_bridge
"$proxy" __guard-hook-proxy "$config"
status=$?
if [ "$status" -eq 125 ] || [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then
  fallback_bridge
fi
exit "$status"
""".strip()


def _bundle_for_executable(path: Path) -> Path | None:
    for ancestor in path.parents:
        if ancestor.suffix == ".app":
            return ancestor
    return None


def _trusted_desktop_path(path: Path) -> bool:
    """Require a regular private executable under a non-symlinked app bundle."""

    try:
        raw_metadata = path.lstat()
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return False
    if stat.S_ISLNK(raw_metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if not os.access(resolved, os.X_OK):
        return False
    if metadata.st_uid not in {os.getuid(), 0} or stat.S_IMODE(metadata.st_mode) & 0o022:
        return False
    bundle = _bundle_for_executable(resolved)
    if bundle is None:
        return False
    for directory in (bundle, bundle / "Contents", bundle / "Contents" / "MacOS"):
        try:
            raw = directory.lstat()
            current = directory.stat()
        except OSError:
            return False
        if stat.S_ISLNK(raw.st_mode) or not stat.S_ISDIR(current.st_mode):
            return False
        if current.st_uid not in {os.getuid(), 0} or stat.S_IMODE(current.st_mode) & 0o022:
            return False
    return True


def _trusted_desktop_hook_proxy_command(
    python_executable: str,
    config_json: str,
) -> tuple[str, ...] | None:
    """Return a runtime-verified signed macOS proxy command or retain Core.

    The generated command is installed only by a genuine frozen Desktop launch.
    Both executables must be regular, private files in the same signed app
    bundle and share one non-empty Apple TeamIdentifier with that bundle. The
    runtime launcher re-verifies the bundle, proxy, and Core immediately before
    a normal path-based macOS launch. If any validation, launch, or daemon-fast-
    path step fails, status 125/126/127 executes the exact frozen Core bridge.

    Linux intentionally stays on the internal frozen bridge. AppImage path
    variables are caller-controlled and are never executable provenance.
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
    core_candidate = Path(python_executable)
    if not candidate.is_absolute() or not core_candidate.is_absolute():
        return None
    if not _trusted_desktop_path(candidate) or not _trusted_desktop_path(core_candidate):
        return None
    try:
        proxy = candidate.resolve(strict=True)
        core = core_candidate.resolve(strict=True)
    except OSError:
        return None
    proxy_bundle = _bundle_for_executable(proxy)
    core_bundle = _bundle_for_executable(core)
    if proxy_bundle is None or proxy_bundle != core_bundle or proxy.parent != core.parent:
        return None

    proxy_team = _codesign_team(proxy)
    core_team = _codesign_team(core)
    bundle_team = _codesign_team(proxy_bundle)
    if (
        proxy_team is None
        or proxy_team == "not set"
        or proxy_team != core_team
        or proxy_team != bundle_team
    ):
        return None

    return (
        "/bin/sh",
        "-c",
        _DESKTOP_PROXY_LAUNCH_SCRIPT,
        "hol-guard-desktop-proxy",
        str(proxy),
        proxy_team,
        str(proxy_bundle),
        config_json,
        str(core),
    )


'''

pattern = re.compile(
    r'_DESKTOP_PROXY_LAUNCH_SCRIPT = r""".*?\n\ndef _assert_loopback_http_url',
    re.DOTALL,
)
bridge, count = pattern.subn(replacement + "def _assert_loopback_http_url", bridge, count=1)
if count != 1:
    raise SystemExit(f"expected one Desktop proxy implementation block, found {count}")
BRIDGE.write_text(bridge, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
new_tests = r'''def _signed_bundle_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    bundle = tmp_path / "HOL Guard.app"
    macos = bundle / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    proxy = macos / "HOL Guard"
    core = macos / "hol-guard"
    for path in (proxy, core):
        path.write_text("binary", encoding="utf-8")
        path.chmod(0o755)
    return bundle, proxy, core


def test_frozen_hook_command_prefers_runtime_verified_signed_macos_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setattr(bounded_cli_hook_bridge, "_codesign_team", lambda path: "TEAMID")

    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable=str(core),
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

    assert command[:4] == (
        "/bin/sh",
        "-c",
        bounded_cli_hook_bridge._DESKTOP_PROXY_LAUNCH_SCRIPT,
        "hol-guard-desktop-proxy",
    )
    assert command[4:7] == (str(proxy), "TEAMID", str(bundle))
    config = json.loads(command[7])
    assert config["python_executable"] == str(core)
    assert config["frozen_launcher"] is True
    assert command[8] == str(core)


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


def test_desktop_proxy_requires_one_real_team_and_same_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))

    for teams in (
        {proxy: None, core: None, proxy.parents[2]: None},
        {proxy: "not set", core: "not set", proxy.parents[2]: "not set"},
        {proxy: "TEAM-A", core: "TEAM-B", proxy.parents[2]: "TEAM-A"},
    ):
        monkeypatch.setattr(bounded_cli_hook_bridge, "_codesign_team", teams.get)
        assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None


def test_desktop_proxy_rejects_writable_or_cross_bundle_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    other_bundle, other_proxy, _other_core = _signed_bundle_fixture(tmp_path / "other")
    del other_bundle
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(bounded_cli_hook_bridge, "_codesign_team", lambda path: "TEAMID")

    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(other_proxy))
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None

    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    proxy.chmod(0o777)
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None


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


def test_macos_launcher_reverifies_normal_paths_and_falls_back_by_status() -> None:
    launcher = bounded_cli_hook_bridge._DESKTOP_PROXY_LAUNCH_SCRIPT
    assert "/dev/fd" not in launcher
    assert "HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE" not in launcher
    assert 'verify_team "$bundle"' in launcher
    assert 'verify_team "$proxy"' in launcher
    assert 'verify_team "$fallback"' in launcher
    assert '"$proxy" __guard-hook-proxy "$config"' in launcher
    assert 'if [ "$status" -eq 125 ]' in launcher
    assert 'exec "$fallback" __guard-bounded-hook "$config"' in launcher


'''

test_pattern = re.compile(
    r'def test_frozen_hook_command_prefers_fd_bound_signed_macos_proxy\(.*?\n\ndef test_frozen_fallback_runs_supported_cli_subcommand_without_python_flags',
    re.DOTALL,
)
tests, count = test_pattern.subn(
    new_tests + "def test_frozen_fallback_runs_supported_cli_subcommand_without_python_flags",
    tests,
    count=1,
)
if count != 1:
    raise SystemExit(f"expected one provisional Desktop proxy test block, found {count}")
TESTS.write_text(tests, encoding="utf-8")
