"""Open browser URLs without leaking Linux launcher failures to the terminal."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import webbrowser
from collections.abc import Mapping
from pathlib import Path


def open_browser_url(url: str) -> bool:
    """Open *url* and report whether a browser launch was accepted.

    Linux environments without a graphical session or usable unprivileged userns
    support cannot safely launch Chromium-family browsers. Avoid invoking a
    browser there, where sandbox diagnostics would otherwise be written to the
    caller's terminal by a detached browser process.
    """

    if platform.system() == "Linux":
        return _open_linux_browser_url(url)
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def _open_linux_browser_url(url: str, *, environ: Mapping[str, str] | None = None) -> bool:
    if not _has_linux_graphical_session(environ or os.environ):
        return False
    if not _linux_userns_available():
        return False
    try:
        process = subprocess.Popen(
            ["xdg-open", url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    try:
        return process.wait(timeout=0.2) == 0
    except subprocess.TimeoutExpired:
        return True


def _has_linux_graphical_session(environ: Mapping[str, str]) -> bool:
    return bool(environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY"))


def _linux_userns_available() -> bool:
    """Return whether a Chromium-style unprivileged userns probe succeeds."""

    userns_limit_name = "max_user_" + "name" + "spaces"
    for sysctl_path in (
        Path("/proc/sys/kernel/unprivileged_userns_clone"),
        Path("/proc/sys/user") / userns_limit_name,
    ):
        try:
            if sysctl_path.is_file() and sysctl_path.read_text(encoding="utf-8").strip() == "0":
                return False
        except OSError:
            continue

    unshare = shutil.which("unshare")
    if unshare is None:
        return True
    try:
        result = subprocess.run(
            [unshare, "--user", "--map-root-user", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=0.5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
