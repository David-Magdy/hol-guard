#!/usr/bin/env python3
"""Apply the final native proxy review assertions."""

from pathlib import Path

path = Path("tests/test_bounded_cli_hook_bridge.py")
text = path.read_text(encoding="utf-8")

old = '''    config = json.loads(command[7])
    assert config["python_executable"] == str(core)
    assert config["frozen_launcher"] is True
    assert command[8] == str(core)
'''
new = '''    config = json.loads(command[7])
    assert config == {
        "python_executable": str(core),
        "package_root": str(tmp_path.resolve()),
        "guard_home": str((tmp_path / "guard-home").resolve()),
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ],
        "harness": "grok",
        "timeout_seconds": 25,
        "frozen_launcher": True,
    }
    assert command[8] == str(core)
'''
if text.count(old) != 1:
    raise SystemExit("serialized proxy configuration assertion anchor changed")
text = text.replace(old, new, 1)

old = '''    assert 'if [ "$status" -eq 125 ]' in launcher
    assert 'exec "$fallback" __guard-bounded-hook "$config"' in launcher
'''
new = '''    assert 'if [ "$status" -eq 125 ]' in launcher
    assert '|| [ "$status" -eq 126 ]' in launcher
    assert '|| [ "$status" -eq 127 ]' in launcher
    assert 'exec "$fallback" __guard-bounded-hook "$config"' in launcher
'''
if text.count(old) != 1:
    raise SystemExit("launcher fallback status assertion anchor changed")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
