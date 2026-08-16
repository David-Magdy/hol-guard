# Unlisted CLI allow-list

Extensions already cover built-in tools such as Git, npm, and cloud CLIs. Agents also run tools that are not in that catalog: a local binary, or an interpreter launching a specific script.

Those unlisted CLIs appear on the Extensions page under **Other CLIs** after Guard sees them. From that page you can allow or block every matching command from that exact tool on this device.

## Local boundary

Allowing an unlisted CLI is a this-device setting. It does not require Guard Cloud and does not sync to other machines.

The grant binds to the tool's verified file identity. Changing the binary or script invalidates the allow. Compound commands, wrappers, redirects, and environment overrides are not covered. Built-in destructive floors still apply.

Interpreters themselves are never allow-listed as a whole. `python3 <skill-root>/scripts/cwv.py --by url` is the `cwv.py` CLI, not every Python command.

## Guard Cloud

Keeping the same unlisted CLI trusted across devices, teams, or organizations is a Cloud continuity feature. The local page says so and does not invent a free sync path.
