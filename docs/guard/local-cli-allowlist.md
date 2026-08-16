# Custom extensions

Extensions already cover built-in tools such as Git, npm, and cloud CLIs. Agents also run tools that are not in that catalog: a local binary, or an interpreter launching a specific script.

On the Extensions page, choose **Add custom extension**. Guard lists CLIs it has already seen on this device. Adding one turns that exact tool into a custom extension so you can allow or block its matching commands.

## Local boundary

A custom extension is a this-device setting. It does not require Guard Cloud and does not sync to other machines.

The extension binds to the tool's verified file identity. Changing the binary or script means you review it again. Compound commands, wrappers, redirects, and environment overrides are not covered. Built-in destructive floors still apply.

Interpreters themselves are never added as a whole. `python3 <skill-root>/scripts/cwv.py --by url` becomes a `cwv.py` custom extension, not every Python command.

## Guard Cloud

Keeping the same custom extension on other devices, teams, or organizations is a Cloud continuity feature. Adding the extension locally does not invent a free sync path.
