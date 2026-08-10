from pathlib import Path

path = Path("tests/test_guard_extension_control_authority.py")
text = path.read_text(encoding="utf-8")
path.write_text(text.rstrip() + "\n", encoding="utf-8")
