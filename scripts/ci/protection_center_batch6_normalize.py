from pathlib import Path

path = Path("dashboard/src/protection-center/protection-final-contract.test.ts")
text = path.read_text(encoding="utf-8")
old = 'assert.doesNotMatch(telemetry, /ALLOWED_FIELDS.*command/s);'
new = '''const allowedFields = telemetry.match(/const ALLOWED_FIELDS = new Set\\(\\[([\\s\\S]*?)\\]\\);/)?.[1] ?? "";
for (const forbidden of ["command", "path", "proof_id", "rule_id", "extension_id", "token"]) {
  assert.equal(allowedFields.includes(`"${forbidden}"`), false);
}'''
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit("final telemetry architecture assertion marker changed")
path.write_text(text, encoding="utf-8")
