from pathlib import Path

path = Path("dashboard/e2e/installed-extension-control-center.spec.ts")
text = path.read_text(encoding="utf-8")

replacements = [
    (
        'await expect(page.getByText("Destructive Git reset", { exact: true })).toBeVisible();',
        'await expect(page.getByRole("table").getByText("Destructive Git reset", { exact: true })).toBeVisible();',
        "developer rule selector",
    ),
    (
        '  const appliedRow = page.locator(`[data-permission-id="${permissionId}"]`);\n  await expect(appliedRow.getByText("Blocked", { exact: true })).toBeVisible();',
        '  const appliedRow = await openPolicy(page);\n  await expect(appliedRow.getByText("Blocked", { exact: true })).toBeVisible();',
        "applied policy refresh",
    ),
    (
        '  const restoredRow = page.locator(`[data-permission-id="${permissionId}"]`);\n  await expect(restoredRow.getByText("Inherited", { exact: true })).toBeVisible();',
        '  const restoredRow = await openPolicy(page);\n  await expect(restoredRow.getByText("Inherited", { exact: true })).toBeVisible();',
        "restored policy refresh",
    ),
]

for old, new, label in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
