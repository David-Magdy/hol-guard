from __future__ import annotations

from pathlib import Path


WORKSPACE = Path("dashboard/src/protection-center/protection-center-workspace.tsx")
E2E = Path("dashboard/e2e/installed-extension-control-center.spec.ts")


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    return text.replace(old, new, 1)


def update_workspace() -> None:
    text = WORKSPACE.read_text(encoding="utf-8")
    old = '<ProtectionModuleDetail extension={selectedExtension} effective={state.effective} catalogDigest={state.catalog.catalog_digest} onBack={closeExtension} onChange={() => requestChange({ extension: selectedExtension, enabled: !isExtensionEnabled(state.effective, selectedExtension) })} />'
    new = '<ProtectionModuleDetail extension={selectedExtension} effective={state.effective} catalogDigest={state.catalog.catalog_digest} onBack={closeExtension} onRefresh={load} />'
    text = replace_once(text, old, new, label="module-detail workspace")
    WORKSPACE.write_text(text, encoding="utf-8")


def update_e2e() -> None:
    text = E2E.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();\n  await expect(page.getByRole("heading", { name: "Permission controls" })).toBeVisible();',
        '  await expect(page.getByTestId("protection-module-detail")).toBeVisible();\n  await page.getByRole("button", { name: "Change settings" }).click();\n  await expect(page.getByRole("heading", { name: "Permission controls" })).toBeVisible();',
        label="openPolicy detail surface",
    )
    old_inspection = '''  for (const extensionId of ["command.git", "command.github", "command.package.node"]) {
    await page.goto(`/extensions/${extensionId}`);
    await expectSecretSafeUrl(page);
    await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();
    await expect(page.locator("code", { hasText: extensionId }).first()).toBeVisible();
    await page.getByRole("tab", { name: "Commands & rules" }).click();
    await expect(page.getByRole("heading", { name: "Permissions" })).toBeVisible();
    await expect(page.getByText(/Showing \\d+ permissions and \\d+ rules/)).toBeVisible();
    await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: "Activity" })).toHaveCount(0);
  }

  await page.goto("/extensions/command.git?tab=commands&rule=command.git.hard-reset");
  await expectSecretSafeUrl(page);
  const ruleDialog = page.getByRole("dialog", { name: "Destructive Git reset" });
  await expect(ruleDialog).toBeVisible();
  await expect(ruleDialog.getByText("high detector severity")).toBeVisible();
  await expect(ruleDialog.getByText("Governing permission")).toBeVisible();
  await expect(ruleDialog.getByRole("button", { name: "Test this rule" })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("installed-extension-rule-detail.png"), fullPage: true });
  await page.getByRole("button", { name: "Close rule details" }).click();
  await expect(page.getByRole("dialog", { name: "Destructive Git reset" })).toHaveCount(0);
'''
    new_inspection = '''  for (const moduleId of ["command.git", "command.github", "command.package.node"]) {
    await page.goto(`/extensions/${moduleId}`);
    await expectSecretSafeUrl(page);
    await expect(page.getByTestId("protection-module-detail")).toBeVisible();
    await selectDensity(page, "Developer");
    await page.getByText("Developer details", { exact: true }).click();
    await expect(page.locator("code", { hasText: moduleId }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Protection setting identifiers" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: "Activity" })).toHaveCount(0);
  }

  await page.goto("/extensions/command.git");
  await expectSecretSafeUrl(page);
  await selectDensity(page, "Developer");
  await page.getByText("Developer details", { exact: true }).click();
  await expect(page.getByText("Destructive Git reset", { exact: true })).toBeVisible();
  await expect(page.getByText("command.git.hard-reset", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-rule-detail.png"), fullPage: true });
'''
    text = replace_once(text, old_inspection, new_inspection, label="developer inspection")
    text = replace_once(
        text,
        '  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();\n\n  await expect.poll',
        '  await expect(page.getByTestId("protection-module-detail")).toBeVisible();\n\n  await expect.poll',
        label="history back navigation",
    )
    E2E.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    update_workspace()
    update_e2e()
