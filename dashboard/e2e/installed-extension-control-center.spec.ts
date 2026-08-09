import { expect, test } from "@playwright/test";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const origin = requiredEnvironment("GUARD_INSTALLED_ORIGIN");
const session = requiredEnvironment("GUARD_INSTALLED_DASHBOARD_SESSION");

test("installed dashboard exposes extension permission and rule inspection from the real daemon", async ({ page }, testInfo) => {
  const extensionResponses: { path: string; status: number }[] = [];
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/v1/extension-controls")) {
      extensionResponses.push({ path: url.pathname, status: response.status() });
    }
  });

  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });

  await page.goto("/extensions");
  expect(page.url()).not.toContain(session);
  expect(page.url()).not.toContain("guard-token");
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Open .* controls$/ }).first()).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-catalog.png"), fullPage: true });

  await page.getByRole("button", { name: /^Open .* controls$/ }).first().click();
  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();
  await expect(page).toHaveURL(/\/extensions\?extension=command\./);
  await expect(page.getByText("Baseline and effective behavior")).toHaveCount(0);
  await expect(page.getByText("Detector severity and permission baseline floors are immutable metadata here.")).toBeVisible();

  await page.getByRole("tab", { name: "Permissions" }).click();
  await expect(page.getByRole("heading", { name: "Permission inventory" })).toBeVisible();
  const permissionRows = page.getByRole("button").filter({ has: page.locator("code") });
  await expect(permissionRows.first()).toBeVisible();
  await permissionRows.first().click();
  const permissionInspector = page.getByRole("dialog", { name: /.+/ });
  await expect(permissionInspector.getByText("Baseline and effective behavior")).toBeVisible();
  await expect(permissionInspector.getByText("Baseline floor")).toBeVisible();
  await expect(permissionInspector.getByText("Effective state")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-permission-detail.png"), fullPage: true });
  await permissionInspector.getByRole("button", { name: "Close permission details" }).click();

  await page.getByRole("tab", { name: "Rules" }).click();
  await expect(page.getByRole("heading", { name: "Rule inventory" })).toBeVisible();
  const ruleButtons = page.getByRole("button").filter({ has: page.locator("code") });
  if (await ruleButtons.count()) {
    await ruleButtons.first().click();
    await expect(page.getByRole("dialog").getByText(/detector severity/)).toBeVisible();
    await page.getByRole("button", { name: "Close rule details" }).click();
  }

  await page.getByRole("button", { name: "All extensions" }).click();
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();

  await expect.poll(() => extensionResponses.length).toBeGreaterThan(1);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/catalog" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/effective" && response.status === 200)).toBe(true);
  expect(extensionResponses.every((response) => response.status >= 200 && response.status < 300)).toBe(true);
});