import { expect, test } from "@playwright/test";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const origin = requiredEnvironment("GUARD_INSTALLED_ORIGIN");
const session = requiredEnvironment("GUARD_INSTALLED_DASHBOARD_SESSION");

async function expectSecretSafeUrl(page: import("@playwright/test").Page) {
  expect(page.url()).not.toContain(session);
  expect(page.url()).not.toContain("guard-token");
  expect(page.url()).not.toContain("#");
}

test("installed dashboard drills into canonical extensions using the real daemon", async ({ page }, testInfo) => {
  const extensionResponses: { path: string; status: number }[] = [];
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/v1/extension-controls")) extensionResponses.push({ path: url.pathname, status: response.status() });
  });

  await page.addInitScript(({ daemon, token }) => {
    sessionStorage.setItem("guard-token", token);
    sessionStorage.setItem("guardDaemon", daemon);
  }, { daemon: origin, token: session });

  await page.goto("/extensions");
  await expectSecretSafeUrl(page);
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /^View .* details$/ }).first()).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-catalog.png"), fullPage: true });

  for (const extensionId of ["command.git", "command.github", "command.package.node"]) {
    await page.goto(`/extensions/${extensionId}`);
    await expectSecretSafeUrl(page);
    await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();
    await expect(page.locator("code", { hasText: extensionId }).first()).toBeVisible();
    await expect(page.getByText("Catalog digest")).toBeVisible();
    await page.getByRole("tab", { name: "Commands & rules" }).click();
    await expect(page.getByRole("heading", { name: "Permissions" })).toBeVisible();
    await expect(page.getByText(/Showing \d+ permissions and \d+ rules/)).toBeVisible();
  }

  await page.goto("/extensions/command.git?tab=commands&rule=command.git.hard-reset");
  await expectSecretSafeUrl(page);
  const ruleDialog = page.getByRole("dialog", { name: "Hard reset" });
  await expect(ruleDialog).toBeVisible();
  await expect(ruleDialog.getByText("high detector severity")).toBeVisible();
  await expect(ruleDialog.getByText("Governing permission")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-extension-rule-detail.png"), fullPage: true });
  await page.getByRole("button", { name: "Test this rule" }).click();
  await expect(page.getByRole("tab", { name: "Test Lab" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Side-effect-free command simulation is delivered in Batch 3.")).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("dialog", { name: "Hard reset" })).toBeVisible();
  await page.getByRole("button", { name: "Close rule details" }).click();
  await expect(page.getByRole("dialog", { name: "Hard reset" })).toHaveCount(0);

  await page.getByRole("button", { name: "Extensions" }).click();
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();

  await expect.poll(() => extensionResponses.length).toBeGreaterThan(1);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/catalog" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/effective" && response.status === 200)).toBe(true);
  expect(extensionResponses.every((response) => response.status >= 200 && response.status < 300)).toBe(true);
  expect(runtimeErrors).toEqual([]);
});
