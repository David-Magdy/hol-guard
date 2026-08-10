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

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page) {
  const report = await page.evaluate(() => {
    const root = document.documentElement;
    const overflow = root.scrollWidth - root.clientWidth;
    const offenders = [...document.querySelectorAll<HTMLElement>("body *")]
      .map((element) => {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return {
          tag: element.tagName.toLowerCase(),
          className: typeof element.className === "string" ? element.className.slice(0, 180) : "",
          text: (element.innerText || "").replace(/\s+/g, " ").trim().slice(0, 100),
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          width: Math.round(rect.width),
          display: style.display,
          position: style.position,
        };
      })
      .filter((item) => item.display !== "none" && (item.right > root.clientWidth + 4 || item.left < -4))
      .sort((a, b) => Math.max(b.right - root.clientWidth, -b.left) - Math.max(a.right - root.clientWidth, -a.left))
      .slice(0, 12);
    return {
      overflow,
      clientWidth: root.clientWidth,
      scrollWidth: root.scrollWidth,
      innerWidth: window.innerWidth,
      outerWidth: window.outerWidth,
      screenWidth: window.screen.width,
      rootFontSize: getComputedStyle(root).fontSize,
      lgMatches: window.matchMedia("(min-width: 64rem)").matches,
      offenders,
    };
  });
  expect(report, JSON.stringify(report, null, 2)).toMatchObject({ overflow: expect.any(Number) });
  expect(report.overflow, JSON.stringify(report, null, 2)).toBeLessThanOrEqual(4);
}

async function selectDensity(page: import("@playwright/test").Page, density: "Simple" | "Advanced" | "Developer") {
  await page.getByRole("radio", { name: density }).click();
  await expect(page.getByRole("radio", { name: density })).toHaveAttribute("aria-checked", "true");
}

test("installed Protection Center keeps canonical routes and real-daemon inspection", async ({ page }, testInfo) => {
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
  await expect(page.getByRole("heading", { name: "Protection Center", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Protection modules" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What HOL Guard protects" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recent decisions" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Protection health check" })).toBeVisible();
  await expect(page.getByLabel("Cloud continuity")).toBeVisible();
  await expect(page.getByRole("heading", { name: /^(Protected|Finish setup|Needs repair|Protection limited|Emergency Lockdown active)$/ })).toBeVisible();

  const healthCheck = page.getByRole("button", { name: "Run health check" });
  await healthCheck.click();
  await expect(page.getByRole("status").filter({ hasText: /Protection health check passed|need attention/ })).toBeVisible();

  const advancedFilters = page.getByRole("button", { name: /Advanced filters/ });
  await expect(advancedFilters).toHaveAttribute("aria-expanded", "false");
  await advancedFilters.click();
  await expect(advancedFilters).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByPlaceholder(/Search by name, command, or risk/)).toBeVisible();

  const setupSteps = page.getByRole("button", { name: "Show setup steps" });
  if (await setupSteps.count()) {
    await setupSteps.click();
    await expect(page.getByText("Finish local enrollment", { exact: true })).toBeVisible();
  }

  await selectDensity(page, "Simple");
  await page.screenshot({ path: testInfo.outputPath("installed-extension-catalog.png"), fullPage: true });
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-simple.png"), fullPage: false });
  await selectDensity(page, "Advanced");
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-advanced.png"), fullPage: false });
  await selectDensity(page, "Developer");
  await expect(page.getByText("Developer policy details")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-protection-center-developer.png"), fullPage: false });
  await selectDensity(page, "Simple");

  for (const width of [320, 390, 720, 800, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    // The shell deliberately animates desktop sidebar padding. Validate the
    // settled responsive layout rather than sampling that 200 ms transition.
    await page.waitForTimeout(250);
    await expect(page.getByRole("heading", { name: "Protection Center", exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    const screenshotName = width === 720
      ? "installed-protection-center-simple-zoom-200.png"
      : `installed-protection-center-simple-${width}.png`;
    await page.screenshot({ path: testInfo.outputPath(screenshotName), fullPage: false });
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.waitForTimeout(250);

  for (const extensionId of ["command.git", "command.github", "command.package.node"]) {
    await page.goto(`/extensions/${extensionId}`);
    await expectSecretSafeUrl(page);
    await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();
    await expect(page.locator("code", { hasText: extensionId }).first()).toBeVisible();
    await page.getByRole("tab", { name: "Commands & rules" }).click();
    await expect(page.getByRole("heading", { name: "Permissions" })).toBeVisible();
    await expect(page.getByText(/Showing \d+ permissions and \d+ rules/)).toBeVisible();
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

  await page.getByRole("button", { name: "Protections" }).click();
  await expect(page.getByRole("heading", { name: "Protection Center", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("extension-control-center-detail")).toBeVisible();

  await expect.poll(() => extensionResponses.length).toBeGreaterThan(1);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/catalog" && response.status === 200)).toBe(true);
  expect(extensionResponses.some((response) => response.path === "/v1/extension-controls/effective" && response.status === 200)).toBe(true);
  expect(extensionResponses.every((response) => response.status >= 200 && response.status < 300)).toBe(true);
  expect(runtimeErrors).toEqual([]);
});
