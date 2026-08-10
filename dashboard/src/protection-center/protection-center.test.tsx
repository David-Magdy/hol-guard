import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { assertSimpleCopySafe, localSettingChoiceLabel, PROTECTION_TERMS, simpleCopyViolations } from "./copy/protection-copy";
import { ProtectionDensityControl, ProtectionModuleRow, ProtectionStatusHero, TechnicalDetails } from "./components/protection-primitives";
import { PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./fixtures/protection-fixtures";
import { groupProtectionModules, protectionCategoryIdForExtension } from "./model/protection-categories";
import { deriveProtectionStatus, parseProtectionDensity, readProtectionDensity, writeProtectionDensity } from "./model/protection-presentation";

assert.equal(PROTECTION_TERMS.navigation, "Protections");
assert.equal(PROTECTION_TERMS.pageTitle, "Protection Center");
assert.equal(localSettingChoiceLabel("inherit"), "Recommended");
assert.equal(localSettingChoiceLabel("allow"), "Permit when Guard considers it safe");
assert.equal(localSettingChoiceLabel("block"), "Always block matching actions");

assert.deepEqual(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.protected), {
  status: "protected",
  title: "Protected",
  summary: "Guard is actively applying the trusted protection settings on this device.",
  tone: "safe",
  primaryAction: "none",
  primaryActionLabel: null,
});
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.unenrolled).primaryAction, "finish-setup");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.tampered).primaryAction, "repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.recoveryRequired).primaryAction, "repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.degradedUnacknowledged).status, "limited");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.degradedAcknowledged).primaryAction, "retry-repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.lockdown).status, "lockdown");

assert.equal(parseProtectionDensity("developer"), "developer");
assert.equal(parseProtectionDensity("unexpected"), "simple");
let stored = "advanced";
const fakeStorage = {
  getItem: () => stored,
  setItem: (_key: string, value: string) => { stored = value; },
};
assert.equal(readProtectionDensity(fakeStorage), "advanced");
writeProtectionDensity("developer", fakeStorage);
assert.equal(stored, "developer");

const categoryFixtures = [
  ["command.git", "source-control"],
  ["command.npm", "packages"],
  ["command.aws", "cloud-infrastructure"],
  ["command.postgres", "data-databases"],
  ["command.curl", "network-downloads"],
  ["command.github-actions", "source-control"],
  ["command.slack", "messaging-collaboration"],
  ["command.mcp", "ai-workflows"],
  ["command.unknown-shell", "system-shell"],
] as const;
for (const [id, category] of categoryFixtures) {
  assert.equal(protectionCategoryIdForExtension(protectionModuleFixture({ extension_id: id, name: id })), category);
}
const grouped = groupProtectionModules([
  protectionModuleFixture({ extension_id: "command.git", name: "Git" }),
  protectionModuleFixture({ extension_id: "command.npm", name: "npm" }),
]);
assert.equal(grouped.get("source-control")?.length, 1);
assert.equal(grouped.get("packages")?.length, 1);

assert.deepEqual(simpleCopyViolations("Protection is active on this device."), []);
assert.deepEqual(simpleCopyViolations("Catalog digest is hidden here."), ["catalog digest"]);
assert.doesNotThrow(() => assertSimpleCopySafe("Guard is protecting source control on this device."));
assert.throws(() => assertSimpleCopySafe("The semantic blast radius changed."), /semantic blast radius/);

const hero = renderToStaticMarkup(createElement(ProtectionStatusHero, { status: deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.protected) }));
assert.match(hero, /Local protection/);
assert.match(hero, /Protected/);
assert.match(hero, /No action required/);
assert.doesNotMatch(hero, /revision|catalog digest|authority/);

const moduleRow = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  name: "Git",
  description: "Protects source-control history.",
  behavior: "Ask first",
  onOpen: () => undefined,
}));
assert.match(moduleRow, /Git/);
assert.match(moduleRow, /Ask first/);
assert.doesNotMatch(moduleRow, /permission|rule|version/);

const density = renderToStaticMarkup(createElement(ProtectionDensityControl, { value: "simple", onChange: () => undefined }));
assert.match(density, /role="radiogroup"/);
assert.match(density, /aria-checked="true"/);
assert.match(density, />Developer</);

const technical = renderToStaticMarkup(createElement(TechnicalDetails, { children: createElement("code", null, "command.git") }));
assert.match(technical, /<details/);
assert.doesNotMatch(technical, / open/);

console.log("protection-center.test.tsx: all assertions passed");
