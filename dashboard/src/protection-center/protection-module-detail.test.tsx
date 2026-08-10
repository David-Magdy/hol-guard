import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  FIXED_PROTECTION_MODULE,
  PROTECTION_AUTHORITY_FIXTURES,
  largeDeveloperModuleFixture,
  protectionModuleFixture,
} from "./fixtures/protection-fixtures";

const git = protectionModuleFixture({
  extension_id: "command.git",
  name: "Git",
  description: "Protects repository history and destructive source-control actions.",
  ecosystem_ids: ["git"],
  executables: ["git"],
  safer_alternatives: ["Create a checkpoint before rewriting history."],
});

const simple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onChange: () => undefined,
}));
assert.match(simple, /Protection module/);
assert.match(simple, /What this protects/);
assert.match(simple, /Common examples/);
assert.match(simple, /Protection settings/);
assert.match(simple, /Why this setting\?/);
assert.match(simple, /Safer alternatives/);
assert.match(simple, /Recent decisions/);
assert.match(simple, /Change protection/);
assert.doesNotMatch(simple, /Catalog digest|Extension ID|Matcher|permission_id|rule_id/);

const required = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: FIXED_PROTECTION_MODULE,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onChange: () => undefined,
}));
assert.match(required, /Required by Guard|cannot be turned off|Fixed/);

const managed = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onChange: () => undefined,
}));
assert.match(managed, /Managed by your organization/);
assert.doesNotMatch(managed, />Change protection</);

const lockdown = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.lockdown,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
}));
assert.match(lockdown, /Emergency Lockdown currently controls this module/);

const large = largeDeveloperModuleFixture(500);
assert.equal(large.rules.length, 500);
const started = performance.now();
renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: large,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
}));
assert.ok(performance.now() - started < 500, "Simple module detail should not expand 500 Developer detections by default");

console.log("protection-module-detail.test.tsx: all assertions passed");
