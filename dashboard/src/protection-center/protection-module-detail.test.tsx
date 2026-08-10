import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  FIXED_PROTECTION_MODULE,
  FIXED_PROTECTION_PERMISSION,
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
  permission_count: 1,
  permissions: [{
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: "command.git.permission.history-rewrite",
    label: "Repository history changes",
    description: "Controls destructive repository history changes.",
    configurable: true,
    fixed_reason: null,
  }],
});

const simple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(simple, /Protection module/);
assert.match(simple, /What this protects/);
assert.match(simple, /Common examples/);
assert.match(simple, /Protection settings/);
assert.match(simple, /Why this setting\?/);
assert.match(simple, /Safer alternatives/);
assert.match(simple, /Recent decisions/);
assert.match(simple, /Change settings/);
assert.doesNotMatch(simple, /Catalog digest|Extension ID|Matcher|permission_id|rule_id/);

const requiredExtension = { ...FIXED_PROTECTION_MODULE, required: true };
const required = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: requiredExtension,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(required, /Required protection|cannot be turned off/);
assert.doesNotMatch(required, />Change settings</);

const fixedSettingSimple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: FIXED_PROTECTION_MODULE,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(fixedSettingSimple, /0 changeable settings/);

const managed = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(managed, /Managed by your organization/);
assert.match(managed, /Change settings/);

const lockdown = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.lockdown,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
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
  onRefresh: () => undefined,
}));
assert.ok(performance.now() - started < 500, "Simple module detail should not expand 500 Developer detections by default");

console.log("protection-module-detail.test.tsx: all assertions passed");
