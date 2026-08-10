import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ExtensionPolicyPanel } from "./extension-policy-panel";
import { PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./protection-center/fixtures/protection-fixtures";

const configurablePermission = {
  permission_id: "command.git.permission.history-rewrite",
  schema_version: 1 as const,
  extension_id: "command.git",
  implementation_version: "1.0.0",
  label: "Repository history changes",
  description: "Controls protection for commands that rewrite repository history.",
  risk_tier: "high" as const,
  baseline_floor: "review" as const,
  default_enabled: true,
  configurable: true,
  fixed_reason: null,
  typed_capabilities: [],
  action_classes: ["git.history.rewrite"],
  rule_ids: [],
  dependencies: [],
  conflicts: [],
  implied_permissions: [],
  introduced_version: "1.0.0",
  deprecated: false,
  replacement_permission_id: null,
  safer_guidance: ["Create a checkpoint before rewriting repository history."],
};

const extension = protectionModuleFixture({
  extension_id: "command.git",
  name: "Git",
  permission_count: 1,
  permissions: [configurablePermission],
});
const markup = renderToStaticMarkup(createElement(ExtensionPolicyPanel, {
  extension,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onRefresh: () => undefined,
}));
assert.match(markup, /Protection settings/);
assert.match(markup, /Use recommended/);
assert.match(markup, /Block matching actions/);
assert.match(markup, /Allow when Guard would otherwise permit/);
assert.match(markup, /Recommended/);
assert.match(markup, /Stricter/);
assert.match(markup, /Custom/);
assert.match(markup, /What will change|No local setting changes prepared/);
assert.doesNotMatch(markup, /Blast radius before apply|Server semantic preview|Permission controls|Local policy draft/);
console.log("extension-policy-panel.copy.test.tsx: all assertions passed");