import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { protectionModuleFixture } from "./fixtures/protection-fixtures";
import { ProtectionTestLab } from "./protection-test-lab";
import { normalizeProtectionTestResult } from "./protection-test-api";

const markup = renderToStaticMarkup(createElement(ProtectionTestLab, {
  extension: protectionModuleFixture(),
}));
assert.match(markup, /Test Lab/);
assert.match(markup, /Nothing is executed/);
assert.match(markup, /evaluated locally in memory/);
assert.match(markup, /not saved to Activity or sent to Guard Cloud/);
assert.match(markup, /Check safely/);
assert.match(markup, /4096/);
assert.doesNotMatch(markup, /Run command|Execute command|Upload command/);

const normalized = normalizeProtectionTestResult({
  schema_version: "guard.daemon.extension-control-test.v1",
  decision: "blocked",
  minimum_action: "block",
  matched: true,
  module_matched: true,
  other_protection_matched: false,
  explanation: "A destructive source-control protection matched.",
  matches: [{
    extension_id: "command.git",
    extension_name: "Git",
    rule_id: "command.git.hard-reset",
    rule_title: "Destructive Git reset",
    description: "Protects destructive repository resets.",
    severity: "high",
    risk_classes: ["history-rewrite"],
  }],
  safer_alternatives: ["Create a checkpoint first."],
  authority_health: "protected",
  revision: 7,
  catalog_digest: "a".repeat(64),
});
assert.equal(normalized.decision, "blocked");
assert.equal(normalized.matches.length, 1);
assert.equal(normalized.matches[0]?.rule_title, "Destructive Git reset");

assert.throws(() => normalizeProtectionTestResult({
  schema_version: "guard.daemon.extension-control-test.v1",
  decision: "blocked",
  minimum_action: "block",
  matched: true,
  module_matched: true,
  other_protection_matched: false,
  explanation: "ok",
  matches: Array.from({ length: 33 }, () => ({})),
  safer_alternatives: [],
  authority_health: "protected",
  revision: 1,
  catalog_digest: "a".repeat(64),
}), /too many Test Lab matches/);

console.log("protection-test-lab.test.tsx: all assertions passed");