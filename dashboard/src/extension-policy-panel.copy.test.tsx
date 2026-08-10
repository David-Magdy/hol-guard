import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ExtensionPolicyPanel } from "./extension-policy-panel";
import { PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./protection-center/fixtures/protection-fixtures";

const extension = protectionModuleFixture({ extension_id: "command.git", name: "Git" });
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
assert.match(markup, /Balanced/);
assert.match(markup, /Strict local/);
assert.doesNotMatch(markup, /Blast radius before apply|Server semantic preview|Permission controls|Local policy draft/);
console.log("extension-policy-panel.copy.test.tsx: all assertions passed");
