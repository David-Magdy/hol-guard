import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { CloudValueGate } from "./protection-cloud-value";
import { FIXED_PROTECTION_MODULE } from "./fixtures/protection-fixtures";
import { ProtectionTestLab } from "./protection-test-lab";

const lab = renderToStaticMarkup(createElement(ProtectionTestLab, { extension: FIXED_PROTECTION_MODULE }));
assert.match(lab, /aria-labelledby="protection-test-lab-heading"/);
assert.match(lab, /id="protection-test-lab-heading"/);
assert.match(lab, /<label/);
assert.match(lab, /Command to check/);
assert.match(lab, /<textarea/);
assert.match(lab, /type="button"/);
assert.doesNotMatch(lab, /autofocus/i);

const cloud = renderToStaticMarkup(createElement(CloudValueGate, { runtime: null, loadFailed: true }));
assert.match(cloud, /aria-label="Cloud continuity"/);
assert.match(cloud, /data-local-protection-independent="true"/);

console.log("protection-final-a11y.test.tsx: all assertions passed");
