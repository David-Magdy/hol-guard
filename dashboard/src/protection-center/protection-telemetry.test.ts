import assert from "node:assert/strict";

import { protectionTelemetryEnvelope, sanitizeProtectionTelemetry } from "./protection-telemetry";

const sanitized = sanitizeProtectionTelemetry({
  density: "Developer",
  plan_id: "solo",
  cloud_state: "paired_active",
  result: "blocked",
  category: "source-control",
  command: "curl https://example.invalid/?token=secret",
  path: "/Users/example/.ssh/id_rsa",
  proof_id: "proof-secret",
  rule_id: "command.git.hard-reset",
  extension_id: "command.git",
  token: "secret",
});
assert.deepEqual(sanitized, {
  density: "developer",
  plan_id: "solo",
  cloud_state: "paired_active",
  result: "blocked",
  category: "source-control",
});

const envelope = protectionTelemetryEnvelope("protection_test_lab_checked", {
  result: "ask-first",
  plan_id: "enterprise",
  raw_command: "never include me",
});
assert.equal(envelope.schema_version, "guard.protection-center.telemetry.v1");
assert.deepEqual(envelope.fields, { result: "ask-first", plan_id: "enterprise" });
assert.doesNotMatch(JSON.stringify(envelope), /never include me|raw_command|proof|token|path/);

assert.deepEqual(sanitizeProtectionTelemetry({ plan_id: "future-plan", density: "dense", cloud_state: "online", category: "customer-acme" }), {});

console.log("protection-telemetry.test.ts: all assertions passed");
