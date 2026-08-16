import assert from "node:assert/strict";

import { isLocalCliId, normalizeLocalCliItem, normalizeLocalCliList } from "./local-cli-api";
import { parseProtectionRoute, localCliHref } from "./local-cli-links";

assert.equal(isLocalCliId("local-cli.cwv-py-abcdef12"), true);
assert.equal(isLocalCliId("command.git"), false);

const item = normalizeLocalCliItem({
  cli_id: "local-cli.cwv-py-abcdef12",
  name: "cwv.py",
  kind: "script",
  identity_hash: "a".repeat(64),
  example_label: "python3 cwv.py",
  interpreter_name: "python3",
  observed_count: 3,
  last_seen_at: "2026-08-16T00:00:00Z",
  state: "allowed",
  stale: false,
  grant_revision: 1,
  authority_revision: 1,
});
assert.equal(item.name, "cwv.py");
assert.equal(item.state, "allowed");

const list = normalizeLocalCliList({
  schema_version: "guard.daemon.local-clis.v1",
  revision: 1,
  items: [item],
  cloud: { sync_local_only: true, summary: "This device only." },
});
assert.equal(list.items.length, 1);
assert.equal(list.cloud.sync_local_only, true);

assert.deepEqual(parseProtectionRoute("/extensions/local-cli/local-cli.cwv-py-abcdef12"), {
  kind: "local-cli",
  cliId: "local-cli.cwv-py-abcdef12",
});
assert.equal(parseProtectionRoute("/extensions/command.git").kind, "detail");
assert.equal(localCliHref("local-cli.cwv-py-abcdef12"), "/extensions/local-cli/local-cli.cwv-py-abcdef12");
