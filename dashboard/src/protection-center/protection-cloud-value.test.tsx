import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { GuardRuntimeSnapshot } from "../guard-types";
import { CloudValueGate, protectionCloudDestination, protectionCloudPlan, protectionCloudValue } from "./protection-cloud-value";

function runtime(overrides: Partial<GuardRuntimeSnapshot> = {}): GuardRuntimeSnapshot {
  return {
    generated_at: "2026-08-10T00:00:00Z",
    approval_center_url: null,
    runtime_state: null,
    device: { installation_id: "device", device_label: "Device", local_registered: true },
    latest_connect_state: null,
    proof_status: { state: "not_connected", label: "Not connected", detail: "", request_id: null, pairing_completed_at: null, first_synced_at: null, receipts_stored: 0, inventory_items: 0, runtime_session_id: null, runtime_session_synced_at: null },
    pending_count: 0,
    receipt_count: 0,
    headline_state: "protected",
    headline_label: "Protected",
    headline_detail: "",
    sync_configured: false,
    cloud_state: "local_only",
    cloud_state_label: "Local only",
    cloud_state_detail: "",
    cloud_pairing_state: { state: "local_only", label: "Local only", detail: "", sync_configured: false, plan_id: null, dashboard_url: "", inbox_url: "", fleet_url: "", connect_url: "" },
    cloud_sync_health: { state: "disabled", label: "Disabled", detail: "", pending_events: 0, last_synced_at: null, next_retry_after: null },
    dashboard_url: "",
    inbox_url: "",
    fleet_url: "",
    connect_url: "",
    items: [],
    latest_receipts: [],
    ...overrides,
  };
}

const localOnly = runtime({ connect_url: "https://hol.org/guard/connect" });
assert.equal(protectionCloudPlan(localOnly), null);
assert.equal(protectionCloudValue(localOnly).state, "optional");
assert.match(protectionCloudValue(localOnly).detail, /Local protection is active/);
assert.equal(protectionCloudDestination(localOnly), "https://hol.org/guard/connect");

const offline = protectionCloudValue(null, true);
assert.equal(offline.state, "offline");
assert.match(offline.detail, /Local protection is active independently/);

const solo = runtime({
  sync_configured: true,
  cloud_state: "paired_active",
  dashboard_url: "https://hol.org/guard/dashboard",
  cloud_pairing_state: { state: "paired_active", label: "Connected", detail: "", sync_configured: true, plan_id: "solo", dashboard_url: "https://hol.org/guard/dashboard", inbox_url: "", fleet_url: "", connect_url: "" },
});
assert.equal(protectionCloudPlan(solo), "solo");
assert.match(protectionCloudValue(solo).detail, /cross-device continuity/);
assert.match(protectionCloudValue(solo).detail, /run locally/);
assert.equal(protectionCloudDestination(solo), "https://hol.org/guard/dashboard");

const enterprise = runtime({
  sync_configured: true,
  cloud_state: "paired_active",
  cloud_pairing_state: { state: "paired_active", label: "Connected", detail: "", sync_configured: true, plan_id: "enterprise", dashboard_url: "", inbox_url: "", fleet_url: "", connect_url: "" },
});
assert.match(protectionCloudValue(enterprise).detail, /organization policy/);
assert.match(protectionCloudValue(enterprise).detail, /enforcing locally/);

const unknown = runtime({
  sync_configured: true,
  cloud_state: "paired_active",
  cloud_pairing_state: { state: "paired_active", label: "Connected", detail: "", sync_configured: true, plan_id: "future-plan", dashboard_url: "", inbox_url: "", fleet_url: "", connect_url: "" },
});
assert.equal(protectionCloudPlan(unknown), null);
assert.doesNotMatch(protectionCloudValue(unknown).detail, /device limit|retention|storage/);

const unsafe = runtime({ connect_url: "javascript:alert(1)" });
assert.equal(protectionCloudDestination(unsafe), null);

const html = renderToStaticMarkup(createElement(CloudValueGate, { runtime: localOnly, eligiblePlan: "solo" }));
assert.match(html, /data-local-protection-independent="true"/);
assert.match(html, /data-cloud-value-state="optional"/);
assert.match(html, /Cloud continuity is optional/);
assert.match(html, /Available on Solo Cloud/);
assert.match(html, /href="https:\/\/hol\.org\/guard\/connect"/);
assert.match(html, /Hide Cloud continuity/);
assert.doesNotMatch(html, /upgrade required|local protection disabled/i);

const unsafeHtml = renderToStaticMarkup(createElement(CloudValueGate, { runtime: unsafe, destination: "javascript:alert(1)" }));
assert.doesNotMatch(unsafeHtml, /href=/);
assert.doesNotMatch(unsafeHtml, /javascript:/);

console.log("protection-cloud-value.test.tsx: all assertions passed");
