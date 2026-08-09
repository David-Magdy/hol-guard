import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ApprovalProofModal } from "./approval-proof-modal";
import {
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  extensionEffectiveState,
  permissionEffectiveState,
} from "./extension-control-center-model";
import { ExtensionControlApiError, type ExtensionCatalogItem, type EffectiveExtensionControls } from "./extension-controls-api";
import {
  buildExtensionMutation,
  ExtensionStatusBanner,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval,
} from "./extensions-workspace";
import { isExtensionEnabled } from "./extensions-filters";

assert.equal(extensionRecoveryAction("protected"), null);
assert.deepEqual(extensionRecoveryAction("recovery-required"), extensionRecoveryAction("tampered"));
assert.equal(requiresExtensionRecoveryApproval(new ExtensionControlApiError("approval_gate_required", 403, "approval_gate_required")), true);
assert.equal(requiresExtensionRecoveryApproval(new ExtensionControlApiError("authority_not_recoverable", 409, "authority_not_recoverable")), false);

const recoveryMarkup = renderToStaticMarkup(createElement(ExtensionStatusBanner, {
  effective: {
    schema_version: "1.0.0", health: "tampered", revision: 4, catalog_digest: "a".repeat(64),
    global_lockdown: false, controls: [], failures: [{ code: "anchor_mismatch" }], layers: [],
  },
  onRecover: () => undefined,
  onRetry: () => undefined,
}));
assert.match(recoveryMarkup, /hol-guard command controls recover-authority/);
assert.match(recoveryMarkup, /Repair now/);
assert.match(recoveryMarkup, /Check again/);

const totpRecoveryMarkup = renderToStaticMarkup(createElement(ApprovalProofModal, {
  title: "Repair extension controls",
  detail: "Authenticate this repair on your device.",
  confirmLabel: "Repair controls",
  approvalGate: {
    enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: true,
    strict_all_decisions: false, totp_enabled: true,
  },
  error: "That authenticator code was not accepted.",
  onCancel: () => undefined,
  onConfirm: () => undefined,
}));
assert.match(totpRecoveryMarkup, /Authenticator code/);
assert.doesNotMatch(totpRecoveryMarkup, /Approval password/);

const mutationState = {
  kind: "ready" as const,
  catalog: { schema_version: "1.0.0", catalog_digest: "a".repeat(64), extensions: [] },
  effective: {
    schema_version: "1.0.0", health: "protected" as const, revision: 8,
    catalog_digest: "a".repeat(64), global_lockdown: false, controls: [], failures: [],
    layers: [{
      schema_version: "1.0.0", kind: "local-admin" as const, catalog_digest: "a".repeat(64),
      global_lockdown: false,
      controls: [{ target_kind: "extension" as const, target_id: "command.existing", state: "disabled" as const }],
    }],
  },
};
const targeted = buildExtensionMutation(mutationState, {
  extension: { extension_id: "command.new-extension", name: "New extension" }, enabled: false,
});
assert.equal(targeted.previous_revision, 8);
assert.deepEqual(targeted.layers[0]?.controls.map((control) => control.target_id), ["command.existing", "command.new-extension"]);
assert.equal(mutationState.effective.layers[0]?.controls.length, 1, "builder must not mutate loaded authority state");

const extension: ExtensionCatalogItem = {
  schema_version: 2, extension_id: "command.git", name: "Git", description: "Protects source-control commands.",
  enabled: true, required: false, source: "built-in", version: "1.2.3", aliases: ["command.scm"],
  dependencies: [], conflicts: [], delegated_protection: null, ecosystem_ids: ["git"], executables: ["git"],
  project_markers: [".git"], reference_urls: [], action_classes: ["git.history.rewrite"],
  risk_classes: ["history-rewrite"], safer_alternatives: [], rule_count: 1,
  rules: [{
    rule_id: "command.git.hard-reset", rule_version: 1, title: "Hard reset",
    description: "Rewrites the worktree and index.", severity: "high", risk_classes: ["history-rewrite"],
    action_classes: ["git.history.rewrite"], safer_alternatives: [], default_mode: "review",
    matcher_kind: "ExecutableMatcher", safe_variants: [], compatibility_fallback: false,
  }],
  permission_count: 1,
  permissions: [{
    permission_id: "command.git.permission.hard-reset", schema_version: 1, extension_id: "command.git",
    implementation_version: "1.2.3", label: "Hard reset", description: "Controls destructive reset behavior.",
    risk_tier: "high", baseline_floor: "review", default_enabled: true, configurable: true, fixed_reason: null,
    typed_capabilities: [], action_classes: ["git.history.rewrite"], rule_ids: ["command.git.hard-reset"],
    dependencies: [], conflicts: [], implied_permissions: [], introduced_version: "1.0.0",
    deprecated: false, replacement_permission_id: null, safer_guidance: [],
  }],
};
const effective: EffectiveExtensionControls = {
  schema_version: "1.0.0", health: "protected", revision: 7, catalog_digest: "a".repeat(64),
  global_lockdown: false,
  controls: [{ target: { kind: "permission", target_id: "command.git.permission.hard-reset" }, state: "disabled" }],
  layers: [], failures: [],
};
assert.equal(extensionDetailHref("command.git"), "/extensions/command.git");
assert.equal(extensionDetailHref("command.git", { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "commands", ruleId: "command.git.hard-reset" }), "/extensions/command.git?tab=commands&rule=command.git.hard-reset");
assert.doesNotMatch(extensionDetailHref("command.git"), /#|guard-token/);
assert.equal(extensionEffectiveState(effective, extension), "enabled");
assert.equal(isExtensionEnabled(effective, extension), true);
assert.equal(permissionEffectiveState(effective, extension, extension.permissions[0]!), "disabled");
assert.equal(extensionEffectiveState({ ...effective, global_lockdown: true }, { ...extension, required: true }), "disabled");
assert.equal(extensionEffectiveState({ ...effective, health: "tampered" }, extension), "disabled");

console.log("extensions-workspace.test.ts: all assertions passed");
