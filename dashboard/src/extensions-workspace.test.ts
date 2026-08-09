import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ApprovalProofModal } from "./approval-proof-modal";
import {
  canonicalExtensionId,
  extensionDetailHref,
  extensionEffectiveState,
  extensionIdFromSearch,
  permissionEffectiveState,
  permissionForRule,
  permissionRelations,
  treatmentLabel,
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
      controls: [{ target_kind: "extension" as const, target_id: "existing", state: "disabled" as const }],
    }],
  },
};
const targeted = buildExtensionMutation(mutationState, {
  extension: { extension_id: "new-extension", name: "New extension" }, enabled: false,
});
assert.equal(targeted.previous_revision, 8);
assert.deepEqual(targeted.layers[0]?.controls.map((control) => control.target_id), ["existing", "new-extension"]);
assert.equal(mutationState.effective.layers[0]?.controls.length, 1, "builder must not mutate loaded authority state");

const extension: ExtensionCatalogItem = {
  schema_version: 2, extension_id: "command.git", name: "Git", description: "Protects source-control commands.",
  enabled: true, required: false, source: "built-in", version: "1.2.3", aliases: ["command.scm"],
  dependencies: [], conflicts: [], delegated_protection: null, ecosystem_ids: ["git"], executables: ["git"],
  project_markers: [".git"], reference_urls: [], action_classes: ["git.history.rewrite"],
  risk_classes: ["history-rewrite"], safer_alternatives: [], rule_count: 1,
  rules: [{
    rule_id: "command.git.reset-hard", rule_version: 1, title: "Hard reset",
    description: "Rewrites the worktree and index.", severity: "high", risk_classes: ["history-rewrite"],
    action_classes: ["git.history.rewrite"], safer_alternatives: [], default_mode: "review",
    matcher_kind: "ExecutableMatcher", safe_variants: [], compatibility_fallback: false,
  }],
  permission_count: 2,
  permissions: [
    {
      permission_id: "command.git.permission.reset-hard", schema_version: 1, extension_id: "command.git",
      implementation_version: "1.2.3", label: "Hard reset", description: "Controls destructive reset behavior.",
      risk_tier: "high", baseline_floor: "review", default_enabled: true, configurable: true, fixed_reason: null,
      typed_capabilities: [], action_classes: ["git.history.rewrite"], rule_ids: ["command.git.reset-hard"],
      dependencies: ["command.git.permission.read"], conflicts: [], implied_permissions: ["command.git.permission.read"],
      introduced_version: "2.2.0", deprecated: false, replacement_permission_id: null, safer_guidance: [],
    },
    {
      permission_id: "command.git.permission.read", schema_version: 1, extension_id: "command.git",
      implementation_version: "1.2.3", label: "Read repository", description: "Read-only repository inspection.",
      risk_tier: "low", baseline_floor: "allow", default_enabled: true, configurable: true, fixed_reason: null,
      typed_capabilities: [], action_classes: [], rule_ids: [], dependencies: [], conflicts: [], implied_permissions: [],
      introduced_version: "2.2.0", deprecated: false, replacement_permission_id: null, safer_guidance: [],
    },
  ],
};
const effective: EffectiveExtensionControls = {
  schema_version: "1.0.0", health: "protected", revision: 7, catalog_digest: "a".repeat(64),
  global_lockdown: false,
  controls: [{ target: { kind: "permission", target_id: "command.git.permission.reset-hard" }, state: "disabled" }],
  layers: [], failures: [],
};
assert.equal(extensionIdFromSearch("?extension=command.git"), "command.git");
assert.equal(extensionDetailHref("command.git"), "/extensions?extension=command.git");
assert.doesNotMatch(extensionDetailHref("command.git"), /#/);
assert.equal(canonicalExtensionId([extension], "command.scm"), "command.git");
assert.equal(extensionEffectiveState(effective, extension), "enabled");
assert.equal(isExtensionEnabled(effective, extension), true);
assert.equal(permissionEffectiveState(effective, extension, extension.permissions[0]!), "disabled");
assert.equal(permissionForRule(extension, extension.rules[0]!)?.permission_id, "command.git.permission.reset-hard");
assert.deepEqual(permissionRelations(extension, extension.permissions[0]!).dependencies.map((item) => item.permission_id), ["command.git.permission.read"]);
assert.equal(treatmentLabel("sandbox-required"), "Require sandbox");

const lockedDown = { ...effective, global_lockdown: true };
assert.equal(extensionEffectiveState(lockedDown, extension), "disabled");
assert.equal(isExtensionEnabled(lockedDown, extension), false);
const unavailable = { ...effective, health: "tampered" as const };
assert.equal(extensionEffectiveState(unavailable, extension), "disabled");
const requiredExtension = { ...extension, required: true };
assert.equal(extensionEffectiveState(lockedDown, requiredExtension), "disabled", "global lockdown must short-circuit required extensions too");
assert.equal(extension.risk_classes[0], "history-rewrite", "inspection helpers must not rewrite baseline risk metadata");
