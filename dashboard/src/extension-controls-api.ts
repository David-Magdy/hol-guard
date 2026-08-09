import { fetchExtensionControlApi } from "./guard-api";

export type ExtensionControlState = "enabled" | "disabled";
export type GuardTreatment = "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block";
export type ExtensionRiskTier = "low" | "medium" | "high" | "critical";
export type ExtensionRuleMode = "required" | "enforce" | "review" | "monitor" | "disabled";

export type ExtensionRuleSafeVariant = {
  variant_id: string;
  title: string;
  matcher_kind: string;
};

export type ExtensionRule = {
  rule_id: string;
  rule_version: number | string;
  title: string;
  description: string;
  severity: ExtensionRiskTier;
  risk_classes: string[];
  action_classes: string[];
  safer_alternatives: string[];
  default_mode: ExtensionRuleMode;
  matcher_kind: string;
  safe_variants: ExtensionRuleSafeVariant[];
  compatibility_fallback: boolean;
};

export type ExtensionPermission = {
  permission_id: string;
  schema_version: number;
  extension_id: string;
  implementation_version: string;
  label: string;
  description: string;
  risk_tier: ExtensionRiskTier;
  baseline_floor: GuardTreatment;
  default_enabled: boolean;
  configurable: boolean;
  fixed_reason: string | null;
  typed_capabilities: string[];
  action_classes: string[];
  rule_ids: string[];
  dependencies: string[];
  conflicts: string[];
  implied_permissions: string[];
  introduced_version: string;
  deprecated: boolean;
  replacement_permission_id: string | null;
  safer_guidance: string[];
};

export type ExtensionCatalogItem = {
  schema_version: number;
  extension_id: string;
  name: string;
  description: string;
  enabled: boolean;
  required: boolean;
  source: string;
  version: string;
  aliases: string[];
  dependencies: string[];
  conflicts: string[];
  delegated_protection: string | null;
  ecosystem_ids: string[];
  executables: string[];
  project_markers: string[];
  reference_urls: string[];
  action_classes: string[];
  risk_classes: string[];
  safer_alternatives: string[];
  rule_count: number;
  rules: ExtensionRule[];
  permission_count: number;
  permissions: ExtensionPermission[];
};

export type ExtensionControlLayer = {
  schema_version: string;
  kind: "local-admin" | "signed-cloud";
  catalog_digest: string;
  global_lockdown: boolean;
  controls: Array<{
    target_kind: "extension" | "permission";
    target_id: string;
    state: ExtensionControlState;
  }>;
};

export type ExtensionCatalogResponse = {
  schema_version: string;
  control_schema_version?: string;
  catalog_digest: string;
  extensions: ExtensionCatalogItem[];
  limits?: {
    max_body_bytes?: number;
    max_controls?: number;
    max_observations?: number;
  };
};

export type EffectiveExtensionControls = {
  schema_version: string;
  health: "unenrolled" | "protected" | "tampered" | "degraded-unacknowledged" | "recovery-required";
  revision: number;
  catalog_digest: string;
  global_lockdown: boolean;
  controls: Array<{
    target: { kind: "extension" | "permission"; target_id: string };
    state: ExtensionControlState;
  }>;
  layers: ExtensionControlLayer[];
  failures: Array<{ code: string; detail?: string; layer_kind?: string }>;
};

export type ExtensionMutationPayload = {
  previous_revision: number;
  catalog_digest: string;
  layers: ExtensionControlLayer[];
  actor_id: string;
  idempotency_key: string;
  nonce: string;
  approval_password?: string;
  approval_totp_code?: string;
  session_nonce?: string;
  proof_id?: string;
};

export class ExtensionControlApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly recoveryAction?: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetchExtensionControlApi(path, init);
  const payload: unknown = await response.json();
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload as Record<string, unknown> : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : undefined,
      typeof error.recovery === "object" &&
        error.recovery !== null &&
        typeof (error.recovery as Record<string, unknown>).action === "string"
        ? (error.recovery as Record<string, unknown>).action as string
        : undefined,
    );
  }
  return payload as T;
}

export function fetchExtensionCatalog(): Promise<ExtensionCatalogResponse> {
  return request("/v1/extension-controls/catalog");
}

export function fetchEffectiveExtensionControls(): Promise<EffectiveExtensionControls> {
  return request("/v1/extension-controls/effective");
}

export function recoverExtensionControlAuthority(credentials?: {
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<EffectiveExtensionControls> {
  return request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials,
    }),
  });
}

export function previewExtensionMutation(payload: ExtensionMutationPayload): Promise<Record<string, unknown>> {
  return request("/v1/extension-controls/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function applyExtensionMutation(payload: ExtensionMutationPayload): Promise<Record<string, unknown>> {
  return request("/v1/extension-controls/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}