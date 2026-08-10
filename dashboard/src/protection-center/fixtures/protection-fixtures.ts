import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../../extension-controls-api";

const DIGEST = "a".repeat(64);

export function protectionAuthorityFixture(
  health: EffectiveExtensionControls["health"],
  options: { lockdown?: boolean; revision?: number } = {},
): EffectiveExtensionControls {
  return {
    schema_version: "1.0.0",
    health,
    revision: options.revision ?? 1,
    catalog_digest: DIGEST,
    global_lockdown: options.lockdown ?? false,
    controls: [],
    layers: [],
    failures: health === "protected" ? [] : [{ code: "fixture-state" }],
  };
}

export const PROTECTION_AUTHORITY_FIXTURES = {
  protected: protectionAuthorityFixture("protected"),
  unenrolled: protectionAuthorityFixture("unenrolled"),
  tampered: protectionAuthorityFixture("tampered"),
  recoveryRequired: protectionAuthorityFixture("recovery-required"),
  degradedUnacknowledged: protectionAuthorityFixture("degraded-unacknowledged"),
  degradedAcknowledged: protectionAuthorityFixture("degraded-acknowledged"),
  lockdown: protectionAuthorityFixture("protected", { lockdown: true }),
} as const;

export function protectionModuleFixture(overrides: Partial<ExtensionCatalogItem> = {}): ExtensionCatalogItem {
  return {
    schema_version: 2,
    extension_id: "command.git",
    version: "1.0.0",
    name: "Git",
    description: "Protects source-control history and destructive repository operations.",
    enabled: true,
    required: false,
    source: "built-in",
    aliases: [],
    dependencies: [],
    conflicts: [],
    delegated_protection: null,
    ecosystem_ids: ["git"],
    executables: ["git"],
    project_markers: [".git"],
    reference_urls: [],
    action_classes: ["git.history.rewrite"],
    risk_classes: ["history-rewrite"],
    safer_alternatives: ["Create a checkpoint before rewriting repository history."],
    rule_count: 0,
    rules: [],
    permission_count: 0,
    permissions: [],
    ...overrides,
  };
}

export const SYNTHETIC_PROTECTION_DECISIONS = [
  { id: "decision-allowed", result: "allowed" as const, module: "Git", reason: "The operation only inspected repository state." },
  { id: "decision-review", result: "ask-first" as const, module: "Packages", reason: "The install can run package lifecycle code, so Guard asks first." },
  { id: "decision-blocked", result: "blocked" as const, module: "Files and secrets", reason: "The operation could expose sensitive local credentials." },
] as const;
