import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
  ExtensionRule,
} from "./extension-controls-api";

export type ExtensionDetailTab = "overview" | "permissions" | "rules";

export function extensionDetailHref(extensionId: string): string {
  const query = new URLSearchParams({ extension: extensionId });
  return `/extensions?${query.toString()}`;
}

export function extensionIdFromSearch(search: string): string | null {
  const value = new URLSearchParams(search).get("extension")?.trim().toLowerCase() ?? "";
  return value.length > 0 ? value : null;
}

export function canonicalExtensionId(catalog: ExtensionCatalogItem[], candidate: string | null): string | null {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension) => extension.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension) => extension.aliases.includes(normalized))?.extension_id ?? null;
}

export function explicitControlState(
  effective: EffectiveExtensionControls,
  kind: "extension" | "permission",
  targetId: string,
): "enabled" | "disabled" | null {
  const match = effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId,
  );
  return match?.state ?? null;
}

export function extensionEffectiveState(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): "enabled" | "disabled" {
  // Guard fails closed whenever authority is unavailable/tampered and global
  // lockdown short-circuits command evaluation before extension requirements.
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension.required) return "enabled";
  return explicitControlState(effective, "extension", extension.extension_id) ?? "enabled";
}

export function permissionEffectiveState(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
  permission: ExtensionPermission,
): "enabled" | "disabled" {
  if (extensionEffectiveState(effective, extension) === "disabled") return "disabled";
  if (!permission.configurable) return permission.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission.permission_id) ??
    (permission.default_enabled ? "enabled" : "disabled");
}

export function permissionForRule(
  extension: ExtensionCatalogItem,
  rule: ExtensionRule,
): ExtensionPermission | null {
  return extension.permissions.find((permission) => permission.rule_ids.includes(rule.rule_id)) ?? null;
}

export type RelationSummary = {
  dependencies: ExtensionPermission[];
  conflicts: ExtensionPermission[];
  implied: ExtensionPermission[];
  missing: string[];
};

export function permissionRelations(
  extension: ExtensionCatalogItem,
  permission: ExtensionPermission,
): RelationSummary {
  const byId = new Map(extension.permissions.map((item) => [item.permission_id, item]));
  const resolve = (ids: string[]) => ids.map((id) => byId.get(id)).filter((item): item is ExtensionPermission => Boolean(item));
  const referenced = [...permission.dependencies, ...permission.conflicts, ...permission.implied_permissions];
  return {
    dependencies: resolve(permission.dependencies),
    conflicts: resolve(permission.conflicts),
    implied: resolve(permission.implied_permissions),
    missing: referenced.filter((id) => !byId.has(id)),
  };
}

export function treatmentLabel(value: string): string {
  const labels: Record<string, string> = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled",
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
