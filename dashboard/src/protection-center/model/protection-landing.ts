import type { CommandActivityItem, GuardAction } from "../../command-activity/command-activity-types";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../../extension-controls-api";
import type { GuardRuntimeSnapshot } from "../../guard-types";
import { isExtensionEnabled } from "../../extensions-filters";
import { protectionCategoryForExtension } from "./protection-categories";

export type ProtectionDecision = "allowed" | "ask-first" | "blocked";
export type ProtectionModuleSection = "in-use" | "recommended" | "all";

export type ProtectionDecisionView = {
  activityId: string;
  occurredAt: string;
  harness: string;
  result: ProtectionDecision;
  reasonCode: string | null;
  extensionIds: string[];
  extensionNames: string[];
  controllingRuleId: string | null;
};

export type ProtectionModuleRank = {
  extension: ExtensionCatalogItem;
  section: ProtectionModuleSection;
  score: number;
  lastInvolvedAt: string | null;
  involvementCount: number;
};

export type ProtectionCloudContinuity = {
  state: "not-connected" | "waiting" | "connected" | "unavailable";
  label: string;
  detail: string;
};

export type ProtectionHealthCheck = {
  status: "healthy" | "needs-attention";
  summary: string;
  checks: Array<{ id: string; label: string; passed: boolean }>;
};

export function protectionDecisionForAction(action: GuardAction | null): ProtectionDecision {
  if (action === "block") return "blocked";
  if (action === "allow") return "allowed";
  return "ask-first";
}

export function recentProtectionDecisions(
  activity: readonly CommandActivityItem[],
  catalog: readonly ExtensionCatalogItem[],
  limit = 5,
): ProtectionDecisionView[] {
  const names = new Map(catalog.map((extension) => [extension.extension_id, extension.name]));
  return [...activity]
    .filter((item) => item.policy_action !== null)
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at))
    .slice(0, Math.max(0, Math.min(limit, 20)))
    .map((item) => {
      const extensionIds = [...new Set(item.matches.map((match) => match.extension_id))].slice(0, 8);
      return {
        activityId: item.activity_id,
        occurredAt: item.occurred_at,
        harness: item.harness,
        result: protectionDecisionForAction(item.policy_action),
        reasonCode: item.decision_reason_code,
        extensionIds,
        extensionNames: extensionIds.map((id) => names.get(id) ?? "Protection module"),
        controllingRuleId: item.controlling_rule_id,
      };
    });
}

export function rankProtectionModules(
  catalog: readonly ExtensionCatalogItem[],
  activity: readonly CommandActivityItem[],
): ProtectionModuleRank[] {
  const involvement = new Map<string, { count: number; lastAt: string }>();
  for (const item of activity) {
    for (const id of new Set(item.matches.map((match) => match.extension_id))) {
      const previous = involvement.get(id);
      if (!previous) involvement.set(id, { count: 1, lastAt: item.occurred_at });
      else {
        previous.count += 1;
        if (Date.parse(item.occurred_at) > Date.parse(previous.lastAt)) previous.lastAt = item.occurred_at;
      }
    }
  }

  return catalog.map((extension) => {
    const used = involvement.get(extension.extension_id);
    const section: ProtectionModuleSection = used ? "in-use" : extension.required || extension.enabled ? "recommended" : "all";
    const recencyScore = used ? Math.max(0, 10_000_000_000_000 - Math.max(0, Date.now() - Date.parse(used.lastAt))) : 0;
    const score = (used ? 1_000_000_000_000_000 : 0)
      + (used?.count ?? 0) * 1_000_000_000
      + (extension.required ? 100_000_000 : 0)
      + (extension.enabled ? 10_000_000 : 0)
      + recencyScore;
    return {
      extension,
      section,
      score,
      lastInvolvedAt: used?.lastAt ?? null,
      involvementCount: used?.count ?? 0,
    };
  }).sort((left, right) => right.score - left.score || left.extension.name.localeCompare(right.extension.name));
}

function safeSearchText(extension: ExtensionCatalogItem): string {
  const category = protectionCategoryForExtension(extension);
  return [
    extension.name,
    extension.description,
    ...extension.aliases,
    ...extension.ecosystem_ids,
    ...extension.executables,
    category.label,
    category.description,
    ...category.searchAliases,
  ].join(" ").toLowerCase();
}

export function filterProtectionModulesByHumanQuery(
  modules: readonly ProtectionModuleRank[],
  query: string,
): ProtectionModuleRank[] {
  const normalized = query.trim().toLowerCase().slice(0, 160);
  if (!normalized) return [...modules];
  const terms = normalized.split(/\s+/).filter(Boolean).slice(0, 8);
  return modules.filter(({ extension }) => {
    const text = safeSearchText(extension);
    return terms.every((term) => text.includes(term));
  });
}

export function protectionCloudContinuity(
  runtime: GuardRuntimeSnapshot | null,
  loadFailed = false,
): ProtectionCloudContinuity {
  if (loadFailed) {
    return {
      state: "unavailable",
      label: "Cloud continuity unavailable",
      detail: "Local protection continues on this device. Cloud status could not be refreshed.",
    };
  }
  if (!runtime || !runtime.sync_configured || runtime.cloud_state === "local_only") {
    return {
      state: "not-connected",
      label: "Cloud continuity not connected",
      detail: "Local protection continues. Connect Cloud only if you want cross-device continuity and Cloud history.",
    };
  }
  if (runtime.cloud_state === "paired_waiting") {
    return {
      state: "waiting",
      label: "Cloud continuity connecting",
      detail: "Local protection continues while Cloud finishes pairing or synchronization.",
    };
  }
  return {
    state: "connected",
    label: "Cloud continuity connected",
    detail: runtime.cloud_state_detail || "Cloud continuity is connected for this device.",
  };
}

export function protectionCategorySummary(
  catalog: readonly ExtensionCatalogItem[],
  effective: EffectiveExtensionControls,
) {
  const groups = new Map<string, { id: string; label: string; description: string; total: number; allowed: number; blocked: number }>();
  for (const extension of catalog) {
    const category = protectionCategoryForExtension(extension);
    const group = groups.get(category.id) ?? {
      id: category.id,
      label: category.label,
      description: category.description,
      total: 0,
      allowed: 0,
      blocked: 0,
    };
    group.total += 1;
    if (isExtensionEnabled(effective, extension)) group.allowed += 1;
    else group.blocked += 1;
    groups.set(category.id, group);
  }
  return [...groups.values()].sort((left, right) => left.label.localeCompare(right.label));
}

export function evaluateProtectionHealth(
  catalogDigest: string,
  effective: EffectiveExtensionControls,
  runtime: GuardRuntimeSnapshot | null,
): ProtectionHealthCheck {
  const checks = [
    { id: "authority", label: "Trusted protection settings are verified", passed: effective.health === "protected" },
    { id: "catalog", label: "Protection catalog matches effective policy", passed: catalogDigest === effective.catalog_digest },
    { id: "runtime", label: "Guard runtime is responding", passed: runtime !== null && runtime.runtime_state !== null },
  ];
  const healthy = checks.every((check) => check.passed);
  return {
    status: healthy ? "healthy" : "needs-attention",
    summary: healthy
      ? "Protection health check passed. Guard's catalog, policy authority, and runtime agree."
      : "One or more local protection checks need attention. Guard remains conservative when it cannot verify state.",
    checks,
  };
}
