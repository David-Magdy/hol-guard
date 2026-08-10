import type { EffectiveExtensionControls, ExtensionCatalogItem } from "./extension-controls-api";
import { extensionEffectiveState } from "./extension-control-center-model";

/**
 * Risk coverage taxonomy. Guard ships nine distinct risk classes across its
 * built-in command extensions; these are the canonical strings the catalog
 * reports in `risk_classes`. The order here is the filter display order.
 */
export type RiskClass =
  | "destructive_shell"
  | "network_egress"
  | "supply_chain"
  | "local_secret_read"
  | "encoded_execution"
  | "policy_bypass"
  | "data_flow_exfiltration"
  | "credential_exfiltration"
  | "execution";

export type ExtensionDomain =
  | "core"
  | "package"
  | "cloud"
  | "database"
  | "storage"
  | "backup"
  | "remote"
  | "cicd"
  | "platform"
  | "managed-service"
  | "search-messaging"
  | "source-control";

export type ExtensionStateFilter = "all" | "enabled" | "disabled";
export type ExtensionRequiredFilter = "all" | "required" | "optional";

export interface ExtensionFilterState {
  query: string;
  risk: RiskClass | "all";
  domain: ExtensionDomain | "all";
  state: ExtensionStateFilter;
  required: ExtensionRequiredFilter;
}

export const EMPTY_EXTENSION_FILTERS: ExtensionFilterState = {
  query: "",
  risk: "all",
  domain: "all",
  state: "all",
  required: "all",
};

export const RISK_CLASS_ORDER: readonly RiskClass[] = [
  "destructive_shell",
  "network_egress",
  "supply_chain",
  "local_secret_read",
  "encoded_execution",
  "policy_bypass",
  "data_flow_exfiltration",
  "credential_exfiltration",
  "execution",
] as const;

export const RISK_CLASS_LABELS: Record<RiskClass, string> = {
  destructive_shell: "Destructive shell",
  network_egress: "Network egress",
  supply_chain: "Supply chain",
  local_secret_read: "Local secrets",
  encoded_execution: "Encoded execution",
  policy_bypass: "Policy bypass",
  data_flow_exfiltration: "Data exfiltration",
  credential_exfiltration: "Credential exfiltration",
  execution: "Remote execution",
};

export const RISK_CLASS_TONE: Record<RiskClass, { idle: string; active: string; label: string }> = {
  destructive_shell: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-amber-300 hover:bg-amber-50",
    active: "border-amber-400 bg-amber-100 text-amber-900",
    label: "bg-amber-50 text-amber-800 border-amber-200",
  },
  network_egress: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-blue-300 hover:bg-blue-50",
    active: "border-blue-400 bg-blue-100 text-blue-900",
    label: "bg-blue-50 text-blue-800 border-blue-200",
  },
  supply_chain: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-violet-300 hover:bg-violet-50",
    active: "border-violet-400 bg-violet-100 text-violet-900",
    label: "bg-violet-50 text-violet-800 border-violet-200",
  },
  local_secret_read: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-rose-300 hover:bg-rose-50",
    active: "border-rose-400 bg-rose-100 text-rose-900",
    label: "bg-rose-50 text-rose-800 border-rose-200",
  },
  encoded_execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-slate-400 hover:bg-slate-100",
    active: "border-slate-500 bg-slate-200 text-slate-900",
    label: "bg-slate-100 text-slate-700 border-slate-300",
  },
  policy_bypass: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-red-300 hover:bg-red-50",
    active: "border-red-400 bg-red-100 text-red-900",
    label: "bg-red-50 text-red-800 border-red-200",
  },
  data_flow_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200",
  },
  credential_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200",
  },
  execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-teal-300 hover:bg-teal-50",
    active: "border-teal-400 bg-teal-100 text-teal-900",
    label: "bg-teal-50 text-teal-800 border-teal-200",
  },
};

export const DOMAIN_LABELS: Record<ExtensionDomain, string> = {
  core: "Core protection",
  package: "Package ecosystems",
  cloud: "Cloud providers",
  database: "Databases",
  storage: "Storage",
  backup: "Backup & sync",
  remote: "Remote access",
  cicd: "CI/CD pipelines",
  platform: "Platform",
  "managed-service": "Managed services",
  "search-messaging": "Search & messaging",
  "source-control": "Source control",
};

const DOMAIN_PREFIX_MAP: ReadonlyArray<[string, ExtensionDomain]> = [
  ["command.package.", "package"],
  ["command.cloud.", "cloud"],
  ["command.aws", "cloud"],
  ["command.azure", "cloud"],
  ["command.gcp", "cloud"],
  ["command.database.", "database"],
  ["command.storage.", "storage"],
  ["command.backup.", "backup"],
  ["command.remote.", "remote"],
  ["command.cicd.", "cicd"],
  ["command.platform.", "platform"],
  ["command.managed-service.", "managed-service"],
  ["command.search-messaging.", "search-messaging"],
  ["command.github", "source-control"],
];

export function classifyDomain(extensionId: string): ExtensionDomain {
  const id = extensionId.toLowerCase();
  for (const [prefix, domain] of DOMAIN_PREFIX_MAP) {
    if (id.startsWith(prefix)) return domain;
  }
  return "core";
}

/** Shared effective-state resolver used by cards, facets, and details. */
export function isExtensionEnabled(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): boolean {
  return extensionEffectiveState(effective, extension) === "enabled";
}

export function hasActiveFilters(filters: ExtensionFilterState): boolean {
  return (
    filters.query.trim() !== "" ||
    filters.risk !== "all" ||
    filters.domain !== "all" ||
    filters.state !== "all" ||
    filters.required !== "all"
  );
}

function searchHaystack(extension: ExtensionCatalogItem): string {
  const parts = [
    extension.name,
    extension.extension_id,
    extension.description,
    extension.source,
    ...extension.action_classes,
    ...extension.risk_classes,
    classifyDomain(extension.extension_id),
  ];
  return parts.join(" ").toLowerCase();
}

export function matchExtensionQuery(extension: ExtensionCatalogItem, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (normalized === "") return true;
  const haystack = searchHaystack(extension);
  return normalized.split(/\s+/).every((token) => haystack.includes(token));
}

export function filterExtensions(
  extensions: readonly ExtensionCatalogItem[],
  effective: EffectiveExtensionControls,
  filters: ExtensionFilterState,
): ExtensionCatalogItem[] {
  const items = extensions.filter((extension) => {
    if (!matchExtensionQuery(extension, filters.query)) return false;
    if (filters.risk !== "all" && !extension.risk_classes.includes(filters.risk)) return false;
    if (filters.domain !== "all" && classifyDomain(extension.extension_id) !== filters.domain) return false;
    if (filters.required !== "all") {
      const isRequired = extension.required;
      if (filters.required === "required" && !isRequired) return false;
      if (filters.required === "optional" && isRequired) return false;
    }
    if (filters.state !== "all") {
      const enabled = isExtensionEnabled(effective, extension);
      if (filters.state === "enabled" && !enabled) return false;
      if (filters.state === "disabled" && enabled) return false;
    }
    return true;
  });
  items.sort((left, right) => left.name.localeCompare(right.name));
  return items;
}

export function countByRiskClass(extensions: readonly ExtensionCatalogItem[]): Map<RiskClass, number> {
  const counts = new Map<RiskClass, number>();
  for (const risk of RISK_CLASS_ORDER) counts.set(risk, 0);
  for (const extension of extensions) {
    for (const risk of extension.risk_classes) {
      if (risk in RISK_CLASS_LABELS) {
        const key = risk as RiskClass;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
  }
  return counts;
}
