export const PROTECTION_TERMS = {
  navigation: "Protections",
  pageTitle: "Protection Center",
  module: "Protection module",
  modules: "Protection modules",
  setting: "Protection setting",
  detection: "Detection",
  lockdown: "Emergency Lockdown",
  inheritedSetting: "Recommended",
  changeReview: "What will change",
} as const;

export const SIMPLE_MODE_PROHIBITED_TERMS = [
  "catalog digest",
  "canonical id",
  "matcher kind",
  "baseline floor",
  "local-admin",
  "signed-cloud",
  "semantic blast radius",
  "permission id",
  "rule id",
  "degraded-unacknowledged",
] as const;

export type ProtectionBehavior = "allowed" | "ask-first" | "blocked" | "required" | "managed";

export function protectionBehaviorLabel(behavior: ProtectionBehavior): string {
  switch (behavior) {
    case "allowed": return "Allowed";
    case "ask-first": return "Ask first";
    case "blocked": return "Blocked";
    case "required": return "Required";
    case "managed": return "Managed by your organization";
  }
}

export function localSettingChoiceLabel(choice: "inherit" | "allow" | "block"): string {
  if (choice === "inherit") return "Recommended";
  if (choice === "allow") return "Permit when Guard considers it safe";
  return "Always block matching actions";
}

export function localSettingChoiceDescription(choice: "inherit" | "allow" | "block"): string {
  if (choice === "inherit") return "Follow Guard's built-in defaults plus any organization policy.";
  if (choice === "allow") return "Permit matching actions only when Guard's built-in safety rules and organization policy allow them.";
  return "Add a stricter local block for matching actions on this device.";
}

export function simpleCopyViolations(text: string): string[] {
  const lower = text.toLowerCase();
  return SIMPLE_MODE_PROHIBITED_TERMS.filter((term) => lower.includes(term));
}

export function assertSimpleCopySafe(text: string): void {
  const violations = simpleCopyViolations(text);
  if (violations.length) throw new Error(`Simple protection copy leaked internal terms: ${violations.join(", ")}`);
}

export const CLOUD_LOCAL_BOUNDARY_COPY = {
  localProtected: "Local protection is active on this device.",
  cloudDisconnected: "Cloud continuity is not connected. Local protection continues.",
  cloudUnavailable: "Cloud sync is temporarily unavailable. Local protection continues.",
} as const;
