import type { PackageFirewallStatusResponse } from "./guard-types";

export type SupplyChainFixAllPhase =
  | "idle"
  | "working"
  | "approval"
  | "connecting"
  | "success"
  | "incomplete"
  | "error";

export type SupplyChainFixAllState = {
  phase: SupplyChainFixAllPhase;
  message: string | null;
  completedSteps: string[];
  failedSteps: string[];
};

export const IDLE_SUPPLY_CHAIN_FIX_ALL_STATE: SupplyChainFixAllState = {
  phase: "idle",
  message: null,
  completedSteps: [],
  failedSteps: [],
};

export function supplyChainFixAllButtonLabel(phase: SupplyChainFixAllPhase): string {
  if (phase === "working") return "Fixing…";
  if (phase === "approval") return "Approval required";
  if (phase === "connecting") return "Connecting…";
  if (phase === "incomplete" || phase === "error") return "Retry fixes";
  return "Fix all";
}

export function supplyChainFixAllIsPending(phase: SupplyChainFixAllPhase): boolean {
  return phase === "working" || phase === "approval" || phase === "connecting";
}

export function supplyChainFixAllRequiresConnection(data: PackageFirewallStatusResponse): boolean {
  if (data.entitlement.allowed) return false;
  if (data.entitlement.reason === "guard_cloud_reconnect_required") return true;
  if (data.entitlement.reason !== "guard_cloud_connect_required") return false;
  return !data.package_shims.some((entry) => entry.installed);
}
