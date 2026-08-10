import type { GuardRuntimeSnapshot } from "../guard-types";

export type ProtectionCloudPlan = "free" | "solo" | "pro" | "team" | "enterprise";

const PLAN_IDS = new Set<ProtectionCloudPlan>(["free", "solo", "pro", "team", "enterprise"]);

export type ProtectionCloudValue = {
  state: "offline" | "optional" | "connecting" | "connected";
  plan: ProtectionCloudPlan | null;
  label: string;
  detail: string;
};

export function protectionCloudPlan(runtime: GuardRuntimeSnapshot | null): ProtectionCloudPlan | null {
  const raw = runtime?.cloud_pairing_state?.plan_id?.trim().toLowerCase();
  return raw && PLAN_IDS.has(raw as ProtectionCloudPlan) ? raw as ProtectionCloudPlan : null;
}

function connectedPlanDetail(plan: ProtectionCloudPlan | null): string {
  switch (plan) {
    case "solo":
      return "Solo adds personal cross-device continuity and Cloud history. Protection and blocking still run locally on this device.";
    case "pro":
      return "Pro adds extended Cloud history plus richer evidence and export workflows. Protection and blocking still run locally on this device.";
    case "team":
      return "Team adds organization coordination, policy continuity, and centralized audit. This device keeps enforcing locally if Cloud is unavailable.";
    case "enterprise":
      return "Enterprise adds organization policy, centralized oversight, and delegated workflows. This device keeps enforcing locally if Cloud is unavailable.";
    case "free":
      return "Cloud is connected for account continuity. Plan choices affect Cloud features only; protection and blocking still run locally on this device.";
    default:
      return "Cloud continuity is connected. Protection and blocking still run locally on this device.";
  }
}

export function protectionCloudValue(runtime: GuardRuntimeSnapshot | null, loadFailed = false): ProtectionCloudValue {
  if (loadFailed) {
    return {
      state: "offline",
      plan: null,
      label: "Cloud status unavailable",
      detail: "Local protection is active independently. Cloud status could not be refreshed.",
    };
  }
  if (!runtime || !runtime.sync_configured || runtime.cloud_state === "local_only") {
    return {
      state: "optional",
      plan: protectionCloudPlan(runtime),
      label: "Cloud continuity is optional",
      detail: "Local protection is active on this device. Connect Guard Cloud only if you want continuity, history, or organization coordination.",
    };
  }
  if (runtime.cloud_state === "paired_waiting") {
    return {
      state: "connecting",
      plan: protectionCloudPlan(runtime),
      label: "Cloud continuity is connecting",
      detail: "Local protection remains active while Cloud pairing or synchronization finishes.",
    };
  }
  const plan = protectionCloudPlan(runtime);
  return {
    state: "connected",
    plan,
    label: plan ? `${plan[0].toUpperCase()}${plan.slice(1)} Cloud continuity` : "Cloud continuity connected",
    detail: connectedPlanDetail(plan),
  };
}

/**
 * Gates Cloud value copy only. Local Protection Center controls must never be
 * passed through this component or conditioned on its state.
 */
export function CloudValueGate(props: {
  runtime: GuardRuntimeSnapshot | null;
  loading?: boolean;
  loadFailed?: boolean;
}) {
  const value = protectionCloudValue(props.runtime, props.loadFailed);
  return <aside
    aria-label="Cloud continuity"
    data-local-protection-independent="true"
    className="rounded-2xl border border-slate-200 bg-white px-4 py-3"
  >
    <div className="flex flex-wrap items-center gap-2">
      <strong className="text-sm text-slate-900">{props.loading ? "Checking Cloud continuity…" : value.label}</strong>
      {value.plan ? <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-600">{value.plan}</span> : null}
    </div>
    <p className="mt-1 text-xs leading-5 text-slate-600">{props.loading ? "Local protection continues while Cloud status is checked." : value.detail}</p>
  </aside>;
}
