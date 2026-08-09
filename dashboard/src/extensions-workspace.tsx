import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronRight,
  HiMiniChevronUp,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniExclamationTriangle,
  HiMiniLockClosed,
  HiMiniMagnifyingGlass,
  HiMiniPuzzlePiece,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import { ApprovalProofModal } from "./approval-proof-modal";
import { ExtensionControlCenterDetail } from "./extension-control-center-detail";
import {
  canonicalExtensionId,
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  extensionDetailSearch,
  extensionStateLabel,
  parseExtensionRoute,
  readExtensionDetailUrlState,
  type ExtensionDetailUrlState,
  type ExtensionRoute,
} from "./extension-control-center-model";
import {
  acknowledgeDegradedExtensionControlAuthority,
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  previewExtensionMutation,
  recoverExtensionControlAuthority,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionCatalogResponse,
  type ExtensionMutationPayload,
} from "./extension-controls-api";
import { ExtensionsFilterBar } from "./extensions-filter-bar";
import {
  classifyDomain,
  DOMAIN_LABELS,
  EMPTY_EXTENSION_FILTERS,
  filterExtensions,
  hasActiveFilters,
  isExtensionEnabled,
  RISK_CLASS_LABELS,
  RISK_CLASS_TONE,
  type ExtensionFilterState,
  type RiskClass,
} from "./extensions-filters";
import { useDebounce } from "./use-debounce";
import { useModalDialog } from "./use-modal-dialog";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";

const EXTENSION_ROUTE_STATE_KEY = "guardExtensionDetailPath";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type ExtensionMutationTarget = Pick<ExtensionCatalogItem, "extension_id" | "name">;
type PendingChange = { extension: ExtensionMutationTarget; enabled: boolean } | { globalLockdown: boolean };

type RouteState = {
  route: ExtensionRoute;
  detail: ExtensionDetailUrlState;
};

export type ExtensionRecoveryAction = { actionLabel?: string; copyLabel: string; command: string; description: string; title: string };

function historyDetailPath(): string | null {
  const state = window.history.state;
  if (typeof state !== "object" || state === null) return null;
  const value = (state as Record<string, unknown>)[EXTENSION_ROUTE_STATE_KEY];
  return typeof value === "string" && value.startsWith("/extensions/") ? value : null;
}

export function currentExtensionRouteState(): RouteState {
  const bridgedPath = window.location.pathname === "/extensions" ? historyDetailPath() : null;
  return {
    route: parseExtensionRoute(bridgedPath ?? window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search),
  };
}

export function extensionRecoveryAction(health: EffectiveExtensionControls["health"]): ExtensionRecoveryAction | null {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      actionLabel: "Repair now",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority",
    };
  }
  if (health === "degraded-unacknowledged") {
    return {
      title: "Acknowledge degraded extension controls",
      actionLabel: "Acknowledge degraded state",
      copyLabel: "Copy status command",
      description: "Guard is failing closed because extension-control authority is degraded. Authenticate to acknowledge the degraded state. Acknowledgement does not restore protected authority.",
      command: "hol-guard status",
    };
  }
  if (health === "degraded-acknowledged") {
    return {
      title: "Degraded extension controls acknowledged",
      copyLabel: "Copy status command",
      description: "Guard remains fail-closed while extension-control authority is degraded. Restore protected authority before changing extension policy.",
      command: "hol-guard status",
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description: "Authenticate in this device's terminal to protect extension settings, then check again.",
    command: "hol-guard command controls enroll",
  };
}

export function requiresExtensionRecoveryApproval(error: unknown): boolean {
  return error instanceof ExtensionControlApiError &&
    (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}

function randomToken(): string { return crypto.randomUUID().replaceAll("-", ""); }

export function buildExtensionMutation(
  state: Extract<LoadState, { kind: "ready" }>,
  change: PendingChange,
): ExtensionMutationPayload {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: [],
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id,
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled",
    });
    local.controls.sort((left, right) =>
      `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`),
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken(),
  };
}

export function ExtensionStatusBanner(props: {
  busy?: boolean;
  effective: EffectiveExtensionControls;
  error?: string | null;
  status?: string | null;
  onRecover?: () => void;
  onRetry: () => void;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const recovery = extensionRecoveryAction(props.effective.health);
  const handleCopy = useCallback(async () => {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }, [recovery]);

  if (props.effective.health === "protected") {
    return <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"><HiMiniShieldCheck className="size-5 shrink-0" aria-hidden="true" /><span><strong>Protected authority</strong> · revision {props.effective.revision}</span></div>;
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required" || props.effective.health === "degraded-unacknowledged";
  const busyLabel = props.effective.health === "degraded-unacknowledged" ? "Acknowledging…" : "Repairing…";
  return <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5"><div className="flex items-start gap-3"><span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700"><HiMiniExclamationTriangle className="size-5" aria-hidden="true" /></span><div className="min-w-0 flex-1"><h2 className="font-semibold text-slate-950">{recovery?.title}</h2><p className="mt-1 text-sm leading-6 text-slate-700">{recovery?.description}</p><div className="mt-4 flex flex-wrap items-center gap-2">{repairable && props.onRecover ? <button type="button" aria-busy={props.busy} disabled={props.busy} onClick={props.onRecover} className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">{props.busy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <HiMiniShieldCheck className="size-4" aria-hidden="true" />}{props.busy ? busyLabel : recovery?.actionLabel}</button> : null}<button type="button" onClick={props.onRetry} className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"><HiMiniArrowPath className="size-4" aria-hidden="true" />Check again</button></div><div className="mt-4 border-t border-amber-200 pt-3"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Command-line fallback</p><div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center"><code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800">{recovery?.command}</code><button type="button" onClick={handleCopy} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-brand-blue">{copyState === "copied" ? <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" /> : <HiMiniClipboard className="size-4" aria-hidden="true" />}{copyState === "copied" ? "Copied" : recovery?.copyLabel}</button></div>{copyState === "failed" ? <span role="status" className="mt-2 block text-sm text-red-700">Copy failed. Select the command above.</span> : null}</div>{props.error ? <p role="alert" className="mt-3 text-sm font-medium text-red-700">{props.error}</p> : null}{props.status ? <p role="status" className="mt-3 text-sm font-medium text-slate-800">{props.status}</p> : null}</div></div></div>;
}

function ExtensionCard(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  locked: boolean;
  onChange: (change: PendingChange) => void;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const domain = classifyDomain(props.extension.extension_id);
  const risks = props.extension.risk_classes.filter((risk): risk is RiskClass => risk in RISK_CLASS_LABELS);
  const enabled = isExtensionEnabled(props.effective, props.extension);
  const stateLabel = extensionStateLabel(props.effective, props.extension);
  return <article className="group relative flex min-h-60 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition motion-reduce:transition-none hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)] motion-reduce:hover:translate-y-0">
    <button type="button" aria-label={`View ${props.extension.name} details`} onClick={() => props.onOpen(props.extension)} className="absolute inset-0 z-0 rounded-3xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"><span className="sr-only">View details</span></button>
    <div className="pointer-events-none relative z-10 flex items-start justify-between gap-4"><span className="grid size-11 place-items-center rounded-2xl bg-blue-50 text-brand-blue"><HiMiniPuzzlePiece className="size-6" aria-hidden="true" /></span><span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${enabled ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700"}`}>{stateLabel}</span></div>
    <div className="pointer-events-none relative z-10 mt-5 flex flex-wrap items-center gap-2"><h2 className="font-semibold text-slate-950">{props.extension.name}</h2>{props.extension.required ? <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand-blue">Required</span> : null}</div>
    <p className="pointer-events-none relative z-10 mt-2 line-clamp-3 text-sm leading-6 text-slate-600">{props.extension.description}</p>
    {risks.length ? <div className="pointer-events-none relative z-10 mt-3 flex flex-wrap gap-1">{risks.map((risk) => <span key={risk} className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`}>{RISK_CLASS_LABELS[risk]}</span>)}</div> : null}
    <div className="pointer-events-none relative z-10 mt-4 flex flex-wrap gap-2 text-xs text-slate-500"><span>{DOMAIN_LABELS[domain]}</span><span>·</span><span>{props.extension.permission_count} permissions</span><span>·</span><span>{props.extension.rule_count} rules</span><span>·</span><span>v{props.extension.version}</span></div>
    <div className="relative z-10 mt-auto flex items-end justify-between gap-3 border-t border-slate-100 pt-4"><span className="pointer-events-none inline-flex items-center gap-1 text-sm font-semibold text-brand-blue">View details <HiMiniChevronRight className="size-4" aria-hidden="true" /></span>{!props.extension.required ? <button type="button" disabled={props.locked} onClick={() => props.onChange({ extension: props.extension, enabled: !enabled })} className="min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50">Review capability policy</button> : null}</div>
  </article>;
}

function ReviewModal(props: { change: PendingChange; busy: boolean; error: string | null; onCancel: () => void; onConfirm: (password: string, totp: string) => void }) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change
    ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown`
    : `${props.change.enabled ? "Allow" : "Block"} ${props.change.extension.name} capability`;
  const current = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Open" : "Lockdown"
    : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Lockdown" : "Open"
    : props.change.enabled ? "Allowed" : "Blocked";
  return <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm"><form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="extension-review-title" onSubmit={(event) => { event.preventDefault(); props.onConfirm(password, totp); }} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none"><div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Review capability control</p><h2 id="extension-review-title" className="mt-2 text-xl font-semibold text-slate-950">{title}</h2></div><button type="button" disabled={props.busy} onClick={props.onCancel} aria-label="Close review" className="grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100 disabled:opacity-50"><HiMiniXMark className="size-5" /></button></div><div className="mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm"><span className="text-slate-500">Current</span><span aria-hidden="true">→</span><strong className="text-slate-950">Requested</strong><span>{current}</span><span /><span>{requested}</span></div><p className="mt-4 text-sm text-slate-600">Blocking a capability makes Guard block matching actions. It does not turn detector coverage off.</p><label className="mt-5 block text-sm font-medium text-slate-700">Approval password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" /></label><label className="mt-4 block text-sm font-medium text-slate-700">Authenticator code<input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(event) => setTotp(event.target.value)} className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" /></label>{props.error ? <p role="alert" className="mt-4 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-700">{props.error}</p> : null}<div className="mt-6 flex justify-end gap-3"><button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50">Cancel</button><button type="submit" disabled={props.busy} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60">{props.busy ? "Verifying…" : `Confirm ${requested.toLowerCase()}`}</button></div></form></div>;
}

export function ExtensionsWorkspace() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [routeState, setRouteState] = useState<RouteState>(() => currentExtensionRouteState());
  const [pending, setPending] = useState<PendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const [provenanceOpen, setProvenanceOpen] = useState(false);
  const [filters, setFilters] = useState<ExtensionFilterState>(EMPTY_EXTENSION_FILTERS);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = useRef<string | null>(null);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Catalog changed while extension controls were loading. Refresh Guard and try again.");
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const catalogExtensions = useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = useMemo<ExtensionFilterState>(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);

  useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    const href = extensionDetailHref(canonicalSelected, routeState.detail);
    window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);

  const openExtension = useCallback((extension: ExtensionCatalogItem) => {
    const href = extensionDetailHref(extension.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: extension.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  const closeExtension = useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  const updateDetailState = useCallback((next: ExtensionDetailUrlState) => {
    if (!canonicalSelected) return;
    const href = extensionDetailHref(canonicalSelected, next);
    const historyMode = next.tab !== routeState.detail.tab || next.ruleId !== routeState.detail.ruleId ? "push" : "replace";
    if (historyMode === "push") window.history.pushState({}, "", href);
    else window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: next });
  }, [canonicalSelected, routeState.detail]);

  const requestBroadControl = useCallback((extension: ExtensionCatalogItem) => {
    if (state.kind !== "ready") return;
    setMutationError(null);
    setPending({ extension, enabled: !isExtensionEnabled(state.effective, extension) });
  }, [state]);

  const confirm = useCallback(async (password: string, totp: string) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      payload.approval_password = password;
      payload.approval_totp_code = totp;
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a mutation proof");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : undefined;
      setMutationError(`${error instanceof Error ? error.message : "Change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);

  const recover = useCallback(async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
    const acknowledgingDegraded = state.kind === "ready" && state.effective.health === "degraded-unacknowledged";
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(acknowledgingDegraded ? "Acknowledging degraded extension controls…" : "Repairing extension controls…");
    try {
      const effective = acknowledgingDegraded
        ? await acknowledgeDegradedExtensionControlAuthority(credentials)
        : await recoverExtensionControlAuthority(credentials);
      if (acknowledgingDegraded) {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not acknowledge the degraded authority state.");
        if (state.kind === "ready") setState({ ...state, effective });
        setRecoveryApprovalOpen(false);
        setRecoveryStatus("Degraded state acknowledged. Guard remains fail-closed until protected authority is restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not restore protected extension controls.");
        if (state.kind === "ready") setState({ ...state, effective });
        setRecoveryApprovalOpen(false);
        setRecoveryStatus("Extension controls repaired.");
      }
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        await resolveApprovalGate();
        setRecoveryApprovalOpen(true);
      } else {
        setRecoveryError(error instanceof Error ? error.message : acknowledgingDegraded ? "Guard could not acknowledge degraded extension controls." : "Guard could not repair extension controls.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);

  if (state.kind === "loading") return <main className="grid min-h-[60vh] place-items-center" aria-busy="true"><HiMiniArrowPath className="size-7 animate-spin text-brand-blue motion-reduce:animate-none" /></main>;
  if (state.kind === "error") return <main className="mx-auto max-w-5xl p-6"><div className="rounded-3xl border border-red-200 bg-red-50 p-6"><h1 className="font-semibold text-red-950">Extensions unavailable</h1><p role="alert" className="mt-2 text-sm text-red-700">{state.message}</p><button type="button" onClick={load} className="mt-4 min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white">Try again</button></div></main>;

  const acknowledgingDegraded = state.effective.health === "degraded-unacknowledged";
  const recoveryBanner = <ExtensionStatusBanner busy={recoveryBusy} effective={state.effective} error={recoveryError} status={recoveryStatus} onRecover={() => { void recover(); }} onRetry={load} />;
  const recoveryModal = recoveryApprovalOpen ? <ApprovalProofModal title={acknowledgingDegraded ? "Acknowledge degraded extension controls" : "Repair extension controls"} detail={acknowledgingDegraded ? "Authenticate this acknowledgement on your device. Guard remains fail-closed until protected authority is restored." : "Authenticate this repair on your device. Guard uses the proof once and does not store it."} confirmLabel={acknowledgingDegraded ? "Acknowledge degraded state" : "Repair controls"} approvalGate={resolvedApprovalGate} busy={recoveryBusy} error={recoveryError} onCancel={() => { if (!recoveryBusy) setRecoveryApprovalOpen(false); }} onConfirm={(credentials) => { void recover(credentials); }} /> : null;

  if (routeState.route.kind === "detail" && selectedExtension) {
    return <><div className="mx-auto w-full max-w-7xl px-4 pt-6 sm:px-6 lg:px-8">{recoveryBanner}</div><ExtensionControlCenterDetail extension={selectedExtension} effective={state.effective} catalogDigest={state.catalog.catalog_digest} urlState={routeState.detail} onUrlState={updateDetailState} onBack={closeExtension} onBroadControl={() => requestBroadControl(selectedExtension)} />{pending ? <ReviewModal change={pending} busy={busy} error={mutationError} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}{recoveryModal}</>;
  }

  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return <><main className="mx-auto max-w-4xl p-6"><div>{recoveryBanner}</div><div className="mt-6 rounded-3xl border border-amber-200 bg-amber-50 p-6"><h1 className="font-semibold text-amber-950">Extension not found</h1><p className="mt-2 text-sm text-amber-800">This extension route is invalid or the canonical extension is not present in the current catalog.</p><button type="button" onClick={closeExtension} className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">Back to extensions</button></div></main>{recoveryModal}</>;
  }

  const locked = state.effective.health !== "protected";
  return <main className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
    <header className="flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-xs font-bold uppercase tracking-[0.22em] text-brand-blue">Command safety</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Extensions</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Inspect canonical command protections and review broad capability policy without changing detector truth.</p></div><button type="button" disabled={locked} onClick={() => setPending({ globalLockdown: !state.effective.global_lockdown })} className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 text-sm font-semibold ${state.effective.global_lockdown ? "bg-red-700 text-white" : "border border-slate-300 bg-white text-slate-700"} disabled:opacity-50`}><HiMiniLockClosed className="size-4" />{state.effective.global_lockdown ? "Review ending lockdown" : "Review global lockdown"}</button></header>
    <div className="mt-6">{recoveryBanner}</div>
    {state.effective.global_lockdown ? <div role="status" className="mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white"><HiMiniLockClosed className="size-5" /><span><strong>Global lockdown active.</strong> Matching capabilities are blocked regardless of optional local controls.</span></div> : null}
    <section aria-labelledby="installed-extensions" className="mt-8"><div className="flex flex-col gap-1"><div className="flex items-center justify-between gap-4"><h2 id="installed-extensions" className="text-lg font-semibold text-slate-950">Installed extensions</h2><span className="text-sm text-slate-500">{catalogExtensions.length} available</span></div><p className="text-sm text-slate-500">Search by name or command, or filter by risk, domain, and effective state.</p></div><div className="mt-4"><ExtensionsFilterBar filters={filters} onChange={(patch) => setFilters((previous) => ({ ...previous, ...patch }))} onClear={() => setFilters(EMPTY_EXTENSION_FILTERS)} extensions={catalogExtensions} effective={state.effective} /></div>{filtered.length ? <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">{filtered.map((extension) => <ExtensionCard key={extension.extension_id} extension={extension} effective={state.effective} locked={locked || state.effective.global_lockdown} onChange={(change) => { setMutationError(null); setPending(change); }} onOpen={openExtension} />)}</div> : hasActiveFilters(effectiveFilters) ? <div className="mt-5 flex flex-col items-center gap-3 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center"><HiMiniMagnifyingGlass className="size-7 text-slate-300" aria-hidden="true" /><h3 className="text-sm font-semibold text-slate-900">No extensions match these filters</h3><p className="max-w-sm text-sm text-slate-500">Try a different search term or clear the filters.</p><button type="button" onClick={() => setFilters(EMPTY_EXTENSION_FILTERS)} className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">Clear filters</button></div> : <div className="mt-5 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center text-sm text-slate-500">No extensions are registered.</div>}</section>
    <section className="mt-8 overflow-hidden rounded-3xl border border-slate-200 bg-white"><button type="button" onClick={() => setProvenanceOpen((value) => !value)} aria-expanded={provenanceOpen} className="flex min-h-11 w-full items-center justify-between p-5 text-left"><span><span className="block font-semibold text-slate-950">Policy provenance</span><span className="mt-1 block text-sm text-slate-500">Catalog {state.catalog.catalog_digest.slice(0, 12)}… · {state.effective.layers.length} authority layer{state.effective.layers.length === 1 ? "" : "s"}</span></span>{provenanceOpen ? <HiMiniChevronUp className="size-5" /> : <HiMiniChevronDown className="size-5" />}</button>{provenanceOpen ? <div className="border-t border-slate-200 p-5"><div className="grid gap-3 sm:grid-cols-2">{state.effective.layers.map((layer) => <div key={`${layer.kind}-${layer.catalog_digest}`} className="rounded-2xl bg-slate-50 p-4"><div className="flex items-center gap-2"><HiMiniCheckCircle className="size-5 text-emerald-600" /><strong className="text-sm text-slate-900">{layer.kind === "local-admin" ? "Local administrator" : "Signed cloud policy"}</strong></div><p className="mt-2 text-xs text-slate-500">{layer.controls.length} explicit controls · catalog {layer.catalog_digest.slice(0, 12)}…</p></div>)}</div></div> : null}</section>
    {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}
    {recoveryModal}
  </main>;
}
