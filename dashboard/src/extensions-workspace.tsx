import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniChevronRight,
  HiMiniClipboard,
  HiMiniExclamationTriangle,
  HiMiniLockClosed,
  HiMiniPuzzlePiece,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import { ApprovalProofModal } from "./approval-proof-modal";
import { ExtensionControlCenterDetail } from "./extension-control-center-detail";
import { canonicalExtensionId, extensionDetailHref, extensionIdFromSearch } from "./extension-control-center-model";
import {
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

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type ExtensionMutationTarget = Pick<ExtensionCatalogItem, "extension_id" | "name">;
type PendingChange = { extension: ExtensionMutationTarget; enabled: boolean } | { globalLockdown: boolean };

export type ExtensionRecoveryAction = { copyLabel: string; command: string; description: string; title: string };

export function extensionRecoveryAction(health: EffectiveExtensionControls["health"]): ExtensionRecoveryAction | null {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority",
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
  const copy = useCallback(async () => {
    if (!recovery) return;
    try { await navigator.clipboard.writeText(recovery.command); setCopyState("copied"); }
    catch { setCopyState("failed"); }
  }, [recovery]);
  if (props.effective.health === "protected") {
    return <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"><HiMiniShieldCheck className="size-5" /><span><strong>Protected authority</strong> · revision {props.effective.revision}</span></div>;
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required";
  return <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5"><div className="flex gap-3"><HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0 text-amber-700" /><div className="min-w-0 flex-1"><h2 className="font-semibold text-slate-950">{recovery?.title}</h2><p className="mt-1 text-sm text-slate-700">{recovery?.description}</p><div className="mt-4 flex flex-wrap gap-2">{repairable && props.onRecover ? <button type="button" aria-busy={props.busy} disabled={props.busy} onClick={props.onRecover} className="rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">{props.busy ? "Repairing…" : "Repair now"}</button> : null}<button type="button" onClick={props.onRetry} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700">Check again</button></div><div className="mt-4 border-t border-amber-200 pt-3"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Command-line fallback</p><div className="mt-2 flex gap-2"><code className="min-w-0 flex-1 overflow-x-auto rounded-lg bg-white px-3 py-2 text-xs">{recovery?.command}</code><button type="button" onClick={copy} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 text-sm font-semibold"><HiMiniClipboard className="size-4" />{copyState === "copied" ? "Copied" : recovery?.copyLabel}</button></div>{copyState === "failed" ? <p role="status" className="mt-2 text-sm text-red-700">Copy failed. Select the command above.</p> : null}</div>{props.error ? <p role="alert" className="mt-3 text-sm font-medium text-red-700">{props.error}</p> : null}{props.status ? <p role="status" className="mt-3 text-sm font-medium text-slate-800">{props.status}</p> : null}</div></div></div>;
}

function ExtensionCard(props: {
  extension: ExtensionCatalogItem;
  enabled: boolean;
  locked: boolean;
  onChange: (change: PendingChange) => void;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const domain = classifyDomain(props.extension.extension_id);
  const risks = props.extension.risk_classes.filter((risk): risk is RiskClass => risk in RISK_CLASS_LABELS);
  return <article className="group flex min-h-60 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)]">
    <div className="flex items-start justify-between gap-4"><span className="grid size-11 place-items-center rounded-2xl bg-blue-50 text-brand-blue"><HiMiniPuzzlePiece className="size-6" /></span><button type="button" role="switch" aria-checked={props.enabled} aria-label={`${props.enabled ? "Disable" : "Enable"} ${props.extension.name}`} disabled={props.locked || props.extension.required} onClick={() => props.onChange({ extension: props.extension, enabled: !props.enabled })} className={`relative h-7 w-12 rounded-full ${props.enabled ? "bg-brand-blue" : "bg-slate-300"} disabled:opacity-50`}><span className={`absolute top-1 size-5 rounded-full bg-white shadow transition ${props.enabled ? "left-6" : "left-1"}`} /></button></div>
    <div className="mt-5 flex flex-wrap items-center gap-2"><h2 className="font-semibold text-slate-950">{props.extension.name}</h2>{props.extension.required ? <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase text-brand-blue">Required</span> : null}</div>
    <p className="mt-2 line-clamp-3 text-sm leading-6 text-slate-600">{props.extension.description}</p>
    {risks.length ? <div className="mt-3 flex flex-wrap gap-1">{risks.map((risk) => <span key={risk} className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`}>{RISK_CLASS_LABELS[risk]}</span>)}</div> : null}
    <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-500"><span>{DOMAIN_LABELS[domain]}</span><span>·</span><span>{props.extension.permission_count} permissions</span><span>·</span><span>{props.extension.rule_count} rules</span><span>·</span><span>v{props.extension.version}</span></div>
    <button type="button" aria-label={`Open ${props.extension.name} controls`} onClick={() => props.onOpen(props.extension)} className="mt-auto flex items-center justify-between border-t border-slate-100 pt-4 text-left text-sm font-semibold text-brand-blue"><span>Inspect commands and permissions</span><HiMiniChevronRight className="size-4" /></button>
  </article>;
}

function ReviewModal(props: { change: PendingChange; busy: boolean; error: string | null; onCancel: () => void; onConfirm: (password: string, totp: string) => void }) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown` : `${props.change.enabled ? "Enable" : "Disable"} ${props.change.extension.name}`;
  return <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4"><form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="extension-review-title" onSubmit={(event) => { event.preventDefault(); props.onConfirm(password, totp); }} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none"><div className="flex justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-wide text-brand-blue">Review control change</p><h2 id="extension-review-title" className="mt-2 text-xl font-semibold">{title}</h2></div><button type="button" aria-label="Close review" disabled={props.busy} onClick={props.onCancel}><HiMiniXMark className="size-5" /></button></div><label className="mt-5 block text-sm font-medium">Approval password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5" /></label><label className="mt-4 block text-sm font-medium">Authenticator code<input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(event) => setTotp(event.target.value)} className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5" /></label>{props.error ? <p role="alert" className="mt-4 text-sm text-red-700">{props.error}</p> : null}<div className="mt-6 flex justify-end gap-3"><button type="button" disabled={props.busy} onClick={props.onCancel}>Cancel</button><button type="submit" disabled={props.busy} className="rounded-xl bg-brand-blue px-5 py-2.5 text-sm font-semibold text-white disabled:opacity-60">{props.busy ? "Verifying…" : "Confirm change"}</button></div></form></div>;
}

export function ExtensionsWorkspace() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [pending, setPending] = useState<PendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const [filters, setFilters] = useState<ExtensionFilterState>(EMPTY_EXTENSION_FILTERS);
  const [selectedExtensionId, setSelectedExtensionId] = useState(() => extensionIdFromSearch(window.location.search));
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const onPopState = () => setSelectedExtensionId(extensionIdFromSearch(window.location.search));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const catalogExtensions = useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const canonicalSelected = useMemo(() => canonicalExtensionId(catalogExtensions, selectedExtensionId), [catalogExtensions, selectedExtensionId]);
  const selectedExtension = useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = useMemo<ExtensionFilterState>(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);

  const openExtension = useCallback((extension: ExtensionCatalogItem) => {
    window.history.pushState({}, "", extensionDetailHref(extension.extension_id));
    setSelectedExtensionId(extension.extension_id);
    window.scrollTo({ top: 0 });
  }, []);
  const closeExtension = useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setSelectedExtensionId(null);
    window.scrollTo({ top: 0 });
  }, []);
  const confirm = useCallback(async (password: string, totp: string) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true); setMutationError(null);
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
    } finally { setBusy(false); }
  }, [load, pending, state]);
  const recover = useCallback(async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
    setRecoveryBusy(true); setRecoveryError(null); setRecoveryStatus("Repairing extension controls…");
    try {
      const effective = await recoverExtensionControlAuthority(credentials);
      if (effective.health !== "protected") throw new Error("Guard could not restore protected extension controls.");
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false); setRecoveryStatus("Extension controls repaired.");
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        await resolveApprovalGate(); setRecoveryApprovalOpen(true);
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair extension controls."); setRecoveryStatus(null);
      }
    } finally { setRecoveryBusy(false); }
  }, [resolveApprovalGate, state]);

  if (state.kind === "loading") return <main className="grid min-h-[60vh] place-items-center" aria-busy="true"><HiMiniArrowPath className="size-7 animate-spin text-brand-blue" /></main>;
  if (state.kind === "error") return <main className="mx-auto max-w-5xl p-6"><div className="rounded-3xl border border-red-200 bg-red-50 p-6"><h1 className="font-semibold text-red-950">Extensions unavailable</h1><p className="mt-2 text-sm text-red-700">{state.message}</p><button type="button" onClick={load} className="mt-4 rounded-xl bg-red-700 px-4 py-2 text-sm font-semibold text-white">Try again</button></div></main>;

  const recoveryBanner = <ExtensionStatusBanner busy={recoveryBusy} effective={state.effective} error={recoveryError} status={recoveryStatus} onRecover={() => { void recover(); }} onRetry={load} />;
  const recoveryModal = recoveryApprovalOpen ? <ApprovalProofModal title="Repair extension controls" detail="Authenticate this repair on your device. Guard uses the proof once and does not store it." confirmLabel="Repair controls" approvalGate={resolvedApprovalGate} busy={recoveryBusy} error={recoveryError} onCancel={() => { if (!recoveryBusy) setRecoveryApprovalOpen(false); }} onConfirm={(credentials) => { void recover(credentials); }} /> : null;

  if (selectedExtensionId && selectedExtension) return <><div className="mx-auto w-full max-w-7xl px-4 pt-6 sm:px-6 lg:px-8">{recoveryBanner}</div><ExtensionControlCenterDetail extension={selectedExtension} effective={state.effective} onBack={closeExtension} />{recoveryModal}</>;
  if (selectedExtensionId) return <><main className="mx-auto max-w-4xl p-6"><div>{recoveryBanner}</div><div className="mt-6 rounded-3xl border border-amber-200 bg-amber-50 p-6"><h1 className="font-semibold text-amber-950">Extension not found</h1><p className="mt-2 text-sm text-amber-800">This stable extension ID is not present in the current catalog.</p><button type="button" onClick={closeExtension} className="mt-4 rounded-xl bg-brand-blue px-4 py-2 text-sm font-semibold text-white">Back to extensions</button></div></main>{recoveryModal}</>;

  const locked = state.effective.health !== "protected";
  return <main className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
    <header className="flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-xs font-bold uppercase tracking-[0.22em] text-brand-blue">Command safety</p><h1 className="mt-2 text-3xl font-semibold text-slate-950">Extensions</h1><p className="mt-2 max-w-2xl text-sm text-slate-600">Inspect and govern the capabilities Guard uses to understand development commands.</p></div><button type="button" disabled={locked} onClick={() => setPending({ globalLockdown: !state.effective.global_lockdown })} className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold disabled:opacity-50"><HiMiniLockClosed className="size-4" />{state.effective.global_lockdown ? "Disable lockdown" : "Enable lockdown"}</button></header>
    <div className="mt-6">{recoveryBanner}</div>
    <section aria-labelledby="installed-extensions" className="mt-8"><div className="flex items-center justify-between gap-4"><div><h2 id="installed-extensions" className="text-lg font-semibold text-slate-950">Installed extensions</h2><p className="mt-1 text-sm text-slate-500">Open an extension to inspect its permissions and command rules.</p></div><span className="text-sm text-slate-500">{catalogExtensions.length} available</span></div><div className="mt-4"><ExtensionsFilterBar filters={filters} onChange={(patch) => setFilters((previous) => ({ ...previous, ...patch }))} onClear={() => setFilters(EMPTY_EXTENSION_FILTERS)} extensions={catalogExtensions} effective={state.effective} /></div>{filtered.length ? <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">{filtered.map((extension) => <ExtensionCard key={extension.extension_id} extension={extension} enabled={isExtensionEnabled(state.effective, extension)} locked={locked || state.effective.global_lockdown} onChange={(change) => { setMutationError(null); setPending(change); }} onOpen={openExtension} />)}</div> : <div className="mt-5 rounded-3xl border border-dashed border-slate-300 bg-white p-10 text-center text-sm text-slate-500">{hasActiveFilters(effectiveFilters) ? "No extensions match these filters." : "No extensions are registered."}</div>}</section>
    {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}
    {recoveryModal}
  </main>;
}
