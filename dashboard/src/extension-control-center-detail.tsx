import { useCallback, useMemo, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
  ExtensionRule,
} from "./extension-controls-api";
import {
  extensionEffectiveState,
  explicitControlState,
  permissionEffectiveState,
  permissionForRule,
  permissionRelations,
  treatmentLabel,
  type ExtensionDetailTab,
} from "./extension-control-center-model";
import { useModalDialog } from "./use-modal-dialog";

const RISK_TONE: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700",
};

function Pill({ children, tone = "border-slate-200 bg-slate-50 text-slate-700" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`}>{children}</span>;
}

function Definition({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</dt><dd className="mt-1 text-sm text-slate-900">{children}</dd></div>;
}

function PermissionInspector(props: {
  effective: EffectiveExtensionControls;
  extension: ExtensionCatalogItem;
  permission: ExtensionPermission;
  onClose: () => void;
}) {
  const dialogRef = useModalDialog<HTMLElement>(props.onClose);
  const relations = permissionRelations(props.extension, props.permission);
  const effectiveState = permissionEffectiveState(props.effective, props.extension, props.permission);
  const explicitState = explicitControlState(props.effective, "permission", props.permission.permission_id);
  return (
    <aside ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="permission-inspector-title" className="fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-6 shadow-2xl focus:outline-none">
      <div className="flex items-start justify-between gap-4">
        <div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Permission</p><h2 id="permission-inspector-title" className="mt-2 text-2xl font-semibold text-slate-950">{props.permission.label}</h2><code className="mt-2 block break-all text-xs text-slate-500">{props.permission.permission_id}</code></div>
        <button type="button" onClick={props.onClose} aria-label="Close permission details" className="rounded-full p-2 text-slate-500 hover:bg-slate-100"><HiMiniXMark className="size-5" /></button>
      </div>
      <p className="mt-5 text-sm leading-6 text-slate-600">{props.permission.description}</p>
      <div className="mt-5 flex flex-wrap gap-2"><Pill tone={RISK_TONE[props.permission.risk_tier]}>{props.permission.risk_tier} baseline risk</Pill><Pill>{effectiveState === "enabled" ? "Enabled" : "Disabled"}</Pill>{!props.permission.configurable ? <Pill>Fixed protection</Pill> : null}{props.permission.deprecated ? <Pill tone="border-amber-200 bg-amber-50 text-amber-800">Deprecated</Pill> : null}</div>
      <section className="mt-7 rounded-2xl border border-slate-200 bg-slate-50 p-5" aria-labelledby="permission-effective-heading">
        <div className="flex items-center gap-2"><HiMiniShieldCheck className="size-5 text-brand-blue" /><h3 id="permission-effective-heading" className="font-semibold text-slate-950">Baseline and effective behavior</h3></div>
        <dl className="mt-4 grid gap-4 sm:grid-cols-2"><Definition label="Baseline floor">{treatmentLabel(props.permission.baseline_floor)}</Definition><Definition label="Default state">{props.permission.default_enabled ? "Enabled" : "Disabled"}</Definition><Definition label="Explicit local/cloud state">{explicitState ?? "Inherited"}</Definition><Definition label="Effective state">{effectiveState}</Definition></dl>
        <p className="mt-4 text-xs leading-5 text-slate-500">Baseline risk and the baseline action floor are detector metadata. This view does not rewrite either value.</p>
      </section>
      <section className="mt-7" aria-labelledby="permission-rules-heading"><h3 id="permission-rules-heading" className="font-semibold text-slate-950">Governed rules</h3><div className="mt-3 space-y-2">{props.permission.rule_ids.map((ruleId) => { const rule = props.extension.rules.find((item) => item.rule_id === ruleId); return <div key={ruleId} className="rounded-xl border border-slate-200 px-3 py-2"><div className="text-sm font-medium text-slate-900">{rule?.title ?? ruleId}</div><code className="text-[11px] text-slate-500">{ruleId}</code></div>; })}</div></section>
      <section className="mt-7" aria-labelledby="permission-relations-heading"><h3 id="permission-relations-heading" className="font-semibold text-slate-950">Relationships</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Definition label="Depends on">{relations.dependencies.length ? relations.dependencies.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Conflicts with">{relations.conflicts.length ? relations.conflicts.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Implies">{relations.implied.length ? relations.implied.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Capabilities">{props.permission.typed_capabilities.length ? props.permission.typed_capabilities.join(", ") : "Rule-derived"}</Definition></dl>{relations.missing.length ? <p role="status" className="mt-3 text-xs text-amber-700">Referenced permission metadata is not present in this extension version: {relations.missing.join(", ")}.</p> : null}</section>
      <section className="mt-7" aria-labelledby="permission-guidance-heading"><h3 id="permission-guidance-heading" className="font-semibold text-slate-950">Safer guidance</h3>{props.permission.safer_guidance.length ? <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600">{props.permission.safer_guidance.map((guidance) => <li key={guidance}>{guidance}</li>)}</ul> : <p className="mt-2 text-sm text-slate-500">No alternate workflow is registered.</p>}{props.permission.fixed_reason ? <p className="mt-4 rounded-xl bg-slate-50 px-3 py-2 text-sm text-slate-600"><strong>Why fixed:</strong> {props.permission.fixed_reason}</p> : null}</section>
    </aside>
  );
}

function RuleInspector(props: { extension: ExtensionCatalogItem; rule: ExtensionRule; onClose: () => void }) {
  const dialogRef = useModalDialog<HTMLElement>(props.onClose);
  const permission = permissionForRule(props.extension, props.rule);
  return (
    <aside ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="rule-inspector-title" className="fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-6 shadow-2xl focus:outline-none">
      <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Command rule</p><h2 id="rule-inspector-title" className="mt-2 text-2xl font-semibold text-slate-950">{props.rule.title}</h2><code className="mt-2 block break-all text-xs text-slate-500">{props.rule.rule_id}</code></div><button type="button" onClick={props.onClose} aria-label="Close rule details" className="rounded-full p-2 text-slate-500 hover:bg-slate-100"><HiMiniXMark className="size-5" /></button></div>
      <p className="mt-5 text-sm leading-6 text-slate-600">{props.rule.description}</p><div className="mt-5 flex flex-wrap gap-2"><Pill tone={RISK_TONE[props.rule.severity]}>{props.rule.severity} detector severity</Pill><Pill>{treatmentLabel(props.rule.default_mode)} default mode</Pill><Pill>{props.rule.matcher_kind}</Pill></div>
      <dl className="mt-7 grid gap-5 sm:grid-cols-2"><Definition label="Permission owner">{permission?.label ?? "Compatibility rule"}</Definition><Definition label="Rule version">{String(props.rule.rule_version)}</Definition><Definition label="Action classes">{props.rule.action_classes.join(", ") || "None"}</Definition><Definition label="Risk classes">{props.rule.risk_classes.join(", ") || "None"}</Definition></dl>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Safe variants</h3>{props.rule.safe_variants.length ? <div className="mt-3 space-y-2">{props.rule.safe_variants.map((variant) => <div key={variant.variant_id} className="rounded-xl border border-slate-200 p-3"><div className="text-sm font-medium text-slate-900">{variant.title}</div><div className="mt-1 text-xs text-slate-500">{variant.matcher_kind} · {variant.variant_id}</div></div>)}</div> : <p className="mt-2 text-sm text-slate-500">No explicit safe variants are registered.</p>}</section>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Safer alternatives</h3>{props.rule.safer_alternatives.length ? <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600">{props.rule.safer_alternatives.map((alternative) => <li key={alternative}>{alternative}</li>)}</ul> : <p className="mt-2 text-sm text-slate-500">No alternate workflow is registered.</p>}</section>
      {props.rule.compatibility_fallback ? <div className="mt-7 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900"><HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0" /><span>This is a compatibility fallback. Guard may use it when structured matching cannot establish a narrower rule.</span></div> : null}
    </aside>
  );
}

export function ExtensionControlCenterDetail(props: { extension: ExtensionCatalogItem; effective: EffectiveExtensionControls; onBack: () => void }) {
  const [tab, setTab] = useState<ExtensionDetailTab>("overview");
  const [permission, setPermission] = useState<ExtensionPermission | null>(null);
  const [rule, setRule] = useState<ExtensionRule | null>(null);
  const extensionState = extensionEffectiveState(props.effective, props.extension);
  const explicitState = explicitControlState(props.effective, "extension", props.extension.extension_id);
  const permissionSummary = useMemo(() => {
    const enabled = props.extension.permissions.filter((item) => permissionEffectiveState(props.effective, props.extension, item) === "enabled").length;
    return { enabled, disabled: props.extension.permissions.length - enabled };
  }, [props.effective, props.extension]);
  const openPermission = useCallback((item: ExtensionPermission) => setPermission(item), []);
  const openRule = useCallback((item: ExtensionRule) => setRule(item), []);
  const tabs: ExtensionDetailTab[] = ["overview", "permissions", "rules"];

  return (
    <main data-testid="extension-control-center-detail" className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      <button type="button" onClick={props.onBack} className="inline-flex items-center gap-2 text-sm font-semibold text-slate-600 hover:text-brand-blue"><HiMiniArrowLeft className="size-4" />All extensions</button>
      <header className="mt-5 rounded-3xl border border-slate-200 bg-white p-6 shadow-[0_10px_30px_rgba(15,23,42,0.05)]"><div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0"><p className="text-xs font-bold uppercase tracking-[0.2em] text-brand-blue">Extension control center</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">{props.extension.name}</h1><code className="mt-2 block break-all text-xs text-slate-500">{props.extension.extension_id}</code><p className="mt-4 max-w-3xl text-sm leading-6 text-slate-600">{props.extension.description}</p></div><div className="flex flex-wrap gap-2"><Pill tone={extensionState === "enabled" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700"}>{extensionState === "enabled" ? "Enabled" : "Disabled"}</Pill>{props.extension.required ? <Pill>Required</Pill> : null}<Pill>{props.extension.source}</Pill><Pill>v{props.extension.version}</Pill></div></div><div className="mt-6 grid gap-3 sm:grid-cols-3"><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{props.extension.permission_count}</div><div className="text-xs text-slate-500">Permissions</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{props.extension.rule_count}</div><div className="text-xs text-slate-500">Rules</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{props.extension.risk_classes.length}</div><div className="text-xs text-slate-500">Risk classes</div></div></div></header>
      <nav aria-label="Extension detail sections" className="mt-6 flex gap-1 overflow-x-auto border-b border-slate-200" role="tablist">{tabs.map((item) => <button key={item} type="button" role="tab" aria-selected={tab === item} onClick={() => setTab(item)} className={`border-b-2 px-4 py-3 text-sm font-semibold capitalize ${tab === item ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:text-slate-900"}`}>{item}</button>)}</nav>
      {tab === "overview" ? <div className="mt-6 grid gap-5 lg:grid-cols-2"><section className="rounded-3xl border border-slate-200 bg-white p-5"><div className="flex items-center gap-2"><HiMiniShieldCheck className="size-5 text-brand-blue" /><h2 className="font-semibold text-slate-950">Effective protection</h2></div><dl className="mt-5 grid gap-4 sm:grid-cols-2"><Definition label="Extension state">{extensionState}</Definition><Definition label="Explicit policy">{explicitState ?? "Inherited"}</Definition><Definition label="Global lockdown">{props.effective.global_lockdown ? "Active" : "Off"}</Definition><Definition label="Authority">{props.effective.health}</Definition><Definition label="Permissions enabled">{permissionSummary.enabled}</Definition><Definition label="Permissions disabled">{permissionSummary.disabled}</Definition></dl><div className="mt-5 flex gap-3 rounded-xl bg-blue-50 p-4 text-sm text-slate-700"><HiMiniInformationCircle className="mt-0.5 size-5 shrink-0 text-brand-blue" /><p>Detector severity and permission baseline floors are immutable metadata here. Later policy controls can change effective treatment only within Guard safety floors.</p></div></section><section className="rounded-3xl border border-slate-200 bg-white p-5"><h2 className="font-semibold text-slate-950">Capability relationships</h2><dl className="mt-5 space-y-5"><Definition label="Depends on">{props.extension.dependencies.join(", ") || "None"}</Definition><Definition label="Conflicts with">{props.extension.conflicts.join(", ") || "None"}</Definition><Definition label="Executables">{props.extension.executables.join(", ") || "Detected structurally"}</Definition><Definition label="Ecosystems">{props.extension.ecosystem_ids.join(", ") || "General development tooling"}</Definition></dl>{props.extension.delegated_protection ? <div className="mt-5 flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700"><HiMiniLockClosed className="mt-0.5 size-5 shrink-0" /><span>Protection is delegated to <strong>{props.extension.delegated_protection}</strong>.</span></div> : null}</section></div> : null}
      {tab === "permissions" ? <section aria-labelledby="extension-permissions-heading" className="mt-6"><div className="flex items-end justify-between gap-4"><div><h2 id="extension-permissions-heading" className="text-lg font-semibold text-slate-950">Permission inventory</h2><p className="mt-1 text-sm text-slate-500">Independently governed capabilities and the rules they own.</p></div><span className="text-sm text-slate-500">{props.extension.permissions.length} total</span></div><div className="mt-4 space-y-3">{props.extension.permissions.map((item) => { const state = permissionEffectiveState(props.effective, props.extension, item); return <button key={item.permission_id} type="button" onClick={() => openPermission(item)} className="flex w-full items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 hover:shadow-sm"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-slate-950">{item.label}</span><Pill tone={RISK_TONE[item.risk_tier]}>{item.risk_tier}</Pill><Pill>{state}</Pill>{!item.configurable ? <Pill>fixed</Pill> : null}</div><p className="mt-2 line-clamp-2 text-sm text-slate-600">{item.description}</p><div className="mt-2 text-xs text-slate-500">Baseline floor: {treatmentLabel(item.baseline_floor)} · {item.rule_ids.length} rule{item.rule_ids.length === 1 ? "" : "s"}</div><code className="mt-1 block truncate text-[11px] text-slate-400">{item.permission_id}</code></div><HiMiniChevronRight className="size-5 shrink-0 text-slate-400" /></button>; })}</div></section> : null}
      {tab === "rules" ? <section aria-labelledby="extension-rules-heading" className="mt-6"><div className="flex items-end justify-between gap-4"><div><h2 id="extension-rules-heading" className="text-lg font-semibold text-slate-950">Rule inventory</h2><p className="mt-1 text-sm text-slate-500">Stable detector identities, matcher types, severities, and safe variants.</p></div><span className="text-sm text-slate-500">{props.extension.rules.length} total</span></div>{props.extension.rules.length ? <div className="mt-4 space-y-3">{props.extension.rules.map((item) => <button key={item.rule_id} type="button" onClick={() => openRule(item)} className="flex w-full items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 hover:shadow-sm"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-slate-950">{item.title}</span><Pill tone={RISK_TONE[item.severity]}>{item.severity}</Pill><Pill>{treatmentLabel(item.default_mode)}</Pill></div><p className="mt-2 line-clamp-2 text-sm text-slate-600">{item.description}</p><code className="mt-2 block truncate text-xs text-slate-500">{item.rule_id}</code></div><HiMiniChevronRight className="size-5 shrink-0 text-slate-400" /></button>)}</div> : <div className="mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500">This extension delegates protection and has no local command rules.</div>}</section> : null}
      {permission ? <PermissionInspector effective={props.effective} extension={props.extension} permission={permission} onClose={() => setPermission(null)} /> : null}
      {rule ? <RuleInspector extension={props.extension} rule={rule} onClose={() => setRule(null)} /> : null}
    </main>
  );
}
