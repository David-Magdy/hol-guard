import { useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniCloud,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";

import { commandReasonLabel } from "../../command-activity/command-activity-presenters";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../../extension-controls-api";
import { isExtensionEnabled } from "../../extensions-filters";
import { ProtectionDecisionBadge, ProtectionModuleRow } from "./protection-primitives";
import {
  filterProtectionModulesByHumanQuery,
  protectionCategorySummary,
  type ProtectionCloudContinuity,
  type ProtectionDecisionView,
  type ProtectionHealthCheck,
  type ProtectionModuleRank,
  type ProtectionModuleSection,
} from "../model/protection-landing";

function managedByOrganization(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) =>
    layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId),
  );
}

export function CloudContinuityIndicator(props: {
  continuity: ProtectionCloudContinuity;
  loading?: boolean;
}) {
  return <aside aria-label="Cloud continuity" className="flex items-start gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3">
    <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-slate-100 text-slate-800" aria-hidden="true">
      {props.loading ? <HiMiniArrowPath className="size-5 animate-spin motion-reduce:animate-none" /> : <HiMiniCloud className="size-5" />}
    </span>
    <div className="min-w-0">
      <div className="text-sm font-semibold text-slate-950">{props.loading ? "Checking Cloud continuity…" : props.continuity.label}</div>
      <p className="mt-1 text-xs leading-5 text-slate-800">{props.continuity.detail}</p>
    </div>
  </aside>;
}

export function ProtectionWatchingMap(props: {
  catalog: readonly ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
  inUseExtensionIds?: ReadonlySet<string>;
  selectedId?: string | null;
  onSelect?: (searchAlias: string, categoryId: string) => void;
}) {
  const areas = useMemo(
    () => protectionCategorySummary(props.catalog, props.effective, props.inUseExtensionIds),
    [props.catalog, props.effective, props.inUseExtensionIds],
  );
  const featured = areas.filter((area) => area.inUse > 0);
  const rest = featured.length ? areas.filter((area) => area.inUse === 0) : areas.slice(4);
  const primary = featured.length ? featured : areas.slice(0, 4);

  return <section aria-labelledby="what-guard-protects-heading" className="mt-8">
    <div>
      <h2 id="what-guard-protects-heading" className="text-xl font-semibold text-slate-950">What HOL Guard protects</h2>
      <p className="mt-1 max-w-3xl text-sm text-slate-800">Guard is watching the tools your agent uses on this device. Open an area to see the matching protections.</p>
    </div>
    <ol className="mt-4 divide-y divide-slate-200 border-y border-slate-200">
      {primary.map((area) => {
        const selected = props.selectedId === area.id;
        const status = area.inUse
          ? `${area.inUse} in use`
          : area.blocked
            ? `${area.blocked} blocked locally`
            : `${area.total} ready`;
        return <li key={area.id}>
          <button
            type="button"
            aria-pressed={selected}
            onClick={() => props.onSelect?.(area.searchAlias, area.id)}
            className={`flex min-h-16 w-full items-baseline justify-between gap-4 py-3 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${selected ? "text-brand-blue" : "text-slate-950 hover:text-brand-blue"}`}
          >
            <span className="min-w-0">
              <span className="block text-base font-semibold tracking-tight">{area.label}</span>
              <span className={`mt-0.5 block text-sm ${selected ? "text-brand-blue" : "text-slate-800"}`}>{area.description}</span>
            </span>
            <span className={`shrink-0 text-xs font-semibold ${selected ? "text-brand-blue" : "text-slate-800"}`}>{status}</span>
          </button>
        </li>;
      })}
    </ol>
    {rest.length ? <details className="mt-3">
      <summary className="cursor-pointer text-sm font-semibold text-slate-800">More areas</summary>
      <ol className="mt-2 divide-y divide-slate-200">
        {rest.map((area) => <li key={area.id}>
          <button type="button" onClick={() => props.onSelect?.(area.searchAlias, area.id)} className="flex min-h-12 w-full items-baseline justify-between gap-4 py-2 text-left text-sm text-slate-950 hover:text-brand-blue">
            <span className="font-medium">{area.label}</span>
            <span className="text-xs font-medium text-slate-800">{area.total} ready</span>
          </button>
        </li>)}
      </ol>
    </details> : null}
  </section>;
}

const SECTION_LABELS: Record<ProtectionModuleSection, string> = {
  "in-use": "In use",
  recommended: "Recommended",
  all: "All",
};

export function ProtectionModuleExplorer(props: {
  modules: readonly ProtectionModuleRank[];
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogItem) => void;
  advancedFilters?: React.ReactNode;
  focusQuery?: string;
}) {
  const hasInUse = props.modules.some((module) => module.section === "in-use");
  const [section, setSection] = useState<ProtectionModuleSection>(hasInUse ? "in-use" : "recommended");
  const sectionTouched = useRef(false);
  const [query, setQuery] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (hasInUse && !sectionTouched.current && section !== "in-use") setSection("in-use");
  }, [hasInUse, section]);
  useEffect(() => {
    if (!props.focusQuery) return;
    setQuery(props.focusQuery);
    sectionTouched.current = true;
    setSection("all");
    searchRef.current?.focus();
  }, [props.focusQuery]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const queried = useMemo(() => filterProtectionModulesByHumanQuery(props.modules, query), [props.modules, query]);
  const visible = queried.filter((module) => section === "all" || module.section === section);

  return <section aria-labelledby="protection-modules-heading" className="mt-8">
    <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 id="protection-modules-heading" className="text-xl font-semibold text-slate-950">Protection modules</h2>
        <p className="mt-1 text-sm text-slate-800">Start with tools already in use. Search or browse all when you need a specific protection.</p>
      </div>
      <span className="text-sm font-medium text-slate-800">{props.modules.length} available</span>
    </div>
    <div className="mt-4 flex flex-col gap-3 rounded-2xl border border-slate-200 bg-slate-100 p-3 sm:flex-row sm:items-center">
      <label className="relative min-w-0 flex-1">
        <span className="sr-only">Search protection modules</span>
        <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-700" aria-hidden="true" />
        <input ref={searchRef} type="search" value={query} onChange={(event) => setQuery(event.target.value.slice(0, 160))} placeholder="Search Git, packages, secrets, downloads…" className="min-h-11 w-full rounded-xl border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-slate-950 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" />
      </label>
      <div role="tablist" aria-label="Protection module groups" className="flex shrink-0 rounded-xl border border-slate-200 bg-white p-1">
        {(["in-use", "recommended", "all"] as const).map((id) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={section === id}
            disabled={id === "in-use" && !hasInUse}
            onClick={() => { sectionTouched.current = true; setSection(id); }}
            className={`min-h-9 rounded-lg px-3 text-xs font-semibold disabled:opacity-40 ${section === id ? "bg-slate-950 text-white" : "text-slate-800 hover:bg-slate-100"}`}
          >{SECTION_LABELS[id]}</button>
        ))}
      </div>
    </div>
    {props.advancedFilters ? <div className="mt-3">
      <button type="button" aria-expanded={advancedOpen} onClick={() => setAdvancedOpen((value) => !value)} className="inline-flex min-h-10 items-center gap-2 rounded-lg px-2 text-xs font-semibold text-slate-800 hover:bg-slate-100">
        Advanced filters <HiMiniChevronDown className={`size-4 transition motion-reduce:transition-none ${advancedOpen ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>
      {advancedOpen ? <div className="mt-2">{props.advancedFilters}</div> : null}
    </div> : null}
    {visible.length ? <div className="mt-4 space-y-2">{visible.map((module) => <ProtectionModuleRow key={module.extension.extension_id} name={module.extension.name} description={module.extension.description} behavior={isExtensionEnabled(props.effective, module.extension) ? "Guard defaults active" : "Blocked on this device"} required={module.extension.required} managed={managedByOrganization(props.effective, module.extension.extension_id)} onOpen={() => props.onOpen(module.extension)} />)}</div> : <div className="mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center"><p className="text-sm font-semibold text-slate-950">No protection modules match this view.</p><p className="mt-1 text-sm text-slate-800">Try All modules or a simpler search.</p></div>}
  </section>;
}

export function RecentProtectionDecisions(props: {
  decisions: readonly ProtectionDecisionView[];
  loading?: boolean;
  unavailable?: boolean;
}) {
  if (props.loading) {
    return <section aria-labelledby="recent-protection-decisions-heading" className="mt-8" aria-busy="true">
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-slate-950">Recent decisions</h2>
      <div className="guard-skeleton mt-4 h-24 w-full" />
    </section>;
  }
  if (props.unavailable) {
    return <section aria-labelledby="recent-protection-decisions-heading" className="mt-8">
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-slate-950">Recent decisions</h2>
      <p className="mt-2 text-sm text-slate-800">Recent local decision evidence could not be loaded. Protection status above remains independent of this activity view.</p>
    </section>;
  }
  return <section aria-labelledby="recent-protection-decisions-heading" className="mt-8">
    <div>
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-slate-950">Recent decisions</h2>
      <p className="mt-1 text-sm text-slate-800">Privacy-safe local evidence. Raw commands and paths are not shown.</p>
    </div>
    {props.decisions.length ? <div className="mt-3 divide-y divide-slate-200 border-y border-slate-200">{props.decisions.map((decision) => <article key={decision.activityId} className="py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <ProtectionDecisionBadge result={decision.result} />
          <strong className="text-sm text-slate-950">{decision.extensionNames.length ? decision.extensionNames.join(", ") : "Guard protection"}</strong>
        </div>
        <time className="text-xs font-medium text-slate-800" dateTime={decision.occurredAt}>{new Date(decision.occurredAt).toLocaleString()}</time>
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs font-semibold text-brand-blue">Why?</summary>
        <p className="mt-2 text-sm leading-6 text-slate-800">{commandReasonLabel(decision.reasonCode)}</p>
      </details>
    </article>)}</div> : <p className="mt-3 text-sm text-slate-800">No recent local command decisions are recorded yet.</p>}
  </section>;
}

export function ProtectionHealthCheckPanel(props: {
  result: ProtectionHealthCheck | null;
  busy: boolean;
  error?: string | null;
  onRun: () => void;
}) {
  return <section aria-labelledby="protection-health-check-heading" className="mt-8 rounded-2xl border border-slate-200 bg-white p-5">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h2 id="protection-health-check-heading" className="text-lg font-semibold text-slate-950">Protection health check</h2>
        <p className="mt-1 max-w-2xl text-sm text-slate-800">Safely re-read Guard's local catalog, trusted settings, and runtime. This check does not execute a command or change protection.</p>
      </div>
      <button type="button" onClick={props.onRun} disabled={props.busy} aria-busy={props.busy} className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50 disabled:opacity-60">
        {props.busy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <HiMiniCheckCircle className="size-4" aria-hidden="true" />}
        {props.busy ? "Checking…" : "Run health check"}
      </button>
    </div>
    {props.error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800">{props.error}</p> : null}
    {props.result ? <div role="status" aria-live="polite" className={`mt-4 rounded-xl border p-4 ${props.result.status === "healthy" ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`}>
      <div className="flex items-start gap-2">
        {props.result.status === "healthy" ? <HiMiniCheckCircle className="mt-0.5 size-5 shrink-0 text-emerald-800" /> : <HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0 text-amber-800" />}
        <p className="text-sm font-medium text-slate-950">{props.result.summary}</p>
      </div>
      <ul className="mt-3 space-y-1.5">{props.result.checks.map((check) => <li key={check.id} className="flex items-center gap-2 text-xs text-slate-800"><span aria-hidden="true">{check.passed ? "✓" : "•"}</span>{check.label}</li>)}</ul>
    </div> : null}
  </section>;
}
