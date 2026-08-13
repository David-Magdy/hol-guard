import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import type { ProtectionDensity, ProtectionStatusView } from "../model/protection-presentation";
import { readProtectionDensity, writeProtectionDensity } from "../model/protection-presentation";

export function useProtectionDensity(): [ProtectionDensity, (density: ProtectionDensity) => void] {
  const [density, setDensity] = useState<ProtectionDensity>(() => readProtectionDensity());
  const update = useCallback((next: ProtectionDensity) => {
    writeProtectionDensity(next);
    setDensity(next);
  }, []);
  return [density, update];
}

export function ProtectionDensityControl(props: {
  value: ProtectionDensity;
  onChange: (density: ProtectionDensity) => void;
}) {
  const choices: Array<{ value: ProtectionDensity; label: string }> = [
    { value: "simple", label: "Simple" },
    { value: "advanced", label: "Advanced" },
    { value: "developer", label: "Developer" },
  ];
  return <div role="radiogroup" aria-label="Information detail" className="flex w-full max-w-full flex-wrap rounded-xl border border-slate-200 bg-slate-50 p-1 sm:inline-flex sm:w-auto sm:flex-nowrap">
    {choices.map((choice) => <button
      key={choice.value}
      type="button"
      role="radio"
      aria-checked={props.value === choice.value}
      onClick={() => props.onChange(choice.value)}
      className={`min-h-10 min-w-0 flex-1 rounded-lg px-2.5 text-xs font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:flex-none sm:px-3 ${props.value === choice.value ? "bg-white text-brand-blue shadow-sm" : "text-slate-600 hover:bg-white"}`}
    >{choice.label}</button>)}
  </div>;
}

const HERO_TONE: Record<ProtectionStatusView["tone"], string> = {
  safe: "border-emerald-200 bg-emerald-50 text-emerald-950",
  attention: "border-amber-200 bg-amber-50 text-amber-950",
  danger: "border-red-200 bg-red-50 text-red-950",
  neutral: "border-slate-200 bg-slate-50 text-slate-950",
};

export function ProtectionStatusHero(props: {
  status: ProtectionStatusView;
  busy?: boolean;
  onPrimaryAction?: () => void;
  children?: React.ReactNode;
}) {
  const safe = props.status.tone === "safe";
  return <section aria-labelledby="protection-status-heading" className={`rounded-3xl border p-5 sm:p-6 ${HERO_TONE[props.status.tone]}`}>
    <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <div className="flex items-center gap-3">
          <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-white/80" aria-hidden="true">
            {safe ? <HiMiniShieldCheck className="size-6" /> : <HiMiniExclamationTriangle className="size-6" />}
          </span>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] opacity-70">Local protection</p>
            <h2 id="protection-status-heading" className="mt-1 text-2xl font-semibold tracking-tight">{props.status.title}</h2>
          </div>
        </div>
        <p className="mt-4 max-w-2xl text-sm leading-6 opacity-85">{props.status.summary}</p>
      </div>
      {props.status.primaryActionLabel && props.onPrimaryAction ? <button
        type="button"
        aria-busy={props.busy}
        disabled={props.busy}
        onClick={props.onPrimaryAction}
        className="min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60"
      >{props.busy ? "Working…" : props.status.primaryActionLabel}</button> : <span className="inline-flex min-h-10 items-center gap-2 self-start rounded-full border border-current/15 bg-white/70 px-3 text-xs font-semibold"><HiMiniCheckCircle className="size-4" />No action required</span>}
    </div>
    {props.children ? <div className="mt-5 border-t border-current/10 pt-4">{props.children}</div> : null}
  </section>;
}

export function ProtectionDecisionBadge({ result }: { result: "allowed" | "ask-first" | "blocked" }) {
  const label = result === "allowed" ? "Allowed" : result === "ask-first" ? "Ask first" : "Blocked";
  const classes = result === "allowed" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : result === "ask-first" ? "border-amber-200 bg-amber-50 text-amber-800" : "border-red-200 bg-red-50 text-red-800";
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${classes}`}>{label}</span>;
}

export function ProtectionModuleRow(props: {
  name: string;
  description: string;
  behavior: string;
  required?: boolean;
  managed?: boolean;
  onOpen: () => void;
}) {
  return <button type="button" onClick={props.onOpen} className="flex min-h-20 w-full items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-left transition hover:border-blue-200 hover:bg-blue-50/30 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue motion-reduce:transition-none">
    <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-blue-50 text-brand-blue" aria-hidden="true"><HiMiniShieldCheck className="size-5" /></span>
    <span className="min-w-0 flex-1">
      <span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-slate-950">{props.name}</strong>{props.required ? <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-600">Required</span> : null}{props.managed ? <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-semibold text-indigo-700">Managed</span> : null}</span>
      <span className="mt-1 block line-clamp-2 text-sm leading-5 text-slate-600">{props.description}</span>
    </span>
    <span className="hidden shrink-0 text-xs font-semibold text-slate-600 sm:inline">{props.behavior}</span>
    <HiMiniChevronRight className="size-5 shrink-0 text-slate-400" aria-hidden="true" />
  </button>;
}

export function SettingSource({ source }: { source: "built-in" | "device" | "organization" }) {
  const label = source === "organization" ? "Managed by your organization" : source === "device" ? "Set on this device" : "Built in to Guard";
  return <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600"><HiMiniInformationCircle className="size-4" aria-hidden="true" />{label}</span>;
}

export function WhyThisHappened(props: { summary: string; children?: React.ReactNode }) {
  return <details className="rounded-2xl border border-slate-200 bg-white p-4"><summary className="cursor-pointer list-none font-semibold text-slate-900"><span className="inline-flex items-center gap-2">Why this setting?<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><p className="mt-3 text-sm leading-6 text-slate-600">{props.summary}</p>{props.children ? <div className="mt-3">{props.children}</div> : null}</details>;
}

export function TechnicalDetails(props: { title?: string; children: React.ReactNode }) {
  return <details className="rounded-2xl border border-slate-200 bg-slate-50 p-4"><summary className="cursor-pointer list-none text-sm font-semibold text-slate-700"><span className="inline-flex items-center gap-2">{props.title ?? "Technical details"}<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><div className="mt-4 text-sm text-slate-700">{props.children}</div></details>;
}

export function RecoveryProgress(props: { currentStep: number; steps: readonly string[] }) {
  return <ol aria-label="Repair progress" className="space-y-2">{props.steps.map((step, index) => <li key={step} className={`flex items-center gap-2 text-sm ${index < props.currentStep ? "text-emerald-700" : index === props.currentStep ? "font-semibold text-slate-950" : "text-slate-400"}`}><span className="grid size-6 shrink-0 place-items-center rounded-full border border-current/30 text-xs">{index < props.currentStep ? "✓" : index + 1}</span>{step}</li>)}</ol>;
}

export function InlineError({ message }: { message: string }) {
  return <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{message}</p>;
}

export function AsyncActionButton(props: React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean; busyLabel?: string }) {
  const { busy, busyLabel, children, className = "", disabled, ...buttonProps } = props;
  return <button {...buttonProps} type={buttonProps.type ?? "button"} aria-busy={busy} disabled={disabled || busy} className={`min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60 ${className}`}>{busy ? busyLabel ?? "Working…" : children}</button>;
}
