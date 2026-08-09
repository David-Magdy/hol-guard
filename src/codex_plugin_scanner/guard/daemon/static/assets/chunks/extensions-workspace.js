import { r as reactExports, j as jsxRuntimeExports, an as HiMiniArrowLeft, o as HiMiniShieldCheck, ao as HiMiniInformationCircle, Z as HiMiniLockClosed, c as HiMiniChevronRight, w as HiMiniXMark, J as HiMiniExclamationTriangle, ap as fetchExtensionControlApi, $ as HiMiniAdjustmentsHorizontal, ak as HiMiniMagnifyingGlass, V as HiMiniClipboard, aq as HiMiniArrowPath, ar as HiMiniPuzzlePiece } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
function extensionDetailHref(extensionId) {
  const query = new URLSearchParams({ extension: extensionId });
  return `/extensions?${query.toString()}`;
}
function extensionIdFromSearch(search) {
  const value = new URLSearchParams(search).get("extension")?.trim().toLowerCase() ?? "";
  return value.length > 0 ? value : null;
}
function canonicalExtensionId(catalog, candidate) {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension) => extension.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension) => extension.aliases.includes(normalized))?.extension_id ?? null;
}
function explicitControlState(effective, kind, targetId) {
  const match = effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId
  );
  return match?.state ?? null;
}
function extensionEffectiveState(effective, extension) {
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension.required) return "enabled";
  return explicitControlState(effective, "extension", extension.extension_id) ?? "enabled";
}
function permissionEffectiveState(effective, extension, permission) {
  if (extensionEffectiveState(effective, extension) === "disabled") return "disabled";
  if (!permission.configurable) return permission.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission.permission_id) ?? (permission.default_enabled ? "enabled" : "disabled");
}
function permissionForRule(extension, rule) {
  return extension.permissions.find((permission) => permission.rule_ids.includes(rule.rule_id)) ?? null;
}
function permissionRelations(extension, permission) {
  const byId = new Map(extension.permissions.map((item) => [item.permission_id, item]));
  const resolve = (ids) => ids.map((id) => byId.get(id)).filter((item) => Boolean(item));
  const referenced = [...permission.dependencies, ...permission.conflicts, ...permission.implied_permissions];
  return {
    dependencies: resolve(permission.dependencies),
    conflicts: resolve(permission.conflicts),
    implied: resolve(permission.implied_permissions),
    missing: referenced.filter((id) => !byId.has(id))
  };
}
function treatmentLabel(value) {
  const labels = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled"
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])"
].join(",");
function focusableElements(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true"
  );
}
function useModalDialog(onClose, canClose = true) {
  const dialogRef = reactExports.useRef(null);
  const closeRef = reactExports.useRef(onClose);
  const canCloseRef = reactExports.useRef(canClose);
  closeRef.current = onClose;
  canCloseRef.current = canClose;
  reactExports.useEffect(() => {
    const root = dialogRef.current;
    if (!root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const initial = focusableElements(root)[0] ?? root;
    initial.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && canCloseRef.current) {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements(root);
      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
const RISK_TONE = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700"
};
function Pill({ children, tone = "border-slate-200 bg-slate-50 text-slate-700" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`, children });
}
function Definition({ label, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-slate-900", children })
  ] });
}
function PermissionInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const relations = permissionRelations(props.extension, props.permission);
  const effectiveState = permissionEffectiveState(props.effective, props.extension, props.permission);
  const explicitState = explicitControlState(props.effective, "permission", props.permission.permission_id);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "permission-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Permission" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "permission-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.permission.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.permission.permission_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close permission details", className: "rounded-full p-2 text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.permission.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[props.permission.risk_tier], children: [
        props.permission.risk_tier,
        " baseline risk"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: effectiveState === "enabled" ? "Enabled" : "Disabled" }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Fixed protection" }) : null,
      props.permission.deprecated ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: "border-amber-200 bg-amber-50 text-amber-800", children: "Deprecated" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7 rounded-2xl border border-slate-200 bg-slate-50 p-5", "aria-labelledby": "permission-effective-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 text-brand-blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "permission-effective-heading", className: "font-semibold text-slate-950", children: "Baseline and effective behavior" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Baseline floor", children: treatmentLabel(props.permission.baseline_floor) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Default state", children: props.permission.default_enabled ? "Enabled" : "Disabled" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Explicit local/cloud state", children: explicitState ?? "Inherited" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective state", children: effectiveState })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs leading-5 text-slate-500", children: "Baseline risk and the baseline action floor are detector metadata. This view does not rewrite either value." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", "aria-labelledby": "permission-rules-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "permission-rules-heading", className: "font-semibold text-slate-950", children: "Governed rules" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: props.permission.rule_ids.map((ruleId) => {
        const rule = props.extension.rules.find((item) => item.rule_id === ruleId);
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 px-3 py-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-slate-900", children: rule?.title ?? ruleId }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-[11px] text-slate-500", children: ruleId })
        ] }, ruleId);
      }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", "aria-labelledby": "permission-relations-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "permission-relations-heading", className: "font-semibold text-slate-950", children: "Relationships" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: relations.dependencies.length ? relations.dependencies.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: relations.conflicts.length ? relations.conflicts.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Implies", children: relations.implied.length ? relations.implied.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Capabilities", children: props.permission.typed_capabilities.length ? props.permission.typed_capabilities.join(", ") : "Rule-derived" })
      ] }),
      relations.missing.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-3 text-xs text-amber-700", children: [
        "Referenced permission metadata is not present in this extension version: ",
        relations.missing.join(", "),
        "."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", "aria-labelledby": "permission-guidance-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "permission-guidance-heading", className: "font-semibold text-slate-950", children: "Safer guidance" }),
      props.permission.safer_guidance.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.permission.safer_guidance.map((guidance) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: guidance }, guidance)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." }),
      props.permission.fixed_reason ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl bg-slate-50 px-3 py-2 text-sm text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Why fixed:" }),
        " ",
        props.permission.fixed_reason
      ] }) : null
    ] })
  ] });
}
function RuleInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const permission = permissionForRule(props.extension, props.rule);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "rule-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Command rule" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "rule-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.rule.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.rule.rule_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close rule details", className: "rounded-full p-2 text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.rule.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[props.rule.severity], children: [
        props.rule.severity,
        " detector severity"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
        treatmentLabel(props.rule.default_mode),
        " default mode"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: props.rule.matcher_kind })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-7 grid gap-5 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Permission owner", children: permission?.label ?? "Compatibility rule" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Rule version", children: String(props.rule.rule_version) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: props.rule.action_classes.join(", ") || "None" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Risk classes", children: props.rule.risk_classes.join(", ") || "None" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safe variants" }),
      props.rule.safe_variants.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: props.rule.safe_variants.map((variant) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 p-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-slate-900", children: variant.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 text-xs text-slate-500", children: [
          variant.matcher_kind,
          " · ",
          variant.variant_id
        ] })
      ] }, variant.variant_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No explicit safe variants are registered." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safer alternatives" }),
      props.rule.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.rule.safer_alternatives.map((alternative) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: alternative }, alternative)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." })
    ] }),
    props.rule.compatibility_fallback ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-7 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "This is a compatibility fallback. Guard may use it when structured matching cannot establish a narrower rule." })
    ] }) : null
  ] });
}
function ExtensionControlCenterDetail(props) {
  const [tab, setTab] = reactExports.useState("overview");
  const [permission, setPermission] = reactExports.useState(null);
  const [rule, setRule] = reactExports.useState(null);
  const extensionState = extensionEffectiveState(props.effective, props.extension);
  const explicitState = explicitControlState(props.effective, "extension", props.extension.extension_id);
  const permissionSummary = reactExports.useMemo(() => {
    const enabled = props.extension.permissions.filter((item) => permissionEffectiveState(props.effective, props.extension, item) === "enabled").length;
    return { enabled, disabled: props.extension.permissions.length - enabled };
  }, [props.effective, props.extension]);
  const openPermission = reactExports.useCallback((item) => setPermission(item), []);
  const openRule = reactExports.useCallback((item) => setRule(item), []);
  const tabs = ["overview", "permissions", "rules"];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { "data-testid": "extension-control-center-detail", className: "mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onBack, className: "inline-flex items-center gap-2 text-sm font-semibold text-slate-600 hover:text-brand-blue", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4" }),
      "All extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-5 rounded-3xl border border-slate-200 bg-white p-6 shadow-[0_10px_30px_rgba(15,23,42,0.05)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.2em] text-brand-blue", children: "Extension control center" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: props.extension.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.extension.extension_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-3xl text-sm leading-6 text-slate-600", children: props.extension.description })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: extensionState === "enabled" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700", children: extensionState === "enabled" ? "Enabled" : "Disabled" }),
          props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Required" }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: props.extension.source }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
            "v",
            props.extension.version
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 grid gap-3 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.permission_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Permissions" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.rule_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Rules" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.risk_classes.length }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Risk classes" })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { "aria-label": "Extension detail sections", className: "mt-6 flex gap-1 overflow-x-auto border-b border-slate-200", role: "tablist", children: tabs.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", role: "tab", "aria-selected": tab === item, onClick: () => setTab(item), className: `border-b-2 px-4 py-3 text-sm font-semibold capitalize ${tab === item ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:text-slate-900"}`, children: item }, item)) }),
    tab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 grid gap-5 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 text-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Effective protection" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Extension state", children: extensionState }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Explicit policy", children: explicitState ?? "Inherited" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Global lockdown", children: props.effective.global_lockdown ? "Active" : "Off" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Authority", children: props.effective.health }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Permissions enabled", children: permissionSummary.enabled }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Permissions disabled", children: permissionSummary.disabled })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex gap-3 rounded-xl bg-blue-50 p-4 text-sm text-slate-700", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0 text-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Detector severity and permission baseline floors are immutable metadata here. Later policy controls can change effective treatment only within Guard safety floors." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Capability relationships" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 space-y-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: props.extension.dependencies.join(", ") || "None" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: props.extension.conflicts.join(", ") || "None" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Executables", children: props.extension.executables.join(", ") || "Detected structurally" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Ecosystems", children: props.extension.ecosystem_ids.join(", ") || "General development tooling" })
        ] }),
        props.extension.delegated_protection ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-5 shrink-0" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Protection is delegated to ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: props.extension.delegated_protection }),
            "."
          ] })
        ] }) : null
      ] })
    ] }) : null,
    tab === "permissions" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "extension-permissions-heading", className: "mt-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-end justify-between gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-permissions-heading", className: "text-lg font-semibold text-slate-950", children: "Permission inventory" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Independently governed capabilities and the rules they own." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
          props.extension.permissions.length,
          " total"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: props.extension.permissions.map((item) => {
        const state = permissionEffectiveState(props.effective, props.extension, item);
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => openPermission(item), className: "flex w-full items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 hover:shadow-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-950", children: item.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: RISK_TONE[item.risk_tier], children: item.risk_tier }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: state }),
              !item.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "fixed" }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 line-clamp-2 text-sm text-slate-600", children: item.description }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
              "Baseline floor: ",
              treatmentLabel(item.baseline_floor),
              " · ",
              item.rule_ids.length,
              " rule",
              item.rule_ids.length === 1 ? "" : "s"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block truncate text-[11px] text-slate-400", children: item.permission_id })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-slate-400" })
        ] }, item.permission_id);
      }) })
    ] }) : null,
    tab === "rules" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "extension-rules-heading", className: "mt-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-end justify-between gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-rules-heading", className: "text-lg font-semibold text-slate-950", children: "Rule inventory" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Stable detector identities, matcher types, severities, and safe variants." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
          props.extension.rules.length,
          " total"
        ] })
      ] }),
      props.extension.rules.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: props.extension.rules.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => openRule(item), className: "flex w-full items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 hover:shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-950", children: item.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: RISK_TONE[item.severity], children: item.severity }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: treatmentLabel(item.default_mode) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 line-clamp-2 text-sm text-slate-600", children: item.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block truncate text-xs text-slate-500", children: item.rule_id })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-slate-400" })
      ] }, item.rule_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500", children: "This extension delegates protection and has no local command rules." })
    ] }) : null,
    permission ? /* @__PURE__ */ jsxRuntimeExports.jsx(PermissionInspector, { effective: props.effective, extension: props.extension, permission, onClose: () => setPermission(null) }) : null,
    rule ? /* @__PURE__ */ jsxRuntimeExports.jsx(RuleInspector, { extension: props.extension, rule, onClose: () => setRule(null) }) : null
  ] });
}
class ExtensionControlApiError extends Error {
  constructor(message, status, code, recoveryAction) {
    super(message);
    this.status = status;
    this.code = code;
    this.recoveryAction = recoveryAction;
  }
  status;
  code;
  recoveryAction;
}
async function request(path, init) {
  const response = await fetchExtensionControlApi(path, init);
  const payload = await response.json();
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : void 0,
      typeof error.recovery === "object" && error.recovery !== null && typeof error.recovery.action === "string" ? error.recovery.action : void 0
    );
  }
  return payload;
}
function fetchExtensionCatalog() {
  return request("/v1/extension-controls/catalog");
}
function fetchEffectiveExtensionControls() {
  return request("/v1/extension-controls/effective");
}
function recoverExtensionControlAuthority(credentials) {
  return request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
}
function previewExtensionMutation(payload) {
  return request("/v1/extension-controls/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
function applyExtensionMutation(payload) {
  return request("/v1/extension-controls/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
const EMPTY_EXTENSION_FILTERS = {
  query: "",
  risk: "all",
  domain: "all",
  state: "all",
  required: "all"
};
const RISK_CLASS_ORDER = [
  "destructive_shell",
  "network_egress",
  "supply_chain",
  "local_secret_read",
  "encoded_execution",
  "policy_bypass",
  "data_flow_exfiltration",
  "credential_exfiltration",
  "execution"
];
const RISK_CLASS_LABELS = {
  destructive_shell: "Destructive shell",
  network_egress: "Network egress",
  supply_chain: "Supply chain",
  local_secret_read: "Local secrets",
  encoded_execution: "Encoded execution",
  policy_bypass: "Policy bypass",
  data_flow_exfiltration: "Data exfiltration",
  credential_exfiltration: "Credential exfiltration",
  execution: "Remote execution"
};
const RISK_CLASS_TONE = {
  destructive_shell: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-amber-300 hover:bg-amber-50",
    active: "border-amber-400 bg-amber-100 text-amber-900",
    label: "bg-amber-50 text-amber-800 border-amber-200"
  },
  network_egress: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-blue-300 hover:bg-blue-50",
    active: "border-blue-400 bg-blue-100 text-blue-900",
    label: "bg-blue-50 text-blue-800 border-blue-200"
  },
  supply_chain: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-violet-300 hover:bg-violet-50",
    active: "border-violet-400 bg-violet-100 text-violet-900",
    label: "bg-violet-50 text-violet-800 border-violet-200"
  },
  local_secret_read: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-rose-300 hover:bg-rose-50",
    active: "border-rose-400 bg-rose-100 text-rose-900",
    label: "bg-rose-50 text-rose-800 border-rose-200"
  },
  encoded_execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-slate-400 hover:bg-slate-100",
    active: "border-slate-500 bg-slate-200 text-slate-900",
    label: "bg-slate-100 text-slate-700 border-slate-300"
  },
  policy_bypass: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-red-300 hover:bg-red-50",
    active: "border-red-400 bg-red-100 text-red-900",
    label: "bg-red-50 text-red-800 border-red-200"
  },
  data_flow_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200"
  },
  credential_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200"
  },
  execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-teal-300 hover:bg-teal-50",
    active: "border-teal-400 bg-teal-100 text-teal-900",
    label: "bg-teal-50 text-teal-800 border-teal-200"
  }
};
const DOMAIN_LABELS = {
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
  "source-control": "Source control"
};
const DOMAIN_PREFIX_MAP = [
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
  ["command.github", "source-control"]
];
function classifyDomain(extensionId) {
  const id = extensionId.toLowerCase();
  for (const [prefix, domain] of DOMAIN_PREFIX_MAP) {
    if (id.startsWith(prefix)) return domain;
  }
  return "core";
}
function isExtensionEnabled(effective, extension) {
  return extensionEffectiveState(effective, extension) === "enabled";
}
function hasActiveFilters(filters) {
  return filters.query.trim() !== "" || filters.risk !== "all" || filters.domain !== "all" || filters.state !== "all" || filters.required !== "all";
}
function searchHaystack(extension) {
  const parts = [
    extension.name,
    extension.extension_id,
    extension.description,
    extension.source,
    ...extension.action_classes,
    ...extension.risk_classes,
    classifyDomain(extension.extension_id)
  ];
  return parts.join(" ").toLowerCase();
}
function matchExtensionQuery(extension, query) {
  const normalized = query.trim().toLowerCase();
  if (normalized === "") return true;
  const haystack = searchHaystack(extension);
  return normalized.split(/\s+/).every((token) => haystack.includes(token));
}
function filterExtensions(extensions, effective, filters) {
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
const SELECT_CLASS = "min-h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60";
const DOMAIN_ORDER = [
  "core",
  "package",
  "cloud",
  "database",
  "storage",
  "backup",
  "remote",
  "cicd",
  "platform",
  "managed-service",
  "search-messaging",
  "source-control"
];
function SearchField(props) {
  const handleChange = reactExports.useCallback(
    (event) => props.onChange(event.target.value),
    [props]
  );
  const handleClear = reactExports.useCallback(() => props.onChange(""), [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative flex flex-1 items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search extensions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      HiMiniMagnifyingGlass,
      {
        className: "pointer-events-none absolute left-3 size-4 text-slate-400",
        "aria-hidden": "true"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "input",
      {
        ref: props.inputRef,
        type: "search",
        value: props.value,
        onChange: handleChange,
        placeholder: "Search by name, command, or risk (press /)",
        className: "min-h-9 w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      }
    ),
    props.value ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: handleClear,
        "aria-label": "Clear search",
        className: "absolute right-2 flex size-5 items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" })
      }
    ) : null
  ] });
}
function RiskChips(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-center gap-1.5", role: "group", "aria-label": "Filter by risk class", children: RISK_CLASS_ORDER.map((risk) => {
    const isActive = props.value === risk;
    const tone = RISK_CLASS_TONE[risk];
    const count = props.counts.get(risk) ?? 0;
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: () => props.onChange(isActive ? "all" : risk),
        "aria-pressed": isActive,
        className: `inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${isActive ? tone.active : tone.idle}`,
        children: [
          RISK_CLASS_LABELS[risk],
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: isActive ? "opacity-70" : "text-slate-400", "aria-hidden": "true", children: count })
        ]
      },
      risk
    );
  }) });
}
function ActiveChip(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full bg-brand-blue/10 px-2.5 py-1 text-xs font-medium text-brand-blue", children: [
    props.label,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onRemove,
        "aria-label": `Remove filter: ${props.label}`,
        className: "flex size-4 items-center justify-center rounded-full transition-colors hover:bg-brand-blue/20",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-3", "aria-hidden": "true" })
      }
    )
  ] });
}
function ExtensionsFilterBar(props) {
  const [showFacets, setShowFacets] = reactExports.useState(false);
  const searchRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    const handleKeyDown = (event) => {
      const target = event.target;
      const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable;
      if (event.key === "/" && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === "Escape" && document.activeElement === searchRef.current && props.filters.query) {
        props.onChange({ query: "" });
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [props]);
  const handleQuery = reactExports.useCallback((value) => props.onChange({ query: value }), [props]);
  const handleRisk = reactExports.useCallback((risk) => props.onChange({ risk }), [props]);
  const handleDomain = reactExports.useCallback(
    (event) => props.onChange({ domain: event.target.value === "all" ? "all" : event.target.value }),
    [props]
  );
  const handleState = reactExports.useCallback(
    (event) => props.onChange({ state: event.target.value }),
    [props]
  );
  const handleRequired = reactExports.useCallback(
    (event) => props.onChange({ required: event.target.value }),
    [props]
  );
  const toggleFacets = reactExports.useCallback(() => setShowFacets((prev) => !prev), []);
  const riskCounts = reactExports.useMemo(
    () => {
      const counts = /* @__PURE__ */ new Map();
      for (const risk of RISK_CLASS_ORDER) counts.set(risk, 0);
      for (const extension of props.extensions) {
        for (const risk of extension.risk_classes) {
          if (risk in RISK_CLASS_LABELS) {
            const key = risk;
            counts.set(key, (counts.get(key) ?? 0) + 1);
          }
        }
      }
      return counts;
    },
    [props.extensions]
  );
  const totalCount = props.extensions.length;
  const filteredCount = reactExports.useMemo(
    () => filterExtensions(props.extensions, props.effective, props.filters).length,
    [props.extensions, props.effective, props.filters]
  );
  const active = hasActiveFilters(props.filters);
  const facetsActive = props.filters.domain !== "all" || props.filters.state !== "all" || props.filters.required !== "all";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", "aria-label": "Extension filters", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SearchField, { value: props.filters.query, onChange: handleQuery, inputRef: searchRef }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: toggleFacets,
          "aria-expanded": showFacets,
          "aria-label": "Toggle domain, state, and requirement filters",
          className: `inline-flex min-h-9 items-center gap-1.5 rounded-xl border px-3 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${showFacets || facetsActive ? "border-brand-blue bg-brand-blue/5 text-brand-blue" : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "size-4", "aria-hidden": "true" }),
            "Filters",
            facetsActive ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex size-4 items-center justify-center rounded-full bg-brand-blue text-[10px] font-bold text-white", children: [props.filters.domain !== "all", props.filters.state !== "all", props.filters.required !== "all"].filter(Boolean).length }) : null
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(RiskChips, { value: props.filters.risk, onChange: handleRisk, counts: riskCounts }),
    showFacets ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 rounded-xl bg-slate-50/70 p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.domain,
          onChange: handleDomain,
          "aria-label": "Filter by domain",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All domains" }),
            DOMAIN_ORDER.map((domain) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: domain, children: DOMAIN_LABELS[domain] }, domain))
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.state,
          onChange: handleState,
          "aria-label": "Filter by enabled state",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All states" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "enabled", children: "Enabled" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "disabled", children: "Disabled" })
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.required,
          onChange: handleRequired,
          "aria-label": "Filter by required status",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "Required & optional" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "required", children: "Required only" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "optional", children: "Optional only" })
          ]
        }
      )
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
      active ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        props.filters.query ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActiveChip, { label: `“${props.filters.query}”`, onRemove: () => props.onChange({ query: "" }) }) : null,
        props.filters.risk !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: RISK_CLASS_LABELS[props.filters.risk],
            onRemove: () => props.onChange({ risk: "all" })
          }
        ) : null,
        props.filters.domain !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: DOMAIN_LABELS[props.filters.domain],
            onRemove: () => props.onChange({ domain: "all" })
          }
        ) : null,
        props.filters.state !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: props.filters.state === "enabled" ? "Enabled" : "Disabled",
            onRemove: () => props.onChange({ state: "all" })
          }
        ) : null,
        props.filters.required !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: props.filters.required === "required" ? "Required only" : "Optional only",
            onRemove: () => props.onChange({ required: "all" })
          }
        ) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: props.onClear,
            className: "ml-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark",
            children: "Clear all"
          }
        )
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-auto text-xs text-slate-500", "aria-live": "polite", children: active ? `${filteredCount} of ${totalCount} shown` : `${totalCount} total` })
    ] })
  ] });
}
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = reactExports.useState(value);
  reactExports.useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debouncedValue;
}
function extensionRecoveryAction(health) {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority"
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description: "Authenticate in this device's terminal to protect extension settings, then check again.",
    command: "hol-guard command controls enroll"
  };
}
function requiresExtensionRecoveryApproval(error) {
  return error instanceof ExtensionControlApiError && (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}
function randomToken() {
  return crypto.randomUUID().replaceAll("-", "");
}
function buildExtensionMutation(state, change) {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: []
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled"
    });
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken()
  };
}
function ExtensionStatusBanner(props) {
  const [copyState, setCopyState] = reactExports.useState("idle");
  const recovery = extensionRecoveryAction(props.effective.health);
  const copy = reactExports.useCallback(async () => {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }, [recovery]);
  if (props.effective.health === "protected") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Protected authority" }),
        " · revision ",
        props.effective.revision
      ] })
    ] });
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-amber-200 bg-amber-50 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0 text-amber-700" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: recovery?.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-700", children: recovery?.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-2", children: [
        repairable && props.onRecover ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-busy": props.busy, disabled: props.busy, onClick: props.onRecover, className: "rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60", children: props.busy ? "Repairing…" : "Repair now" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onRetry, className: "rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700", children: "Check again" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-amber-200 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Command-line fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg bg-white px-3 py-2 text-xs", children: recovery?.command }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: copy, className: "inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 text-sm font-semibold", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4" }),
            copyState === "copied" ? "Copied" : recovery?.copyLabel
          ] })
        ] }),
        copyState === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-2 text-sm text-red-700", children: "Copy failed. Select the command above." }) : null
      ] }),
      props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-red-700", children: props.error }) : null,
      props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-slate-800", children: props.status }) : null
    ] })
  ] }) });
}
function ExtensionCard(props) {
  const domain = classifyDomain(props.extension.extension_id);
  const risks = props.extension.risk_classes.filter((risk) => risk in RISK_CLASS_LABELS);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "group flex min-h-60 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-11 place-items-center rounded-2xl bg-blue-50 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPuzzlePiece, { className: "size-6" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", role: "switch", "aria-checked": props.enabled, "aria-label": `${props.enabled ? "Disable" : "Enable"} ${props.extension.name}`, disabled: props.locked || props.extension.required, onClick: () => props.onChange({ extension: props.extension, enabled: !props.enabled }), className: `relative h-7 w-12 rounded-full ${props.enabled ? "bg-brand-blue" : "bg-slate-300"} disabled:opacity-50`, children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `absolute top-1 size-5 rounded-full bg-white shadow transition ${props.enabled ? "left-6" : "left-1"}` }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: props.extension.name }),
      props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase text-brand-blue", children: "Required" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 line-clamp-3 text-sm leading-6 text-slate-600", children: props.extension.description }),
    risks.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-1", children: risks.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`, children: RISK_CLASS_LABELS[risk] }, risk)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-2 text-xs text-slate-500", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: DOMAIN_LABELS[domain] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        props.extension.permission_count,
        " permissions"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        props.extension.rule_count,
        " rules"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "v",
        props.extension.version
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-label": `Open ${props.extension.name} controls`, onClick: () => props.onOpen(props.extension), className: "mt-auto flex items-center justify-between border-t border-slate-100 pt-4 text-left text-sm font-semibold text-brand-blue", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Inspect commands and permissions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-4" })
    ] })
  ] });
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown` : `${props.change.enabled ? "Enable" : "Disable"} ${props.change.extension.name}`;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "extension-review-title", onSubmit: (event) => {
    event.preventDefault();
    props.onConfirm(password, totp);
  }, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-wide text-brand-blue", children: "Review control change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-review-title", className: "mt-2 text-xl font-semibold", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-label": "Close review", disabled: props.busy, onClick: props.onCancel, children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-5 block text-sm font-medium", children: [
      "Approval password",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "password", autoComplete: "current-password", value: password, onChange: (event) => setPassword(event.target.value), className: "mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block text-sm font-medium", children: [
      "Authenticator code",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { inputMode: "numeric", autoComplete: "one-time-code", value: totp, onChange: (event) => setTotp(event.target.value), className: "mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5" })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 text-sm text-red-700", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: props.busy, className: "rounded-xl bg-brand-blue px-5 py-2.5 text-sm font-semibold text-white disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
function ExtensionsWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = reactExports.useState(false);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const [filters, setFilters] = reactExports.useState(EMPTY_EXTENSION_FILTERS);
  const [selectedExtensionId, setSelectedExtensionId] = reactExports.useState(() => extensionIdFromSearch(window.location.search));
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => setSelectedExtensionId(extensionIdFromSearch(window.location.search));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, selectedExtensionId), [catalogExtensions, selectedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = reactExports.useMemo(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = reactExports.useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);
  const openExtension = reactExports.useCallback((extension) => {
    window.history.pushState({}, "", extensionDetailHref(extension.extension_id));
    setSelectedExtensionId(extension.extension_id);
    window.scrollTo({ top: 0 });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setSelectedExtensionId(null);
    window.scrollTo({ top: 0 });
  }, []);
  const confirm = reactExports.useCallback(async (password, totp) => {
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
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : void 0;
      setMutationError(`${error instanceof Error ? error.message : "Change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);
  const recover = reactExports.useCallback(async (credentials) => {
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus("Repairing extension controls…");
    try {
      const effective = await recoverExtensionControlAuthority(credentials);
      if (effective.health !== "protected") throw new Error("Guard could not restore protected extension controls.");
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
      setRecoveryStatus("Extension controls repaired.");
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        await resolveApprovalGate();
        setRecoveryApprovalOpen(true);
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair extension controls.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);
  if (state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-7 animate-spin text-brand-blue" }) });
  if (state.kind === "error") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "mx-auto max-w-5xl p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-red-200 bg-red-50 p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-red-950", children: "Extensions unavailable" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-red-700", children: state.message }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: load, className: "mt-4 rounded-xl bg-red-700 px-4 py-2 text-sm font-semibold text-white", children: "Try again" })
  ] }) });
  const recoveryBanner = /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatusBanner, { busy: recoveryBusy, effective: state.effective, error: recoveryError, status: recoveryStatus, onRecover: () => {
    void recover();
  }, onRetry: load });
  const recoveryModal = recoveryApprovalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofModal, { title: "Repair extension controls", detail: "Authenticate this repair on your device. Guard uses the proof once and does not store it.", confirmLabel: "Repair controls", approvalGate: resolvedApprovalGate, busy: recoveryBusy, error: recoveryError, onCancel: () => {
    if (!recoveryBusy) setRecoveryApprovalOpen(false);
  }, onConfirm: (credentials) => {
    void recover(credentials);
  } }) : null;
  if (selectedExtensionId && selectedExtension) return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto w-full max-w-7xl px-4 pt-6 sm:px-6 lg:px-8", children: recoveryBanner }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionControlCenterDetail, { extension: selectedExtension, effective: state.effective, onBack: closeExtension }),
    recoveryModal
  ] });
  if (selectedExtensionId) return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto max-w-4xl p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: recoveryBanner }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 rounded-3xl border border-amber-200 bg-amber-50 p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: "Extension not found" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-800", children: "This stable extension ID is not present in the current catalog." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: closeExtension, className: "mt-4 rounded-xl bg-brand-blue px-4 py-2 text-sm font-semibold text-white", children: "Back to extensions" })
      ] })
    ] }),
    recoveryModal
  ] });
  const locked = state.effective.health !== "protected";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.22em] text-brand-blue", children: "Command safety" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold text-slate-950", children: "Extensions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm text-slate-600", children: "Inspect and govern the capabilities Guard uses to understand development commands." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: locked, onClick: () => setPending({ globalLockdown: !state.effective.global_lockdown }), className: "inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold disabled:opacity-50", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-4" }),
        state.effective.global_lockdown ? "Disable lockdown" : "Enable lockdown"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: recoveryBanner }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "installed-extensions", className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "installed-extensions", className: "text-lg font-semibold text-slate-950", children: "Installed extensions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Open an extension to inspect its permissions and command rules." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
          catalogExtensions.length,
          " available"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsFilterBar, { filters, onChange: (patch) => setFilters((previous) => ({ ...previous, ...patch })), onClear: () => setFilters(EMPTY_EXTENSION_FILTERS), extensions: catalogExtensions, effective: state.effective }) }),
      filtered.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3", children: filtered.map((extension) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionCard, { extension, enabled: isExtensionEnabled(state.effective, extension), locked: locked || state.effective.global_lockdown, onChange: (change) => {
        setMutationError(null);
        setPending(change);
      }, onOpen: openExtension }, extension.extension_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 rounded-3xl border border-dashed border-slate-300 bg-white p-10 text-center text-sm text-slate-500", children: hasActiveFilters(effectiveFilters) ? "No extensions match these filters." : "No extensions are registered." })
    ] }),
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, onCancel: () => {
      if (!busy) setPending(null);
    }, onConfirm: confirm }) : null,
    recoveryModal
  ] });
}
export {
  ExtensionStatusBanner,
  ExtensionsWorkspace,
  buildExtensionMutation,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval
};
