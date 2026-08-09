import { r as reactExports, j as jsxRuntimeExports, an as HiMiniArrowLeft, Z as HiMiniLockClosed, o as HiMiniShieldCheck, ao as HiMiniArrowTopRightOnSquare, c as HiMiniChevronRight, ap as HiMiniInformationCircle, w as HiMiniXMark, J as HiMiniExclamationTriangle, aq as fetchExtensionControlApi, $ as HiMiniAdjustmentsHorizontal, ak as HiMiniMagnifyingGlass, ar as HiMiniArrowPath, U as HiMiniClipboardDocumentCheck, V as HiMiniClipboard, x as HiMiniChevronUp, y as HiMiniChevronDown, l as HiMiniCheckCircle, as as HiMiniPuzzlePiece } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
const EXTENSION_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DEFAULT_EXTENSION_DETAIL_URL_STATE = {
  tab: "overview",
  query: "",
  risk: "all",
  state: "all",
  configurable: "all",
  source: "all",
  deprecated: "all",
  type: "all",
  sort: "name",
  ruleId: null
};
function oneOf(value, allowed, fallback) {
  return value !== null && allowed.includes(value) ? value : fallback;
}
function parseExtensionRoute(pathname) {
  if (pathname === "/extensions" || pathname === "/extensions/") return { kind: "overview" };
  if (!pathname.startsWith("/extensions/")) return { kind: "invalid" };
  const encoded = pathname.slice("/extensions/".length);
  if (!encoded || encoded.includes("/")) return { kind: "invalid" };
  try {
    const decoded = decodeURIComponent(encoded).trim().toLowerCase();
    if (!EXTENSION_ID_PATTERN.test(decoded)) return { kind: "invalid" };
    return { kind: "detail", extensionId: decoded };
  } catch {
    return { kind: "invalid" };
  }
}
function readExtensionDetailUrlState(search) {
  const params = new URLSearchParams(search);
  const rawQuery = params.get("q") ?? "";
  const query = rawQuery.slice(0, 160);
  const rawRule = params.get("rule")?.trim().toLowerCase() ?? null;
  const ruleId = rawRule && RULE_ID_PATTERN.test(rawRule) ? rawRule : null;
  return {
    tab: oneOf(params.get("tab"), ["overview", "commands", "policy", "test-lab", "activity"], "overview"),
    query,
    risk: oneOf(params.get("risk"), ["all", "low", "medium", "high", "critical"], "all"),
    state: oneOf(params.get("state"), ["all", "allowed", "blocked"], "all"),
    configurable: oneOf(params.get("configurable"), ["all", "yes", "no"], "all"),
    source: oneOf(params.get("source"), ["all", "built-in", "local-admin", "signed-cloud"], "all"),
    deprecated: oneOf(params.get("deprecated"), ["all", "yes", "no"], "all"),
    type: oneOf(params.get("type"), ["all", "permission", "rule"], "all"),
    sort: oneOf(params.get("sort"), ["name", "risk", "id"], "name"),
    ruleId
  };
}
function extensionDetailSearch(state) {
  const params = new URLSearchParams();
  if (state.tab !== "overview") params.set("tab", state.tab);
  if (state.query.trim()) params.set("q", state.query.trim().slice(0, 160));
  if (state.risk !== "all") params.set("risk", state.risk);
  if (state.state !== "all") params.set("state", state.state);
  if (state.configurable !== "all") params.set("configurable", state.configurable);
  if (state.source !== "all") params.set("source", state.source);
  if (state.deprecated !== "all") params.set("deprecated", state.deprecated);
  if (state.type !== "all") params.set("type", state.type);
  if (state.sort !== "name") params.set("sort", state.sort);
  if (state.ruleId && RULE_ID_PATTERN.test(state.ruleId)) params.set("rule", state.ruleId);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}
function extensionDetailHref(extensionId, state = DEFAULT_EXTENSION_DETAIL_URL_STATE) {
  const canonical = extensionId.trim().toLowerCase();
  if (!EXTENSION_ID_PATTERN.test(canonical)) return "/extensions";
  return `/extensions/${encodeURIComponent(canonical)}${extensionDetailSearch(state)}`;
}
function canonicalExtensionId(catalog, candidate) {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension2) => extension2.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension2) => extension2.aliases.includes(normalized))?.extension_id ?? null;
}
function explicitControlState(effective, kind, targetId) {
  return effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId
  )?.state ?? null;
}
function extensionEffectiveState(effective, extension2) {
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension2.required) return "enabled";
  return explicitControlState(effective, "extension", extension2.extension_id) ?? "enabled";
}
function permissionEffectiveState(effective, extension2, permission2) {
  if (extensionEffectiveState(effective, extension2) === "disabled") return "disabled";
  if (!permission2.configurable) return permission2.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission2.permission_id) ?? (permission2.default_enabled ? "enabled" : "disabled");
}
function extensionStateLabel(effective, extension2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  const cloud = effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extension2.extension_id));
  if (cloud) return "Managed";
  if (extension2.required) return "Required";
  return extensionEffectiveState(effective, extension2) === "enabled" ? "Allowed" : "Blocked";
}
function permissionStateLabel(effective, extension2, permission2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (extensionEffectiveState(effective, extension2) === "disabled") return "Blocked";
  const cloud = effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "permission" && control.target_id === permission2.permission_id));
  if (cloud) return "Managed";
  if (!permission2.configurable) return "Required";
  const explicit = explicitControlState(effective, "permission", permission2.permission_id);
  if (explicit === null) return "Inherited";
  return explicit === "enabled" ? "Allowed" : "Blocked";
}
function controlProvenance(effective, kind, targetId) {
  const sources = [];
  if (effective.global_lockdown) sources.push("Global lockdown");
  for (const layer of effective.layers) {
    if (layer.controls.some((control) => control.target_kind === kind && control.target_id === targetId)) {
      sources.push(layer.kind === "signed-cloud" ? "Signed cloud policy" : "Local administrator");
    }
  }
  if (sources.length === 0) sources.push("Built-in default");
  return sources;
}
function permissionForRule(extension2, rule2) {
  return extension2.permissions.find((permission2) => permission2.rule_ids.includes(rule2.rule_id)) ?? null;
}
function permissionRelations(extension2, permission2) {
  const byId = new Map(extension2.permissions.map((item) => [item.permission_id, item]));
  const resolve = (ids) => ids.map((id2) => byId.get(id2)).filter((item) => Boolean(item));
  const referenced = [...permission2.dependencies, ...permission2.conflicts, ...permission2.implied_permissions];
  return {
    dependencies: resolve(permission2.dependencies),
    conflicts: resolve(permission2.conflicts),
    implied: resolve(permission2.implied_permissions),
    missing: referenced.filter((id2) => !byId.has(id2))
  };
}
const RISK_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function queryMatch(values, query) {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const haystack = values.join(" ").toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}
function filterDetailPermissions(extension2, effective, state) {
  if (state.type === "rule") return [];
  const items = extension2.permissions.filter((permission2) => {
    if (!queryMatch([permission2.label, permission2.permission_id, permission2.description, ...permission2.action_classes, ...permission2.typed_capabilities, ...permission2.rule_ids], state.query)) return false;
    if (state.risk !== "all" && permission2.risk_tier !== state.risk) return false;
    const enabled = permissionEffectiveState(effective, extension2, permission2) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable === "yes" && !permission2.configurable) return false;
    if (state.configurable === "no" && permission2.configurable) return false;
    if (state.source !== "all" && extension2.source !== state.source) return false;
    if (state.deprecated === "yes" && !permission2.deprecated) return false;
    if (state.deprecated === "no" && permission2.deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.permission_id.localeCompare(right.permission_id);
    if (state.sort === "risk") return RISK_RANK[right.risk_tier] - RISK_RANK[left.risk_tier] || left.label.localeCompare(right.label);
    return left.label.localeCompare(right.label);
  });
}
function filterDetailRules(extension2, effective, state) {
  if (state.type === "permission") return [];
  const permissionByRule = /* @__PURE__ */ new Map();
  for (const permission2 of extension2.permissions) {
    for (const ruleId of permission2.rule_ids) {
      if (!permissionByRule.has(ruleId)) permissionByRule.set(ruleId, permission2);
    }
  }
  const items = extension2.rules.filter((rule2) => {
    const permission2 = permissionByRule.get(rule2.rule_id) ?? null;
    if (!queryMatch([rule2.title, rule2.rule_id, rule2.description, rule2.matcher_kind, ...rule2.action_classes, ...rule2.risk_classes, ...permission2 ? [permission2.label, permission2.permission_id] : []], state.query)) return false;
    if (state.risk !== "all" && rule2.severity !== state.risk) return false;
    const enabled = permission2 ? permissionEffectiveState(effective, extension2, permission2) === "enabled" : extensionEffectiveState(effective, extension2) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable !== "all" && permission2) {
      if (state.configurable === "yes" && !permission2.configurable) return false;
      if (state.configurable === "no" && permission2.configurable) return false;
    }
    if (state.source !== "all" && extension2.source !== state.source) return false;
    const deprecated = permission2?.deprecated ?? false;
    if (state.deprecated === "yes" && !deprecated) return false;
    if (state.deprecated === "no" && deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.rule_id.localeCompare(right.rule_id);
    if (state.sort === "risk") return RISK_RANK[right.severity] - RISK_RANK[left.severity] || left.title.localeCompare(right.title);
    return left.title.localeCompare(right.title);
  });
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
const TABS = [
  { id: "overview", label: "Overview" },
  { id: "commands", label: "Commands & rules" },
  { id: "policy", label: "Policy" },
  { id: "test-lab", label: "Test Lab" },
  { id: "activity", label: "Activity" }
];
function Pill({ children, tone = "border-slate-200 bg-slate-50 text-slate-700" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`, children });
}
function Definition({ label, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-words text-sm text-slate-900", children })
  ] });
}
function ListValue({ values, empty = "None" }) {
  return values.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: values.join(", ") }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: empty });
}
function safeReferenceUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}
function DetailFilters(props) {
  const patch = (key, value) => props.onChange({ ...props.state, [key]: value, ruleId: null });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4", "aria-label": "Command and permission filters", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-xs font-semibold uppercase tracking-wide text-slate-500", children: [
      "Search",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { value: props.state.query, onChange: (event) => patch("query", event.target.value.slice(0, 160)), placeholder: "Rule, permission, capability…", className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Risk",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.risk, onChange: (event) => patch("risk", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All risk" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "critical", children: "Critical" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "high", children: "High" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "medium", children: "Medium" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "low", children: "Low" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Effective state",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.state, onChange: (event) => patch("state", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All states" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "allowed", children: "Allowed" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "blocked", children: "Blocked" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Configurable",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.configurable, onChange: (event) => patch("configurable", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "yes", children: "Configurable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "no", children: "Fixed" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Source",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.source, onChange: (event) => patch("source", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All sources" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "built-in", children: "Built in" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "local-admin", children: "Local admin" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "signed-cloud", children: "Signed cloud" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Deprecation",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.deprecated, onChange: (event) => patch("deprecated", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "no", children: "Current" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "yes", children: "Deprecated" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Type",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.type, onChange: (event) => patch("type", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "Rules & permissions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "rule", children: "Rules only" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "permission", children: "Permissions only" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Sort",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.sort, onChange: (event) => patch("sort", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "name", children: "Name" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "risk", children: "Risk" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "id", children: "Canonical ID" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => props.onChange({ ...props.state, query: "", risk: "all", state: "all", configurable: "all", source: "all", deprecated: "all", type: "all", sort: "name", ruleId: null }), className: "min-h-11 self-end rounded-xl border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 hover:bg-slate-50", children: "Clear filters" })
    ] })
  ] });
}
function PermissionInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const relations = permissionRelations(props.extension, props.permission);
  const effectiveState = permissionEffectiveState(props.effective, props.extension, props.permission);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "permission-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Permission" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "permission-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.permission.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.permission.permission_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close permission details", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.permission.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[props.permission.risk_tier], children: [
        props.permission.risk_tier,
        " baseline risk"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: permissionStateLabel(props.effective, props.extension, props.permission) }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Fixed" }) : null,
      props.permission.deprecated ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: "border-amber-200 bg-amber-50 text-amber-800", children: "Deprecated" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7 rounded-2xl border border-slate-200 bg-slate-50 p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Baseline and effective behavior" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Baseline floor", children: treatmentLabel(props.permission.baseline_floor) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Default", children: props.permission.default_enabled ? "Allowed" : "Blocked" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective", children: effectiveState === "enabled" ? "Allowed" : "Blocked" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Provenance", children: controlProvenance(props.effective, "permission", props.permission.permission_id).join(" · ") })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Capabilities and ownership" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.action_classes }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Typed capabilities", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.typed_capabilities, empty: "Rule-derived" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Governed rule IDs", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.rule_ids }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Introduced", children: props.permission.introduced_version })
      ] }),
      props.permission.rule_ids.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl bg-blue-50 p-3 text-sm text-slate-700", children: [
        "This permission governs ",
        props.permission.rule_ids.length,
        " rules. A future policy change to this permission affects every governed rule."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Relationships" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: relations.dependencies.length ? relations.dependencies.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: relations.conflicts.length ? relations.conflicts.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Implies", children: relations.implied.length ? relations.implied.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Replacement", children: props.permission.replacement_permission_id ?? "None" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safer guidance" }),
      props.permission.safer_guidance.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.permission.safer_guidance.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Why this cannot be changed:" }),
        " ",
        props.permission.fixed_reason ?? "Guard marks this capability as fixed."
      ] }) : null
    ] })
  ] });
}
function RuleInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const permission2 = permissionForRule(props.extension, props.rule);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "rule-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Command rule" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "rule-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.rule.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.rule.rule_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close rule details", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.rule.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[props.rule.severity], children: [
        props.rule.severity,
        " detector severity"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
        treatmentLabel(props.rule.default_mode),
        " default"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: props.rule.matcher_kind })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-7 grid gap-5 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Governing permission", children: permission2?.label ?? "Compatibility mapping" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Permission ID", children: permission2?.permission_id ?? "None" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Rule version", children: String(props.rule.rule_version) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Risk classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.rule.risk_classes }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.rule.action_classes }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Matcher kind", children: props.rule.matcher_kind })
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
      props.rule.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.rule.safer_alternatives.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." })
    ] }),
    props.rule.compatibility_fallback ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-7 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "This compatibility fallback is still a canonical detector rule and retains its baseline facts." })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onTest, className: "mt-7 min-h-11 rounded-xl bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-dark", children: "Test this rule" })
  ] });
}
function ExtensionControlCenterDetail(props) {
  const extensionState = extensionEffectiveState(props.effective, props.extension);
  const stateLabel = extensionStateLabel(props.effective, props.extension);
  const provenance = controlProvenance(props.effective, "extension", props.extension.extension_id);
  const permissions = reactExports.useMemo(() => filterDetailPermissions(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const rules = reactExports.useMemo(() => filterDetailRules(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const selectedRule = props.urlState.ruleId ? props.extension.rules.find((item) => item.rule_id === props.urlState.ruleId) ?? null : null;
  const selectedPermission = props.urlState.ruleId?.includes(".permission.") ? props.extension.permissions.find((item) => item.permission_id === props.urlState.ruleId) ?? null : null;
  const setTab = (tab) => props.onUrlState({ ...props.urlState, tab, ruleId: tab === "commands" ? props.urlState.ruleId : null });
  const handleTabKey = (event, tab) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const current = TABS.findIndex((item) => item.id === tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length;
    setTab(TABS[next].id);
    requestAnimationFrame(() => document.getElementById(`extension-tab-${TABS[next].id}`)?.focus());
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { "data-testid": "extension-control-center-detail", className: "mx-auto w-full max-w-7xl px-4 pb-10 pt-5 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { "aria-label": "Breadcrumb", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 hover:text-brand-blue", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4" }),
      "Extensions"
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-3 rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] sm:p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.2em] text-brand-blue", children: "Extension control center" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: props.extension.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.extension.extension_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-3xl text-sm leading-6 text-slate-600", children: props.extension.description })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: extensionState === "enabled" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700", children: stateLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: props.extension.required ? "Required" : "Optional" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: props.extension.source }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
            "v",
            props.extension.version
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Authority" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 font-semibold text-slate-950", children: props.effective.health })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.permission_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Permissions" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.rule_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Rules" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-sm font-semibold text-slate-950", children: provenance.join(" · ") })
        ] })
      ] }),
      props.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-5 flex gap-3 rounded-xl border border-slate-300 bg-slate-100 p-4 text-sm text-slate-800", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Global lockdown controls this capability." }),
          " Matching actions remain blocked regardless of optional local settings."
        ] })
      ] }) : null,
      props.onBroadControl && !props.extension.required && props.effective.health === "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onBroadControl, className: "mt-5 min-h-11 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50", children: "Review broad capability control" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 overflow-x-auto border-b border-slate-200", role: "tablist", "aria-label": "Extension detail sections", children: TABS.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { id: `extension-tab-${item.id}`, type: "button", role: "tab", "aria-selected": props.urlState.tab === item.id, "aria-controls": `extension-panel-${item.id}`, onKeyDown: (event) => handleTabKey(event, item.id), onClick: () => setTab(item.id), className: `min-h-11 border-b-2 px-4 py-3 text-sm font-semibold whitespace-nowrap focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${props.urlState.tab === item.id ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:text-slate-900"}`, children: item.label }, item.id)) }),
    props.urlState.tab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-overview", role: "tabpanel", "aria-labelledby": "extension-tab-overview", className: "mt-6 grid gap-5 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 text-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Canonical coverage" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.action_classes }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Risk classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.risk_classes }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Executables", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.executables, empty: "Registry matcher metadata" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Project markers", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.project_markers }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Ecosystems", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.ecosystem_ids }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Aliases", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.aliases }) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Relationships and provenance" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.dependencies }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.conflicts }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Delegated protection", children: props.extension.delegated_protection ?? "None" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Catalog digest", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.catalogDigest }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective state", children: stateLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Policy provenance", children: provenance.join(" · ") })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 lg:col-span-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Safer alternatives" }),
        props.extension.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.extension.safer_alternatives.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No extension-level alternative is registered." }),
        props.extension.reference_urls.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 border-t border-slate-100 pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-slate-900", children: "References" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-2", children: props.extension.reference_urls.map((value) => {
            const href = safeReferenceUrl(value);
            return href ? /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href, target: "_blank", rel: "noopener noreferrer", referrerPolicy: "no-referrer", className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-3 text-sm font-semibold text-brand-blue", children: [
              "Open reference ",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4" })
            ] }, value) : null;
          }) })
        ] }) : null
      ] })
    ] }) : null,
    props.urlState.tab === "commands" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-commands", role: "tabpanel", "aria-labelledby": "extension-tab-commands", className: "mt-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(DetailFilters, { state: props.urlState, onChange: props.onUrlState }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "aria-live": "polite", className: "mt-3 text-sm text-slate-500", children: [
        "Showing ",
        permissions.length,
        " permissions and ",
        rules.length,
        " rules."
      ] }),
      props.urlState.type !== "rule" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Permissions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 grid gap-3 lg:grid-cols-2", children: permissions.map((permission2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => props.onUrlState({ ...props.urlState, ruleId: permission2.permission_id }), className: "min-h-11 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-950", children: permission2.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: RISK_TONE[permission2.risk_tier], children: permission2.risk_tier }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: permissionStateLabel(props.effective, props.extension, permission2) }),
            !permission2.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Fixed" }) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: permission2.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
            "Baseline floor ",
            treatmentLabel(permission2.baseline_floor),
            " · ",
            permission2.rule_ids.length,
            " governed rule",
            permission2.rule_ids.length === 1 ? "" : "s"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-slate-400", children: permission2.permission_id })
        ] }, permission2.permission_id)) }),
        permissions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500", children: "No permissions match these filters." }) : null
      ] }) : null,
      props.urlState.type !== "permission" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Commands and rules" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 hidden overflow-x-auto rounded-2xl border border-slate-200 bg-white md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "bg-slate-50 text-xs uppercase tracking-wide text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "State" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Rule" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Severity / default" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Matcher" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Permission" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Open" }) })
          ] }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: rules.map((rule2) => {
            const permission2 = permissionForRule(props.extension, rule2);
            const allowed = permission2 ? permissionEffectiveState(props.effective, props.extension, permission2) === "enabled" : extensionState === "enabled";
            return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 font-semibold text-slate-700", children: allowed ? "Allowed" : "Blocked" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "max-w-md px-4 py-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-semibold text-slate-950", children: rule2.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-[11px] text-slate-500", children: rule2.rule_id })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-4 py-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: RISK_TONE[rule2.severity], children: rule2.severity }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-xs text-slate-500", children: treatmentLabel(rule2.default_mode) })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 text-slate-600", children: rule2.matcher_kind }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 text-slate-600", children: permission2?.label ?? "Compatibility" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-label": `Inspect rule ${rule2.title}`, onClick: () => props.onUrlState({ ...props.urlState, ruleId: rule2.rule_id }), className: "grid size-11 place-items-center rounded-xl text-brand-blue hover:bg-blue-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5" }) }) })
            ] }, rule2.rule_id);
          }) })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 grid gap-3 md:hidden", children: rules.map((rule2) => {
          const permission2 = permissionForRule(props.extension, rule2);
          const allowed = permission2 ? permissionEffectiveState(props.effective, props.extension, permission2) === "enabled" : extensionState === "enabled";
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => props.onUrlState({ ...props.urlState, ruleId: rule2.rule_id }), className: "rounded-2xl border border-slate-200 bg-white p-4 text-left", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: allowed ? "Allowed" : "Blocked" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { tone: RISK_TONE[rule2.severity], children: rule2.severity })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 font-semibold text-slate-950", children: rule2.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-slate-500", children: rule2.rule_id }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
              rule2.matcher_kind,
              " · ",
              permission2?.label ?? "Compatibility"
            ] })
          ] }, rule2.rule_id);
        }) }),
        rules.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500", children: "No rules match these filters." }) : null
      ] }) : null
    ] }) : null,
    props.urlState.tab === "policy" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-policy", role: "tabpanel", "aria-labelledby": "extension-tab-policy", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Policy" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm text-slate-600", children: "This Batch 1 view is read-only below the existing broad capability control. Permission editing and semantic preview arrive in the next implementation batch." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective capability", children: stateLabel }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Authority", children: props.effective.health }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Provenance", children: provenance.join(" · ") }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Global lockdown", children: props.effective.global_lockdown ? "Active" : "Off" })
      ] })
    ] }) : null,
    props.urlState.tab === "test-lab" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-test-lab", role: "tabpanel", "aria-labelledby": "extension-tab-test-lab", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Test Lab" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex gap-3 rounded-xl bg-blue-50 p-4 text-sm text-slate-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0 text-brand-blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Side-effect-free command simulation is delivered in Batch 3. This placeholder never accepts or executes command text." })
      ] }),
      props.urlState.ruleId ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm text-slate-600", children: [
        "Selected rule: ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: props.urlState.ruleId })
      ] }) : null
    ] }) : null,
    props.urlState.tab === "activity" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-activity", role: "tabpanel", "aria-labelledby": "extension-tab-activity", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Activity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Extension-scoped decision and policy history arrives in Batch 4. No activity is synthesized in the dashboard." })
    ] }) : null,
    selectedPermission ? /* @__PURE__ */ jsxRuntimeExports.jsx(PermissionInspector, { effective: props.effective, extension: props.extension, permission: selectedPermission, onClose: () => props.onUrlState({ ...props.urlState, ruleId: null }) }) : null,
    selectedRule ? /* @__PURE__ */ jsxRuntimeExports.jsx(RuleInspector, { extension: props.extension, rule: selectedRule, onClose: () => props.onUrlState({ ...props.urlState, ruleId: null }), onTest: () => props.onUrlState({ ...props.urlState, tab: "test-lab", ruleId: selectedRule.rule_id }) }) : null
  ] });
}
const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DIGEST = /^[a-f0-9]{64}$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const EXTENSION_CLIENT_LIMITS = Object.freeze({
  extensions: 256,
  rulesPerExtension: 1024,
  permissionsPerExtension: 1024,
  relationshipIds: 1024,
  controls: 4096,
  layers: 16,
  failures: 256,
  stringLength: 8192
});
class ExtensionControlProtocolError extends Error {
  constructor(message) {
    super(`Invalid extension-control response: ${message}`);
  }
}
function record(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExtensionControlProtocolError(`${label} must be an object`);
  }
  return value;
}
function array(value, label, max) {
  if (!Array.isArray(value)) throw new ExtensionControlProtocolError(`${label} must be an array`);
  if (value.length > max) throw new ExtensionControlProtocolError(`${label} exceeds ${max} items`);
  return value;
}
function string(value, label, allowEmpty = false) {
  if (typeof value !== "string") throw new ExtensionControlProtocolError(`${label} must be a string`);
  if (value.length > EXTENSION_CLIENT_LIMITS.stringLength) throw new ExtensionControlProtocolError(`${label} is too long`);
  if (!allowEmpty && value.trim().length === 0) throw new ExtensionControlProtocolError(`${label} is required`);
  return value;
}
function optionalString(value, label) {
  if (value === null) return null;
  return string(value, label);
}
function bool(value, label) {
  if (typeof value !== "boolean") throw new ExtensionControlProtocolError(`${label} must be boolean`);
  return value;
}
function integer(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new ExtensionControlProtocolError(`${label} must be an integer >= ${min}`);
  }
  return value;
}
function enumValue(value, label, values) {
  const candidate = string(value, label);
  if (!values.includes(candidate)) throw new ExtensionControlProtocolError(`${label} has unsupported value`);
  return candidate;
}
function id(value, label, pattern) {
  const candidate = string(value, label).trim().toLowerCase();
  if (!pattern.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not canonical`);
  return candidate;
}
function digest(value, label) {
  const candidate = string(value, label).trim().toLowerCase();
  if (!DIGEST.test(candidate)) throw new ExtensionControlProtocolError(`${label} must be a SHA-256 digest`);
  return candidate;
}
function version(value, label) {
  const candidate = string(value, label);
  if (!VERSION.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not a semantic implementation version`);
  return candidate;
}
function stringList(value, label, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  return array(value, label, max).map((item, index) => string(item, `${label}[${index}]`));
}
function idList(value, label, pattern, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}
function safeVariant(value, label) {
  const item = record(value, label);
  return {
    variant_id: string(item.variant_id, `${label}.variant_id`),
    title: string(item.title, `${label}.title`),
    matcher_kind: string(item.matcher_kind, `${label}.matcher_kind`)
  };
}
function rule(value, extensionId, label) {
  const item = record(value, label);
  const ruleId = id(item.rule_id, `${label}.rule_id`, RULE_ID);
  if (!ruleId.startsWith(`${extensionId}.`)) throw new ExtensionControlProtocolError(`${label}.rule_id belongs to another extension`);
  const rawVersion = item.rule_version;
  if (!(typeof rawVersion === "string" || Number.isSafeInteger(rawVersion))) {
    throw new ExtensionControlProtocolError(`${label}.rule_version must be string or integer`);
  }
  return {
    rule_id: ruleId,
    rule_version: rawVersion,
    title: string(item.title, `${label}.title`),
    description: string(item.description, `${label}.description`),
    severity: enumValue(item.severity, `${label}.severity`, ["low", "medium", "high", "critical"]),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"]),
    matcher_kind: string(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool(item.compatibility_fallback, `${label}.compatibility_fallback`)
  };
}
function permission(value, extensionId, label) {
  const item = record(value, label);
  const permissionId = id(item.permission_id, `${label}.permission_id`, PERMISSION_ID);
  const owner = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  if (owner !== extensionId || !permissionId.startsWith(`${extensionId}.permission.`)) {
    throw new ExtensionControlProtocolError(`${label} belongs to another extension`);
  }
  const replacement = item.replacement_permission_id === null ? null : id(item.replacement_permission_id, `${label}.replacement_permission_id`, PERMISSION_ID);
  return {
    permission_id: permissionId,
    schema_version: integer(item.schema_version, `${label}.schema_version`, 1),
    extension_id: owner,
    implementation_version: version(item.implementation_version, `${label}.implementation_version`),
    label: string(item.label, `${label}.label`),
    description: string(item.description, `${label}.description`),
    risk_tier: enumValue(item.risk_tier, `${label}.risk_tier`, ["low", "medium", "high", "critical"]),
    baseline_floor: enumValue(item.baseline_floor, `${label}.baseline_floor`, ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]),
    default_enabled: bool(item.default_enabled, `${label}.default_enabled`),
    configurable: bool(item.configurable, `${label}.configurable`),
    fixed_reason: optionalString(item.fixed_reason, `${label}.fixed_reason`),
    typed_capabilities: stringList(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    rule_ids: idList(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList(item.safer_guidance, `${label}.safer_guidance`)
  };
}
function extension(value, label) {
  const item = record(value, label);
  const extensionId = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  const rules = array(item.rules, `${label}.rules`, EXTENSION_CLIENT_LIMITS.rulesPerExtension).map((entry, index) => rule(entry, extensionId, `${label}.rules[${index}]`));
  const permissions = array(item.permissions, `${label}.permissions`, EXTENSION_CLIENT_LIMITS.permissionsPerExtension).map((entry, index) => permission(entry, extensionId, `${label}.permissions[${index}]`));
  const ruleIds = rules.map((entry) => entry.rule_id);
  const permissionIds = permissions.map((entry) => entry.permission_id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new ExtensionControlProtocolError(`${label}.rules contains duplicate rule IDs`);
  if (new Set(permissionIds).size !== permissionIds.length) throw new ExtensionControlProtocolError(`${label}.permissions contains duplicate permission IDs`);
  const knownRules = new Set(ruleIds);
  for (const spec of permissions) {
    for (const ruleId of spec.rule_ids) {
      if (!knownRules.has(ruleId)) throw new ExtensionControlProtocolError(`${label} permission references unknown rule ${ruleId}`);
    }
  }
  const ruleCount = integer(item.rule_count, `${label}.rule_count`);
  const permissionCount = integer(item.permission_count, `${label}.permission_count`);
  if (ruleCount !== rules.length || permissionCount !== permissions.length) {
    throw new ExtensionControlProtocolError(`${label} count metadata does not match payload`);
  }
  return {
    schema_version: integer(item.schema_version, `${label}.schema_version`, 1),
    extension_id: extensionId,
    name: string(item.name, `${label}.name`),
    description: string(item.description, `${label}.description`),
    enabled: bool(item.enabled, `${label}.enabled`),
    required: bool(item.required, `${label}.required`),
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"]),
    version: version(item.version, `${label}.version`),
    aliases: idList(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList(item.executables, `${label}.executables`),
    project_markers: stringList(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions
  };
}
function controlLayer(value, label) {
  const item = record(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record(entry, `${label}.controls[${index}]`);
    const kind = enumValue(raw.target_kind, `${label}.controls[${index}].target_kind`, ["extension", "permission"]);
    return {
      target_kind: kind,
      target_id: id(raw.target_id, `${label}.controls[${index}].target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      state: enumValue(raw.state, `${label}.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target_kind}:${control.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError(`${label}.controls contains duplicate targets`);
  return {
    schema_version: string(item.schema_version, `${label}.schema_version`),
    kind: enumValue(item.kind, `${label}.kind`, ["local-admin", "signed-cloud"]),
    catalog_digest: digest(item.catalog_digest, `${label}.catalog_digest`),
    global_lockdown: bool(item.global_lockdown, `${label}.global_lockdown`),
    controls
  };
}
function normalizeExtensionCatalog(value) {
  const root = record(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === void 0 ? void 0 : record(root.limits, "catalog.limits");
  return {
    schema_version: string(root.schema_version, "catalog.schema_version"),
    control_schema_version: root.control_schema_version === void 0 ? void 0 : string(root.control_schema_version, "catalog.control_schema_version"),
    catalog_digest: digest(root.catalog_digest, "catalog.catalog_digest"),
    extensions,
    limits: limits === void 0 ? void 0 : {
      max_body_bytes: limits.max_body_bytes === void 0 ? void 0 : integer(limits.max_body_bytes, "catalog.limits.max_body_bytes", 1),
      max_controls: limits.max_controls === void 0 ? void 0 : integer(limits.max_controls, "catalog.limits.max_controls", 1),
      max_observations: limits.max_observations === void 0 ? void 0 : integer(limits.max_observations, "catalog.limits.max_observations", 1)
    }
  };
}
function normalizeEffectiveExtensionControls(value) {
  const root = record(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record(entry, `effective.controls[${index}]`);
    const target = record(raw.target, `effective.controls[${index}].target`);
    const kind = enumValue(target.kind, `effective.controls[${index}].target.kind`, ["extension", "permission"]);
    return {
      target: {
        kind,
        target_id: id(target.target_id, `effective.controls[${index}].target.target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID)
      },
      state: enumValue(raw.state, `effective.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target.kind}:${control.target.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError("effective.controls contains duplicate targets");
  const layers = array(root.layers, "effective.layers", EXTENSION_CLIENT_LIMITS.layers).map((entry, index) => controlLayer(entry, `effective.layers[${index}]`));
  const failures = array(root.failures, "effective.failures", EXTENSION_CLIENT_LIMITS.failures).map((entry, index) => {
    const raw = record(entry, `effective.failures[${index}]`);
    return {
      code: string(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === void 0 ? void 0 : string(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === void 0 ? void 0 : string(raw.layer_kind, `effective.failures[${index}].layer_kind`)
    };
  });
  return {
    schema_version: string(root.schema_version, "effective.schema_version"),
    health: enumValue(root.health, "effective.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    revision: integer(root.revision, "effective.revision"),
    catalog_digest: digest(root.catalog_digest, "effective.catalog_digest"),
    global_lockdown: bool(root.global_lockdown, "effective.global_lockdown"),
    controls,
    layers,
    failures
  };
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
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ExtensionControlApiError(`Guard returned invalid JSON (${response.status})`, response.status);
  }
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
async function fetchExtensionCatalog() {
  return normalizeExtensionCatalog(await request("/v1/extension-controls/catalog"));
}
async function fetchEffectiveExtensionControls() {
  return normalizeEffectiveExtensionControls(await request("/v1/extension-controls/effective"));
}
async function recoverExtensionControlAuthority(credentials) {
  return normalizeEffectiveExtensionControls(await request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  }));
}
async function acknowledgeDegradedExtensionControlAuthority(credentials) {
  return normalizeEffectiveExtensionControls(await request("/v1/extension-controls/acknowledge-degraded", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  }));
}
async function previewExtensionMutation(payload) {
  const result = await request("/v1/extension-controls/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (typeof result !== "object" || result === null || Array.isArray(result)) {
    throw new ExtensionControlApiError("Guard returned an invalid preview response", 502);
  }
  return result;
}
async function applyExtensionMutation(payload) {
  const result = await request("/v1/extension-controls/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (typeof result !== "object" || result === null || Array.isArray(result)) {
    throw new ExtensionControlApiError("Guard returned an invalid apply response", 502);
  }
  return result;
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
  const id2 = extensionId.toLowerCase();
  for (const [prefix, domain] of DOMAIN_PREFIX_MAP) {
    if (id2.startsWith(prefix)) return domain;
  }
  return "core";
}
function isExtensionEnabled(effective, extension2) {
  return extensionEffectiveState(effective, extension2) === "enabled";
}
function hasActiveFilters(filters) {
  return filters.query.trim() !== "" || filters.risk !== "all" || filters.domain !== "all" || filters.state !== "all" || filters.required !== "all";
}
function searchHaystack(extension2) {
  const parts = [
    extension2.name,
    extension2.extension_id,
    extension2.description,
    extension2.source,
    ...extension2.action_classes,
    ...extension2.risk_classes,
    classifyDomain(extension2.extension_id)
  ];
  return parts.join(" ").toLowerCase();
}
function matchExtensionQuery(extension2, query) {
  const normalized = query.trim().toLowerCase();
  if (normalized === "") return true;
  const haystack = searchHaystack(extension2);
  return normalized.split(/\s+/).every((token) => haystack.includes(token));
}
function filterExtensions(extensions, effective, filters) {
  const items = extensions.filter((extension2) => {
    if (!matchExtensionQuery(extension2, filters.query)) return false;
    if (filters.risk !== "all" && !extension2.risk_classes.includes(filters.risk)) return false;
    if (filters.domain !== "all" && classifyDomain(extension2.extension_id) !== filters.domain) return false;
    if (filters.required !== "all") {
      const isRequired = extension2.required;
      if (filters.required === "required" && !isRequired) return false;
      if (filters.required === "optional" && isRequired) return false;
    }
    if (filters.state !== "all") {
      const enabled = isExtensionEnabled(effective, extension2);
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
      for (const extension2 of props.extensions) {
        for (const risk of extension2.risk_classes) {
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
function currentExtensionRouteState() {
  return {
    route: parseExtensionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search)
  };
}
function extensionRecoveryAction(health) {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      actionLabel: "Repair now",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority"
    };
  }
  if (health === "degraded-unacknowledged") {
    return {
      title: "Acknowledge degraded extension controls",
      actionLabel: "Acknowledge degraded state",
      copyLabel: "Copy status command",
      description: "Guard is failing closed because extension-control authority is degraded. Authenticate to acknowledge the degraded state. Acknowledgement does not restore protected authority.",
      command: "hol-guard status"
    };
  }
  if (health === "degraded-acknowledged") {
    return {
      title: "Degraded extension controls acknowledged",
      copyLabel: "Copy status command",
      description: "Guard remains fail-closed while extension-control authority is degraded. Restore protected authority before changing extension policy.",
      command: "hol-guard status"
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
    local.controls.sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    );
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
  const handleCopy = reactExports.useCallback(async () => {
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
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 shrink-0", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Protected authority" }),
        " · revision ",
        props.effective.revision
      ] })
    ] });
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required" || props.effective.health === "degraded-unacknowledged";
  const busyLabel = props.effective.health === "degraded-unacknowledged" ? "Acknowledging…" : "Repairing…";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-amber-200 bg-amber-50 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: recovery?.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-700", children: recovery?.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
        repairable && props.onRecover ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-busy": props.busy, disabled: props.busy, onClick: props.onRecover, className: "inline-flex min-h-11 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60", children: [
          props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4", "aria-hidden": "true" }),
          props.busy ? busyLabel : recovery?.actionLabel
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onRetry, className: "inline-flex min-h-11 items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4", "aria-hidden": "true" }),
          "Check again"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-amber-200 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Command-line fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800", children: recovery?.command }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleCopy, className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-brand-blue", children: [
            copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
            copyState === "copied" ? "Copied" : recovery?.copyLabel
          ] })
        ] }),
        copyState === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", className: "mt-2 block text-sm text-red-700", children: "Copy failed. Select the command above." }) : null
      ] }),
      props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-red-700", children: props.error }) : null,
      props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-slate-800", children: props.status }) : null
    ] })
  ] }) });
}
function ExtensionCard(props) {
  const domain = classifyDomain(props.extension.extension_id);
  const risks = props.extension.risk_classes.filter((risk) => risk in RISK_CLASS_LABELS);
  const enabled = isExtensionEnabled(props.effective, props.extension);
  const stateLabel = extensionStateLabel(props.effective, props.extension);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "group relative flex min-h-60 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition motion-reduce:transition-none hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)] motion-reduce:hover:translate-y-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-label": `View ${props.extension.name} details`, onClick: () => props.onOpen(props.extension), className: "absolute inset-0 z-0 rounded-3xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "View details" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "pointer-events-none relative z-10 flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-11 place-items-center rounded-2xl bg-blue-50 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPuzzlePiece, { className: "size-6", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rounded-full border px-2.5 py-1 text-xs font-semibold ${enabled ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700"}`, children: stateLabel })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "pointer-events-none relative z-10 mt-5 flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: props.extension.name }),
      props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand-blue", children: "Required" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "pointer-events-none relative z-10 mt-2 line-clamp-3 text-sm leading-6 text-slate-600", children: props.extension.description }),
    risks.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "pointer-events-none relative z-10 mt-3 flex flex-wrap gap-1", children: risks.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`, children: RISK_CLASS_LABELS[risk] }, risk)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "pointer-events-none relative z-10 mt-4 flex flex-wrap gap-2 text-xs text-slate-500", children: [
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative z-10 mt-auto flex items-end justify-between gap-3 border-t border-slate-100 pt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "pointer-events-none inline-flex items-center gap-1 text-sm font-semibold text-brand-blue", children: [
        "View details ",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-4", "aria-hidden": "true" })
      ] }),
      !props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.locked, onClick: () => props.onChange({ extension: props.extension, enabled: !enabled }), className: "min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50", children: "Review capability policy" }) : null
    ] })
  ] });
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown` : `${props.change.enabled ? "Allow" : "Block"} ${props.change.extension.name} capability`;
  const current = "globalLockdown" in props.change ? props.change.globalLockdown ? "Open" : "Lockdown" : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change ? props.change.globalLockdown ? "Lockdown" : "Open" : props.change.enabled ? "Allowed" : "Blocked";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "extension-review-title", onSubmit: (event) => {
    event.preventDefault();
    props.onConfirm(password, totp);
  }, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review capability control" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-review-title", className: "mt-2 text-xl font-semibold text-slate-950", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, "aria-label": "Close review", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-slate-950", children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: current }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: requested })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm text-slate-600", children: "Blocking a capability makes Guard block matching actions. It does not turn detector coverage off." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-5 block text-sm font-medium text-slate-700", children: [
      "Approval password",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "password", autoComplete: "current-password", value: password, onChange: (event) => setPassword(event.target.value), className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block text-sm font-medium text-slate-700", children: [
      "Authenticator code",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { inputMode: "numeric", autoComplete: "one-time-code", value: totp, onChange: (event) => setTotp(event.target.value), className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-700", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: props.busy, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : `Confirm ${requested.toLowerCase()}` })
    ] })
  ] }) });
}
function ExtensionsWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [routeState, setRouteState] = reactExports.useState(() => currentExtensionRouteState());
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = reactExports.useState(false);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const [provenanceOpen, setProvenanceOpen] = reactExports.useState(false);
  const [filters, setFilters] = reactExports.useState(EMPTY_EXTENSION_FILTERS);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = reactExports.useRef(null);
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Catalog changed while extension controls were loading. Refresh Guard and try again.");
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = reactExports.useMemo(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = reactExports.useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);
  reactExports.useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    const href = extensionDetailHref(canonicalSelected, routeState.detail);
    window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);
  const openExtension = reactExports.useCallback((extension2) => {
    const href = extensionDetailHref(extension2.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: extension2.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const updateDetailState = reactExports.useCallback((next) => {
    if (!canonicalSelected) return;
    const href = extensionDetailHref(canonicalSelected, next);
    const historyMode = next.tab !== routeState.detail.tab || next.ruleId !== routeState.detail.ruleId ? "push" : "replace";
    if (historyMode === "push") window.history.pushState({}, "", href);
    else window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: next });
  }, [canonicalSelected, routeState.detail]);
  const requestBroadControl = reactExports.useCallback((extension2) => {
    if (state.kind !== "ready") return;
    setMutationError(null);
    setPending({ extension: extension2, enabled: !isExtensionEnabled(state.effective, extension2) });
  }, [state]);
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
    const acknowledgingDegraded2 = state.kind === "ready" && state.effective.health === "degraded-unacknowledged";
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(acknowledgingDegraded2 ? "Acknowledging degraded extension controls…" : "Repairing extension controls…");
    try {
      const effective = acknowledgingDegraded2 ? await acknowledgeDegradedExtensionControlAuthority(credentials) : await recoverExtensionControlAuthority(credentials);
      if (acknowledgingDegraded2) {
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
        setRecoveryError(error instanceof Error ? error.message : acknowledgingDegraded2 ? "Guard could not acknowledge degraded extension controls." : "Guard could not repair extension controls.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);
  if (state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-7 animate-spin text-brand-blue motion-reduce:animate-none" }) });
  if (state.kind === "error") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "mx-auto max-w-5xl p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-red-200 bg-red-50 p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-red-950", children: "Extensions unavailable" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-2 text-sm text-red-700", children: state.message }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: load, className: "mt-4 min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white", children: "Try again" })
  ] }) });
  const acknowledgingDegraded = state.effective.health === "degraded-unacknowledged";
  const recoveryBanner = /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatusBanner, { busy: recoveryBusy, effective: state.effective, error: recoveryError, status: recoveryStatus, onRecover: () => {
    void recover();
  }, onRetry: load });
  const recoveryModal = recoveryApprovalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofModal, { title: acknowledgingDegraded ? "Acknowledge degraded extension controls" : "Repair extension controls", detail: acknowledgingDegraded ? "Authenticate this acknowledgement on your device. Guard remains fail-closed until protected authority is restored." : "Authenticate this repair on your device. Guard uses the proof once and does not store it.", confirmLabel: acknowledgingDegraded ? "Acknowledge degraded state" : "Repair controls", approvalGate: resolvedApprovalGate, busy: recoveryBusy, error: recoveryError, onCancel: () => {
    if (!recoveryBusy) setRecoveryApprovalOpen(false);
  }, onConfirm: (credentials) => {
    void recover(credentials);
  } }) : null;
  if (routeState.route.kind === "detail" && selectedExtension) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto w-full max-w-7xl px-4 pt-6 sm:px-6 lg:px-8", children: recoveryBanner }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionControlCenterDetail, { extension: selectedExtension, effective: state.effective, catalogDigest: state.catalog.catalog_digest, urlState: routeState.detail, onUrlState: updateDetailState, onBack: closeExtension, onBroadControl: () => requestBroadControl(selectedExtension) }),
      pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, onCancel: () => {
        if (!busy) setPending(null);
      }, onConfirm: confirm }) : null,
      recoveryModal
    ] });
  }
  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto max-w-4xl p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: recoveryBanner }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 rounded-3xl border border-amber-200 bg-amber-50 p-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: "Extension not found" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-800", children: "This extension route is invalid or the canonical extension is not present in the current catalog." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: closeExtension, className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: "Back to extensions" })
        ] })
      ] }),
      recoveryModal
    ] });
  }
  const locked = state.effective.health !== "protected";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.22em] text-brand-blue", children: "Command safety" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: "Extensions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: "Inspect canonical command protections and review broad capability policy without changing detector truth." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: locked, onClick: () => setPending({ globalLockdown: !state.effective.global_lockdown }), className: `inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 text-sm font-semibold ${state.effective.global_lockdown ? "bg-red-700 text-white" : "border border-slate-300 bg-white text-slate-700"} disabled:opacity-50`, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-4" }),
        state.effective.global_lockdown ? "Review ending lockdown" : "Review global lockdown"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: recoveryBanner }),
    state.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-5" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Global lockdown active." }),
        " Matching capabilities are blocked regardless of optional local controls."
      ] })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "installed-extensions", className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "installed-extensions", className: "text-lg font-semibold text-slate-950", children: "Installed extensions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
            catalogExtensions.length,
            " available"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Search by name or command, or filter by risk, domain, and effective state." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsFilterBar, { filters, onChange: (patch) => setFilters((previous) => ({ ...previous, ...patch })), onClear: () => setFilters(EMPTY_EXTENSION_FILTERS), extensions: catalogExtensions, effective: state.effective }) }),
      filtered.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3", children: filtered.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionCard, { extension: extension2, effective: state.effective, locked: locked || state.effective.global_lockdown, onChange: (change) => {
        setMutationError(null);
        setPending(change);
      }, onOpen: openExtension }, extension2.extension_id)) }) : hasActiveFilters(effectiveFilters) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-col items-center gap-3 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "size-7 text-slate-300", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-slate-900", children: "No extensions match these filters" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-sm text-sm text-slate-500", children: "Try a different search term or clear the filters." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => setFilters(EMPTY_EXTENSION_FILTERS), className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: "Clear filters" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center text-sm text-slate-500", children: "No extensions are registered." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 overflow-hidden rounded-3xl border border-slate-200 bg-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => setProvenanceOpen((value) => !value), "aria-expanded": provenanceOpen, className: "flex min-h-11 w-full items-center justify-between p-5 text-left", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block font-semibold text-slate-950", children: "Policy provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-1 block text-sm text-slate-500", children: [
            "Catalog ",
            state.catalog.catalog_digest.slice(0, 12),
            "… · ",
            state.effective.layers.length,
            " authority layer",
            state.effective.layers.length === 1 ? "" : "s"
          ] })
        ] }),
        provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "size-5" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-5" })
      ] }),
      provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-200 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: state.effective.layers.map((layer) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-600" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-slate-900", children: layer.kind === "local-admin" ? "Local administrator" : "Signed cloud policy" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-slate-500", children: [
          layer.controls.length,
          " explicit controls · catalog ",
          layer.catalog_digest.slice(0, 12),
          "…"
        ] })
      ] }, `${layer.kind}-${layer.catalog_digest}`)) }) }) : null
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
  currentExtensionRouteState,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval
};
