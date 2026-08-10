from __future__ import annotations

import json
from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected one marker, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Backend: authenticated history projection. Private hashes, MACs, proof IDs and raw
# commands are intentionally never returned.
p = Path("src/codex_plugin_scanner/guard/store_extension_control_authority_transitions.py")
t = p.read_text(encoding="utf-8")
t = t.replace("    layers_from_json,\n", "    layers_from_json,\n    layers_to_json,\n", 1)
marker = "    def _commit_pending_transition(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:\n"
method = '''    def list_extension_control_authority_history(\n        self,\n        *,\n        catalog_digest: str,\n        limit: int = 20,\n    ) -> list[dict[str, object]]:\n        \"\"\"Return authenticated, privacy-safe prior snapshots for the current catalog.\"\"\"\n\n        if type(limit) is not int or limit < 1 or limit > 50:\n            raise ExtensionControlAuthorityError(\"invalid extension control history limit\")\n        with self._extension_control_authority_lock():\n            current = self._read_extension_control_authority_locked(catalog_digest)\n            if current.health is not AuthorityHealth.PROTECTED:\n                raise ExtensionControlAuthorityError(\"extension control history unavailable\")\n            if current.revision <= 0:\n                return []\n            key = self._authority_key(required=True)\n            assert key is not None\n            anchor = self._read_anchor(key=key)\n            if (\n                anchor is None\n                or anchor.phase is not AuthorityPhase.COMMITTED\n                or anchor.revision != current.revision\n            ):\n                raise ExtensionControlAuthorityError(\"extension control history anchor mismatch\")\n            self._validate_transition_chain(\n                current.revision,\n                current_snapshot_digest=anchor.snapshot_digest,\n                key=key,\n            )\n            with self._connect() as connection:\n                rows = cast(\n                    list[sqlite3.Row],\n                    connection.execute(\n                        \"\"\"\n                        select * from extension_control_authority_transition\n                        where phase = ? and catalog_digest = ? and revision < ?\n                        order by revision desc limit ?\n                        \"\"\",\n                        (AuthorityPhase.COMMITTED.value, catalog_digest, current.revision, limit),\n                    ).fetchall(),\n                )\n            history: list[dict[str, object]] = []\n            for row in rows:\n                layers_json = _row_str(row, \"layers_json\")\n                self._validate_serialized_layers(layers_json)\n                layers = layers_from_json(layers_json)\n                self._validate_layers(layers, catalog_digest)\n                occurred_at = _row_optional_str(row, \"committed_at\") or _row_str(row, \"created_at\")\n                history.append(\n                    {\n                        \"revision\": _row_int(row, \"revision\"),\n                        \"previous_revision\": _row_int(row, \"previous_revision\"),\n                        \"occurred_at\": occurred_at,\n                        \"catalog_digest\": catalog_digest,\n                        \"layers\": json.loads(layers_to_json(layers)),\n                    }\n                )\n            return history\n\n'''
if method not in t:
    if marker not in t:
        raise SystemExit("history method marker missing")
    t = t.replace(marker, method + marker, 1)
if "import json\n" not in t:
    t = t.replace("from __future__ import annotations\n\n", "from __future__ import annotations\n\nimport json\n", 1)
p.write_text(t, encoding="utf-8")

# Daemon API: Test Lab delegates to the pure evaluator. History is read-only and
# available only when the authenticated authority chain validates.
p = Path("src/codex_plugin_scanner/guard/daemon/extension_control_api.py")
t = p.read_text(encoding="utf-8")
refresh = '''    def refresh(self) -> dict[str, object]:\n        view = self._store.read_extension_control_authority(\n            catalog_digest=self._registry.catalog_digest,\n        )\n        _ = self._runtime.refresh(view)\n        return self.effective()\n\n'''
addition = '''    def test_command(self, payload: dict[str, object]) -> dict[str, object]:\n        from .extension_control_test_api import evaluate_extension_control_test\n\n        return evaluate_extension_control_test(\n            registry=self._registry,\n            runtime=self._runtime,\n            payload=payload,\n        )\n\n    def history(self) -> dict[str, object]:\n        current = self._runtime.current()\n        try:\n            items = self._store.list_extension_control_authority_history(\n                catalog_digest=self._registry.catalog_digest,\n                limit=20,\n            )\n        except ExtensionControlAuthorityError as exc:\n            raise ExtensionControlApiError(409, \"authority_history_unavailable\") from exc\n        return {\n            \"schema_version\": \"guard.daemon.extension-control-history.v1\",\n            \"revision\": current.revision,\n            \"catalog_digest\": current.catalog_digest,\n            \"items\": items,\n        }\n\n'''
if addition not in t:
    if t.count(refresh) != 1:
        raise SystemExit("extension-control refresh marker changed")
    t = t.replace(refresh, refresh + addition, 1)
p.write_text(t, encoding="utf-8")

# Authenticated daemon transport.
p = Path("src/codex_plugin_scanner/guard/daemon/server.py")
t = p.read_text(encoding="utf-8")
get_marker = '''        if parsed.path == "/v1/extension-controls/effective":\n            self._write_json(\n                self._daemon_server().extension_control_api.effective(),\n                extra_headers={"Cache-Control": "no-store"},\n            )\n            return\n'''
get_add = get_marker + '''        if parsed.path == "/v1/extension-controls/history":\n            try:\n                history = self._daemon_server().extension_control_api.history()\n            except ExtensionControlApiError as error:\n                self._write_json(error.to_payload(), status=error.status)\n                return\n            self._write_json(history, extra_headers={"Cache-Control": "no-store"})\n            return\n'''
if 'if parsed.path == "/v1/extension-controls/history":' not in t:
    if t.count(get_marker) != 1:
        raise SystemExit("history GET marker changed")
    t = t.replace(get_marker, get_add, 1)
preview_entry = '            "/v1/extension-controls/preview",\n'
if '            "/v1/extension-controls/test",\n' not in t:
    if preview_entry not in t:
        raise SystemExit("extension-control path allowlist changed")
    t = t.replace(preview_entry, preview_entry + '            "/v1/extension-controls/test",\n', 1)
dispatch = '''                if parsed.path.endswith("/preview"):\n                    response = self._daemon_server().extension_control_api.preview(payload)'''
replacement = '''                if parsed.path.endswith("/test"):\n                    response = self._daemon_server().extension_control_api.test_command(payload)\n                elif parsed.path.endswith("/preview"):\n                    response = self._daemon_server().extension_control_api.preview(payload)'''
if replacement not in t:
    if t.count(dispatch) != 1:
        raise SystemExit("extension-control POST dispatch changed")
    t = t.replace(dispatch, replacement, 1)
p.write_text(t, encoding="utf-8")

# Frontend protocol normalizer: expose the existing strict layer parser for history.
p = Path("dashboard/src/extension-controls-normalize.ts")
t = p.read_text(encoding="utf-8")
old = "function controlLayer(value: unknown, label: string): ExtensionControlLayer {"
new = "export function normalizeExtensionControlLayer(value: unknown, label = \"layer\"): ExtensionControlLayer {"
if new not in t:
    if old not in t:
        raise SystemExit("control layer normalizer marker missing")
    t = t.replace(old, new, 1)
t = t.replace("controlLayer(entry, `effective.layers[${index}]`)", "normalizeExtensionControlLayer(entry, `effective.layers[${index}]`)")
p.write_text(t, encoding="utf-8")

# Frontend API: strongly validate authenticated history before it can become a draft.
p = Path("dashboard/src/extension-controls-api.ts")
t = p.read_text(encoding="utf-8")
t = t.replace(
    '  normalizeExtensionCatalog,\n} from "./extension-controls-normalize";',
    '  normalizeExtensionCatalog,\n  normalizeExtensionControlLayer,\n} from "./extension-controls-normalize";',
    1,
)
type_marker = '''export type ExtensionMutationPayload = {\n'''
history_types = '''export type ExtensionControlHistoryItem = {\n  revision: number;\n  previous_revision: number;\n  occurred_at: string;\n  catalog_digest: string;\n  layers: ExtensionControlLayer[];\n};\n\nexport type ExtensionControlHistoryResponse = {\n  schema_version: "guard.daemon.extension-control-history.v1";\n  revision: number;\n  catalog_digest: string;\n  items: ExtensionControlHistoryItem[];\n};\n\n'''
if history_types not in t:
    if type_marker not in t:
        raise SystemExit("history type marker missing")
    t = t.replace(type_marker, history_types + type_marker, 1)
fetch_marker = '''export async function recoverExtensionControlAuthority(credentials?: {\n'''
history_fetch = '''export async function fetchExtensionControlHistory(): Promise<ExtensionControlHistoryResponse> {\n  const raw = await request("/v1/extension-controls/history");\n  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ExtensionControlApiError("Guard returned invalid settings history", 502);\n  const root = raw as Record<string, unknown>;\n  if (root.schema_version !== "guard.daemon.extension-control-history.v1") throw new ExtensionControlApiError("Guard returned unsupported settings history", 502);\n  if (!Number.isSafeInteger(root.revision) || (root.revision as number) < 0 || typeof root.catalog_digest !== "string") throw new ExtensionControlApiError("Guard returned invalid settings history metadata", 502);\n  if (!Array.isArray(root.items) || root.items.length > 50) throw new ExtensionControlApiError("Guard returned too much settings history", 502);\n  const items = root.items.map((value, index) => {\n    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);\n    const item = value as Record<string, unknown>;\n    if (!Number.isSafeInteger(item.revision) || !Number.isSafeInteger(item.previous_revision) || typeof item.occurred_at !== "string" || typeof item.catalog_digest !== "string" || !Array.isArray(item.layers)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);\n    const layers = item.layers.map((layer, layerIndex) => normalizeExtensionControlLayer(layer, `history.items[${index}].layers[${layerIndex}]`));\n    return {\n      revision: item.revision as number,\n      previous_revision: item.previous_revision as number,\n      occurred_at: item.occurred_at,\n      catalog_digest: item.catalog_digest,\n      layers,\n    };\n  });\n  return {\n    schema_version: "guard.daemon.extension-control-history.v1",\n    revision: root.revision as number,\n    catalog_digest: root.catalog_digest,\n    items,\n  };\n}\n\n'''
if history_fetch not in t:
    if fetch_marker not in t:
        raise SystemExit("history fetch marker missing")
    t = t.replace(fetch_marker, history_fetch + fetch_marker, 1)
p.write_text(t, encoding="utf-8")

Path("dashboard/src/protection-center/protection-settings-history.tsx").write_text('''import { useEffect, useState } from "react";\n\nimport { fetchExtensionControlHistory, type ExtensionControlLayer } from "../extension-controls-api";\n\nexport function ProtectionSettingsHistory(props: {\n  catalogDigest: string;\n  disabled?: boolean;\n  onUse: (layers: ExtensionControlLayer[], revision: number) => void;\n}) {\n  const [items, setItems] = useState<Awaited<ReturnType<typeof fetchExtensionControlHistory>>["items"]>([]);\n  const [loading, setLoading] = useState(true);\n  const [error, setError] = useState<string | null>(null);\n  useEffect(() => {\n    let active = true;\n    setLoading(true);\n    fetchExtensionControlHistory().then((history) => {\n      if (!active) return;\n      setItems(history.items.filter((item) => item.catalog_digest === props.catalogDigest));\n      setError(null);\n    }).catch(() => { if (active) setError("Local settings history is unavailable until Guard verifies settings integrity."); }).finally(() => { if (active) setLoading(false); });\n    return () => { active = false; };\n  }, [props.catalogDigest]);\n  return <details className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4"><summary className="cursor-pointer text-sm font-semibold text-slate-800">Settings history</summary><p className="mt-2 text-xs leading-5 text-slate-600">Guard verifies the authenticated local history before showing it. Restoring a version only prepares the device layer as a draft. Current organization policy stays in force, and nothing changes until you review and approve it.</p>{loading ? <p className="mt-3 text-xs text-slate-500">Loading verified history…</p> : error ? <p className="mt-3 text-xs text-amber-800">{error}</p> : items.length ? <div className="mt-3 space-y-2">{items.slice(0, 10).map((item) => <div key={item.revision} className="flex flex-col gap-2 rounded-xl bg-white p-3 sm:flex-row sm:items-center sm:justify-between"><div><div className="text-sm font-medium text-slate-800">Device settings revision {item.revision}</div><time className="text-xs text-slate-500" dateTime={item.occurred_at}>{new Date(item.occurred_at).toLocaleString()}</time></div><button type="button" disabled={props.disabled} onClick={() => props.onUse(item.layers, item.revision)} className="min-h-10 rounded-xl border border-slate-300 bg-white px-3 text-xs font-semibold text-brand-blue disabled:opacity-40">Use this version as draft</button></div>)}</div> : <p className="mt-3 text-xs text-slate-500">No earlier authenticated device settings are available yet.</p>}</details>;\n}\n''', encoding="utf-8")

Path("dashboard/src/protection-center/protection-repair-card.tsx").write_text('''import { useState } from "react";\nimport { HiMiniWrenchScrewdriver } from "react-icons/hi2";\n\nimport { ApprovalProofModal } from "../approval-proof-modal";\nimport { recoverExtensionControlAuthority, type EffectiveExtensionControls } from "../extension-controls-api";\nimport { useResolvedApprovalGate } from "../use-resolved-approval-gate";\n\nexport function ProtectionRepairCard(props: { effective: EffectiveExtensionControls; onRefresh: () => Promise<void> | void }) {\n  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required";\n  const [open, setOpen] = useState(false);\n  const [busy, setBusy] = useState(false);\n  const [error, setError] = useState<string | null>(null);\n  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);\n  if (!repairable) return null;\n  const begin = async () => {\n    try { await resolveApprovalGate({ failClosed: true }); setError(null); setOpen(true); }\n    catch { setError("Guard could not load the local approval gate. Repair was not started."); }\n  };\n  const repair = async (credentials: { approval_password?: string; approval_totp_code?: string }) => {\n    setBusy(true); setError(null);\n    try { await recoverExtensionControlAuthority(credentials); setOpen(false); await props.onRefresh(); }\n    catch (cause) { setError(cause instanceof Error ? cause.message : "Guard could not repair settings integrity."); }\n    finally { setBusy(false); }\n  };\n  return <section aria-labelledby="protection-repair-heading" className="mt-5 rounded-3xl border border-amber-200 bg-amber-50 p-5 sm:p-6"><div className="flex items-start gap-3"><HiMiniWrenchScrewdriver className="mt-0.5 size-5 shrink-0 text-amber-800" aria-hidden="true" /><div><h2 id="protection-repair-heading" className="font-semibold text-amber-950">Repair protection settings integrity</h2><p className="mt-1 text-sm leading-6 text-amber-900">Guard is staying fail-safe because the authenticated local settings state cannot be trusted. Repair rebuilds a protected local authority after explicit approval. Organization policy is not weakened.</p><button type="button" onClick={() => { void begin(); }} className="mt-4 min-h-11 rounded-xl bg-amber-900 px-4 text-sm font-semibold text-white">Repair safely</button>{error && !open ? <p role="alert" className="mt-3 text-sm text-red-800">{error}</p> : null}</div></div>{open ? <ApprovalProofModal title="Repair protection settings" detail="Authenticate this local recovery. Guard will rebuild settings integrity fail-safe and then reload the current protected state." confirmLabel="Repair settings" approvalGate={resolvedApprovalGate} busy={busy} error={error} onCancel={() => { if (!busy) setOpen(false); }} onConfirm={(credentials) => { void repair(credentials); }} /> : null}</section>;\n}\n''', encoding="utf-8")

# Policy editor: verified history can only become a draft; current signed organization
# layers are always preserved.
p = Path("dashboard/src/extension-policy-panel.tsx")
t = p.read_text(encoding="utf-8")
import_marker = 'import { useResolvedApprovalGate } from "./use-resolved-approval-gate";\n'
history_import = 'import { ProtectionSettingsHistory } from "./protection-center/protection-settings-history";\n'
if history_import not in t:
    if import_marker not in t:
        raise SystemExit("policy history import marker missing")
    t = t.replace(import_marker, import_marker + history_import, 1)
profile_marker = '''  const configurableCount = policyExtension.permissions.filter((permission) => permission.configurable).length;\n'''
history_callback = '''  const useHistoricalDraft = useCallback((historicalLayers: EffectiveExtensionControls["layers"], _revision: number) => {\n    draftGeneration.current += 1;\n    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");\n    const next = baseEffective.layers.flatMap((layer) => layer.kind === "local-admin" ? (historicalLocal ? [historicalLocal] : []) : [layer]);\n    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);\n    setDraftLayers(next);\n    setIdentity(newExtensionPolicyDraftIdentity());\n    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);\n  }, [baseEffective.layers]);\n\n'''
if history_callback not in t:
    if profile_marker not in t:
        raise SystemExit("policy history callback marker missing")
    t = t.replace(profile_marker, history_callback + profile_marker, 1)
quick_profile_tail = '''<p className="mt-2 text-xs leading-5 text-slate-500">Profiles only prepare a local draft. Custom appears automatically when you adjust individual settings. You still review the exact outcome and authenticate before anything is applied.</p></div>'''
quick_profile_new = quick_profile_tail + '''<ProtectionSettingsHistory catalogDigest={baseEffective.catalog_digest} disabled={baseEffective.health !== "protected" || refreshRequired} onUse={useHistoricalDraft} />'''
if quick_profile_new not in t:
    if quick_profile_tail not in t:
        raise SystemExit("policy history UI marker missing")
    t = t.replace(quick_profile_tail, quick_profile_new, 1)
p.write_text(t, encoding="utf-8")

# Module detail: Activity, side-effect-free Test Lab, and guided authenticated repair.
p = Path("dashboard/src/protection-center/protection-module-detail.tsx")
t = p.read_text(encoding="utf-8")
activity_import = 'import { useProtectionModuleActivity } from "./use-protection-module-activity";\n'
imports = 'import { ProtectionRepairCard } from "./protection-repair-card";\nimport { ProtectionTestLab } from "./protection-test-lab";\n'
if imports not in t:
    if activity_import not in t:
        raise SystemExit("module integration import marker missing")
    t = t.replace(activity_import, imports + activity_import, 1)
t = t.replace('<h2 id="module-recent-heading" className="text-lg font-semibold text-slate-950">Recent decisions</h2><p className="mt-1 text-sm text-slate-600">Privacy-safe local activity for this protection. Raw commands and paths are not shown.</p>', '<h2 id="module-recent-heading" className="text-lg font-semibold text-slate-950">Activity</h2><p className="mt-1 text-sm text-slate-600">Recent privacy-safe decisions on this device. Raw commands and paths are not shown.</p><p className="mt-2 text-xs leading-5 text-slate-500">Local activity works without Cloud. Guard Cloud adds longer retention, synchronization, advanced search, evidence exports, and team history according to your plan.</p>', 1)
repair_marker = '''</header><div className="mt-6 grid gap-5 lg:grid-cols-2">'''
repair_new = '''</header><ProtectionRepairCard effective={props.effective} onRefresh={props.onRefresh} /><div className="mt-6 grid gap-5 lg:grid-cols-2">'''
if repair_new not in t:
    if repair_marker not in t:
        raise SystemExit("repair card marker missing")
    t = t.replace(repair_marker, repair_new, 1)
lab_marker = '''</section><ModuleRecentDecisions extension={props.extension} /></div>{density !== "simple" ?'''
lab_new = '''</section><ModuleRecentDecisions extension={props.extension} /></div><div className="mt-5"><ProtectionTestLab extension={props.extension} /></div>{density !== "simple" ?'''
if lab_new not in t:
    if lab_marker not in t:
        raise SystemExit("Test Lab insertion marker missing")
    t = t.replace(lab_marker, lab_new, 1)
p.write_text("\n".join(line.rstrip() for line in t.splitlines()) + "\n", encoding="utf-8")

# Existing dashboard Test Lab unit enters the full suite.
p = Path("dashboard/package.json")
d = json.loads(p.read_text(encoding="utf-8"))
cmd = "tsx src/protection-center/protection-test-lab.test.tsx"
parts = [part.strip() for part in d["scripts"]["test"].split("&&")]
if cmd not in parts:
    parts.insert(5 if len(parts) >= 5 else len(parts), cmd)
d["scripts"]["test"] = " && ".join(parts)
p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")

# Authority history tests reuse the repository's real proof/enrollment helpers.
p = Path("tests/test_guard_extension_control_authority.py")
t = p.read_text(encoding="utf-8")
append = '''\n\ndef test_authenticated_history_returns_only_verified_prior_device_layers(tmp_path: Path) -> None:\n    secrets = MemorySecretStore()\n    store = _store(tmp_path, secrets)\n    first = (_disabled_layer(),)\n    committed = store.commit_extension_control_layers(\n        first,\n        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n        actor_id="history-test",\n        expected_revision=0,\n        idempotency_key="history-1",\n        nonce="history-nonce-1",\n        proof=_proof(store, first, revision=0, key="history-1", actor_id="history-test", nonce="history-nonce-1"),\n    )\n    assert committed.revision == 1\n    second: tuple[ExtensionControlLayer, ...] = ()\n    committed = store.commit_extension_control_layers(\n        second,\n        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n        actor_id="history-test",\n        expected_revision=1,\n        idempotency_key="history-2",\n        nonce="history-nonce-2",\n        proof=_proof(store, second, revision=1, key="history-2", actor_id="history-test", nonce="history-nonce-2"),\n    )\n    assert committed.revision == 2\n    history = store.list_extension_control_authority_history(\n        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n        limit=20,\n    )\n    assert [item["revision"] for item in history] == [1]\n    assert history[0]["layers"][0]["kind"] == "local-admin"\n    encoded = json.dumps(history, sort_keys=True)\n    for private_name in ("actor_id_hash", "idempotency_key_hash", "nonce_hash", "snapshot_mac", "transition_mac", "proof"):\n        assert private_name not in encoded\n\n\ndef test_authenticated_history_fails_closed_on_tampered_transition(tmp_path: Path) -> None:\n    secrets = MemorySecretStore()\n    store = _store(tmp_path, secrets)\n    first = (_disabled_layer(),)\n    _ = store.commit_extension_control_layers(\n        first,\n        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n        actor_id="history-test",\n        expected_revision=0,\n        idempotency_key="history-tamper-1",\n        nonce="history-tamper-nonce-1",\n        proof=_proof(store, first, revision=0, key="history-tamper-1", actor_id="history-test", nonce="history-tamper-nonce-1"),\n    )\n    second: tuple[ExtensionControlLayer, ...] = ()\n    _ = store.commit_extension_control_layers(\n        second,\n        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n        actor_id="history-test",\n        expected_revision=1,\n        idempotency_key="history-tamper-2",\n        nonce="history-tamper-nonce-2",\n        proof=_proof(store, second, revision=1, key="history-tamper-2", actor_id="history-test", nonce="history-tamper-nonce-2"),\n    )\n    with store._connect() as connection:\n        connection.execute("update extension_control_authority_transition set transition_mac = ? where revision = 1", ("invalid",))\n    with pytest.raises(ExtensionControlAuthorityError):\n        store.list_extension_control_authority_history(\n            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,\n            limit=20,\n        )\n'''
if "test_authenticated_history_returns_only_verified_prior_device_layers" not in t:
    p.write_text(t.rstrip() + append + "\n", encoding="utf-8")

# Tiny contract test: history is a draft-only surface and repair is approval-gated.
Path("dashboard/src/protection-center/protection-history-repair.test.ts").write_text('''import assert from "node:assert/strict";\nimport fs from "node:fs";\nimport path from "node:path";\nconst history = fs.readFileSync(path.join(process.cwd(), "src/protection-center/protection-settings-history.tsx"), "utf8");\nconst policy = fs.readFileSync(path.join(process.cwd(), "src/extension-policy-panel.tsx"), "utf8");\nconst repair = fs.readFileSync(path.join(process.cwd(), "src/protection-center/protection-repair-card.tsx"), "utf8");\nassert.match(history, /Use this version as draft/);\nassert.doesNotMatch(history, /applyExtensionMutation/);\nassert.match(policy, /historicalLocal/);\nassert.match(policy, /layer.kind === "local-admin"/);\nassert.match(policy, /Review \\{changeCount\\} change/);\nassert.match(repair, /recoverExtensionControlAuthority/);\nassert.match(repair, /resolveApprovalGate\\(\\{ failClosed: true \\}\\)/);\nconsole.log("protection-history-repair.test.ts: all assertions passed");\n''', encoding="utf-8")

d = json.loads(Path("dashboard/package.json").read_text(encoding="utf-8"))
cmd = "tsx src/protection-center/protection-history-repair.test.ts"
parts = [part.strip() for part in d["scripts"]["test"].split("&&")]
if cmd not in parts:
    parts.insert(6 if len(parts) >= 6 else len(parts), cmd)
d["scripts"]["test"] = " && ".join(parts)
Path("dashboard/package.json").write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
