from __future__ import annotations

from pathlib import Path


PATH = Path("dashboard/src/extension-policy-panel.tsx")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    return text.replace(old, new, 1)


text = PATH.read_text(encoding="utf-8")

text = replace_once(
    text,
    '''  const choices: Array<{ value: PermissionDraftState; label: string; disabled?: boolean }> = [
    { value: "inherit", label: "Inherit" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" },
  ];''',
    '''  const choices: Array<{ value: PermissionDraftState; label: string; disabled?: boolean }> = [
    { value: "inherit", label: "Use recommended" },
    { value: "block", label: "Block matching actions" },
    { value: "allow", label: "Allow when Guard would otherwise permit", disabled: managed === "disabled" },
  ];''',
    "setting choices",
)
text = replace_once(text, 'aria-label={`${props.permission.label} local policy`}', 'aria-label={`${props.permission.label} protection setting`}', "setting radio label")
text = text.replace('Managed policy already blocks this permission; local policy cannot weaken it.', 'Your organization already blocks this capability; this device cannot weaken it.')
text = text.replace('{props.permission.risk_tier} baseline risk', '{props.permission.risk_tier} risk')
text = text.replace('<Pill>Fixed</Pill>', '<Pill>Required safety</Pill>')
text = text.replace('<Pill tone="border-indigo-200 bg-indigo-50 text-indigo-800">Managed {managed === "disabled" ? "block" : "allow"}</Pill>', '<Pill tone="border-indigo-200 bg-indigo-50 text-indigo-800">Organization managed</Pill>')
text = replace_once(
    text,
    '<div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">',
    '<details className="mt-3 rounded-xl bg-slate-50 p-3 text-xs text-slate-600"><summary className="cursor-pointer font-semibold text-slate-700">Technical setting details</summary><div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">',
    "technical details opener",
)
text = text.replace('Baseline floor:', 'Minimum protection:', 1)
text = text.replace('Provenance:', 'Managed by:', 1)
text = replace_once(
    text,
    '<code className="mt-2 block break-all text-[11px] text-slate-400">{props.permission.permission_id}</code>',
    '<code className="mt-2 block break-all text-[11px] text-slate-500">{props.permission.permission_id}</code></details>',
    "technical details closer",
)
text = text.replace('<strong>Why fixed:</strong>', '<strong>Why this cannot be changed:</strong>')
text = text.replace('Managed policy blocks this permission. Local policy may inherit or add a block, but it cannot weaken the managed block.', 'Your organization blocks this capability. You can keep the organization setting or add a local block, but this device cannot weaken it.')

text = text.replace('Server semantic preview', 'Protection review')
text = text.replace('Blast radius before apply', 'What will change')
text = text.replace('Newly blocked permissions', 'Newly blocked settings')
text = text.replace('Newly allowed permissions', 'Newly allowed settings')
text = text.replace('Effective changes', 'Settings changing')
text = text.replace('Affected rule IDs', 'Developer details')
text = replace_once(
    text,
    '<p className="mt-4 break-all text-[11px] text-slate-400">Canonical diff: {props.preview.canonical_diff_digest}</p>',
    '<details className="mt-4"><summary className="cursor-pointer text-xs font-semibold text-slate-500">Developer change identity</summary><code className="mt-2 block break-all text-[11px] text-slate-500">{props.preview.canonical_diff_digest}</code></details>',
    "canonical diff disclosure",
)
text = text.replace('>Semantic review</p>', '>Protection review</p>')
text = text.replace('Review {count} permission change{count === 1 ? "" : "s"}', 'Review {count} protection setting change{count === 1 ? "" : "s"}')
text = text.replace('>Apply {count} reviewed change{count === 1 ? "" : "s"}</button>', '>Continue to approval</button>')

marker = '  const configurableCount = policyExtension.permissions.filter((permission) => permission.configurable).length;'
profile = '''  const applyProfile = useCallback((profile: "recommended" | "stricter" | "custom") => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission of policyExtension.permissions) {
      if (!permission.configurable) continue;
      const state: PermissionDraftState = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective, policyExtension]);

'''
text = replace_once(text, marker, profile + marker, "profile insertion")

old_header = '<div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Local policy draft</p><h2 id="extension-policy-heading" className="mt-1 text-lg font-semibold text-slate-950">Permission controls</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">Choose Inherit, Allow, or Block for independently configurable capabilities. A blocked capability makes Guard block matching actions; it does not turn detection off. Detector severity and baseline floors never change.</p></div><div className="flex flex-wrap gap-2"><Pill>{configurableCount} configurable</Pill><Pill>{policyExtension.permissions.length - configurableCount} fixed</Pill>{dirty ? <Pill tone="border-blue-200 bg-blue-50 text-blue-800">{changeCount} staged</Pill> : <Pill>Authoritative</Pill>}</div></div>'
new_header = '<div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">This device</p><h2 id="extension-policy-heading" className="mt-1 text-lg font-semibold text-slate-950">Protection settings</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">Keep Guard\'s recommended behavior or make selected capabilities stricter. Allow is available only where Guard\'s built-in minimum safety and organization policy still permit it. Detection and minimum protection never turn off.</p></div><div className="flex flex-wrap gap-2"><Pill>{configurableCount} configurable</Pill><Pill>{policyExtension.permissions.length - configurableCount} required</Pill>{dirty ? <Pill tone="border-blue-200 bg-blue-50 text-blue-800">{changeCount} staged</Pill> : <Pill>Current</Pill>}</div></div><div className="mt-5"><div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Quick profiles</div><div className="mt-2 flex flex-wrap gap-2"><button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile("recommended")} className="min-h-10 rounded-xl border border-slate-300 bg-white px-3 text-xs font-semibold text-slate-700 disabled:opacity-40">Recommended</button><button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile("stricter")} className="min-h-10 rounded-xl border border-slate-300 bg-white px-3 text-xs font-semibold text-slate-700 disabled:opacity-40">Stricter</button><button type="button" disabled className="min-h-10 rounded-xl border border-slate-300 bg-slate-50 px-3 text-xs font-semibold text-slate-500 opacity-70">Custom</button></div><p className="mt-2 text-xs leading-5 text-slate-500">Profiles only prepare a local draft. Custom appears automatically when you adjust individual settings. You still review the exact outcome and authenticate before anything is applied.</p></div>'
text = replace_once(text, old_header, new_header, "friendly header")
text = text.replace('Global lockdown remains dominant.', 'Emergency Lockdown remains dominant.')
text = text.replace('Permission editing is disabled until extension-control authority is protected.', 'Settings cannot be changed until Guard verifies local settings integrity.')
text = replace_once(
    text,
    '{managedCount} permission{managedCount === 1 ? " is" : "s are"} governed by signed organization policy. Local policy cannot weaken a managed block. Managed exception requests must be made through the organization policy workflow.',
    '{managedCount} setting{managedCount === 1 ? " is" : "s are"} managed by your organization. This device can add stricter blocks but cannot weaken an organization block.',
    "managed summary",
)
text = text.replace('Policy applied. Editing stays locked until this page reloads current authoritative state.', 'Settings applied. Editing stays locked until Guard reloads the current protected state.')
text = text.replace('staged permission change', 'unsaved setting change')
text = text.replace('No local policy changes drafted.', 'No local setting changes prepared.')
text = text.replace('>Discard draft</button>', '>Reset changes</button>')
text = text.replace('>Rebase draft onto current policy</button>', '>Update draft with latest protection</button>')
text = text.replace('>Keep my remaining draft changes</button>', '>Keep my compatible changes</button>')
text = text.replace('>Use current policy</button>', '>Use current protection</button>')
text = replace_once(
    text,
    'Review is required before apply. Guard calculates effective blast radius server-side from the canonical registry, dependencies, managed policy, and global lockdown.',
    'Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change.',
    "review explanation",
)
text = text.replace('title={`Apply ${confirmationCount} extension permission change${confirmationCount === 1 ? "" : "s"}`}', 'title={`Apply ${confirmationCount} protection setting change${confirmationCount === 1 ? "" : "s"}`}')
text = text.replace('detail="Authenticate this exact reviewed draft. Guard issues a one-use proof bound to the canonical mutation digest."', 'detail="Authenticate the exact settings you just reviewed. Guard uses a one-time local proof and rejects the apply if the reviewed settings changed."')

PATH.write_text("\n".join(line.rstrip() for line in text.splitlines()) + "\n", encoding="utf-8")
