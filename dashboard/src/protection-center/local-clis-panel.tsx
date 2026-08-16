import { useCallback, useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniArrowLeft, HiMiniCloud } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import {
  applyLocalCliMutation,
  fetchLocalCliList,
  LocalCliApiError,
  previewLocalCliMutation,
  type LocalCliItem,
  type LocalCliListResponse,
  type LocalCliState,
} from "../local-cli-api";
import { localCliHref } from "../local-cli-links";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError, ProtectionModuleRow } from "./components/protection-primitives";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function localCliStateLabel(item: LocalCliItem): string {
  if (item.stale) return "This CLI changed. Review the allow-list again.";
  if (item.state === "allowed") return "All matching commands from this CLI are allowed on this device.";
  if (item.state === "blocked") return "All matching commands from this CLI are blocked on this device.";
  return "Guard asks before commands from this CLI run.";
}

export function LocalClisSection(props: {
  items: LocalCliItem[];
  cloudSummary: string;
  onOpen: (cliId: string) => void;
}) {
  if (props.items.length === 0) return null;
  return (
    <section className="mt-10" aria-labelledby="other-clis-heading">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="other-clis-heading" className="text-xl font-semibold tracking-tight text-brand-dark">Other CLIs</h2>
          <p className="mt-1 text-sm text-slate-500">Tools Guard has seen that are not in the built-in Extensions catalog. Allow every matching command from one of them on this device.</p>
        </div>
        <span className="text-sm text-brand-dark/70">{props.items.length} tools</span>
      </div>
      <p className="mt-3 inline-flex items-start gap-2 text-sm text-brand-dark/75">
        <HiMiniCloud className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        {props.cloudSummary}
      </p>
      <div className="mt-4">
        {props.items.map((item) => (
          <LocalCliRow key={item.cli_id} item={item} onOpen={props.onOpen} />
        ))}
      </div>
    </section>
  );
}

function LocalCliRow(props: { item: LocalCliItem; onOpen: (cliId: string) => void }) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.item.cli_id);
  }, [props]);
  return (
    <ProtectionModuleRow
      name={props.item.name}
      description={props.item.example_label}
      behavior={localCliStateLabel(props.item)}
      onOpen={handleOpen}
    />
  );
}

export function LocalCliDetail(props: {
  item: LocalCliItem;
  revision: number;
  onBack: () => void;
  onRefresh: () => Promise<void>;
}) {
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestAllow = useCallback(() => setPending("allowed"), []);
  const requestBlock = useCallback(() => setPending("blocked"), []);
  const requestClear = useCallback(() => setPending("unset"), []);
  const clearPending = useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirmChange = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        ...credentials,
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      setPending(null);
      await props.onRefresh();
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this CLI allow-list.");
    } finally {
      setBusy(false);
    }
  }, [pending, props]);

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load the local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  return (
    <div data-testid="local-cli-detail" className="w-full">
      <button type="button" onClick={props.onBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-4 border-b border-slate-200 pb-6">
        <p className="font-mono text-xs font-semibold tracking-[0.14em] text-slate-400">{props.item.example_label}</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{props.item.name}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{localCliStateLabel(props.item)}</p>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75">
          Allowing this CLI covers every matching invocation of this exact tool on this device. Guard still blocks destructive or wrapped commands that are not just this CLI.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAllow}>
            Allow this CLI
          </button>
          <button type="button" className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark" onClick={requestBlock}>
            Block this CLI
          </button>
          {props.item.state !== "unset" ? (
            <button type="button" className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80" onClick={requestClear}>
              Clear this-device rule
            </button>
          ) : null}
        </div>
      </header>
      {pending ? (
        <LocalCliReviewModal
          item={props.item}
          nextState={pending}
          busy={busy}
          error={error}
          approvalGate={resolvedApprovalGate}
          onCancel={clearPending}
          onConfirm={confirmChange}
        />
      ) : null}
    </div>
  );
}

function LocalCliReviewModal(props: {
  item: LocalCliItem;
  nextState: LocalCliState;
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const verb = props.nextState === "allowed" ? "Allow" : props.nextState === "blocked" ? "Block" : "Clear";
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const handleSubmit = useCallback((event: FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp,
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
  );
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="local-cli-review-title" onSubmit={handleSubmit} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <h2 id="local-cli-review-title" className="text-xl font-semibold text-brand-dark">{verb} {props.item.name}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/80">
          {verb} every matching command from this CLI on this device. This does not sync to other machines.
        </p>
        <div className="mt-5">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totp}
            onApprovalPasswordChange={handlePassword}
            onApprovalTotpCodeChange={handleTotp}
          />
        </div>
        {props.error ? <div className="mt-4"><InlineError message={props.error} /></div> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {props.busy ? "Saving…" : "Confirm"}
          </button>
        </div>
      </form>
    </div>
  );
}

export function useLocalCliCatalog() {
  const [data, setData] = useState<LocalCliListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      setData(await fetchLocalCliList());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Guard could not load other CLIs.");
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, error, load };
}

export function openLocalCli(cliId: string): void {
  window.history.pushState({}, "", localCliHref(cliId));
}
