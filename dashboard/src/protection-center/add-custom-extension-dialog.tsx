import { useCallback, useEffect, useRef, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniArrowLeft } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import {
  applyBulkCommandState,
  applyLocalCliMutation,
  bulkCommandState,
  enrollablePackageScriptCommands,
  enrollmentCommandStates,
  filterExtensionSuggestions,
  filterPackageScriptCommands,
  LocalCliApiError,
  previewLocalCliMutation,
  looksLikePackageScriptPaste,
  keepsPackageScriptCatalog,
  preferredPackageScriptExtension,
  recognizeLocalCli,
  suggestedHarnessExtensions,
  suggestedPackageScriptExtensions,
  suggestedSeenExtensions,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliState,
} from "../local-cli-api";
import {
  addDialogSubmitLabel,
  allowActionLabel,
  blockActionLabel,
  commandFieldLabel,
  dialogIntro,
  filterCountCopy,
  ProjectSwitcher,
  SuggestionPanel,
  suggestionSummary,
} from "./add-custom-extension-support";
import { CustomExtensionCommandList, withCommandState } from "./custom-extension-commands";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError } from "./components/protection-primitives";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function AddCustomExtensionWorkspace(props: {
  items: LocalCliItem[];
  revision: number;
  onBack: () => void;
  onAdded: (cliId: string) => void;
}) {
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const [command, setCommand] = useState("");
  const [recognized, setRecognized] = useState<LocalCliItem | null>(null);
  const [commands, setCommands] = useState<LocalCliItem["commands"]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reviewingScripts, setReviewingScripts] = useState(false);
  const recognizeGeneration = useRef(0);
  const autoRecognizedCommand = useRef("");
  const didAutoSelect = useRef(false);
  const rememberedProjects = suggestedPackageScriptExtensions(props.items);
  const packageScriptSuggestions = filterExtensionSuggestions(rememberedProjects, command).slice(0, 8);
  const harnessSuggestions = filterExtensionSuggestions(suggestedHarnessExtensions(props.items), command).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(suggestedSeenExtensions(props.items), command).slice(0, 6);
  const hasSuggestions = packageScriptSuggestions.length > 0
    || harnessSuggestions.length > 0
    || seenSuggestions.length > 0;

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  const handleCommand = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    const keepCatalog = recognized?.surface === "package-scripts" && keepsPackageScriptCatalog(value, commands);
    setCommand(value);
    setError(null);
    if (keepCatalog) return;
    recognizeGeneration.current += 1;
    autoRecognizedCommand.current = "";
    setBusy(false);
    setRecognized(null);
    setCommands([]);
    setSummary(null);
    setPending(null);
    setReviewingScripts(false);
  }, [commands, recognized]);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const runRecognize = useCallback(async (commandText: string, cliId?: string, silent = false) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    if (!silent) setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : undefined);
      if (recognizeGeneration.current !== generation) return;
      setRecognized(result.item);
      setCommands(result.item.commands);
      setSummary(result.summary);
      setPending("allowed");
      setError(null);
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      setRecognized(null);
      setSummary(null);
      if (!silent) {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
      }
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, []);
  const selectSuggestion = useCallback((item: LocalCliItem) => {
    if (item.surface !== "package-scripts") setCommand(item.example_label);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      setPending(null);
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    setRecognized(item);
    setCommands(item.commands);
    setSummary(suggestionSummary(item));
    setPending("allowed");
    setReviewingScripts(false);
  }, [runRecognize]);
  const findTool = useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
  useEffect(() => {
    if (didAutoSelect.current || recognized !== null || command.trim() !== "") return;
    const preferred = preferredPackageScriptExtension(props.items);
    if (preferred === null) return;
    didAutoSelect.current = true;
    selectSuggestion(preferred);
  }, [command, props.items, recognized, selectSuggestion]);
  useEffect(() => {
    const trimmed = command.trim();
    if (recognized !== null || !looksLikePackageScriptPaste(trimmed)) return;
    if (autoRecognizedCommand.current === trimmed) return;
    const handle = window.setTimeout(() => {
      autoRecognizedCommand.current = trimmed;
      void runRecognize(trimmed, undefined, true);
    }, 280);
    return () => window.clearTimeout(handle);
  }, [busy, command, recognized, runRecognize]);
  const requestAllow = useCallback(() => setPending("allowed"), []);
  const requestBlock = useCallback(() => setPending("blocked"), []);
  const openScriptReview = useCallback(() => setReviewingScripts(true), []);
  const closeScriptReview = useCallback(() => setReviewingScripts(false), []);
  const applyBulk = useCallback((state: LocalCliCommandState) => {
    setCommands((current) => applyBulkCommandState(
      current,
      state,
      recognized?.surface === "package-scripts" ? new Set(["root", "other"]) : new Set(),
    ));
    setPending(state === "block" ? "blocked" : "allowed");
  }, [recognized]);
  const handleSubmit = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (recognized === null) {
      await findTool();
      return;
    }
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: recognized.cli_id,
        identity_hash: recognized.identity_hash,
        name: recognized.name,
        kind: recognized.kind,
        example_label: recognized.example_label,
        interpreter_name: recognized.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        commands: enrollmentCommandStates(commands, pending, recognized.surface),
        ...buildApprovalProofCredentials(resolvedApprovalGate, {
          approvalPassword: password,
          approvalTotpCode: totp,
        }),
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      props.onAdded(recognized.cli_id);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not add this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, findTool, password, pending, props, recognized, resolvedApprovalGate, totp]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);

  const proofReady = pending !== null && recognized !== null;
  const submitDisabled = recognized === null
    ? command.trim() === "" || busy
    : !proofReady || isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy,
    );
  const showingPackageCatalog = recognized?.surface === "package-scripts";
  const showingMcpCatalog = recognized?.surface === "mcp";
  const showingCatalog = showingPackageCatalog || showingMcpCatalog;
  const enrollable = showingPackageCatalog ? enrollablePackageScriptCommands(commands) : commands;
  const visibleCommands = showingPackageCatalog
    ? filterPackageScriptCommands(enrollable, command)
    : commands;
  const previewNames = visibleCommands.slice(0, 8).map((entry) => entry.name);
  const bulkState = bulkCommandState(enrollable);

  return (
    <form
      data-testid="add-custom-extension"
      onSubmit={handleSubmit}
      className="flex min-h-[70vh] w-full flex-col"
    >
      <button type="button" onClick={props.onBack} className="inline-flex min-h-11 w-fit items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-3 max-w-2xl pb-4">
        <h1 id="add-custom-extension-title" className="text-2xl font-semibold tracking-tight text-brand-dark">Add a custom extension</h1>
        <p className="mt-2 text-sm leading-6 text-slate-500">
          {dialogIntro(rememberedProjects.length > 0, recognized?.surface ?? null)}
        </p>
      </header>
      <label htmlFor="custom-extension-command" className="mt-4 block text-sm font-semibold text-brand-dark">
        {commandFieldLabel(recognized?.surface ?? null)}
      </label>
      <input
        id="custom-extension-command"
        value={command}
        onChange={handleCommand}
        spellCheck={false}
        autoComplete="off"
        placeholder={showingPackageCatalog ? "guard:audit" : "npm run guard:audit"}
        className="mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark placeholder:text-brand-dark/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
      />
      {recognized !== null && showingPackageCatalog ? (
        <ProjectSwitcher items={rememberedProjects} currentId={recognized.cli_id} onSelect={selectSuggestion} />
      ) : null}
      {recognized ? (
        <section className="mt-5 max-w-3xl" aria-labelledby="custom-extension-selected">
          <h2 id="custom-extension-selected" className="text-xl font-semibold tracking-tight text-brand-dark">
            {recognized.name}
          </h2>
          <p className="mt-1 font-mono text-xs text-brand-dark/70">
            {recognized.source_label ? `${recognized.source_label} · ${recognized.example_label}` : recognized.example_label}
          </p>
          {summary ? <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{summary}</p> : null}
          {showingCatalog && enrollable.length > 0 ? (
            <BulkPolicyPicker value={bulkState} disabled={busy} onChange={applyBulk} />
          ) : null}
          {showingCatalog ? (
            <CatalogPreview
              query={command}
              showFilterCount={showingPackageCatalog}
              previewNames={previewNames}
              visibleCount={visibleCommands.length}
              totalCount={enrollable.length}
              reviewing={reviewingScripts}
              adjustLabel={showingMcpCatalog ? "Adjust individual tools" : "Adjust individual scripts"}
              hideLabel="Hide individual settings"
              onOpenReview={openScriptReview}
              onCloseReview={closeScriptReview}
            />
          ) : null}
          {(!showingCatalog || reviewingScripts) && visibleCommands.length > 0 ? (
            <div className="mt-3 overflow-auto rounded-2xl border border-slate-200 bg-white">
              <CustomExtensionCommandList
                commands={visibleCommands}
                disabled={busy}
                surface={recognized.surface}
                onChange={handleCommandState}
              />
            </div>
          ) : null}
        </section>
      ) : (
        <SuggestionPanel
          query={command}
          hasSuggestions={hasSuggestions}
          packageScriptSuggestions={packageScriptSuggestions}
          harnessSuggestions={harnessSuggestions}
          seenSuggestions={seenSuggestions}
          onSelect={selectSuggestion}
        />
      )}
      {error ? <div className="mt-4 max-w-xl"><InlineError message={error} /></div> : null}
      <div className="sticky bottom-0 mt-auto border-t border-slate-200 bg-white py-4">
        {proofReady ? (
          <div className="mb-4 max-w-sm">
            <ApprovalProofFieldInputs
              approvalGate={resolvedApprovalGate}
              approvalPassword={password}
              approvalTotpCode={totp}
              onApprovalPasswordChange={handlePassword}
              onApprovalTotpCodeChange={handleTotp}
            />
          </div>
        ) : null}
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {addDialogSubmitLabel({ recognized, busy, pending })}
          </button>
          {recognized && pending === "allowed" ? (
            <button type="button" onClick={requestBlock} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">
              {blockActionLabel(recognized.surface)}
            </button>
          ) : null}
          {recognized && pending === "blocked" ? (
            <button type="button" onClick={requestAllow} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">
              {allowActionLabel(recognized.surface)}
            </button>
          ) : null}
        </div>
      </div>
    </form>
  );
}

function CatalogPreview(props: {
  query: string;
  showFilterCount: boolean;
  previewNames: string[];
  visibleCount: number;
  totalCount: number;
  reviewing: boolean;
  adjustLabel: string;
  hideLabel: string;
  onOpenReview: () => void;
  onCloseReview: () => void;
}) {
  return (
    <div className="mt-4">
      {props.showFilterCount && props.query.trim() !== "" ? (
        <p className="text-xs leading-5 text-brand-dark/60">{filterCountCopy(props.visibleCount, props.totalCount)}</p>
      ) : null}
      {props.previewNames.length > 0 && !props.reviewing ? (
        <ul className="mt-3 flex flex-wrap gap-2">
          {props.previewNames.map((name) => (
            <li key={name} className="rounded-full bg-slate-100 px-3 py-1.5 font-mono text-xs text-brand-dark">
              {name}
            </li>
          ))}
          {props.visibleCount > props.previewNames.length ? (
            <li className="rounded-full px-3 py-1.5 text-xs font-semibold text-brand-dark/60">
              +{props.visibleCount - props.previewNames.length} more
            </li>
          ) : null}
        </ul>
      ) : null}
      <button
        type="button"
        onClick={props.reviewing ? props.onCloseReview : props.onOpenReview}
        className="mt-3 min-h-11 text-sm font-semibold text-brand-blue"
      >
        {props.reviewing ? props.hideLabel : props.adjustLabel}
      </button>
    </div>
  );
}

function BulkPolicyPicker(props: {
  value: LocalCliCommandState | "mixed";
  disabled: boolean;
  onChange: (state: LocalCliCommandState) => void;
}) {
  const choices: Array<{ value: LocalCliCommandState; label: string }> = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow all" },
    { value: "block", label: "Block all" },
  ];
  const selected = props.value === "mixed" ? "inherit" : props.value;
  const tabStopIndex = extensionPolicyRadioTabStop(choices, selected, props.disabled);
  const chooseAdjacent = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next]!.value);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
  };
  return (
    <div className="mt-4">
      <div
        role="radiogroup"
        aria-label="All tools protection setting"
        aria-describedby={props.value === "mixed" ? "bulk-policy-mixed" : undefined}
        className="guard-segmented w-fit"
      >
        {choices.map((choice, index) => (
          <BulkPolicyChoice
            key={choice.value}
            choice={choice}
            checked={props.value === choice.value}
            tabIndex={!props.disabled && index === tabStopIndex ? 0 : -1}
            disabled={props.disabled}
            index={index}
            onChoose={props.onChange}
            onAdjacent={chooseAdjacent}
          />
        ))}
      </div>
      {props.value === "mixed" ? (
        <p id="bulk-policy-mixed" className="mt-2 text-xs leading-5 text-brand-dark/70">
          Custom mix. Pick Recommended, Allow all, or Block all to reset every tool.
        </p>
      ) : null}
    </div>
  );
}

function BulkPolicyChoice(props: {
  choice: { value: LocalCliCommandState; label: string };
  checked: boolean;
  tabIndex: number;
  disabled: boolean;
  index: number;
  onChoose: (state: LocalCliCommandState) => void;
  onAdjacent: (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => void;
}) {
  const handleClick = useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = useCallback((event: React.KeyboardEvent<HTMLButtonElement>) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return (
    <button
      type="button"
      role="radio"
      aria-checked={props.checked}
      tabIndex={props.tabIndex}
      disabled={props.disabled}
      onKeyDown={handleKeyDown}
      onClick={handleClick}
      className="min-h-11 px-4 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-45"
    >
      {props.choice.label}
    </button>
  );
}
