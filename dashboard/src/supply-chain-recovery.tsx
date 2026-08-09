import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniExclamationCircle,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { SupplyChainFixAllState } from "./supply-chain-fix-all";
import {
  supplyChainFixAllButtonLabel,
  supplyChainFixAllIsPending,
} from "./supply-chain-fix-all";
import type { SupplyChainIssue } from "./supply-chain-issues";

type SupplyChainRecoveryProps = {
  issues: SupplyChainIssue[];
  state: SupplyChainFixAllState;
  onFixAll: () => void;
  guidance?: string | null;
};

function recoverySummary(issueCount: number): string {
  return `Fix ${issueCount} open issue${issueCount === 1 ? "" : "s"} in one guided pass. Guard repairs package tools, activates routing, refreshes safety intelligence, and rechecks status.`;
}

export function SupplyChainRecovery({
  issues,
  state,
  onFixAll,
  guidance = null,
}: SupplyChainRecoveryProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const handleDetailsToggle = useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const pending = supplyChainFixAllIsPending(state.phase);
  const showResult = state.message !== null;

  return (
    <section
      className="border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5"
      aria-label="Supply-chain recovery"
      data-testid="supply-chain-recovery"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniWrenchScrewdriver
              className="h-4 w-4 shrink-0 text-brand-attention"
              aria-hidden="true"
            />
            <h2 className="text-sm font-semibold text-brand-dark">
              Restore supply-chain protection
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-sm text-slate-600">
            {recoverySummary(issues.length)}
          </p>
          {guidance ? (
            <p
              className="mt-2 max-w-3xl text-sm font-medium text-brand-primary"
              data-testid="supply-chain-restart-guidance"
            >
              {guidance}
            </p>
          ) : null}
        </div>
        <ActionButton onClick={onFixAll} disabled={pending} aria-busy={pending}>
          {supplyChainFixAllButtonLabel(state.phase)}
        </ActionButton>
      </div>

      <div className={showResult ? "mt-3" : ""} aria-live="polite">
        {showResult ? (
          <>
            <p
              className={`flex items-start gap-2 text-sm ${
                state.phase === "error" || state.phase === "incomplete"
                  ? "text-red-600"
                  : "text-slate-600"
              }`}
            >
              {state.phase === "success" ? (
                <HiMiniCheckCircle
                  className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500"
                  aria-hidden="true"
                />
              ) : null}
              {state.message}
            </p>
            {state.failedSteps.length > 0 ? (
              <ul className="mt-2 space-y-1 text-xs text-red-600">
                {state.failedSteps.map((failure, index) => (
                  <li key={`${index}:${failure}`}>{failure}</li>
                ))}
              </ul>
            ) : null}
          </>
        ) : null}
      </div>

      <button
        type="button"
        onClick={handleDetailsToggle}
        aria-expanded={detailsOpen}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
      >
        View issue details
        <HiMiniChevronDown
          className={`h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>
      {detailsOpen ? (
        <ul className="mt-2 border-t border-brand-attention/10">
          {issues.map((issue) => (
            <li
              key={issue.id}
              className="flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0"
            >
              <HiMiniExclamationCircle
                className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-attention"
                aria-hidden="true"
              />
              <span className="text-xs text-slate-600">
                <strong className="block font-semibold text-brand-dark">{issue.title}</strong>
                {issue.detail}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
