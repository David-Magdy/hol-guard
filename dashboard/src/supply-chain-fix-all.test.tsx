import { renderToStaticMarkup } from "react-dom/server";
import { SupplyChainRecovery } from "./supply-chain-recovery";
import {
  IDLE_SUPPLY_CHAIN_FIX_ALL_STATE,
  supplyChainFixAllButtonLabel,
  supplyChainFixAllIsPending,
} from "./supply-chain-fix-all";
import type { SupplyChainIssue } from "./supply-chain-issues";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const issues: SupplyChainIssue[] = [
  {
    id: "unprotected_tools",
    title: "Package installs are not protected yet",
    detail: "Protect npm and bun before installs run.",
    tone: "attention",
    actionLabel: "Protect package tools",
    action: { kind: "firewall_unprotected" },
  },
  {
    id: "stale_intel",
    title: "Safety check data looks old",
    detail: "Refresh package warnings.",
    tone: "attention",
    actionLabel: "Run workspace audit",
    action: { kind: "firewall_audit" },
  },
];

const markup = renderToStaticMarkup(
  <SupplyChainRecovery
    issues={issues}
    state={IDLE_SUPPLY_CHAIN_FIX_ALL_STATE}
    onFixAll={() => undefined}
  />,
);

assert(markup.includes("Restore supply-chain protection"), "recovery heading is visible");
assert(markup.includes("Fix all"), "one aggregate repair action is visible");
assert(markup.includes("Fix 2 open issues"), "summary reports the bounded repair scope");
assert(markup.includes("View issue details"), "issues remain available through progressive disclosure");
assert(!markup.includes("Package installs are not protected yet"), "details start collapsed");
assert(supplyChainFixAllButtonLabel("incomplete") === "Retry fixes", "partial repair remains actionable");
assert(supplyChainFixAllIsPending("approval"), "approval phase prevents duplicate submissions");

console.log("supply-chain-fix-all.test.tsx: all assertions passed");
