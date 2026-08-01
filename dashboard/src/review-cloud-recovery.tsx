import { useCallback, useState } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { GuardApprovalRequest } from "./guard-types";
import { startGuardCloudConnect } from "./guard-api";
import {
  openPackageFirewallAuthorizeFallback,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "./package-firewall-connect-browser";

const unavailableEvidencePhrases = [
  // Queued requests can outlive the daemon version that created their copy.
  "could not verify registry identity or package intelligence",
  "cloud evaluation could not validate",
  "current package safety data was unavailable",
];

export function packageReviewNeedsCloudRecovery(item: GuardApprovalRequest): boolean {
  const packageRequest =
    item.artifact_type === "supply_chain" ||
    item.artifact_type === "package_request" ||
    item.artifact_type.endsWith("_package");
  if (!packageRequest) return false;
  const evidence = [item.risk_headline, item.risk_summary, ...(item.risk_signals ?? [])]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLowerCase();
  return unavailableEvidencePhrases.some((phrase) => evidence.includes(phrase));
}

export function ReviewCloudRecovery({ item }: { item: GuardApprovalRequest }) {
  const [connecting, setConnecting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [manualConnectUrl, setManualConnectUrl] = useState<string | null>(null);

  const handleConnect = useCallback(async () => {
    setConnecting(true);
    setMessage(null);
    setManualConnectUrl(null);
    try {
      const status = await startGuardCloudConnect();
      const flow = status.connect_flow;
      if (flow?.authorize_url && !openPackageFirewallAuthorizeFallback(flow.authorize_url, flow.browser_opened)) {
        setMessage(PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE);
        setManualConnectUrl(flow.authorize_url ?? flow.connect_url);
        return;
      }
      setMessage(
        status.connect_required
          ? "Finish signing in, then retry the install."
          : "Guard Cloud is connected. Retry the install for a fresh safety check.",
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Guard could not start sign-in. Try again.");
    } finally {
      setConnecting(false);
    }
  }, []);

  if (!packageReviewNeedsCloudRecovery(item)) return null;

  return (
    <div className="mt-4 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4">
      <p className="text-sm font-semibold text-brand-dark">Get a current package safety check</p>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
        Guard could not load current safety data for this package. This does not mean the package is unsafe.
        Connect Guard Cloud and retry, or approve this install once.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <ActionButton onClick={handleConnect} disabled={connecting} variant="outline">
          <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
          {connecting ? "Starting sign-in..." : "Connect Guard Cloud"}
        </ActionButton>
        {manualConnectUrl ? (
          <ActionButton href={manualConnectUrl} variant="quiet">
            Open sign-in
          </ActionButton>
        ) : null}
        {message ? <p className="text-sm text-muted-foreground" role="status">{message}</p> : null}
      </div>
    </div>
  );
}
