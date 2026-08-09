import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { GuardApprovalRequest } from "./guard-types";
import type { GuardCloudConnectStatusResponse } from "./guard-types";
import { fetchGuardCloudConnectStatus, startGuardCloudConnect } from "./guard-api";
import {
  openPackageFirewallAuthorizeFallback,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "./package-firewall-connect-browser";

const validationEvidencePhrases = [
  // Queued requests can outlive the daemon version that created their copy.
  "could not verify registry identity or package intelligence",
  "cloud evaluation could not validate",
  "cloud evaluation endpoint was not trusted",
  "cloud evaluation returned http",
  "cloud evaluation returned an invalid",
  "cloud evaluation timed out",
  "current package safety data was unavailable",
];
const authorizationEvidencePhrases = [
  "cloud evaluation was not authorized",
  "cloud authorization expired",
  "cloud evaluation could not establish a trusted session",
  "cloud sign-in is missing or stale",
];

type PackageCloudRecoveryKind = "authorization" | "validation";

const validationReasonCodes = new Set([
  "cloud_validation_error",
  "cloud_http_error",
  "cloud_timeout",
]);

export function packageReviewCloudRecoveryKind(
  item: GuardApprovalRequest,
): PackageCloudRecoveryKind | null {
  const packageRequest =
    item.artifact_type === "supply_chain" ||
    item.artifact_type === "package_request" ||
    item.artifact_type.endsWith("_package");
  if (!packageRequest) return null;
  const reasonCode = item.decision_v2_json?.package_review_cloud_reason_code;
  if (reasonCode === "cloud_auth_error") return "authorization";
  if (typeof reasonCode === "string" && validationReasonCodes.has(reasonCode)) return "validation";

  // Legacy queued requests predate the structured recovery reason code.
  const evidence = [item.risk_headline, item.risk_summary, ...(item.risk_signals ?? [])]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLowerCase();
  if (authorizationEvidencePhrases.some((phrase) => evidence.includes(phrase))) {
    return "authorization";
  }
  return validationEvidencePhrases.some((phrase) => evidence.includes(phrase))
    ? "validation"
    : null;
}

async function withCloudRequestTimeout<T>(
  request: (signal: AbortSignal) => Promise<T>,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (parentSignal?.aborted) {
    throw new DOMException("Cloud connection request stopped", "AbortError");
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  const timeout = globalThis.setTimeout(() => controller.abort(), 5000);
  try {
    return await request(controller.signal);
  } finally {
    globalThis.clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abort);
  }
}

function waitForPoll(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(new DOMException("Cloud connection polling stopped", "AbortError"));
  }
  return new Promise<void>((resolve, reject) => {
    const finish = () => {
      signal.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = globalThis.setTimeout(finish, delayMs);
    const abort = () => {
      globalThis.clearTimeout(timeout);
      reject(new DOMException("Cloud connection polling stopped", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

async function waitForAuthorizeUrl(
  initialStatus: GuardCloudConnectStatusResponse,
  signal: AbortSignal,
): Promise<GuardCloudConnectStatusResponse> {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const flow = status.connect_flow;
    if (!status.connect_required || flow?.authorize_url || !flow || !["starting", "running"].includes(flow.state)) {
      return status;
    }
    const pollDelayMs = Math.max(100, Math.min(5000, flow.poll_after_ms ?? 1000));
    await waitForPoll(pollDelayMs, signal);
    status = await withCloudRequestTimeout(fetchGuardCloudConnectStatus, signal);
  }
  return status;
}

type CloudConnectionPollOptions = {
  signal: AbortSignal;
  fetchStatus?: (signal?: AbortSignal) => Promise<GuardCloudConnectStatusResponse>;
  wait?: (delayMs: number, signal: AbortSignal) => Promise<void>;
  maxAttempts?: number;
};

export async function waitForCloudConnection(
  initialStatus: GuardCloudConnectStatusResponse,
  {
    signal,
    fetchStatus = fetchGuardCloudConnectStatus,
    wait = waitForPoll,
    maxAttempts = 300,
  }: CloudConnectionPollOptions,
): Promise<GuardCloudConnectStatusResponse> {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < maxAttempts && status.connect_required; attempt += 1) {
    if (status.connect_flow?.state === "failed") return status;
    const pollDelayMs = Math.max(250, Math.min(5000, status.connect_flow?.poll_after_ms ?? 1000));
    await wait(pollDelayMs, signal);
    status = await withCloudRequestTimeout(fetchStatus, signal);
  }
  return status;
}

export function packageReviewNeedsCloudRecovery(item: GuardApprovalRequest): boolean {
  return packageReviewCloudRecoveryKind(item) !== null;
}

export function cloudRecoveryContent(
  connected: boolean,
  kind: PackageCloudRecoveryKind = "authorization",
): { title: string; detail: string } {
  if (kind === "validation") {
    return {
      title: "Optional Cloud check unavailable",
      detail: "Local Guard is still active. Retry the install, or approve it once if you trust the package.",
    };
  }
  return connected
    ? {
        title: "Guard Cloud connected",
        detail: "Run the install command again for a current package safety check.",
      }
    : {
        title: "Optional: add a Guard Cloud check",
        detail:
          "Local Guard is working and still needs your decision. Approve this install once, or connect Guard Cloud for live package reputation.",
      };
}

export function ReviewCloudRecovery({ item }: { item: GuardApprovalRequest }) {
  const recoveryKind = packageReviewCloudRecoveryKind(item);
  const [connecting, setConnecting] = useState(false);
  const [connected, setConnected] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [manualConnectUrl, setManualConnectUrl] = useState<string | null>(null);
  const connectControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    connectControllerRef.current?.abort();
    setConnecting(false);
    setConnected(false);
    setMessage(null);
    setManualConnectUrl(null);
    return () => connectControllerRef.current?.abort();
  }, [item.request_id]);

  const handleConnect = useCallback(async () => {
    connectControllerRef.current?.abort();
    const controller = new AbortController();
    connectControllerRef.current = controller;
    setConnecting(true);
    setConnected(false);
    setMessage(null);
    setManualConnectUrl(null);
    try {
      const status = await waitForAuthorizeUrl(
        await withCloudRequestTimeout(startGuardCloudConnect, controller.signal),
        controller.signal,
      );
      const flow = status.connect_flow;
      if (flow?.authorize_url) {
        setManualConnectUrl(flow.authorize_url);
        setMessage(
          openPackageFirewallAuthorizeFallback(flow.authorize_url, flow.browser_opened)
            ? "Complete sign-in in the opened window. This page will update automatically."
            : PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
        );
        const connectedStatus = await waitForCloudConnection(status, { signal: controller.signal });
        if (!connectedStatus.connect_required) {
          setConnected(true);
          setManualConnectUrl(null);
          setMessage(null);
          return;
        }
        setMessage("Sign-in is still pending. Complete it in the opened window, or open sign-in again.");
        return;
      }
      if (status.connect_required && flow?.connect_url) {
        setMessage("Open sign-in to continue. This page will update automatically.");
        setManualConnectUrl(flow.connect_url);
        const connectedStatus = await waitForCloudConnection(status, { signal: controller.signal });
        if (!connectedStatus.connect_required) {
          setConnected(true);
          setManualConnectUrl(null);
          setMessage(null);
          return;
        }
        setMessage("Sign-in is still pending. Complete it in the opened window, or open sign-in again.");
        return;
      }
      setMessage(
        status.connect_required
          ? "Guard could not finish starting sign-in. Try again."
          : null,
      );
      setConnected(!status.connect_required);
    } catch (error) {
      if (controller.signal.aborted) return;
      setMessage(error instanceof Error ? error.message : "Guard could not start sign-in. Try again.");
    } finally {
      if (!controller.signal.aborted) setConnecting(false);
    }
  }, []);

  if (recoveryKind === null) return null;
  const content = cloudRecoveryContent(connected, recoveryKind);

  return (
    <div className="mt-4 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4">
      <p className="text-sm font-semibold text-brand-dark">{content.title}</p>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{content.detail}</p>
      {!connected && recoveryKind === "authorization" ? (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <ActionButton onClick={handleConnect} disabled={connecting} variant="outline">
            <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
            {connecting ? "Waiting for sign-in..." : "Connect Guard Cloud"}
          </ActionButton>
          {manualConnectUrl ? (
            <ActionButton href={manualConnectUrl} variant="quiet">
              Open sign-in
            </ActionButton>
          ) : null}
          {message ? <p className="text-sm text-muted-foreground" role="status">{message}</p> : null}
        </div>
      ) : null}
    </div>
  );
}
