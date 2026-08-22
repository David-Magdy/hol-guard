import type { GuardCloudConnectStatusResponse } from "./guard-types";
import { fetchGuardCloudConnectStatus } from "./guard-api";

export async function withCloudRequestTimeout<T>(
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

export async function waitForAuthorizeUrl(
  initialStatus: GuardCloudConnectStatusResponse,
  signal: AbortSignal,
): Promise<GuardCloudConnectStatusResponse> {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const flow = status.connect_flow;
    if (
      !status.connect_required
      || flow?.authorize_url
      || !flow
      || !["starting", "running"].includes(flow.state)
    ) {
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
  fetchStatus?: (signal: AbortSignal) => Promise<GuardCloudConnectStatusResponse>;
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
