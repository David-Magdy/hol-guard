import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import { extensionDetailSearch, readExtensionDetailUrlState } from "./extension-control-center-model";
import "./styles.css";

export const EXTENSION_ROUTE_STATE_KEY = "guardExtensionDetailPath";

function sanitizeExtensionSearch(search: string): string {
  return extensionDetailSearch(readExtensionDetailUrlState(search));
}

/**
 * App's legacy top-level router predates nested extension routes. Normalize a
 * detail path only long enough for the App to select the Extensions workspace,
 * then restore the canonical detail URL without dispatching a second route.
 * The stable detail path remains visible/shareable and no fragment is retained.
 */
export function bridgeExtensionDetailRoute(): void {
  if (!window.location.pathname.startsWith("/extensions/")) return;
  const detailPath = window.location.pathname;
  const safeSearch = sanitizeExtensionSearch(window.location.search);
  const state = { ...(window.history.state ?? {}), [EXTENSION_ROUTE_STATE_KEY]: detailPath };
  window.history.replaceState(state, "", `/extensions${safeSearch}`);
  window.requestAnimationFrame(() => {
    const currentState = window.history.state ?? {};
    if (currentState[EXTENSION_ROUTE_STATE_KEY] !== detailPath) return;
    window.history.replaceState(currentState, "", `${detailPath}${safeSearch}`);
  });
}

bridgeExtensionDetailRoute();
window.addEventListener("popstate", bridgeExtensionDetailRoute);

const container = document.getElementById("guard-dashboard-root");

if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
