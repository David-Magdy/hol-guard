import { guardAwareHref } from "../guard-api";

/** Keep the dashboard session fragment on in-page Extensions navigation. */
export function pushExtensionHistory(href: string): void {
  window.history.pushState({}, "", guardAwareHref(href));
}

/** Canonicalize an Extensions URL without dropping the dashboard session fragment. */
export function replaceExtensionHistory(href: string): void {
  window.history.replaceState({}, "", guardAwareHref(href));
}
