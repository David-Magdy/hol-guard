import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function source(name: string): string {
  return readFileSync(join(__dirname, name), "utf8");
}

const statusSource = source("shell-navigation-status.tsx");
const statusCss = source("shell-navigation-status.css");
const sidebarSource = source("shell-navigation.tsx");
const drawerSource = source("shell-navigation-drawer.tsx");
const primitivesSource = source("approval-center-primitives.tsx");
const mainSource = source("main.tsx");

assert(
  statusSource.includes("a Guard decision.") && statusSource.includes("Open Inbox"),
  "status copy keeps the queue sentence and a compact Inbox action",
);
assert(
  !statusSource.includes("Open Inbox to review."),
  "status copy must not wrap the whole sentence as the action label",
);
assert(
  statusSource.includes('className="guard-shell-status-action"') &&
    statusSource.includes('href={shellHref("/inbox")}'),
  "Inbox action is a dedicated compact control",
);
assert(
  statusCss.includes("text-decoration: none") &&
    statusCss.includes("font-size: 0.6875rem") &&
    statusCss.includes(".guard-shell-status-action"),
  "Inbox action stays compact and un-underlined",
);
assert(
  sidebarSource.includes("<LocalGuardStatusCopy") && drawerSource.includes("<LocalGuardStatusCopy"),
  "sidebar and drawer share the compact Local Guard status copy",
);
assert(
  mainSource.includes('import "./shell-navigation-status.css"'),
  "status typography loads with the shell",
);
assert(
  primitivesSource.includes(">Open Inbox</span>") &&
    primitivesSource.includes("no-underline") &&
    !primitivesSource.includes("Open Inbox to review.") &&
    !primitivesSource.includes("guard-quiet-link"),
  "legacy sidebar card also keeps compact un-underlined Inbox copy",
);

console.log("sidebar-local-guard-card.test.ts: all tests passed");
