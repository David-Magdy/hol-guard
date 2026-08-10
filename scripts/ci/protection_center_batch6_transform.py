from __future__ import annotations

import json
from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected one marker, found {text.count(old)}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Use explicit performance budgets instead of scattering magic limits through
# the human-query and recent-activity model.
path = Path("dashboard/src/protection-center/model/protection-landing.ts")
text = path.read_text(encoding="utf-8")
import_marker = 'import { protectionCategoryForExtension } from "./protection-categories";\n'
import_add = import_marker + 'import { PROTECTION_CENTER_PERFORMANCE_BUDGETS } from "./protection-performance-budgets";\n'
if 'from "./protection-performance-budgets"' not in text:
    if import_marker not in text:
        raise SystemExit("performance budget import marker changed")
    text = text.replace(import_marker, import_add, 1)
text = text.replace('.slice(0, Math.max(0, Math.min(limit, 20)))', '.slice(0, Math.max(0, Math.min(limit, PROTECTION_CENTER_PERFORMANCE_BUDGETS.recentDecisionCap)))')
text = text.replace('query.trim().toLowerCase().slice(0, 160)', 'query.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap)')
text = text.replace('normalized.split(/\\s+/).filter(Boolean).slice(0, 8)', 'normalized.split(/\\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap)')
path.write_text(text, encoding="utf-8")

# Add the final contracts to the dashboard suite.
package_path = Path("dashboard/package.json")
package = json.loads(package_path.read_text(encoding="utf-8"))
test = package["scripts"]["test"]
new_tests = [
    "tsx src/protection-center/protection-cloud-value.test.tsx",
    "tsx src/protection-center/protection-telemetry.test.ts",
    "tsx src/protection-center/protection-terminology.test.tsx",
    "tsx src/protection-center/protection-final-a11y.test.tsx",
    "tsx src/protection-center/model/protection-author-metadata.test.ts",
    "tsx src/protection-center/model/protection-performance-budgets.test.ts",
]
for command in reversed(new_tests):
    if command not in test:
        test = f"{command} && {test}"
package["scripts"]["test"] = test
package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

# Extend installed-wheel Chromium proof. The default isolated server is local
# only, which proves Cloud absence does not remove local protection. Test Lab is
# exercised through the packaged UI and real installed daemon response.
spec_path = Path("dashboard/e2e/installed-extension-control-center.spec.ts")
spec = spec_path.read_text(encoding="utf-8")
cloud_marker = '  await expect(page.getByLabel("Cloud continuity")).toBeVisible();\n'
cloud_assert = cloud_marker + '  await expect(page.getByLabel("Cloud continuity")).toContainText("Local protection is active");\n'
if 'toContainText("Local protection is active")' not in spec:
    if cloud_marker not in spec:
        raise SystemExit("installed Cloud continuity marker changed")
    spec = spec.replace(cloud_marker, cloud_assert, 1)

git_marker = '''  await page.goto("/extensions/command.git");\n  await expectSecretSafeUrl(page);\n  await selectDensity(page, "Developer");\n'''
test_lab_proof = '''  await page.goto("/extensions/command.git");\n  await expectSecretSafeUrl(page);\n  await expect(page.getByRole("heading", { name: "Test Lab", exact: true })).toBeVisible();\n  const labCommand = "git reset --hard HEAD~1";\n  await page.getByLabel("Command to check").fill(labCommand);\n  const labResponsePromise = page.waitForResponse((response) => {\n    const url = new URL(response.url());\n    return url.pathname === "/v1/extension-controls/test" && response.status() === 200;\n  });\n  await page.getByRole("button", { name: "Check safely" }).click();\n  const labResponse = await labResponsePromise;\n  const labPayload = await labResponse.json();\n  expect(JSON.stringify(labPayload)).not.toContain(labCommand);\n  await expect(page.getByRole("status").filter({ hasText: /Guard would (allow|ask first|block) this/ })).toBeVisible();\n  await page.screenshot({ path: testInfo.outputPath("installed-protection-test-lab.png"), fullPage: true });\n  await selectDensity(page, "Developer");\n'''
if 'installed-protection-test-lab.png' not in spec:
    if git_marker not in spec:
        raise SystemExit("installed Test Lab marker changed")
    spec = spec.replace(git_marker, test_lab_proof, 1)
spec_path.write_text(spec, encoding="utf-8")

# Protect the architecture itself with a small final source contract. This is
# intentionally about boundaries rather than marketing plan numbers.
Path("dashboard/src/protection-center/protection-final-contract.test.ts").write_text('''import assert from "node:assert/strict";\nimport { readFileSync } from "node:fs";\n\nconst cloud = readFileSync(new URL("./protection-cloud-value.tsx", import.meta.url), "utf8");\nconst telemetry = readFileSync(new URL("./protection-telemetry.ts", import.meta.url), "utf8");\nconst lab = readFileSync(new URL("./protection-test-lab.tsx", import.meta.url), "utf8");\nconst docs = readFileSync(new URL("../../../docs/guard/protection-center.md", import.meta.url), "utf8");\n\nassert.match(cloud, /data-local-protection-independent/);\nassert.match(cloud, /cloud_pairing_state.*plan_id/s);\nassert.doesNotMatch(cloud, /4\\.99|15\\.00|1073741824|30-day|deviceLimit/);\nassert.match(telemetry, /ALLOWED_FIELDS/);\nassert.doesNotMatch(telemetry, /ALLOWED_FIELDS.*command/s);\nassert.match(lab, /Nothing is executed/);\nassert.match(lab, /not saved to Activity or sent to Guard Cloud/);\nassert.match(docs, /must never disable or hide local protection controls/);\nassert.match(docs, /client must not invent device, retention, or storage quotas/);\n\nconsole.log("protection-final-contract.test.ts: all assertions passed");\n''', encoding="utf-8")

package = json.loads(package_path.read_text(encoding="utf-8"))
test = package["scripts"]["test"]
final_command = "tsx src/protection-center/protection-final-contract.test.ts"
if final_command not in test:
    package["scripts"]["test"] = f"{final_command} && {test}"
    package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
