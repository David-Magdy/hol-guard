import assert from "node:assert/strict";

import { patternExampleCommand } from "./pattern-example";
import { FIXED_PROTECTION_PERMISSION, protectionModuleFixture } from "./fixtures/protection-fixtures";

const git = protectionModuleFixture({
  executables: ["git"],
  permissions: [
    { ...FIXED_PROTECTION_PERMISSION, permission_id: "command.git.permission.force-push", label: "Forced Git push", configurable: true, fixed_reason: null },
    { ...FIXED_PROTECTION_PERMISSION, permission_id: "command.git.permission.hard-reset", label: "Destructive Git reset", configurable: true, fixed_reason: null },
  ],
});
const github = protectionModuleFixture({
  extension_id: "command.github",
  name: "GitHub",
  executables: ["gh"],
  permissions: [
    { ...FIXED_PROTECTION_PERMISSION, permission_id: "command.github.permission.merge-remote", extension_id: "command.github", label: "GitHub merge", configurable: true, fixed_reason: null },
    { ...FIXED_PROTECTION_PERMISSION, permission_id: "command.github.permission.merge-admin", extension_id: "command.github", label: "GitHub admin merge", configurable: true, fixed_reason: null },
  ],
});

assert.equal(patternExampleCommand(git.permissions[0]!, git), "git push --force");
assert.equal(patternExampleCommand(git.permissions[1]!, git), "git reset --hard");
assert.equal(patternExampleCommand(github.permissions[0]!, github), "gh pr merge");
assert.equal(patternExampleCommand(github.permissions[1]!, github), "gh pr merge --admin");
assert.equal(patternExampleCommand(FIXED_PROTECTION_PERMISSION, git), "git");

console.log("pattern-example.test.ts: all assertions passed");
