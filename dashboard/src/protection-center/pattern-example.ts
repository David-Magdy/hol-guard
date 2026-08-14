import type { ExtensionCatalogItem, ExtensionPermission } from "../extension-controls-api";

const PATTERN_EXAMPLES: Record<string, string> = {
  "command.git.permission.hard-reset": "git reset --hard",
  "command.git.permission.force-push": "git push --force",
  "command.git.permission.force-clean": "git clean -f",
  "command.git.permission.remote-branch-delete": "git push --delete",
  "command.git.permission.local-branch-delete": "git branch -D",
  "command.git.hard-reset": "git reset --hard",
  "command.git.force-push": "git push --force",
  "command.git.force-clean": "git clean -f",
  "command.git.remote-branch-delete": "git push --delete",
  "command.git.local-branch-delete": "git branch -D",
  "command.github.permission.merge-remote": "gh pr merge",
  "command.github.permission.merge-admin": "gh pr merge --admin",
  "command.github.permission.routine-merge-remote": "gh pr merge --squash",
  "command.filesystem.permission.recursive-delete": "rm -r",
  "command.filesystem.permission.recursive-permission-change": "chmod -R",
};

export function patternExampleCommand(
  permission: ExtensionPermission,
  extension: ExtensionCatalogItem,
): string {
  const mapped = PATTERN_EXAMPLES[permission.permission_id];
  if (mapped) return mapped;
  for (const ruleId of permission.rule_ids) {
    const fromRule = PATTERN_EXAMPLES[ruleId];
    if (fromRule) return fromRule;
  }
  const executable = extension.executables[0]?.trim();
  if (executable) return executable;
  return permission.label;
}
