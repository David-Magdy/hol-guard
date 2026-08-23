import assert from 'node:assert/strict';
import { buildLocalProtectionView } from './local-protection-model';

const local = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'allowed',
  source: 'This device',
  cloudControlsUrl: 'https://cloud.example.test/dashboard',
  extensionId: 'command.git',
});
assert.equal(local.primaryAction?.label, 'Apply across my devices');
assert.equal(
  local.primaryAction?.href,
  'https://cloud.example.test/guard/controls?extensionId=command.git',
);
assert.equal(local.status, 'protected');

const managed = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  cloudControlsUrl: 'https://cloud.example.test',
  extensionId: 'command.git',
  permissionId: 'command.git.permission.push',
});
assert.equal(managed.status, 'managed');
assert.equal(managed.primaryAction?.label, 'Manage in Guard Cloud');
assert.equal(
  managed.primaryAction?.href,
  'https://cloud.example.test/guard/controls?extensionId=command.git&permissionId=command.git.permission.push',
);

const stale = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  stale: true,
});
assert.equal(stale.primaryAction?.label, 'Check again');
