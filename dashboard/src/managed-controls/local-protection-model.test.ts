import assert from 'node:assert/strict';
import { buildLocalProtectionView } from './local-protection-model';

const local = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'allowed',
  source: 'This device',
});
assert.equal(local.primaryAction?.label, 'Apply across my devices');
assert.equal(local.status, 'protected');

const managed = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
});
assert.equal(managed.status, 'managed');
assert.equal(managed.primaryAction?.label, 'Manage in Guard Cloud');

const stale = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  stale: true,
});
assert.equal(stale.primaryAction?.label, 'Check again');
