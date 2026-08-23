import assert from 'node:assert/strict';
import { customExtensionContinuityView } from './custom-extension-continuity';

const localOnly = customExtensionContinuityView('local-only');
assert.equal(localOnly.canApplyAcrossDevices, false);
assert.match(localOnly.description, /remains local/);
assert.doesNotMatch(localOnly.privacyDisclosure, /path is|source path:/i);

const portable = customExtensionContinuityView('portable');
assert.equal(portable.canApplyAcrossDevices, true);
