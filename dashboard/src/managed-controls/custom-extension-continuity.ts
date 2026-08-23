export type CustomExtensionContinuityState =
  | 'local-only'
  | 'identity-matched'
  | 'portable'
  | 'incompatible';

export interface CustomExtensionContinuityView {
  state: CustomExtensionContinuityState;
  title: string;
  description: string;
  canApplyAcrossDevices: boolean;
  privacyDisclosure: string;
}

export function customExtensionContinuityView(
  state: CustomExtensionContinuityState,
): CustomExtensionContinuityView {
  const privacyDisclosure =
    'Guard Cloud receives stable identity and compatibility metadata, not local source paths.';
  switch (state) {
    case 'local-only':
      return {
        state,
        title: 'Available on this device',
        description:
          'This custom protection remains local until portable continuity is enabled.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'identity-matched':
      return {
        state,
        title: 'Matched on another device',
        description:
          'Guard matched the stable identity. Each device still uses its own verified definition.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'portable':
      return {
        state,
        title: 'Portable continuity enabled',
        description:
          'A verified portable definition is available to compatible devices.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'incompatible':
      return {
        state,
        title: 'Needs a compatible definition',
        description:
          'This device cannot apply the shared custom protection safely.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
  }
}
