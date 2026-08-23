export type ProtectionSource =
  | 'Built-in protection'
  | 'This device'
  | 'Personal Control Set'
  | 'Organization Control Set';

export type LocalProtectionStatus =
  | 'protected'
  | 'needs-attention'
  | 'managed'
  | 'lockdown'
  | 'unsupported';

export interface LocalProtectionView {
  title: string;
  summary: string;
  source: ProtectionSource;
  status: LocalProtectionStatus;
  primaryAction: {
    label: string;
    href?: string;
    action?: 'refresh' | 'repair' | 'connect-cloud';
  } | null;
  technicalDetails: ReadonlyArray<{ label: string; value: string }>;
}

export interface LocalProtectionInput {
  extensionName: string;
  effectiveState: 'allowed' | 'blocked' | 'required' | 'lockdown';
  source: ProtectionSource;
  catalogDigest?: string;
  acknowledgementRevision?: number;
  stale?: boolean;
  supported?: boolean;
  cloudControlsUrl?: string;
  extensionId?: string;
  permissionId?: string;
}

function managedControlsHref(input: LocalProtectionInput): string | null {
  if (!input.cloudControlsUrl) {
    return null;
  }
  let target: URL;
  try {
    target = new URL('/guard/controls', input.cloudControlsUrl);
  } catch {
    return null;
  }
  if (input.extensionId) {
    target.searchParams.set('extensionId', input.extensionId);
  }
  if (input.permissionId) {
    target.searchParams.set('permissionId', input.permissionId);
  }
  return target.toString();
}

export function buildLocalProtectionView(
  input: LocalProtectionInput,
): LocalProtectionView {
  if (input.supported === false) {
    return {
      title: input.extensionName,
      summary: 'Update Guard before this managed setting can be applied.',
      source: input.source,
      status: 'unsupported',
      primaryAction: { label: 'Check for updates', action: 'refresh' },
      technicalDetails: [],
    };
  }
  if (input.stale) {
    return {
      title: input.extensionName,
      summary: 'Guard is using the last verified setting while it checks for an update.',
      source: input.source,
      status: 'needs-attention',
      primaryAction: { label: 'Check again', action: 'refresh' },
      technicalDetails: [],
    };
  }
  let status: LocalProtectionStatus = 'protected';
  if (input.effectiveState === 'lockdown') {
    status = 'lockdown';
  } else if (input.source === 'Organization Control Set') {
    status = 'managed';
  }

  let summary = 'Guard checks matching actions before they run.';
  if (input.effectiveState === 'blocked') {
    summary = 'Matching actions are blocked.';
  } else if (input.effectiveState === 'required') {
    summary = 'This protection stays on.';
  } else if (input.effectiveState === 'lockdown') {
    summary = 'Emergency Lockdown blocks governed actions.';
  }

  const controlsHref = managedControlsHref(input);
  const primaryAction = controlsHref
    ? {
        label:
          input.source === 'This device'
            ? 'Apply across my devices'
            : 'Manage in Guard Cloud',
        href: controlsHref,
      }
    : { label: 'Connect Guard Cloud', action: 'connect-cloud' as const };
  return {
    title: input.extensionName,
    summary,
    source: input.source,
    status,
    primaryAction,
    technicalDetails: [
      ...(input.catalogDigest
        ? [{ label: 'Catalog digest', value: input.catalogDigest }]
        : []),
      ...(input.acknowledgementRevision !== undefined
        ? [
            {
              label: 'Acknowledgement revision',
              value: String(input.acknowledgementRevision),
            },
          ]
        : []),
    ],
  };
}
