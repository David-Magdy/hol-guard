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
  primaryAction: { label: string; href?: string; action?: 'refresh' | 'repair' } | null;
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
  const status: LocalProtectionStatus =
    input.effectiveState === 'lockdown'
      ? 'lockdown'
      : input.source === 'Organization Control Set'
        ? 'managed'
        : 'protected';
  return {
    title: input.extensionName,
    summary:
      input.effectiveState === 'blocked'
        ? 'Matching actions are blocked.'
        : input.effectiveState === 'required'
          ? 'This protection stays on.'
          : input.effectiveState === 'lockdown'
            ? 'Emergency Lockdown blocks governed actions.'
            : 'Guard checks matching actions before they run.',
    source: input.source,
    status,
    primaryAction:
      input.source === 'This device'
        ? { label: 'Apply across my devices', href: '/guard/controls' }
        : { label: 'Manage in Guard Cloud', href: '/guard/controls' },
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
