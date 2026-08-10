import { useMemo, useState } from "react";

import {
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
} from "../extension-controls-api";
import { ExtensionsFilterBar } from "../extensions-filter-bar";
import type { ExtensionFilterState } from "../extensions-filters";
import { fetchRuntimeSnapshot } from "../guard-api";
import {
  CloudContinuityIndicator,
  ProtectionCategoryGrid,
  ProtectionHealthCheckPanel,
  ProtectionModuleExplorer,
  RecentProtectionDecisions,
} from "./components/protection-landing-panels";
import {
  evaluateProtectionHealth,
  protectionCloudContinuity,
  rankProtectionModules,
  recentProtectionDecisions,
  type ProtectionHealthCheck,
} from "./model/protection-landing";
import { useProtectionLandingData } from "./use-protection-landing-data";

export function ProtectionLandingExperience(props: {
  catalog: readonly ExtensionCatalogItem[];
  catalogDigest: string;
  effective: EffectiveExtensionControls;
  filters: ExtensionFilterState;
  onFilters: (patch: Partial<ExtensionFilterState>) => void;
  onClearFilters: () => void;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const landing = useProtectionLandingData();
  const [healthBusy, setHealthBusy] = useState(false);
  const [healthResult, setHealthResult] = useState<ProtectionHealthCheck | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const modules = useMemo(() => rankProtectionModules(props.catalog, landing.activity), [landing.activity, props.catalog]);
  const decisions = useMemo(() => recentProtectionDecisions(landing.activity, props.catalog, 5), [landing.activity, props.catalog]);
  const continuity = useMemo(
    () => protectionCloudContinuity(landing.runtime, landing.runtimeError),
    [landing.runtime, landing.runtimeError],
  );

  async function runHealthCheck() {
    setHealthBusy(true);
    setHealthError(null);
    try {
      const [catalog, effective, runtime] = await Promise.all([
        fetchExtensionCatalog(),
        fetchEffectiveExtensionControls(),
        fetchRuntimeSnapshot({ includeItems: false, includeReceipts: false }),
      ]);
      setHealthResult(evaluateProtectionHealth(catalog.catalog_digest, effective, runtime));
    } catch (error) {
      setHealthResult(null);
      setHealthError(error instanceof Error ? error.message : "Guard could not complete the local protection health check.");
    } finally {
      setHealthBusy(false);
    }
  }

  return <>
    <div className="mt-4"><CloudContinuityIndicator continuity={continuity} loading={landing.runtimeLoading} /></div>
    <ProtectionCategoryGrid catalog={props.catalog} effective={props.effective} />
    <ProtectionModuleExplorer
      modules={modules}
      effective={props.effective}
      onOpen={props.onOpen}
      advancedFilters={<ExtensionsFilterBar filters={props.filters} onChange={props.onFilters} onClear={props.onClearFilters} extensions={props.catalog as ExtensionCatalogItem[]} effective={props.effective} />}
    />
    <RecentProtectionDecisions decisions={decisions} loading={landing.activityLoading} unavailable={landing.activityError} />
    <ProtectionHealthCheckPanel result={healthResult} busy={healthBusy} error={healthError} onRun={() => { void runHealthCheck(); }} />
  </>;
}
