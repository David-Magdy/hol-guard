import { useCallback, useEffect, useState } from "react";

import { createCommandActivityClient } from "../command-activity/command-activity-api";
import { DEFAULT_COMMAND_ACTIVITY_FILTERS } from "../command-activity/command-activity-state";
import type { CommandActivityItem } from "../command-activity/command-activity-types";
import { fetchCommandActivityApi, fetchRuntimeSnapshot } from "../guard-api";
import type { GuardRuntimeSnapshot } from "../guard-types";

const client = createCommandActivityClient(fetchCommandActivityApi);

type LandingDataState = {
  activity: CommandActivityItem[];
  activityLoading: boolean;
  activityError: boolean;
  runtime: GuardRuntimeSnapshot | null;
  runtimeLoading: boolean;
  runtimeError: boolean;
};

const INITIAL_STATE: LandingDataState = {
  activity: [],
  activityLoading: true,
  activityError: false,
  runtime: null,
  runtimeLoading: true,
  runtimeError: false,
};

export function useProtectionLandingData() {
  const [state, setState] = useState<LandingDataState>(INITIAL_STATE);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState((current) => ({
      ...current,
      activityLoading: true,
      activityError: false,
      runtimeLoading: true,
      runtimeError: false,
    }));
    void client.fetchPage({ ...DEFAULT_COMMAND_ACTIVITY_FILTERS, limit: 12 }, null, controller.signal).then(
      (page) => setState((current) => ({ ...current, activity: page.items, activityLoading: false })),
      () => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, activity: [], activityLoading: false, activityError: true }));
      },
    );
    void fetchRuntimeSnapshot({ includeItems: false, includeReceipts: false }).then(
      (runtime) => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, runtime, runtimeLoading: false }));
      },
      () => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, runtime: null, runtimeLoading: false, runtimeError: true }));
      },
    );
    return () => controller.abort();
  }, [refreshKey]);

  const refresh = useCallback(() => setRefreshKey((value) => value + 1), []);
  return { ...state, refresh };
}
