import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { getTransport } from "../lib";
import { useToast } from "../components/ui/toastContext";
import { useProject } from "./project";
import { useRunStatus } from "./runStatus";
import { RunOutputContext } from "./runOutput";
import { RunOutputController } from "./runOutputController";

export function RunOutputProvider({ children }: { children: React.ReactNode }) {
  const { activeProject } = useProject();
  const { setActiveEngine } = useRunStatus();
  const { toast } = useToast();
  const [controller] = useState(() => new RunOutputController(getTransport()));
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
  useEffect(
    () => controller.configure(toast, setActiveEngine),
    [controller, toast, setActiveEngine],
  );
  useEffect(() => controller.start(), [controller]);
  useEffect(() => controller.selectProject(activeProject), [controller, activeProject]);
  const id = state.latest[activeProject];
  const selected =
    id && state.runs[id]?.owner?.project_root === activeProject
      ? state.runs[id]
      : state.legacy[activeProject];
  const value = useMemo(
    () => ({
      log: selected?.log ?? [],
      stats: selected?.stats ?? {
        currentExecs: null,
        meanExecs: null,
        peakExecs: null,
        edges: null,
        rawCrashSignals: null,
      },
      summary: selected?.summary ?? null,
      selectedRun: selected?.owner ?? null,
      requestState: state.requestState,
      requestError: state.requestError,
      running: state.requestState !== "idle",
      cancelling: state.cancelling,
      lastTarget: selected?.lastTarget ?? "",
      lastEngine: selected?.lastEngine ?? "",
      healthEvents: selected?.healthEvents ?? [],
      healthState: {
        loading: selected?.healthLoading ?? false,
        error: selected?.healthError ?? null,
        hasOlder: !!selected?.nextCursor,
      },
      loadOlderHealthEvents: controller.loadOlderHealthEvents,
      runFuzzer: controller.runFuzzer,
      runSyzkaller: controller.runSyzkaller,
      cancelRun: controller.cancelRun,
      clear: controller.clear,
    }),
    [controller, selected, state.requestState, state.requestError, state.cancelling],
  );
  return <RunOutputContext.Provider value={value}>{children}</RunOutputContext.Provider>;
}
