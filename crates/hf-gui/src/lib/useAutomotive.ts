// Shared automotive availability for presentation surfaces (sidebar).
//
// Exposes whether the automotive subsystem is enabled so the sidebar can show
// its entry point only when it is usable. The automotive domain (CAN/UDS bench
// work) is irrelevant to most fuzzing projects, so -- like DefectDojo -- its nav
// item should not occupy a permanent slot. Unlike DefectDojo, automotive
// settings are served over both transports, so this fetches regardless of
// environment and simply stays disabled if the endpoint is unavailable.

import { useEffect, useState } from "react";
import { getAutomotiveSettings } from "./automotive";

export interface AutomotiveAccess {
  /** True once automotive support is enabled in settings. */
  enabled: boolean;
}

export function useAutomotive(): AutomotiveAccess {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    let alive = true;
    getAutomotiveSettings()
      .then((settings) => {
        if (alive) setEnabled(settings.enabled);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  return { enabled };
}
