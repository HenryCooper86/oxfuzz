// Shared DefectDojo access for presentation surfaces (sidebar, dashboard).
//
// Exposes whether DefectDojo is configured so those surfaces can show their entry
// points only when it is usable. Opening navigates to the in-app DefectDojo view
// (which embeds the real web UI as a native child webview), so no open helper is
// needed here. Desktop-only: in the browser build `configured` stays false.

import { useEffect, useState } from "react";
import { getTransport, isTauriEnvironment } from "./index";

export interface DefectDojoAccess {
  /** True once a usable (non-placeholder) DefectDojo config is present. */
  configured: boolean;
}

export function useDefectDojo(): DefectDojoAccess {
  const [configured, setConfigured] = useState(false);

  useEffect(() => {
    if (!isTauriEnvironment()) return;
    let alive = true;
    getTransport()
      .invoke<boolean>("defectdojo_configured")
      .then((v) => {
        if (alive) setConfigured(v);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  return { configured };
}
