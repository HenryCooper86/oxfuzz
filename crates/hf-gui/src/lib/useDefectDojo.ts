// Shared DefectDojo access for presentation surfaces (sidebar, dashboard).
//
// Exposes whether DefectDojo is configured and a helper to open its web UI in
// the dedicated in-app window. Desktop-only: in the browser build `configured`
// stays false (opening a native window is a Tauri capability), so callers hide
// their entry points there and rely on the Settings > Integrations buttons.

import { useCallback, useEffect, useState } from "react";
import { getTransport, isTauriEnvironment } from "./index";

export interface DefectDojoAccess {
  /** True once a usable (non-placeholder) DefectDojo config is present. */
  configured: boolean;
  /** Open the DefectDojo web UI in the in-app window. Rejects on failure. */
  open: () => Promise<void>;
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

  const open = useCallback(async () => {
    await getTransport().invoke("open_defectdojo", { inBrowser: false });
  }, []);

  return { configured, open };
}
