// Transport singleton -- selects Tauri or HTTP based on environment.

import { isTauriEnvironment, type Transport } from "./transport";
import { createTauriTransport } from "./tauriTransport";
import { createHttpTransport } from "./httpTransport";

let transport: Transport | null = null;

export function getTransport(): Transport {
  if (!transport) {
    if (import.meta.env.VITE_BACKEND === "http" || !isTauriEnvironment()) {
      transport = createHttpTransport();
    } else {
      transport = createTauriTransport();
    }
  }
  return transport;
}

export { isTauriEnvironment };
export type { Transport, UnlistenFn } from "./transport";
export { pickFolder, pickFile } from "./platform";
export { emitDataChanged, onDataChanged } from "./events";
export { useDefectDojo, type DefectDojoAccess } from "./useDefectDojo";