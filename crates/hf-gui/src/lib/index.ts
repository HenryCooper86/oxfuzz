// Transport singleton -- selects Tauri or HTTP based on environment.

import { isTauriEnvironment, usesHttpBackend, type Transport } from "./transport";
import { createTauriTransport } from "./tauriTransport";
import { createHttpTransport } from "./httpTransport";

let transport: Transport | null = null;

export function getTransport(): Transport {
  if (!transport) {
    if (usesHttpBackend()) {
      transport = createHttpTransport();
    } else {
      transport = createTauriTransport();
    }
  }
  return transport;
}

export { isTauriEnvironment, usesHttpBackend };
export type { Transport, UnlistenFn } from "./transport";
export { pickFolder, pickFile, openExternal } from "./platform";
export { emitDataChanged, onDataChanged } from "./events";
export { useDefectDojo, type DefectDojoAccess } from "./useDefectDojo";