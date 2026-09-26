import { getTransport } from "./index";
import type { RankedDiscoveryResult, RankedDiscoveryStatus } from "../types";

const POLL_INTERVAL_MS = 200;
const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);

function pause(signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    if (signal.aborted) { resolve(); return; }
    const timer = setTimeout(finish, POLL_INTERVAL_MS);
    function finish() {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    }
    signal.addEventListener("abort", finish, { once: true });
  });
}

export async function waitForRankedDiscovery(
  operationId: string,
  initialRevision: number,
  onStatus: (status: RankedDiscoveryStatus) => void,
  onResult: (result: RankedDiscoveryResult) => void,
  signal: AbortSignal,
): Promise<void> {
  let shownRevision = initialRevision;
  while (!signal.aborted) {
    const status = await getTransport().invoke<RankedDiscoveryStatus>(
      "ranked_discovery_status", { operationId }, { signal },
    );
    if (signal.aborted) return;
    if (status.operation_id !== operationId) throw new Error("Discovery status belongs to another operation");
    onStatus(status);
    if (status.revision > shownRevision) {
      const result = await getTransport().invoke<RankedDiscoveryResult | null>(
        "ranked_discovery_result", { operationId }, { signal },
      );
      if (signal.aborted) return;
      if (!result || result.operation_id !== operationId || result.revision !== status.revision) {
        throw new Error("Discovery result does not match the published revision");
      }
      shownRevision = result.revision;
      onResult(result);
    }
    if (TERMINAL.has(status.state)) return;
    await pause(signal);
  }
}
