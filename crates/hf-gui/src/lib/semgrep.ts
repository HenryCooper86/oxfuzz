import { getTransport } from "./index";
import type {
  SemgrepInventory,
  SemgrepOperationState,
  SemgrepOperationView,
} from "../types";

const SEMGREP_POLL_MS = 500;

function waitForPoll(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const finish = () => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", finish);
      resolve();
    };
    const timeout = setTimeout(finish, SEMGREP_POLL_MS);
    signal.addEventListener("abort", finish, { once: true });
  });
}

/** Poll one exact service operation until its complete inventory is available. */
export async function waitForSemgrep(
  operationId: string,
  onState: (state: SemgrepOperationState) => void,
  signal: AbortSignal,
): Promise<SemgrepInventory> {
  while (!signal.aborted) {
    const view = await getTransport().invoke<SemgrepOperationView>(
      "semgrep_status",
      { operationId },
    );
    if (signal.aborted) {
      throw new DOMException("Semgrep polling stopped", "AbortError");
    }
    onState(view.state);
    if (view.state === "done") {
      if (!view.result) {
        throw new Error("completed Semgrep operation has no result");
      }
      return view.result;
    }
    if (view.state === "failed" || view.state === "cancelled") {
      throw new Error(
        view.failure_message ?? `Semgrep enrichment ${view.state}`,
      );
    }
    await waitForPoll(signal);
  }
  throw new DOMException("Semgrep polling stopped", "AbortError");
}
