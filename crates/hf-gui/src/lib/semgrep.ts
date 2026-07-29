import { getTransport } from "./index";
import type { InvokeOptions } from "./transport";
import type {
  SemgrepCancelOutcome,
  SemgrepInventory,
  SemgrepOperationState,
  SemgrepOperationView,
  SemgrepOverlayState,
  TargetCandidate,
} from "../types";

const SEMGREP_POLL_MS = 500;
const SEMGREP_STATUS_TIMEOUT_MS = 5_000;
const SEMGREP_MAX_CONSECUTIVE_FAILURES = 3;
const ACTIVE_SEMGREP_STATES: ReadonlySet<SemgrepOperationState> = new Set([
  "staging",
  "scanning",
  "validating",
  "persisting",
]);

export interface SemgrepContext {
  project: string;
  lang: string;
}

export interface BoundSemgrepInventory {
  context: SemgrepContext;
  inventory: SemgrepInventory;
}

export interface SemgrepPresentation {
  candidates: readonly TargetCandidate[];
  inventory: SemgrepInventory | null;
  showScores: boolean;
  staleMessageKey: string | null;
}

export interface SemgrepCancelDecision {
  abortPolling: boolean;
  releaseOwnership: boolean;
  nextState: SemgrepOperationState | null;
  errorKey: string | null;
}

interface SemgrepStatusTransport {
  invoke(
    command: string,
    args: Record<string, unknown>,
    options?: InvokeOptions,
  ): Promise<SemgrepOperationView>;
}

interface WaitForSemgrepOptions {
  transport?: SemgrepStatusTransport;
  pollMs?: number;
  requestTimeoutMs?: number;
  ownershipSignal?: AbortSignal;
  maxConsecutiveFailures?: number;
}

function sameContext(
  left: SemgrepContext | null,
  right: SemgrepContext | null,
): boolean {
  return (
    left !== null
    && right !== null
    && left.project === right.project
    && left.lang === right.lang
  );
}

/** Whether the exact current discovery is eligible for a new enrichment. */
export function canStartSemgrep(
  available: boolean,
  hasInventory: boolean,
  discoveryContext: SemgrepContext | null,
  selection: SemgrepContext,
  operationOwned: boolean,
): boolean {
  return (
    available
    && hasInventory
    && !operationOwned
    && sameContext(discoveryContext, selection)
    && (discoveryContext?.lang === "c" || discoveryContext?.lang === "cpp")
  );
}

/** Active ownership is the exact admitted UUID plus a nonterminal service state. */
export function hasOwnedSemgrepOperation(
  operationId: string | null,
  state: SemgrepOperationState | null,
): boolean {
  return (
    operationId !== null
    && state !== null
    && ACTIVE_SEMGREP_STATES.has(state)
  );
}

/** Remove a provisional state when start failed before service admission. */
export function semgrepStateAfterError(
  operationId: string | null,
  state: SemgrepOperationState | null,
): SemgrepOperationState | null {
  return operationId ? state : null;
}

/** Decide UI effects without conflating refusal/not-found with cancellation. */
export function semgrepCancelDecision(
  outcome: SemgrepCancelOutcome,
): SemgrepCancelDecision {
  switch (outcome) {
    case "accepted":
      return {
        abortPolling: true,
        releaseOwnership: false,
        nextState: "cancelled",
        errorKey: null,
      };
    case "inactive":
      return {
        abortPolling: false,
        releaseOwnership: false,
        nextState: null,
        errorKey: null,
      };
    case "not_found":
      return {
        abortPolling: false,
        releaseOwnership: true,
        nextState: null,
        errorKey: "discover.semgrepCancelNotFound",
      };
  }
}

/** Accept a late result only for the exact operation, discovery, and selection. */
export function canApplySemgrepResult(
  operationContext: SemgrepContext,
  discoveryContext: SemgrepContext | null,
  selection: SemgrepContext,
): boolean {
  return (
    sameContext(operationContext, discoveryContext)
    && sameContext(operationContext, selection)
  );
}

export function semgrepOverlayMessageKey(
  overlayState: SemgrepOverlayState,
): string | null {
  switch (overlayState) {
    case "stale_source":
      return "discover.semgrepStaleSource";
    case "stale_base":
      return "discover.semgrepStaleBase";
    case "incomplete_journal":
      return "discover.semgrepIncompleteJournal";
    case "none":
    case "current":
      return null;
  }
}

/** Build the component presentation while preserving base data and service order. */
export function buildSemgrepPresentation(
  baseCandidates: readonly TargetCandidate[],
  enrichment: BoundSemgrepInventory | null,
  discoveryContext: SemgrepContext | null,
  selection: SemgrepContext,
): SemgrepPresentation {
  const visible =
    enrichment
    && canApplySemgrepResult(
      enrichment.context,
      discoveryContext,
      selection,
    )
      ? enrichment.inventory
      : null;
  return {
    candidates: visible?.candidates ?? baseCandidates,
    inventory: visible,
    showScores: visible?.overlay_state === "current",
    staleMessageKey: visible
      ? semgrepOverlayMessageKey(visible.overlay_state)
      : null,
  };
}

function abortError(): DOMException {
  return new DOMException("Semgrep polling stopped", "AbortError");
}

function ownershipReleasedError(): DOMException {
  return new DOMException(
    "Semgrep operation ownership released",
    "SemgrepOwnershipReleased",
  );
}

function statusUnavailableError(): DOMException {
  return new DOMException(
    "Semgrep status is unavailable after repeated attempts",
    "SemgrepStatusUnavailable",
  );
}

function waitForPoll(
  signal: AbortSignal,
  ownershipSignal: AbortSignal | undefined,
  delayMs: number,
): Promise<void> {
  if (signal.aborted) return Promise.reject(abortError());
  if (ownershipSignal?.aborted) {
    return Promise.reject(ownershipReleasedError());
  }
  if (delayMs <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const finish = () => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", stop);
      ownershipSignal?.removeEventListener("abort", release);
      resolve();
    };
    const stop = () => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", stop);
      ownershipSignal?.removeEventListener("abort", release);
      reject(abortError());
    };
    const release = () => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", stop);
      ownershipSignal?.removeEventListener("abort", release);
      reject(ownershipReleasedError());
    };
    const timeout = setTimeout(finish, delayMs);
    signal.addEventListener("abort", stop, { once: true });
    ownershipSignal?.addEventListener("abort", release, { once: true });
  });
}

async function readStatus(
  operationId: string,
  signal: AbortSignal,
  ownershipSignal: AbortSignal | undefined,
  transport: SemgrepStatusTransport,
  timeoutMs: number,
): Promise<SemgrepOperationView | null> {
  if (signal.aborted) throw abortError();
  const requestController = new AbortController();
  const stopRequest = () => requestController.abort();
  signal.addEventListener("abort", stopRequest, { once: true });
  ownershipSignal?.addEventListener("abort", stopRequest, { once: true });
  const timeout = setTimeout(() => requestController.abort(), timeoutMs);
  let stopAbortRace: () => void = () => undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    const rejectAbort = () => reject(abortError());
    stopAbortRace = () =>
      requestController.signal.removeEventListener("abort", rejectAbort);
    requestController.signal.addEventListener("abort", rejectAbort, {
      once: true,
    });
  });

  try {
    return await Promise.race([
      transport.invoke(
        "semgrep_status",
        { operationId },
        { signal: requestController.signal },
      ),
      aborted,
    ]);
  } catch {
    if (signal.aborted) throw abortError();
    if (ownershipSignal?.aborted) throw ownershipReleasedError();
    return null;
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener("abort", stopRequest);
    ownershipSignal?.removeEventListener("abort", stopRequest);
    stopAbortRace();
  }
}

/** Poll one exact service operation until its complete inventory is available. */
export async function waitForSemgrep(
  operationId: string,
  onState: (state: SemgrepOperationState) => void,
  signal: AbortSignal,
  options: WaitForSemgrepOptions = {},
): Promise<SemgrepInventory> {
  const transport: SemgrepStatusTransport =
    options.transport ?? {
      invoke: (command, args, invokeOptions) =>
        getTransport().invoke<SemgrepOperationView>(
          command,
          args,
          invokeOptions,
        ),
    };
  const pollMs = options.pollMs ?? SEMGREP_POLL_MS;
  const requestTimeoutMs =
    options.requestTimeoutMs ?? SEMGREP_STATUS_TIMEOUT_MS;
  const ownershipSignal = options.ownershipSignal;
  const maxConsecutiveFailures =
    options.maxConsecutiveFailures ?? SEMGREP_MAX_CONSECUTIVE_FAILURES;
  let consecutiveFailures = 0;

  while (!signal.aborted) {
    if (ownershipSignal?.aborted) throw ownershipReleasedError();
    const view = await readStatus(
      operationId,
      signal,
      ownershipSignal,
      transport,
      requestTimeoutMs,
    );
    if (view === null) {
      consecutiveFailures += 1;
      if (consecutiveFailures >= maxConsecutiveFailures) {
        throw statusUnavailableError();
      }
      await waitForPoll(signal, ownershipSignal, pollMs);
      continue;
    }
    consecutiveFailures = 0;
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
    await waitForPoll(signal, ownershipSignal, pollMs);
  }
  throw abortError();
}
