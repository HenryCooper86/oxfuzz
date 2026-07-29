// Transport abstraction for dual-host (Tauri desktop + web HTTP).

export interface UnlistenFn {
  (): void;
}

/** Lifecycle values emitted by the service-owned web run controller. */
export type RunLifecycleStatus =
  | "pending"
  | "running"
  | "cancellation_requested"
  | "done"
  | "failed"
  | "cancelled";

/** Accepted response from the asynchronous `POST /runs/start` contract. */
export interface RunStartResponse {
  run_id: string;
  status: RunLifecycleStatus;
}

/** Accepted response from the asynchronous `POST /semgrep/enrich` contract. */
export interface SemgrepStartResponse {
  operation_id: string;
  state: "staging";
}

/** Durable lifecycle snapshot returned by `GET /runs/{id}/status`. */
export interface RunControlStatus {
  run_id: string;
  status: RunLifecycleStatus;
  active: boolean;
  started_at: string;
  ended_at: string | null;
}

/** Run-attributed progress shape produced by the web SSE adapter. */
export interface RunProgressEvent {
  run_id: string;
  type: string;
  data: unknown;
}

/** Run-attributed lifecycle event delivered by web SSE. */
export interface RunStatusEvent {
  run_id: string;
  status: RunLifecycleStatus;
}

/** Result shape expected by the existing Run output provider. */
export interface FuzzerRunResult {
  run_id: string;
  edges: number;
  crashes: number;
  execs: number;
  exit_code: number | null;
  termination: "completed" | "timed_out" | "cancelled";
  stagnation: string | null;
  auto_revert: unknown | null;
}

export interface Transport {
  invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T>;
  listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn>;
}

export function isTauriEnvironment(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
