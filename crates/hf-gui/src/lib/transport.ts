// Transport abstraction for dual-host (Tauri desktop + web HTTP).

export interface UnlistenFn {
  (): void;
}

export interface InvokeOptions {
  signal?: AbortSignal;
  onRunStarted?: (runId: string) => void;
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

export interface RunOwner {
  run_id: string;
  project_root: string;
  target: string | null;
  engine: string;
  kind: string;
  status: string;
  started_at: string;
}

export interface CoverageSample {
  t: number;
  edges: number;
  execs: number;
}

export interface CampaignTelemetry {
  schema_version: 2;
  run_id: string;
  observed_at: string;
  last_progress_at: string | null;
  coverage_series: CoverageSample[];
  current_execs: number | null;
  mean_execs: number | null;
  peak_execs: number | null;
  throughput_sample_count: number;
  throughput_sample_sum: number;
  edges: number | null;
  managed_invocations_expected: number;
  managed_invocations_alive: number;
  free_disk_bytes: number | null;
}

export type HealthCondition =
  | "coverage_plateau"
  | "managed_invocation_missing"
  | "worker_stats_stale"
  | "disk_pressure"
  | "run_failed";

export interface CampaignHealthEvidence {
  schema_version: 2;
  run_id: string;
  condition: HealthCondition;
  observed_at: string;
  run_status: string;
  plateau_window: number;
  stale_progress_secs: number;
  disk_floor_bytes: number;
  coverage_samples: Array<{
    elapsed_secs: number;
    edges: number;
    execs: number;
  }>;
  last_progress_at: string | null;
  progress_stale_secs: number | null;
  current_execs: number | null;
  mean_execs: number | null;
  peak_execs: number | null;
  throughput_sample_count: number;
  throughput_sample_sum: number;
  managed_invocations_expected: number;
  managed_invocations_alive: number;
  free_disk_bytes: number | null;
}

export interface CampaignHealthEvent {
  schema_version: 2;
  id: string | null;
  run_id: string;
  condition: HealthCondition;
  severity: "warning" | "error";
  dedup_key: string;
  detail: string;
  observed_at: string;
  evidence: CampaignHealthEvidence;
}

export interface CampaignHealthEventPage {
  events: CampaignHealthEvent[];
  next_cursor: string | null;
}

export interface CampaignHealthReport {
  schema_version: 2;
  run_id: string;
  plateau_check:
    | { state: "evaluated"; window: number }
    | { state: "unavailable"; reason: string };
  events: CampaignHealthEvent[];
}

export interface CampaignHealthDelivery {
  owner: RunOwner;
  event: CampaignHealthEvent;
}

export interface MorningHealthSummary {
  schema_version: 2;
  project_root: string;
  since: string;
  failed: string[];
  stalled: string[];
  interrupted: string[];
  unprocessed: string[];
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
  invoke<T = unknown>(
    command: string,
    args?: Record<string, unknown>,
    options?: InvokeOptions,
  ): Promise<T>;
  listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn>;
}

export function isTauriEnvironment(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
