// HTTP transport for web mode -- routes invoke() to REST endpoints.

import type {
  FuzzerRunResult,
  RunControlStatus,
  RunLifecycleStatus,
  RunStartResponse,
  RunStatusEvent,
  Transport,
  UnlistenFn,
} from "./transport";
import { SseAdapter } from "./sseAdapter";

const DEFAULT_BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8081";
const DEFAULT_API_TOKEN = import.meta.env.VITE_API_TOKEN;
const RUN_STATUS_POLL_MS = 1000;

interface HttpTransportOptions {
  baseUrl?: string;
  token?: string;
}

const COMMAND_MAP: Record<string, { method: string; path: string }> = {
  discover: { method: "POST", path: "/discover" },
  harness_draft: { method: "POST", path: "/harness/draft" },
  harness_compile: { method: "POST", path: "/harness/compile" },
  harness_smoke: { method: "POST", path: "/harness/smoke" },
  harness_promote: { method: "POST", path: "/harness/promote" },
  artifact_summary: { method: "POST", path: "/artifacts/summary" },
  report_formats: { method: "GET", path: "/report/formats" },
  all_crashes: { method: "GET", path: "/crashes/all" },
  all_corpus: { method: "GET", path: "/corpus/all" },
  run_history: { method: "POST", path: "/runs/history" },
  run_coverage_series: { method: "POST", path: "/runs/coverage" },
  run_harness_source: { method: "POST", path: "/runs/harness-source" },
  revert_harness_from_run: { method: "POST", path: "/runs/revert-harness" },
  run_fuzzer: { method: "POST", path: "/runs/start" },
  run_status: { method: "GET", path: "/runs/{run_id}/status" },
  cancel_run_by_id: { method: "POST", path: "/runs/{run_id}/cancel" },
  project_auto_revert_override: { method: "POST", path: "/projects/auto-revert" },
  project_auto_revert_overrides: { method: "GET", path: "/projects/auto-revert/all" },
  effective_auto_revert_policy: { method: "POST", path: "/projects/auto-revert/effective" },
  auto_revert_events: { method: "POST", path: "/audit/auto-revert" },
  set_project_auto_revert_override: { method: "POST", path: "/projects/auto-revert/set" },
  clear_project_auto_revert_override: { method: "POST", path: "/projects/auto-revert/clear" },
  generate_seeds: { method: "POST", path: "/seeds/generate" },
  generate_seeds_llm: { method: "POST", path: "/seeds/generate-llm" },
  corpus_list: { method: "POST", path: "/corpus/list" },
  corpus_seed: { method: "POST", path: "/corpus/seed" },
  corpus_grow: { method: "POST", path: "/corpus/grow" },
  corpus_prune: { method: "POST", path: "/corpus/prune" },
  triage: { method: "POST", path: "/triage" },
  generate_report: { method: "POST", path: "/report" },
  list_report_drafts: { method: "GET", path: "/reports" },
  save_report_draft: { method: "POST", path: "/reports/save" },
  delete_report_draft: { method: "POST", path: "/reports/delete" },
  clear_knowledge: { method: "POST", path: "/knowledge/clear" },
  delete_project: { method: "POST", path: "/projects/delete" },
  delete_crash: { method: "POST", path: "/crashes/delete" },
  delete_corpus_entry: { method: "POST", path: "/corpus/delete-entry" },
  clear_all_artifacts: { method: "POST", path: "/artifacts/clear" },
  delete_run: { method: "POST", path: "/runs/delete" },
  clear_all_runs: { method: "POST", path: "/runs/clear" },
  export_project_data: { method: "POST", path: "/projects/export" },
  system_snapshot: { method: "GET", path: "/system/snapshot" },
  workbench_dashboard: { method: "POST", path: "/workbench/dashboard" },
  harness_review_queue: { method: "POST", path: "/workbench/harnesses" },
  gitlab_issue_export: { method: "POST", path: "/gitlab/issue" },
  issue_export: { method: "POST", path: "/issues/export" },
  file_issue: { method: "POST", path: "/issues/file" },
  issue_tracker_configured: { method: "GET", path: "/issues/configured" },
  issue_tracker_test_connection: { method: "GET", path: "/issues/test" },
  push_to_defectdojo: { method: "POST", path: "/defectdojo/push" },
  defectdojo_test_connection: { method: "GET", path: "/defectdojo/test" },
  defectdojo_configured: { method: "GET", path: "/defectdojo/configured" },
  defectdojo_status: { method: "GET", path: "/defectdojo/status" },
  defectdojo_start: { method: "POST", path: "/defectdojo/start" },
  defectdojo_stop: { method: "POST", path: "/defectdojo/stop" },
  schedule_list: { method: "GET", path: "/schedule" },
  schedule_create: { method: "POST", path: "/schedule" },
  schedule_history: { method: "GET", path: "/schedule/history" },
  schedule_history_clear: { method: "POST", path: "/schedule/history/clear" },
  schedule_targets: { method: "POST", path: "/schedule/targets" },
  schedule_concurrency_get: { method: "GET", path: "/schedule/concurrency" },
  schedule_concurrency_set: { method: "POST", path: "/schedule/concurrency" },
  schedule_delete: { method: "DELETE", path: "/schedule/{id}" },
  schedule_set_enabled: { method: "POST", path: "/schedule/{id}/enabled" },
  system_status: { method: "GET", path: "/system/status" },
  system_status_cmd: { method: "GET", path: "/system/status" },
  ensure_docker: { method: "GET", path: "/system/status" },
  chat_agent: { method: "POST", path: "/chat/agent" },
  create_session: { method: "POST", path: "/chat/session" },
  delete_session: { method: "POST", path: "/chat/delete" },
  chat_history: { method: "POST", path: "/chat/history" },
  chat_rollback: { method: "POST", path: "/chat/rollback" },
  chat_rollback_to: { method: "POST", path: "/chat/rollback_to" },
  chat_checkpoints: { method: "POST", path: "/chat/checkpoints" },
  chat_branch: { method: "POST", path: "/chat/branch" },
  chat_branches: { method: "POST", path: "/chat/branches" },
  list_models: { method: "GET", path: "/config/models" },
  list_configs: { method: "GET", path: "/config/sections" },
  read_config: { method: "POST", path: "/config/read" },
  write_config: { method: "POST", path: "/config/write" },
  config_toml_to_value: { method: "POST", path: "/config/toml_to_value" },
  config_value_to_toml: { method: "POST", path: "/config/value_to_toml" },
  get_providers: { method: "GET", path: "/config/providers" },
  set_providers: { method: "POST", path: "/config/providers" },
  provider_statuses: { method: "GET", path: "/providers/status" },
  diagnostics_cost_summary: { method: "GET", path: "/diagnostics/cost" },
  app_paths: { method: "GET", path: "/system/paths" },
  host_arch: { method: "GET", path: "/system/arch" },
  knowledge_index: { method: "POST", path: "/knowledge/index" },
  knowledge_ingest: { method: "POST", path: "/knowledge/ingest" },
  knowledge_search: { method: "POST", path: "/knowledge/search" },
};

// Tauri (desktop) converts JS camelCase arg keys to snake_case Rust params, so
// the whole frontend speaks camelCase. The hf-web routes deserialize snake_case
// field names, so for web mode we mirror Tauri's conversion here. Pure-casing
// keys convert generically (runId -> run_id); the few cases where the web field
// name genuinely differs from a straight snake_case (not just casing) live in
// RENAME_OVERRIDES so a generic converter can't silently mis-map them.
const RENAME_OVERRIDES: Record<string, string> = {
  // hf-web BranchRequest expects `fork_message_count`, not `fork_count`.
  forkCount: "fork_message_count",
};

function camelToSnake(key: string): string {
  return key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

function toWebArgs(args?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!args) return undefined;
  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    const webKey = RENAME_OVERRIDES[key] ?? camelToSnake(key);
    mapped[webKey] = value;
  }
  return mapped;
}

/**
 * Resolve a command's URL and body.
 *
 * Path placeholders (`/schedule/{id}`) are filled from the args and consumed, so
 * a REST route that keys on an id works from the same invoke() call shape the
 * Tauri transport takes. What is left over becomes the query string on a GET, or
 * the JSON body otherwise.
 */
function buildRequest(
  baseUrl: string,
  endpoint: { method: string; path: string },
  args?: Record<string, unknown>,
): { url: string; body: Record<string, unknown> } {
  const rest: Record<string, unknown> = { ...(toWebArgs(args) ?? {}) };
  const path = endpoint.path.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = rest[key];
    delete rest[key];
    return encodeURIComponent(String(value ?? ""));
  });
  const body = rest;
  if (endpoint.method !== "GET") return { url: `${baseUrl}${path}`, body };

  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(body)) {
    if (value !== undefined && value !== null) query.append(key, String(value));
  }
  const suffix = query.toString();
  return { url: `${baseUrl}${path}${suffix ? `?${suffix}` : ""}`, body };
}

interface RunHistorySnapshot {
  id: string;
  status: string;
  crashes: number;
  edges: number | null;
  execs: number | null;
}

function runStartArgs(args?: Record<string, unknown>): Record<string, unknown> {
  const mapped = { ...(args ?? {}) };
  if ("duration" in mapped) {
    mapped.durationSecs = mapped.duration;
    delete mapped.duration;
  }
  return mapped;
}

function serviceRunId(start: RunStartResponse): string {
  if (typeof start.run_id !== "string" || start.run_id.trim().length === 0) {
    throw new Error("POST /runs/start did not return a service-owned run id");
  }
  return start.run_id;
}

function isTerminalStatus(status: RunLifecycleStatus): boolean {
  return status === "done" || status === "failed" || status === "cancelled";
}

function isAttributedRunEvent(payload: unknown, runId: string | null): boolean {
  if (!runId || !payload || typeof payload !== "object" || !("run_id" in payload)) {
    return false;
  }
  return (payload as { run_id?: unknown }).run_id === runId;
}

function finiteMetric(value: number | null): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function createHttpTransport(options: HttpTransportOptions = {}): Transport {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const token = options.token ?? DEFAULT_API_TOKEN;
  const sse = new SseAdapter(baseUrl, token);
  let activeRunId: string | null = null;
  let pendingRunStart: Promise<RunStartResponse> | null = null;

  async function request<T>(
    endpoint: { method: string; path: string },
    args?: Record<string, unknown>,
  ): Promise<T> {
    const { url, body } = buildRequest(baseUrl, endpoint, args);
    const headers: Record<string, string> = {};
    if (endpoint.method !== "GET") headers["content-type"] = "application/json";
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(url, {
      method: endpoint.method,
      headers,
      body: endpoint.method === "GET" ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`${endpoint.method} ${endpoint.path}: ${response.status}`);
    }
    return response.json() as Promise<T>;
  }

  function waitForTerminalStatus(runId: string): Promise<RunLifecycleStatus> {
    return new Promise((resolve) => {
      let settled = false;
      let pollInFlight = false;
      let pollTimer: ReturnType<typeof setInterval> | null = null;
      let unlisten: UnlistenFn = () => {};

      const finish = (status: RunLifecycleStatus) => {
        if (settled || !isTerminalStatus(status)) return;
        settled = true;
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
        unlisten();
        resolve(status);
      };

      unlisten = sse.listen<RunStatusEvent>("run:status", (event) => {
        if (event.payload.run_id === runId) finish(event.payload.status);
      });

      const poll = async () => {
        if (settled || pollInFlight) return;
        pollInFlight = true;
        try {
          const snapshot = await request<RunControlStatus>(COMMAND_MAP.run_status, {
            runId,
          });
          if (snapshot.run_id === runId) finish(snapshot.status);
        } catch {
          // SSE remains authoritative while a transient status read is
          // unavailable. The next bounded poll retries without detaching from
          // the service-owned run.
        } finally {
          pollInFlight = false;
        }
      };
      void poll();
      pollTimer = setInterval(() => void poll(), RUN_STATUS_POLL_MS);
    });
  }

  async function runFuzzer(args?: Record<string, unknown>): Promise<FuzzerRunResult> {
    if (activeRunId || pendingRunStart) {
      throw new Error("A browser fuzz run is already active");
    }

    const startPromise = request<RunStartResponse>(
      COMMAND_MAP.run_fuzzer,
      runStartArgs(args),
    );
    pendingRunStart = startPromise;
    let start: RunStartResponse;
    try {
      start = await startPromise;
    } finally {
      if (pendingRunStart === startPromise) pendingRunStart = null;
    }

    const runId = serviceRunId(start);
    activeRunId = runId;
    try {
      const status = await waitForTerminalStatus(runId);
      if (status === "failed") {
        throw new Error(`Fuzz run ${runId} failed`);
      }
      const history = await request<RunHistorySnapshot[]>(COMMAND_MAP.run_history, {
        project: args?.project,
      });
      const completed = history.find((run) => run.id === runId);
      if (!completed) {
        throw new Error(`Run history does not contain service-owned run ${runId}`);
      }
      return {
        run_id: runId,
        edges: finiteMetric(completed.edges),
        crashes: finiteMetric(completed.crashes),
        execs: finiteMetric(completed.execs),
        exit_code: null,
        termination: status === "cancelled" ? "cancelled" : "completed",
        stagnation: null,
        auto_revert: null,
      };
    } finally {
      if (activeRunId === runId) activeRunId = null;
    }
  }

  async function cancelActiveRun(): Promise<number> {
    let runId = activeRunId;
    if (!runId && pendingRunStart) {
      runId = serviceRunId(await pendingRunStart);
    }
    if (!runId) return 0;
    const response = await request<{ run_id: string; accepted: boolean }>(
      COMMAND_MAP.cancel_run_by_id,
      { runId },
    );
    if (response.run_id !== runId) {
      throw new Error("Run cancellation response did not match the active service-owned run id");
    }
    return response.accepted ? 1 : 0;
  }

  return {
    async invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> {
      if (command === "run_fuzzer") return runFuzzer(args) as Promise<T>;
      if (command === "cancel_run") return cancelActiveRun() as Promise<T>;
      const endpoint = COMMAND_MAP[command];
      if (!endpoint) {
        // Lifecycle/noop commands return undefined in web mode.
        if (["show_window", "heartbeat_pong", "toggle_devtools", "open_folder_dialog", "open_file_dialog", "run_syzkaller", "save_report"].includes(command)) {
          if (command === "open_folder_dialog") {
            // Web fallback: use <input type="file" webkitdirectory>
            return new Promise((resolve) => {
              const input = document.createElement("input");
              input.type = "file";
              input.webkitdirectory = true;
              input.onchange = () => {
                if (input.files && input.files.length > 0) {
                  const file = input.files[0] as File & { webkitRelativePath?: string };
                  const path = file.webkitRelativePath?.split("/")[0] ?? "";
                  resolve(path as T);
                } else {
                  resolve(undefined as T);
                }
              };
              input.click();
            });
          }
          return undefined as T;
        }
        // Agent/session/skills/knowledge commands (chat_agent aside) have no
        // hf-web endpoint yet. Fail loudly so callers fall back gracefully
        // instead of silently mapping to the wrong route. Their UI callers
        // already `.catch()` this and degrade to an empty/offline state.
        throw new Error(`Unsupported command in web mode: ${command}`);
      }
      return request<T>(endpoint, args);
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      if (event === "run:progress" || event === "run:status") {
        return sse.listen<T>(event, (message) => {
          if (isAttributedRunEvent(message.payload, activeRunId)) callback(message);
        });
      }
      return sse.listen(event, callback);
    },
  };
}
