// HTTP transport for web mode -- routes invoke() to REST endpoints.

import type {
  FuzzerRunResult,
  RunControlStatus,
  RunLifecycleStatus,
  RunStartResponse,
  RunStatusEvent,
  SemgrepStartResponse,
  InvokeOptions,
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

interface CommandEndpoint {
  method: string;
  path: string;
  emptyBody?: boolean;
}

const COMMAND_MAP: Record<string, CommandEndpoint> = {
  discover: { method: "POST", path: "/discover" },
  semgrep_available: { method: "GET", path: "/semgrep/available" },
  semgrep_enrich: { method: "POST", path: "/semgrep/enrich" },
  semgrep_status: { method: "GET", path: "/semgrep/enrich/{operation_id}" },
  semgrep_cancel: {
    method: "POST",
    path: "/semgrep/enrich/{operation_id}/cancel",
  },
  harness_draft: { method: "POST", path: "/harness/draft" },
  harness_compile: { method: "POST", path: "/harness/compile" },
  harness_smoke: { method: "POST", path: "/harness/smoke" },
  harness_promote: { method: "POST", path: "/harness/promote" },
  work_order_export: { method: "POST", path: "/harness/work-orders" },
  work_order_list: { method: "GET", path: "/harness/work-orders" },
  work_order_get: { method: "GET", path: "/harness/work-orders/{work_order_id}" },
  work_order_import: {
    method: "POST",
    path: "/harness/work-orders/{work_order_id}/submissions",
  },
  work_order_submissions: {
    method: "GET",
    path: "/harness/work-orders/{work_order_id}/submissions",
  },
  work_order_qualify: {
    method: "POST",
    path: "/harness/work-order-submissions/{submission_id}/qualifications",
    emptyBody: true,
  },
  work_order_attempts: {
    method: "GET",
    path: "/harness/work-order-submissions/{submission_id}/qualifications",
  },
  work_order_attempt: {
    method: "GET",
    path: "/harness/work-order-attempts/{attempt_id}",
  },
  work_order_rank: { method: "POST", path: "/harness/work-order-attempts/rank" },
  work_order_promote: {
    method: "POST",
    path: "/harness/work-order-attempts/{attempt_id}/promotion",
    emptyBody: true,
  },
  artifact_summary: { method: "POST", path: "/artifacts/summary" },
  report_formats: { method: "GET", path: "/report/formats" },
  all_crashes: { method: "GET", path: "/crashes/all" },
  all_corpus: { method: "GET", path: "/corpus/all" },
  run_comparison: { method: "POST", path: "/runs/compare" },
  run_history: { method: "POST", path: "/runs/history" },
  run_coverage_series: { method: "POST", path: "/runs/coverage" },
  run_harness_source: { method: "POST", path: "/runs/harness-source" },
  revert_harness_from_run: { method: "POST", path: "/runs/revert-harness" },
  replay_review: { method: "GET", path: "/runs/{run_id}/replay" },
  replay_run: { method: "POST", path: "/runs/{run_id}/replay" },
  run_fuzzer: { method: "POST", path: "/runs/start" },
  run_owner: { method: "GET", path: "/runs/{run_id}/owner" },
  run_status: { method: "GET", path: "/runs/{run_id}/status" },
  campaign_health_report: { method: "GET", path: "/runs/{run_id}/health" },
  campaign_telemetry: { method: "GET", path: "/runs/{run_id}/telemetry" },
  campaign_health_events: { method: "GET", path: "/runs/{run_id}/health/events" },
  morning_health_summary: { method: "POST", path: "/campaign-health/morning" },
  run_closeout_report: { method: "GET", path: "/runs/{run_id}/closeout" },
  run_closeout: {
    method: "POST",
    path: "/runs/{run_id}/closeout",
    emptyBody: true,
  },
  cancel_run_by_id: { method: "POST", path: "/runs/{run_id}/cancel" },
  allocation_candidates: { method: "POST", path: "/campaign/allocation/candidates" },
  allocation_status: { method: "POST", path: "/campaign/allocation/status" },
  allocation_propose: { method: "POST", path: "/campaign/allocation/propose" },
  allocation_review: { method: "POST", path: "/campaign/allocation/review" },
  campaign_advice: { method: "POST", path: "/campaign/advice" },
  campaign_evidence: { method: "POST", path: "/campaign/evidence" },
  remediation_draft: { method: "POST", path: "/remediation/draft" },
  create_remediation_operation: { method: "POST", path: "/remediation/operations" },
  approve_remediation_operation: {
    method: "POST",
    path: "/remediation/operations/{operation_id}/approve",
  },
  start_remediation_verification: {
    method: "POST",
    path: "/remediation/operations/{operation_id}/verify",
  },
  remediation_operation: { method: "GET", path: "/remediation/operations/{operation_id}" },
  finding_proof_card_for_crash: { method: "GET", path: "/findings/{crash_id}/proof-card" },
  finding_review_queue: { method: "POST", path: "/findings/review" },
  finding_review: { method: "GET", path: "/findings/{finding_id}/review" },
  change_impact: { method: "POST", path: "/change/impact" },
  change_compare: { method: "POST", path: "/change/compare" },
  change_publish: { method: "POST", path: "/change/publish" },
  build_diagnose: { method: "POST", path: "/build/diagnose" },
  build_run: { method: "POST", path: "/build/run" },
  build_profile: { method: "GET", path: "/build/profile" },
  build_profile_set: { method: "PUT", path: "/build/profile" },
  build_profile_clear: { method: "DELETE", path: "/build/profile" },
  build_history: { method: "GET", path: "/build/history" },
  harness_tournament: { method: "POST", path: "/harness/tournament" },
  coverage_experiment_create: { method: "POST", path: "/coverage/experiments" },
  coverage_experiment_get: { method: "GET", path: "/coverage/experiments/{id}" },
  coverage_experiment_list: { method: "GET", path: "/coverage/experiments" },
  coverage_experiment_complete: { method: "POST", path: "/coverage/experiments/{id}/complete" },
  coverage_experiment_cancel: { method: "POST", path: "/coverage/experiments/{id}/cancel" },
  coverage_blockers: { method: "POST", path: "/coverage/blockers" },
  automotive_lab_coverage: { method: "POST", path: "/automotive/lab/coverage" },
  automotive_lab_plan: { method: "POST", path: "/automotive/lab/plan" },
  automotive_lab_simulate: { method: "POST", path: "/automotive/lab/simulate" },
  automotive_lab_reset: { method: "POST", path: "/automotive/lab/reset" },
  oracle_scaffold: { method: "POST", path: "/oracles/scaffold" },
  oracle_violation: { method: "GET", path: "/findings/{crash_id}/oracle-violation" },
  project_auto_revert_override: { method: "POST", path: "/projects/auto-revert" },
  project_auto_revert_overrides: { method: "GET", path: "/projects/auto-revert/all" },
  effective_auto_revert_policy: { method: "POST", path: "/projects/auto-revert/effective" },
  auto_revert_events: { method: "POST", path: "/audit/auto-revert" },
  policy_decisions: { method: "GET", path: "/policy/decisions" },
  set_project_auto_revert_override: { method: "POST", path: "/projects/auto-revert/set" },
  clear_project_auto_revert_override: { method: "POST", path: "/projects/auto-revert/clear" },
  generate_seeds: { method: "POST", path: "/seeds/generate" },
  generate_seeds_llm: { method: "POST", path: "/seeds/generate-llm" },
  corpus_list: { method: "POST", path: "/corpus/list" },
  corpus_seed: { method: "POST", path: "/corpus/seed" },
  corpus_grow: { method: "POST", path: "/corpus/grow" },
  corpus_prune: { method: "POST", path: "/corpus/prune" },
  corpus_import: { method: "POST", path: "/corpus/import" },
  seed_survival: { method: "POST", path: "/corpus/survival" },
  corpus_prune_coverage: { method: "POST", path: "/corpus/prune-coverage" },
  corpus_minimize: { method: "POST", path: "/corpus/minimize" },
  corpus_capabilities: { method: "POST", path: "/corpus/capabilities" },
  triage: { method: "POST", path: "/triage" },
  verify_crash: { method: "POST", path: "/crash/verify" },
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
  schedule_recovery_list: { method: "GET", path: "/schedule/recovery" },
  schedule_recovery_acknowledge: {
    method: "POST",
    path: "/schedule/recovery/{occurrenceId}/acknowledge",
  },
  schedule_targets: { method: "POST", path: "/schedule/targets" },
  schedule_concurrency_get: { method: "GET", path: "/schedule/concurrency" },
  schedule_runtime: { method: "GET", path: "/schedule/runtime" },
  schedule_concurrency_limits: { method: "GET", path: "/schedule/concurrency/limits" },
  schedule_concurrency_set: { method: "POST", path: "/schedule/concurrency" },
  schedule_delete: { method: "DELETE", path: "/schedule/{id}" },
  schedule_set_enabled: { method: "POST", path: "/schedule/{id}/enabled" },
  system_status: { method: "GET", path: "/system/status" },
  system_status_cmd: { method: "GET", path: "/system/status" },
  ensure_docker: { method: "GET", path: "/system/status" },
  chat_agent: { method: "POST", path: "/chat/agent" },
  agent_info: { method: "GET", path: "/agents/info" },
  agent_tools: { method: "GET", path: "/agents/tools" },
  list_agents: { method: "GET", path: "/agents" },
  get_agent: { method: "POST", path: "/agents/read" },
  save_agent: { method: "POST", path: "/agents/save" },
  delete_agent: { method: "POST", path: "/agents/delete" },
  list_skills: { method: "GET", path: "/skills" },
  read_skill: { method: "POST", path: "/skills/read" },
  save_skill: { method: "POST", path: "/skills/save" },
  delete_skill: { method: "POST", path: "/skills/delete" },
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
  get_fuzzing_settings: { method: "GET", path: "/config/fuzzing" },
  get_automotive_settings: { method: "GET", path: "/config/automotive" },
  set_automotive_settings: { method: "PUT", path: "/config/automotive" },
  automotive_capabilities: { method: "POST", path: "/automotive/capabilities" },
  automotive_analyze_capture: { method: "POST", path: "/automotive/analyze-capture" },
  automotive_generate_mutations: { method: "POST", path: "/automotive/mutations" },
  automotive_build_replay_plan: { method: "POST", path: "/automotive/replay-plan" },
  automotive_execute_replay: { method: "POST", path: "/automotive/replay" },
  list_automotive_operations: { method: "GET", path: "/automotive/operations" },
  promote_automotive_state_artifact: { method: "POST", path: "/automotive/state-corpus/promote" },
  list_automotive_state_corpus: { method: "GET", path: "/automotive/state-corpus" },
  generate_automotive_report: { method: "POST", path: "/automotive/report" },
  get_providers: { method: "GET", path: "/config/providers" },
  provider_test: { method: "POST", path: "/config/providers/test" },
  setup_readiness: { method: "GET", path: "/system/setup" },
  setup_providers: { method: "GET", path: "/system/setup/providers" },
  initialize_provider: { method: "POST", path: "/system/setup/providers" },
  set_providers: { method: "POST", path: "/config/providers" },
  get_defectdojo_config: { method: "GET", path: "/config/defectdojo" },
  patch_defectdojo_config: { method: "PATCH", path: "/config/defectdojo" },
  get_issue_tracker_config: { method: "GET", path: "/config/issue-tracker" },
  patch_issue_tracker_config: { method: "PATCH", path: "/config/issue-tracker" },
  provider_statuses: { method: "GET", path: "/providers/status" },
  diagnostics_cost_summary: { method: "GET", path: "/diagnostics/cost" },
  app_paths: { method: "GET", path: "/system/paths" },
  host_arch: { method: "GET", path: "/system/arch" },
  knowledge_index: { method: "POST", path: "/knowledge/index" },
  knowledge_ingest: { method: "POST", path: "/knowledge/ingest" },
  knowledge_search: { method: "POST", path: "/knowledge/search" },
  knowledge_stats: { method: "GET", path: "/knowledge/stats" },
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

function typedPatchBody(args?: Record<string, unknown>): Record<string, unknown> {
  const patch = args?.patch;
  return patch !== null && typeof patch === "object" && !Array.isArray(patch)
    ? patch as Record<string, unknown>
    : {};
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
  endpoint: CommandEndpoint,
  args?: Record<string, unknown>,
): { url: string; body: Record<string, unknown> } {
  const rest: Record<string, unknown> = { ...(toWebArgs(args) ?? {}) };
  const path = endpoint.path.replace(/\{(\w+)\}/g, (_, key: string) => {
    const restKey = key in rest ? key : camelToSnake(key);
    const value = rest[restKey];
    delete rest[restKey];
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
  if (
    typeof start.run_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(start.run_id)
  ) {
    throw new Error("POST /runs/start did not return a valid UUID service-owned run id");
  }
  return start.run_id;
}

function serviceSemgrepOperationId(start: SemgrepStartResponse): string {
  if (
    typeof start.operation_id !== "string"
    || start.operation_id.trim().length === 0
  ) {
    throw new Error(
      "POST /semgrep/enrich did not return a service-owned operation id",
    );
  }
  return start.operation_id;
}

function isTerminalStatus(status: RunLifecycleStatus): boolean {
  return status === "done" || status === "failed" || status === "cancelled";
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
    endpoint: CommandEndpoint,
    args?: Record<string, unknown>,
    options?: InvokeOptions,
  ): Promise<T> {
    const { url, body } = buildRequest(baseUrl, endpoint, args);
    const headers: Record<string, string> = {};
    if (endpoint.method !== "GET" && !endpoint.emptyBody) {
      headers["content-type"] = "application/json";
    }
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(url, {
      method: endpoint.method,
      headers,
      body: endpoint.method === "GET" || endpoint.emptyBody
        ? undefined
        : JSON.stringify(body),
      signal: options?.signal,
    });
    if (!response.ok) {
      let structured: Record<string, unknown> = {};
      let detail = `${endpoint.method} ${endpoint.path}: ${response.status}`;
      try {
        const error = await response.json() as Record<string, unknown>;
        structured = error;
        if (typeof error.error === "string") {
          detail = typeof error.code === "string"
            ? `${error.code}: ${error.error}`
            : error.error;
        }
      } catch {
        // A non-JSON error has no stable service detail to preserve.
      }
      throw Object.assign(new Error(detail), structured, { status: response.status });
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

  async function runFuzzer(
    command: "run_fuzzer" | "replay_run",
    args?: Record<string, unknown>,
    options?: InvokeOptions,
  ): Promise<FuzzerRunResult> {
    if (activeRunId || pendingRunStart) {
      throw new Error("A browser fuzz run is already active");
    }

    const startPromise = request<RunStartResponse>(
      COMMAND_MAP[command],
      command === "replay_run" ? { runId: args?.runId, review: args?.review } : runStartArgs(args),
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
      options?.onRunStarted?.(runId);
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

  async function cancelActiveRun(args?: Record<string, unknown>): Promise<number> {
    let runId = typeof args?.runId === "string" ? args.runId : activeRunId;
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

  async function startSemgrep(
    args?: Record<string, unknown>,
  ): Promise<string> {
    const start = await request<SemgrepStartResponse>(
      COMMAND_MAP.semgrep_enrich,
      args,
    );
    return serviceSemgrepOperationId(start);
  }

  async function cancelSemgrep(
    args?: Record<string, unknown>,
    options?: InvokeOptions,
  ): Promise<"accepted" | "inactive" | "not_found"> {
    const endpoint = COMMAND_MAP.semgrep_cancel;
    const { url, body } = buildRequest(baseUrl, endpoint, args);
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(url, {
      method: endpoint.method,
      headers,
      body: JSON.stringify(body),
      signal: options?.signal,
    });
    if (response.status === 202) return "accepted";
    if (response.status === 409) return "inactive";
    if (response.status === 404) return "not_found";
    throw new Error(`${endpoint.method} ${endpoint.path}: ${response.status}`);
  }

  return {
    async invoke<T = unknown>(
      command: string,
      args?: Record<string, unknown>,
      options?: InvokeOptions,
    ): Promise<T> {
      if (command === "run_fuzzer" || command === "replay_run") return runFuzzer(command, args, options) as Promise<T>;
      if (command === "cancel_run") return cancelActiveRun(args) as Promise<T>;
      if (command === "semgrep_enrich") return startSemgrep(args) as Promise<T>;
      if (command === "semgrep_cancel") {
        return cancelSemgrep(args, options) as Promise<T>;
      }
      if (command === "run_syzkaller") {
        throw new Error("Syzkaller campaigns are unavailable in web mode");
      }
      const endpoint = COMMAND_MAP[command];
      if (!endpoint) {
        // Lifecycle/noop commands return undefined in web mode.
        if (["show_window", "heartbeat_pong", "toggle_devtools", "open_folder_dialog", "open_file_dialog", "save_report"].includes(command)) {
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
        // Fail loudly for commands without an HTTP equivalent so callers can
        // present an accurate unsupported/offline state.
        throw new Error(`Unsupported command in web mode: ${command}`);
      }
      if (command === "coverage_experiment_get") return request<T>(endpoint, { id: args?.id, ...args?.scope as Record<string, unknown> }, options);
      if (command === "coverage_experiment_complete" || command === "coverage_experiment_cancel") return request<T>(endpoint, { id: args?.id, ...args?.request as Record<string, unknown> }, options);
      if (command === "coverage_experiment_list") {
        const { before, ...rest } = args ?? {};
        const cursor = before as { created_at: string; id: string } | null;
        return request<T>(endpoint, { ...rest, before_created_at: cursor?.created_at, before_id: cursor?.id }, options);
      }
      const requestArgs = command === "patch_defectdojo_config" || command === "patch_issue_tracker_config"
        ? typedPatchBody(args)
        : command === "campaign_advice" || command === "allocation_propose"
          ? args?.request as Record<string, unknown> | undefined
          : args;
      return request<T>(endpoint, requestArgs, options);
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      return sse.listen(event, callback);
    },
  };
}
