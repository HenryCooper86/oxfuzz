// HTTP transport for web mode -- routes invoke() to REST endpoints.

import type { Transport, UnlistenFn } from "./transport";
import { SseAdapter } from "./sseAdapter";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8081";

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
  endpoint: { method: string; path: string },
  args?: Record<string, unknown>,
): { url: string; body: Record<string, unknown> } {
  const rest: Record<string, unknown> = { ...(args ?? {}) };
  const path = endpoint.path.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = rest[key];
    delete rest[key];
    return encodeURIComponent(String(value ?? ""));
  });
  const body = toWebArgs(rest) ?? {};
  if (endpoint.method !== "GET") return { url: `${BASE_URL}${path}`, body };

  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(body)) {
    if (value !== undefined && value !== null) query.append(key, String(value));
  }
  const suffix = query.toString();
  return { url: `${BASE_URL}${path}${suffix ? `?${suffix}` : ""}`, body };
}

export function createHttpTransport(): Transport {
  const sse = new SseAdapter(BASE_URL);
  return {
    async invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> {
      const endpoint = COMMAND_MAP[command];
      if (!endpoint) {
        // Lifecycle/noop commands return undefined in web mode.
        if (["show_window", "heartbeat_pong", "toggle_devtools", "open_folder_dialog", "open_file_dialog", "run_fuzzer", "run_syzkaller", "cancel_run", "save_report"].includes(command)) {
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
      const { url, body } = buildRequest(endpoint, args);
      const response = await fetch(url, {
        method: endpoint.method,
        headers: { "content-type": "application/json" },
        body: endpoint.method === "GET" ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error(`${endpoint.method} ${endpoint.path}: ${response.status}`);
      }
      return response.json() as Promise<T>;
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      return sse.listen(event, callback);
    },
  };
}
