// HTTP transport for web mode -- routes invoke() to REST endpoints.

import type { Transport, UnlistenFn } from "./transport";
import { SseAdapter } from "./sseAdapter";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8081";

const COMMAND_MAP: Record<string, { method: string; path: string }> = {
  discover: { method: "POST", path: "/discover" },
  harness_draft: { method: "POST", path: "/harness/draft" },
  harness_compile: { method: "POST", path: "/harness/compile" },
  generate_seeds: { method: "POST", path: "/seeds/generate" },
  corpus_list: { method: "POST", path: "/corpus/list" },
  corpus_seed: { method: "POST", path: "/corpus/seed" },
  corpus_grow: { method: "POST", path: "/corpus/grow" },
  corpus_prune: { method: "POST", path: "/corpus/prune" },
  triage: { method: "POST", path: "/triage" },
  generate_report: { method: "POST", path: "/report" },
  clear_knowledge: { method: "POST", path: "/knowledge/clear" },
  system_snapshot: { method: "GET", path: "/system/snapshot" },
  workbench_dashboard: { method: "POST", path: "/workbench/dashboard" },
  harness_review_queue: { method: "POST", path: "/workbench/harnesses" },
  gitlab_issue_export: { method: "POST", path: "/gitlab/issue" },
  system_status: { method: "GET", path: "/system/status" },
  system_status_cmd: { method: "GET", path: "/system/status" },
  ensure_docker: { method: "GET", path: "/system/status" },
  chat_agent: { method: "POST", path: "/chat/agent" },
  create_session: { method: "POST", path: "/chat/session" },
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

function toWebArgs(args?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!args) return undefined;
  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    const webKey =
      key === "sessionId"
        ? "session_id"
        : key === "agentId"
          ? "agent_id"
          : key === "checkpointId"
            ? "checkpoint_id"
            : key === "forkCount"
              ? "fork_message_count"
              : key;
    mapped[webKey] = value;
  }
  return mapped;
}

export function createHttpTransport(): Transport {
  const sse = new SseAdapter(BASE_URL);
  return {
    async invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> {
      const endpoint = COMMAND_MAP[command];
      if (!endpoint) {
        // Lifecycle/noop commands return undefined in web mode.
        if (["show_window", "heartbeat_pong", "toggle_devtools", "open_folder_dialog", "open_file_dialog", "run_fuzzer", "run_syzkaller", "cancel_run", "save_report", "artifact_summary"].includes(command)) {
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
      const url = `${BASE_URL}${endpoint.path}`;
      const response = await fetch(url, {
        method: endpoint.method,
        headers: { "content-type": "application/json" },
        body:
          endpoint.method === "GET"
            ? undefined
            : JSON.stringify(toWebArgs(args) ?? {}),
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
