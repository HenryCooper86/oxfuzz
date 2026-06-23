// HTTP transport for web mode -- routes invoke() to REST endpoints.

import type { Transport, UnlistenFn } from "./transport";
import { SseAdapter } from "./sseAdapter";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8081";

const COMMAND_MAP: Record<string, { method: string; path: string }> = {
  discover: { method: "POST", path: "/discover" },
  corpus_list: { method: "POST", path: "/corpus/list" },
  corpus_seed: { method: "POST", path: "/corpus/seed" },
  corpus_grow: { method: "POST", path: "/corpus/grow" },
  corpus_prune: { method: "POST", path: "/corpus/prune" },
  triage: { method: "POST", path: "/triage" },
  system_status: { method: "GET", path: "/health" },
};

export function createHttpTransport(): Transport {
  const sse = new SseAdapter(BASE_URL);
  return {
    async invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> {
      const endpoint = COMMAND_MAP[command];
      if (!endpoint) {
        // Lifecycle/noop commands return undefined in web mode.
        if (["show_window", "heartbeat_pong", "toggle_devtools"].includes(command)) {
          return undefined as T;
        }
        throw new Error(`Unsupported command in web mode: ${command}`);
      }
      const url = `${BASE_URL}${endpoint.path}`;
      const response = await fetch(url, {
        method: endpoint.method,
        headers: { "content-type": "application/json" },
        body: args ? JSON.stringify(args) : undefined,
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