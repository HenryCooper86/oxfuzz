// Tauri IPC transport implementation.

import type { InvokeOptions, Transport, UnlistenFn } from "./transport";

export function createTauriTransport(): Transport {
  return {
    async invoke<T = unknown>(
      command: string,
      args?: Record<string, unknown>,
      options?: InvokeOptions,
    ): Promise<T> {
      void options;
      const { invoke } = await import("@tauri-apps/api/core");
      return invoke<T>(command, args);
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      const { listen } = await import("@tauri-apps/api/event");
      return listen<T>(event, callback);
    },
  };
}
