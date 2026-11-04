// Tauri IPC transport implementation.

import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { InvokeOptions, Transport, UnlistenFn } from "./transport";

export function createTauriTransport(): Transport {
  return {
    async invoke<T = unknown>(
      command: string,
      args?: Record<string, unknown>,
      options?: InvokeOptions,
    ): Promise<T> {
      const isRunLaunch = command === "replay_run" || command === "run_fuzzer" || command === "run_syzkaller";
      const invokeArgs = isRunLaunch && options?.onRunStarted
        ? {
            ...args,
            onRunStarted: new Channel<string>(options.onRunStarted),
          }
        : args;
      return invoke<T>(command, invokeArgs);
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      return listen<T>(event, callback);
    },
  };
}
