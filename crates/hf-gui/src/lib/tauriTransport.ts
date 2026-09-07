// Tauri IPC transport implementation.

import type { InvokeOptions, Transport, UnlistenFn } from "./transport";

export function createTauriTransport(): Transport {
  return {
    async invoke<T = unknown>(
      command: string,
      args?: Record<string, unknown>,
      options?: InvokeOptions,
    ): Promise<T> {
      const { Channel, invoke } = await import("@tauri-apps/api/core");
      const isRunLaunch = command === "run_fuzzer" || command === "run_syzkaller";
      const invokeArgs = isRunLaunch && options?.onRunStarted
        ? {
            ...args,
            onRunStarted: new Channel<string>(options.onRunStarted),
          }
        : args;
      return invoke<T>(command, invokeArgs);
    },
    async listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn> {
      const { listen } = await import("@tauri-apps/api/event");
      return listen<T>(event, callback);
    },
  };
}
