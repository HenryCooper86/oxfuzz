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
      if (["coverage_experiment_create", "coverage_experiment_get", "coverage_experiment_list", "coverage_experiment_complete", "coverage_experiment_cancel"].includes(command)) {
        return invoke<T>(command, new TextEncoder().encode(JSON.stringify(args)));
      }
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
      const { listen } = await import("@tauri-apps/api/event");
      return listen<T>(event, callback);
    },
  };
}
