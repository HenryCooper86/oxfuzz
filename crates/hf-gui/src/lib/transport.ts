// Transport abstraction for dual-host (Tauri desktop + web HTTP).

export interface UnlistenFn {
  (): void;
}

export interface Transport {
  invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T>;
  listen<T = unknown>(event: string, callback: (event: { payload: T }) => void): Promise<UnlistenFn>;
}

export function isTauriEnvironment(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}