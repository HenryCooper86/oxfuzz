// SSE adapter normalizing EventSource to match Tauri event shape.

import type { UnlistenFn } from "./transport";

export class SseAdapter {
  private eventSource: EventSource | null = null;
  private listeners = new Map<string, Set<(data: unknown) => void>>();
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;

  constructor(private baseUrl: string) {}

  private connect() {
    if (this.eventSource) return;
    this.eventSource = new EventSource(`${this.baseUrl}/api/v1/events`);
    this.eventSource.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data);
        const type = parsed.type ?? "message";
        const data = parsed.data ?? parsed;
        this.dispatch(type, data);
      } catch {
        this.dispatch("message", ev.data);
      }
    };
    this.eventSource.onerror = () => {
      this.eventSource?.close();
      this.eventSource = null;
      setTimeout(() => this.connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    };
    this.eventSource.onopen = () => {
      this.reconnectDelay = 1000;
    };
  }

  private dispatch(type: string, data: unknown) {
    const set = this.listeners.get(type);
    if (set) {
      set.forEach((cb) => cb(data));
    }
  }

  listen<T>(event: string, callback: (event: { payload: T }) => void): UnlistenFn {
    this.connect();
    const wrapped = (data: unknown) => callback({ payload: data as T });
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(wrapped);
    return () => {
      this.listeners.get(event)?.delete(wrapped);
    };
  }
}