// Authenticated SSE adapter normalizing web events to the Tauri event shape.

import type { UnlistenFn } from "./transport";

const MAX_EVENT_BUFFER_BYTES = 128 * 1024;

export class SseAdapter {
  private listeners = new Map<string, Set<(data: unknown) => void>>();
  private reconnectDelay = 1000;
  private readonly maxReconnectDelay = 30000;
  private abortController: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private baseUrl: string,
    private token?: string,
  ) {}

  private hasListeners(): boolean {
    return [...this.listeners.values()].some((listeners) => listeners.size > 0);
  }

  private connect() {
    if (this.abortController || !this.hasListeners()) return;
    const controller = new AbortController();
    this.abortController = controller;
    void this.consume(controller);
  }

  private async consume(controller: AbortController) {
    try {
      const headers: Record<string, string> = { Accept: "text/event-stream" };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      const response = await fetch(`${this.baseUrl}/events`, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        throw new Error(`SSE connection failed: ${response.status}`);
      }
      this.reconnectDelay = 1000;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (!controller.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        buffer = buffer.replace(/\r\n/g, "\n");
        buffer = this.consumeFrames(buffer);
        if (buffer.length > MAX_EVENT_BUFFER_BYTES) {
          throw new Error("SSE event buffer exceeded its transport limit");
        }
      }
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        // A reconnect is scheduled below. Keep secrets and response bodies out
        // of console output; the HTTP status is enough for local diagnostics.
      }
    } finally {
      if (this.abortController === controller) this.abortController = null;
      if (!controller.signal.aborted && this.hasListeners()) this.scheduleReconnect();
    }
  }

  private consumeFrames(buffer: string): string {
    let boundary = buffer.indexOf("\n\n");
    while (boundary >= 0) {
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      this.consumeFrame(frame);
      boundary = buffer.indexOf("\n\n");
    }
    return buffer;
  }

  private consumeFrame(frame: string) {
    let eventName = "message";
    const data: string[] = [];
    for (const line of frame.split("\n")) {
      if (line.startsWith("event:")) eventName = line.slice(6).trimStart();
      else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
    }
    if (data.length === 0) return;
    const raw = data.join("\n");
    try {
      const parsed = JSON.parse(raw) as { data?: unknown };
      let payload = parsed.data ?? parsed;
      if (
        eventName === "run:progress" &&
        payload &&
        typeof payload === "object" &&
        "kind" in payload &&
        "run_id" in payload
      ) {
        const progress = payload as { run_id: unknown; kind: unknown; data: unknown };
        if (typeof progress.run_id !== "string" || typeof progress.kind !== "string") {
          return;
        }
        payload = {
          run_id: progress.run_id,
          type: progress.kind,
          data: progress.data,
        };
      } else if (eventName === "run:status") {
        if (!payload || typeof payload !== "object") return;
        const status = payload as { run_id?: unknown; status?: unknown };
        if (typeof status.run_id !== "string" || typeof status.status !== "string") {
          return;
        }
        payload = { run_id: status.run_id, status: status.status };
      }
      this.dispatch(eventName, payload);
    } catch {
      this.dispatch(eventName, raw);
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer || !this.hasListeners()) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.reconnectDelay);
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
  }

  private dispatch(type: string, data: unknown) {
    this.listeners.get(type)?.forEach((callback) => callback(data));
  }

  listen<T>(event: string, callback: (event: { payload: T }) => void): UnlistenFn {
    const wrapped = (data: unknown) => callback({ payload: data as T });
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(wrapped);
    this.connect();
    return () => {
      this.listeners.get(event)?.delete(wrapped);
      if (!this.hasListeners()) {
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
        this.abortController?.abort();
        this.abortController = null;
      }
    };
  }
}
