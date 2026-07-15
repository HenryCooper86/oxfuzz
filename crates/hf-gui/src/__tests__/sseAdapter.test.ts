import { describe, expect, it } from "vitest";
import { SseAdapter } from "../lib/sseAdapter";

describe("SseAdapter", () => {
  it("uses authenticated fetch streaming and dispatches named SSE events", async () => {
    const originalFetch = globalThis.fetch;
    const requests: RequestInit[] = [];
    const encoder = new TextEncoder();
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      requests.push(init ?? {});
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode(
              [
                'event: run:status\r\ndata: {"type":"RunStatus","data":{"status":"running"}}\r\n\r\n',
                'event: run:status\r\ndata: {"type":"RunStatus","data":{"run_id":"run-1","status":"running"}}\r\n\r\n',
              ].join(""),
            ),
          );
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    }) as typeof fetch;

    try {
      const adapter = new SseAdapter("http://localhost:8081", "browser-secret");
      let unlisten = () => {};
      const payload = await new Promise<{ run_id: string; status: string }>((resolve) => {
        unlisten = adapter.listen<{ run_id: string; status: string }>(
          "run:status",
          (event) => resolve(event.payload),
        );
      });
      unlisten();
      expect(payload).toEqual({ run_id: "run-1", status: "running" });
      expect(requests[0].method).toBe("GET");
      expect(new Headers(requests[0].headers).get("authorization")).toBe(
        "Bearer browser-secret",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("retains the service-owned run id while normalizing progress", async () => {
    const originalFetch = globalThis.fetch;
    const encoder = new TextEncoder();
    globalThis.fetch = (async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode(
              'event: run:progress\ndata: {"type":"RunProgress","data":{"run_id":"run-42","kind":"EdgesCovered","data":17}}\n\n',
            ),
          );
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    }) as typeof fetch;

    try {
      const adapter = new SseAdapter("http://localhost:8081");
      let unlisten = () => {};
      const payload = await new Promise<{
        run_id: string;
        type: string;
        data: unknown;
      }>((resolve) => {
        unlisten = adapter.listen<{
          run_id: string;
          type: string;
          data: unknown;
        }>("run:progress", (event) => resolve(event.payload));
      });
      unlisten();
      expect(payload).toEqual({
        run_id: "run-42",
        type: "EdgesCovered",
        data: 17,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
