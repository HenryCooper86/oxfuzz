import { describe, expect, it, vi } from "vitest";
import { SseAdapter } from "../lib/sseAdapter";

describe("SseAdapter", () => {
  it("isolates failing subscribers and keeps later frames on the same connection", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const encoder = new TextEncoder();
    const fetchMock = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("event: run:status\ndata: null\n\n"));
        for (const status of ["running", "done"]) {
          controller.enqueue(encoder.encode(`event: run:status\ndata: {"data":{"run_id":"run-1","status":"${status}"}}\n\n`));
        }
      },
    })));
    vi.stubGlobal("fetch", fetchMock);
    const adapter = new SseAdapter("http://localhost:8081");
    const failing = vi.fn(() => { throw new Error("subscriber failed"); });
    const healthy = vi.fn();
    const unlisten = [
      adapter.listen("stream:connected", failing),
      adapter.listen("run:status", failing),
      adapter.listen("run:status", healthy),
    ];
    try {
      await vi.waitFor(() => expect(healthy).toHaveBeenCalledTimes(2));
      expect(healthy.mock.calls.map(([event]) => event.payload.status)).toEqual(["running", "done"]);
      expect(failing).toHaveBeenCalledTimes(3);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      unlisten.forEach(stop => stop());
      vi.unstubAllGlobals();
      warn.mockRestore();
    }
  });

  it("announces a successful connection before streamed delivery", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(new ReadableStream<Uint8Array>(), { status: 200 })) as typeof fetch;
    try {
      const adapter = new SseAdapter("http://localhost:8081");
      let unlisten = () => {};
      await new Promise<void>((resolve) => {
        unlisten = adapter.listen("stream:connected", () => resolve());
      });
      unlisten();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

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

  it("delivers owner-attributed campaign health without rewriting ids", async () => {
    const originalFetch = globalThis.fetch;
    const encoder = new TextEncoder();
    globalThis.fetch = (async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                'event: campaign:health\ndata: {"type":"CampaignHealth","data":{"owner":{"run_id":"run-7","project_root":"/p"},"event":{"id":"event-9","run_id":"run-7","condition":"run_failed"}}}\n\n',
              ),
            );
            controller.close();
          },
        }),
        { status: 200 },
      )) as typeof fetch;
    try {
      const adapter = new SseAdapter("http://localhost:8081");
      let unlisten = () => {};
      const payload = await new Promise<Record<string, unknown>>((resolve) => {
        unlisten = adapter.listen<Record<string, unknown>>(
          "campaign:health",
          (event) => resolve(event.payload),
        );
      });
      unlisten();
      expect(payload).toMatchObject({
        owner: { run_id: "run-7", project_root: "/p" },
        event: { id: "event-9", run_id: "run-7", condition: "run_failed" },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
