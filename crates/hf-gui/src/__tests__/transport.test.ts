import { describe, it, expect } from "vitest";
import { isTauriEnvironment } from "../lib/transport";
import { createHttpTransport } from "../lib/httpTransport";
import type { FuzzerRunResult, RunProgressEvent } from "../lib/transport";

describe("transport", () => {
  it("isTauriEnvironment returns false in test env", () => {
    expect(isTauriEnvironment()).toBe(false);
  });

  it("maps chat_agent to the autonomous agent endpoint with web JSON keys", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify("ok"), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const result = await transport.invoke<string>("chat_agent", {
        message: "hi",
        project: "/tmp/proj",
        sessionId: "session-1",
        agentId: "orchestrator",
        history: [{ role: "user", content: "hello" }],
      });

      expect(result).toBe("ok");
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe("http://localhost:8081/chat/agent");
      expect(JSON.parse(String(calls[0].init.body))).toEqual({
        message: "hi",
        project: "/tmp/proj",
        session_id: "session-1",
        agent_id: "orchestrator",
        history: [{ role: "user", content: "hello" }],
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("sends the configured bearer token in an authorization header", async () => {
    const calls: RequestInit[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      calls.push(init ?? {});
      return new Response(JSON.stringify({ docker: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport({ token: "browser-secret" });
      await transport.invoke("system_status");
      expect(new Headers(calls[0].headers).get("authorization")).toBe(
        "Bearer browser-secret",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fills run-control paths from Tauri-style camelCase arguments", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ active: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("run_status", { runId: "run/id" });
      await transport.invoke("cancel_run_by_id", { runId: "run/id" });
      expect(calls[0].url).toBe("http://localhost:8081/runs/run%2Fid/status");
      expect(calls[0].init.method).toBe("GET");
      expect(calls[1].url).toBe("http://localhost:8081/runs/run%2Fid/cancel");
      expect(calls[1].init.method).toBe("POST");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("bridges run_fuzzer to the durable asynchronous run contract", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const progress: RunProgressEvent[] = [];
    const encoder = new TextEncoder();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const request = { url: String(url), init: init ?? {} };
      calls.push(request);
      const path = new URL(request.url).pathname;
      if (path === "/runs/start") {
        return new Response(
          JSON.stringify({ run_id: "service-run-1", status: "running" }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      if (path === "/events") {
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(
                encoder.encode(
                  [
                    'event: run:progress\ndata: {"type":"RunProgress","data":{"run_id":"other-run","kind":"LogLine","data":"ignore"}}\n\n',
                    'event: run:progress\ndata: {"type":"RunProgress","data":{"run_id":"service-run-1","kind":"LogLine","data":"owned"}}\n\n',
                    'event: run:status\ndata: {"type":"RunStatus","data":{"run_id":"service-run-1","status":"done"}}\n\n',
                  ].join(""),
                ),
              );
              controller.close();
            },
          }),
          { status: 200, headers: { "content-type": "text/event-stream" } },
        );
      }
      if (path === "/runs/service-run-1/status") {
        return new Response(
          JSON.stringify({
            run_id: "service-run-1",
            status: "running",
            active: true,
            started_at: "2026-07-15T00:00:00Z",
            ended_at: null,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (path === "/runs/history") {
        return new Response(
          JSON.stringify([
            {
              id: "other-run",
              status: "Done",
              crashes: 99,
              edges: 999,
              execs: 999,
            },
            {
              id: "service-run-1",
              status: "Done",
              crashes: 2,
              edges: 41,
              execs: 123.5,
            },
          ]),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected request: ${request.url}`);
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const unlisten = await transport.listen<RunProgressEvent>("run:progress", (event) => {
        progress.push(event.payload);
      });
      const result = await transport.invoke<FuzzerRunResult>("run_fuzzer", {
        project: "/tmp/project",
        target: "parse_entry",
        engine: "libfuzzer",
        duration: 60,
      });
      unlisten();

      expect(result).toEqual({
        run_id: "service-run-1",
        edges: 41,
        crashes: 2,
        execs: 123.5,
        exit_code: null,
        termination: "completed",
        stagnation: null,
        auto_revert: null,
      });
      expect(progress).toEqual([
        { run_id: "service-run-1", type: "LogLine", data: "owned" },
      ]);
      const start = calls.find((call) => call.url.endsWith("/runs/start"));
      expect(start?.init.method).toBe("POST");
      expect(JSON.parse(String(start?.init.body))).toEqual({
        project: "/tmp/project",
        target: "parse_entry",
        engine: "libfuzzer",
        duration_secs: 60,
      });
      expect(calls.some((call) => call.url.endsWith("/runs/service-run-1/status"))).toBe(
        true,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("cancels the exact service-owned run id returned by start", async () => {
    const calls: string[] = [];
    const encoder = new TextEncoder();
    const originalFetch = globalThis.fetch;
    let eventController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let eventsReadyResolve: (() => void) | undefined;
    const eventsReady = new Promise<void>((resolve) => {
      eventsReadyResolve = resolve;
    });
    let cancelled = false;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const value = String(url);
      calls.push(value);
      const path = new URL(value).pathname;
      if (path === "/runs/start") {
        return new Response(
          JSON.stringify({ run_id: "server-selected-id", status: "running" }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      if (path === "/events") {
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              eventController = controller;
              eventsReadyResolve?.();
            },
          }),
          { status: 200, headers: { "content-type": "text/event-stream" } },
        );
      }
      if (path === "/runs/server-selected-id/status") {
        return new Response(
          JSON.stringify({
            run_id: "server-selected-id",
            status: cancelled ? "cancelled" : "running",
            active: !cancelled,
            started_at: "2026-07-15T00:00:00Z",
            ended_at: cancelled ? "2026-07-15T00:00:01Z" : null,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (path === "/runs/server-selected-id/cancel") {
        expect(init?.method).toBe("POST");
        cancelled = true;
        eventController?.enqueue(
          encoder.encode(
            'event: run:status\ndata: {"type":"RunStatus","data":{"run_id":"server-selected-id","status":"cancelled"}}\n\n',
          ),
        );
        eventController?.close();
        return new Response(
          JSON.stringify({ run_id: "server-selected-id", accepted: true }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      if (path === "/runs/history") {
        return new Response(
          JSON.stringify([
            {
              id: "server-selected-id",
              status: "Cancelled",
              crashes: 1,
              edges: 12,
              execs: 34,
            },
          ]),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected request: ${value}`);
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const run = transport.invoke<FuzzerRunResult>("run_fuzzer", {
        project: "/tmp/project",
        target: "parse_entry",
        engine: "libfuzzer",
        duration: 60,
      });
      await eventsReady;
      expect(await transport.invoke<number>("cancel_run")).toBe(1);
      expect((await run).termination).toBe("cancelled");
      expect(calls).toContain(
        "http://localhost:8081/runs/server-selected-id/cancel",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects a run start response without a service-owned id", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ status: "running" }), {
        status: 202,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await expect(
        transport.invoke("run_fuzzer", {
          project: "/tmp/project",
          target: "parse_entry",
          engine: "libfuzzer",
          duration: 60,
        }),
      ).rejects.toThrow("service-owned run id");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps config conversion commands to the web API", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("config_toml_to_value", { content: "enabled = true" });
      await transport.invoke("config_value_to_toml", { value: { enabled: true } });

      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/config/toml_to_value",
        "http://localhost:8081/config/value_to_toml",
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps typed policy and integration settings without wrapping patch bodies", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const patch = { verify_tls: false, api_token: { operation: "clear" } };
      await transport.invoke("get_fuzzing_settings");
      await transport.invoke("get_defectdojo_config");
      await transport.invoke("patch_defectdojo_config", { patch });
      await transport.invoke("get_issue_tracker_config");
      await transport.invoke("patch_issue_tracker_config", { patch });

      expect(calls.map((call) => call.url)).toEqual([
        "http://localhost:8081/config/fuzzing",
        "http://localhost:8081/config/defectdojo",
        "http://localhost:8081/config/defectdojo",
        "http://localhost:8081/config/issue-tracker",
        "http://localhost:8081/config/issue-tracker",
      ]);
      expect(calls.map((call) => call.init.method)).toEqual(["GET", "GET", "PATCH", "GET", "PATCH"]);
      expect(JSON.parse(String(calls[2].init.body))).toEqual(patch);
      expect(JSON.parse(String(calls[4].init.body))).toEqual(patch);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps typed automotive commands and top-level Tauri arguments to web routes", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const settings = { enabled: false };
      await transport.invoke("get_automotive_settings");
      await transport.invoke("set_automotive_settings", { settings });
      await transport.invoke("automotive_capabilities", { projectRoot: "/tmp/project" });
      await transport.invoke("automotive_analyze_capture", {
        projectRoot: "/tmp/project",
        protocol: "uds",
        capturePath: "/tmp/capture.pcap",
      });
      await transport.invoke("list_automotive_operations", {
        projectRoot: "/tmp/project",
        limit: 25,
      });
      await transport.invoke("generate_automotive_report", {
        projectRoot: "/tmp/project",
        includeAi: true,
      });

      expect(calls.map((call) => [call.init.method, call.url])).toEqual([
        ["GET", "http://localhost:8081/config/automotive"],
        ["PUT", "http://localhost:8081/config/automotive"],
        ["POST", "http://localhost:8081/automotive/capabilities"],
        ["POST", "http://localhost:8081/automotive/analyze-capture"],
        [
          "GET",
          "http://localhost:8081/automotive/operations?project_root=%2Ftmp%2Fproject&limit=25",
        ],
        ["POST", "http://localhost:8081/automotive/report"],
      ]);
      expect(JSON.parse(String(calls[1].init.body))).toEqual({ settings });
      expect(JSON.parse(String(calls[2].init.body))).toEqual({
        project_root: "/tmp/project",
      });
      expect(JSON.parse(String(calls[3].init.body))).toEqual({
        project_root: "/tmp/project",
        protocol: "uds",
        capture_path: "/tmp/capture.pcap",
      });
      expect(JSON.parse(String(calls[5].init.body))).toEqual({
        project_root: "/tmp/project",
        include_ai: true,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps report draft commands to the web API", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("list_report_drafts");
      await transport.invoke("save_report_draft", { title: "T", project: "/p", status: "Draft", content: "# T" });
      await transport.invoke("delete_report_draft", { id: "report-1" });

      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/reports",
        "http://localhost:8081/reports/save",
        "http://localhost:8081/reports/delete",
      ]);
      expect(calls[0].init.method).toBe("GET");
      expect(calls[0].init.body).toBeUndefined();
      expect(JSON.parse(String(calls[1].init.body))).toEqual({
        title: "T",
        project: "/p",
        status: "Draft",
        content: "# T",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps knowledge_stats to a GET with the project as a query param", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ indexed: false, files: 0, chunks: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("knowledge_stats", { project: "/tmp/proj" });

      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/knowledge/stats?project=%2Ftmp%2Fproj",
      ]);
      expect(calls[0].init.method).toBe("GET");
      expect(calls[0].init.body).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps system status commands to a JSON endpoint in web mode", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ docker: false, sandbox_image: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("ensure_docker", { arch: "linux/arm64" });
      await transport.invoke("system_status");

      // A GET carries its args as a query string (the handler ignores the ones
      // it does not declare); a body would be dropped on the floor.
      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/system/status?arch=linux%2Farm64",
        "http://localhost:8081/system/status",
      ]);
      expect(calls.every((c) => c.init.method === "GET")).toBe(true);
      expect(calls.every((c) => c.init.body === undefined)).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fills path placeholders from args and keeps the rest in the body", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      // Without placeholder support these routes are unreachable in web mode --
      // the id is part of the path, not the body.
      await transport.invoke("schedule_delete", { id: "abc-123" });
      await transport.invoke("schedule_set_enabled", { id: "abc-123", enabled: false });

      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/schedule/abc-123",
        "http://localhost:8081/schedule/abc-123/enabled",
      ]);
      expect(calls[0].init.method).toBe("DELETE");
      expect(calls[1].init.method).toBe("POST");
      expect(JSON.parse(String(calls[1].init.body))).toEqual({ enabled: false });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("sends an empty JSON object for arg-less JSON POST commands", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify(null), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("create_session");
      expect(calls[0].url).toBe("http://localhost:8081/chat/session");
      expect(calls[0].init.method).toBe("POST");
      expect(calls[0].init.body).toBe("{}");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("routes the diagnostics summary to the session-scoped web endpoint", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(
        JSON.stringify({
          calls: 0,
          input_tokens: 0,
          output_tokens: 0,
          cost_usd: 0,
          by_model: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await transport.invoke("diagnostics_cost_summary");
      expect(calls[0].url).toBe("http://localhost:8081/diagnostics/cost");
      expect(calls[0].init.method).toBe("GET");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("loads the independently enforced scheduler concurrency limits", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(
        JSON.stringify({
          active_fuzz_campaign_limit: 4,
          scheduler_workflow_dispatch_limit: 2,
          effective_max_concurrent_fuzz_runs: 2,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      const limits = await transport.invoke("schedule_concurrency_limits");

      expect(limits).toEqual({
        active_fuzz_campaign_limit: 4,
        scheduler_workflow_dispatch_limit: 2,
        effective_max_concurrent_fuzz_runs: 2,
      });
      expect(calls[0].url).toBe("http://localhost:8081/schedule/concurrency/limits");
      expect(calls[0].init.method).toBe("GET");
      expect(calls[0].init.body).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
