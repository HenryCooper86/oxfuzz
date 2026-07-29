import { describe, expect, it } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
import type { SemgrepCancelOutcome } from "../types";

describe("Semgrep transport", () => {
  it("maps availability and lifecycle commands to exact REST endpoints", async () => {
    const operationId = "9f4667be-d739-4f92-aefe-7b43a0790ec1";
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const call = { url: String(url), init: init ?? {} };
      calls.push(call);
      const path = new URL(call.url).pathname;
      if (path === "/semgrep/available") {
        return Response.json(true);
      }
      if (path === "/semgrep/enrich") {
        return Response.json(
          { operation_id: operationId, state: "staging" },
          { status: 202 },
        );
      }
      if (path.endsWith("/cancel")) {
        return Response.json("accepted", { status: 202 });
      }
      return Response.json({
        operation_id: operationId,
        project_root: "/tmp/project",
        language: "c",
        state: "scanning",
        active: true,
        started_at: "2026-07-29T00:00:00Z",
        ended_at: null,
        failure_code: null,
        failure_message: null,
        result: null,
      });
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await expect(transport.invoke<boolean>("semgrep_available")).resolves.toBe(
        true,
      );
      await expect(
        transport.invoke<string>("semgrep_enrich", {
          project: "/tmp/project",
          lang: "c",
        }),
      ).resolves.toBe(operationId);
      await transport.invoke("semgrep_status", { operationId });
      await transport.invoke("semgrep_cancel", { operationId });

      expect(calls.map((call) => [call.init.method, call.url])).toEqual([
        ["GET", "http://localhost:8081/semgrep/available"],
        ["POST", "http://localhost:8081/semgrep/enrich"],
        ["GET", `http://localhost:8081/semgrep/enrich/${operationId}`],
        [
          "POST",
          `http://localhost:8081/semgrep/enrich/${operationId}/cancel`,
        ],
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it.each([
    [202, "accepted"],
    [409, "inactive"],
    [404, "not_found"],
  ] as const)("normalizes cancel status %s to %s", async (status, expected) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      Response.json(
        status === 202 ? "accepted" : { error: "bounded server detail" },
        { status },
      )) as typeof fetch;

    try {
      const outcome = await createHttpTransport().invoke<SemgrepCancelOutcome>(
        "semgrep_cancel",
        { operationId: "9f4667be-d739-4f92-aefe-7b43a0790ec1" },
      );
      expect(outcome).toBe(expected);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("forwards an abort signal to an in-flight HTTP status request", async () => {
    const originalFetch = globalThis.fetch;
    let receivedSignal: AbortSignal | null = null;
    globalThis.fetch = ((_url: RequestInfo | URL, init?: RequestInit) => {
      receivedSignal = init?.signal as AbortSignal;
      return new Promise<Response>((_resolve, reject) => {
        receivedSignal?.addEventListener(
          "abort",
          () => reject(new DOMException("stopped", "AbortError")),
          { once: true },
        );
      });
    }) as typeof fetch;

    try {
      const controller = new AbortController();
      const pending = createHttpTransport().invoke(
        "semgrep_status",
        { operationId: "9f4667be-d739-4f92-aefe-7b43a0790ec1" },
        { signal: controller.signal },
      );
      controller.abort();

      await expect(pending).rejects.toMatchObject({ name: "AbortError" });
      expect(receivedSignal).toBe(controller.signal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
