import { describe, expect, it } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";

describe("Semgrep transport", () => {
  it("maps the typed commands to the exact REST methods and paths", async () => {
    const operationId = "9f4667be-d739-4f92-aefe-7b43a0790ec1";
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const call = { url: String(url), init: init ?? {} };
      calls.push(call);
      const path = new URL(call.url).pathname;
      if (path === "/semgrep/enrich") {
        return new Response(
          JSON.stringify({ operation_id: operationId, state: "staging" }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      if (path.endsWith("/cancel")) {
        return new Response(JSON.stringify("accepted"), {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(
        JSON.stringify({
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
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    try {
      const transport = createHttpTransport();
      await expect(
        transport.invoke<string>("semgrep_enrich", {
          project: "/tmp/project",
          lang: "c",
        }),
      ).resolves.toBe(operationId);
      await transport.invoke("semgrep_status", { operationId });
      await transport.invoke("semgrep_cancel", { operationId });

      expect(calls.map((call) => [call.init.method, call.url])).toEqual([
        ["POST", "http://localhost:8081/semgrep/enrich"],
        [
          "GET",
          `http://localhost:8081/semgrep/enrich/${operationId}`,
        ],
        [
          "POST",
          `http://localhost:8081/semgrep/enrich/${operationId}/cancel`,
        ],
      ]);
      expect(JSON.parse(String(calls[0].init.body))).toEqual({
        project: "/tmp/project",
        lang: "c",
      });
      expect(calls[1].init.body).toBeUndefined();
      expect(JSON.parse(String(calls[2].init.body))).toEqual({});
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
