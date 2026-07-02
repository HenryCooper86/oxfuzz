import { describe, it, expect } from "vitest";
import { isTauriEnvironment } from "../lib/transport";
import { createHttpTransport } from "../lib/httpTransport";

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

      expect(calls.map((c) => c.url)).toEqual([
        "http://localhost:8081/system/status",
        "http://localhost:8081/system/status",
      ]);
      expect(calls.every((c) => c.init.method === "GET")).toBe(true);
      expect(calls.every((c) => c.init.body === undefined)).toBe(true);
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
});
