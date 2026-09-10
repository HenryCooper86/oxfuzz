import { afterEach, expect, it, vi } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
afterEach(() => vi.unstubAllGlobals());
it("uses an authorized read-only readiness request and an explicit provider probe request", async () => {
  const provider = { id: "fixture", model: "fixture-model", api_key: "fixture-key" };
  const fetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ runtime_ready: false })));
  vi.stubGlobal("fetch", fetch);
  const transport = createHttpTransport({ token: "fixture-token" });
  await transport.invoke("setup_readiness");
  await transport.invoke("provider_test", { provider });
  await transport.invoke("setup_providers");
  await transport.invoke("initialize_provider", { provider });
  expect(fetch.mock.calls.map(([url, init]) => [new URL(url).pathname, init.method])).toEqual([["/system/setup", "GET"], ["/config/providers/test", "POST"], ["/system/setup/providers", "GET"], ["/system/setup/providers", "POST"]]);
  expect(fetch.mock.calls[0][1].body).toBeUndefined();
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ provider });
  for (const [, init] of fetch.mock.calls) expect(new Headers(init.headers).get("authorization")).toBe("Bearer fixture-token");
});
