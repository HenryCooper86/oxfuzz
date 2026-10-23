import { afterEach, expect, it, vi } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
import { createTauriTransport } from "../lib/tauriTransport";
const invoke = vi.hoisted(() => vi.fn().mockResolvedValue({}));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));
afterEach(() => { vi.unstubAllGlobals(); invoke.mockClear(); });
it("reads the same budget service through HTTP and native transports", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response("{}"));
  vi.stubGlobal("fetch", fetch);
  await createHttpTransport().invoke("model_budget_view");
  expect(new URL(fetch.mock.calls[0][0]).pathname).toBe("/model-budget");
  expect(fetch.mock.calls[0][1].method).toBe("GET");
  await createTauriTransport().invoke("model_budget_view");
  expect(invoke).toHaveBeenCalledWith("model_budget_view", undefined);
});
