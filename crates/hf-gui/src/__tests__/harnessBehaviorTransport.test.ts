import { afterEach, expect, it, vi } from "vitest";
import { createHttpTransport } from "../lib/httpTransport";
import { createTauriTransport } from "../lib/tauriTransport";
const invoke = vi.hoisted(() => vi.fn().mockResolvedValue({}));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));
afterEach(() => { vi.unstubAllGlobals(); invoke.mockClear(); });
it("reads retained behavior through both transports", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response("{}")); vi.stubGlobal("fetch", fetch);
  await createHttpTransport().invoke("run_harness_behavior", { runId: "run-a" });
  expect(new URL(fetch.mock.calls[0][0]).pathname).toBe("/runs/run-a/harness-behavior"); expect(fetch.mock.calls[0][1].method).toBe("GET");
  await createTauriTransport().invoke("run_harness_behavior", { runId: "run-a" });
  expect(invoke).toHaveBeenCalledWith("run_harness_behavior", { runId: "run-a" });
});
