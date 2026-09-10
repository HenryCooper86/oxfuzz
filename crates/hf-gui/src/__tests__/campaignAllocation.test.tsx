// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { CampaignAllocation } from "../components/CampaignAllocation";
import { createHttpTransport } from "../lib/httpTransport";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => ({ invoke }) }));
let cleanup = async () => {};
afterEach(async () => { await cleanup(); vi.restoreAllMocks(); });
const candidate = { target: "parser.c::parse", dispatch_target: "parse", engine: "libfuzzer", language: "c", target_id: "target", harness_id: "harness", source_sha256: "a".repeat(64) };
const plan = { proposal: { id: "plan", project: "/project", max_runs: 10, max_total_secs: 600, per_run_secs: 60, unallocated_secs: 0, entries: [{ candidate, weight: 1, max_runs: 10, reason: "Two comparable retained runs are unavailable; equal service", evidence: [] }] }, digest: "b".repeat(64), status: "draft", reservations: [] };
it("requires review of the exact persisted proposal and shows reserved consumption", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  invoke.mockImplementation(async (command: string, args: Record<string, unknown>) => {
    if (command === "allocation_candidates") return [candidate];
    if (command === "allocation_status") return null;
    if (command === "allocation_propose") { expect(args.request).toEqual({ project: "/project", harness_ids: ["harness"], max_runs: 10, max_total_secs: 600 }); return plan; }
    if (command === "allocation_review") { expect(args).toEqual({ project: "/project", id: "plan", digest: plan.digest, approve: true }); return { ...plan, status: "approved", reservations: [{ candidate, duration_secs: 60 }] }; }
    throw new Error(command);
  });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); };
  await act(async () => root.render(<I18nProvider><CampaignAllocation project="/project" /></I18nProvider>));
  const click = async (text: string) => {
    const button = [...host.querySelectorAll("button")].find(item => item.textContent === text);
    expect(button, host.textContent ?? "").toBeTruthy(); await act(async () => button!.click());
  };
  await act(async () => (host.querySelector('input[type="checkbox"]') as HTMLInputElement).click());
  await click("Prepare allocation");
  expect(host.textContent).toContain("equal service");
  expect(host.textContent).toContain(plan.digest);
  expect(host.textContent).toContain(candidate.source_sha256);
  expect(invoke.mock.calls.filter(([command]) => command === "allocation_review")).toHaveLength(0);
  await click("Approve this allocation");
  expect(host.textContent).toContain("Approved");
  expect(host.textContent).toContain("1 / 10");
});
it("maps allocation requests to HTTP without changing review authority", async () => {
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("null", { headers: { "content-type": "application/json" } }));
  const transport = createHttpTransport();
  for (const command of ["allocation_candidates", "allocation_status", "allocation_propose", "allocation_review"]) {
    fetch.mockResolvedValueOnce(new Response("null", { headers: { "content-type": "application/json" } }));
    await transport.invoke(command, command === "allocation_propose" ? { request: { project: "/p", harness_ids: ["h"], max_runs: 1, max_total_secs: 10 } } : { project: "/p", ...(command === "allocation_review" ? { id: "plan", digest: "exact", approve: true } : {}) });
  }
  expect(fetch.mock.calls.map(call => String(call[0]))).toEqual(["candidates", "status", "propose", "review"].map(action => `http://localhost:8081/campaign/allocation/${action}`));
  expect(JSON.parse(String(fetch.mock.calls[2][1]?.body))).toEqual({ project: "/p", harness_ids: ["h"], max_runs: 1, max_total_secs: 10 });
  expect(JSON.parse(String(fetch.mock.calls[3][1]?.body))).toEqual({ project: "/p", id: "plan", digest: "exact", approve: true });
});
