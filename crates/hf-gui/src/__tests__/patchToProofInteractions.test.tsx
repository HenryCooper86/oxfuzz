// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { PatchToProofPanel } from "../components/PatchToProofPanel";
import { I18nProvider } from "../i18n";
import { createHttpTransport } from "../lib/httpTransport";
import type { Transport } from "../lib/transport";
import type { RemediationOperationView, VerificationStageEvidence } from "../types";

const mocks = vi.hoisted(() => ({ transport: null as Transport | null }));
vi.mock("../lib", async () => ({ ...await vi.importActual("../lib"), getTransport: () => mocks.transport }));
const finding = "10000000-0000-4000-8000-000000000001";
const run = "20000000-0000-4000-8000-000000000002";
const operation = "30000000-0000-4000-8000-000000000003";
const digest = "a".repeat(64);
let cleanup = async () => {};
afterEach(async () => { await cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it("reviews exact HTTP operation, separately approves and starts, polls retained status and clears on keyed finding navigation", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.useFakeTimers();
  localStorage.clear();
  localStorage.setItem("hf_locale", "en");
  const patch = "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-return data[1];\n+return size > 1 ? data[1] : 0;\n";
  let view: RemediationOperationView = {
    operation_id: operation, run_id: run, finding_id: finding, status: "draft", current_stage: "review",
    binding: { finding_id: finding, run_id: run, source_revision_sha256: digest, patch_sha256: digest, patch,
      reproducer_sha256: digest, harness_sha256: digest, original_binary_sha256: digest, sandbox_image_sha256: digest,
      evidence_manifest_sha256: digest, regression_corpus_sha256: digest, verification_spec_sha256: digest,
      verification_spec: { schema_version: 1, engine: "libfuzzer", replay_timeout_secs: 30, max_regression_cases: 10,
        follow_up_fuzz_seconds: 300, max_mem_mb: 512, max_cpus: 1, seed: 7 } },
    verification: null, failure_code: null, failure_message: null,
  };
  const requests: { path: string; method: string; body: Record<string, unknown> | null }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input, init: RequestInit = {}) => {
    const path = new URL(String(input)).pathname;
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : null;
    requests.push({ path, method, body });
    let response: unknown = view;
    if (path === "/remediation/operations") response = { operation_id: operation, status: "draft" };
    else if (path.endsWith("/approve")) { view = { ...view, status: "approved" }; response = view; }
    else if (path.endsWith("/verify")) { view = { ...view, status: "running", current_stage: "original_replay" }; response = view; }
    else expect(path).toBe(`/remediation/operations/${operation}`);
    return new Response(JSON.stringify(response));
  }));
  mocks.transport = createHttpTransport();
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  cleanup = async () => { await act(async () => root.unmount()); host.remove(); };
  const render = (id: string, runId: string) => root.render(<I18nProvider><PatchToProofPanel key={id} findingId={id} runId={runId} /></I18nProvider>);
  const button = (label: string) => {
    const result = [...host.querySelectorAll("button")].find(item => item.textContent === label);
    expect(result, host.textContent ?? "").toBeTruthy();
    return result!;
  };
  const starts = () => requests.filter(item => item.path.endsWith("/verify"));
  await act(async () => render(finding, run));
  expect(requests).toEqual([]);
  const editor = host.querySelector("textarea")!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(editor, patch);
    editor.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => button("Create draft").click());
  expect(requests[0]).toEqual({ path: "/remediation/operations", method: "POST", body: {
    run_id: run, finding_id: finding, patch, follow_up_fuzz_seconds: 300, compute_usd_per_hour: 0, model_cost_usd: 0,
  } });
  expect(host.querySelector(`[title="${digest}"]`)).toBeTruthy();
  expect(starts()).toHaveLength(0);
  await act(async () => button("Approve this exact scope").click());
  expect(requests.find(item => item.path.endsWith("/approve"))).toEqual({ path: `/remediation/operations/${operation}/approve`, method: "POST", body: { operator: "desktop-operator" } });
  expect(starts()).toHaveLength(0);
  expect(button("Run sandbox verification").disabled).toBe(true);
  await act(async () => button("Run sandbox verification").click());
  expect(starts()).toHaveLength(0);
  await act(async () => host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
  expect(starts()).toHaveLength(0);
  await act(async () => button("Run sandbox verification").click());
  expect(starts()).toEqual([{ path: `/remediation/operations/${operation}/verify`, method: "POST", body: {} }]);
  const passed: VerificationStageEvidence = { status: "passed", detail_code: "fixture_pass", cases: 1, failures: 0, findings: 0 };
  view = { ...view, status: "inconclusive", current_stage: "complete", verification: {
    verification_id: "40000000-0000-4000-8000-000000000004", source_revision_sha256: digest, patch_sha256: digest,
    reproducer_sha256: digest, harness_sha256: digest, original_binary_sha256: digest, patched_binary_sha256: digest,
    sandbox_image_sha256: digest, regression_corpus_sha256: digest, verification_spec_sha256: digest,
    original_replay: passed, patch_build: passed, patched_replay: passed, regression: passed,
    follow_up_fuzz: { ...passed, status: "inconclusive", detail_code: "deadline" },
  } };
  await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
  expect(host.textContent).toContain("Inconclusive");
  expect(host.textContent).not.toContain("Verified");
  const terminalReads = requests.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
  expect(requests).toHaveLength(terminalReads);
  await act(async () => render("50000000-0000-4000-8000-000000000005", "60000000-0000-4000-8000-000000000006"));
  expect(host.querySelector("textarea")!.value).toBe("");
  expect(host.querySelector('input[type="checkbox"]')).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
  expect(requests).toHaveLength(terminalReads);
  expect(starts()).toHaveLength(1);
});
