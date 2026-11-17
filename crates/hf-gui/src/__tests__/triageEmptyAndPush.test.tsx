// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { ToastProvider } from "../components/ui/Toast";
import { TriageView } from "../views/TriageView";
import type * as LibModule from "../lib";

// Found walking the app on 2026-11-17: a finished run said "1 retained crash
// artifact, Review findings", and Triage then showed "No findings match the
// current filters" because crashes become findings only after a scan. The same
// screen offered "Push to DefectDojo" with no DefectDojo configured.
const mocks = vi.hoisted(() => ({
  runs: [] as unknown[],
  queue: [] as unknown[],
  defectDojo: false,
  invoke: vi.fn(),
}));
vi.mock("../lib", async (importOriginal) => ({
  ...(await importOriginal<typeof LibModule>()),
  getTransport: () => ({ invoke: mocks.invoke, listen: async () => () => {} }),
  isTauriEnvironment: () => false,
}));
vi.mock("../providers/project", () => ({ useProject: () => ({ activeProject: "/proj", recentProjects: ["/proj"] }) }));
vi.mock("../providers/target", () => ({ useTarget: () => ({ target: "decode_utf8", lang: "c", engine: "libfuzzer" }) }));

const FINDING = {
  crash: { id: "c-1", run_id: "r-1", target_id: "t-1", kind: "Asan", summary: "heap-buffer-overflow", stack_signature: "sig", input_path: "/w/crash-1", origin: "target" },
  target_symbol: "decode_utf8", target_selector: "utf8.c::decode_utf8", latest_for_target: true,
};

let host: HTMLDivElement; let root: Root;
const flush = async () => act(async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); });
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  mocks.runs = []; mocks.queue = []; mocks.defectDojo = false;
  mocks.invoke.mockReset();
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "run_history") return mocks.runs;
    if (command === "finding_review_queue" || command === "findings_review") return mocks.queue;
    if (command === "defectdojo_configured") return mocks.defectDojo;
    if (command === "scan_crashes") return [];
    return null;
  });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });
const mount = async () => {
  await act(async () => root.render(<I18nProvider><ToastProvider><TriageView /></ToastProvider></I18nProvider>));
  await flush();
};

it("points at the scan when runs retained crashes that are not findings yet", async () => {
  mocks.runs = [{ id: "r-1", crashes: 2 }, { id: "r-2", crashes: 1 }, { id: "r-3", crashes: 0 }];
  await mount();
  expect(host.textContent).toContain("3 retained crash artifacts have not been scanned yet");
  expect(host.textContent).not.toContain("No findings match the current filters");
});

it("keeps the filter hint when no run retained a crash", async () => {
  mocks.runs = [{ id: "r-1", crashes: 0 }];
  await mount();
  expect(host.textContent).toContain("No findings match the current filters");
});

it("says nothing about unscanned crashes once findings exist but are all resolved", async () => {
  mocks.runs = [{ id: "r-1", crashes: 1 }];
  mocks.invoke.mockImplementation(async (command: string, args?: { filter?: { disposition?: { mode?: string } } }) => {
    if (command === "run_history") return mocks.runs;
    if (command === "finding_review_queue") return args?.filter?.disposition?.mode === "all" ? [FINDING] : [];
    if (command === "defectdojo_configured") return false;
    return null;
  });
  await mount();
  expect(host.textContent).not.toContain("have not been scanned yet");
  expect(host.textContent).toContain("No findings match the current filters");
});

it("offers the DefectDojo push only where DefectDojo is configured", () => {
  // Reports already hides its push without a configured instance; Triage
  // showed the button on every finding and failed on click.
  const triage = readFileSync("src/views/TriageView.tsx", "utf8");
  expect(triage).toContain('invoke<boolean>("defectdojo_configured")');
  expect(triage).toContain("{activeFinding && defectDojoConfigured && <Button");
});
