// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { RunCloseoutPanel } from "../components/RunCloseoutPanel";
import { I18nProvider } from "../i18n";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }) }));

it("shows the six closeout steps and a plain-language trust verdict", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  invoke.mockResolvedValue({
    schema_version: 3, run_id: "run-1", availability: { status: "available" }, resumed_at: null,
    steps: [
      { step: "triage", outcome: { outcome: "completed", detail: "0 crash(es) attributed" } },
      { step: "minimize", outcome: { outcome: "skipped", reason: "nothing to minimize" } },
      { step: "corpus_absorb", outcome: { outcome: "completed", detail: "3 input(s) absorbed" } },
      { step: "edge_set", outcome: { outcome: "completed", detail: "edge set retained: 40 edges" } },
      { step: "disposition", outcome: { outcome: "completed", detail: "0 crash(es) dispositioned" } },
      { step: "trust_report", outcome: { outcome: "completed", detail: "Unqualified" } },
    ],
  });
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  try {
    await act(async () => root.render(<I18nProvider><RunCloseoutPanel runId="run-1" runKind="Campaign" runStatus="Done" /></I18nProvider>));
    await act(async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); });
    expect(host.querySelectorAll("li")).toHaveLength(6);
    expect(host.textContent).not.toMatch(/\bBlockers\b/);
    expect(host.textContent).not.toContain("Pending");
    expect(host.textContent).toContain("Not everything could be measured");
    expect(host.textContent).not.toContain("Unqualified");
  } finally { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
