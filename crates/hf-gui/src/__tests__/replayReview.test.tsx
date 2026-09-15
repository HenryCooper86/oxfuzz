// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { ReplayRun } from "../components/ReplayRun";
import { I18nProvider } from "../i18n";
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), replayRun: vi.fn(), cancelRun: vi.fn() }));
vi.mock("../lib", () => ({ getTransport: () => ({ invoke: mocks.invoke }), emitDataChanged: vi.fn() }));
vi.mock("../providers/runOutput", () => ({ useRunOutput: () => ({ replayRun: mocks.replayRun, running: false, cancelRun: mocks.cancelRun }) }));
it.each(["retained", "current"] as const)("requires an explicit %s review and launch, preserving all seed bits", async (inputs) => {
  vi.clearAllMocks();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const review = {run_id: "original", project: "/fixture", target: "src/parser.c::parse", engine: "LibFuzzer", seed: "18446744073709551615", duration_secs: 60, max_mem_mb: "512", max_cpus: 1, input_manifest_sha256: inputs === "retained" ? "abcdef0123456789" : null, inputs};
  mocks.invoke.mockResolvedValue(review); mocks.replayRun.mockRejectedValue(new Error("Review settings changed"));
  const host = document.createElement("div"); document.body.append(host); const root = createRoot(host);
  const reviewLabel = inputs === "retained" ? "Review replay" : "Review current-input rerun";
  const startLabel = inputs === "retained" ? "Start reviewed replay" : "Start reviewed rerun";
  const button = (name: string) => [...host.querySelectorAll("button")].find(b=>b.textContent === name)!;
  try {
    await act(async () => root.render(<I18nProvider><ReplayRun runId="original" inputs={inputs} /></I18nProvider>));
    expect(mocks.invoke).not.toHaveBeenCalled(); expect(mocks.replayRun).not.toHaveBeenCalled();
    await act(async () => button(reviewLabel).click());
    expect(host.textContent).toContain(review.seed); expect(host.textContent).toContain(review.target);
    expect(mocks.invoke).toHaveBeenCalledWith("replay_review", { runId: "original", inputs });
    if (inputs === "retained") expect(host.textContent).toContain(review.input_manifest_sha256);
    expect(host.textContent).toContain(inputs === "retained" ? "retained inputs" : "current promoted harness");
    expect(mocks.replayRun).not.toHaveBeenCalled();
    await act(async () => button(startLabel).click());
    expect(mocks.replayRun).toHaveBeenCalledWith(review);
    expect(host.textContent).toContain("Review settings changed");
    expect(button(startLabel)).toBeUndefined();
  } finally { await act(async()=>root.unmount()); host.remove(); vi.unstubAllGlobals(); }
});
