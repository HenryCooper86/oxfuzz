// @vitest-environment jsdom
import { act, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ProjectProvider } from "../providers/ProjectContext";
import { PipelineProvider } from "../providers/PipelineContext";
import { usePipeline, type PipelineContextValue } from "../providers/pipeline";
import { useProject } from "../providers/project";

// Approval is the gate of the harness stage. One-click preparation and
// "Approve with Known Findings" reach it without the optional seed step and
// without a crash-free smoke pass, and the Workflow kept saying
// "Next: Generate Harness" for a harness that was already approved and fuzzed.
let pipeline: PipelineContextValue;
function Probe() {
  const value = usePipeline();
  useEffect(() => { pipeline = value; });
  const { setActiveProject } = useProject();
  return <button onClick={() => setActiveProject("/proj")}>open</button>;
}

let host: HTMLDivElement; let root: Root;
beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  localStorage.clear();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => root.render(<ProjectProvider><PipelineProvider><Probe /></PipelineProvider></ProjectProvider>));
  await act(async () => host.querySelector("button")!.click());
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

const harnessStage = () => pipeline.coreStages.find(stage => stage.id === "harness")!;

it("completes the harness stage when the harness is approved", async () => {
  await act(async () => pipeline.markDone("discover"));
  await act(async () => pipeline.markDone("compile"));
  expect(harnessStage().done).toBe(false);
  await act(async () => pipeline.markDone("approve"));
  expect(harnessStage().done).toBe(true);
  expect(pipeline.coreStages.find(stage => stage.current)?.id).toBe("run");
  // The seed step was never run, so it is recorded as skipped, not as done.
  expect(pipeline.isSkipped("seeds")).toBe(true);
  expect(pipeline.isSkipped("compile")).toBe(false);
  expect(pipeline.isSkipped("smoke")).toBe(false);
});

it("keeps a seed step that was run as done when approval follows", async () => {
  await act(async () => pipeline.markDone("seeds"));
  await act(async () => pipeline.markDone("approve"));
  expect(pipeline.isDone("seeds")).toBe(true);
  expect(pipeline.isSkipped("seeds")).toBe(false);
});
