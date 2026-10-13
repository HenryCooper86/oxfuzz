// @vitest-environment jsdom

import { StrictMode, act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectProvider } from "../providers/ProjectContext";
import { useProject } from "../providers/project";
import { PipelineProvider } from "../providers/PipelineContext";
import { usePipeline } from "../providers/pipeline";
import { FindingSelectionProvider } from "../providers/FindingSelectionContext";
import { useFindingSelection } from "../providers/findingSelection";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib", () => ({ getTransport: () => ({ invoke }), emitDataChanged: vi.fn() }));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function Probe() {
  const project = useProject();
  const pipeline = usePipeline();
  const finding = useFindingSelection();
  return <>
    <output>{JSON.stringify({ active: project.activeProject, recents: project.recentProjects, completed: pipeline.completed, finding: finding.selection })}</output>
    {["/a", "/b", "/c"].map(path => <div key={path}>
      <button onClick={() => project.setActiveProject(path)}>open {path}</button>
      <button onClick={() => project.removeRecent(path)}>remove {path}</button>
      <button onClick={() => void project.deleteProjectData(path).catch(() => {
        // The probe observes retained state after a rejected backend deletion.
      })}>delete {path}</button>
    </div>)}
    <button onClick={() => pipeline.markDone("discover")}>complete discover</button>
    <button onClick={() => finding.selectFinding(`finding:${project.activeProject}`, `run:${project.activeProject}`)}>select finding</button>
  </>;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(accept => { resolve = accept; });
  return { promise, resolve };
}

let container: HTMLDivElement;
let root: Root;

beforeEach(async () => {
  localStorage.clear();
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(<StrictMode>
    <ProjectProvider><PipelineProvider><FindingSelectionProvider><Probe /></FindingSelectionProvider></PipelineProvider></ProjectProvider>
  </StrictMode>));
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  localStorage.clear();
});

async function click(label: string) {
  const button = [...container.querySelectorAll("button")].find(item => item.textContent === label);
  if (!button) throw new Error(`Missing action: ${label}`);
  await act(async () => button.click());
}

function state() {
  return JSON.parse(container.querySelector("output")!.textContent!);
}

describe("project deletion lifecycle", () => {
  it("preserves the project opened while another project's deletion is pending", async () => {
    const deletion = deferred();
    invoke.mockReturnValue(deletion.promise);
    await click("open /a");
    await click("delete /a");
    await click("open /b");
    await act(async () => deletion.resolve());

    expect(state().active).toBe("/b");
    expect(state().recents).toEqual(["/b"]);
    expect(localStorage.getItem("hf_active_project")).toBe("/b");
    expect(JSON.parse(localStorage.getItem("hf_recent_projects")!)).toEqual(["/b"]);
  });

  it("does not restore a project when overlapping deletions finish in reverse order", async () => {
    const first = deferred();
    const second = deferred();
    invoke.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    await click("open /a");
    await click("open /b");
    await click("open /c");
    await click("delete /a");
    await click("delete /b");
    await act(async () => second.resolve());
    await act(async () => first.resolve());

    expect(state().active).toBe("/c");
    expect(state().recents).toEqual(["/c"]);
    expect(JSON.parse(localStorage.getItem("hf_recent_projects")!)).toEqual(["/c"]);
  });

  it("persists a new selection made in the deletion completion batch", async () => {
    const deletion = deferred();
    invoke.mockReturnValue(deletion.promise);
    await click("open /a");
    await click("delete /a");
    await act(async () => {
      deletion.resolve();
      await Promise.resolve();
      [...container.querySelectorAll("button")].find(item => item.textContent === "open /b")!.click();
    });

    expect(state().active).toBe("/b");
    expect(localStorage.getItem("hf_active_project")).toBe("/b");
  });

  it("retains project selection when backend deletion fails", async () => {
    invoke.mockRejectedValue(new Error("project busy"));
    await click("open /a");
    await click("delete /a");

    expect(state().active).toBe("/a");
    expect(state().recents).toEqual(["/a"]);
  });
});

describe("removed project presentation state", () => {
  it("forgets completed stages when a removed project is reopened", async () => {
    await click("open /a");
    await click("complete discover");
    await click("open /b");
    await click("complete discover");
    await click("remove /a");
    expect(state().completed).toEqual(["discover"]);
    await click("open /a");

    expect(state().completed).toEqual([]);
    expect(JSON.parse(localStorage.getItem("hf_pipeline_progress_v1")!)["/a"]).toBeUndefined();
    await click("open /b");
    expect(state().completed).toEqual(["discover"]);
  });

  it("forgets the selected finding when a deleted project is reopened", async () => {
    await click("open /a");
    await click("select finding");
    await click("open /b");
    await click("select finding");
    await click("delete /a");
    expect(state().finding).toEqual({ findingId: "finding:/b", runId: "run:/b" });
    await click("open /a");

    expect(state().finding).toBeNull();
    expect(JSON.parse(localStorage.getItem("hf_finding_selection_v1")!)["/a"]).toBeUndefined();
    await click("open /b");
    expect(state().finding).toEqual({ findingId: "finding:/b", runId: "run:/b" });
  });
});
