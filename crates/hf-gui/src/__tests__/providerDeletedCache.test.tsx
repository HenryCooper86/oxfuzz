// @vitest-environment jsdom

import { StrictMode, act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectProvider } from "../providers/ProjectContext";
import { useProject } from "../providers/project";
import { DiscoveryProvider } from "../providers/DiscoveryContext";
import { useDiscoveryInventory } from "../providers/discovery";
import { RunOutputProvider } from "../providers/RunOutputContext";
import { useRunOutput } from "../providers/runOutput";
import type { RunOwner } from "../lib/transport";

const invoke = vi.hoisted(() => vi.fn());
const listeners = new Map<string, Set<(event: { payload: unknown }) => void>>();
vi.mock("../lib", () => ({
  getTransport: () => ({
    invoke,
    listen: async (event: string, handler: (event: { payload: unknown }) => void) => {
      const handlers = listeners.get(event) ?? new Set();
      handlers.add(handler);
      listeners.set(event, handlers);
      return () => { handlers.delete(handler); };
    },
  }),
  emitDataChanged: vi.fn(),
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const owners = new Map<string, RunOwner>();
const histories = new Map<string, Array<{ id: string; status: string; crashes: number; edges: number; execs: number }>>();
let discoveryResult: Promise<void>;

function Probe() {
  const project = useProject();
  const discovery = useDiscoveryInventory(project.activeProject, "c");
  const run = useRunOutput();
  const snapshot = { inventory: { project_root: project.activeProject, candidates: [] }, semgrep: null };
  return <>
    <output>{JSON.stringify({ active: project.activeProject, discovery: discovery.snapshot?.inventory.project_root ?? null, run: run.selectedRun?.run_id ?? null, summary: run.summary })}</output>
    {["/a", "/b"].map(path => <div key={path}>
      <button onClick={() => project.setActiveProject(path)}>open {path}</button>
      <button onClick={() => project.removeRecent(path)}>remove {path}</button>
      <button onClick={() => void project.deleteProjectData(path)}>delete {path}</button>
    </div>)}
    <button onClick={() => discovery.save(snapshot)}>save discovery</button>
    <button onClick={() => void discoveryResult.then(() => discovery.save(snapshot))}>start discovery</button>
  </>;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}

function addRun(id: string, project: string) {
  const owner: RunOwner = { run_id: id, project_root: project, target: "parse.c::parse", engine: "libfuzzer", kind: "standard", status: "done", started_at: "2026-10-13T00:00:00Z" };
  owners.set(id, owner);
  histories.set(project, [{ id, status: "Done", crashes: 1, edges: 5, execs: 30 }]);
  return owner;
}

async function backend(command: string, args?: Record<string, unknown>) {
  if (command === "run_history") return histories.get(String(args?.project)) ?? [];
  if (command === "run_owner") {
    const owner = owners.get(String(args?.runId));
    if (!owner) throw new Error("run no longer exists");
    return owner;
  }
  if (command === "delete_project") {
    const project = String(args?.project);
    histories.delete(project);
    for (const [id, owner] of owners) if (owner.project_root === project) owners.delete(id);
  }
  if (command === "campaign_health_events") return { events: [], next_cursor: null };
  return null;
}

let container: HTMLDivElement;
let root: Root;

beforeEach(async () => {
  localStorage.clear();
  listeners.clear();
  owners.clear();
  histories.clear();
  invoke.mockReset();
  invoke.mockImplementation(backend);
  discoveryResult = Promise.resolve();
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(<StrictMode>
    <ProjectProvider><DiscoveryProvider><RunOutputProvider><Probe /></RunOutputProvider></DiscoveryProvider></ProjectProvider>
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

describe("deleted project caches", () => {
  it("forgets deleted discovery inventories while retaining other projects and accepting a fresh scan", async () => {
    await click("open /a");
    await click("save discovery");
    await click("open /b");
    await click("save discovery");
    await click("delete /a");
    expect(state().discovery).toBe("/b");
    await click("open /a");
    expect(state().discovery).toBeNull();
    await click("save discovery");
    expect(state().discovery).toBe("/a");
  });

  it("rejects a deferred discovery save started before deletion", async () => {
    const result = deferred<void>();
    discoveryResult = result.promise;
    await click("open /a");
    await click("start discovery");
    await click("delete /a");
    await click("open /a");
    await act(async () => result.resolve());
    expect(state().discovery).toBeNull();
  });

  it("clears deleted run output in memory and storage without clearing another project", async () => {
    addRun(A, "/a");
    addRun(B, "/b");
    await click("open /a");
    expect(state().run).toBe(A);
    await click("open /b");
    await click("delete /a");
    expect(state().run).toBe(B);
    await click("open /a");
    expect(state().run).toBeNull();
    expect(state().summary).toBeNull();
    const persisted = JSON.parse(localStorage.getItem("hf_run_summary_v2")!);
    expect(persisted.runs[A]).toBeUndefined();
    expect(persisted.latest_run_by_project["/a"]).toBeUndefined();
    expect(persisted.runs[B].owner.run_id).toBe(B);
  });

  it("does not restore output from an owner request made before deletion", async () => {
    const originalOwner = addRun(A, "/a");
    const reply = deferred<RunOwner>();
    invoke.mockImplementation((command, args) => command === "run_owner" ? reply.promise : backend(command, args));
    await click("open /a");
    await click("delete /a");
    await click("open /a");
    await act(async () => reply.resolve(originalOwner));
    expect(state().run).toBeNull();
  });

  it("accepts a new run after the same project is reopened", async () => {
    addRun(A, "/a");
    await click("open /a");
    await click("delete /a");
    addRun(B, "/a");
    await click("open /a");

    expect(state().run).toBe(B);
    expect(state().summary).toMatchObject({ crashes: 1, edges: 5, execs: 30 });
  });

  it("retains another project's deferred owner read through deletion", async () => {
    const retainedOwner = addRun(B, "/b");
    const reply = deferred<RunOwner>();
    invoke.mockImplementation((command, args) => command === "run_owner" ? reply.promise : backend(command, args));
    await click("open /a");
    await click("open /b");
    await click("delete /a");
    await act(async () => reply.resolve(retainedOwner));

    expect(state().run).toBe(B);
  });

  it("does not restore a deleted run from a queued health event", async () => {
    const owner = addRun(A, "/a");
    await click("open /a");
    await click("delete /a");
    await click("open /a");
    await act(async () => {
      for (const handler of listeners.get("campaign:health") ?? []) handler({ payload: {
        owner,
        event: { schema_version: 2, id: B, run_id: A, condition: "run_failed", severity: "error", detail: "Old failure", observed_at: "2026-10-13T00:00:00Z", dedup_key: B, evidence: { schema_version: 2, run_id: A, condition: "run_failed", observed_at: "2026-10-13T00:00:00Z" } },
      } });
    });
    expect(state().run).toBeNull();
  });

  it("keeps run and discovery output when a project is merely removed from recents", async () => {
    addRun(A, "/a");
    await click("open /a");
    await click("save discovery");
    await click("remove /a");
    await click("open /a");
    expect(state().run).toBe(A);
    expect(state().discovery).toBe("/a");
  });
});
