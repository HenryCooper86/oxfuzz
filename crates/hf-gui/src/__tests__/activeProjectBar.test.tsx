// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ActiveProjectBar } from "../components/ActiveProjectBar";
import { I18nProvider } from "../i18n";

// One project picker for the whole app: every stage page shows the active
// project and changes it through the same action, so no page can drift onto a
// different project than the rest of the app.
const project = vi.hoisted(() => ({ activeProject: "", recentProjects: [] as string[], setActiveProject: vi.fn() }));
const pickFolder = vi.hoisted(() => vi.fn());
vi.mock("../providers/project", () => ({ useProject: () => project }));
vi.mock("../lib", () => ({ pickFolder }));

let host: HTMLDivElement; let root: Root;
const button = (label: string) => [...host.querySelectorAll("button")].find(b => b.textContent?.trim() === label);
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  project.setActiveProject.mockReset(); pickFolder.mockReset();
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

it("shows the active project and changes it for the whole app", async () => {
  project.activeProject = "/work/json_parser"; project.recentProjects = ["/work/json_parser"];
  pickFolder.mockResolvedValue("/work/other");
  await act(async () => root.render(<I18nProvider><ActiveProjectBar /></I18nProvider>));
  expect(host.textContent).toContain("json_parser");
  expect(host.textContent).toContain("/work/json_parser");
  expect(host.querySelector("input")).toBeNull();
  await act(async () => button("Change")!.click());
  expect(project.setActiveProject).toHaveBeenCalledWith("/work/other");
});

it("asks for a folder and offers recent projects when none is active", async () => {
  project.activeProject = ""; project.recentProjects = ["/work/a", "/work/b"];
  pickFolder.mockResolvedValue(null);
  await act(async () => root.render(<I18nProvider><ActiveProjectBar /></I18nProvider>));
  expect(host.textContent).toContain("No project selected");
  await act(async () => button("Choose Folder…")!.click());
  expect(project.setActiveProject).not.toHaveBeenCalled();
  await act(async () => button("/work/b")!.click());
  expect(project.setActiveProject).toHaveBeenCalledWith("/work/b");
});
