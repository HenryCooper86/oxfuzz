import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  AI_SYSTEM_VIEW_IDS,
  RESULTS_VIEW_IDS,
  getSidebarSectionOpenAfterNavigation,
  sidebarSectionContainsView,
} from "../lib/sidebarSections";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("sidebar section membership", () => {
  it("recognizes Results views", () => {
    for (const view of ["projects", "artifacts", "reports", "runs", "audit"] as const) {
      expect(sidebarSectionContainsView(RESULTS_VIEW_IDS, view)).toBe(true);
    }
  });

  it("recognizes AI System views", () => {
    for (const view of ["chat", "agents", "skills", "knowledge", "automation"] as const) {
      expect(sidebarSectionContainsView(AI_SYSTEM_VIEW_IDS, view)).toBe(true);
    }
  });

  it("excludes unrelated and Pipeline views", () => {
    for (const view of ["dashboard", "workflow", "discover", "harness", "run", "triage", "corpus"] as const) {
      expect(sidebarSectionContainsView(RESULTS_VIEW_IDS, view)).toBe(false);
      expect(sidebarSectionContainsView(AI_SYSTEM_VIEW_IDS, view)).toBe(false);
    }
  });
});

describe("sidebar section navigation state", () => {
  it("opens a section when navigation enters one of its views", () => {
    expect(
      getSidebarSectionOpenAfterNavigation(
        false,
        "dashboard",
        "projects",
        RESULTS_VIEW_IDS,
      ),
    ).toBe(true);
  });

  it("preserves manual open and closed state while the active view is stable", () => {
    expect(
      getSidebarSectionOpenAfterNavigation(
        false,
        "projects",
        "projects",
        RESULTS_VIEW_IDS,
      ),
    ).toBe(false);
    expect(
      getSidebarSectionOpenAfterNavigation(
        true,
        "projects",
        "projects",
        RESULTS_VIEW_IDS,
      ),
    ).toBe(true);
  });

  it("preserves manual state when navigation leaves the section", () => {
    expect(
      getSidebarSectionOpenAfterNavigation(
        false,
        "projects",
        "dashboard",
        RESULTS_VIEW_IDS,
      ),
    ).toBe(false);
    expect(
      getSidebarSectionOpenAfterNavigation(
        true,
        "projects",
        "dashboard",
        RESULTS_VIEW_IDS,
      ),
    ).toBe(true);
  });
});

describe("Sidebar collapsible sections", () => {
  it("uses accessible collapsible controls for secondary navigation without wrapping Pipeline", () => {
    const sidebar = source("../components/Sidebar.tsx");

    expect(sidebar).toContain("aria-expanded");
    expect(sidebar).toContain("aria-controls");
    expect(sidebar).toContain("getSidebarSectionOpenAfterNavigation");
    expect(sidebar).toContain("setIsOpen((open) => !open)");
    expect(sidebar).toMatch(/<SectionLabel>\{t\("sidebar\.pipeline"\)\}<\/SectionLabel>[\s\S]*?PIPELINE_ITEMS\.map/);
    expect(sidebar).toMatch(/<CollapsibleNavSection[\s\S]*?RESULTS_ITEMS/);
    expect(sidebar).toMatch(/<CollapsibleNavSection[\s\S]*?AI_SYSTEM_ITEMS/);
  });
});
