import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("sidebar secondary navigation layout", () => {
  it("renders Results and AI System as flat, always-visible sections like Pipeline", () => {
    const sidebar = source("../components/Sidebar.tsx");
    // Results and AI System use the same flat pattern as Pipeline: a section
    // label immediately followed by the mapped nav buttons -- nothing hidden.
    expect(sidebar).toMatch(
      /<SectionLabel>\{t\("sidebar\.results"\)\}<\/SectionLabel>[\s\S]*?RESULTS_ITEMS\.map/,
    );
    expect(sidebar).toMatch(
      /<SectionLabel>\{t\("sidebar\.aiSystem"\)\}<\/SectionLabel>[\s\S]*?AI_SYSTEM_ITEMS\.map/,
    );
  });

  it("carries no collapsible secondary-navigation machinery", () => {
    const sidebar = source("../components/Sidebar.tsx");
    expect(sidebar).not.toContain("CollapsibleNavSection");
    expect(sidebar).not.toContain("aria-expanded");
    expect(sidebar).not.toContain("sidebarSections");
  });
});
