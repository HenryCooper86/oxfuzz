import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("oxfuzz branding in app chrome", () => {
  it("shows a logo + oxfuzz wordmark brand block at the top of the sidebar", () => {
    const sidebar = source("../components/Sidebar.tsx");
    expect(sidebar).toContain('src="/logo.png"');
    // The brand block pairs the logo with the oxfuzz wordmark.
    expect(sidebar).toMatch(/src="\/logo\.png"[\s\S]{0,600}oxfuzz/);
  });

  it("keeps the header free of brand identity -- name and logo live only in the sidebar", () => {
    const header = source("../components/Header.tsx");
    expect(header).not.toContain('src="/logo.png"');
    expect(header).not.toContain("oxfuzz");
  });
});
