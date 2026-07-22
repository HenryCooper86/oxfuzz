import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("oxfuzz branding in app chrome", () => {
  it("shows the logo next to the oxfuzz wordmark in the header", () => {
    const header = source("../components/Header.tsx");
    // The header presents a brand lockup: the logo image immediately followed
    // by the oxfuzz wordmark, with accessible alt text on the image.
    expect(header).toContain('src="/logo.png"');
    expect(header).toContain('alt="oxfuzz"');
    expect(header).toMatch(/src="\/logo\.png"[\s\S]{0,600}oxfuzz/);
  });

  it("shows a logo + oxfuzz wordmark brand block at the top of the sidebar", () => {
    const sidebar = source("../components/Sidebar.tsx");
    expect(sidebar).toContain('src="/logo.png"');
    // The brand block pairs the logo with the oxfuzz wordmark.
    expect(sidebar).toMatch(/src="\/logo\.png"[\s\S]{0,600}oxfuzz/);
  });
});
