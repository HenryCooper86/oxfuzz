import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("frontend cleanup boundaries", () => {
  it("keeps provider component modules limited to component exports", () => {
    const providerModules = [
      "../providers/ConfirmContext.tsx",
      "../providers/PipelineContext.tsx",
      "../providers/PrefsContext.tsx",
      "../providers/ProjectContext.tsx",
      "../providers/RunOutputContext.tsx",
      "../providers/RunStatusContext.tsx",
      "../providers/TargetContext.tsx",
      "../components/ui/Toast.tsx",
      "../i18n.tsx",
    ];

    for (const path of providerModules) {
      const contents = source(path);
      expect(contents, path).not.toMatch(/export function use[A-Z]/);
      expect(contents, path).not.toMatch(/export const [A-Z_]+/);
    }
  });

  it("loads the Help surface and Mermaid renderer on demand", () => {
    expect(source("../App.tsx")).toMatch(
      /lazy\(\(\) =>\s*import\("\.\/views\/HelpView"\)/,
    );
    expect(source("../components/Mermaid.tsx")).toContain('import("mermaid")');
    expect(source("../components/Mermaid.tsx")).not.toMatch(/^import mermaid from "mermaid";/m);
    expect(source("../views/HelpView.tsx")).toContain(
      'from "../lib/reportPreviewCode"',
    );
    expect(source("../components/ReportPreview.tsx")).not.toContain(
      "export function codeInfo",
    );
  });

  it("uses local dependency-safe provider glyphs", () => {
    expect(source("../components/common/ProviderBrandIcon.tsx")).not.toContain("@lobehub/icons");
    const pkg = JSON.parse(source("../../package.json")) as { dependencies?: Record<string, string> };
    expect(pkg.dependencies).not.toHaveProperty("@lobehub/icons");
  });

  it("presents workspace cleanup as an explicit destructive warning", () => {
    const storage = source("../components/settings/StorageTab.tsx");
    expect(storage).toContain('role="note"');
    expect(storage).toContain("AlertTriangle");
    expect(storage).toContain('variant="danger"');
  });
});
