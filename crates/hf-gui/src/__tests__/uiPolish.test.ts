import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

function themeBlock(css: string, selector: string): string {
  const escapedSelector = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`${escapedSelector}\\s*\\{([\\s\\S]*?)\\n\\}`));
  if (!match) throw new Error(`Missing ${selector} theme block`);
  return match[1];
}

function cssHex(block: string, token: string): string {
  const match = block.match(new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`));
  if (!match) throw new Error(`Missing ${token}`);
  return match[1];
}

function relativeLuminance(hex: string): number {
  const channels = hex.slice(1).match(/.{2}/g);
  if (!channels) throw new Error(`Invalid hex color: ${hex}`);

  const linear = channels.map((channel) => {
    const value = Number.parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });

  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrastRatio(first: string, second: string): number {
  const [lighter, darker] = [relativeLuminance(first), relativeLuminance(second)].sort(
    (a, b) => b - a,
  );
  return (lighter + 0.05) / (darker + 0.05);
}

describe("UI polish foundations", () => {
  it("keeps secondary and muted text at AA contrast against every opaque surface", () => {
    const css = source("../styles/index.css");

    for (const selector of [":root,\n[data-theme=\"dark\"]", "[data-theme=\"light\"]"]) {
      const block = themeBlock(css, selector);

      for (const surfaceToken of [
        "--surface-primary",
        "--surface-secondary",
        "--surface-tertiary",
      ]) {
        const surface = cssHex(block, surfaceToken);

        for (const textToken of ["--text-secondary", "--text-muted"]) {
          expect(
            contrastRatio(cssHex(block, textToken), surface),
            `${selector} ${textToken} against ${surfaceToken}`,
          ).toBeGreaterThanOrEqual(4.5);
        }
      }
    }
  });

  it("keeps the view title as normal secondary context in the header", () => {
    const header = source("../components/Header.tsx");

    expect(header).toContain("{title}");
    expect(header).toContain("var(--text-secondary)");
    expect(header).not.toMatch(/fontStyle:\s*["']italic["']/);
  });

  it("provides a shared scrolling canvas for primary views", () => {
    const canvas = source("../components/ui/ViewCanvas.tsx");

    expect(canvas).toContain("view-scroll");
    expect(canvas).toContain("view-canvas");
    expect(source("../components/ui/index.ts")).toContain('export { ViewCanvas } from "./ViewCanvas"');
  });

  it("routes primary views through the shared canvas while preserving DefectDojo's full width", () => {
    const app = source("../App.tsx");

    expect(app).toMatch(/import \{[^}]*ViewCanvas[^}]*\} from "\.\/components\/ui"/);
    expect(app).toContain("<ViewCanvas>");
    expect(app).not.toContain('style={{ padding: "var(--space-lg)" }}');
    expect(app).toContain('activeView === "defectdojo"');
  });

  it("defines centered canvas geometry and responsive scrolling gutters", () => {
    const css = source("../styles/index.css");

    expect(css).toMatch(/\.view-canvas\s*\{[\s\S]*max-width:\s*1440px/);
    expect(css).toMatch(/\.view-canvas\s*\{[\s\S]*margin:\s*0 auto/);
    expect(css).toMatch(/\.view-scroll\s*\{[\s\S]*padding:/);
    expect(css).toMatch(/@media\s*\([^)]*max-width:[^)]*\)[\s\S]*\.view-scroll\s*\{/);
  });
});
