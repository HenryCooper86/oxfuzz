import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Pins the visual design system: both themes expose the same tokens, state
// colors meet WCAG AA, and components route colors through tokens instead of
// hardcoding them.

const SRC = fileURLToPath(new URL("..", import.meta.url));

function source(relativePath: string): string {
  return readFileSync(join(SRC, relativePath), "utf8");
}

const DARK = ":root,\n[data-theme=\"dark\"]";
const LIGHT = "[data-theme=\"light\"]";

function themeBlock(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`${escaped}\\s*\\{([\\s\\S]*?)\\n\\}`));
  if (!match) throw new Error(`Missing ${selector} theme block`);
  return match[1];
}

function tokenNames(block: string): string[] {
  return [...block.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((m) => m[1]);
}

function hex(block: string, token: string): string {
  const match = block.match(new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})\\b`));
  if (!match) throw new Error(`Missing hex ${token}`);
  return match[1];
}

function luminance(color: string): number {
  const channels = color.slice(1).match(/.{2}/g) ?? [];
  const [r, g, b] = channels.map((c) => {
    const v = Number.parseInt(c, 16) / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Hue in degrees for warm colors (red..yellow), where red is the max channel. */
function hue(color: string): number {
  const [r, g, b] = (color.slice(1).match(/.{2}/g) ?? []).map((c) => Number.parseInt(c, 16));
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max !== r) throw new Error(`${color} is not a warm color`);
  return (60 * (g - b)) / (max - min);
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "__tests__" ? [] : walk(path);
    return /\.tsx?$/.test(name) ? [path] : [];
  });
}

const css = source("styles/index.css");
const themes = [DARK, LIGHT].map((selector) => [selector, themeBlock(css, selector)] as const);

const NEW_TOKENS = [
  "--surface-raised",
  "--border-strong",
  "--success-subtle",
  "--warning-subtle",
  "--overlay",
  "--danger-solid",
  "--danger-solid-hover",
  "--accent-border",
  "--scrollbar-thumb",
  "--scrollbar-thumb-hover",
];

describe("visual design tokens", () => {
  it("defines the same token set in the dark and light themes", () => {
    const [dark, light] = themes.map(([, block]) => new Set(tokenNames(block)));
    for (const token of NEW_TOKENS) {
      expect(dark.has(token), `dark ${token}`).toBe(true);
    }
    // Light inherits layout tokens (spacing, radii, fonts) from :root, but every
    // color it overrides must exist in dark and vice versa for color tokens.
    const layout = /^--(space|radius|font)-/;
    const darkColors = [...dark].filter((t) => !layout.test(t)).sort();
    const lightColors = [...light].filter((t) => !layout.test(t)).sort();
    expect(lightColors).toEqual(darkColors);
  });

  it("keeps text, state and accent colors at AA on every opaque surface", () => {
    for (const [selector, block] of themes) {
      for (const surface of ["--surface-primary", "--surface-secondary", "--surface-raised"]) {
        for (const text of ["--text-secondary", "--text-muted", "--success", "--warning", "--error"]) {
          expect(
            contrast(hex(block, text), hex(block, surface)),
            `${selector} ${text} on ${surface}`,
          ).toBeGreaterThanOrEqual(4.5);
        }
      }
      expect(contrast(hex(block, "--accent-contrast"), hex(block, "--accent")), `${selector} accent button`).toBeGreaterThanOrEqual(4.5);
      expect(contrast(hex(block, "--accent-contrast"), hex(block, "--accent-hover")), `${selector} accent hover`).toBeGreaterThanOrEqual(4.5);
      for (const danger of ["--danger-solid", "--danger-solid-hover"]) {
        expect(contrast("#ffffff", hex(block, danger)), `${selector} ${danger}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("keeps warnings visually distinct from the brand accent and from errors", () => {
    for (const [selector, block] of themes) {
      const accent = hue(hex(block, "--accent"));
      const warning = hue(hex(block, "--warning"));
      const error = hue(hex(block, "--error"));
      expect(accent - warning, `${selector} accent vs warning hue`).toBeGreaterThanOrEqual(15);
      expect(warning - error, `${selector} warning vs error hue`).toBeGreaterThanOrEqual(15);
    }
  });

  it("lifts cards onto the raised surface and exposes the new tokens to UnoCSS", () => {
    const uno = readFileSync(join(SRC, "..", "uno.config.ts"), "utf8");
    expect(uno).toMatch(/"surface-card":\s*\n?\s*"bg-surface-raised/);
    expect(uno).toContain('raised: "var(--surface-raised)"');
    expect(uno).toContain('strong: "var(--border-strong)"');
  });
});

describe("components use theme tokens", () => {
  it("never hardcodes hex or rgba colors outside the stylesheet", () => {
    const offenders = walk(SRC)
      .filter((file) => !file.endsWith(".css"))
      .flatMap((file) => {
        const text = readFileSync(file, "utf8");
        return [...text.matchAll(/#[0-9a-fA-F]{6}\b|rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+[^)]*\)/g)].map(
          (m) => `${file.slice(SRC.length)}: ${m[0]}`,
        );
      });
    expect(offenders).toEqual([]);
  });

  it("never references the undefined --danger token", () => {
    const offenders = walk(SRC).filter((file) => /var\(--danger[,)]/.test(readFileSync(file, "utf8")));
    expect(offenders.map((f) => f.slice(SRC.length))).toEqual([]);
  });
});

describe("buttons, icons and navigation", () => {
  const button = source("components/ui/Button.tsx");

  it("gives buttons real hover and pressed states instead of fading them", () => {
    expect(button).not.toContain("op-85");
    expect(button).toContain("var(--accent-hover)");
    expect(button).toContain("var(--danger-solid)");
    expect(button).toContain("var(--border-strong)");
    expect(button).toMatch(/active:/);
  });

  it("draws icons with one lighter stroke weight", () => {
    expect(css).toMatch(/svg\.lucide\s*\{[^}]*stroke-width:\s*1\.75/);
  });

  it("styles every sidebar row through one shared class", () => {
    const sidebar = source("components/Sidebar.tsx");
    expect(css).toMatch(/\.hf-nav-row\s*\{/);
    expect(css).toMatch(/\.hf-nav-row\[aria-current\]/);
    const settings = source("components/settings/SettingsView.tsx");
    for (const nav of [sidebar, settings]) {
      expect(nav).not.toContain("hover:bg-accent-subtle");
      expect(nav).not.toContain("bg-surface-active text-text-primary border border-border");
      expect(nav).toContain('className="hf-nav-row');
    }
  });

  it("gives inputs a visible border and an accent focus border", () => {
    const input = source("components/ui/Input.tsx");
    const select = source("components/ui/Select.tsx");
    for (const control of [input, select]) {
      expect(control).toContain("border-[var(--border-strong)]");
      expect(control).toContain("focus:border-[var(--accent)]");
    }
  });

  it("renders the settings title upright like every other view title", () => {
    expect(source("components/settings/SettingsView.tsx")).not.toMatch(/fontStyle:\s*"italic"/);
  });
});
