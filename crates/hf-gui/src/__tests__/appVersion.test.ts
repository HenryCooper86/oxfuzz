import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { APP_VERSION } from "../lib/appVersion";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

const packageVersion = JSON.parse(source("../../package.json")).version as string;

describe("app version", () => {
  // The displayed version drifted to 0.1.0 across the 0.1.1 and 0.1.2 releases
  // because each surface hardcoded its own copy. package.json is the single
  // source Tauri also bundles from, so bind the UI to it and assert the bind.
  it("reports the version declared in package.json", () => {
    expect(APP_VERSION).toBe(packageVersion);
  });

  it("declares a plain semver version", () => {
    expect(APP_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  // A literal here is the exact defect this module exists to prevent: it renders
  // correctly on the day it is written and silently goes stale at the next bump.
  it("keeps version-displaying surfaces free of hardcoded literals", () => {
    const surfaces = [
      "../components/Sidebar.tsx",
      "../components/settings/AboutTab.tsx",
    ];

    for (const surface of surfaces) {
      expect(source(surface)).not.toMatch(/\d+\.\d+\.\d+/);
    }
  });
});
