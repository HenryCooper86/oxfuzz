import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const script = fileURLToPath(new URL("../../scripts/check-bundle-budget.mjs", import.meta.url));
const fixtures: string[] = [];

afterEach(() => {
  for (const path of fixtures.splice(0)) rmSync(path, { recursive: true, force: true });
});

/**
 * A build with three chunks: the entry we wrote, a view we lazy-load, and a
 * dependency's own lazily-loaded chunk.
 *
 * The dependency chunk is reachable only through a `node_modules/` dynamic
 * entry, which is what separates vendor weight from ours.
 */
function fixture(entryBytes: number, appLazyBytes: number, vendorBytes: number): string {
  const root = mkdtempSync(join(tmpdir(), "hf-gui-budget-"));
  fixtures.push(root);
  mkdirSync(join(root, "assets"), { recursive: true });
  mkdirSync(join(root, ".vite"), { recursive: true });
  writeFileSync(join(root, "assets", "index.js"), "x".repeat(entryBytes));
  writeFileSync(join(root, "assets", "lazy.js"), "y".repeat(appLazyBytes));
  writeFileSync(join(root, "assets", "vendor.js"), "z".repeat(vendorBytes));
  writeFileSync(
    join(root, ".vite", "manifest.json"),
    JSON.stringify({
      "src/main.tsx": {
        file: "assets/index.js",
        isEntry: true,
        dynamicImports: ["src/lazy.tsx", "node_modules/dep/dep.mjs"],
      },
      "src/lazy.tsx": { file: "assets/lazy.js", isDynamicEntry: true },
      "node_modules/dep/dep.mjs": { file: "assets/vendor.js", isDynamicEntry: true },
    }),
  );
  return root;
}

function check(root: string, overrides: Record<string, string> = {}) {
  return spawnSync(process.execPath, [script, root], {
    encoding: "utf8",
    env: {
      ...process.env,
      HF_GUI_INITIAL_JS_BUDGET: "100",
      HF_GUI_MAX_CHUNK_BUDGET: "600",
      HF_GUI_APP_JS_BUDGET: "300",
      HF_GUI_VENDOR_JS_BUDGET: "500",
      ...overrides,
    },
  });
}

describe("bundle budget", () => {
  it("accepts a build within every configured JavaScript limit", () => {
    const result = check(fixture(80, 120, 400));
    expect(result.status, result.stderr || result.stdout).toBe(0);
  });

  it("rejects an initial entry chunk over budget", () => {
    const result = check(fixture(101, 120, 400));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("initial JavaScript");
  });

  it("rejects a single chunk over the per-chunk budget", () => {
    const result = check(fixture(80, 250, 100), { HF_GUI_MAX_CHUNK_BUDGET: "200" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("largest JavaScript chunk");
  });

  it("rejects our own JavaScript over the app budget", () => {
    // 90 + 220 = 310 of app JavaScript against a 300 budget.
    const result = check(fixture(90, 220, 100));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("app JavaScript");
  });

  it("rejects dependency JavaScript over the vendor budget", () => {
    const result = check(fixture(80, 120, 501));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("vendor JavaScript");
  });

  it("does not spend the app budget on dependency weight", () => {
    // The whole point of the split: a dependency an order of magnitude larger
    // than our code must not be what fails the budget that bounds our code.
    const result = check(fixture(80, 120, 499));
    expect(result.status, result.stderr || result.stdout).toBe(0);
    expect(result.stdout).toContain("app 200/300");
    expect(result.stdout).toContain("vendor 499/500");
  });

  it("counts a chunk reachable only from a dependency as vendor", () => {
    const result = check(fixture(80, 120, 400));
    // 80 entry + 120 lazy view = 200 app; the 400 B dependency is not ours.
    expect(result.stdout).toContain("app 200/300");
    expect(result.stdout).toContain("vendor 400/500");
  });
});
