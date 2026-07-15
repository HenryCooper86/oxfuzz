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

function fixture(entryBytes: number, lazyBytes: number): string {
  const root = mkdtempSync(join(tmpdir(), "hf-gui-budget-"));
  fixtures.push(root);
  mkdirSync(join(root, "assets"), { recursive: true });
  mkdirSync(join(root, ".vite"), { recursive: true });
  writeFileSync(join(root, "assets", "index.js"), "x".repeat(entryBytes));
  writeFileSync(join(root, "assets", "lazy.js"), "y".repeat(lazyBytes));
  writeFileSync(
    join(root, ".vite", "manifest.json"),
    JSON.stringify({
      "src/main.tsx": { file: "assets/index.js", isEntry: true },
      "src/lazy.tsx": { file: "assets/lazy.js", isDynamicEntry: true },
    }),
  );
  return root;
}

function check(root: string) {
  return spawnSync(process.execPath, [script, root], {
    encoding: "utf8",
    env: {
      ...process.env,
      HF_GUI_INITIAL_JS_BUDGET: "100",
      HF_GUI_TOTAL_JS_BUDGET: "300",
      HF_GUI_MAX_CHUNK_BUDGET: "200",
    },
  });
}

describe("bundle budget", () => {
  it("accepts a build within every configured JavaScript limit", () => {
    const result = check(fixture(80, 120));
    expect(result.status, result.stderr || result.stdout).toBe(0);
  });

  it("rejects an initial entry chunk over budget", () => {
    const result = check(fixture(101, 120));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("initial JavaScript");
  });
});
