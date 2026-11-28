import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..");
const read = (relative: string) => readFileSync(join(root, relative), "utf8");

/** Engine flags `SystemStatus` carries, read from its declaration. */
function engineFlags(): string[] {
  const types = read("types/index.ts");
  const start = types.indexOf("export interface SystemStatus");
  const body = types.slice(start, types.indexOf("}", start));
  const flags = ["libfuzzer", "aflplusplus", "honggfuzz", "syzkaller", "go_native", "atheris", "jazzer", "jazzer_js"];
  return flags.filter((flag) => new RegExp(`\\b${flag}\\??:`).test(body));
}

describe("engine readiness surfaces", () => {
  it("declares the Go native fuzzing flag the system probe reports", () => {
    // `oxfuzz doctor` and the Dashboard listed every engine but Go native
    // fuzzing, so nothing said whether the image could build a Go target.
    expect(engineFlags()).toContain("go_native");
  });

  it("shows every engine flag on the Dashboard and in the About summary", () => {
    const dashboard = read("views/DashboardView.tsx");
    const about = read("components/settings/AboutTab.tsx");
    for (const flag of engineFlags()) {
      expect(dashboard, flag).toContain(`status?.${flag}`);
      expect(about, flag).toContain(`status.${flag}`);
    }
  });
});
