import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("automotive surface boundaries", () => {
  it("keeps the workspace behind a lazy application boundary", () => {
    expect(source("../App.tsx")).toMatch(
      /lazy\(\(\) =>\s*import\("\.\/views\/AutomotiveView"\)/,
    );
  });

  it("exposes automotive navigation and a dedicated typed settings tab", () => {
    expect(source("../types/index.ts")).toContain('| "automotive"');
    expect(source("../components/Sidebar.tsx")).toContain('view: "automotive"');
    expect(source("../components/settings/SettingsView.tsx")).toContain(
      "<AutomotiveSettingsTab",
    );
  });

  it("keeps virtual replay in a confirmed sandbox workflow and physical execution absent", () => {
    const workspace = source("../views/AutomotiveView.tsx");
    const replay = source("../components/AutomotiveReplayWorkspace.tsx");
    expect(workspace).toContain("automotive.virtual.policyGated");
    expect(workspace).toContain("automotive.physical.approvalRequired");
    expect(workspace).toContain("<AutomotiveReplayWorkspace");
    expect(replay).toContain("executeAutomotiveReplay");
    expect(replay).toContain("useConfirm");
    expect(replay).not.toContain('mode: "physical_bench"');
  });
});
