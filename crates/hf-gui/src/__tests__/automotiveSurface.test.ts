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
    expect(source("../components/Sidebar.tsx")).toContain('onNavigate("automotive")');
    expect(source("../components/settings/SettingsView.tsx")).toContain(
      "<AutomotiveSettingsTab",
    );
  });

  it("keeps the automotive nav entry always present and visually prominent", () => {
    const sidebar = source("../components/Sidebar.tsx");
    // Automotive is a first-class capability: it renders unconditionally in its
    // own labelled, accent-highlighted section and is never hidden behind a
    // runtime `enabled` toggle the way the optional DefectDojo entry is.
    expect(sidebar).toContain("AutomotiveNavButton");
    expect(sidebar).toContain('t("sidebar.vehicle")');
    expect(sidebar).not.toMatch(/automotiveOn\s*&&/);
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

  it("registers a thin Tauri command for the service-owned automotive report", () => {
    const commands = source("../../src-tauri/src/commands.rs");
    const app = source("../../src-tauri/src/lib.rs");
    expect(commands).toContain("pub async fn generate_automotive_report");
    expect(commands).toContain(".generate_automotive_report(&project_root, include_ai)");
    expect(app).toContain("generate_automotive_report,");
  });

  it("offers report composition, retained draft handoff, preview, and export", () => {
    const workspace = source("../views/AutomotiveView.tsx");
    expect(workspace).toContain("generateAutomotiveReport");
    expect(workspace).toContain("includeAi");
    expect(workspace).toContain('"save_report_draft"');
    expect(workspace).toContain("<ReportPreview");
    expect(workspace).toContain('"export_markdown"');
  });

  it("makes the disabled state actionable and handles a feature-absent build", () => {
    const workspace = source("../views/AutomotiveView.tsx");
    // The disabled banner enables the subsystem in one click by persisting the
    // master switch, rather than sending the user off to Settings.
    expect(workspace).toContain("enableAutomotive");
    expect(workspace).toContain("setAutomotiveSettings");
    expect(workspace).toContain('t("automotive.enableAction")');
    // A build compiled without the automotive feature shows a clean unavailable
    // state instead of surfacing a raw backend error string.
    expect(workspace).toContain("isFeatureUnavailable");
    expect(workspace).toContain('t("automotive.unavailableTitle")');
  });

  it("polls operation status while a run is still in progress", () => {
    const workspace = source("../views/AutomotiveView.tsx");
    expect(workspace).toContain("OPERATIONS_POLL_MS");
    expect(workspace).toContain("setInterval");
    expect(workspace).toMatch(/status === "running"/);
  });
});
