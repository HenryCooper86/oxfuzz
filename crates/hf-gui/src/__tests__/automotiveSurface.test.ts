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

  it("wires an offline analysis workspace: import, DBC decode, sniffer, and diff", () => {
    const lib = source("../lib/automotive.ts");
    expect(lib).toContain('"automotive_import_capture"');
    expect(lib).toContain('"automotive_diff_captures"');
    expect(source("../views/AutomotiveView.tsx")).toContain("<AutomotiveOfflineWorkspace");
    const offline = source("../components/AutomotiveOfflineWorkspace.tsx");
    expect(offline).toContain("importAutomotiveCapture");
    expect(offline).toContain("diffAutomotiveCaptures");
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub fn automotive_import_capture");
    expect(commands).toContain("pub fn automotive_diff_captures");
  });

  it("wires a read-only virtual-CAN live monitor into the workspace", () => {
    expect(source("../lib/automotive.ts")).toContain('"automotive_live_monitor"');
    expect(source("../views/AutomotiveView.tsx")).toContain("<AutomotiveLiveMonitor");
    const live = source("../components/AutomotiveLiveMonitor.tsx");
    expect(live).toContain("liveMonitorAutomotive");
    // Virtual CAN only from the GUI; physical bench is not offered here.
    expect(live).toContain('"virtual_can"');
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "pub async fn automotive_live_monitor",
    );
  });

  it("wires a read-only UDS discovery scan with a dangerous-service denial", () => {
    expect(source("../lib/automotive.ts")).toContain('"automotive_scan_uds"');
    expect(source("../lib/automotive.ts")).toContain("READ_ONLY_UDS_SERVICES");
    expect(source("../views/AutomotiveView.tsx")).toContain("<AutomotiveUdsScan");
    expect(source("../components/AutomotiveUdsScan.tsx")).toContain("scanUdsAutomotive");
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "pub async fn automotive_scan_uds",
    );
    // The service enforces the read-only allowlist / dangerous-service denial.
    expect(source("../../../hf-service/src/automotive.rs")).toContain("READ_ONLY_UDS_SERVICES");
  });

  it("wires signal graphing and a periodic frame sender that reuses replay", () => {
    expect(source("../components/AutomotiveOfflineWorkspace.tsx")).toContain(
      "<AutomotiveSignalGraph",
    );
    // The graph is a self-contained inline-SVG chart (no external chart lib / CDN).
    const graph = source("../components/AutomotiveSignalGraph.tsx");
    expect(graph).toContain("<svg");
    // Multi-series overlay uses a validated categorical palette (theme-aware CSS
    // vars) plus dash-pattern secondary encoding, so identity is never color-alone.
    expect(graph).toContain("--chart-series-1");
    expect(graph).toContain("SERIES_DASH");
    expect(source("../styles/index.css")).toContain("--chart-series-1:");
    expect(source("../views/AutomotiveView.tsx")).toContain("<AutomotiveFrameSender");
    const sender = source("../components/AutomotiveFrameSender.tsx");
    // The sender builds a replay plan and reuses the replay path + confirmation.
    expect(sender).toContain("executeAutomotiveReplay");
    expect(sender).toContain("useConfirm");
  });
});
