import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned build doctor surface", () => {
  it("declares the serialized diagnosis and run outcome", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface BuildSystemDiagnosis");
    expect(types).toContain("interface BuildPlan");
    expect(types).toContain("interface BuildPlanRunOutcome");
    expect(types).toContain("type BuildSystemStatus");
    expect(types).toContain("expected_artifact");
    expect(types).toContain("missing_tool");
    expect(types).toContain('"cmake"');
  });

  it("shows the whole plan before anything runs", () => {
    const panel = source("../components/BuildDoctorPanel.tsx");
    expect(panel).toContain("plan.steps");
    expect(panel).toContain("step.argv");
    expect(panel).toContain("plan.expected_artifact");
    // The run is a separate, later, confirmed call.
    expect(panel).toContain("buildDoctor.confirmRun");
    const diagnoseIndex = panel.indexOf('invoke<BuildSystemDiagnosis[]>("build_diagnose"');
    const runIndex = panel.indexOf('invoke<BuildPlanRunOutcome>("build_run"');
    expect(diagnoseIndex).toBeGreaterThan(-1);
    expect(runIndex).toBeGreaterThan(diagnoseIndex);
  });

  it("renders the service status and never decides supportability itself", () => {
    const panel = source("../components/BuildDoctorPanel.tsx");
    expect(panel).toContain("entry.status");
    expect(panel).toContain("entry.missing_tool");
    expect(panel).toContain("outcome.status");
    expect(panel).not.toContain("deriveSupported");
    expect(panel).not.toMatch(/status\s*===\s*["']supported["']\s*\?\s*true/);
    // A run button only exists where the service supplied a plan.
    expect(panel).toMatch(/entry\.plan\s*&&/);
  });

  it("keeps REST and Tauri as transports", () => {
    const transport = source("../lib/httpTransport.ts");
    expect(transport).toContain('path: "/build/diagnose"');
    expect(transport).toContain('path: "/build/run"');
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub async fn build_diagnose");
    expect(commands).toContain("pub async fn build_run");
    expect(source("../../../hf-web/src/router.rs")).toContain('.route("/build/diagnose"');
  });

  it("is mounted where a build failure is discovered", () => {
    expect(source("../views/HarnessView.tsx")).toContain("BuildDoctorPanel");
  });

  it("keeps English and Chinese build doctor labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"buildDoctor.title": "Build Doctor"');
    expect(translations).toContain('"buildDoctor.title": "构建诊断"');
    expect(translations).toContain('"buildDoctor.status.unsupported_in_image": "Not runnable here"');
    expect(translations).toContain('"buildDoctor.status.unsupported_in_image": "当前镜像无法运行"');
  });
});
