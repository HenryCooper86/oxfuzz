import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned stateful automotive lab surface", () => {
  it("declares the serialized coverage and plan views", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface ProtocolStateCoverage");
    expect(types).toContain("interface SequencePlan");
    expect(types).toContain("interface SequenceStep");
    expect(types).toContain("expected_total");
    expect(types).toContain("model_name");
    expect(types).toContain("PlanRefusal");
  });

  it("never offers the physical bench as a sequenceable mode", () => {
    const panel = source("../components/AutomotiveLabPanel.tsx");
    expect(panel).toContain("virtual_can");
    expect(panel).toContain("offline_pcap");
    expect(panel).not.toContain("physical_bench");
    // And it renders the service refusal rather than deciding one.
    expect(panel).toContain("plan.refusal");
    expect(panel).toContain("automotiveLab.refusal.");
  });

  it("shows an absent denominator as absent rather than as full coverage", () => {
    const panel = source("../components/AutomotiveLabPanel.tsx");
    expect(panel).toContain("coverage.expected_total");
    expect(panel).toContain("automotiveLab.noDenominator");
    // No percentage is computed from the observed count alone.
    expect(panel).not.toMatch(/observed\.length\s*\/\s*observed\.length/);
    expect(panel).not.toMatch(/100\s*\*\s*coverage\.observed\.length/);
  });

  it("renders the service plan without reordering it", () => {
    const panel = source("../components/AutomotiveLabPanel.tsx");
    expect(panel).toContain("plan.steps");
    expect(panel).toContain("step.reason_code");
    expect(panel).not.toContain("planSequence");
    expect(panel).not.toMatch(/steps\.sort\(/);
    // The plan is advisory: the panel starts nothing.
    expect(panel).not.toContain('invoke("execute_automotive"');
  });

  it("keeps REST and Tauri as transports", () => {
    const transport = source("../lib/httpTransport.ts");
    expect(transport).toContain('path: "/automotive/lab/coverage"');
    expect(transport).toContain('path: "/automotive/lab/plan"');
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub async fn automotive_lab_coverage");
    expect(commands).toContain("pub async fn automotive_lab_plan");
    expect(source("../../../hf-web/src/router.rs")).toContain(
      '.route("/automotive/lab/plan"',
    );
  });

  it("is mounted in the automotive view", () => {
    expect(source("../views/AutomotiveView.tsx")).toContain("AutomotiveLabPanel");
  });

  it("keeps English and Chinese lab labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"automotiveLab.title": "Stateful Lab"');
    expect(translations).toContain('"automotiveLab.title": "状态实验室"');
    expect(translations).toContain(
      '"automotiveLab.refusal.physical_bench_not_sequenceable": "The physical bench cannot run a sequence. Each physical transmission needs its own fresh approval."',
    );
    expect(translations).toContain(
      '"automotiveLab.refusal.physical_bench_not_sequenceable": "物理台架无法运行序列。每次物理发送都需要单独的新批准。"',
    );
  });
});
