import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned coverage blocker surface", () => {
  it("declares the serialized blocker view", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface CoverageBlockerView");
    expect(types).toContain("interface CoverageBlocker");
    expect(types).toContain("interface NextExperiment");
    expect(types).toContain("unlocked_uncovered");
    expect(types).toContain("frontier_distance");
    expect(types).toContain("nearest_covered");
    expect(types).toContain("MeasurementStatus");
  });

  it("shows an absent measurement as absent rather than as no blockers", () => {
    const panel = source("../components/CoverageBlockerPanel.tsx");
    expect(panel).toContain("view.measurement.status");
    expect(panel).toContain("coverageBlockers.unavailable");
    // The blocker list renders only when a measurement backs it.
    expect(panel).toMatch(/measurement\.status\s*===\s*["']available["']/);
  });

  it("renders unavailable distance distinctly from a short one", () => {
    const panel = source("../components/CoverageBlockerPanel.tsx");
    expect(panel).toContain("blocker.frontier_distance");
    expect(panel).toContain("coverageBlockers.noRoute");
    expect(panel).toContain("blocker.path");
  });

  it("renders the service experiment without deriving one", () => {
    const panel = source("../components/CoverageBlockerPanel.tsx");
    expect(panel).toContain("view.experiment.kind");
    expect(panel).toContain("view.experiment.target_function");
    expect(panel).not.toContain("proposeExperiment");
    expect(panel).not.toMatch(/blockers\[0\]\s*\?\s*["']grow_corpus["']/);
    // The proposal is advisory: the panel starts nothing.
    expect(panel).not.toContain('invoke("harness_refine"');
    expect(panel).not.toContain('invoke("corpus_grow"');
  });

  it("keeps REST and Tauri as transports", () => {
    expect(source("../lib/httpTransport.ts")).toContain('path: "/coverage/blockers"');
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "pub async fn coverage_blockers",
    );
    expect(source("../../../hf-web/src/router.rs")).toContain('.route("/coverage/blockers"');
  });

  it("is mounted where coverage is reviewed", () => {
    expect(source("../views/CorpusView.tsx")).toContain("CoverageBlockerPanel");
  });

  it("keeps English and Chinese blocker labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"coverageBlockers.title": "Coverage Blockers"');
    expect(translations).toContain('"coverageBlockers.title": "覆盖率阻塞点"');
    expect(translations).toContain('"coverageBlockers.noRoute": "No observed route"');
    expect(translations).toContain('"coverageBlockers.noRoute": "没有观察到的路径"');
  });
});
