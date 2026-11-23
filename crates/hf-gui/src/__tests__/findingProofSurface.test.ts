import { extraTranslationDictionariesJson } from "./translationDictionaryScan";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned finding proof card", () => {
  it("declares the complete serialized service view", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface FindingProofCard");
    expect(types).toContain("deterministic_reproduction");
    expect(types).toContain("casr_exploitability");
    expect(types).toContain("external_reachability");
    expect(types).toContain("fix_verification");
    expect(types).toContain("proof: FindingProofCard");
  });

  it("renders the service proof in Dashboard without deriving it from severity", () => {
    const dashboard = source("../views/DashboardView.tsx");
    expect(dashboard).toContain("<FindingProofCard proof={crash.proof}");
    expect(dashboard).not.toContain("proof={deriveFindingProof");
  });

  it("keeps REST and Tauri entrypoints for the service dashboard DTO", () => {
    expect(source("../lib/httpTransport.ts")).toContain('path: "/workbench/dashboard"');
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "Result<hf_service::WorkbenchDashboard, String>",
    );
  });

  it("shows control-replay evidence and its disposition from the service view", () => {
    const types = source("../types/index.ts");
    const card = source("../components/FindingProofCard.tsx");
    const triage = source("../views/TriageView.tsx");
    const translations = extraTranslationDictionariesJson;
    expect(types).toContain("input_dependence: FindingProofClaim<InputDependenceDetermination>");
    expect(types).toContain('"input_independent_fault"');
    expect(types).toContain('"review_harness_usage"');
    expect(types).toContain('"target_frames_fault"');
    expect(card).toContain("claim: proof.input_dependence");
    expect(triage).toContain('"input_independent_fault"');
    for (const key of [
      "triage.disposition.input_independent_fault",
      "findingProof.inputDependence",
      "findingProof.value.input_independent",
      "findingProof.value.size_or_content_sensitive",
      "findingProof.value.input_dependent",
      "findingProof.detail.input_dependence_not_run",
      "findingProof.detail.input_dependence_independent",
      "findingProof.detail.input_dependence_sensitive",
      "findingProof.detail.input_dependence_dependent",
      "findingProof.detail.input_dependence_inconclusive",
      "findingProof.detail.input_dependence_reviewed",
      "triage.acceptUsage",
      "triage.holdUsage",
      "triage.pushHeld",
    ]) {
      expect(translations.split(`"${key}"`).length - 1).toBe(2);
    }
  });

  it("keeps English and Chinese proof labels paired", () => {
    const translations = extraTranslationDictionariesJson;
    expect(translations).toContain('"findingProof.title": "Finding Proof"');
    expect(translations).toContain('"findingProof.title": "发现证据"');
  });
});
