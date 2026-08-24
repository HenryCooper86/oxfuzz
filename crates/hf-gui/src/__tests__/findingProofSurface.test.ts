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

  it("reloads the same workbench proof after triage and renders it", () => {
    const triage = source("../views/TriageView.tsx");
    expect(triage).toContain('invoke<WorkbenchDashboard>("workbench_dashboard"');
    expect(triage).toContain("proof={proofs[crashes[selected].id]}");
    expect(triage).not.toContain("deriveFindingProof");
  });

  it("keeps REST and Tauri as transports for the service dashboard DTO", () => {
    expect(source("../lib/httpTransport.ts")).toContain('path: "/workbench/dashboard"');
    expect(source("../../src-tauri/src/commands.rs")).toContain(
      "Result<hf_service::WorkbenchDashboard, String>",
    );
    expect(source("../../../hf-web/src/router.rs")).toContain(
      ".workbench_dashboard(project.as_deref(), opt_target(req.target.as_ref()))",
    );
  });

  it("keeps English and Chinese proof labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"findingProof.title": "Finding Proof"');
    expect(translations).toContain('"findingProof.title": "发现证据"');
  });
});
