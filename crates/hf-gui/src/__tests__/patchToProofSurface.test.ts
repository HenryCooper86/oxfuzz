import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("service-owned Patch-to-Proof surface", () => {
  it("declares the complete serialized remediation operation view", () => {
    const types = source("../types/index.ts");
    expect(types).toContain("interface RemediationOperationView");
    expect(types).toContain("interface SandboxVerificationEvidence");
    expect(types).toContain("interface VerificationStageEvidence");
    expect(types).toContain("type RemediationOperationStatus");
    expect(types).toContain("type RemediationOperationStage");
    expect(types).toContain("original_replay");
    expect(types).toContain("patch_build");
    expect(types).toContain("patched_replay");
    expect(types).toContain("regression");
    expect(types).toContain("follow_up_fuzz");
    // The card's fix verification can now cite a remediation record.
    expect(types).toContain("remediation_record");
  });

  it("renders the service status and never derives a verdict from the stages", () => {
    const panel = source("../components/PatchToProofPanel.tsx");
    expect(panel).toContain("operation.status");
    expect(panel).toContain("operation.current_stage");
    // Every stage row is read straight from the persisted service evidence.
    expect(panel).toContain("verification.original_replay");
    expect(panel).toContain("verification.follow_up_fuzz");
    // No presentation-layer derivation of the terminal determination.
    expect(panel).not.toMatch(/status\s*=\s*["']verified["']/);
    expect(panel).not.toContain("deriveRemediationStatus");
    expect(panel).not.toContain("every((stage) => stage.status === \"passed\")");
  });

  it("requires an explicit confirmation before any sandbox execution", () => {
    const panel = source("../components/PatchToProofPanel.tsx");
    // Approval is a distinct operator step, and verification starts only from
    // an approved operation.
    expect(panel).toContain('invoke("approve_remediation_operation"');
    expect(panel).toContain('invoke("start_remediation_verification"');
    expect(panel).toContain("patchToProof.confirmVerify");
    const approveIndex = panel.indexOf('invoke("approve_remediation_operation"');
    const verifyIndex = panel.indexOf('invoke("start_remediation_verification"');
    expect(approveIndex).toBeGreaterThan(-1);
    expect(verifyIndex).toBeGreaterThan(approveIndex);
  });

  it("polls durable status instead of holding the result in memory only", () => {
    const panel = source("../components/PatchToProofPanel.tsx");
    expect(panel).toContain('invoke<RemediationOperationView>("remediation_operation"');
    expect(panel).toContain("setInterval");
  });

  it("mounts the panel on the selected triage finding", () => {
    const triage = source("../views/TriageView.tsx");
    expect(triage).toContain("PatchToProofPanel");
    expect(triage).toContain("findingId={crash.id}");
    expect(triage).toContain("runId={crash.run_id}");
  });

  it("keeps REST and Tauri as transports for the service workflow", () => {
    const transport = source("../lib/httpTransport.ts");
    expect(transport).toContain('path: "/remediation/operations"');
    expect(transport).toContain('path: "/remediation/operations/{operation_id}/approve"');
    expect(transport).toContain('path: "/remediation/operations/{operation_id}/verify"');
    expect(transport).toContain('path: "/remediation/operations/{operation_id}"');
    const commands = source("../../src-tauri/src/commands.rs");
    expect(commands).toContain("pub async fn create_remediation_operation");
    expect(commands).toContain("pub async fn approve_remediation_operation");
    expect(commands).toContain("pub async fn start_remediation_verification");
    expect(commands).toContain("pub async fn remediation_operation");
  });

  it("keeps English and Chinese Patch-to-Proof labels paired", () => {
    const translations = source("../i18n.extra.ts");
    expect(translations).toContain('"patchToProof.title": "Patch to Proof"');
    expect(translations).toContain('"patchToProof.title": "补丁验证"');
    expect(translations).toContain('"patchToProof.stage.original_replay": "Original replay"');
    expect(translations).toContain('"patchToProof.stage.original_replay": "原始回放"');
  });
});
