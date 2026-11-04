import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

const triage = readFileSync(new URL("../views/TriageView.tsx", import.meta.url), "utf8");
const detail = triage.slice(triage.indexOf("function CrashDetail"));

it("leads the crash detail with the plain-language bug summary and the stack", () => {
  const summary = detail.indexOf("crash.bug_report.title");
  const stack = detail.indexOf("crash.casr.stack");
  const proof = detail.indexOf("<FindingProofCard");
  const patch = detail.indexOf("<PatchToProofPanel");
  expect(summary).toBeGreaterThan(-1);
  expect(summary).toBeLessThan(stack);
  expect(stack).toBeLessThan(proof);
  expect(stack).toBeLessThan(patch);
});

it("keeps proof evidence collapsed and opens fix verification on request", () => {
  expect(detail).toMatch(/<details[^>]*>\s*<summary[^>]*>\{t\("triage\.evidenceDetails"\)\}<\/summary>\s*<FindingProofCard/);
  expect(detail).toMatch(/\{verifyingFix \? <PatchToProofPanel/);
  expect(detail).toContain('t("triage.verifyFix")');
});
