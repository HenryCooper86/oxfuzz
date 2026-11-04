import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { enExtra } from "../i18n.extra";

const harness = readFileSync(new URL("../views/HarnessView.tsx", import.meta.url), "utf8");
const pipeline = readFileSync(new URL("../providers/pipeline.ts", import.meta.url), "utf8");

it("orders the harness steps so the one-click build covers everything before approval", () => {
  const seeds = harness.indexOf('title={t("harness.stepSeedsTitle")}');
  const approve = harness.indexOf('title={t("harness.stepApproveTitle")}');
  expect(seeds).toBeGreaterThan(-1);
  expect(seeds).toBeLessThan(approve);
  expect(harness.slice(seeds - 200, seeds)).toContain("number={4}");
  expect(harness.slice(approve - 200, approve)).toContain("number={5}");
  expect(pipeline).toContain('steps: ["harness", "compile", "smoke", "seeds", "approve"]');
});

it("shows the approval evidence once and does not dim a finished step", () => {
  expect(harness).toMatch(/promotionStatus === "done" && \(\s*<div className="mt-2">\s*<HarnessApprovalEvidence/);
  const step = harness.slice(harness.indexOf("function Step("));
  expect(step).not.toMatch(/opacity: disabled \?/);
});

it("gives one consistent instruction when the smoke test finds crashes", () => {
  expect(enExtra["harness.smokeCrashes"]).not.toMatch(/before approval/);
  expect(enExtra["harness.smokeCrashes"]).toMatch(/approve/i);
});
