import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { enExtra, zhExtra } from "../i18n.extra";
import { parseSummary } from "../providers/runOutputValidation";

// Regressions for the run figures a check against retained engine evidence
// found on 2026-11-19: total executions were collected for every engine but
// shown only for syzkaller, and syzkaller's "Executed" card read the rate
// field, which carried a count for that one engine.

const source = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

describe("total executions", () => {
  it("are read from the service's execs_total", () => {
    expect(parseSummary({ edges: 11, crashes: 3, execs: 16637.22, execs_total: 998483 })?.executions).toBe(998483);
    expect(parseSummary({ edges: 11, crashes: 3, execs: 16637.22 })?.executions).toBeNull();
  });

  it("reject a malformed total instead of showing it", () => {
    expect(parseSummary({ edges: 11, crashes: 3, execs: 1, execs_total: -4 })).toBeNull();
    expect(parseSummary({ edges: 11, crashes: 3, execs: 1, execs_total: "many" })).toBeNull();
  });

  it("are shown for every engine, not only syzkaller", () => {
    const run = source("../views/RunView.tsx");
    expect(run).toContain('label={t("run.totalExecutions")} value={summary.executions}');
    // The rate field is never labelled as a count.
    expect(run).not.toContain('label={t("run.executed")} value={summary.execs}');
  });

  it("appear in run history and comparison", () => {
    const runs = source("../views/RunsView.tsx");
    expect(runs).toContain("runs.totalExecutions");
    expect(runs).toContain("r.execs_total");
  });

  it("are carried by the browser transport", () => {
    expect(source("../lib/httpTransport.ts")).toContain("execs_total: finiteMetric(completed.execs_total)");
  });

  it("call the per-run crash figure what it is: inputs the engine retained", () => {
    // honggfuzz saved 2972 crashing inputs of one bug; "Crashes: 2972" read as
    // 2972 bugs next to Triage's single finding.
    expect(enExtra["runs.crashes"]).toBe("Crashing inputs");
    expect(zhExtra["runs.crashes"]).toBe("崩溃输入");
  });

  it("are labelled in both languages", () => {
    for (const key of ["run.totalExecutions", "runs.totalExecutions", "run.notMeasured"]) {
      expect(enExtra[key], key).toBeTruthy();
      expect(zhExtra[key], key).toBeTruthy();
    }
  });
});
