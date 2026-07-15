import { describe, expect, it } from "vitest";
import { buildRunComparisons } from "../lib/runComparison";
import type { RunHistoryItem } from "../types";

function run(
  id: string,
  comparisonKey: string | null,
  revision: string,
  edges: number,
): RunHistoryItem {
  return {
    id,
    project_root: "/project",
    target: id.startsWith("parser") ? "parse" : "decode",
    comparison_key: comparisonKey,
    engine: "LibFuzzer",
    status: "Done",
    started_at: `2026-07-11T00:00:0${id.length}Z`,
    ended_at: null,
    duration_secs: 60,
    crashes: 0,
    edges,
    execs: 100,
    harness_rev: revision,
    binary_rev: "binary-revision",
    evidence_dir: `runs/${id}/out`,
  };
}

describe("buildRunComparisons", () => {
  it("compares against the last matching experiment, not an unrelated adjacent run", () => {
    const runs = [
      run("parser-old", "parser-60", "rev-a", 100),
      run("decoder", "decoder-60", "rev-x", 10),
      run("parser-new", "parser-60", "rev-b", 70),
    ];

    const result = buildRunComparisons(runs);
    expect(result.baselineAt).toEqual([-1, -1, 0]);
    expect(result.changeAt).toEqual([false, false, true]);
    expect(result.regressAt).toEqual([false, false, true]);
  });

  it("does not call a different engine or budget a regression", () => {
    const runs = [
      run("parser-a", "parser-libfuzzer-60", "rev-a", 100),
      run("parser-b", "parser-afl-60", "rev-b", 20),
      run("parser-c", "parser-libfuzzer-600", "rev-c", 10),
    ];

    const result = buildRunComparisons(runs);
    expect(result.baselineAt).toEqual([-1, -1, -1]);
    expect(result.regressAt).toEqual([false, false, false]);
  });
});
