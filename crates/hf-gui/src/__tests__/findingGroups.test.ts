import { expect, it } from "vitest";
import { groupFindings } from "../lib/findingGroups";

const item = (id: string, run: string, signature: string, target = "t1") =>
  ({ crash: { id, run_id: run, stack_signature: signature }, target_id: target });

it("groups findings with the same target and stack signature, keeping queue order", () => {
  const groups = groupFindings([
    item("c1", "r1", "sigA"),
    item("c2", "r1", "sigB"),
    item("c3", "r2", "sigA"),
    item("c4", "r3", "sigA"),
  ]);
  expect(groups.map(g => g.representative.crash.id)).toEqual(["c1", "c2"]);
  expect(groups[0].members.map(m => m.crash.id)).toEqual(["c1", "c3", "c4"]);
  expect(groups[0].runCount).toBe(3);
  expect(groups[1].members).toHaveLength(1);
});

it("never merges findings without a signature or from different targets", () => {
  const groups = groupFindings([
    item("c1", "r1", ""),
    item("c2", "r2", ""),
    item("c3", "r1", "sigA", "t1"),
    item("c4", "r1", "sigA", "t2"),
  ]);
  expect(groups).toHaveLength(4);
});
