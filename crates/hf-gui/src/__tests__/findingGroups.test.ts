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

it("groups by the service's bug key when present, across differing signatures", () => {
  // One overflow: symbolized in one run, unsymbolized (run-specific path) in two.
  const keyed = (id: string, run: string, signature: string, bug_key: string) =>
    ({ ...item(id, run, signature), bug_key });
  const groups = groupFindings([
    keyed("c1", "r3", "/work/utf8.c:31:27", "t1:c1"),
    keyed("c2", "r2", "/work/runs/r2/input/harness+0x111dfc", "t1:c1"),
    keyed("c3", "r1", "/work/runs/r1/input/harness+0x111dfc", "t1:c1"),
    keyed("c4", "r1", "/work/parser.c:88:3", "t1:c4"),
  ]);
  expect(groups.map(g => g.members.length)).toEqual([3, 1]);
  expect(groups[0].runCount).toBe(3);
});
