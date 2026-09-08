import { expect, it } from "vitest";
import { candidateTargetSelector, matchesTargetSelection } from "../lib/harnessScope";
import type { TargetCandidate } from "../types";

it.each([
  ["/project", "/project/src/parser.cpp", "src/parser.cpp::ns::parse"],
  ["C:\\project\\", "C:\\project\\src\\parser.cpp", "src\\parser.cpp::ns::parse"],
  ["/project", "src/parser.cpp", "src/parser.cpp::ns::parse"],
  ["/project", "/project-other/parser.cpp", "/project-other/parser.cpp::ns::parse"],
])("retains source spelling and whole namespaced symbols for %s", (root, file, expected) => {
  const candidate = { project_root: root, location: { file }, symbol: "ns::parse" } as TargetCandidate;
  expect(candidateTargetSelector(candidate)).toBe(expected);
});

it("requires the complete qualified selection while retaining plain-symbol selection", () => {
  expect(matchesTargetSelection("ns::parse", "second.cpp::ns::parse", "first.cpp::ns::parse")).toBe(false);
  expect(matchesTargetSelection("ns::parse", "second.cpp::ns::parse", "second.cpp::ns::parse")).toBe(true);
  expect(matchesTargetSelection("ns::parse", "second.cpp::ns::parse", "ns::parse")).toBe(true);
});
