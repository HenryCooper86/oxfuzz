import { describe, it, expect } from "vitest";
import { pruneToKeys, NO_PROJECT_KEY } from "../lib/projectState";

describe("pruneToKeys", () => {
  it("drops entries for removed projects", () => {
    const map = { "/a": 1, "/b": 2, "/c": 3 };
    const pruned = pruneToKeys(map, ["/a", "/c"]);
    expect(pruned).toEqual({ "/a": 1, "/c": 3 });
    expect("/b" in pruned).toBe(false);
  });

  it("always keeps the no-project bucket", () => {
    const map = { [NO_PROJECT_KEY]: 0, "/gone": 1 };
    expect(pruneToKeys(map, [])).toEqual({ [NO_PROJECT_KEY]: 0 });
  });

  it("returns the same reference when nothing changed (no redundant write)", () => {
    const map = { "/a": 1 };
    expect(pruneToKeys(map, ["/a"])).toBe(map);
  });

  it("clears everything (but the bucket) when no projects remain", () => {
    const map = { "/a": 1, "/b": 2 };
    expect(pruneToKeys(map, [])).toEqual({});
  });
});
