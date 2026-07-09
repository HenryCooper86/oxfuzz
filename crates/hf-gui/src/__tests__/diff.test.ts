import { describe, it, expect } from "vitest";
import { lineDiff } from "../lib/diff";

describe("lineDiff", () => {
  it("marks unchanged lines equal", () => {
    const d = lineDiff("a\nb\nc", "a\nb\nc");
    expect(d.every((l) => l.type === "eq")).toBe(true);
  });

  it("detects an added line", () => {
    const d = lineDiff("a\nc", "a\nb\nc");
    expect(d.find((l) => l.type === "add")?.text).toBe("b");
    expect(d.filter((l) => l.type === "eq").map((l) => l.text)).toEqual(["a", "c"]);
  });

  it("detects a removed line", () => {
    const d = lineDiff("a\nb\nc", "a\nc");
    expect(d.find((l) => l.type === "del")?.text).toBe("b");
  });

  it("handles a changed line as a delete + add", () => {
    const d = lineDiff("x\nold\ny", "x\nnew\ny");
    expect(d.some((l) => l.type === "del" && l.text === "old")).toBe(true);
    expect(d.some((l) => l.type === "add" && l.text === "new")).toBe(true);
  });
});
