import { describe, it, expect } from "vitest";
import { applyMode } from "../views/ChatView";

describe("applyMode", () => {
  it("sends the message unchanged in auto mode", () => {
    expect(applyMode("find bugs in parse_image", "auto")).toBe("find bugs in parse_image");
  });

  it("prepends a planning instruction in plan mode", () => {
    const out = applyMode("find bugs in parse_image", "plan");
    expect(out).toContain("[Plan mode]");
    expect(out).toContain("step-by-step plan");
    // The user's original message is preserved at the end.
    expect(out.endsWith("find bugs in parse_image")).toBe(true);
  });
});
