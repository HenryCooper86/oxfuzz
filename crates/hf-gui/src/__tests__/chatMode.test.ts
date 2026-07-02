import { describe, it, expect } from "vitest";
import { applyMode, normalizeAssistantContent, normalizeChatRole } from "../views/chatHelpers";

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

  it("normalizes persisted role names from desktop and web backends", () => {
    expect(normalizeChatRole("assistant")).toBe("assistant");
    expect(normalizeChatRole("Assistant")).toBe("assistant");
    expect(normalizeChatRole("System")).toBe("system");
    expect(normalizeChatRole("Tool")).toBe("system");
    expect(normalizeChatRole("User")).toBe("user");
    expect(normalizeChatRole("unknown")).toBe("user");
  });

  it("renders final answers from assistant protocol objects without leaking thought text", () => {
    const out = normalizeAssistantContent(
      '{"thought":"ask for project","final":"Hi!\\n\\nWhat would you like to fuzz?"}',
    );
    expect(out).toBe("Hi!\n\nWhat would you like to fuzz?");
  });

  it("recovers final answers when providers emit literal newlines inside protocol JSON", () => {
    const out = normalizeAssistantContent(
      '{"thought":"ask for project","final":"Hi!\n\nWhat would you like to fuzz?"}',
    );
    expect(out).toBe("Hi!\n\nWhat would you like to fuzz?");
  });
});
