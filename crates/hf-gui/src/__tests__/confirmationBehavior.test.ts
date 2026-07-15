import { describe, expect, it } from "vitest";

import {
  confirmationFocusTarget,
  confirmationKeyboardAction,
} from "../lib/confirmationBehavior";

describe("confirmation dialog safety", () => {
  it("focuses cancel for destructive confirmations", () => {
    expect(confirmationFocusTarget(true)).toBe("cancel");
    expect(confirmationFocusTarget(false)).toBe("confirm");
  });

  it("does not turn a global Enter key into destructive confirmation", () => {
    expect(confirmationKeyboardAction("Enter")).toBeNull();
    expect(confirmationKeyboardAction("Escape")).toBe("cancel");
  });
});
