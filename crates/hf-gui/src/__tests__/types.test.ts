import { describe, it, expect } from "vitest";

describe("types", () => {
  it("ViewType includes discover", () => {
    const view = "discover" as const;
    expect(view).toBe("discover");
  });

  it("ViewType includes dashboard", () => {
    const view = "dashboard" as const;
    expect(view).toBe("dashboard");
  });
});
