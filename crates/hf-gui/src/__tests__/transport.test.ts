import { describe, it, expect } from "vitest";
import { isTauriEnvironment } from "../lib/transport";

describe("transport", () => {
  it("isTauriEnvironment returns false in test env", () => {
    expect(isTauriEnvironment()).toBe(false);
  });
});