import { describe, expect, it } from "vitest";
import { acknowledgeRecoveryWithRefresh } from "../lib/scheduleRecovery";

describe("acknowledgeRecoveryWithRefresh", () => {
  it("does nothing when confirmation is declined", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => false,
      acknowledge: async () => calls.push("acknowledge"),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(false);
    expect(calls).toEqual([]);
  });

  it("acknowledges before refreshing all automation state", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => true,
      acknowledge: async (occurrenceId) =>
        calls.push(`acknowledge:${occurrenceId}`),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(true);
    expect(calls).toEqual(["acknowledge:occ-1", "refresh"]);
  });
});
