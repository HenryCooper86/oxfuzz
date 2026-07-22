import { describe, expect, it } from "vitest";
import {
  buildPeriodicCanReplayPlan,
  type PeriodicCanReplayInput,
} from "../lib/automotiveFrameSender";

const base: PeriodicCanReplayInput = {
  arbitrationId: "0x123",
  payload: "00 11",
  intervalMs: 100,
  count: 3,
  limits: {
    max_packets: 100,
    max_input_bytes: 1_048_576,
    max_payload_bytes: 1_048_576,
    max_duration_secs: 60,
    max_rate_per_second: 100,
    max_output_bytes: 1_048_576,
    max_mem_mb: 512,
    max_cpus: 1,
  },
};

describe("periodic CAN replay preflight", () => {
  it("builds a normalized bounded replay plan", () => {
    const plan = buildPeriodicCanReplayPlan(base);
    expect(plan).not.toBeNull();
    expect(plan?.steps).toHaveLength(3);
    expect(plan?.steps[0].delay_micros).toBe(0);
    expect(plan?.steps[1].delay_micros).toBe(100_000);
    expect(plan?.steps[0].message.payload_hex).toBe("0011");
    expect(plan?.steps[0].message.fields.arbitration_id).toBe("291");
  });

  it("rejects counts that are unsafe to allocate", () => {
    for (const count of [0, 1.5, Number.POSITIVE_INFINITY, 101, Number.MAX_SAFE_INTEGER]) {
      expect(buildPeriodicCanReplayPlan({ ...base, count })).toBeNull();
    }
  });

  it("rejects invalid classic CAN ids and payloads", () => {
    expect(buildPeriodicCanReplayPlan({ ...base, arbitrationId: "not-an-id" })).toBeNull();
    expect(buildPeriodicCanReplayPlan({ ...base, arbitrationId: "0x20000000" })).toBeNull();
    expect(
      buildPeriodicCanReplayPlan({ ...base, payload: "00 01 02 03 04 05 06 07 08" }),
    ).toBeNull();
  });

  it("rejects plans outside duration, aggregate payload, or peak-rate limits", () => {
    expect(buildPeriodicCanReplayPlan({ ...base, intervalMs: 30_001 })).toBeNull();
    expect(
      buildPeriodicCanReplayPlan({
        ...base,
        limits: { ...base.limits, max_payload_bytes: 5 },
      }),
    ).toBeNull();
    expect(
      buildPeriodicCanReplayPlan({
        ...base,
        intervalMs: 0,
        limits: { ...base.limits, max_rate_per_second: 2 },
      }),
    ).toBeNull();
  });
});
