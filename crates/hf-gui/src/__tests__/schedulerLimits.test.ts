import { describe, expect, it } from "vitest";
import {
  campaignConcurrencyHierarchy,
  parseCampaignConcurrencyLimits,
} from "../lib/schedulerLimits";

describe("parseCampaignConcurrencyLimits", () => {
  it("accepts both independent caps and their effective minimum", () => {
    expect(
      parseCampaignConcurrencyLimits({
        active_fuzz_campaign_limit: 4,
        scheduler_workflow_dispatch_limit: 2,
        effective_max_concurrent_fuzz_runs: 2,
      }),
    ).toEqual({
      active_fuzz_campaign_limit: 4,
      scheduler_workflow_dispatch_limit: 2,
      effective_max_concurrent_fuzz_runs: 2,
    });
  });

  it("treats the all-zero no-scheduler response as unavailable", () => {
    expect(
      parseCampaignConcurrencyLimits({
        active_fuzz_campaign_limit: 0,
        scheduler_workflow_dispatch_limit: 0,
        effective_max_concurrent_fuzz_runs: 0,
      }),
    ).toBeNull();
  });

  it.each([
    { active_fuzz_campaign_limit: 4, scheduler_workflow_dispatch_limit: 2 },
    {
      active_fuzz_campaign_limit: 4,
      scheduler_workflow_dispatch_limit: 2,
      effective_max_concurrent_fuzz_runs: 4,
    },
    {
      active_fuzz_campaign_limit: 1.5,
      scheduler_workflow_dispatch_limit: 2,
      effective_max_concurrent_fuzz_runs: 1.5,
    },
    {
      active_fuzz_campaign_limit: 0,
      scheduler_workflow_dispatch_limit: 2,
      effective_max_concurrent_fuzz_runs: 0,
    },
  ])("rejects malformed or inconsistent DTOs", (value) => {
    expect(() => parseCampaignConcurrencyLimits(value)).toThrow(
      "Invalid scheduler concurrency limits",
    );
  });
});

describe("campaignConcurrencyHierarchy", () => {
  it("makes the effective run cap primary and keeps its two inputs secondary", () => {
    expect(
      campaignConcurrencyHierarchy({
        active_fuzz_campaign_limit: 4,
        scheduler_workflow_dispatch_limit: 2,
        effective_max_concurrent_fuzz_runs: 2,
      }),
    ).toEqual({
      primary: { kind: "effective", value: 2 },
      supporting: [
        { kind: "active", value: 4, editable: true },
        { kind: "dispatch", value: 2, editable: false },
      ],
    });
  });
});
