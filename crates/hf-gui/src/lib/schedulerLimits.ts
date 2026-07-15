export interface CampaignConcurrencyLimits {
  active_fuzz_campaign_limit: number;
  scheduler_workflow_dispatch_limit: number;
  effective_max_concurrent_fuzz_runs: number;
}

export interface CampaignConcurrencyHierarchy {
  primary: { kind: "effective"; value: number };
  supporting: [
    { kind: "active"; value: number; editable: true },
    { kind: "dispatch"; value: number; editable: false },
  ];
}

/**
 * Describe the operator-facing hierarchy for the three related scheduler caps.
 * The effective minimum is the actual run ceiling, while the editable campaign
 * cap and fixed dispatch cap explain where that ceiling comes from.
 */
export function campaignConcurrencyHierarchy(
  limits: CampaignConcurrencyLimits,
): CampaignConcurrencyHierarchy {
  return {
    primary: {
      kind: "effective",
      value: limits.effective_max_concurrent_fuzz_runs,
    },
    supporting: [
      { kind: "active", value: limits.active_fuzz_campaign_limit, editable: true },
      {
        kind: "dispatch",
        value: limits.scheduler_workflow_dispatch_limit,
        editable: false,
      },
    ],
  };
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/**
 * Validate the service DTO before using it for operator-facing safety limits.
 * An all-zero response is the REST API's explicit "scheduler unavailable"
 * representation; mixed zero/non-zero or a wrong derived minimum is corrupt.
 */
export function parseCampaignConcurrencyLimits(
  value: unknown,
): CampaignConcurrencyLimits | null {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid scheduler concurrency limits");
  }

  const candidate = value as Partial<CampaignConcurrencyLimits>;
  const active = candidate.active_fuzz_campaign_limit;
  const dispatch = candidate.scheduler_workflow_dispatch_limit;
  const effective = candidate.effective_max_concurrent_fuzz_runs;
  if (
    !isNonNegativeInteger(active) ||
    !isNonNegativeInteger(dispatch) ||
    !isNonNegativeInteger(effective)
  ) {
    throw new Error("Invalid scheduler concurrency limits");
  }
  if (active === 0 && dispatch === 0 && effective === 0) return null;
  if (active < 1 || dispatch < 1 || effective !== Math.min(active, dispatch)) {
    throw new Error("Invalid scheduler concurrency limits");
  }
  return {
    active_fuzz_campaign_limit: active,
    scheduler_workflow_dispatch_limit: dispatch,
    effective_max_concurrent_fuzz_runs: effective,
  };
}
