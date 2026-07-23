import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

const CALL_SITES = [
  "../views/RunView.tsx",
  "../views/HarnessView.tsx",
  "../views/FeatureViews.tsx",
] as const;

describe("FuzzingPolicyNotice state naming", () => {
  // The notice renders only where the policy is absent, so its two states are
  // "still loading" and "load settled, policy unavailable". It previously took
  // the hook's `loaded` flag directly, which meant `loaded === true` selected
  // the red failure branch -- a boolean that reads as healthy while rendering
  // an error. The prop now names the state it is actually in.
  it("takes an explicit state union rather than an inverted boolean", () => {
    const notice = source("../components/FuzzingPolicyNotice.tsx");
    expect(notice).toContain('state: "loading" | "unavailable"');
    expect(notice).not.toMatch(/\bloaded\b/);
  });

  it("keys the failure branch off the unavailable state", () => {
    const notice = source("../components/FuzzingPolicyNotice.tsx");
    expect(notice).toMatch(/const unavailable = state === "unavailable"/);
    expect(notice).toContain("fuzzing.policyUnavailable");
    expect(notice).toContain("fuzzing.policyLoading");
  });

  it("maps the settled-load flag to a named state at every call site", () => {
    for (const path of CALL_SITES) {
      const view = source(path);
      expect(view).toContain(
        'state={fuzzingPolicyLoaded ? "unavailable" : "loading"}',
      );
      expect(view).not.toMatch(/<FuzzingPolicyNotice[^>]*\bloaded=/);
    }
  });

  it("keeps the notice guarded by the absent-policy condition", () => {
    for (const path of CALL_SITES) {
      expect(source(path)).toMatch(
        /\{!fuzzingSettings && \(\s*<FuzzingPolicyNotice/,
      );
    }
  });
});
