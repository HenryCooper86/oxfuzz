import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PolicyDecisionList } from "../components/PolicyDecisionList";

describe("PolicyDecisionList", () => {
  it("renders every recorded field of a guardrail decision", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList
        decisions={[
          {
            id: "decision-1",
            decided_at: "2026-07-30T09:15:00Z",
            action: "run_fuzzer",
            risk_tier: "high",
            decision: "approved",
            origin: "run_fuzzer",
            project: "/projects/libjson",
            detail: "operator approved a 60m campaign",
          },
        ]}
        emptyLabel="No decisions recorded"
      />,
    );

    expect(html).toContain("run_fuzzer");
    expect(html).toContain("high");
    expect(html).toContain("approved");
    expect(html).toContain("libjson");
    expect(html).toContain("operator approved a 60m campaign");
  });

  it("renders a distinct empty state rather than an empty list", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList decisions={[]} emptyLabel="No decisions recorded" />,
    );

    expect(html).toContain("No decisions recorded");
  });

  it("omits the optional fields when the record has none", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList
        decisions={[
          {
            id: "decision-2",
            decided_at: "2026-07-30T09:16:00Z",
            action: "discover",
            risk_tier: "low",
            decision: "allowed",
            origin: "discover",
            project: null,
            detail: null,
          },
        ]}
        emptyLabel="No decisions recorded"
      />,
    );

    expect(html).toContain("discover");
    expect(html).not.toContain("null");
    expect(html).not.toContain("undefined");
  });
});
