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
            // Distinct from `action` so the assertions below can show each
            // field renders independently, rather than one string matching
            // both.
            origin: "chat_agent",
            project: "/projects/libjson",
            detail: "operator approved a 60m campaign",
          },
        ]}
        emptyLabel="No decisions recorded"
      />,
    );

    expect(html).toContain("run_fuzzer");
    expect(html).toContain("chat_agent");
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
    // PolicyDecisionList.tsx:75 emits the " -- " separator only ahead of a
    // present `detail`; with `detail: null` it must not appear. (Asserting
    // `.not.toContain("null")`/`"undefined"` would pass even with no guard
    // at all, since renderToStaticMarkup never emits those literal strings
    // for null/undefined children -- this checks the guard's actual output
    // instead.)
    expect(html).not.toContain(" -- ");
    // PolicyDecisionList.tsx:69-71 wraps a present `project` in exactly this
    // span; with `project: null` it must not appear.
    expect(html).not.toContain('class="text-xs text-text-muted truncate"');
  });
});
