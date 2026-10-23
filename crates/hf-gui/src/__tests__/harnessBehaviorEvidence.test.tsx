import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { HarnessBehaviorEvidence, type HarnessBehaviorReport } from "../components/HarnessBehaviorEvidence";

describe("HarnessBehaviorEvidence", () => {
  it("keeps unavailable target evidence separate from measured contamination", () => {
    const report: HarnessBehaviorReport = {
      input_sensitivity: { status: "pass", detail: "A and B differ" },
      entry_rejection: { status: "suspect", detail: "Possible early rejection" },
      repeated_input_stability: { status: "pass", detail: "Fresh A is stable" },
      persistent_state: { status: "suspect", detail: "A-B-A changed A" },
      target_coverage_growth: { status: "unavailable", detail: "No target-only measurement" },
    };
    const html = renderToStaticMarkup(<I18nProvider><HarnessBehaviorEvidence report={report} /></I18nProvider>);
    for (const label of ["Input sensitivity", "Entry and rejection", "Repeated-input stability", "Persistent state", "Target coverage growth"]) {
      expect(html).toContain(label);
    }
    expect(html).toContain("A-B-A changed A");
    expect(html).toContain("No target-only measurement");
    expect(html).toContain("Unavailable");
    expect(html).toContain("Needs review");
  });
});
