import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { HarnessApprovalEvidence } from "../components/HarnessApprovalEvidence";
import { RunOutcomeNotice } from "../components/RunEvidenceSummary";
import { enExtra, zhExtra } from "../i18n.extra";
import { parseSummary } from "../providers/runOutputValidation";
import type { HarnessReviewItem } from "../types";

// Regressions for what a walk through every sidebar destination turned up on
// 2026-11-12: a libFuzzer run that stopped at its first crash looked like a
// one-minute campaign at zero executions per second, and two labels claimed
// more than the product does.

const source = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

const crashedSmoke: HarnessReviewItem = {
  harness_id: "h-1",
  target_id: "t-1",
  project_root: "/proj",
  target_symbol: "decode_utf8",
  target_selector: "utf8.c::decode_utf8",
  engine: "LibFuzzer",
  language: "C",
  status: "SmokeFailed",
  build_output: "fuzz_decode_utf8",
  smoke_passed: false,
  smoke_crashes: 1,
  smoke_execs_per_sec: 0,
  needs_review: true,
  next_action: "promote",
  source_preview: "int LLVMFuzzerTestOneInput...",
  ai_review: null,
  source_sha256: null,
  binary_sha256: null,
  lint: [],
};

describe("a run that stops at its first crash", () => {
  it("carries the service's first-crash flag through summary validation", () => {
    expect(parseSummary({ edges: 7, crashes: 1, execs: 0, stopped_at_first_crash: true })?.stoppedAtFirstCrash).toBe(true);
    expect(parseSummary({ edges: 7, crashes: 1, execs: 0 })?.stoppedAtFirstCrash).toBe(false);
  });

  it("says why the requested budget was not used", () => {
    const stopped = renderToStaticMarkup(
      <I18nProvider><RunOutcomeNotice crashes={1} stoppedAtFirstCrash /></I18nProvider>,
    );
    expect(stopped).toContain("stops at the first crash");

    const ordinary = renderToStaticMarkup(
      <I18nProvider><RunOutcomeNotice crashes={1} /></I18nProvider>,
    );
    expect(ordinary).not.toContain("stops at the first crash");
  });

  it("does not print an unmeasured smoke rate as zero executions per second", () => {
    const html = renderToStaticMarkup(
      <I18nProvider><HarnessApprovalEvidence item={crashedSmoke} /></I18nProvider>,
    );
    expect(html).toContain("found 1 crash(es)");
    expect(html).not.toContain("0 exec/s");

    const measured = renderToStaticMarkup(
      <I18nProvider><HarnessApprovalEvidence item={{ ...crashedSmoke, smoke_execs_per_sec: 512 }} /></I18nProvider>,
    );
    expect(measured).toContain("512 exec/s");
  });
});

describe("the Triage detail pane", () => {
  it("cannot be widened past the window by a long crash file name", () => {
    // A flex item's minimum width is its content's, so honggfuzz's
    // SIGABRT.PC...STACK...fuzz names pushed the pane off the right edge.
    const triage = source("../views/TriageView.tsx");
    expect(triage).toContain('<div className="surface-card flex-1 min-w-0" style={{ padding: "var(--space-md)" }}>');
  });
});

describe("labels that claimed more than the product does", () => {
  it("does not attribute every approval request to the agent", () => {
    // Composing a report asks through the same dialog as a chat turn.
    expect(enExtra["approval.title"]).toBe("oxfuzz needs your approval");
    expect(zhExtra["approval.title"]).toBe("oxfuzz 需要你的批准");
  });


  it("names a pending closeout instead of calling a triaged run unprocessed", () => {
    const [english, chinese] = [enExtra, zhExtra];
    expect(english["runs.healthUnprocessed"]).toBe("Closeout pending");
    expect(chinese["runs.healthUnprocessed"]).toBe("收尾未完成");
  });

  it("marks Go and Python as discovery-only in About", () => {
    const about = source("../components/settings/AboutTab.tsx");
    expect(about).not.toMatch(/<Badge>(Go|Python)<\/Badge>/);
    expect(about).toContain("settings.about.discoveryOnly");
    const [english, chinese] = [enExtra, zhExtra];
    expect(english["settings.about.discoveryOnly"]).toBe("{language} (discovery only)");
    expect(chinese["settings.about.discoveryOnly"]).toBe("{language}（仅发现目标）");
  });
});
