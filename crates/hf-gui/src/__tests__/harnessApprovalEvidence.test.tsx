import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { HarnessApprovalEvidence } from "../components/HarnessApprovalEvidence";
import type { HarnessReviewItem } from "../types";

const base: HarnessReviewItem = {
  harness_id: "h-1",
  target_id: "t-1",
  project_root: "/proj",
  target_symbol: "parse_packet",
  target_selector: "parser.c::parse_packet",
  engine: "LibFuzzer",
  language: "C",
  status: "SmokePassed",
  build_output: "fuzz_parse_packet",
  smoke_passed: true,
  smoke_execs_per_sec: 512.0,
  needs_review: true,
  next_action: "promote",
  source_preview: "int LLVMFuzzerTestOneInput...",
  ai_review: {
    exercises_target: true,
    safe_to_execute: true,
    reasons: ["drives parse_packet with fuzz input"],
    reviewed_at: "2026-09-03T09:00:00Z",
  },
  source_sha256: null,
  binary_sha256: null,
  lint: [],
};

function withItem(overrides: Partial<HarnessReviewItem>) {
  return { ...base, ...overrides };
}

describe("HarnessApprovalEvidence", () => {
  it("renders the review verdict, reasons, digests, and smoke stats together", () => {
    const html = renderToStaticMarkup(
      <I18nProvider>
        <HarnessApprovalEvidence
          item={withItem({
            source_sha256: "a".repeat(64),
            binary_sha256: "b".repeat(64),
            lint: [
              {
                severity: "warning",
                rule: "no-strlen-on-fuzz-data",
                message: "fuzz input is not NUL-terminated",
                line: 7,
              },
            ],
          })}
        />
      </I18nProvider>,
    );

    expect(html).toContain("drives parse_packet with fuzz input");
    // Digests are shown truncated, with the full value on the title attr.
    expect(html).toContain("aaaaaaaaaaaaaaaa...");
    expect(html).toContain("bbbbbbbbbbbbbbbb...");
    expect(html).toContain("a".repeat(64));
    expect(html).toContain("no-strlen-on-fuzz-data");
    expect(html).toContain("512");
  });

  it("states absent evidence rather than implying approval", () => {
    const absent = renderToStaticMarkup(
      <I18nProvider>
        <HarnessApprovalEvidence
          item={withItem({ ai_review: null, smoke_passed: false, smoke_execs_per_sec: 0 })}
        />
      </I18nProvider>,
    );
    const present = renderToStaticMarkup(
      <I18nProvider>
        <HarnessApprovalEvidence item={withItem({})} />
      </I18nProvider>,
    );

    // Locale-agnostic: the no-review badge exists exactly when no review is
    // persisted, and absent digests render the explicit placeholder.
    expect(absent).toContain("harness-evidence-no-review");
    expect(present).not.toContain("harness-evidence-no-review");
    expect(absent).toContain("--");
  });

  it("shows a bypassed review as a bypass, never as a model verdict", () => {
    const html = renderToStaticMarkup(
      <I18nProvider>
        <HarnessApprovalEvidence
          item={withItem({
            ai_review: {
              exercises_target: false,
              safe_to_execute: false,
              reasons: ["the operator bypassed the independent LLM pre-execution review"],
              reviewed_at: "2026-10-09T09:00:00Z",
              bypass_source: "cli_flag",
            },
          })}
        />
      </I18nProvider>,
    );

    expect(html).toContain("harness-evidence-bypassed-review");
    expect(html).toContain("--no-llm-review");
    // The bypass marker replaces the boolean verdict badges: no model
    // affirmed either property, so neither may render as a verdict.
    expect(html).not.toContain("exercises target");
    expect(html).not.toContain("safe to execute");
    expect(html).not.toContain("harness-evidence-no-review");
  });

  it("marks blocking lint findings with the error styling hook", () => {
    const html = renderToStaticMarkup(
      <I18nProvider>
        <HarnessApprovalEvidence
          item={withItem({
            lint: [
              {
                severity: "error",
                rule: "no-sleep",
                message: "do not sleep in the fuzz loop",
                line: 3,
              },
            ],
          })}
        />
      </I18nProvider>,
    );

    expect(html).toContain("no-sleep");
    expect(html).toContain("error");
  });
});
