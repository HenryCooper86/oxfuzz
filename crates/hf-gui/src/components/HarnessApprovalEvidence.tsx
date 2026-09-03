import { FileWarning, ShieldCheck, ShieldX } from "lucide-react";
import { Badge } from "./ui";
import { useI18n, type TParams } from "../i18nContext";
import type { HarnessReviewItem } from "../types";

type Translate = (key: string, params?: TParams) => string;

function localized(t: Translate, key: string, fallback: string): string {
  const value = t(key);
  return value === key ? fallback : value;
}

function digest(value: string | null): string {
  if (!value) return "--";
  return value.length > 16 ? `${value.slice(0, 16)}...` : value;
}

/**
 * The evidence an approver needs in one glance before promoting a harness:
 * the independent review verdict bound to this exact source and binary, the
 * digest binding itself, the lexical lint findings for this source, and the
 * smoke statistics. Missing evidence is stated, never implied -- an absent
 * review reads as "no review persisted", not as approval.
 */
export function HarnessApprovalEvidence({ item }: { item: HarnessReviewItem }) {
  const { t } = useI18n();
  const review = item.ai_review;
  const blockingLint = item.lint.filter((finding) => finding.severity === "error");

  return (
    <section
      className="rounded-md border border-border"
      style={{
        padding: "var(--space-md)",
        background: "var(--surface-secondary)",
        fontFamily: "var(--font-sans)",
      }}
      data-testid="harness-approval-evidence"
    >
      <div className="flex items-center gap-2 text-xs font-semibold">
        <ShieldCheck size={14} className="text-text-muted" />
        {localized(
          t,
          "harness.evidence.title",
          "Qualification evidence for this exact revision"
        )}
      </div>

      {/* Independent review */}
      <div className="mt-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted uppercase" style={{ fontWeight: 600 }}>
            {localized(t, "harness.evidence.review", "Independent review")}
          </span>
          {review ? (
            <>
              <Badge variant={review.exercises_target ? "success" : "error"}>
                {localized(t, "harness.evidence.exercises", "exercises target")}:{" "}
                {String(review.exercises_target)}
              </Badge>
              <Badge variant={review.safe_to_execute ? "success" : "error"}>
                {localized(t, "harness.evidence.safe", "safe to execute")}:{" "}
                {String(review.safe_to_execute)}
              </Badge>
            </>
          ) : (
            <span
              className="text-xs px-2 py-0.5 rounded-sm"
              data-testid="harness-evidence-no-review"
              style={{
                background: "var(--surface-active)",
                border: "1px solid var(--warning, #e5a000)",
                color: "var(--warning, #e5a000)",
              }}
            >
              {localized(
                t,
                "harness.evidence.noReview",
                "no independent review persisted"
              )}
            </span>
          )}
        </div>
        {review && review.reasons.length > 0 && (
          <ul className="text-xs text-text-secondary mt-1" style={{ paddingLeft: 16 }}>
            {review.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
      </div>

      {/* Digest binding */}
      <div
        className="text-xs mt-3 flex flex-wrap gap-x-6 gap-y-1"
        style={{ fontFamily: "var(--font-mono)" }}
      >
        <span>
          <span className="text-text-muted">source </span>
          <span title={item.source_sha256 ?? undefined}>{digest(item.source_sha256)}</span>
        </span>
        <span>
          <span className="text-text-muted">binary </span>
          <span title={item.binary_sha256 ?? undefined}>{digest(item.binary_sha256)}</span>
        </span>
        <span>
          <span className="text-text-muted">smoke </span>
          {item.smoke_passed
            ? localized(t, "harness.evidence.smokePassed", "passed")
            : localized(t, "harness.evidence.smokeNotPassed", "not passed")}{" "}
          ({item.smoke_execs_per_sec.toFixed(0)} exec/s)
        </span>
      </div>

      {/* Lint findings */}
      <div className="mt-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-muted uppercase" style={{ fontWeight: 600 }}>
            {localized(t, "harness.evidence.lint", "Lint findings")}
          </span>
          {blockingLint.length > 0 ? (
            <ShieldX size={14} style={{ color: "var(--danger, #e5484d)" }} />
          ) : (
            <FileWarning size={14} className="text-text-muted" />
          )}
        </div>
        {item.lint.length === 0 ? (
          <p className="text-xs text-text-muted mt-1">
            {localized(t, "harness.evidence.noLint", "none for this source")}
          </p>
        ) : (
          <ul className="text-xs mt-1" style={{ paddingLeft: 16 }}>
            {item.lint.map((finding) => (
              <li key={`${finding.rule}-${finding.line}`}>
                <span
                  style={{
                    color:
                      finding.severity === "error"
                        ? "var(--danger, #e5484d)"
                        : "var(--warning, #e5a000)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {finding.severity}
                </span>{" "}
                <span style={{ fontFamily: "var(--font-mono)" }}>
                  {finding.rule}:{finding.line}
                </span>{" "}
                {finding.message}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
