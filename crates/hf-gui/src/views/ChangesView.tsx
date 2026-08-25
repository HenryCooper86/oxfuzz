import { useState } from "react";
import { GitCompare } from "lucide-react";
import { Badge, Button, Textarea, ViewHeader } from "../components/ui";
import { getTransport } from "../lib";
import { useProject } from "../providers/project";
import { useI18n } from "../i18nContext";
import type {
  AffectedTarget,
  ChangeImpactView,
  ClassifiedFinding,
  FindingChange,
  PublishedComparison,
  RevisionComparisonView,
  TargetImpact,
} from "../types";

const DEFAULT_REGRESSION_THRESHOLD_PCT = 5;

/// Service determinations mapped to a badge tone. The view styles what the
/// service decided; it never derives a determination of its own.
const IMPACT_TONE: Record<TargetImpact, "accent" | "warning" | "default"> = {
  changed: "accent",
  reaches_change: "warning",
  unknown: "default",
};

const FINDING_TONE: Record<FindingChange, "error" | "warning" | "success" | "default"> = {
  introduced: "error",
  carried_over: "warning",
  resolved: "success",
  unknown: "default",
};

export function ChangesView() {
  const { t } = useI18n();
  const { activeProject } = useProject();
  const [diff, setDiff] = useState("");
  const [base, setBase] = useState("");
  const [head, setHead] = useState("");
  const [impact, setImpact] = useState<ChangeImpactView | null>(null);
  const [baseRun, setBaseRun] = useState("");
  const [headRun, setHeadRun] = useState("");
  const [comparison, setComparison] = useState<RevisionComparisonView | null>(null);
  const [published, setPublished] = useState<PublishedComparison | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function mapChange() {
    setBusy(true);
    setError(null);
    try {
      const view = await getTransport().invoke<ChangeImpactView>("change_impact", {
        project: activeProject,
        diff: diff.trim() ? diff : undefined,
        base: base.trim() || undefined,
        head: head.trim() || undefined,
      });
      setImpact(view);
    } catch (e) {
      setImpact(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function compare() {
    setBusy(true);
    setError(null);
    setPublished(null);
    setConfirmed(false);
    try {
      const view = await getTransport().invoke<RevisionComparisonView>("change_compare", {
        baseRunId: baseRun.trim(),
        headRunId: headRun.trim(),
        regressionThresholdPct: DEFAULT_REGRESSION_THRESHOLD_PCT,
      });
      setComparison(view);
    } catch (e) {
      setComparison(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function publish() {
    setBusy(true);
    setError(null);
    try {
      const result = await getTransport().invoke<PublishedComparison>("change_publish", {
        baseRunId: baseRun.trim(),
        headRunId: headRun.trim(),
        regressionThresholdPct: DEFAULT_REGRESSION_THRESHOLD_PCT,
        destination: "issue_tracker",
      });
      setPublished(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <ViewHeader title={t("changeAware.title")} description={t("changeAware.subtitle")} />

      <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }}>
        <span className="text-xs font-semibold">{t("changeAware.mapTitle")}</span>
        <p className="text-xs text-text-muted">{t("changeAware.mapHint")}</p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            aria-label={t("changeAware.baseRevision")}
            placeholder={t("changeAware.baseRevision")}
            value={base}
            onChange={(event) => setBase(event.target.value)}
            className="px-2 py-1 text-11px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
          />
          <input
            aria-label={t("changeAware.headRevision")}
            placeholder={t("changeAware.headRevision")}
            value={head}
            onChange={(event) => setHead(event.target.value)}
            className="px-2 py-1 text-11px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
          />
          <span className="text-xs text-text-muted">{t("changeAware.orDiff")}</span>
        </div>
        <Textarea
          mono
          rows={6}
          value={diff}
          placeholder={t("changeAware.diffPlaceholder")}
          onChange={(event) => setDiff(event.target.value)}
        />
        <Button
          variant="outline"
          size="sm"
          className="self-start"
          loading={busy}
          disabled={!activeProject}
          onClick={() => void mapChange()}
        >
          {t("changeAware.mapAction")}
        </Button>

        {impact && (
          <div className="flex flex-col gap-2 mt-2">
            <span className="text-xs text-text-muted">
              {t("changeAware.filesChanged")}: {impact.files.length}
            </span>
            <p className="text-xs text-text-muted">{t("changeAware.approximateNotice")}</p>
            {impact.affected.map((entry: AffectedTarget) => (
              <div key={entry.target_id} className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono text-text-secondary mr-auto">{entry.symbol}</span>
                <Badge variant={IMPACT_TONE[entry.impact]}>
                  {t(`changeAware.impact.${entry.impact}`)}
                </Badge>
                <span className="text-xs text-text-muted">
                  {t(`changeAware.reason.${entry.reason_code}`)}
                </span>
                {entry.approximate && (
                  <Badge variant="default">{t("changeAware.approximate")}</Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-md)" }}>
        <div className="flex items-center gap-2 text-xs font-semibold">
          <GitCompare size={14} style={{ color: "var(--accent)" }} />
          {t("changeAware.compareTitle")}
        </div>
        <p className="text-xs text-text-muted">{t("changeAware.compareHint")}</p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            aria-label={t("changeAware.baseRun")}
            placeholder={t("changeAware.baseRun")}
            value={baseRun}
            onChange={(event) => setBaseRun(event.target.value)}
            className="w-80 px-2 py-1 text-11px font-mono border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
          />
          <input
            aria-label={t("changeAware.headRun")}
            placeholder={t("changeAware.headRun")}
            value={headRun}
            onChange={(event) => setHeadRun(event.target.value)}
            className="w-80 px-2 py-1 text-11px font-mono border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
          />
          <Button
            variant="outline"
            size="sm"
            loading={busy}
            disabled={!baseRun.trim() || !headRun.trim()}
            onClick={() => void compare()}
          >
            {t("changeAware.compareAction")}
          </Button>
        </div>

        {comparison && !comparison.comparable && (
          <div className="rounded-sm border border-border mt-2" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
            <Badge variant="warning">{t("changeAware.incomparable")}</Badge>
            <p className="text-xs text-text-muted mt-1">
              {comparison.refusal
                ? t(`changeAware.refusal.${comparison.refusal}`)
                : t("changeAware.refusal.unknown")}
            </p>
          </div>
        )}

        {comparison && comparison.comparable && (
          <div className="flex flex-col gap-2 mt-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-text-secondary mr-auto">
                {t("changeAware.coverage")}
              </span>
              <Badge
                variant={comparison.coverage.status === "regressed" ? "error" : "success"}
              >
                {t(`changeAware.coverageStatus.${comparison.coverage.status}`)}
              </Badge>
              {comparison.coverage.status !== "unavailable" && (
                <span className="text-xs font-mono text-text-muted">
                  {comparison.coverage.delta_pct.toFixed(2)}%
                </span>
              )}
            </div>
            {comparison.findings.map((finding: ClassifiedFinding) => (
              <div key={finding.stack_signature} className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono text-text-secondary mr-auto">
                  {finding.stack_signature}
                </span>
                <Badge variant={FINDING_TONE[finding.change]}>
                  {t(`changeAware.finding.${finding.change}`)}
                </Badge>
              </div>
            ))}

            <div className="border-t border-border pt-2 mt-1 flex flex-col gap-2">
              <label className="flex items-start gap-2 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                {t("changeAware.confirmPublish")}
              </label>
              <Button
                variant="primary"
                size="sm"
                className="self-start"
                disabled={!confirmed}
                loading={busy}
                onClick={() => void publish()}
              >
                {t("changeAware.publishAction")}
              </Button>
              {published && (
                <p className="text-xs text-text-muted">
                  {t("changeAware.published")}
                  {published.url ? ` ${published.url}` : ""}
                </p>
              )}
            </div>
          </div>
        )}
      </section>

      {error && <p className="text-xs" style={{ color: "var(--error)" }}>{error}</p>}
    </div>
  );
}
