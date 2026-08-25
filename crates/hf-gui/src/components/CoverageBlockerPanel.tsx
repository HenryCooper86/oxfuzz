import { useState } from "react";
import { Route } from "lucide-react";
import { Badge, Button } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type { CoverageBlockerView, NextExperimentKind } from "../types";

/// Service proposals mapped to a badge tone. The panel renders what the service
/// proposed; it derives no experiment of its own and starts nothing.
const EXPERIMENT_TONE: Record<NextExperimentKind, "accent" | "warning" | "default"> = {
  grow_corpus: "accent",
  refine_harness: "warning",
  no_experiment_available: "default",
};

export function CoverageBlockerPanel({
  project,
  target,
  lang,
}: {
  project: string;
  target: string;
  lang: string;
}) {
  const { t } = useI18n();
  const [view, setView] = useState<CoverageBlockerView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function explore() {
    setBusy(true);
    setError(null);
    try {
      const result = await getTransport().invoke<CoverageBlockerView>("coverage_blockers", {
        project,
        target,
        lang,
      });
      setView(result);
    } catch (e) {
      setView(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="rounded-md border border-border"
      style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <Route size={14} style={{ color: "var(--accent)" }} />
          {t("coverageBlockers.title")}
        </div>
        <Button
          variant="outline"
          size="sm"
          loading={busy}
          disabled={!project || !target}
          onClick={() => void explore()}
        >
          {t("coverageBlockers.explore")}
        </Button>
      </div>
      <p className="text-xs text-text-muted mt-1">{t("coverageBlockers.advisory")}</p>

      {view && view.measurement.status === "unavailable" && (
        <div
          className="rounded-sm border border-border mt-2"
          style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
        >
          <Badge variant="warning">{t("coverageBlockers.unavailable")}</Badge>
          <p className="text-xs text-text-muted mt-1">
            {t(`coverageBlockers.reason.${view.measurement.reason_code}`)}
          </p>
        </div>
      )}

      {view && view.measurement.status === "available" && (
        <div className="flex flex-col gap-2 mt-3">
          <div
            className="rounded-sm border border-border"
            style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-text-secondary mr-auto">
                {t("coverageBlockers.experiment")}
              </span>
              <Badge variant={EXPERIMENT_TONE[view.experiment.kind]}>
                {t(`coverageBlockers.experimentKind.${view.experiment.kind}`)}
              </Badge>
            </div>
            <p className="text-xs text-text-muted mt-1">
              {t(`coverageBlockers.experimentReason.${view.experiment.reason_code}`)}
            </p>
            {view.experiment.target_function && (
              <p className="text-xs font-mono text-text-secondary mt-1">
                {t("coverageBlockers.aimAt")}: {view.experiment.target_function}
              </p>
            )}
          </div>

          {view.blockers.map((blocker) => (
            <div
              key={blocker.function}
              className="rounded-sm border border-border"
              style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono text-text-secondary mr-auto">
                  {blocker.function}
                </span>
                <Badge variant="default">
                  {t("coverageBlockers.unlocks", {
                    n: String(blocker.unlocked_uncovered),
                  })}
                </Badge>
                {blocker.frontier_distance === null ? (
                  <Badge variant="warning">{t("coverageBlockers.noRoute")}</Badge>
                ) : (
                  <Badge variant="accent">
                    {t("coverageBlockers.hops", {
                      n: String(blocker.frontier_distance),
                    })}
                  </Badge>
                )}
              </div>
              {blocker.location && (
                <p className="text-xs text-text-muted font-mono mt-1">{blocker.location}</p>
              )}
              {blocker.path.length > 0 && (
                <p className="text-xs text-text-muted font-mono mt-1" style={{ overflowX: "auto" }}>
                  {blocker.path.join(" -> ")}
                </p>
              )}
            </div>
          ))}

          {view.blockers.length === 0 && (
            <p className="text-xs text-text-muted">{t("coverageBlockers.noBlockers")}</p>
          )}
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}
