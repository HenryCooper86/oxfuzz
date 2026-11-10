// Info panel -- shows campaign artifacts and the iteration loop. The stage
// plan lives in the Progress panel.
//
// Everything here is driven from real in-app state: artifact counts (compiled
// harness, corpus, crash inputs) come from the `artifact_summary` command for
// the active project/target; the loop status from the shared pipeline
// progress, the selected target/engine, and the live RunOutput context.

import { useCallback } from "react";
import { FileCode, Repeat, RotateCw, Crosshair as TargetIcon } from "lucide-react";
import { usePolledResource } from "../../hooks/usePolledResource";
import { IconButton } from "../ui/IconButton";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import { usePipeline } from "../../providers/pipeline";
import { useProject } from "../../providers/project";
import { useTarget } from "../../providers/target";
import { activeStatus } from "../../providers/runOutputValidation";
import { useRunOutput } from "../../providers/runOutput";

interface ArtifactSummary {
  harness_built: boolean | null;
  corpus_count: number | null;
  crash_count: number | null;
}

export function InfoPanel() {
  const { t } = useI18n();
  const { coreStages } = usePipeline();
  const { activeProject } = useProject();
  const { target, engine } = useTarget();
  const { selectedRun } = useRunOutput();
  const activeRun = selectedRun?.project_root === activeProject && activeStatus(selectedRun.status) ? selectedRun : null;
  const activeTarget = activeRun ? activeRun.target : target;
  const activeEngine = activeRun ? activeRun.engine : engine;
  const currentStage = coreStages.find(stage => stage.current);
  const currentLabel = currentStage ? t(`stage.${currentStage.id}`) : t("info.allStagesComplete");
  const load = useCallback(() => getTransport().invoke<ArtifactSummary>("artifact_summary", { project: activeProject, target: activeTarget }), [activeProject, activeTarget]);
  const hasSelection = !!activeProject && !!activeTarget;
  const { data: artifacts, error, loading, reload } = usePolledResource(load, hasSelection);

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--surface-secondary)" }}>
      <div className="flex items-center gap-2 p-2 border-b border-border">
        <TargetIcon size={14} style={{ color: "var(--accent)" }} />
        <span className="text-xs font-semibold uppercase text-text-muted" style={{ letterSpacing: "0.08em" }}>{t("info.campaignInfo")}</span>
        {hasSelection && <IconButton size={22} onClick={() => void reload()} title={t("common.refresh")} aria-label={t("common.refresh")}><RotateCw size={12} /></IconButton>}
      </div>

      <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
        {/* Generated Artifacts -- live counts for the active target */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <FileCode size={11} /> {t("info.artifacts")}
          </div>
          {artifacts ? (
            <div className="surface-card p-2 flex flex-col gap-1">
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">{t("info.harness")}</span>
                <span style={{ color: artifacts.harness_built ? "var(--success)" : "var(--text-muted)" }}>
                  {artifacts.harness_built == null ? "—" : artifacts.harness_built ? t("info.compiled") : t("info.notBuilt")}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">{t("info.corpusInputs")}</span>
                <span className="text-text-primary">{artifacts.corpus_count ?? "—"}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">{t("info.crashInputs")}</span>
                <span style={{ color: (artifacts.crash_count ?? 0) > 0 ? "var(--error)" : "var(--text-primary)" }}>
                  {artifacts.crash_count ?? "—"}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-xs text-text-muted py-1">
              {!hasSelection ? t("info.pickProject") : error ? <span role="alert">{t("info.artifactsFailed")}: {error}</span> : loading ? <span role="status">{t("common.loading")}</span> : "—"}
            </div>
          )}
        </div>

        {/* Iteration Loop */}
        <div>
          <div className="text-xs text-text-muted uppercase mb-1 flex items-center gap-1" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            <Repeat size={11} /> {t("info.iterationLoop")}
          </div>
          <div className="surface-card p-2 text-xs">
            <div className="flex justify-between mb-1">
              <span className="text-text-muted">{t("info.phase")}</span>
              <span className="text-accent">{activeRun ? t("stage.run") : currentLabel}</span>
            </div>
            <div className="flex justify-between mb-1">
              <span className="text-text-muted">{t("info.engine")}</span>
              <span className="text-text-primary font-mono">{activeEngine || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">{t("info.target")}</span>
              <span className="text-text-primary font-mono">{activeTarget || "—"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
