import { useState } from "react";
import { Stethoscope } from "lucide-react";
import { Badge, Button } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type {
  BuildPlanRunOutcome,
  BuildPlanRunStatus,
  BuildSystemDiagnosis,
  BuildSystemStatus,
} from "../types";

/// Service determinations mapped to a badge tone. The panel styles what the
/// service decided; it never decides supportability itself.
const STATUS_TONE: Record<BuildSystemStatus, "success" | "accent" | "warning" | "default"> = {
  ready: "success",
  supported: "accent",
  unsupported_in_image: "warning",
  not_needed: "default",
  unknown: "default",
};

const RUN_TONE: Record<BuildPlanRunStatus, "success" | "error" | "warning"> = {
  succeeded: "success",
  step_failed: "error",
  artifact_missing: "warning",
};

export function BuildDoctorPanel({ project }: { project: string }) {
  const { t } = useI18n();
  const [diagnosis, setDiagnosis] = useState<BuildSystemDiagnosis[] | null>(null);
  const [outcome, setOutcome] = useState<BuildPlanRunOutcome | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function diagnose() {
    setBusy(true);
    setError(null);
    setOutcome(null);
    setConfirmed(false);
    try {
      const result = await getTransport().invoke<BuildSystemDiagnosis[]>("build_diagnose", {
        project,
      });
      setDiagnosis(result);
    } catch (e) {
      setDiagnosis(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function run(buildSystem: string) {
    setBusy(true);
    setError(null);
    try {
      const result = await getTransport().invoke<BuildPlanRunOutcome>("build_run", {
        project,
        buildSystem,
      });
      setOutcome(result);
      // Re-diagnose: a successful run changes what the project now ships.
      const refreshed = await getTransport().invoke<BuildSystemDiagnosis[]>("build_diagnose", {
        project,
      });
      setDiagnosis(refreshed);
    } catch (e) {
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
          <Stethoscope size={14} style={{ color: "var(--accent)" }} />
          {t("buildDoctor.title")}
        </div>
        <Button variant="outline" size="sm" loading={busy} disabled={!project} onClick={() => void diagnose()}>
          {t("buildDoctor.diagnose")}
        </Button>
      </div>
      <p className="text-xs text-text-muted mt-1">{t("buildDoctor.advisory")}</p>

      {diagnosis?.map((entry) => (
        <div
          key={entry.build_system}
          className="rounded-sm border border-border mt-2"
          style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-text-secondary mr-auto">
              {t(`buildDoctor.system.${entry.build_system}`)}
            </span>
            <Badge variant={STATUS_TONE[entry.status]}>
              {t(`buildDoctor.status.${entry.status}`)}
            </Badge>
          </div>
          {entry.markers.length > 0 && (
            <p className="text-xs text-text-muted font-mono mt-1">
              {t("buildDoctor.markers")}: {entry.markers.join(", ")}
            </p>
          )}
          {entry.missing_tool && (
            <p className="text-xs mt-1" style={{ color: "var(--warning)" }}>
              {t("buildDoctor.missingTool", { tool: entry.missing_tool })}
            </p>
          )}

          {entry.plan && (
            <div className="mt-2 flex flex-col gap-2">
              <span className="text-xs text-text-secondary">{t("buildDoctor.planTitle")}</span>
              {entry.plan.steps.map((step, index) => (
                <div key={index} className="flex flex-col gap-1">
                  <span className="text-xs text-text-muted">{step.purpose}</span>
                  <code
                    className="text-xs font-mono block"
                    style={{
                      background: "var(--surface-primary)",
                      padding: "var(--space-xs)",
                      borderRadius: "var(--radius-sm)",
                      overflowX: "auto",
                    }}
                  >
                    {step.argv.join(" ")}
                  </code>
                </div>
              ))}
              <span className="text-xs text-text-muted font-mono">
                {t("buildDoctor.expectedArtifact")}: {entry.plan.expected_artifact}
              </span>
              <label className="flex items-start gap-2 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                {t("buildDoctor.confirmRun")}
              </label>
              <Button
                variant="primary"
                size="sm"
                className="self-start"
                disabled={!confirmed}
                loading={busy}
                onClick={() => void run(entry.build_system)}
              >
                {t("buildDoctor.runPlan")}
              </Button>
            </div>
          )}
        </div>
      ))}

      {outcome && (
        <div className="mt-2 flex flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-text-secondary mr-auto">{t("buildDoctor.runResult")}</span>
            <Badge variant={RUN_TONE[outcome.status]}>
              {t(`buildDoctor.runStatus.${outcome.status}`)}
            </Badge>
          </div>
          {outcome.failed_step && (
            <pre
              className="text-xs font-mono"
              style={{
                background: "var(--surface-primary)",
                padding: "var(--space-sm)",
                borderRadius: "var(--radius-sm)",
                overflowX: "auto",
                whiteSpace: "pre-wrap",
              }}
            >
              {t("buildDoctor.failedStep", {
                index: String(outcome.failed_step.index + 1),
                code: String(outcome.failed_step.exit_code),
              })}
              {"\n"}
              {outcome.failed_step.output}
            </pre>
          )}
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}
