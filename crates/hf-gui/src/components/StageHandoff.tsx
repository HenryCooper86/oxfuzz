import { ArrowRight, CheckCircle2 } from "lucide-react";
import { Button } from "./ui";
import { useI18n } from "../i18nContext";
import type { ViewType } from "../types";

// The "what next" actions at the end of a pipeline stage. Each one only
// navigates; starting work still needs the next stage's own action and approval.

/** Shown once a harness is approved and seeded: continue to the Run stage. */
export function HarnessReadyCard({ target, engine, onNavigate }: {
  target: string;
  engine: string;
  onNavigate?: (view: ViewType) => void;
}) {
  const { t } = useI18n();
  return (
    <div
      className="surface-card flex items-center gap-3"
      style={{ padding: "var(--space-md)", animation: "slideInUp 0.2s ease" }}
    >
      <CheckCircle2 size={20} style={{ color: "var(--success)" }} />
      <div className="flex-1">
        <span className="text-sm font-medium text-text-primary">{t("harness.readyToFuzz")}</span>
        <p className="text-xs text-text-secondary mt-0.5">{t("harness.readyToFuzzHint", { target, engine })}</p>
      </div>
      {onNavigate && (
        <Button variant="primary" onClick={() => onNavigate("run")}>
          {t("harness.continueToRun")}<ArrowRight size={14} />
        </Button>
      )}
    </div>
  );
}

/** Shown when a run finishes: review findings first when crashes were retained. */
export function RunCompletionActions({ crashes, onNavigate }: {
  crashes: number;
  onNavigate: (view: ViewType) => void;
}) {
  const { t } = useI18n();
  return (
    <div className="flex flex-wrap gap-2">
      {crashes > 0 && <Button variant="primary" onClick={() => onNavigate("triage")}>{t("run.reviewFindings")}</Button>}
      <Button variant={crashes > 0 ? "outline" : "ghost"} onClick={() => onNavigate("runs")}>{t("nav.runs")}</Button>
    </div>
  );
}
