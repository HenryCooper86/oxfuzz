import { useState } from "react";
import { Workflow } from "lucide-react";
import { Badge, Button, Textarea } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type {
  LabMode,
  PlanSimulation,
  ProtocolStateCoverage,
  ResetEvidence,
  SequencePlan,
} from "../types";

/// Only the sequenceable modes. The physical bench is deliberately absent:
/// each physical transmission needs its own fresh approval, so a sequence
/// runner has no place there.
const MODES: LabMode[] = ["virtual_can", "offline_pcap"];

export function AutomotiveLabPanel({
  project,
  protocol,
}: {
  project: string;
  protocol: string;
}) {
  const { t } = useI18n();
  const [mode, setMode] = useState<LabMode>("virtual_can");
  const [coverage, setCoverage] = useState<ProtocolStateCoverage | null>(null);
  const [plan, setPlan] = useState<SequencePlan | null>(null);
  const [simulation, setSimulation] = useState<PlanSimulation | null>(null);
  const [reset, setReset] = useState<ResetEvidence | null>(null);
  const [scriptJson, setScriptJson] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      const transport = getTransport();
      const observed = await transport.invoke<ProtocolStateCoverage>(
        "automotive_lab_coverage",
        { request: { project, protocol } },
      );
      setCoverage(observed);
      const proposed = await transport.invoke<SequencePlan>("automotive_lab_plan", {
        request: {
          project,
          protocol,
          mode,
          operations: ["scan_uds", "replay"],
        },
      });
      setPlan(proposed);
      // The reset claim is checked against whatever baseline the evidence
      // recorded; a missing digest stays unconfirmed rather than assumed good.
      const baseline = observed.observed[0]?.digest ?? null;
      const latest = observed.observed[observed.observed.length - 1]?.digest ?? null;
      setReset(
        await transport.invoke<ResetEvidence>("automotive_lab_reset", {
          request: { baseline_digest: baseline, observed_digest: latest },
        }),
      );
    } catch (e) {
      setCoverage(null);
      setPlan(null);
      setSimulation(null);
      setReset(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function simulate() {
    setBusy(true);
    setError(null);
    try {
      // The script is reviewed evidence supplied by the operator; a malformed
      // one is refused here rather than sent as something the service must
      // guess at.
      const script: unknown = JSON.parse(scriptJson);
      const simulated = await getTransport().invoke<PlanSimulation>(
        "automotive_lab_simulate",
        {
          request: {
            project,
            script,
            protocol,
            mode,
            operations: ["scan_uds", "replay"],
          },
        },
      );
      setSimulation(simulated);
    } catch (e) {
      setSimulation(null);
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
          <Workflow size={14} style={{ color: "var(--accent)" }} />
          {t("automotiveLab.title")}
        </div>
        <Button variant="outline" size="sm" loading={busy} disabled={!project} onClick={() => void load()}>
          {t("automotiveLab.explore")}
        </Button>
      </div>
      <p className="text-xs text-text-muted mt-1">{t("automotiveLab.advisory")}</p>

      <div className="flex flex-wrap items-center gap-2 mt-2">
        {MODES.map((option) => (
          <Button
            key={option}
            variant={option === mode ? "primary" : "outline"}
            size="sm"
            onClick={() => setMode(option)}
          >
            {t(`automotiveLab.mode.${option}`)}
          </Button>
        ))}
        <span className="text-xs text-text-muted">{t("automotiveLab.benchExcluded")}</span>
      </div>

      {coverage && (
        <div
          className="rounded-sm border border-border mt-3"
          style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-text-secondary mr-auto">
              {t("automotiveLab.observedStates")}
            </span>
            <Badge variant="accent">{coverage.observed.length}</Badge>
            {coverage.expected_total === null ? (
              <Badge variant="default">{t("automotiveLab.noDenominator")}</Badge>
            ) : (
              <Badge variant="success">
                {coverage.observed.length} / {coverage.expected_total}
              </Badge>
            )}
          </div>
          {coverage.expected_total === null && (
            <p className="text-xs text-text-muted mt-1">
              {t("automotiveLab.noDenominatorHelp")}
            </p>
          )}
          {coverage.model_name && (
            <p className="text-xs text-text-muted mt-1">
              {t("automotiveLab.model")}: {coverage.model_name}
            </p>
          )}
          {coverage.observed.map((observed) => (
            <p key={observed.digest} className="text-xs font-mono text-text-muted mt-1">
              {observed.digest.slice(0, 16)}
            </p>
          ))}
        </div>
      )}

      {plan && plan.refusal && (
        <div
          className="rounded-sm border border-border mt-2"
          style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
        >
          <Badge variant="warning">{t("automotiveLab.refused")}</Badge>
          <p className="text-xs text-text-muted mt-1">
            {t(`automotiveLab.refusal.${plan.refusal}`)}
          </p>
        </div>
      )}

      {plan && !plan.refusal && (
        <div className="flex flex-col gap-1 mt-2">
          <span className="text-xs font-medium text-text-secondary">
            {t("automotiveLab.plan")}
          </span>
          <p className="text-xs text-text-muted">{t("automotiveLab.planAdvisory")}</p>
          {plan.steps.map((step) => (
            <div key={step.index} className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-text-secondary" style={{ minWidth: "1.5rem" }}>
                {step.index + 1}
              </span>
              <span className="text-xs font-mono text-text-secondary mr-auto">
                {step.operation}
              </span>
              <Badge variant="default">{t(`automotiveLab.reason.${step.reason_code}`)}</Badge>
              {step.expected_start_state && (
                <span className="text-xs font-mono text-text-muted">
                  {step.expected_start_state.slice(0, 12)}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {plan && !plan.refusal && (
        <div className="flex flex-col gap-2 mt-3">
          <span className="text-xs font-medium text-text-secondary">
            {t("automotiveLab.scriptTitle")}
          </span>
          <p className="text-xs text-text-muted">{t("automotiveLab.scriptHelp")}</p>
          <Textarea
            mono
            rows={4}
            value={scriptJson}
            placeholder={t("automotiveLab.scriptPlaceholder")}
            onChange={(event) => setScriptJson(event.target.value)}
          />
          <Button
            variant="outline"
            size="sm"
            className="self-start"
            loading={busy}
            disabled={scriptJson.trim().length === 0}
            onClick={() => void simulate()}
          >
            {t("automotiveLab.simulate")}
          </Button>
        </div>
      )}

      {simulation && (
        <div className="flex flex-col gap-1 mt-2">
          <span className="text-xs font-medium text-text-secondary">
            {t("automotiveLab.simulation")} ({simulation.script_name})
          </span>
          <p className="text-xs text-text-muted">{t("automotiveLab.modelNotice")}</p>
          {simulation.steps.map((step) => (
            <div key={step.index} className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono text-text-secondary mr-auto">
                {step.operation}
              </span>
              <Badge
                variant={step.reachability === "reachable" ? "success" : "warning"}
              >
                {t(`automotiveLab.reachability.${step.reachability}`)}
              </Badge>
              <span className="text-xs font-mono text-text-muted">{step.state_before}</span>
            </div>
          ))}
        </div>
      )}

      {reset && (
        <div
          className="rounded-sm border border-border mt-2"
          style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-text-secondary mr-auto">
              {t("automotiveLab.resetTitle")}
            </span>
            <Badge
              variant={
                reset.outcome === "confirmed"
                  ? "success"
                  : reset.outcome === "mismatched"
                    ? "error"
                    : "warning"
              }
            >
              {t(`automotiveLab.reset.${reset.outcome}`)}
            </Badge>
          </div>
          <p className="text-xs text-text-muted mt-1">
            {t(`automotiveLab.resetReason.${reset.reason_code}`)}
          </p>
          {!reset.attributable && (
            <p className="text-xs mt-1" style={{ color: "var(--warning)" }}>
              {t("automotiveLab.notAttributable")}
            </p>
          )}
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}
