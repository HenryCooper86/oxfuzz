import "../i18n.parityAnalysis";
import { useEffect, useRef, useState } from "react";
import { Cpu, History } from "lucide-react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import type { AiPolicy, RegressionResult } from "../lib/parityAnalysis";
import { Button } from "./ui";

/**
 * Two triage actions beside the plain scan: model-assisted triage with an
 * explicit model policy, and a replay of the target's stored crashes.
 */
export function TriageParityPanel({ project, target, disabled, onTriaged }: { project: string; target: string; disabled: boolean; onTriaged: () => void }) {
  const { t } = useI18n();
  const [policy, setPolicy] = useState<AiPolicy>("auto");
  const [busy, setBusy] = useState<"ai" | "regress" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<RegressionResult[] | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  async function aiTriage() {
    if (busy) return;
    setBusy("ai"); setError(null); setMessage(null);
    try {
      const found = await getTransport().invoke<unknown>("triage", { project, target, ai: policy });
      if (!mounted.current) return;
      setMessage(t("parity.analysis.triage.aiDone", { n: Array.isArray(found) ? found.length : 0 }));
      onTriaged();
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }

  async function replay() {
    if (busy) return;
    setBusy("regress"); setError(null); setResults(null);
    try {
      const found = await getTransport().invoke<RegressionResult[]>("verify_regressions", { project, target });
      if (mounted.current) setResults(Array.isArray(found) ? found : []);
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }

  const still = results?.filter((r) => r.still_crashes).length ?? 0;
  const fixed = results?.filter((r) => r.verified && !r.still_crashes).length ?? 0;
  const inconclusive = results?.filter((r) => !r.verified).length ?? 0;
  const reason = target ? undefined : t("triage.scanNeedsTarget");
  return <section className="surface-card flex flex-col gap-2" style={{ padding: "var(--space-sm) var(--space-md)" }} aria-label={t("parity.analysis.triage.title")}>
    <div className="text-sm font-medium">{t("parity.analysis.triage.title")}</div>
    <p className="text-xs text-text-muted m-0">{t("parity.analysis.triage.help")}</p>
    <div className="flex flex-wrap items-center gap-2">
      <select className="bg-surface-secondary text-text-primary border border-border rounded-md px-2 py-1 min-w-0" aria-label={t("parity.analysis.triage.policy")} value={policy} onChange={(event) => setPolicy(event.target.value as AiPolicy)}>
        <option value="auto">{t("parity.analysis.triage.policyAuto")}</option>
        <option value="require">{t("parity.analysis.triage.policyRequire")}</option>
        <option value="off">{t("parity.analysis.triage.policyOff")}</option>
      </select>
      <Button size="sm" variant="outline" onClick={() => void aiTriage()} loading={busy === "ai"} disabled={disabled || !target || busy !== null} title={reason}>
        {busy !== "ai" && <Cpu size={13} />}{t("parity.analysis.triage.ai")}
      </Button>
      <Button size="sm" variant="outline" onClick={() => void replay()} loading={busy === "regress"} disabled={disabled || !target || busy !== null} title={reason ?? t("parity.analysis.triage.replayHelp")}>
        {busy !== "regress" && <History size={13} />}{t("parity.analysis.triage.replay")}
      </Button>
    </div>
    <p className="text-xs text-text-muted m-0">{t(`parity.analysis.triage.policyHelp.${policy}`)}</p>
    {message && <p role="status" className="text-xs m-0">{message}</p>}
    {error && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{error}</p>}
    {results && (results.length === 0
      ? <p role="status" className="text-xs m-0 text-text-muted">{t("parity.analysis.triage.noStored")}</p>
      : <div data-testid="regression-results" className="flex flex-col gap-1 text-xs">
        <p className="m-0 font-medium">{t("parity.analysis.triage.replaySummary", { n: results.length, still, fixed, inconclusive })}</p>
        <ul className="m-0 font-mono" style={{ listStyle: "none", paddingLeft: 0 }}>
          {results.map((r, index) => <li key={`${r.crash_id}-${r.input}-${index}`}>
            [{t(r.still_crashes ? "parity.analysis.triage.stillCrashes" : r.verified ? "parity.analysis.triage.fixed" : "parity.analysis.triage.inconclusive")}] {r.crash_id.slice(0, 8)} {r.input} -- {r.summary}
          </li>)}
        </ul>
      </div>)}
  </section>;
}
