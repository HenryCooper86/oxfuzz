import "../i18n.parityAnalysis";
import { useEffect, useRef, useState } from "react";
import { GitBranch } from "lucide-react";
import { useI18n } from "../i18nContext";
import { getTransport } from "../lib";
import { shortCommit, type BisectOutcome } from "../lib/parityAnalysis";
import { Button, Input } from "./ui";

/** Finds the first commit at which one finding's crash input crashes. */
export function BisectPanel({ project, target, crashId }: { project: string; target: string; crashId: string }) {
  const { t } = useI18n();
  const [good, setGood] = useState("");
  const [bad, setBad] = useState("");
  const [running, setRunning] = useState(false);
  const [outcome, setOutcome] = useState<BisectOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  async function bisect() {
    if (running || !good.trim()) return;
    setRunning(true);
    setError(null);
    setOutcome(null);
    try {
      // An empty bad revision means HEAD, as on the command line.
      const result = await getTransport().invoke<BisectOutcome>("bisect_crash", { project, target, crashId, good: good.trim(), bad: bad.trim() || "HEAD" });
      if (mounted.current) setOutcome(result);
    } catch (caught) {
      if (mounted.current) setError(String(caught));
    } finally {
      if (mounted.current) setRunning(false);
    }
  }

  return <section className="border-t border-border pt-3 flex flex-col gap-2" aria-label={t("parity.analysis.bisect.title")}>
    <div className="text-xs font-medium text-text-primary">{t("parity.analysis.bisect.title")}</div>
    <p className="text-xs text-text-muted m-0">{t("parity.analysis.bisect.help")}</p>
    <div className="flex flex-wrap gap-2">
      <Input mono className="flex-1" aria-label={t("parity.analysis.bisect.good")} placeholder={t("parity.analysis.bisect.good")} value={good} onChange={(event) => setGood(event.target.value)} />
      <Input mono className="flex-1" aria-label={t("parity.analysis.bisect.bad")} placeholder={t("parity.analysis.bisect.bad")} value={bad} onChange={(event) => setBad(event.target.value)} />
      <Button size="sm" variant="outline" onClick={() => void bisect()} loading={running} disabled={running || !good.trim()}>
        {!running && <GitBranch size={13} />}{t("parity.analysis.bisect.run")}
      </Button>
    </div>
    {error && <p role="alert" className="text-xs m-0" style={{ color: "var(--error)" }}>{t("parity.analysis.bisect.failed", { error })}</p>}
    {outcome && <BisectReport outcome={outcome} />}
  </section>;
}

function BisectReport({ outcome }: { outcome: BisectOutcome }) {
  const { t } = useI18n();
  return <div className="flex flex-col gap-1 text-xs" data-testid="bisect-report">
    <p className="m-0">{t("parity.analysis.bisect.summary", { n: outcome.candidates, good: shortCommit(outcome.good), bad: shortCommit(outcome.bad) })}</p>
    <ul className="m-0 font-mono" style={{ listStyle: "none", paddingLeft: 0 }}>
      {outcome.steps.map((step, index) => <li key={`${step.commit}-${index}`}>
        {t(`parity.analysis.bisect.verdict.${step.verdict}`)} {shortCommit(step.commit)}{step.note ? `  ${step.note}` : ""}
      </li>)}
    </ul>
    {outcome.result.kind === "first_bad" ? <>
      <p className="m-0 font-medium">{t("parity.analysis.bisect.firstBad", { commit: outcome.result.commit })}</p>
      <p className="m-0 text-text-secondary">{outcome.result.subject}</p>
      <p className="m-0 text-text-muted">{t("parity.analysis.bisect.caveat")}</p>
    </> : <>
      <p className="m-0 font-medium">{t("parity.analysis.bisect.undecided", { n: outcome.result.commits.length })}</p>
      <ul className="m-0 font-mono" style={{ listStyle: "none", paddingLeft: 0 }}>{outcome.result.commits.map((commit) => <li key={commit}>{commit}</li>)}</ul>
    </>}
  </div>;
}
