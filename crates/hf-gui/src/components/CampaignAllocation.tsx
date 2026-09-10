import { useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { useI18n } from "../i18nContext";

interface Candidate { target: string; engine: string; harness_id: string; source_sha256: string }
interface Allocation {
  proposal: {
    id: string; project: string; max_runs: number; max_total_secs: number;
    per_run_secs: number; unallocated_secs: number;
    entries: { candidate: Candidate; max_runs: number; reason: string; evidence: { run_id: string; edges: number }[] }[];
  };
  digest: string;
  status: "draft" | "approved" | "revoked";
  reservations: { candidate: Candidate; duration_secs: number }[];
}

export function CampaignAllocation({ project }: { project: string }) {
  const { t } = useI18n();
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [plan, setPlan] = useState<Allocation | null>(null);
  const [runs, setRuns] = useState("10");
  const [seconds, setSeconds] = useState("600");
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  useEffect(() => {
    const current = ++generation.current;
    void Promise.resolve().then(async () => {
      if (current !== generation.current) return;
      setBusy(true);
      const [choices, status] = await Promise.allSettled([
        getTransport().invoke<Candidate[]>("allocation_candidates", { project }),
        getTransport().invoke<Allocation | null>("allocation_status", { project }),
      ]);
      if (current !== generation.current) return;
      setCandidates(choices.status === "fulfilled" ? choices.value : []);
      setPlan(status.status === "fulfilled" ? status.value : null);
      setError(status.status === "rejected" ? String(status.reason) : choices.status === "rejected" ? String(choices.reason) : "");
      setBusy(false);
    });
    return () => { generation.current += 1; };
  }, [project, revision]);

  async function mutate(command: string, args: Record<string, unknown>) {
    const current = ++generation.current;
    setBusy(true); setError("");
    try {
      const result = await getTransport().invoke<Allocation>(command, args);
      if (current === generation.current) setPlan(result);
    } catch (cause) {
      if (current === generation.current) setError(String(cause));
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  const retained = plan && plan.status !== "revoked";
  return <section className="surface-card p-4 flex flex-col gap-3">
    <div className="flex justify-between items-center gap-3">
      <h2 className="m-0 text-sm font-semibold">{t("allocation.title")}</h2>
      <Button variant="outline" size="sm" disabled={busy} onClick={() => setRevision(value => value + 1)}>{t("common.refresh")}</Button>
    </div>
    <p className="m-0 text-xs text-text-muted break-all">{project}</p>
    <p className="m-0 text-xs text-text-muted">{t("allocation.scope")}</p>
    {error ? <p role="alert" className="m-0 text-xs text-error">{error}</p> : null}
    {!retained ? <>
      <div className="flex flex-wrap gap-3">
        {candidates.map(candidate => <label key={candidate.harness_id} className="text-xs flex items-center gap-2">
          <input type="checkbox" disabled={busy} checked={selected.includes(candidate.harness_id)} onChange={event => setSelected(values => event.target.checked ? [...values, candidate.harness_id] : values.filter(id => id !== candidate.harness_id))} />
          {candidate.target} · {candidate.engine}
        </label>)}
        {!busy && candidates.length === 0 ? <p className="m-0 text-xs">{t("allocation.noCandidates")}</p> : null}
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs flex flex-col gap-1">{t("allocation.runs")}<Input type="number" min="1" max="10000" value={runs} disabled={busy} onChange={event => setRuns(event.target.value)} /></label>
        <label className="text-xs flex flex-col gap-1">{t("allocation.seconds")}<Input type="number" min="1" max="31536000" value={seconds} disabled={busy} onChange={event => setSeconds(event.target.value)} /></label>
        <Button variant="primary" size="sm" disabled={busy || selected.length === 0} onClick={() => void mutate("allocation_propose", { request: { project, harness_ids: selected, max_runs: Number(runs), max_total_secs: Number(seconds) } })}>{t("allocation.prepare")}</Button>
      </div>
    </> : null}
    {plan ? <>
      <p className="m-0 text-sm font-semibold">{t(`allocation.${plan.status}`)} · {plan.reservations.length} / {plan.proposal.max_runs} {t("allocation.charged")}</p>
      <p className="m-0 text-xs">{t("allocation.cap", { seconds: plan.proposal.per_run_secs, remainder: plan.proposal.unallocated_secs })}</p>
      <div className="overflow-x-auto"><table className="w-full text-xs text-left"><thead><tr><th>{t("allocation.target")}</th><th>{t("allocation.runs")}</th><th>{t("allocation.evidence")}</th></tr></thead><tbody>
        {plan.proposal.entries.map(entry => <tr key={entry.candidate.harness_id} className="border-t border-border"><td className="py-2 pr-3">{entry.candidate.target}<br />{entry.candidate.engine}<details className="mt-1 text-text-muted"><summary>{t("allocation.harnessRevision")}</summary><code className="block break-all">{entry.candidate.harness_id}</code><code className="block break-all">{entry.candidate.source_sha256}</code></details></td><td className="pr-3">{entry.max_runs}</td><td>{entry.reason}{entry.evidence.map(run => <span key={run.run_id} className="block text-text-muted">{run.run_id} · {run.edges} {t("allocation.edges")}</span>)}</td></tr>)}
      </tbody></table></div>
      <p className="m-0 text-xs text-text-muted break-all">{t("allocation.reviewDigest")}: <code>{plan.digest}</code></p>
      <div className="flex gap-3">
        {plan.status === "draft" ? <Button variant="primary" size="sm" disabled={busy} onClick={() => void mutate("allocation_review", { project, id: plan.proposal.id, digest: plan.digest, approve: true })}>{t("allocation.approve")}</Button> : null}
        {plan.status !== "revoked" ? <Button variant="outline" size="sm" disabled={busy} onClick={() => void mutate("allocation_review", { project, id: plan.proposal.id, digest: plan.digest, approve: false })}>{t("allocation.revoke")}</Button> : null}
      </div>
    </> : null}
  </section>;
}
