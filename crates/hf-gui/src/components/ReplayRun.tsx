import { useEffect, useRef, useState } from "react";
import { emitDataChanged, getTransport } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import { useProject } from "../providers/project";
import type { ViewType } from "../types";
import { useRunOutput } from "../providers/runOutput";
import { useI18n } from "../i18nContext";
import type { ReplayReview } from "../lib/transport";
import { Button } from "./ui";

type ReplayProps = { runId: string; onNavigate?: (view: ViewType) => void };
export function ReplayRun(props: ReplayProps) {
  return <ScopedReplay key={props.runId} {...props} />;
}
function ScopedReplay({ runId, onNavigate }: ReplayProps) {
  const { t } = useI18n();
  const output = useRunOutput();
  const { setActiveProject } = useProject();
  const [review, setReview] = useState<ReplayReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [finished, setFinished] = useState(false);
  const [replayProject, setReplayProject] = useState("");
  const active = useRef(true);
  const pending = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  async function perform(launch: boolean) {
    if (pending.current || output.running) return;
    pending.current = true; setBusy(true); setError(null); setFinished(false);
    try {
      if (launch && review) {
        setReview(null);
        await output.replayRun(review);
        emitDataChanged();
        if (active.current) setFinished(true);
      } else {
        const value = await getTransport().invoke<ReplayReview>("replay_review", { runId });
        if (value.run_id !== runId) throw new Error(t("replay.wrongRun"));
        if (active.current) { setReview(value); setReplayProject(value.project); }
      }
    } catch (error) {
      if (active.current) { setError(formatInvokeError(error)); setReview(null); }
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  }
  return <div className="flex flex-col gap-2 mt-3">
    {error && <p role="alert" className="text-error">{error}</p>}
    {finished && <p role="status">{t("replay.finished")}</p>}
    {review ? <section className="surface-card p-3 flex flex-col gap-2" aria-label={t("replay.review")}>
      <p className="text-xs break-all">{review.project} · {review.target}</p>
      <p>{review.engine} · {review.duration_secs}s · {review.max_mem_mb} MiB · {review.max_cpus} CPU</p>
      <p className="text-xs break-all">{t("experiments.seed")}: {review.seed}</p>
      <p className="text-xs break-all">{t("replay.original")}: {review.run_id}</p>
      <p className="text-sm">{t("replay.limits")}</p>
      <div className="flex gap-2 flex-wrap">
        <Button variant="primary" disabled={busy || output.running} onClick={() => void perform(true)}>{t("replay.start")}</Button>
        <Button onClick={() => setReview(null)}>{t("common.cancel")}</Button>
      </div>
    </section> : <Button className="self-start" disabled={busy || output.running} onClick={() => void perform(false)}>{busy ? t("common.loading") : t("replay.review")}</Button>}
    {output.running && replayProject && <><p role="status">{t("replay.monitor")}</p>{onNavigate && <Button className="self-start" onClick={() => { setActiveProject(replayProject); onNavigate("run"); }}>{t("nav.run")}</Button>}</>}
  </div>;
}
