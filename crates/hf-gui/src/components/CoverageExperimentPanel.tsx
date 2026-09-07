import { useCallback, useEffect, useRef, useState } from "react";
import { getTransport } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import { useI18n } from "../i18nContext";
import type { RunHistoryItem, ViewType } from "../types";
import type { CoverageExperiment, ExperimentAdvice, ExperimentCursor, ExperimentKind, ExperimentPage, ExperimentRun } from "../types/coverageExperiments";
import { Button } from "./ui";

function codeOf(error: unknown): string | null {
  if (error !== null && typeof error === "object" && "code" in error && typeof error.code === "string") return error.code;
  return null;
}
export function CoverageExperimentPanel(props: { project: string; target: string; advice: ExperimentAdvice | null; onNavigate?: (view: ViewType) => void }) {
  return <Inventory key={`${props.project}\0${props.target}`} {...props} />;
}
function Inventory({ project, target, advice, onNavigate }: { project: string; target: string; advice: ExperimentAdvice | null; onNavigate?: (view: ViewType) => void }) {
  const { t } = useI18n();
  const [runs, setRuns] = useState<RunHistoryItem[]>([]);
  const [chosenTarget, setChosenTarget] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    getTransport().invoke<RunHistoryItem[]>("run_history", { project }).then(value => {
      if (active) setRuns(value.filter(run => run.target === target && run.target_id && run.kind.toLowerCase() === "campaign" && ["done", "failed", "cancelled"].includes(run.status.toLowerCase()) && run.ended_at));
    }).catch(error => { if (active) setError(error); });
    return () => { active = false; };
  }, [project, target, revision]);
  const ids = [...new Set(runs.map(run => run.target_id!))];
  const targetId = ids.length === 1 ? ids[0] : ids.includes(chosenTarget) ? chosenTarget : "";
  const scopedRuns = runs.filter(run => run.target_id === targetId);
  return <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
    <h3>{t("experiments.title")}</h3><p className="text-xs text-text-muted">{t("experiments.manual")}</p>
    <Button variant="outline" size="sm" onClick={() => setRevision(value => value + 1)}>{t("experiments.refresh")}</Button>
    {error !== null && <p role="alert">{formatInvokeError(error)}</p>}
    {ids.length > 1 && <label>{t("experiments.target")}<select aria-label={t("experiments.target")} value={targetId} onChange={event => setChosenTarget(event.target.value)}><option value="">{t("experiments.choose")}</option>{ids.map(id => <option key={id}>{id}</option>)}</select></label>}
    {!targetId ? <p>{t("experiments.none")}</p> : <ExperimentWorkspace key={`${project}\0${targetId}`} project={scopedRuns[0].project_root} targetId={targetId} runs={scopedRuns} advice={advice} onNavigate={onNavigate} inventoryRevision={revision} />}
  </section>;
}
function ExperimentWorkspace({ project, targetId, runs, advice, onNavigate, inventoryRevision }: { project: string; targetId: string; runs: RunHistoryItem[]; advice: ExperimentAdvice | null; onNavigate?: (view: ViewType) => void; inventoryRevision: number }) {
  const { t } = useI18n();
  const selectionKey = `hf_coverage_experiment_selection_v1:${project}:${targetId}`;
  const [restoration] = useState(() => {
    try { return { id: localStorage.getItem(selectionKey), error: null as unknown }; }
    catch (error) { return { id: null, error }; }
  });
  const [items, setItems] = useState<CoverageExperiment[]>([]);
  const [cursor, setCursor] = useState<ExperimentCursor | null>(null);
  const [selected, setSelected] = useState<CoverageExperiment | null>(null);
  const [baseline, setBaseline] = useState("");
  const [kind, setKind] = useState<ExperimentKind>(advice?.kind ?? "grow_corpus");
  const [goal, setGoal] = useState(advice?.goal ?? "");
  const [hypothesis, setHypothesis] = useState("");
  const [duration, setDuration] = useState("");
  const [result, setResult] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<unknown>(restoration.error);
  const [unavailable, setUnavailable] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [busy, setBusy] = useState(false);
  const active = useRef(true);
  const generation = useRef(0);
  const listGeneration = useRef(0);
  const writing = useRef(false);
  const invalidateRequests = useCallback(() => { generation.current++; listGeneration.current++; }, []);
  useEffect(() => { active.current = true; return () => { active.current = false; invalidateRequests(); }; }, [invalidateRequests]);
  const failure = useCallback((error: unknown) => { setError(error); if (codeOf(error) === "feature_unavailable") setUnavailable(true); }, []);
  const history = useCallback(async (before: ExperimentCursor | null = null) => {
    const token = ++listGeneration.current;
    try {
      const page = await getTransport().invoke<ExperimentPage>("coverage_experiment_list", { project, target_id: targetId, limit: 20, before });
      if (!active.current || token !== listGeneration.current) return;
      setItems(old => before ? [...old, ...page.items] : page.items); setCursor(page.next_cursor); setUncertain(false);
    } catch (error) { if (active.current && token === listGeneration.current) failure(error); }
  }, [failure, project, targetId]);
  useEffect(() => { const timer = window.setTimeout(() => void history(), 0); return () => window.clearTimeout(timer); }, [history, inventoryRevision]);
  const scope = { project, target_id: targetId };
  const remember = useCallback((id: string | null) => {
    try { if (id) localStorage.setItem(selectionKey, id); else localStorage.removeItem(selectionKey); }
    catch (error) { failure(error); }
  }, [failure, selectionKey]);
  const choose = useCallback(async (id: string) => {
    const token = ++generation.current; setSelected(null); setResult(""); setReason(""); setError(null);
    if (!id) return;
    setBusy(true);
    try { const value = await getTransport().invoke<CoverageExperiment>("coverage_experiment_get", { id, scope: { project, target_id: targetId } }); if (active.current && token === generation.current) { setSelected(value); remember(value.id); } }
    catch (error) { if (active.current && token === generation.current) failure(error); }
    finally { if (active.current && token === generation.current) setBusy(false); }
  }, [failure, project, remember, targetId]);
  useEffect(() => {
    if (!restoration.id) return;
    const timer = window.setTimeout(() => void choose(restoration.id!), 0);
    return () => window.clearTimeout(timer);
  }, [choose, restoration.id]);
  const write = async (command: string, args: Record<string, unknown>) => {
    if (writing.current || unavailable) return;
    if (command === "coverage_experiment_create") listGeneration.current++;
    writing.current = true; const token = ++generation.current; setBusy(true); setError(null);
    try {
      const value = await getTransport().invoke<CoverageExperiment>(command, args);
      if (!active.current || token !== generation.current) return;
      setSelected(value); remember(value.id); setResult(""); setReason(""); await history();
    } catch (error) {
      if (active.current && token === generation.current) { failure(error); if (command === "coverage_experiment_create" && (codeOf(error) === null || codeOf(error) === "storage_error")) {
        // Reads started before the ambiguous outcome cannot recover its retained record.
        listGeneration.current++; setUncertain(true);
      } }
    } finally { if (active.current && token === generation.current) { writing.current = false; setBusy(false); } }
  };
  const baselineRun = runs.find(run => run.id === baseline);
  const laterRuns = runs.filter(run => selected && run.id !== selected.baseline_run_id);
  const [previousAdvice, setPreviousAdvice] = useState(advice);
  if (advice !== previousAdvice) {
    setPreviousAdvice(advice);
    if (advice && !selected && !busy) { setKind(advice.kind); setGoal(advice.goal); }
  }
  const errorCode = codeOf(error);
  const errorText = errorCode ? t(`experiments.error.${errorCode}`) : formatInvokeError(error);
  const disabled = busy || unavailable;
  return <div className="flex flex-col gap-3">
    <p className="font-mono text-xs">{targetId}</p>
    {error !== null && <p role="alert">{errorText}</p>}
    {uncertain && <p role="alert">{t("experiments.recover")}</p>}
    <label>{t("experiments.history")}<select aria-label={t("experiments.history")} value={selected?.id ?? ""} disabled={disabled} onChange={event => void choose(event.target.value)}><option value="">{t("experiments.choose")}</option>{items.map(item => <option key={item.id} value={item.id}>{item.goal_function} · {t(`experiments.status.${item.status}`)} · {item.id}</option>)}</select></label>
    {!items.length && !unavailable && <p>{t("experiments.empty")}</p>}
    {cursor && <Button disabled={disabled} onClick={() => void history(cursor)}>{t("experiments.more")}</Button>}
    {selected ? <>
      <Button disabled={disabled} onClick={() => { generation.current++; setSelected(null); setBaseline(""); setHypothesis(""); setGoal(""); setDuration(""); setReason(""); setResult(""); setError(null); remember(null); }}>{t("experiments.new")}</Button>
      <p>{selected.id} · {t(`experiments.status.${selected.status}`)}</p>
      <p>{t(`experiments.fact.${selected.kind}`)} · {selected.goal_function}</p><p>{selected.hypothesis}</p><p>{t("experiments.budget")}: {selected.duration_secs}</p>
      <RunEvidence run={selected.baseline} label={t("experiments.baselineStatus")} />
      {selected.status === "prepared" && <>
        <div className="flex gap-2"><Button disabled={!onNavigate} onClick={() => onNavigate?.(selected.kind === "grow_corpus" ? "corpus" : "harness")}>{t(selected.kind === "grow_corpus" ? "experiments.openCorpus" : "experiments.openHarness")}</Button><Button disabled={!onNavigate} onClick={() => onNavigate?.("run")}>{t("experiments.openRun")}</Button></div>
        <p className="text-xs">{t("experiments.error.invalid_chronology")}</p>
        <label>{t("experiments.result")}<select aria-label={t("experiments.result")} value={result} disabled={disabled} onChange={event => setResult(event.target.value)}><option value="">{t("experiments.choose")}</option>{laterRuns.map(run => <option key={run.id} value={run.id}>{run.id} · {run.started_at} · {t(`experiments.status.${run.status.toLowerCase() === "cancelled" ? "cancelledRun" : run.status.toLowerCase()}`)}</option>)}</select></label>
        <Button disabled={disabled || !result} onClick={() => void write("coverage_experiment_complete", { id: selected.id, request: { scope, result_run_id: result } })}>{t("experiments.attach")}</Button>
        <label>{t("experiments.reason")}<textarea aria-label={t("experiments.reason")} value={reason} disabled={disabled} onChange={event => setReason(event.target.value)} /></label>
        <Button disabled={disabled || !reason.trim()} onClick={() => void write("coverage_experiment_cancel", { id: selected.id, request: { scope, reason } })}>{t("experiments.cancel")}</Button>
      </>}
      {selected.cancellation_reason && <p>{selected.cancellation_reason}</p>}
      {selected.result && <>
        <RunEvidence run={selected.result.run} label={t("experiments.resultStatus")} />
        <p>{t("experiments.input")}: {t(`experiments.fact.${selected.result.input_change}`)}</p>
        <p>{t("experiments.build")}: {t(`experiments.fact.${selected.result.build_comparison}`)}</p>
        <p>{t("experiments.delta")}: {selected.result.edge_comparison.status === "observed" ? `${selected.result.edge_comparison.baseline_edges} → ${selected.result.edge_comparison.result_edges} (${selected.result.edge_comparison.delta})` : t(`experiments.limit.${selected.result.edge_comparison.reason_code}`)}</p>
        <p>{t("experiments.function")}: {t(`experiments.fact.${selected.result.target_entry.reason_code}`)}</p>
        <p>{t("experiments.limits")}</p><ul>{selected.result.limitations.map(code => <li key={code}>{t(`experiments.limit.${code}`)}</li>)}</ul>
      </>}
    </> : <>
      {advice && <Button disabled={disabled} onClick={() => { setGoal(advice.goal); setKind(advice.kind); }}>{t("experiments.advice")}</Button>}
      <label>{t("experiments.baseline")}<select aria-label={t("experiments.baseline")} value={baseline} disabled={disabled} onChange={event => { setBaseline(event.target.value); const run = runs.find(run => run.id === event.target.value); setDuration(run?.requested_duration_secs?.toString() ?? ""); }}><option value="">{t("experiments.choose")}</option>{runs.map(run => <option key={run.id} value={run.id}>{run.id} · {run.started_at} · {t(`experiments.status.${run.status.toLowerCase() === "cancelled" ? "cancelledRun" : run.status.toLowerCase()}`)}</option>)}</select></label>
      {baselineRun && <p>{t("experiments.budget")}: {baselineRun.requested_duration_secs ?? t("experiments.unknown")}</p>}
      <label>{t("experiments.kind")}<select aria-label={t("experiments.kind")} value={kind} disabled={disabled} onChange={event => setKind(event.target.value as ExperimentKind)}><option value="grow_corpus">{t("experiments.fact.grow_corpus")}</option><option value="refine_harness">{t("experiments.fact.refine_harness")}</option></select></label>
      <label>{t("experiments.goal")}<input aria-label={t("experiments.goal")} value={goal} disabled={disabled} onChange={event => setGoal(event.target.value)} /></label>
      <label>{t("experiments.hypothesis")}<textarea aria-label={t("experiments.hypothesis")} value={hypothesis} disabled={disabled} onChange={event => setHypothesis(event.target.value)} /></label>
      <label>{t("experiments.duration")}<input type="number" min="1" max="604800" step="1" aria-label={t("experiments.duration")} value={duration} disabled={disabled} onChange={event => setDuration(event.target.value)} /></label>
      <Button disabled={disabled || uncertain || !baseline || !goal.trim() || !hypothesis.trim() || !duration} onClick={() => void write("coverage_experiment_create", { ...scope, baseline_run_id: baseline, kind, goal_function: goal, hypothesis, duration_secs: Number(duration) })}>{t("experiments.prepare")}</Button>
    </>}
  </div>;
}
function RunEvidence({ run, label }: { run: ExperimentRun; label: string }) {
  const { t } = useI18n();
  return <div className="text-xs"><p>{label}: {t(`experiments.status.${run.status === "cancelled" ? "cancelledRun" : run.status}`)} · {run.run_id}</p><p>{t("experiments.seed")}: {run.seed ?? t("experiments.unknown")}</p><p>{t("experiments.memory")}: {run.max_mem_mb}</p><p>{t("experiments.edges")}: {run.edges ?? t("experiments.unknown")}</p><p>{t("experiments.build")}: {run.build_inputs?.build_input_sha256 ?? t("experiments.unknown")}</p></div>;
}
