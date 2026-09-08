import { useEffect, useMemo, useRef, useState } from "react";
import { getTransport } from "../lib";
import { formatInvokeError } from "../lib/invokeError";
import type {
  HarnessReviewItem,
  HarnessWorkOrder,
  HarnessWorkOrderAttempt,
  HarnessWorkOrderRanking,
  HarnessWorkOrderSubmission,
  WorkOrderSubmissionOrigin,
} from "../types";
import { Button, Input, Textarea } from "./ui";
import { HarnessApprovalEvidence } from "./HarnessApprovalEvidence";
import { useI18n } from "../i18nContext";
import { canonicalHarnessEngine, canonicalHarnessLanguage, qualifiedTargetSelector, matchesTargetSelection } from "../lib/harnessScope";

function short(value: string | null | undefined) {
  return value ? `${value.slice(0, 16)}...` : "--";
}

interface WorkOrderPanelProps {
  project: string;
  target: string;
  language: string;
  engine: string;
  onPromoted?: (harnessId: string, targetSelector: string) => void;
}

function belongsToScope(order: HarnessWorkOrder, target: string, language: string, engine: string) {
  const evidence = order.payload.target as Record<string, unknown> | undefined;
  return typeof evidence?.symbol === "string"
    && matchesTargetSelection(evidence.symbol, typeof evidence.relative_source === "string" ? qualifiedTargetSelector(evidence.relative_source, evidence.symbol) : null, target)
    && canonicalHarnessLanguage(evidence.language) === canonicalHarnessLanguage(language)
    && canonicalHarnessEngine(order.payload.engine) === canonicalHarnessEngine(engine);
}

export function WorkOrderPanel(props: WorkOrderPanelProps) {
  const scope = `${props.project}\u0000${props.target}\u0000${props.language}\u0000${props.engine}`;
  return <WorkOrderPanelSession key={scope} {...props} />;
}

function WorkOrderPanelSession({
  project,
  target,
  language,
  engine,
  onPromoted,
}: WorkOrderPanelProps) {
  const { t } = useI18n();
  const [orders, setOrders] = useState<HarnessWorkOrder[]>([]);
  const [selectedOrder, setSelectedOrder] = useState<string | null>(null);
  const [submissions, setSubmissions] = useState<HarnessWorkOrderSubmission[]>([]);
  const [selectedSubmission, setSelectedSubmission] = useState<string | null>(null);
  const [attempts, setAttempts] = useState<HarnessWorkOrderAttempt[]>([]);
  const [selectedAttempt, setSelectedAttempt] = useState<string | null>(null);
  const [source, setSource] = useState("");
  const [external, setExternal] = useState(false);
  const [tool, setTool] = useState("");
  const [model, setModel] = useState("");
  const [responseId, setResponseId] = useState("");
  const [parentSubmission, setParentSubmission] = useState<string | null>(null);
  const [ranking, setRanking] = useState<HarnessWorkOrderRanking | null>(null);
  const [approvalEvidence, setApprovalEvidence] = useState<HarnessReviewItem | null>(null);
  const [evidenceState, setEvidenceState] = useState<"idle" | "loading" | "ready" | "missing" | "error">("idle");
  const [evidenceRefresh, setEvidenceRefresh] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const lifetime = useRef(0);
  const orderRead = useRef(0);
  const submissionRead = useRef(0);
  const attemptRead = useRef(0);
  const evidenceRead = useRef(0);
  useEffect(() => {
    lifetime.current += 1;
    return () => { lifetime.current += 1; };
  }, []);

  const order = useMemo(
    () => orders.find((item) => item.id === selectedOrder) ?? null,
    [orders, selectedOrder],
  );
  const selectedAttemptRecord = attempts.find((item) => item.id === selectedAttempt) ?? null;
  const selectedSubmissionRecord = submissions.find((item) => item.id === selectedSubmission) ?? null;
  const sourceBytes = useMemo(() => new TextEncoder().encode(source).length, [source]);
  const sourceValid = source.trim().length > 0 && sourceBytes <= 65_536;
  const qualificationRunning = attempts.some((item) => item.status === "running");

  useEffect(() => {
    let current = true;
    const generation = ++orderRead.current;
    getTransport().invoke<HarnessWorkOrder[]>("work_order_list", { project })
      .then((items) => {
        if (!current || orderRead.current !== generation) return;
        const scoped = items.filter((item) => belongsToScope(item, target, language, engine));
        setOrders(scoped);
        setSelectedOrder((id) => scoped.some((item) => item.id === id) ? id : scoped[0]?.id ?? null);
      })
      .catch((cause) => {
        if (!current || orderRead.current !== generation) return;
        const message = formatInvokeError(cause);
        setError(message);
        setUnavailable(message.toLowerCase().includes("unavailable") || message.includes("404"));
      });
    return () => { current = false; };
  }, [project, target, language, engine]);

  useEffect(() => {
    let current = true;
    if (!selectedOrder) {
      return () => { current = false; };
    }
    const generation = ++submissionRead.current;
    getTransport().invoke<HarnessWorkOrderSubmission[]>("work_order_submissions", { workOrderId: selectedOrder })
      .then((items) => {
        if (!current || submissionRead.current !== generation) return;
        setSubmissions(items);
        setSelectedSubmission((id) => items.some((item) => item.id === id) ? id : items[0]?.id ?? null);
      })
      .catch((cause) => { if (current && submissionRead.current === generation) setError(formatInvokeError(cause)); });
    return () => { current = false; };
  }, [selectedOrder]);

  useEffect(() => {
    let current = true;
    if (!selectedSubmission) {
      return () => { current = false; };
    }
    const generation = ++attemptRead.current;
    getTransport().invoke<HarnessWorkOrderAttempt[]>("work_order_attempts", { submissionId: selectedSubmission })
      .then((items) => {
        if (!current || attemptRead.current !== generation) return;
        setAttempts(items);
        const next = items[0] ?? null;
        setEvidenceState(next?.harness_id ? "loading" : "idle");
        setSelectedAttempt(next?.id ?? null);
      })
      .catch((cause) => { if (current && attemptRead.current === generation) setError(formatInvokeError(cause)); });
    return () => { current = false; };
  }, [selectedSubmission]);

  useEffect(() => {
    let current = true;
    const harnessId = selectedAttemptRecord?.harness_id;
    if (!harnessId) {
      return () => { current = false; };
    }
    const generation = ++evidenceRead.current;
    getTransport().invoke<HarnessReviewItem[]>("harness_review_queue", { project, target })
      .then((items) => {
        if (!current || evidenceRead.current !== generation) return;
        const evidence = items.find((item) => item.harness_id === harnessId) ?? null;
        setApprovalEvidence(evidence);
        setEvidenceState(evidence ? "ready" : "missing");
      })
      .catch((cause) => {
        if (!current || evidenceRead.current !== generation) return;
        setEvidenceState("error");
        setError(formatInvokeError(cause));
      });
    return () => { current = false; };
  }, [evidenceRefresh, project, selectedAttemptRecord?.harness_id, target]);

  async function run<T>(name: string, operation: () => Promise<T>): Promise<T | null> {
    const generation = lifetime.current;
    setBusy(name);
    setError(null);
    try {
      const value = await operation();
      return lifetime.current === generation ? value : null;
    } catch (cause) {
      if (lifetime.current === generation) setError(formatInvokeError(cause));
      return null;
    } finally {
      if (lifetime.current === generation) setBusy(null);
    }
  }

  async function exportOrder() {
    orderRead.current += 1;
    const created = await run("export", () => getTransport().invoke<HarnessWorkOrder>("work_order_export", {
      project, target, lang: language, engine,
    }));
    if (!created) return;
    setOrders((items) => [created, ...items.filter((item) => item.id !== created.id)]);
    if (created.id === selectedOrder) return;
    submissionRead.current += 1;
    attemptRead.current += 1;
    evidenceRead.current += 1;
    setSelectedOrder(created.id);
    setSubmissions([]);
    setSelectedSubmission(null);
    setParentSubmission(null);
    setAttempts([]);
    setSelectedAttempt(null);
    setApprovalEvidence(null);
    setEvidenceState("idle");
    setRanking(null);
  }

  async function importSubmission() {
    if (!selectedOrder || !source.trim()) return;
    const origin: WorkOrderSubmissionOrigin = external
      ? { external_tool: { tool, model: model || null, response_id: responseId || null } }
      : "human";
    submissionRead.current += 1;
    const created = await run("import", () => getTransport().invoke<HarnessWorkOrderSubmission>("work_order_import", {
      workOrderId: selectedOrder,
      source,
      origin,
      parentSubmissionId: parentSubmission,
    }));
    if (!created) return;
    setSubmissions((items) => [created, ...items]);
    setAttempts([]);
    setSelectedAttempt(null);
    setApprovalEvidence(null);
    setEvidenceState("idle");
    setRanking(null);
    setSelectedSubmission(created.id);
  }

  async function qualify() {
    if (!selectedSubmission) return;
    attemptRead.current += 1;
    const attempt = await run("qualify", () => getTransport().invoke<HarnessWorkOrderAttempt>("work_order_qualify", {
      submissionId: selectedSubmission,
    }));
    if (!attempt) return;
    setAttempts((items) => [attempt, ...items.filter((item) => item.id !== attempt.id)]);
    setApprovalEvidence(null);
    setEvidenceRefresh((value) => value + 1);
    setSelectedAttempt(attempt.id);
  }

  async function rank() {
    const ranked = await run("rank", () => getTransport().invoke<HarnessWorkOrderRanking>("work_order_rank", {
      attemptIds: attempts.map((item) => item.id),
    }));
    if (!ranked) return;
    setRanking(ranked);
    setApprovalEvidence(null);
    const rankedAttempt = attempts.find((item) => item.id === (ranked.winner_attempt_id ?? ranked.attempt_ids[0]));
    setEvidenceState(rankedAttempt?.harness_id ? "loading" : "idle");
    setEvidenceRefresh((value) => value + 1);
    setSelectedAttempt(ranked.winner_attempt_id ?? ranked.attempt_ids[0] ?? null);
  }

  async function refreshAttempts() {
    if (!selectedSubmission) return;
    attemptRead.current += 1;
    const retained = await run("refresh", () => getTransport().invoke<HarnessWorkOrderAttempt[]>("work_order_attempts", {
      submissionId: selectedSubmission,
    }));
    if (!retained) return;
    setAttempts(retained);
    setApprovalEvidence(null);
    const refreshedAttempt = retained.find((item) => item.id === selectedAttempt) ?? retained[0] ?? null;
    setEvidenceState(refreshedAttempt?.harness_id ? "loading" : "idle");
    setEvidenceRefresh((value) => value + 1);
    setSelectedAttempt((id) => retained.some((item) => item.id === id) ? id : retained[0]?.id ?? null);
  }

  async function promote() {
    if (!selectedAttempt) return;
    const promoted = await run("promote", () => getTransport().invoke<{ id: string }>("work_order_promote", {
      attemptId: selectedAttempt,
    }));
    if (!promoted) return;
    if (approvalEvidence?.target_selector) onPromoted?.(promoted.id, approvalEvidence.target_selector);
  }

  async function copyPacket() {
    if (!order) return;
    const generation = lifetime.current;
    try {
      if (!navigator.clipboard) throw new Error("Clipboard access is unavailable");
      await navigator.clipboard.writeText(JSON.stringify(order, null, 2));
    } catch (cause) {
      if (lifetime.current === generation) setError(formatInvokeError(cause));
    }
  }

  function downloadPacket() {
    if (!order) return;
    try {
      const url = URL.createObjectURL(new Blob([JSON.stringify(order, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `harness-work-order-${order.id}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setError(formatInvokeError(cause));
    }
  }

  return (
    <section data-work-order-panel className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div><h3 className="text-sm font-semibold">{t("workOrder.title")}</h3><p className="text-xs text-text-muted">{t("workOrder.description")}</p></div>
        <Button size="sm" onClick={() => void exportOrder()} disabled={!project || !target || unavailable || busy !== null}>{t("workOrder.export")}</Button>
      </div>
      {error && <p role="alert" className="text-xs" style={{ color: "var(--error)" }}>{error}</p>}
      {orders.length > 0 && (
        <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(180px, 0.35fr) minmax(0, 1fr)" }}>
          <div className="flex flex-col gap-1">
            {orders.map((item) => <button type="button" key={item.id} disabled={busy !== null} className="text-left text-xs surface-card" onClick={() => { if (item.id === selectedOrder) return; setSelectedOrder(item.id); setSubmissions([]); setSelectedSubmission(null); setParentSubmission(null); setAttempts([]); setSelectedAttempt(null); setApprovalEvidence(null); setEvidenceState("idle"); setRanking(null); }}>{short(item.id)}</button>)}
          </div>
          {order && <div className="min-w-0"><p className="text-xs mb-2"><strong>{target}</strong> · {language} · {engine}</p><div className="flex gap-2 mb-2"><Button size="sm" variant="outline" onClick={() => void copyPacket()}>{t("workOrder.copy")}</Button><Button size="sm" variant="outline" onClick={downloadPacket}>{t("workOrder.download")}</Button></div><pre className="text-xs overflow-auto max-h-48">{JSON.stringify(order, null, 2)}</pre></div>}
        </div>
      )}
      {selectedOrder && (
        <div className="flex flex-col gap-2 border-t border-border pt-3">
          <Textarea aria-label={t("workOrder.source")} value={source} onChange={(event) => setSource(event.target.value)} placeholder={t("workOrder.sourcePlaceholder")} rows={8} />
          <label className="text-xs"><input type="checkbox" checked={external} onChange={(event) => setExternal(event.target.checked)} /> {t("workOrder.external")}</label>
          <p className="text-xs text-text-muted">{t("workOrder.toolRequired")}</p>
          {external && <div className="grid grid-cols-3 gap-2"><Input aria-label={t("workOrder.tool")} value={tool} onChange={(event) => setTool(event.target.value)} placeholder={t("workOrder.tool")} /><Input aria-label={t("workOrder.model")} value={model} onChange={(event) => setModel(event.target.value)} placeholder={t("workOrder.modelOptional")} /><Input aria-label={t("workOrder.responseId")} value={responseId} onChange={(event) => setResponseId(event.target.value)} placeholder={t("workOrder.responseIdOptional")} /></div>}
          <label className="text-xs">{t("workOrder.parent")}: <select value={parentSubmission ?? ""} onChange={(event) => setParentSubmission(event.target.value || null)} disabled={busy !== null}><option value="">{t("workOrder.noParent")}</option>{submissions.map((item) => <option key={item.id} value={item.id}>{short(item.source_sha256)}</option>)}</select></label>
          <p className="text-xs text-text-muted">{sourceBytes.toLocaleString()} / 65,536 UTF-8 bytes{sourceBytes > 65_536 ? ` · ${t("workOrder.tooLarge")}` : ""}</p>
          <Button size="sm" onClick={() => void importSubmission()} disabled={!sourceValid || (external && !tool.trim()) || unavailable || busy !== null}>{t("workOrder.import")}</Button>
        </div>
      )}
      {submissions.length > 0 && <div className="flex flex-col gap-1"><h4 className="text-xs font-semibold">{t("workOrder.history")}</h4>{submissions.map((item) => <button type="button" key={item.id} disabled={busy !== null} className="text-left text-xs" onClick={() => { if (item.id === selectedSubmission) return; setSelectedSubmission(item.id); setAttempts([]); setSelectedAttempt(null); setApprovalEvidence(null); setEvidenceState("idle"); setRanking(null); }}>{short(item.source_sha256)} · {typeof item.origin === "string" ? item.origin : item.origin.external_tool.tool} · {item.parent_submission_id ? `${t("workOrder.repairs")} ${item.parent_submission_id}` : t("workOrder.new")} · {item.lint.length} {t("workOrder.lintFindings")}</button>)}{selectedSubmissionRecord && <div className="surface-card p-2"><pre className="text-xs overflow-auto max-h-40">{selectedSubmissionRecord.source}</pre>{selectedSubmissionRecord.lint.map((finding) => <p key={`${finding.rule}-${finding.line}`} className="text-xs">{finding.severity} · {finding.rule}:{finding.line} · {finding.message}</p>)}</div>}<div className="flex gap-2"><Button size="sm" onClick={() => void qualify()} disabled={!selectedSubmission || qualificationRunning || unavailable || busy !== null}>{t("workOrder.qualify")}</Button><Button size="sm" variant="outline" onClick={() => void refreshAttempts()} disabled={!selectedSubmission || busy !== null}>{t("workOrder.refresh")}</Button></div></div>}
      {attempts.length > 0 && <div className="flex flex-col gap-2"><h4 className="text-xs font-semibold">{t("workOrder.evidence")}</h4>{attempts.map((item) => <button type="button" key={item.id} disabled={busy !== null} className="surface-card text-left text-xs" onClick={() => { setSelectedAttempt(item.id); setApprovalEvidence(null); setEvidenceState(item.harness_id ? "loading" : "idle"); setEvidenceRefresh((value) => value + 1); }}><strong>{item.status} · {item.current_stage}</strong><br />{item.failure_code && `${item.failure_code}: `}{item.failure_message ?? ""}{item.result && <span>{t("workOrder.compiled")} {String(item.result.compiled)} · {t("workOrder.smoke")} {item.result.smoke_verdict ?? t("workOrder.unavailable")} · {t("workOrder.sourceLabel")} {short(item.result.source_sha256)} · {t("workOrder.binary")} {short(item.result.binary_sha256)} · {t("workOrder.crashes")} {item.result.crashes ?? "--"} · {item.result.execs_per_sec ?? "--"} exec/s</span>}</button>)}<div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => void rank()} disabled={qualificationRunning || attempts.length === 0 || unavailable || busy !== null}>{t("workOrder.rank")}</Button><Button size="sm" onClick={() => void promote()} disabled={selectedAttemptRecord?.status !== "smoke_passed" || approvalEvidence?.harness_id !== selectedAttemptRecord.harness_id || unavailable || busy !== null}>{t("workOrder.promote")}</Button></div>{selectedAttemptRecord?.status === "smoke_passed" && evidenceState === "loading" && <p className="text-xs text-text-muted">{t("workOrder.loadingReview")}</p>}{selectedAttemptRecord?.status === "smoke_passed" && (evidenceState === "missing" || evidenceState === "error") && <p className="text-xs text-text-muted">{t("workOrder.missingReview")} <button type="button" onClick={() => { setEvidenceState("loading"); setEvidenceRefresh((value) => value + 1); }}>{t("workOrder.retry")}</button></p>}{ranking && <p className="text-xs">{t("workOrder.ranked")}: {ranking.attempt_ids.join(", ")}</p>}</div>}
      {approvalEvidence && <HarnessApprovalEvidence item={approvalEvidence} />}
    </section>
  );
}
