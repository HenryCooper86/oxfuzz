import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Bug, ChevronRight, Download, FileText, Share2 } from "lucide-react";
import { Button, Input, SeverityBadge, ViewHeader } from "../components/ui";
import { FindingProofCard } from "../components/FindingProofCard";
import { PatchToProofPanel } from "../components/PatchToProofPanel";
import { PathActions } from "../components/PathActions";
import { emitDataChanged, getTransport, isTauriEnvironment } from "../lib";
import { useI18n } from "../i18nContext";
import { useFindingSelection } from "../providers/findingSelection";
import { usePipeline } from "../providers/pipeline";
import { useProject } from "../providers/project";
import { useRunOutput } from "../providers/runOutput";
import type { Crash, CrashVerdict, FindingReviewFilter, FindingReviewItem, TriageDisposition } from "../types";

const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((module) => ({ default: module.ReportPreview })),
);

const DISPOSITIONS: TriageDisposition["disposition"][] = [
  "report_ready",
  "reachability_unproven",
  "minimization_pending",
  "symbolization_pending",
  "runtime_artifact",
  "harness_defect",
  "resolved",
];

function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 8) : id;
}

export function TriageView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject } = useProject();
  return <ScopedTriageView key={activeProject} embedded={embedded} />;
}

function ScopedTriageView({ embedded }: { embedded: boolean }) {
  const { t, locale } = useI18n();
  const { activeProject } = useProject();
  const { markDone, markSkipped } = usePipeline();
  const { lastTarget, lastEngine, summary } = useRunOutput();
  const { selection, selectFinding } = useFindingSelection();
  const [queue, setQueue] = useState<FindingReviewItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<FindingReviewItem | null>(null);
  const [queueLoading, setQueueLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [dispositionFilter, setDispositionFilter] = useState("open");
  const [originFilter, setOriginFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [runFilter, setRunFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [reloadVersion, setReloadVersion] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [reportMd, setReportMd] = useState<string | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, CrashVerdict | "loading" | "none">>({});
  const [formats, setFormats] = useState<string[]>(["md", "html"]);
  const queueRequest = useRef(0);
  const detailRequest = useRef(0);
  const actionRequest = useRef(0);
  const scanRequest = useRef(0);
  const selectionGeneration = useRef(0);
  const mounted = useRef(true);
  const isKernelRun = lastEngine === "syzkaller";

  const serviceFilter = useMemo<FindingReviewFilter>(() => ({
    disposition: dispositionFilter.startsWith("only:")
      ? { mode: "only", value: dispositionFilter.slice(5) as TriageDisposition["disposition"] }
      : { mode: dispositionFilter as "open" | "all" },
    origin: originFilter ? originFilter as Crash["origin"] : null,
    severity: severityFilter ? severityFilter as FindingReviewFilter["severity"] : null,
    run_id: runFilter.trim() || null,
    target_id: targetFilter.trim() || null,
  }), [dispositionFilter, originFilter, severityFilter, runFilter, targetFilter]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      queueRequest.current += 1;
      detailRequest.current += 1;
      actionRequest.current += 1;
      scanRequest.current += 1;
    };
  }, []);

  useEffect(() => {
    if (!isTauriEnvironment()) return;
    getTransport().invoke<string[]>("report_formats").then(setFormats).catch(() => setFormats(["md", "html"]));
  }, []);

  useEffect(() => {
    const request = ++queueRequest.current;
    if (!activeProject) return;
    queueMicrotask(() => {
      if (request !== queueRequest.current || !mounted.current) return;
      setQueue([]);
      setQueueLoading(true);
      setQueueError(null);
    });
    getTransport().invoke<FindingReviewItem[]>("finding_review_queue", { project: activeProject, filter: serviceFilter })
      .then((items) => {
        if (request !== queueRequest.current) return;
        setQueue(items);
      })
      .catch((error) => {
        if (request !== queueRequest.current) return;
        setQueue([]);
        setQueueError(String(error));
      })
      .finally(() => {
        if (request === queueRequest.current) setQueueLoading(false);
      });
  }, [activeProject, reloadVersion, serviceFilter]);

  useEffect(() => {
    const request = ++detailRequest.current;
    selectionGeneration.current += 1;
    actionRequest.current += 1;
    queueMicrotask(() => {
      if (request !== detailRequest.current || !mounted.current) return;
      setMessage(null);
      setReportMd(null);
      setVerdicts({});
      setReporting(false);
      setPushing(false);
    });
    if (!activeProject || !selection) {
      return;
    }
    queueMicrotask(() => {
      if (request !== detailRequest.current || !mounted.current) return;
      setSelectedFinding(null);
      setDetailError(null);
      setDetailLoading(true);
    });
    getTransport().invoke<FindingReviewItem>("finding_review", { project: activeProject, findingId: selection.findingId })
      .then((item) => {
        if (request === detailRequest.current) setSelectedFinding(item);
      })
      .catch((error) => {
        if (request === detailRequest.current) setDetailError(String(error));
      })
      .finally(() => {
        if (request === detailRequest.current) setDetailLoading(false);
      });
  }, [activeProject, selection]);

  const activeFinding = selectedFinding?.crash.id === selection?.findingId
    ? selectedFinding
    : null;

  const visibleQueue = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return queue;
    return queue.filter((item) => [item.target_symbol, item.crash.summary, item.crash.stack_signature, item.crash.id, item.crash.run_id]
      .some((value) => value.toLowerCase().includes(needle)));
  }, [queue, search]);

  const triage = useCallback(async () => {
    const request = ++scanRequest.current;
    const selectedGeneration = selectionGeneration.current;
    setScanning(true);
    setMessage(null);
    try {
      const crashes = await getTransport().invoke<Crash[]>("triage", { project: activeProject || ".", target: lastTarget });
      if (
        !mounted.current
        || request !== scanRequest.current
        || selectedGeneration !== selectionGeneration.current
      ) return;
      if (crashes.length > 0) {
        markDone("triage");
        selectFinding(crashes[0].id, crashes[0].run_id);
      } else {
        markSkipped("triage");
      }
      setReloadVersion((value) => value + 1);
    } catch (error) {
      if (
        mounted.current
        && request === scanRequest.current
        && selectedGeneration === selectionGeneration.current
      ) setMessage(t("triage.scanFailed", { error: String(error) }));
    } finally {
      if (mounted.current && request === scanRequest.current) setScanning(false);
    }
  }, [activeProject, lastTarget, markDone, markSkipped, selectFinding, t]);

  const actionTarget = selection ? activeFinding?.target_selector ?? "" : lastTarget;
  const actionDisplayTarget = selection ? activeFinding?.target_symbol ?? "" : lastTarget;
  const latestActionsAllowed = selection
    ? activeFinding?.latest_scoped_actions_allowed === true
    : Boolean(lastTarget);
  const disabledReason = activeFinding?.latest_scoped_action_reason ?? undefined;
  const actionsBusy = scanning || reporting || pushing || Object.values(verdicts).includes("loading");

  const composeReport = useCallback(async () => {
    if (!actionTarget || !latestActionsAllowed) return;
    const request = ++actionRequest.current;
    setReporting(true);
    setMessage(null);
    try {
      const markdown = await getTransport().invoke<string>("generate_report", { project: activeProject || ".", target: actionTarget, language: locale, expectedRunId: activeFinding?.crash.run_id });
      if (request !== actionRequest.current || !mounted.current) return;
      setReportMd(markdown);
      await getTransport().invoke("save_report_draft", { title: t("reports.triageDraftTitle", { target: actionDisplayTarget }), project: activeProject || ".", target: actionTarget, status: "Draft", content: markdown });
      if (request !== actionRequest.current || !mounted.current) return;
      emitDataChanged();
      setMessage(t("triage.reportComposed"));
    } catch (error) {
      if (request === actionRequest.current && mounted.current) setMessage(t("triage.reportFailed", { error: String(error) }));
    } finally {
      if (request === actionRequest.current && mounted.current) setReporting(false);
    }
  }, [actionDisplayTarget, actionTarget, activeFinding, activeProject, latestActionsAllowed, locale, t]);

  const exportReport = useCallback(async (format: string) => {
    if (!actionTarget || !latestActionsAllowed) return;
    try {
      if (isTauriEnvironment()) {
        const saved = await getTransport().invoke<string | null>("export_report", { project: activeProject || ".", target: actionTarget, format, language: locale, expectedRunId: activeFinding?.crash.run_id });
        if (saved && mounted.current) setMessage(t("triage.reportSaved", { format: format.toUpperCase(), path: saved }));
      } else if (format === "md" && reportMd && mounted.current) {
        const url = URL.createObjectURL(new Blob([reportMd], { type: "text/markdown" }));
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `oxfuzz_report_${actionTarget.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
        anchor.click();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      if (mounted.current) setMessage(t("triage.exportFailed", { error: String(error) }));
    }
  }, [actionTarget, activeFinding, activeProject, latestActionsAllowed, locale, reportMd, t]);

  const exportRepro = useCallback(async () => {
    if (!activeFinding?.latest_scoped_actions_allowed || !isTauriEnvironment()) return;
    const request = ++actionRequest.current;
    try {
      const saved = await getTransport().invoke<string | null>("export_repro", {
        project: activeProject || ".",
        target: activeFinding.target_selector,
        engine: activeFinding.engine,
        lang: activeFinding.target_language,
        crash: activeFinding.crash.id,
      });
      if (saved && request === actionRequest.current && mounted.current) setMessage(t("triage.reproSaved", { path: saved }));
    } catch (error) {
      if (request === actionRequest.current && mounted.current) setMessage(t("triage.exportFailed", { error: String(error) }));
    }
  }, [activeFinding, activeProject, t]);

  const pushToDefectDojo = useCallback(async () => {
    if (!activeFinding?.latest_scoped_actions_allowed) return;
    const request = ++actionRequest.current;
    setPushing(true);
    try {
      const outcome = await getTransport().invoke<{ findings_pushed: number }>("push_to_defectdojo", { project: activeProject || ".", target: activeFinding.target_selector, expectedRunId: activeFinding.crash.run_id });
      if (request === actionRequest.current && mounted.current) setMessage(t("triage.pushed", { n: outcome.findings_pushed, reimport: "", where: "" }));
    } catch (error) {
      if (request === actionRequest.current && mounted.current) setMessage(t("triage.pushFailed", { error: String(error) }));
    } finally {
      if (request === actionRequest.current && mounted.current) setPushing(false);
    }
  }, [activeFinding, activeProject, t]);

  const verifyCrash = useCallback(async (item: FindingReviewItem) => {
    if (!item.latest_scoped_actions_allowed) return;
    const request = ++actionRequest.current;
    setVerdicts((current) => ({ ...current, [item.crash.id]: "loading" }));
    try {
      const verdict = await getTransport().invoke<CrashVerdict | null>("verify_crash", { project: activeProject || ".", target: item.target_symbol, crash: item.crash });
      if (request === actionRequest.current && mounted.current) setVerdicts((current) => ({ ...current, [item.crash.id]: verdict ?? "none" }));
    } catch {
      if (request === actionRequest.current && mounted.current) setVerdicts((current) => ({ ...current, [item.crash.id]: "none" }));
    }
  }, [activeProject]);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        {embedded ? <span /> : <ViewHeader title={t("triage.title")} description={t("triage.description")} />}
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void composeReport()} disabled={actionsBusy || !actionTarget || !latestActionsAllowed} loading={reporting} title={disabledReason ?? t("triage.composeReportTooltip")}>
            {!reporting && <FileText size={14} />}{t(reporting ? "triage.composing" : "triage.composeReport")}
          </Button>
          {activeFinding && <Button variant="outline" size="sm" onClick={() => void pushToDefectDojo()} disabled={actionsBusy || !latestActionsAllowed} loading={pushing} title={disabledReason ?? t("triage.pushTooltip")}>
            {!pushing && <Share2 size={14} />}{t(pushing ? "triage.pushing" : "triage.pushToDefectDojo")}
          </Button>}
          {activeFinding && isTauriEnvironment() && <Button variant="outline" size="sm" onClick={() => void exportRepro()} disabled={actionsBusy || !latestActionsAllowed} title={disabledReason ?? t("triage.downloadRepro")}>
            <Download size={14} />{t("triage.downloadRepro")}
          </Button>}
          <Button variant="primary" onClick={() => void triage()} disabled={actionsBusy || !lastTarget || isKernelRun} loading={scanning}>
            {!scanning && <Bug size={14} />}{t(scanning ? "triage.scanning" : "triage.scanForCrashes")}
          </Button>
        </div>
      </div>
      {message && <div className="text-xs text-text-muted">{message}</div>}
      {disabledReason && <div role="status" className="surface-card text-xs text-text-muted" style={{ padding: "var(--space-sm) var(--space-md)" }}>{disabledReason}</div>}
      <div className="surface-card grid gap-2" style={{ padding: "var(--space-sm)", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
        <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("triage.searchFindings")} />
        <select aria-label={t("triage.filterDisposition")} value={dispositionFilter} onChange={(event) => setDispositionFilter(event.target.value)}>
          <option value="open">{t("triage.filterOpen")}</option><option value="all">{t("triage.filterAll")}</option>
          {DISPOSITIONS.map((disposition) => <option key={disposition} value={`only:${disposition}`}>{t(`triage.disposition.${disposition}`)}</option>)}
        </select>
        <select aria-label={t("triage.filterOrigin")} value={originFilter} onChange={(event) => setOriginFilter(event.target.value)}>
          <option value="">{t("triage.filterAnyOrigin")}</option><option value="target">target</option><option value="unknown">unknown</option><option value="runtime">runtime</option><option value="harness">harness</option>
        </select>
        <select aria-label={t("triage.filterSeverity")} value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
          <option value="">{t("triage.filterAnySeverity")}</option><option value="exploitable">exploitable</option><option value="probably_exploitable">probably exploitable</option><option value="not_exploitable">not exploitable</option><option value="undefined">undefined</option><option value="unavailable">unclassified</option>
        </select>
        <Input value={runFilter} onChange={(event) => setRunFilter(event.target.value)} placeholder={t("triage.filterRun")} mono />
        <Input value={targetFilter} onChange={(event) => setTargetFilter(event.target.value)} placeholder={t("triage.filterTarget")} mono />
      </div>
      {queueError && <div role="alert" className="surface-card text-xs" style={{ padding: "var(--space-sm)", color: "var(--error)" }}>{t("triage.queueFailed", { error: queueError })}</div>}
      {queueLoading && <div role="status" className="text-xs text-text-muted">{t("triage.loadingQueue")}</div>}
      {!queueLoading && !queueError && visibleQueue.length === 0 && <div className="surface-card text-sm text-text-muted" style={{ padding: "var(--space-xl)", textAlign: "center" }}>{t("triage.noMatchingFindings")}</div>}
      {(visibleQueue.length > 0 || selection || detailLoading || detailError) && <div className="flex gap-3" style={{ animation: "slideInUp 0.2s ease" }}>
        <div className="flex flex-col gap-1 flex-1">
          {visibleQueue.map((item) => <button key={item.crash.id} onClick={() => selectFinding(item.crash.id, item.crash.run_id)} className={`surface-card flex items-center gap-2 text-left ${selection?.findingId === item.crash.id ? "border-[var(--border-focus)]" : ""}`} style={{ padding: "var(--space-sm) var(--space-md)" }}>
            <Bug size={14} style={{ color: "var(--error)" }} />
            <span className="flex flex-col min-w-0 flex-1">
              <span className="text-xs font-mono truncate">{item.target_symbol} · {shortId(item.crash.id)}</span>
              <span className="text-xs text-text-secondary truncate">{item.crash.summary || item.crash.kind}</span>
              <span className="text-xs text-text-muted font-mono">{shortId(item.crash.run_id)} · {item.proof.casr_exploitability.determination}</span>
            </span>
            <span className="text-xs text-text-muted">{t(`triage.disposition.${item.disposition.disposition}`)}</span><ChevronRight size={14} className="text-text-muted" />
          </button>)}
        </div>
        <div className="surface-card flex-1" style={{ padding: "var(--space-md)" }}>
          {detailLoading && <div role="status" className="text-xs text-text-muted">{t("triage.loadingFinding")}</div>}
          {detailError && <div role="alert" className="text-xs" style={{ color: "var(--error)" }}>{t("triage.findingUnavailable", { id: selection?.findingId ?? "", error: detailError })}</div>}
          {activeFinding && <CrashDetail item={activeFinding} verdict={verdicts[activeFinding.crash.id]} onVerify={() => void verifyCrash(activeFinding)} actionBusy={actionsBusy} />}
        </div>
      </div>}
      {reportMd !== null && <Suspense fallback={null}><ReportPreview markdown={reportMd} onClose={() => setReportMd(null)} onExport={(format) => void exportReport(format)} formats={formats} /></Suspense>}
      {isKernelRun && summary && <div className="surface-card text-sm" style={{ padding: "var(--space-md)" }}>{t("triage.kernelReportedPrefix")} {summary.crashes}{t("triage.kernelExplanation")}</div>}
    </div>
  );
}

function CrashDetail({ item, verdict, onVerify, actionBusy }: { item: FindingReviewItem; verdict: CrashVerdict | "loading" | "none" | undefined; onVerify: () => void; actionBusy: boolean }) {
  const { t } = useI18n();
  const { crash } = item;
  return <div className="flex flex-col gap-3">
    <div className="flex items-center gap-2"><span className="text-xs px-2 py-1 rounded-sm font-medium" style={{ background: "var(--error-subtle)", color: "var(--error)" }}>{crash.kind}</span>{crash.casr && <SeverityBadge severity={crash.casr.severity} title={crash.casr.severity_short || crash.casr.severity} />}<span className="text-xs text-text-muted font-mono truncate min-w-0 flex-1" title={crash.input_path}>{crash.input_path.split("/").pop()}</span><PathActions path={crash.input_path} /></div>
    <div className="text-xs text-text-muted font-mono">{item.target_symbol} · {crash.run_id}</div>
    {crash.summary && <p className="text-sm text-text-secondary">{crash.summary}</p>}
    <FindingProofCard proof={item.proof} />
    <PatchToProofPanel key={crash.id} findingId={crash.id} runId={crash.run_id} />
    <div className="border-t border-border pt-3">
      {verdict === undefined && <Button size="sm" variant="ghost" onClick={onVerify} disabled={actionBusy || !item.latest_scoped_actions_allowed} title={item.latest_scoped_action_reason ?? undefined}>{t("triage.verifyCrash")}</Button>}
      {verdict === "loading" && <span className="text-xs text-text-muted">{t("triage.verifying")}</span>}
      {verdict === "none" && <span className="text-xs text-text-muted">{t("triage.noVerdict")}</span>}
      {verdict && verdict !== "loading" && verdict !== "none" && <div className="flex flex-col gap-1 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-text-secondary">{verdict.likely_target_bug ? t("triage.likelyTargetBug") : t("triage.likelyArtifact")}</span>
          <span className="text-text-muted">{t("triage.confidence", { level: verdict.confidence })}</span>
          {verdict.reproduces_deterministically && <span className="text-text-muted">· {t("triage.reproduces")}</span>}
        </div>
        {verdict.reasons.length > 0 && <ul className="text-text-secondary" style={{ paddingLeft: 16, listStyleType: "disc" }}>
          {verdict.reasons.map((reason) => <li key={reason}>{reason}</li>)}
        </ul>}
      </div>}
    </div>
    {crash.casr && <div className="border-t border-border pt-3">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <SeverityBadge severity={crash.casr.severity} title={crash.casr.severity_short || crash.casr.severity} />
        {crash.casr.severity_short && <span className="text-xs text-text-secondary font-mono">{crash.casr.severity_short}</span>}
        {crash.casr.crashline && <span className="text-xs text-text-muted font-mono">@ {crash.casr.crashline}</span>}
        {crash.casr.cluster != null && <span className="text-xs text-text-muted">{t("triage.cluster", { n: crash.casr.cluster })}</span>}
      </div>
      {crash.casr.stack.length > 0 && <code className="text-xs text-text-secondary block font-mono p-2 rounded-md whitespace-pre-wrap" style={{ background: "var(--surface-code)" }}>
        {crash.casr.stack.slice(0, 8).join("\n")}
      </code>}
    </div>}
    {crash.stack_signature && <code className="text-xs text-text-secondary block font-mono p-2 rounded-md" style={{ background: "var(--surface-code)" }}>{crash.stack_signature}</code>}
    {crash.bug_report && <div className="border-t border-border pt-3"><div className="text-xs text-text-muted uppercase">{t("triage.draftBugReport")}</div><p className="text-sm font-medium text-accent">{crash.bug_report.title}</p><p className="text-xs text-text-secondary">{crash.bug_report.summary}</p></div>}
  </div>;
}
