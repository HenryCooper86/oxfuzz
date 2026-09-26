import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTransport, pickFolder } from "../lib";
import {
  buildSemgrepPresentation,
  canApplySemgrepResult,
  canStartSemgrep,
  hasOwnedSemgrepOperation,
  semgrepCancelDecision,
  semgrepStateAfterError,
  waitForSemgrep,
} from "../lib/semgrep";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { useDiscoveryInventory } from "../providers/discovery";
import { candidateTargetSelector } from "../lib/harnessScope";
import type { ViewType } from "../types";
import { useTarget } from "../providers/target";
import type {
  BoundSemgrepInventory,
  SemgrepContext,
} from "../lib/semgrep";
import type {
  SemgrepCancelOutcome,
  SemgrepOperationState,
  SemgrepTargetCandidate,
  TargetCandidate,
} from "../types";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import { useI18n } from "../i18nContext";
import { Crosshair, Search, Loader2, FolderOpen, ChevronRight, ChevronDown } from "lucide-react";
import { shouldLoadCoverage } from "../lib/discoverCoverage";
import { waitForRankedDiscovery } from "../lib/rankedDiscovery";
import { TargetAssessmentPanel } from "../components/discovery/TargetAssessmentPanel";
import type { RankedDiscoveryStatus, TargetAssessment } from "../types";

export function DiscoverView({ embedded = false, onNavigate }: { embedded?: boolean; onNavigate?: (view: ViewType) => void }) {
  const { t } = useI18n();
  const { activeProject, setActiveProject } = useProject();
  const { markDone } = usePipeline();
  // Language lives in the shared TargetContext so the C/C++ choice made here
  // flows through to Harness generation (which reads it from the same context).
  const { lang, setLang, setTarget, selectionRepair, storageError } = useTarget();
  // When embedded in the unified workflow, the project is fixed by the
  // workflow's project gate; standalone, this view has its own picker.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const { snapshot, save } = useDiscoveryInventory(project, lang);
  const inventory = snapshot?.inventory ?? null;
  const rankedResult = snapshot?.ranked ?? null;
  const [discoveryContext, setDiscoveryContext] =
    useState<SemgrepContext | null>(snapshot ? { project, lang } : null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rankingStatus, setRankingStatus] = useState<RankedDiscoveryStatus | null>(null);
  const [semgrepInventory, setSemgrepInventory] =
    useState<BoundSemgrepInventory | null>(snapshot?.semgrep ?? null);
  const [semgrepAvailable, setSemgrepAvailable] = useState(false);
  const [semgrepState, setSemgrepState] =
    useState<SemgrepOperationState | null>(null);
  const [semgrepOperationId, setSemgrepOperationId] =
    useState<string | null>(null);
  const [semgrepLoading, setSemgrepLoading] = useState(false);
  const [semgrepError, setSemgrepError] = useState<string | null>(null);
  const semgrepAbortRef = useRef<AbortController | null>(null);
  const semgrepOwnershipRef = useRef<AbortController | null>(null);
  const semgrepOperationIdRef = useRef<string | null>(null);
  const rankingAbortRef = useRef<AbortController | null>(null);
  const rankingOperationIdRef = useRef<string | null>(snapshot?.rankedOperationId ?? null);
  const rankingSequenceRef = useRef(0);
  const rankingContextRef = useRef<SemgrepContext | null>(snapshot ? { project, lang } : null);
  const mountedRef = useRef(true);
  const currentSelectionRef = useRef<SemgrepContext>({ project, lang });
  const discoveryContextRef = useRef<SemgrepContext | null>(discoveryContext);

  useEffect(() => {
    if (rankingContextRef.current && (
      rankingContextRef.current.project !== project || rankingContextRef.current.lang !== lang
    )) {
      rankingAbortRef.current?.abort();
      rankingAbortRef.current = null;
      rankingOperationIdRef.current = null;
      rankingContextRef.current = null;
      rankingSequenceRef.current += 1;
      setRankingStatus(null);
      setLoading(false);
    }
    currentSelectionRef.current = { project, lang };
    discoveryContextRef.current = discoveryContext;
  }, [discoveryContext, lang, project]);

  useEffect(() => {
    mountedRef.current = true;
    void getTransport()
      .invoke<boolean>("semgrep_available")
      .then((available) => {
        if (mountedRef.current) setSemgrepAvailable(available);
      })
      .catch(() => {
        if (mountedRef.current) setSemgrepAvailable(false);
      });
    return () => {
      mountedRef.current = false;
      const operationId = semgrepOperationIdRef.current;
      if (semgrepAbortRef.current && operationId) {
        void getTransport().invoke("semgrep_cancel", { operationId });
      }
      semgrepAbortRef.current?.abort();
      semgrepOwnershipRef.current?.abort();
      rankingAbortRef.current?.abort();
    };
  }, []);

  const pollRanking = useCallback((operationId: string, initialRevision = 0) => {
    rankingAbortRef.current?.abort();
    const controller = new AbortController();
    rankingAbortRef.current = controller;
    rankingOperationIdRef.current = operationId;
    rankingContextRef.current = { project, lang };
    const owns = () => mountedRef.current
      && !controller.signal.aborted
      && rankingOperationIdRef.current === operationId
      && currentSelectionRef.current.project === project
      && currentSelectionRef.current.lang === lang;
    void waitForRankedDiscovery(
      operationId,
      initialRevision,
      status => {
        if (!owns()) return;
        setRankingStatus(status);
        if (status.state === "failed" || status.state === "cancelled" || status.state === "interrupted") setLoading(false);
      },
      result => {
        if (!owns()) return;
        save({ inventory: result.inventory, semgrep: null, ranked: result, rankedOperationId: operationId });
        setLoading(false);
        setDiscoveryContext({ project, lang });
        setActiveProject(project);
      },
      controller.signal,
    ).catch(cause => {
      if (owns()) { setError(String(cause)); setLoading(false); }
    }).finally(() => {
      if (rankingAbortRef.current === controller) rankingAbortRef.current = null;
    });
  }, [lang, project, save, setActiveProject]);

  useEffect(() => {
    const operationId = snapshot?.rankedOperationId;
    if (operationId && snapshot?.ranked?.ranking_source === "pending" && !rankingAbortRef.current && !rankingStatus && !loading) {
      pollRanking(operationId, snapshot.ranked.revision);
    }
  }, [loading, pollRanking, rankingStatus, snapshot?.ranked?.ranking_source, snapshot?.ranked?.revision, snapshot?.rankedOperationId]);

  const browse = useCallback(async () => {
    setScanning(true);
    try {
      const path = await pickFolder();
      if (path) setLocalProject(path);
    } finally {
      setScanning(false);
    }
  }, []);

  const discover = useCallback(async () => {
    if (!project) return;
    const sequence = ++rankingSequenceRef.current;
    rankingAbortRef.current?.abort();
    rankingOperationIdRef.current = null;
    rankingContextRef.current = { project, lang };
    setLoading(true);
    setError(null);
    setRankingStatus(null);
    try {
      const operationId = await getTransport().invoke<string>("ranked_discovery_start", {
        project,
        lang,
      });
      if (!mountedRef.current || sequence !== rankingSequenceRef.current) return;
      setSemgrepInventory(null);
      setSemgrepState(null);
      setSemgrepOperationId(null);
      semgrepOperationIdRef.current = null;
      setSemgrepError(null);
      pollRanking(operationId);
    } catch (e) {
      if (mountedRef.current && sequence === rankingSequenceRef.current) {
        setError(String(e));
        setLoading(false);
      }
    }
  }, [lang, project, pollRanking]);

  const retryRanking = useCallback(async () => {
    const priorId = snapshot?.rankedOperationId;
    if (!priorId) return;
    const sequence = ++rankingSequenceRef.current;
    setError(null);
    try {
      const operationId = await getTransport().invoke<string>("ranked_discovery_retry", { operationId: priorId });
      if (mountedRef.current && sequence === rankingSequenceRef.current) {
        setRankingStatus({ operation_id: operationId, state: "ranking", revision: 1, assessed_count: 0, total_count: inventory?.candidates.length ?? 0, reason_code: null });
        pollRanking(operationId);
      }
    } catch (cause) {
      if (mountedRef.current && sequence === rankingSequenceRef.current) setError(String(cause));
    }
  }, [inventory, pollRanking, snapshot]);

  const enrichWithSemgrep = useCallback(async () => {
    const operationOwned = hasOwnedSemgrepOperation(
      semgrepOperationId,
      semgrepState,
    );
    if (
      !canStartSemgrep(
        semgrepAvailable,
        inventory !== null,
        discoveryContext,
        { project, lang },
        operationOwned,
      )
      || !discoveryContext
    ) {
      return;
    }
    const operationContext = discoveryContext;

    setSemgrepLoading(true);
    setSemgrepInventory(null);
    setSemgrepState("staging");
    setSemgrepOperationId(null);
    semgrepOperationIdRef.current = null;
    setSemgrepError(null);
    const controller = new AbortController();
    const ownership = new AbortController();
    semgrepAbortRef.current = controller;
    semgrepOwnershipRef.current = ownership;
    try {
      const operationId = await getTransport().invoke<string>(
        "semgrep_enrich",
        {
          project: operationContext.project,
          lang: operationContext.lang,
        },
      );
      if (!mountedRef.current) {
        await getTransport().invoke("semgrep_cancel", { operationId });
        return;
      }
      semgrepOperationIdRef.current = operationId;
      setSemgrepOperationId(operationId);
      const result = await waitForSemgrep(
        operationId,
        (state) => {
          if (mountedRef.current) setSemgrepState(state);
        },
        controller.signal,
        {
          ownershipSignal: ownership.signal,
        },
      );
      if (
        mountedRef.current
        && canApplySemgrepResult(
          operationContext,
          discoveryContextRef.current,
          currentSelectionRef.current,
        )
      ) {
        const enriched = { context: operationContext, inventory: result };
        setSemgrepInventory(enriched);
        if (inventory) save({ inventory, semgrep: enriched, ranked: rankedResult, rankedOperationId: snapshot?.rankedOperationId });
      }
    } catch (cause) {
      const ownershipReleased =
        cause instanceof DOMException
        && cause.name === "SemgrepOwnershipReleased";
      if (
        mountedRef.current
        && !controller.signal.aborted
        && !ownershipReleased
      ) {
        setSemgrepError(String(cause));
        setSemgrepState((state) =>
          semgrepStateAfterError(semgrepOperationIdRef.current, state),
        );
      }
    } finally {
      if (semgrepAbortRef.current === controller) {
        semgrepAbortRef.current = null;
      }
      if (semgrepOwnershipRef.current === ownership) {
        semgrepOwnershipRef.current = null;
      }
      if (mountedRef.current) setSemgrepLoading(false);
    }
  }, [
    discoveryContext,
    save,
    inventory,
    rankedResult,
    snapshot,
    lang,
    project,
    semgrepAvailable,
    semgrepOperationId,
    semgrepState,
  ]);

  const stopSemgrep = useCallback(async () => {
    const operationId = semgrepOperationId;
    if (!operationId) return;
    try {
      const outcome = await getTransport().invoke<SemgrepCancelOutcome>(
        "semgrep_cancel",
        { operationId },
      );
      if (!mountedRef.current) return;
      const decision = semgrepCancelDecision(outcome);
      if (decision.errorKey) setSemgrepError(t(decision.errorKey));
      if (decision.releaseOwnership) {
        semgrepOwnershipRef.current?.abort();
        semgrepOperationIdRef.current = null;
        setSemgrepOperationId(null);
        setSemgrepState(null);
        setSemgrepLoading(false);
      }
      if (decision.nextState) setSemgrepState(decision.nextState);
      if (decision.abortPolling) semgrepAbortRef.current?.abort();
    } catch (cause) {
      if (mountedRef.current) setSemgrepError(String(cause));
    }
  }, [semgrepOperationId, t]);

  const baseCandidates = useMemo(
    () =>
      inventory
        ? rankedResult?.revision === 2
          ? inventory.candidates
          : [...inventory.candidates].sort((a, b) => b.fit_score - a.fit_score)
        : [],
    [inventory, rankedResult?.revision],
  );
  const assessmentById = useMemo(
    () => new Map(rankedResult?.assessments.map(assessment => [assessment.target_id, assessment]) ?? []),
    [rankedResult?.assessments],
  );
  const recommendedId = rankedResult?.revision === 2
    ? baseCandidates.find(candidate => assessmentById.has(candidate.id))?.id
    : undefined;
  const rankingTerminal = rankingStatus && ["completed", "failed", "cancelled", "interrupted"].includes(rankingStatus.state);
  const rankingBusy = loading || rankingStatus?.state === "scanning" || rankingStatus?.state === "ranking"
    || (rankedResult?.ranking_source === "pending" && !rankingTerminal);
  function rankingMessage(): string {
    if (loading) return t("discover.scanning");
    if (rankingBusy) return t("discover.assessing");
    if (rankingStatus?.state === "failed") return t("discover.scanFailed");
    if (rankingStatus?.state === "interrupted") return t("discover.interrupted");
    if (rankingStatus?.state === "cancelled") return t("discover.cancelled");
    if (rankedResult?.reason_code === "no_provider") return t("discover.aiNoProvider");
    if (rankedResult?.reason_code === "partial_or_failed_ai") return t("discover.aiFailed");
    if (rankedResult?.revision === 2 && rankedResult.assessed_count > 0) {
      return t("discover.aiAssessed", { n: rankedResult.assessed_count, total: rankedResult.total_count });
    }
    return t("discover.aiUpdated");
  }
  const semgrepOwned = hasOwnedSemgrepOperation(
    semgrepOperationId,
    semgrepState,
  );
  const semgrepEligible = !rankingBusy && canStartSemgrep(
    semgrepAvailable,
    inventory !== null,
    discoveryContext,
    { project, lang },
    semgrepOwned,
  );
  const semgrepPresentation = buildSemgrepPresentation(
    baseCandidates,
    semgrepInventory,
    discoveryContext,
    { project, lang },
  );

  function selectCandidate(candidate: TargetCandidate) {
    const duplicate = semgrepPresentation.candidates.some(item => item.id !== candidate.id && item.symbol === candidate.symbol);
    setTarget(duplicate ? candidateTargetSelector(candidate) : candidate.symbol);
    markDone("discover");
    onNavigate?.("harness");
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      {!embedded && (
        <ViewHeader
          title={t("discover.title")}
          description={t("discover.description")}
        />
      )}

      <div className="flex gap-2">
        {!embedded && (
          <Input
            mono
            type="text"
            aria-label={t("workflow.chooseProjectHint")}
            placeholder="/path/to/project"
            value={project}
            onChange={(e) => setLocalProject(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && discover()}
            disabled={loading || semgrepLoading}
            className="flex-1"
          />
        )}
        <Select
          ariaLabel={t("harness.language")}
          value={lang}
          onChange={(v) => setLang(v)}
          disabled={loading || semgrepLoading}
          options={[
            { value: "c", label: "C" },
            { value: "cpp", label: "C++" },
            { value: "go", label: "Go" },
            { value: "python", label: "Python" },
          ]}
        />
        {!embedded && (
          <Button
            variant="outline"
            size="sm"
            onClick={browse}
            loading={scanning}
            disabled={loading || semgrepLoading}
            title={t("discover.browseFolder")}
            aria-label={t("discover.browseFolder")}
          >
            {!scanning && <FolderOpen size={14} />}
          </Button>
        )}
        <Button
          variant="primary"
          onClick={discover}
          disabled={loading || semgrepLoading || !project}
          loading={loading}
        >
          {!loading && <Search size={14} />}
          {loading ? t("discover.scanning") : t("discover.discover")}
        </Button>
      </div>

      {error && (
        <div
          className="rounded-md text-xs px-3 py-2"
          role="alert"
          style={{ background: "var(--error-subtle)", color: "var(--error)" }}
        >
          {error}
        </div>
      )}

      {(semgrepEligible || semgrepOwned) && (
        <div className="flex items-center gap-2">
          {semgrepEligible && (
            <Button
              variant="outline"
              onClick={enrichWithSemgrep}
              disabled={loading || semgrepLoading || !project}
              loading={semgrepLoading}
            >
              {t("discover.semgrepEnrich")}
            </Button>
          )}
          {semgrepOwned && semgrepOperationId && (
            <Button
              variant="outline"
              onClick={stopSemgrep}
              aria-label={t("discover.semgrepStop")}
            >
              {t("discover.semgrepStop")}
            </Button>
          )}
          {semgrepState && (
            <span
              className="text-xs text-text-secondary"
              role="status"
              aria-live="polite"
            >
              {t(`discover.semgrepState.${semgrepState}`)}
            </span>
          )}
        </div>
      )}

      {semgrepError && (
        <div
          className="rounded-md text-xs px-3 py-2"
          style={{ background: "var(--error-subtle)", color: "var(--error)" }}
          role="alert"
        >
          {semgrepError}
        </div>
      )}

      {semgrepPresentation.inventory && (
        <div
          className="rounded-md text-xs px-3 py-2"
          style={{
            background: "var(--accent-subtle)",
            color: "var(--text-secondary)",
          }}
        >
          <div style={{ fontWeight: 600 }}>
            {t("discover.semgrepSignals")}
          </div>
          {semgrepPresentation.staleMessageKey && (
            <div>{t(semgrepPresentation.staleMessageKey)}</div>
          )}
        </div>
      )}

      {(loading || rankingStatus || rankedResult) && (
        <div className="rounded-md px-3 py-2 text-sm text-text-secondary flex flex-wrap items-center justify-between gap-2"
          style={{ background: "var(--surface-active)" }} role="status" aria-live="polite">
          <span>{rankingMessage()}</span>
          {rankedResult?.reason_code === "no_provider" && onNavigate && (
            <Button variant="outline" size="sm" onClick={() => onNavigate("settings")}>{t("discover.settingsLink")}</Button>
          )}
          {(rankedResult?.reason_code === "partial_or_failed_ai" || rankingStatus?.state === "interrupted" && rankedResult) && !rankingBusy && (
            <Button variant="outline" size="sm" onClick={retryRanking}>{t("discover.retryAi")}</Button>
          )}
        </div>
      )}

      {inventory && !loading && (
        <div className="flex flex-col gap-2" style={{ animation: "slideInUp 0.2s ease" }}>
          <div className="text-xs text-text-secondary flex flex-wrap gap-2 items-center">
            <span>{t("discover.candidatesFound", {
              n: semgrepPresentation.candidates.length,
            })}</span>
          </div>
          {semgrepPresentation.candidates.length === 0 && <p role="status" className="text-sm">{t("gui.noTargets")}</p>}
          <div className="flex flex-col gap-1">
            {semgrepPresentation.inventory
              ? semgrepPresentation.candidates.map((candidate) => (
                  <CandidateCard
                    key={candidate.id}
                    candidate={candidate}
                    onSelect={onNavigate && !selectionRepair && !storageError ? () => selectCandidate(candidate) : undefined}
                    callGraph={semgrepPresentation.inventory?.call_graph ?? {}}
                    project={
                      semgrepPresentation.inventory?.project_root ?? project
                    }
                    semgrepScores={
                      semgrepPresentation.showScores
                        ? candidate as SemgrepTargetCandidate
                        : undefined
                    }
                    assessment={assessmentById.get(candidate.id)}
                    recommended={candidate.id === recommendedId}
                  />
                ))
              : semgrepPresentation.candidates.map((candidate) => (
                  <CandidateCard
                    key={candidate.id}
                    candidate={candidate}
                    onSelect={onNavigate && !selectionRepair && !storageError ? () => selectCandidate(candidate) : undefined}
                    callGraph={inventory.call_graph ?? {}}
                    project={discoveryContext?.project ?? project}
                    assessment={assessmentById.get(candidate.id)}
                    recommended={candidate.id === recommendedId}
                  />
                ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CandidateCard({
  candidate: c,
  callGraph,
  project,
  semgrepScores,
  assessment,
  recommended,
  onSelect,
}: {
  candidate: TargetCandidate;
  callGraph: Record<string, string[]>;
  project: string;
  semgrepScores?: SemgrepTargetCandidate;
  assessment?: TargetAssessment;
  recommended: boolean;
  onSelect?: () => void;
}) {
  const { t } = useI18n();
  const displayedScore = semgrepScores?.effective_score ?? c.fit_score;
  const fitColor = displayedScore > 0.8 ? "var(--accent)" : displayedScore > 0.6 ? "var(--warning)" : "var(--text-muted)";
  const reaches = c.reachable_functions?.length ?? 0;
  const hasTree = (callGraph[c.symbol]?.length ?? 0) > 0;
  const [treeOpen, setTreeOpen] = useState(false);
  // Per-function coverage overlay: null = not loaded, Set = covered functions
  // (rebuilds a coverage harness + replays the corpus; only if a run happened).
  const [covered, setCovered] = useState<Set<string> | null>(null);
  const [covLoading, setCovLoading] = useState(false);

  const loadCoverage = useCallback(async () => {
    setCovLoading(true);
    try {
      const functions = await getTransport().invoke<string[]>("coverage_functions", {
        project,
        target: c.symbol,
      });
      setCovered(new Set(functions));
    } catch {
      setCovered(new Set());
    } finally {
      setCovLoading(false);
    }
  }, [c.symbol, project]);

  const toggleTree = useCallback(() => {
    const opening = !treeOpen;
    setTreeOpen(opening);
    if (shouldLoadCoverage(opening, covered, covLoading, project)) {
      void loadCoverage();
    }
  }, [covLoading, covered, loadCoverage, project, treeOpen]);

  return (
    <div className="surface-card flex flex-col" style={{ padding: 0, borderInlineStart: recommended ? "3px solid var(--accent)" : undefined }}>
    <div
      className="flex items-center gap-3 transition-all duration-150"
      style={{ padding: "var(--space-md)" }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-focus)")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
    >
      {hasTree ? (
        <button aria-label={t("discover.toggleCallTreeNode")} aria-expanded={treeOpen} onClick={toggleTree} className="shrink-0 p-2 text-text-muted">{treeOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button>
      ) : (
        <span className="shrink-0" style={{ width: "14px" }} />
      )}
      <Crosshair size={16} className="shrink-0" style={{ color: "var(--accent)" }} />
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium break-all" style={{ fontFamily: "var(--font-mono)" }}>
            {c.symbol}
          </span>
          <span
            className="text-xs px-1.5 py-0.5 rounded-sm"
            style={{
              background: "var(--surface-active)",
              color: "var(--text-muted)",
              fontSize: "10px",
              fontWeight: 500,
            }}
          >
            {c.kind}
          </span>
        </div>
        <div className="text-xs text-text-muted truncate mt-0.5" style={{ fontFamily: "var(--font-mono)" }}>
          {c.location.file}:{c.location.line}
        </div>
        {c.rationale && (
          <div className="text-xs text-text-secondary mt-1">{c.rationale}</div>
        )}
      </div>
      <div className="flex flex-col items-end gap-1 shrink-0">
        {semgrepScores ? (
          <>
            <span className="text-xs font-mono text-text-secondary">
              {t("discover.semgrepBase", {
                score: semgrepScores.base_score.toFixed(3),
              })}
            </span>
            <span className="text-xs font-mono text-text-secondary">
              {t("discover.semgrepBoost", {
                score: semgrepScores.semgrep_boost.toFixed(3),
              })}
            </span>
            <span
              className="text-sm font-mono"
              style={{ color: fitColor, fontWeight: 600 }}
            >
              {t("discover.semgrepEffective", {
                score: semgrepScores.effective_score.toFixed(3),
              })}
            </span>
            <span className="text-xs text-text-muted">
              {t("discover.semgrepMatchedRules", {
                n: semgrepScores.semgrep_matched_rule_count,
              })}
            </span>
          </>
        ) : (
          <span className="text-xs font-mono" style={{ color: fitColor, fontWeight: 600 }}>
            {t("discover.heuristicScore", { score: c.fit_score.toFixed(3) })}
          </span>
        )}
        <span className="text-xs text-text-muted">{t("discover.complexity", { n: c.complexity })}</span>
        {reaches > 0 && (
          <span
            className="text-xs px-1.5 py-0.5 rounded-sm"
            style={{ background: "var(--accent-subtle)", color: "var(--accent)", fontSize: "10px", fontWeight: 500 }}
            title={t("discover.reachesTooltip", { n: reaches, fns: (c.reachable_functions ?? []).join(", ") })}
          >
            {t("discover.reachesBadge", { n: reaches, acc: c.accumulated_complexity ?? c.complexity })}
          </span>
        )}
      </div>
    </div>
    <TargetAssessmentPanel assessment={assessment} recommended={recommended} />
    {onSelect && <div className="px-3 pb-3"><Button variant="primary" size="sm" onClick={onSelect}>{t("gui.useTarget")}</Button></div>}
    {treeOpen && hasTree && (
      <div style={{ padding: "0 var(--space-md) var(--space-md) calc(var(--space-md) + 22px)", borderTop: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mt-2 mb-1">
          <span className="text-xs text-text-muted uppercase" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            {t("discover.callTree")}
          </span>
          {covLoading && <Loader2 size={11} className="animate-spin text-text-muted" />}
          {covered && covered.size > 0 && (
            <span className="text-xs text-text-muted flex items-center gap-2">
              <span style={{ color: "var(--success, #16a34a)" }}>● {t("discover.covered")}</span>
              <span style={{ color: "var(--text-muted)" }}>○ {t("discover.notCovered")}</span>
            </span>
          )}
          {covered && covered.size === 0 && !covLoading && (
            <span className="text-xs text-text-muted">{t("discover.noCoverageYet")}</span>
          )}
        </div>
        {(callGraph[c.symbol] ?? []).map((child) => (
          <CallTreeNode key={child} name={child} graph={callGraph} ancestors={new Set([c.symbol])} depth={1} covered={covered} />
        ))}
      </div>
    )}
    </div>
  );
}

// One node of the call tree: the function name + an expander for its project
// callees. `ancestors` guards against cycles; deeper levels start collapsed.
function CallTreeNode({
  name,
  graph,
  ancestors,
  depth,
  covered,
}: {
  name: string;
  graph: Record<string, string[]>;
  ancestors: Set<string>;
  depth: number;
  covered: Set<string> | null;
}) {
  const { t } = useI18n();
  const isCycle = ancestors.has(name);
  const children = isCycle ? [] : graph[name] ?? [];
  const hasChildren = children.length > 0;
  const [open, setOpen] = useState(depth < 2);
  // When coverage data is loaded, color by hit/not-hit; otherwise neutral.
  const hasCoverage = covered !== null && covered.size > 0;
  const isCovered = covered?.has(name) ?? false;
  const nameColor = hasCoverage
    ? isCovered
      ? "var(--success, #16a34a)"
      : "var(--text-muted)"
    : hasChildren
      ? "var(--text-primary)"
      : "var(--text-secondary)";
  return (
    <div>
      <div className="flex items-center gap-1 text-xs font-mono" style={{ padding: "1px 0" }}>
        {hasChildren ? (
          <button onClick={() => setOpen((o) => !o)} aria-label={t("discover.toggleCallTreeNode")} className="text-text-muted hover:text-text-primary outline-none">
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        ) : (
          <span style={{ width: "12px" }} />
        )}
        {hasCoverage && <span style={{ color: nameColor, fontSize: "9px" }}>{isCovered ? "●" : "○"}</span>}
        <span style={{ color: nameColor }}>
          {name}
          {isCycle ? " ↻" : ""}
        </span>
      </div>
      {open && hasChildren && (
        <div style={{ marginLeft: "5px", borderLeft: "1px solid var(--border)", paddingLeft: "8px" }}>
          {children.map((child) => (
            <CallTreeNode key={child} name={child} graph={graph} ancestors={new Set([...ancestors, name])} depth={depth + 1} covered={covered} />
          ))}
        </div>
      )}
    </div>
  );
}
