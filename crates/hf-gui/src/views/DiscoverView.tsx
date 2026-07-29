import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTransport, pickFolder } from "../lib";
import { waitForSemgrep } from "../lib/semgrep";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { useTarget } from "../providers/target";
import type {
  SemgrepInventory,
  SemgrepOperationState,
  SemgrepOverlayState,
  SemgrepTargetCandidate,
  TargetCandidate,
  TargetInventory,
} from "../types";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import { useI18n } from "../i18nContext";
import { Crosshair, Search, Loader2, FolderOpen, ChevronRight, ChevronDown } from "lucide-react";
import { shouldLoadCoverage } from "../lib/discoverCoverage";

const ACTIVE_SEMGREP_STATES: ReadonlySet<SemgrepOperationState> = new Set([
  "staging",
  "scanning",
  "validating",
  "persisting",
]);

interface DiscoveryContext {
  project: string;
  lang: string;
}

function semgrepOverlayMessageKey(
  overlayState: SemgrepOverlayState,
): string | null {
  switch (overlayState) {
    case "stale_source":
      return "discover.semgrepStaleSource";
    case "stale_base":
      return "discover.semgrepStaleBase";
    case "incomplete_journal":
      return "discover.semgrepIncompleteJournal";
    case "none":
    case "current":
      return null;
  }
}

export function DiscoverView({ embedded = false }: { embedded?: boolean }) {
  const { t } = useI18n();
  const { activeProject, setActiveProject } = useProject();
  const { markDone } = usePipeline();
  // Language lives in the shared TargetContext so the C/C++ choice made here
  // flows through to Harness generation (which reads it from the same context).
  const { lang, setLang } = useTarget();
  // When embedded in the unified workflow, the project is fixed by the
  // workflow's project gate; standalone, this view has its own picker.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [inventory, setInventory] = useState<TargetInventory | null>(null);
  const [discoveryContext, setDiscoveryContext] =
    useState<DiscoveryContext | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [semgrepInventory, setSemgrepInventory] =
    useState<SemgrepInventory | null>(null);
  const [semgrepState, setSemgrepState] =
    useState<SemgrepOperationState | null>(null);
  const [semgrepOperationId, setSemgrepOperationId] =
    useState<string | null>(null);
  const [semgrepLoading, setSemgrepLoading] = useState(false);
  const [semgrepError, setSemgrepError] = useState<string | null>(null);
  const semgrepAbortRef = useRef<AbortController | null>(null);
  const semgrepOperationIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const operationId = semgrepOperationIdRef.current;
      if (semgrepAbortRef.current && operationId) {
        void getTransport().invoke("semgrep_cancel", { operationId });
      }
      semgrepAbortRef.current?.abort();
    };
  }, []);

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
    setLoading(true);
    setError(null);
    try {
      const inv = await getTransport().invoke<TargetInventory>("discover", {
        project,
        lang,
      });
      setInventory(inv);
      setDiscoveryContext({ project, lang });
      setSemgrepInventory(null);
      setSemgrepState(null);
      setSemgrepOperationId(null);
      semgrepOperationIdRef.current = null;
      setSemgrepError(null);
      setActiveProject(project);
      markDone("discover");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [lang, markDone, project, setActiveProject]);

  const enrichWithSemgrep = useCallback(async () => {
    if (
      !inventory
      || !discoveryContext
      || discoveryContext.project !== project
      || discoveryContext.lang !== lang
      || (discoveryContext.lang !== "c" && discoveryContext.lang !== "cpp")
    ) {
      return;
    }

    setSemgrepLoading(true);
    setSemgrepInventory(null);
    setSemgrepState("staging");
    setSemgrepOperationId(null);
    semgrepOperationIdRef.current = null;
    setSemgrepError(null);
    const controller = new AbortController();
    semgrepAbortRef.current = controller;
    try {
      const operationId = await getTransport().invoke<string>(
        "semgrep_enrich",
        {
          project: discoveryContext.project,
          lang: discoveryContext.lang,
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
      );
      if (mountedRef.current) setSemgrepInventory(result);
    } catch (cause) {
      if (mountedRef.current && !controller.signal.aborted) {
        setSemgrepError(String(cause));
      }
    } finally {
      if (semgrepAbortRef.current === controller) {
        semgrepAbortRef.current = null;
      }
      if (mountedRef.current) setSemgrepLoading(false);
    }
  }, [discoveryContext, inventory, lang, project]);

  const stopSemgrep = useCallback(async () => {
    const operationId = semgrepOperationId;
    if (!operationId) return;
    try {
      await getTransport().invoke("semgrep_cancel", { operationId });
      if (mountedRef.current) {
        setSemgrepState("cancelled");
        semgrepAbortRef.current?.abort();
      }
    } catch (cause) {
      if (mountedRef.current) setSemgrepError(String(cause));
    }
  }, [semgrepOperationId]);

  const baseCandidates = useMemo(
    () =>
      inventory
        ? [...inventory.candidates].sort((a, b) => b.fit_score - a.fit_score)
        : [],
    [inventory],
  );
  const semgrepEligible =
    inventory !== null
    && discoveryContext !== null
    && discoveryContext.project === project
    && discoveryContext.lang === lang
    && (discoveryContext.lang === "c" || discoveryContext.lang === "cpp");
  const showSemgrepScores = semgrepInventory?.overlay_state === "current";
  const staleMessageKey = semgrepInventory
    ? semgrepOverlayMessageKey(semgrepInventory.overlay_state)
    : null;
  const semgrepActive =
    semgrepLoading
    && semgrepState !== null
    && ACTIVE_SEMGREP_STATES.has(semgrepState);

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
            placeholder="/path/to/project"
            value={project}
            onChange={(e) => setLocalProject(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && discover()}
            disabled={loading || semgrepLoading}
            className="flex-1"
          />
        )}
        <Select
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
          style={{ background: "var(--error-subtle)", color: "var(--error)" }}
        >
          {error}
        </div>
      )}

      {semgrepEligible && (
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={enrichWithSemgrep}
            disabled={loading || semgrepLoading || !project}
            loading={semgrepLoading}
          >
            {t("discover.semgrepEnrich")}
          </Button>
          {semgrepActive && semgrepOperationId && (
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

      {semgrepInventory && (
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
          {staleMessageKey && <div>{t(staleMessageKey)}</div>}
        </div>
      )}

      {inventory && (
        <div className="flex flex-col gap-2" style={{ animation: "slideInUp 0.2s ease" }}>
          <div className="text-xs text-text-secondary">
            {t("discover.candidatesFound", {
              n: semgrepInventory?.candidates.length ?? inventory.candidates.length,
            })}
          </div>
          <div className="flex flex-col gap-1">
            {semgrepInventory
              ? semgrepInventory.candidates.map((candidate) => (
                  <CandidateCard
                    key={candidate.id}
                    candidate={candidate}
                    callGraph={semgrepInventory.call_graph}
                    project={semgrepInventory.project_root}
                    semgrepScores={
                      showSemgrepScores ? candidate : undefined
                    }
                  />
                ))
              : baseCandidates.map((candidate) => (
                  <CandidateCard
                    key={candidate.id}
                    candidate={candidate}
                    callGraph={inventory.call_graph ?? {}}
                    project={discoveryContext?.project ?? project}
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
}: {
  candidate: TargetCandidate;
  callGraph: Record<string, string[]>;
  project: string;
  semgrepScores?: SemgrepTargetCandidate;
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
    <div className="surface-card flex flex-col" style={{ padding: 0 }}>
    <div
      className="flex items-center gap-3 transition-all duration-150"
      style={{ padding: "var(--space-md)", cursor: hasTree ? "pointer" : "default" }}
      onClick={hasTree ? toggleTree : undefined}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-focus)")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
    >
      {hasTree ? (
        <span className="shrink-0 text-text-muted">{treeOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
      ) : (
        <span className="shrink-0" style={{ width: "14px" }} />
      )}
      <Crosshair size={16} className="shrink-0" style={{ color: "var(--accent)" }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium" style={{ fontFamily: "var(--font-mono)" }}>
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
          <span className="text-sm font-mono" style={{ color: fitColor, fontWeight: 600 }}>
            {c.fit_score.toFixed(3)}
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
