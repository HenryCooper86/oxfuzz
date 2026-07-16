import { useState } from "react";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/project";
import { usePipeline } from "../providers/pipeline";
import { useTarget } from "../providers/target";
import type { TargetInventory, TargetCandidate } from "../types";
import { Button, Input, Select, ViewHeader } from "../components/ui";
import { useI18n } from "../i18nContext";
import { Crosshair, Search, Loader2, FolderOpen, ChevronRight, ChevronDown } from "lucide-react";
import { shouldLoadCoverage } from "../lib/discoverCoverage";

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
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function browse() {
    setScanning(true);
    try {
      const path = await pickFolder();
      if (path) setLocalProject(path);
    } finally {
      setScanning(false);
    }
  }

  async function discover() {
    if (!project) return;
    setLoading(true);
    setError(null);
    try {
      const inv = await getTransport().invoke<TargetInventory>("discover", {
        project,
        lang,
      });
      setInventory(inv);
      setActiveProject(project);
      markDone("discover");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
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
            placeholder="/path/to/project"
            value={project}
            onChange={(e) => setLocalProject(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && discover()}
            className="flex-1"
          />
        )}
        <Select
          value={lang}
          onChange={(v) => setLang(v)}
          options={[
            { value: "c", label: "C" },
            { value: "cpp", label: "C++" },
          ]}
        />
        {!embedded && (
          <Button
            variant="outline"
            size="sm"
            onClick={browse}
            loading={scanning}
            title={t("discover.browseFolder")}
            aria-label={t("discover.browseFolder")}
          >
            {!scanning && <FolderOpen size={14} />}
          </Button>
        )}
        <Button
          variant="primary"
          onClick={discover}
          disabled={loading || !project}
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

      {inventory && (
        <div className="flex flex-col gap-2" style={{ animation: "slideInUp 0.2s ease" }}>
          <div className="text-xs text-text-secondary">
            {t("discover.candidatesFound", { n: inventory.candidates.length })}
          </div>
          <div className="flex flex-col gap-1">
            {[...inventory.candidates]
              .sort((a, b) => b.fit_score - a.fit_score)
              .map((c) => (
                <CandidateCard key={c.id} candidate={c} callGraph={inventory.call_graph ?? {}} project={project} />
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CandidateCard({ candidate: c, callGraph, project }: { candidate: TargetCandidate; callGraph: Record<string, string[]>; project: string }) {
  const { t } = useI18n();
  const fitColor = c.fit_score > 0.8 ? "var(--accent)" : c.fit_score > 0.6 ? "var(--warning)" : "var(--text-muted)";
  const reaches = c.reachable_functions?.length ?? 0;
  const hasTree = (callGraph[c.symbol]?.length ?? 0) > 0;
  const [treeOpen, setTreeOpen] = useState(false);
  // Per-function coverage overlay: null = not loaded, Set = covered functions
  // (rebuilds a coverage harness + replays the corpus; only if a run happened).
  const [covered, setCovered] = useState<Set<string> | null>(null);
  const [covLoading, setCovLoading] = useState(false);

  async function loadCoverage() {
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
  }

  function toggleTree() {
    const opening = !treeOpen;
    setTreeOpen(opening);
    if (shouldLoadCoverage(opening, covered, covLoading, project)) {
      void loadCoverage();
    }
  }

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
        <span className="text-sm font-mono" style={{ color: fitColor, fontWeight: 600 }}>
          {c.fit_score.toFixed(3)}
        </span>
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
