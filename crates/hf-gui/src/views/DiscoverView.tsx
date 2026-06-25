import { useState } from "react";
import { getTransport, pickFolder } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { usePipeline } from "../providers/PipelineContext";
import type { TargetInventory, TargetCandidate } from "../types";
import { Crosshair, Search, Loader2, FolderOpen } from "lucide-react";

export function DiscoverView({ embedded = false }: { embedded?: boolean }) {
  const { activeProject, setActiveProject } = useProject();
  const { markDone } = usePipeline();
  // When embedded in the unified workflow, the project is fixed by the
  // workflow's project gate; standalone, this view has its own picker.
  const [localProject, setLocalProject] = useState(activeProject);
  const project = embedded ? activeProject : localProject;
  const [lang, setLang] = useState("c");
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
        <>
          <h1 className="text-xl font-semibold" style={{ letterSpacing: "-0.01em" }}>
            Target Discovery
          </h1>
          <p className="text-sm text-text-secondary">
            Scan a C/C++ project to find functions worth fuzzing. Ranked by input surface, complexity, and parser heuristics.
          </p>
        </>
      )}

      <div className="flex gap-2">
        {!embedded && (
          <input
            type="text"
            placeholder="/path/to/project"
            value={project}
            onChange={(e) => setLocalProject(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && discover()}
            className="flex-1 px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary transition-colors duration-150 outline-none focus:border-[var(--border-focus)]"
            style={{ fontFamily: "var(--font-mono)" }}
          />
        )}
        <select
          value={lang}
          onChange={(e) => setLang(e.target.value)}
          className="px-3 py-2 text-xs border border-solid border-border rounded-md bg-surface-primary text-text-primary outline-none focus:border-[var(--border-focus)] transition-colors duration-150"
        >
          <option value="c">C</option>
          <option value="cpp">C++</option>
        </select>
        {!embedded && (
          <button
            onClick={browse}
            disabled={scanning}
            className="inline-flex items-center justify-center gap-1 px-3 py-2 text-xs font-medium rounded-md border border-solid border-border bg-surface-primary text-text-secondary transition-all duration-150 outline-none hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
            title="Browse for folder"
          >
            {scanning ? <Loader2 size={14} className="animate-spin" /> : <FolderOpen size={14} />}
          </button>
        )}
        <button
          onClick={discover}
          disabled={loading || !project}
          className="inline-flex items-center justify-center gap-1 px-4 py-2 text-xs font-medium rounded-md border border-solid transition-all duration-150 outline-none disabled:opacity-55 disabled:cursor-not-allowed"
          style={{
            background: "var(--accent)",
            color: "var(--accent-contrast)",
            borderColor: "transparent",
          }}
          onMouseEnter={(e) => !loading && (e.currentTarget.style.opacity = "0.85")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          {loading ? "Scanning..." : "Discover"}
        </button>
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
            {inventory.candidates.length} candidates found
          </div>
          <div className="flex flex-col gap-1">
            {inventory.candidates
              .sort((a, b) => b.fit_score - a.fit_score)
              .map((c) => (
                <CandidateCard key={c.id} candidate={c} />
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CandidateCard({ candidate: c }: { candidate: TargetCandidate }) {
  const fitColor = c.fit_score > 0.8 ? "var(--accent)" : c.fit_score > 0.6 ? "var(--warning)" : "var(--text-muted)";
  return (
    <div
      className="surface-card flex items-center gap-3 transition-all duration-150"
      style={{ padding: "var(--space-md)", cursor: "pointer" }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-focus)")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
    >
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
        <span className="text-xs text-text-muted">complexity: {c.complexity}</span>
      </div>
    </div>
  );
}