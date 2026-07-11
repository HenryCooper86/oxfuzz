import { useCallback, useEffect, useState } from "react";
import { getTransport, isTauriEnvironment, emitDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useToast } from "../components/ui/Toast";
import { useConfirm } from "../providers/ConfirmContext";
import type { Crash, CorpusEntry } from "../types";
import { Button, IconButton, Input, ViewHeader, EmptyState, ErrorState, Badge } from "../components/ui";
import { Bug, Database, RotateCw, FileWarning, Download, Search, Trash2 } from "lucide-react";
import { PathActions } from "../components/PathActions";

export function ArtifactsView() {
  const { activeProject } = useProject();
  const { toast } = useToast();
  const confirm = useConfirm();
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [corpus, setCorpus] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [exporting, setExporting] = useState(false);

  const scan = useCallback(async () => {
    setLoading(true);
    setError(null);
    const t = getTransport();
    try {
      // Browse-all view: read persisted artifacts from the store across every
      // target/run. Surface a real failure rather than swallowing it into an
      // empty state -- "the query broke" must look different from "no artifacts".
      const [c, k] = await Promise.all([
        t.invoke<Crash[]>("all_crashes"),
        t.invoke<CorpusEntry[]>("all_corpus"),
      ]);
      setCrashes(c);
      setCorpus(k);
    } catch (e) {
      setError(String(e));
      setCrashes([]);
      setCorpus([]);
    } finally {
      setScanned(true);
      setLoading(false);
    }
  }, []);

  // Auto-scan on mount so the view isn't a dead "Scan" prompt.
  useEffect(() => {
    queueMicrotask(() => void scan());
  }, [scan]);

  async function exportData() {
    setExporting(true);
    try {
      const saved = await getTransport().invoke<string | null>("export_project_data", {
        project: activeProject || undefined,
      });
      if (saved) toast({ title: "Exported", description: `Saved to ${saved}`, variant: "success" });
    } catch (e) {
      toast({ title: "Export failed", description: String(e), variant: "error" });
    } finally {
      setExporting(false);
    }
  }

  async function deleteCrash(c: Crash) {
    if (!(await confirm({ title: "Delete crash", message: `Delete the crash reproducer "${c.input_path.split("/").pop()}"? The record is removed from the database.`, danger: true, confirmLabel: "Delete" }))) return;
    try {
      await getTransport().invoke("delete_crash", { crashId: c.id });
      setCrashes((cs) => cs.filter((x) => x.id !== c.id));
      emitDataChanged();
    } catch (e) {
      toast({ title: "Delete failed", description: String(e), variant: "error" });
    }
  }

  async function deleteCorpus(e: CorpusEntry) {
    if (!(await confirm({ title: "Delete corpus entry", message: `Delete the corpus input "${e.path.split("/").pop()}"?`, danger: true, confirmLabel: "Delete" }))) return;
    try {
      await getTransport().invoke("delete_corpus_entry", { sha256: e.sha256 });
      setCorpus((cs) => cs.filter((x) => x.sha256 !== e.sha256));
      emitDataChanged();
    } catch (err) {
      toast({ title: "Delete failed", description: String(err), variant: "error" });
    }
  }

  async function clearAll() {
    if (!(await confirm({ title: "Clear all artifacts", message: "Delete every crash reproducer and corpus entry across all projects from the database? This cannot be undone.", danger: true, confirmLabel: "Clear all" }))) return;
    try {
      await getTransport().invoke("clear_all_artifacts");
      setCrashes([]);
      setCorpus([]);
      emitDataChanged();
      toast({ title: "Artifacts cleared", variant: "success" });
    } catch (e) {
      toast({ title: "Clear failed", description: String(e), variant: "error" });
    }
  }

  const q = filter.trim().toLowerCase();
  const shownCrashes = q
    ? crashes.filter((c) => `${c.input_path} ${c.kind}`.toLowerCase().includes(q))
    : crashes;
  const shownCorpus = q
    ? corpus.filter((e) => `${e.path} ${e.source}`.toLowerCase().includes(q))
    : corpus;

  const empty = scanned && !error && crashes.length === 0 && corpus.length === 0;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <ViewHeader title="Artifacts" description="Crash reproducers and corpus inputs from your fuzz runs." />
        <div className="flex items-center gap-2">
          {isTauriEnvironment() && (
            <Button variant="outline" onClick={() => void exportData()} loading={exporting} title="Export this project's data as JSON">
              {!exporting && <Download size={14} />}
              Export
            </Button>
          )}
          {(crashes.length > 0 || corpus.length > 0) && (
            <Button variant="danger" onClick={() => void clearAll()} title="Delete every crash reproducer and corpus entry from the database">
              <Trash2 size={14} />
              Clear all
            </Button>
          )}
          <Button variant="primary" onClick={() => void scan()} loading={loading}>
            {!loading && <RotateCw size={14} />}
            {loading ? "Scanning..." : "Rescan"}
          </Button>
        </div>
      </div>

      {(crashes.length > 0 || corpus.length > 0) && (
        <div className="flex items-center gap-2">
          <Search size={14} className="text-text-muted shrink-0" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by filename, kind, or source..." className="flex-1" />
        </div>
      )}

      {!scanned && !loading && (
        <EmptyState
          icon={<FileWarning size={20} />}
          hint="Scan to collect crash and corpus artifacts."
        />
      )}

      {error && (
        <ErrorState
          title="Failed to load artifacts"
          message={error}
          action={
            <Button variant="outline" size="sm" onClick={() => void scan()}>
              <RotateCw size={13} />
              Retry
            </Button>
          }
        />
      )}

      {empty && (
        <EmptyState
          icon={<FileWarning size={20} />}
          title="No artifacts found"
          hint="Run a fuzz campaign first, then rescan to collect crash reproducers and corpus inputs."
        />
      )}

      {shownCrashes.length > 0 && (
        <Section icon={<Bug size={15} style={{ color: "var(--error)" }} />} title="Crashes" count={shownCrashes.length}>
          {shownCrashes.map((c) => (
            <div
              key={c.id}
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-sm) var(--space-md)" }}
            >
              <Bug size={14} style={{ color: "var(--error)", flexShrink: 0 }} />
              <Badge variant="error">{c.kind || "crash"}</Badge>
              <span className="text-xs font-mono text-text-secondary truncate flex-1 min-w-0" title={c.input_path}>
                {c.input_path.split("/").pop()}
              </span>
              {c.minimized && <span className="text-xs text-text-muted shrink-0">minimized</span>}
              <PathActions path={c.input_path} />
              <IconButton danger onClick={() => void deleteCrash(c)} title="Delete this crash" aria-label="Delete crash">
                <Trash2 size={14} />
              </IconButton>
            </div>
          ))}
        </Section>
      )}

      {shownCorpus.length > 0 && (
        <Section icon={<Database size={15} style={{ color: "var(--accent)" }} />} title="Corpus" count={shownCorpus.length}>
          {shownCorpus.map((e) => (
            <div
              key={e.sha256}
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-sm) var(--space-md)" }}
            >
              <Database size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <span className="text-xs font-mono text-text-secondary truncate flex-1 min-w-0" title={e.path}>
                {e.path.split("/").pop()}
              </span>
              <span className="text-xs text-text-muted shrink-0">{e.size} B</span>
              <span className="text-xs text-text-muted shrink-0">{e.source}</span>
              <PathActions path={e.path} />
              <IconButton danger onClick={() => void deleteCorpus(e)} title="Delete this corpus entry" aria-label="Delete corpus entry">
                <Trash2 size={14} />
              </IconButton>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2">
        {icon}
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="text-xs text-text-muted">{count}</span>
      </div>
      {children}
    </div>
  );
}
