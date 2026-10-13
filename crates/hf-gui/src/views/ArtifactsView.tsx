import { useCallback, useEffect, useRef, useState } from "react";
import { getTransport, isTauriEnvironment, emitDataChanged } from "../lib";
import { useProject } from "../providers/project";
import { useToast } from "../components/ui/toastContext";
import { useConfirm } from "../providers/confirm";
import type { Crash, CorpusEntry } from "../types";
import { Button, IconButton, Input, ViewHeader, EmptyState, ErrorState, Badge } from "../components/ui";
import { Bug, Database, RotateCw, FileWarning, Download, Search, Trash2 } from "lucide-react";
import { PathActions } from "../components/PathActions";
import { useI18n } from "../i18nContext";

export function ArtifactsView() {
  const { activeProject } = useProject();
  const desktop = isTauriEnvironment();
  return <ArtifactInventory key={desktop ? "all-projects" : activeProject} activeProject={activeProject} desktop={desktop} />;
}

function ArtifactInventory({ activeProject, desktop }: { activeProject: string; desktop: boolean }) {
  const { toast } = useToast();
  const confirm = useConfirm();
  const { t } = useI18n();
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [corpus, setCorpus] = useState<CorpusEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [exporting, setExporting] = useState(false);
  const mounted = useRef(true);
  const scanGeneration = useRef(0);
  const inventoryProject = desktop ? undefined : activeProject;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      scanGeneration.current += 1;
    };
  }, []);

  const scan = useCallback(async () => {
    const generation = ++scanGeneration.current;
    setLoading(true);
    setError(null);
    const t = getTransport();
    const project = desktop ? undefined : { project: inventoryProject || undefined };
    try {
      // Desktop browses all persisted artifacts; the browser uses the selected
      // project. Surface a failed read rather than showing an empty state.
      const [c, k] = await Promise.all([
        t.invoke<Crash[]>("all_crashes", project),
        t.invoke<CorpusEntry[]>("all_corpus", project),
      ]);
      if (!mounted.current || generation !== scanGeneration.current) return;
      setCrashes(c);
      setCorpus(k);
    } catch (e) {
      if (!mounted.current || generation !== scanGeneration.current) return;
      setError(String(e));
      setCrashes([]);
      setCorpus([]);
    } finally {
      if (mounted.current && generation === scanGeneration.current) {
        setScanned(true);
        setLoading(false);
      }
    }
  }, [desktop, inventoryProject]);

  // Auto-scan on mount so the view isn't a dead "Scan" prompt.
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void scan(); });
    return () => { active = false; };
  }, [scan]);

  function invalidateScan() {
    scanGeneration.current += 1;
    setLoading(false);
  }

  async function exportData() {
    setExporting(true);
    try {
      const saved = await getTransport().invoke<string | null>("export_project_data", {
        project: activeProject || undefined,
      });
      if (saved) toast({ title: t("artifacts.exported"), description: t("artifacts.savedTo", { path: saved }), variant: "success" });
    } catch (e) {
      toast({ title: t("artifacts.exportFailed"), description: String(e), variant: "error" });
    } finally {
      setExporting(false);
    }
  }

  async function deleteCrash(c: Crash) {
    if (!(await confirm({ title: t("artifacts.deleteCrashTitle"), message: t("artifacts.deleteCrashMessage", { name: c.input_path.split("/").pop() ?? "" }), danger: true, confirmLabel: t("common.delete") }))) return;
    if (!mounted.current) return;
    try {
      await getTransport().invoke("delete_crash", desktop
        ? { crashId: c.id }
        : { crashId: c.id, project: activeProject || undefined });
      emitDataChanged();
      if (!mounted.current) return;
      invalidateScan();
      setCrashes((cs) => cs.filter((x) => x.id !== c.id));
    } catch (e) {
      if (!mounted.current) return;
      toast({ title: t("artifacts.deleteFailed"), description: String(e), variant: "error" });
    }
  }

  async function deleteCorpus(e: CorpusEntry) {
    if (!(await confirm({ title: t("artifacts.deleteCorpusTitle"), message: t("artifacts.deleteCorpusMessage", { name: e.path.split("/").pop() ?? "" }), danger: true, confirmLabel: t("common.delete") }))) return;
    if (!mounted.current) return;
    try {
      await getTransport().invoke("delete_corpus_entry", desktop
        ? { sha256: e.sha256, path: e.path }
        : { sha256: e.sha256, targetId: e.target_id, project: activeProject || undefined });
      emitDataChanged();
      if (!mounted.current) return;
      invalidateScan();
      setCorpus((cs) => cs.filter((x) => x.sha256 !== e.sha256 || (e.target_id ? x.target_id !== e.target_id : x.path !== e.path)));
    } catch (err) {
      if (!mounted.current) return;
      toast({ title: t("artifacts.deleteFailed"), description: String(err), variant: "error" });
    }
  }

  async function clearAll() {
    if (!(await confirm({ title: t("artifacts.clearAllTitle"), message: t("artifacts.clearAllMessage"), danger: true, confirmLabel: t("common.clearAll") }))) return;
    if (!mounted.current) return;
    try {
      await getTransport().invoke("clear_all_artifacts", desktop ? undefined : { project: activeProject || undefined });
      emitDataChanged();
      if (!mounted.current) return;
      invalidateScan();
      setCrashes([]);
      setCorpus([]);
      toast({ title: t("artifacts.cleared"), variant: "success" });
    } catch (e) {
      if (!mounted.current) return;
      toast({ title: t("artifacts.clearFailed"), description: String(e), variant: "error" });
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
        <ViewHeader title={t("artifacts.title")} description={t("artifacts.description")} />
        <div className="flex items-center gap-2">
          {desktop && (
            <Button variant="outline" onClick={() => void exportData()} loading={exporting} title={t("artifacts.exportTooltip")}>
              {!exporting && <Download size={14} />}
              {t("common.export")}
            </Button>
          )}
          {(crashes.length > 0 || corpus.length > 0) && (
            <Button variant="danger" onClick={() => void clearAll()} title={t("artifacts.clearAllTooltip")}>
              <Trash2 size={14} />
              {t("common.clearAll")}
            </Button>
          )}
          <Button variant="primary" onClick={() => void scan()} loading={loading}>
            {!loading && <RotateCw size={14} />}
            {loading ? t("artifacts.scanning") : t("common.rescan")}
          </Button>
        </div>
      </div>

      {(crashes.length > 0 || corpus.length > 0) && (
        <div className="flex items-center gap-2">
          <Search size={14} className="text-text-muted shrink-0" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("artifacts.filterPlaceholder")} className="flex-1" />
        </div>
      )}

      {!scanned && !loading && (
        <EmptyState
          icon={<FileWarning size={20} />}
          hint={t("artifacts.scanHint")}
        />
      )}

      {error && (
        <ErrorState
          title={t("artifacts.loadFailed")}
          message={error}
          action={
            <Button variant="outline" size="sm" onClick={() => void scan()}>
              <RotateCw size={13} />
              {t("common.retry")}
            </Button>
          }
        />
      )}

      {empty && (
        <EmptyState
          icon={<FileWarning size={20} />}
          title={t("artifacts.empty")}
          hint={t("artifacts.emptyHint")}
        />
      )}

      {shownCrashes.length > 0 && (
        <Section icon={<Bug size={15} style={{ color: "var(--error)" }} />} title={t("artifacts.crashes")} count={shownCrashes.length}>
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
              {c.minimized && <span className="text-xs text-text-muted shrink-0">{t("artifacts.minimized")}</span>}
              <PathActions path={c.input_path} />
              <IconButton danger onClick={() => void deleteCrash(c)} title={t("artifacts.deleteCrashTooltip")} aria-label={t("artifacts.deleteCrashAria")}>
                <Trash2 size={14} />
              </IconButton>
            </div>
          ))}
        </Section>
      )}

      {shownCorpus.length > 0 && (
        <Section icon={<Database size={15} style={{ color: "var(--accent)" }} />} title={t("artifacts.corpus")} count={shownCorpus.length}>
          {shownCorpus.map((e) => (
            <div
              key={`${e.target_id ?? e.path}:${e.sha256}`}
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
              <IconButton danger onClick={() => void deleteCorpus(e)} title={t("artifacts.deleteCorpusTooltip")} aria-label={t("artifacts.deleteCorpusAria")}>
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
