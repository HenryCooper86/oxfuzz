import { useCallback, useEffect, useState } from "react";
import { getTransport, isTauriEnvironment, emitDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useToast } from "../components/ui/Toast";
import { useConfirm } from "../providers/ConfirmContext";
import type { Crash, CorpusEntry } from "../types";
import { Button, IconButton, Input, ViewHeader, EmptyState, ErrorState, Badge } from "../components/ui";
import { Bug, Database, RotateCw, FileWarning, Download, Search, Trash2 } from "lucide-react";
import { PathActions } from "../components/PathActions";
import { useI18n } from "../i18n";

export function ArtifactsView() {
  const { activeProject } = useProject();
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
      if (saved) toast({ title: t("artifacts.exported"), description: t("artifacts.savedTo", { path: saved }), variant: "success" });
    } catch (e) {
      toast({ title: t("artifacts.exportFailed"), description: String(e), variant: "error" });
    } finally {
      setExporting(false);
    }
  }

  async function deleteCrash(c: Crash) {
    if (!(await confirm({ title: t("artifacts.deleteCrashTitle"), message: t("artifacts.deleteCrashMessage", { name: c.input_path.split("/").pop() ?? "" }), danger: true, confirmLabel: t("common.delete") }))) return;
    try {
      await getTransport().invoke("delete_crash", { crashId: c.id });
      setCrashes((cs) => cs.filter((x) => x.id !== c.id));
      emitDataChanged();
    } catch (e) {
      toast({ title: t("artifacts.deleteFailed"), description: String(e), variant: "error" });
    }
  }

  async function deleteCorpus(e: CorpusEntry) {
    if (!(await confirm({ title: t("artifacts.deleteCorpusTitle"), message: t("artifacts.deleteCorpusMessage", { name: e.path.split("/").pop() ?? "" }), danger: true, confirmLabel: t("common.delete") }))) return;
    try {
      await getTransport().invoke("delete_corpus_entry", { sha256: e.sha256, path: e.path });
      setCorpus((cs) => cs.filter((x) => x.sha256 !== e.sha256 || x.path !== e.path));
      emitDataChanged();
    } catch (err) {
      toast({ title: t("artifacts.deleteFailed"), description: String(err), variant: "error" });
    }
  }

  async function clearAll() {
    if (!(await confirm({ title: t("artifacts.clearAllTitle"), message: t("artifacts.clearAllMessage"), danger: true, confirmLabel: t("common.clearAll") }))) return;
    try {
      await getTransport().invoke("clear_all_artifacts");
      setCrashes([]);
      setCorpus([]);
      emitDataChanged();
      toast({ title: t("artifacts.cleared"), variant: "success" });
    } catch (e) {
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
          {isTauriEnvironment() && (
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
