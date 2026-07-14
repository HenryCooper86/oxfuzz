import { useCallback, useEffect, useState, lazy, Suspense } from "react";
import { getTransport, isTauriEnvironment, onDataChanged } from "../lib";
import { useI18n } from "../i18n";
import { useConfirm } from "../providers/ConfirmContext";
import type { ReportDraft } from "../types";
import { ViewHeader, EmptyState, ErrorState, Input, Button, IconButton } from "../components/ui";
import { FileText, Trash2, Eye, Search, Share2, RotateCw } from "lucide-react";

// Heavy (react-markdown + mermaid); load only when a report is opened.
const ReportPreview = lazy(() =>
  import("../components/ReportPreview").then((m) => ({ default: m.ReportPreview })),
);

// A dedicated home for every composed report, across all projects/targets.
// Reports are produced by Triage (auto-composed on crashes) and the Workbench
// Reports tab; this view lists, previews, exports, and deletes them.
export function ReportsView() {
  const { t } = useI18n();
  const confirm = useConfirm();
  const [reports, setReports] = useState<ReportDraft[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<ReportDraft | null>(null);
  const [formats, setFormats] = useState<string[]>(["md", "html"]);
  const [notice, setNotice] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [pushingId, setPushingId] = useState<string | null>(null);

  // Push the crashes behind a report (its project's latest triaged run) to
  // DefectDojo as findings. Configure the instance in Settings > Integrations.
  const pushReport = useCallback(async (r: ReportDraft) => {
    setNotice(null);
    setPushingId(r.id);
    try {
      const outcome = await getTransport().invoke<{ findings_pushed: number; reimported: boolean; url: string | null }>(
        "push_to_defectdojo",
        { project: r.project, target: r.target ?? undefined },
      );
      const where = outcome.url ? ` (${outcome.url})` : "";
      const reimport = outcome.reimported ? t("reports.reimportSuffix") : "";
      setNotice(t("reports.pushed", { n: outcome.findings_pushed, reimport, where }));
    } catch (e) {
      setNotice(t("reports.pushFailed", { error: String(e) }));
    } finally {
      setPushingId(null);
    }
  }, [t]);

  const load = useCallback(async () => {
    try {
      const list = await getTransport().invoke<ReportDraft[]>("list_report_drafts");
      setReports(list);
      setLoadError(null);
    } catch (e) {
      setReports([]);
      setLoadError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer the initial load out of the synchronous effect body so state is not
    // set during render; re-load whenever data changes elsewhere.
    queueMicrotask(() => void load());
    return onDataChanged(() => void load());
  }, [load]);

  useEffect(() => {
    if (!isTauriEnvironment()) return;
    getTransport()
      .invoke<string[]>("report_formats")
      .then(setFormats)
      .catch(() => setFormats(["md", "html"]));
  }, []);

  const remove = useCallback(
    async (r: ReportDraft) => {
      if (!(await confirm({ title: t("reports.deleteTitle"), message: t("reports.deleteMsg", { title: r.title }), danger: true, confirmLabel: t("common.delete") }))) return;
      try {
        await getTransport().invoke("delete_report_draft", { id: r.id });
        if (open?.id === r.id) setOpen(null);
        await load();
      } catch (e) {
        setNotice(t("reports.deleteFailed", { error: String(e) }));
      }
    },
    [open, load, confirm, t],
  );

  // Export the *saved* content (not a recompose) in the chosen format.
  const exportReport = useCallback(
    async (r: ReportDraft, format: string) => {
      setNotice(null);
      try {
        if (isTauriEnvironment()) {
          const saved = await getTransport().invoke<string | null>("export_markdown", {
            content: r.content,
            title: r.title,
            format,
          });
          if (saved) setNotice(t("reports.savedTo", { format: format.toUpperCase(), path: saved }));
        } else if (format === "md") {
          const blob = new Blob([r.content], { type: "text/markdown" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `${r.title.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
          a.click();
          URL.revokeObjectURL(url);
        } else {
          setNotice(t("reports.exportDesktopOnly", { format: format.toUpperCase() }));
        }
      } catch (e) {
        setNotice(t("reports.exportFailed", { error: String(e) }));
      }
    },
    [t],
  );

  const q = filter.trim().toLowerCase();
  const shown = q
    ? reports.filter((r) => `${r.title} ${r.target ?? ""} ${r.status}`.toLowerCase().includes(q))
    : reports;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title={t("reports.title")}
        description={t("reports.description")}
      />

      {notice && <p className="text-xs text-text-muted">{notice}</p>}

      {!loading && reports.length > 0 && (
        <div className="flex items-center gap-2">
          <Search size={14} className="text-text-muted shrink-0" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("reports.filterPlaceholder")} className="flex-1" />
        </div>
      )}

      {loadError ? (
        <ErrorState
          title={t("reports.loadErrorTitle")}
          message={loadError}
          action={
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RotateCw size={13} />
              {t("common.retry")}
            </Button>
          }
        />
      ) : loading ? (
        <p className="text-sm text-text-muted">{t("reports.loading")}</p>
      ) : reports.length === 0 ? (
        <EmptyState
          icon={<FileText size={20} />}
          title={t("reports.emptyTitle")}
          hint={t("reports.emptyHint")}
        />
      ) : (
        <div className="flex flex-col gap-1.5">
          {shown.map((r) => (
            <div
              key={r.id}
              className="surface-card flex items-center gap-3"
              style={{ padding: "var(--space-sm) var(--space-md)" }}
            >
              <FileText size={16} style={{ color: "var(--accent)", flexShrink: 0 }} />
              <div className="flex flex-col min-w-0 flex-1">
                <span className="text-sm font-medium truncate">{r.title}</span>
                <span className="text-xs text-text-muted truncate">
                  {r.status}
                  {r.target ? ` · ${r.target}` : ""} · {new Date(r.updated_at).toLocaleString()}
                </span>
              </div>
              <Button variant="outline" size="sm" onClick={() => setOpen(r)} title={t("reports.previewExportTitle")}>
                <Eye size={13} />
                {t("common.open")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void pushReport(r)}
                disabled={pushingId === r.id}
                title={t("reports.pushTitle")}
              >
                <Share2 size={13} />
                {pushingId === r.id ? t("reports.pushing") : "DefectDojo"}
              </Button>
              <IconButton
                danger
                onClick={() => void remove(r)}
                title={t("reports.deleteReport")}
                aria-label={t("reports.deleteReport")}
              >
                <Trash2 size={14} />
              </IconButton>
            </div>
          ))}
        </div>
      )}

      {open && (
        <Suspense fallback={null}>
          <ReportPreview
            markdown={open.content}
            onClose={() => setOpen(null)}
            onExport={(format) => void exportReport(open, format)}
            formats={formats}
          />
        </Suspense>
      )}
    </div>
  );
}
