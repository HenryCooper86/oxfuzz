import { useCallback, useEffect, useState, lazy, Suspense } from "react";
import { getTransport, isTauriEnvironment, onDataChanged } from "../lib";
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
      setNotice(
        `Pushed ${outcome.findings_pushed} finding(s) to DefectDojo${outcome.reimported ? " (reimport)" : ""}${where}.`,
      );
    } catch (e) {
      setNotice(`DefectDojo push failed: ${String(e)}`);
    } finally {
      setPushingId(null);
    }
  }, []);

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
      if (!(await confirm({ title: "Delete report", message: `Delete "${r.title}"? This cannot be undone.`, danger: true, confirmLabel: "Delete" }))) return;
      try {
        await getTransport().invoke("delete_report_draft", { id: r.id });
        if (open?.id === r.id) setOpen(null);
        await load();
      } catch (e) {
        setNotice(`Delete failed: ${String(e)}`);
      }
    },
    [open, load, confirm],
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
          if (saved) setNotice(`Saved ${format.toUpperCase()} to ${saved}`);
        } else if (format === "md") {
          const blob = new Blob([r.content], { type: "text/markdown" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `${r.title.replace(/[^a-zA-Z0-9_-]/g, "_")}.md`;
          a.click();
          URL.revokeObjectURL(url);
        } else {
          setNotice(`${format.toUpperCase()} export is only available in the desktop app.`);
        }
      } catch (e) {
        setNotice(`Export failed: ${String(e)}`);
      }
    },
    [],
  );

  const q = filter.trim().toLowerCase();
  const shown = q
    ? reports.filter((r) => `${r.title} ${r.target ?? ""} ${r.status}`.toLowerCase().includes(q))
    : reports;

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <ViewHeader
        title="Composed Reports"
        description="Every report generated from triage and the workbench. Preview, export (MD / HTML / PDF / DOCX), or delete."
      />

      {notice && <p className="text-xs text-text-muted">{notice}</p>}

      {!loading && reports.length > 0 && (
        <div className="flex items-center gap-2">
          <Search size={14} className="text-text-muted shrink-0" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by title, target, or status..." className="flex-1" />
        </div>
      )}

      {loadError ? (
        <ErrorState
          title="Failed to load reports"
          message={loadError}
          action={
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RotateCw size={13} />
              Retry
            </Button>
          }
        />
      ) : loading ? (
        <p className="text-sm text-text-muted">Loading reports…</p>
      ) : reports.length === 0 ? (
        <EmptyState
          icon={<FileText size={20} />}
          title="No reports yet"
          hint="Run a fuzz campaign; when triage finds crashes it composes and saves a report here automatically."
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
              <Button variant="outline" size="sm" onClick={() => setOpen(r)} title="Preview and export">
                <Eye size={13} />
                Open
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void pushReport(r)}
                disabled={pushingId === r.id}
                title="Push this report's crashes to DefectDojo (configure in Settings > Integrations)"
              >
                <Share2 size={13} />
                {pushingId === r.id ? "Pushing..." : "DefectDojo"}
              </Button>
              <IconButton
                danger
                onClick={() => void remove(r)}
                title="Delete report"
                aria-label="Delete report"
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
