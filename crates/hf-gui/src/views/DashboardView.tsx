import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Copy,
  ExternalLink,
  FileCode,
  FileText,
  FolderOpen,
  GitPullRequest,
  Play,
  RotateCw,
  Save,
  Server,
  ShieldCheck,
  Square,
  Crosshair,
  Trash2,
  Users,
  Wrench,
} from "lucide-react";
import { AutoRevertBadge, type AutoRevertPolicyView } from "../components/AutoRevertBadge";
import { Button, EmptyState, Input, LoadingState, Select, Textarea, ViewHeader } from "../components/ui";
import { useToast } from "../components/ui/toastContext";
import { useConfirm } from "../providers/confirm";
import { getTransport, onDataChanged, openExternal, useDefectDojo } from "../lib";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { useI18n, type TParams } from "../i18nContext";
import type {
  CrashReviewItem,
  CreatedIssue,
  DefectDojoStatus,
  IssueExport,
  HarnessReviewItem,
  ReadinessNote,
  ReportDraft,
  SystemStatus,
  WorkbenchDashboard,
  WorkbenchReadiness,
  WorkbenchRun,
  WorkbenchTarget,
  ViewType,
} from "../types";

type TFn = (key: string, params?: TParams) => string;

/**
 * Localize `key`, falling back to `fallback` when the active locale has no entry
 * for it (t() returns the key itself on a miss). This lets English keep the
 * backend's authoritative readiness/next-action prose -- including its correct
 * singular/plural forms -- while Chinese renders from the dictionary by code.
 */
function loc(t: TFn, key: string, fallback: string, params?: TParams): string {
  const out = t(key, params);
  return out === key ? fallback : out;
}

// Dashboard-specific surfaces only. Crashes, harnesses, targets, and knowledge
// each have a canonical standalone view (Artifacts, Harness, Discover,
// Knowledge); the Overview summarizes them with a deep-link there, instead of
// the dashboard re-implementing them as tabs.
type WorkbenchTab =
  | "overview"
  | "reports"
  | "repro"
  | "team"
  | "gitlab"
  | "health";

interface ReportEditorState {
  id: string | null;
  title: string;
  project: string;
  target: string;
  status: string;
  content: string;
}

const EMPTY_TOTALS = {
  projects: 0,
  targets: 0,
  harnesses: 0,
  harnesses_needing_review: 0,
  runs: 0,
  active_runs: 0,
  crashes: 0,
  crashes_needing_triage: 0,
  corpus_entries: 0,
};

const REPORT_STATUSES = [
  "Draft",
  "Needs Review",
  "Approved",
  "Filed",
  "Fixed",
  "Not Reproducible",
];

function emptyDashboard(project: string | null, target: string | null): WorkbenchDashboard {
  return {
    active_project: project,
    active_target: target,
    totals: EMPTY_TOTALS,
    recent_runs: [],
    top_targets: [],
    harness_reviews: [],
    crash_reviews: [],
    readiness: {
      state: "setup_required",
      score: 0,
      headline: "Discovery needed",
      detail: "Run target discovery before creating harnesses or campaigns.",
      blockers: ["No fuzzing targets discovered."],
      blocker_items: [{ code: "no_targets", count: 0 }],
    },
    next_actions: ["Run target discovery on an internal project."],
    next_action_items: [{ code: "run_discovery", count: 0 }],
  };
}

function emptyEditor(project: string, target: string): ReportEditorState {
  return {
    id: null,
    title: target ? `${target} fuzzing report` : "Untitled fuzzing report",
    project,
    target,
    status: "Draft",
    content: "",
  };
}

export function DashboardView({ onNavigate }: { onNavigate?: (view: ViewType) => void }) {
  const { activeProject } = useProject();
  const { target } = useTarget();
  const { toast } = useToast();
  const confirm = useConfirm();
  const { t } = useI18n();
  const { configured: defectDojoOn } = useDefectDojo();
  const [tab, setTab] = useState<WorkbenchTab>("overview");
  const [dashboard, setDashboard] = useState<WorkbenchDashboard>(() => emptyDashboard(activeProject, target));
  const [reports, setReports] = useState<ReportDraft[]>([]);
  const [editor, setEditor] = useState<ReportEditorState>(() => emptyEditor(activeProject, target));
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issue, setIssue] = useState<IssueExport | null>(null);
  // The active project's effective auto-revert policy (override or global), for
  // the header badge. Null until loaded or when no project is active.
  const [autoRevert, setAutoRevert] = useState<(AutoRevertPolicyView & { overridden: boolean }) | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!activeProject) {
        if (!cancelled) setAutoRevert(null);
        return;
      }
      try {
        const v = await getTransport().invoke<AutoRevertPolicyView & { overridden: boolean }>(
          "effective_auto_revert_policy",
          { project: activeProject },
        );
        if (!cancelled) setAutoRevert(v);
      } catch {
        if (!cancelled) setAutoRevert(null);
      }
    };
    void load();
    const unsub = onDataChanged(() => void load());
    return () => {
      cancelled = true;
      unsub();
    };
  }, [activeProject]);

  const args = useMemo(
    () => ({
      project: activeProject || undefined,
      target: target || undefined,
    }),
    [activeProject, target],
  );

  const loadDashboard = useCallback(async () => {
    try {
      return await getTransport().invoke<WorkbenchDashboard>("workbench_dashboard", args);
    } catch (e) {
      // Don't silently show a zeroed dashboard as if there were no data.
      toast({ title: t("dashboard.failedLoadWorkbench"), description: String(e), variant: "error" });
      return emptyDashboard(activeProject, target);
    }
  }, [activeProject, args, target, toast, t]);

  const reloadReports = useCallback(async () => {
    try {
      const next = await getTransport().invoke<ReportDraft[]>("list_report_drafts");
      setReports(next);
      return next;
    } catch (e) {
      setReports([]);
      toast({ title: t("dashboard.failedLoadReports"), description: String(e), variant: "error" });
      return [];
    }
  }, [toast, t]);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    const [nextDashboard, nextReports, nextSystem] = await Promise.all([
      loadDashboard(),
      reloadReports(),
      getTransport().invoke<SystemStatus>("system_status_cmd").catch(() => null),
    ]);
    setDashboard(nextDashboard);
    setSystem(nextSystem);
    if (!editor.content && nextReports.length > 0) {
      selectReport(nextReports[0]);
    }
    setLoading(false);
  }, [editor.content, loadDashboard, reloadReports]);

  // Keep the latest `reload` reachable from the mount effect without listing it
  // as a dependency. `reload` closes over `editor.content`, so a new identity is
  // produced on every keystroke in the report editor; depending on it here would
  // re-run this effect (re-fetching the whole dashboard + reports + system, and
  // re-subscribing onDataChanged) on each character typed.
  const reloadRef = useRef(reload);
  reloadRef.current = reload;

  useEffect(() => {
    let cancelled = false;
    async function loadInitialDashboard() {
      const [nextDashboard, nextReports, nextSystem] = await Promise.all([
        loadDashboard(),
        reloadReports(),
        getTransport().invoke<SystemStatus>("system_status_cmd").catch(() => null),
      ]);
      if (!cancelled) {
        setDashboard(nextDashboard);
        setSystem(nextSystem);
        setEditor((current) => {
          if (current.content || nextReports.length === 0) return current;
          return editorFromReport(nextReports[0]);
        });
        setLoading(false);
      }
    }
    void loadInitialDashboard();
    // Re-fetch when another view clears knowledge / workspace or deletes a
    // project, so the Workbench counts never disagree with what was just wiped.
    const unsubscribe = onDataChanged(() => void reloadRef.current());
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [loadDashboard, reloadReports]);

  function selectReport(report: ReportDraft) {
    setEditor(editorFromReport(report));
    setNotice(null);
    setError(null);
  }

  function startBlankReport() {
    setEditor(emptyEditor(activeProject, target));
    setNotice(null);
    setError(null);
    setTab("reports");
  }

  async function generateActiveReport() {
    setNotice(null);
    setError(null);
    if (!activeProject || !target) {
      setError(t("dashboard.selectProjectTarget"));
      setTab("reports");
      return;
    }
    try {
      const content = await getTransport().invoke<string>("generate_report", {
        project: activeProject,
        target,
      });
      setEditor({
        id: null,
        title: `${target} fuzzing report`,
        project: activeProject,
        target,
        status: "Draft",
        content,
      });
      setTab("reports");
      setNotice(t("dashboard.generatedDraft"));
    } catch (e) {
      setError(t("dashboard.reportGenFailed", { error: String(e) }));
      setTab("reports");
    }
  }

  async function saveDraft() {
    setNotice(null);
    setError(null);
    try {
      const saved = await getTransport().invoke<ReportDraft>("save_report_draft", {
        id: editor.id ?? undefined,
        title: editor.title,
        project: editor.project,
        target: editor.target || null,
        status: editor.status,
        content: editor.content,
      });
      setEditor(editorFromReport(saved));
      await reloadReports();
      setNotice(t("dashboard.reportSaved"));
    } catch (e) {
      setError(t("dashboard.saveFailed", { error: String(e) }));
    }
  }

  async function deleteDraft(report: ReportDraft) {
    if (!(await confirm({ title: t("dashboard.deleteReportTitle"), message: t("dashboard.deleteReportMessage", { title: report.title }), danger: true, confirmLabel: t("common.delete") }))) return;
    setNotice(null);
    setError(null);
    try {
      await getTransport().invoke("delete_report_draft", { id: report.id });
      const next = await reloadReports();
      setEditor(next[0] ? editorFromReport(next[0]) : emptyEditor(activeProject, target));
      setNotice(t("dashboard.reportDeleted"));
    } catch (e) {
      setError(t("dashboard.deleteFailed", { error: String(e) }));
    }
  }

  async function exportCrash(crash: CrashReviewItem) {
    setError(null);
    setNotice(null);
    if (!activeProject) {
      setError(t("dashboard.selectProjectForExport"));
      setTab("gitlab");
      return;
    }
    try {
      const draft = await getTransport().invoke<IssueExport>("issue_export", {
        project: activeProject,
        crashId: crash.crash_id,
      });
      setIssue(draft);
      setTab("gitlab");
    } catch (e) {
      setError(t("dashboard.gitlabExportFailed", { error: String(e) }));
      setTab("gitlab");
    }
  }

  const tabs = workbenchTabs(dashboard, t);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0" style={{ overflowWrap: "anywhere" }}>
          <ViewHeader
            title={t("dashboard.title")}
            description={activeProject ? `${activeProject}${target ? ` / ${target}` : ""}` : t("dashboard.noActiveProject")}
          />
        </div>
        <div className="flex items-center gap-2">
          {activeProject && autoRevert && (
            <AutoRevertBadge policy={autoRevert} overridden={autoRevert.overridden} showScope />
          )}
          {defectDojoOn && onNavigate && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onNavigate("defectdojo")}
              title={t("dashboard.openDefectDojo")}
            >
              <ShieldCheck size={14} />
              DefectDojo
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => void generateActiveReport()} disabled={!activeProject || !target}>
            <FileText size={14} />
            {t("dashboard.draftReport")}
          </Button>
          <Button variant="outline" size="sm" onClick={() => void reload()} disabled={loading}>
            <RotateCw size={14} />
            {t("common.refresh")}
          </Button>
        </div>
      </div>

      {!activeProject && (
        <section
          className="surface-card flex items-start gap-3"
          style={{ padding: "var(--space-md)", borderColor: "var(--accent)", background: "var(--accent-subtle)" }}
          role="status"
        >
          <FolderOpen size={18} style={{ color: "var(--accent)", flexShrink: 0, marginTop: 2 }} />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-text-primary">{t("dashboard.chooseProjectTitle")}</h2>
            <p className="mt-1 text-sm text-text-secondary">
              {t("dashboard.chooseProjectPre")}<strong className="text-text-primary">{t("dashboard.openProject")}</strong>{t("dashboard.chooseProjectPost")}
            </p>
          </div>
        </section>
      )}

      <div
        className="flex flex-wrap gap-1 border-b border-border"
        role="tablist"
        aria-label={t("dashboard.workbenchSections")}
        onKeyDown={(e) => {
          const ids = tabs.map((item) => item.id);
          const idx = ids.indexOf(tab);
          let next = idx;
          if (e.key === "ArrowRight") next = (idx + 1) % ids.length;
          else if (e.key === "ArrowLeft") next = (idx - 1 + ids.length) % ids.length;
          else if (e.key === "Home") next = 0;
          else if (e.key === "End") next = ids.length - 1;
          else return;
          e.preventDefault();
          setTab(ids[next]);
          const btns = e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]');
          btns[next]?.focus();
        }}
      >
        {tabs.map((item) => (
          <button
            key={item.id}
            role="tab"
            aria-selected={tab === item.id}
            tabIndex={tab === item.id ? 0 : -1}
            onClick={() => setTab(item.id)}
            className="flex items-center gap-2 rounded-t-md border border-b-0 transition-colors"
            style={{
              padding: "7px 10px",
              fontSize: 12,
              background: tab === item.id ? "var(--surface-active)" : "transparent",
              color: tab === item.id ? "var(--text-primary)" : "var(--text-secondary)",
              borderColor: tab === item.id ? "var(--border)" : "transparent",
            }}
          >
            {item.icon}
            <span>{item.label}</span>
            {item.count !== undefined && <span className="text-text-muted">{item.count}</span>}
          </button>
        ))}
      </div>

      {notice && <InlineNotice tone="ok" text={notice} />}
      {error && <InlineNotice tone="error" text={error} />}

      {loading ? (
        <LoadingState label={t("dashboard.loadingWorkbench")} />
      ) : (
        <>
          {tab === "overview" && (
            <OverviewTab
              dashboard={dashboard}
              onReport={() => void generateActiveReport()}
              onExport={exportCrash}
              onNavigate={onNavigate}
            />
          )}
          {tab === "reports" && (
            <ReportStudio
              reports={reports}
              editor={editor}
              onEditor={setEditor}
              onSelect={selectReport}
              onBlank={startBlankReport}
              onGenerate={() => void generateActiveReport()}
              onSave={() => void saveDraft()}
              onDelete={(report) => void deleteDraft(report)}
            />
          )}
          {tab === "repro" && (
            <ReproCenter
              project={activeProject}
              crashes={dashboard.crash_reviews}
              harnesses={dashboard.harness_reviews}
            />
          )}
          {tab === "team" && (
            <TeamReview
              reports={reports}
              crashes={dashboard.crash_reviews}
              harnesses={dashboard.harness_reviews}
              onOpenReport={(r) => {
                selectReport(r);
                setTab("reports");
              }}
              onOpenHarnesses={() => onNavigate?.("harness")}
              onOpenCrashes={() => onNavigate?.("artifacts")}
            />
          )}
          {tab === "gitlab" && (
            <GitLabIntegration
              project={activeProject}
              crashes={dashboard.crash_reviews}
              issue={issue}
              onExport={exportCrash}
            />
          )}
          {tab === "health" && <HealthPanel status={system} dashboard={dashboard} />}
        </>
      )}
    </div>
  );
}

function workbenchTabs(
  dashboard: WorkbenchDashboard,
  t: (key: string) => string,
): { id: WorkbenchTab; label: string; icon: React.ReactNode; count?: number }[] {
  return [
    { id: "overview", label: t("dashboard.tabOverview"), icon: <Activity size={14} /> },
    { id: "reports", label: t("dashboard.tabReports"), icon: <FileText size={14} /> },
    { id: "repro", label: t("dashboard.tabRepro"), icon: <Play size={14} /> },
    { id: "team", label: t("dashboard.tabReview"), icon: <Users size={14} />, count: dashboard.harness_reviews.length + dashboard.crash_reviews.length },
    { id: "gitlab", label: "GitLab", icon: <GitPullRequest size={14} /> },
    { id: "health", label: t("dashboard.tabHealth"), icon: <Server size={14} /> },
  ];
}

function OverviewTab({
  dashboard,
  onReport,
  onExport,
  onNavigate,
}: {
  dashboard: WorkbenchDashboard;
  onReport: () => void;
  onExport: (crash: CrashReviewItem) => void;
  onNavigate?: (view: ViewType) => void;
}) {
  return (
    <div className="flex flex-col gap-4">
      <ReadinessSummary readiness={dashboard.readiness} />
      <MetricGrid dashboard={dashboard} />
      <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 360px), 1fr))" }}>
        <section className="flex flex-col gap-4 min-w-0">
          <NextActions actions={dashboard.next_actions} items={dashboard.next_action_items} onReport={onReport} />
          <HarnessQueue items={dashboard.harness_reviews} onOpen={onNavigate && (() => onNavigate("harness"))} />
          <RecentRuns runs={dashboard.recent_runs} onOpen={onNavigate && (() => onNavigate("runs"))} />
        </section>
        <section className="flex flex-col gap-4 min-w-0">
          <TopTargets targets={dashboard.top_targets} onOpen={onNavigate && (() => onNavigate("discover"))} />
          <CrashQueue items={dashboard.crash_reviews} onExport={onExport} onOpen={onNavigate && (() => onNavigate("artifacts"))} />
        </section>
      </div>
    </div>
  );
}

function ReadinessSummary({ readiness }: { readiness: WorkbenchReadiness }) {
  const { t } = useI18n();
  const isReady = readiness.state === "ready" || readiness.state === "active";
  const tone = isReady ? "ok" : "warn";
  const headline = loc(t, `readiness.state.${readiness.state}.headline`, readiness.headline);
  const detail = loc(t, `readiness.state.${readiness.state}.detail`, readiness.detail);
  const badge = loc(t, `readiness.state.${readiness.state}.badge`, readiness.state.replace(/_/g, " "));
  // Render the localizable notes when present, falling back to the parallel
  // English prose (same order/length) per line for the English locale.
  const blockers = readiness.blocker_items.length
    ? readiness.blocker_items.map((item, i) =>
        loc(t, `readiness.blocker.${item.code}`, readiness.blockers[i] ?? item.code, { n: item.count }),
      )
    : readiness.blockers;
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <SectionHeader icon={<ShieldCheck size={15} />} title={t("dashboard.operationalReadiness")} />
          <h2 className="mt-2 text-lg font-semibold text-text-primary">{headline}</h2>
          <p className="mt-1 text-sm text-text-secondary">{detail}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge value={badge} tone={tone} />
          <span className="text-sm font-semibold" style={{ color: isReady ? "var(--success)" : "var(--warning)" }}>
            {readiness.score}%
          </span>
        </div>
      </div>
      <div className="h-2 rounded-sm overflow-hidden" style={{ background: "var(--surface-secondary)" }}>
        <div
          className="h-full"
          style={{
            width: `${Math.max(0, Math.min(100, readiness.score))}%`,
            background: isReady ? "var(--success)" : "var(--warning)",
          }}
        />
      </div>
      {blockers.length > 0 ? (
        <div className="flex flex-col gap-1">
          {blockers.slice(0, 4).map((blocker) => (
            <div key={blocker} className="flex items-start gap-2 text-xs text-text-secondary">
              <AlertTriangle size={13} style={{ color: "var(--warning)", flexShrink: 0, marginTop: 1 }} />
              <span>{blocker}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <CheckCircle2 size={13} style={{ color: "var(--success)" }} />
          <span>{t("dashboard.noBlockers")}</span>
        </div>
      )}
    </section>
  );
}

function ReportStudio({
  reports,
  editor,
  onEditor,
  onSelect,
  onBlank,
  onGenerate,
  onSave,
  onDelete,
}: {
  reports: ReportDraft[];
  editor: ReportEditorState;
  onEditor: (next: ReportEditorState) => void;
  onSelect: (report: ReportDraft) => void;
  onBlank: () => void;
  onGenerate: () => void;
  onSave: () => void;
  onDelete: (report: ReportDraft) => void;
}) {
  const { t } = useI18n();
  const selectedId = editor.id;
  return (
    <div className="flex flex-wrap gap-4 min-w-0">
      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)", minHeight: 520, flex: "1 1 260px", maxWidth: 360, minWidth: 0 }}>
        <SectionHeader icon={<FileText size={15} />} title={t("dashboard.composedReports")} count={reports.length} />
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onBlank}>
            <FileText size={13} />
            {t("common.new")}
          </Button>
          <Button variant="primary" size="sm" onClick={onGenerate}>
            <Wrench size={13} />
            {t("common.generate")}
          </Button>
        </div>
        {reports.length === 0 ? (
          <EmptyState icon={<FileText size={18} />} hint={t("dashboard.noSavedReports")} />
        ) : (
          <div className="flex flex-col gap-2 overflow-auto">
            {reports.map((report) => (
              <div
                key={report.id}
                className="rounded-md border border-border"
                style={{
                  padding: "var(--space-sm)",
                  background: selectedId === report.id ? "var(--surface-active)" : "var(--surface-secondary)",
                }}
              >
                <button className="w-full text-left" onClick={() => onSelect(report)}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium truncate">{report.title}</span>
                    <StatusBadge value={report.status} />
                  </div>
                  <div className="text-xs text-text-muted truncate mt-1">
                    {report.target || t("dashboard.projectReport")} · {formatDate(report.updated_at)}
                  </div>
                </button>
                <div className="flex justify-end mt-2">
                  <Button variant="outline" size="sm" onClick={() => onDelete(report)}>
                    <Trash2 size={13} />
                    {t("common.delete")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)", minHeight: 520, flex: "2 1 380px", minWidth: 0 }}>
        <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(120px, 180px)" }}>
          <label className="flex flex-col gap-1 min-w-0">
            <span className="text-xs text-text-muted">{t("dashboard.labelTitle")}</span>
            <Input value={editor.title} onChange={(e) => onEditor({ ...editor, title: e.target.value })} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-text-muted">{t("dashboard.labelStatus")}</span>
            <Select
              value={editor.status}
              options={REPORT_STATUSES.map((status) => ({ value: status, label: status }))}
              onChange={(status) => onEditor({ ...editor, status })}
            />
          </label>
        </div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(120px, 240px)" }}>
          <label className="flex flex-col gap-1 min-w-0">
            <span className="text-xs text-text-muted">{t("dashboard.labelProject")}</span>
            <Input value={editor.project} onChange={(e) => onEditor({ ...editor, project: e.target.value })} mono />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-text-muted">{t("dashboard.labelTarget")}</span>
            <Input value={editor.target} onChange={(e) => onEditor({ ...editor, target: e.target.value })} mono />
          </label>
        </div>
        <Textarea
          mono
          value={editor.content}
          onChange={(e) => onEditor({ ...editor, content: e.target.value })}
          rows={18}
          placeholder={t("dashboard.reportPlaceholder")}
        />
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-text-muted">{t("dashboard.charactersCount", { count: editor.content.length.toLocaleString() })}</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => copyText(editor.content)} disabled={!editor.content}>
              <Copy size={13} />
              {t("common.copy")}
            </Button>
            <Button variant="primary" size="sm" onClick={onSave} disabled={!editor.content.trim() || !editor.title.trim()}>
              <Save size={13} />
              {t("common.saveDraft")}
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

function CrashCard({ crash, onExport }: { crash: CrashReviewItem; onExport: () => void }) {
  const { t } = useI18n();
  return (
    <div className="rounded-md border border-border" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold truncate">{crash.target_symbol}</div>
          <div className="text-xs text-text-muted mt-1">{crash.kind} · {crash.severity}</div>
        </div>
        <StatusBadge value={t(crash.has_bug_report ? "dashboard.reportReady" : "dashboard.needsReport")} tone={crash.has_bug_report ? "ok" : "warn"} />
      </div>
      <p className="text-xs text-text-secondary mt-3" style={{ minHeight: 34 }}>
        {crash.summary || t("dashboard.noSummary")}
      </p>
      <div className="flex flex-wrap items-center justify-between gap-2 mt-3">
        <span className="text-xs text-text-muted font-mono">{shortId(crash.crash_id)}</span>
        <Button variant="outline" size="sm" onClick={onExport}>
          <GitPullRequest size={13} />
          {t("dashboard.gitlabDraft")}
        </Button>
      </div>
    </div>
  );
}


function ReproCenter({
  project,
  crashes,
  harnesses,
}: {
  project: string;
  crashes: CrashReviewItem[];
  harnesses: HarnessReviewItem[];
}) {
  const { t } = useI18n();
  const firstHarness = harnesses[0];
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Play size={15} />} title={t("dashboard.reproCenter")} count={crashes.length} />
      {!project && <InlineNotice tone="warn" text={t("dashboard.reproSelectProject")} />}
      {crashes.length === 0 ? (
        <EmptyState icon={<Play size={18} />} hint={t("dashboard.noReproducers")} />
      ) : (
        <div className="flex flex-col gap-3">
          {crashes.map((crash) => {
            const target = firstHarness?.target_symbol || crash.target_symbol;
            const command = project
              ? `oxfuzz regress ${shellQuote(project)} --target ${shellQuote(target)}`
              : t("dashboard.selectProjectForCommand");
            return (
              <div key={crash.crash_id} className="rounded-md border border-border" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium truncate">{crash.target_symbol}</span>
                  <StatusBadge value={t(crash.minimized ? "dashboard.minimized" : "dashboard.rawInput")} />
                </div>
                <code className="block text-xs font-mono mt-3 p-2 rounded-md whitespace-pre-wrap" style={{ background: "var(--surface-code)", color: "var(--text-secondary)" }}>
                  {command}
                </code>
                <div className="flex justify-end mt-2">
                  <Button variant="outline" size="sm" onClick={() => copyText(command)} disabled={!project}>
                    <Clipboard size={13} />
                    {t("dashboard.copyCommand")}
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function TeamReview({
  reports,
  crashes,
  harnesses,
  onOpenReport,
  onOpenHarnesses,
  onOpenCrashes,
}: {
  reports: ReportDraft[];
  crashes: CrashReviewItem[];
  harnesses: HarnessReviewItem[];
  onOpenReport: (report: ReportDraft) => void;
  onOpenHarnesses: () => void;
  onOpenCrashes: () => void;
}) {
  const { t } = useI18n();
  const reportNeedsReview = reports.filter((report) => report.status === "Needs Review");
  const harnessNeedsReview = harnesses.filter((item) => item.needs_review);
  const crashNeedsReport = crashes.filter((item) => !item.has_bug_report);
  return (
    <section className="surface-card flex flex-col gap-3 min-w-0" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Users size={15} />} title={t("dashboard.reviewFlow")} />
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 220px), 1fr))" }}>
        <ReviewLane
          title={t("dashboard.reportsNeedingReview")}
          count={reportNeedsReview.length}
          items={reportNeedsReview.map((r) => ({ label: r.title, onClick: () => onOpenReport(r) }))}
        />
        <ReviewLane
          title={t("dashboard.harnessesNeedingApproval")}
          count={harnessNeedsReview.length}
          items={harnessNeedsReview.map((h) => ({ label: h.target_symbol, onClick: onOpenHarnesses }))}
        />
        <ReviewLane
          title={t("dashboard.crashesNeedingReports")}
          count={crashNeedsReport.length}
          items={crashNeedsReport.map((c) => ({ label: c.target_symbol, onClick: onOpenCrashes }))}
        />
      </div>
    </section>
  );
}

function ReviewLane({
  title,
  count,
  items,
}: {
  title: string;
  count: number;
  items: { label: string; onClick: () => void }[];
}) {
  const { t } = useI18n();
  return (
    <div className="rounded-md border border-border min-w-0" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold truncate">{title}</span>
        <span className="text-xs text-text-muted shrink-0">{count}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-text-muted mt-3">{t("dashboard.nothingQueued")}</p>
      ) : (
        <div className="flex flex-col gap-0.5 mt-3">
          {items.slice(0, 6).map((item, i) => (
            <button
              key={`${item.label}:${i}`}
              onClick={item.onClick}
              title={t("dashboard.openItem", { label: item.label })}
              className="flex items-center gap-1.5 text-left text-xs text-text-secondary truncate rounded px-1.5 py-1 -mx-1.5 transition-colors hover:bg-surface-hover hover:text-text-primary"
            >
              <ChevronRight size={11} className="shrink-0 text-text-muted" />
              <span className="truncate">{item.label}</span>
            </button>
          ))}
          {items.length > 6 && (
            <span className="text-xs text-text-muted mt-1">{t("dashboard.moreCount", { count: items.length - 6 })}</span>
          )}
        </div>
      )}
    </div>
  );
}

function GitLabIntegration({
  project,
  crashes,
  issue,
  onExport,
}: {
  project: string;
  crashes: CrashReviewItem[];
  issue: IssueExport | null;
  onExport: (crash: CrashReviewItem) => void;
}) {
  const { t } = useI18n();
  return (
    <div className="flex flex-wrap gap-4 min-w-0">
      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)", flex: "1 1 300px", maxWidth: 440, minWidth: 0 }}>
        <SectionHeader icon={<GitPullRequest size={15} />} title={t("dashboard.gitlabExport")} count={crashes.length} />
        {!project && <InlineNotice tone="warn" text={t("dashboard.gitlabSelectProject")} />}
        {crashes.length === 0 ? (
          <EmptyState icon={<GitPullRequest size={18} />} hint={t("dashboard.noCrashesForExport")} />
        ) : (
          <div className="flex flex-col gap-2">
            {crashes.map((crash) => (
              <button
                key={crash.crash_id}
                className="rounded-md border border-border text-left"
                style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}
                onClick={() => onExport(crash)}
              >
                <span className="block text-sm font-medium truncate">{crash.target_symbol}</span>
                <span className="block text-xs text-text-muted truncate">{crash.kind} · {crash.severity}</span>
              </button>
            ))}
          </div>
        )}
      </section>
      <div style={{ flex: "2 1 380px", minWidth: 0 }}>
        {issue ? <IssueDraft draft={issue} /> : <EmptyState icon={<GitPullRequest size={18} />} hint={t("dashboard.chooseCrashPreview")} />}
      </div>
    </div>
  );
}

function IssueDraft({ draft }: { draft: IssueExport }) {
  const { toast } = useToast();
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [filing, setFiling] = useState(false);
  const providerLabel = draft.provider === "github" ? "GitHub" : "GitLab";

  async function copyBody() {
    await copyText(`${draft.title}\n\n${draft.description}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  // File the issue directly via the provider API, then open the created issue.
  async function fileIssue() {
    setFiling(true);
    try {
      const created = await getTransport().invoke<CreatedIssue>("file_issue", {
        crashId: draft.crash_id,
      });
      toast({ title: t("dashboard.filedIssue", { provider: providerLabel }), description: created.url, variant: "success" });
      if (created.url) void openExternal(created.url);
    } catch (e) {
      toast({ title: t("dashboard.couldNotFileIssue", { provider: providerLabel }), description: String(e), variant: "error" });
    } finally {
      setFiling(false);
    }
  }

  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<GitPullRequest size={15} />} title={t("dashboard.issueDraft")} />
      <div className="mt-3 flex flex-col gap-2">
        <div className="text-sm font-medium">{draft.title}</div>
        {draft.project_web_url && (
          <div className="text-xs text-text-muted truncate">
            {providerLabel} · <span className="font-mono">{draft.project_web_url.replace(/^https?:\/\//, "")}</span>
          </div>
        )}
        <div className="flex flex-wrap gap-1">
          {draft.labels.map((label) => (
            <span key={label} className="text-xs px-2 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-secondary)" }}>{label}</span>
          ))}
        </div>
        <Textarea value={draft.description} readOnly rows={12} />
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => void copyBody()}>
            <Clipboard size={13} />
            {copied ? t("common.copied") : t("common.copy")}
          </Button>
          {draft.can_file && (
            <Button variant="primary" size="sm" onClick={() => void fileIssue()} loading={filing}>
              {!filing && <GitPullRequest size={13} />}
              {t("dashboard.fileIssue", { provider: providerLabel })}
            </Button>
          )}
          {draft.issue_url && (
            <Button variant={draft.can_file ? "outline" : "primary"} size="sm" onClick={() => void openExternal(draft.issue_url ?? "")}>
              <ExternalLink size={13} />
              {t("common.openInBrowser")}
            </Button>
          )}
        </div>
        {!draft.issue_url && (
          <InlineNotice
            tone="warn"
            text={t("dashboard.noIssueTracker")}
          />
        )}
      </div>
    </section>
  );
}

function HealthPanel({ status, dashboard }: { status: SystemStatus | null; dashboard: WorkbenchDashboard }) {
  const { t } = useI18n();
  const checks = [
    ["Docker", status?.docker],
    [t("dashboard.sandboxImage"), status?.sandbox_image],
    ["libFuzzer", status?.libfuzzer],
    ["AFL++", status?.aflplusplus],
    ["honggfuzz", status?.honggfuzz],
    ["ClusterFuzzLite", status?.clusterfuzzlite],
    ["syzkaller", status?.syzkaller],
  ] as const;
  return (
    <section className="surface-card flex flex-col gap-4" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<ShieldCheck size={15} />} title={t("dashboard.productionReadiness")} />
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 180px), 1fr))" }}>
        {checks.map(([label, ok]) => (
          <div key={label} className="rounded-md border border-border flex items-center justify-between gap-3" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
            <span className="text-sm">{label}</span>
            <StatusBadge value={ok ? t("dashboard.ready") : t("dashboard.missing")} tone={ok ? "ok" : "warn"} />
          </div>
        ))}
      </div>
      <DefectDojoHealth />
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 220px), 1fr))" }}>
        <ReadinessItem ready={dashboard.totals.targets > 0} label={t("dashboard.targetsDiscovered")} detail={t("dashboard.targetsCount", { count: dashboard.totals.targets })} />
        <ReadinessItem ready={dashboard.totals.harnesses > 0} label={t("dashboard.harnessLibrary")} detail={t("dashboard.harnessesCount", { count: dashboard.totals.harnesses })} />
        <ReadinessItem ready={dashboard.totals.runs > 0} label={t("dashboard.campaignHistory")} detail={t("dashboard.runsCount", { count: dashboard.totals.runs })} />
        <ReadinessItem ready={dashboard.totals.harnesses_needing_review === 0} label={t("dashboard.harnessReviewQueue")} detail={t("dashboard.pendingCount", { count: dashboard.totals.harnesses_needing_review })} />
      </div>
    </section>
  );
}

/** Badge i18n key per DefectDojo lifecycle state; the badge tone is driven separately by whether the state is `ready`. */
const DD_BADGE: Record<DefectDojoStatus["state"], string> = {
  ready: "dashboard.ready",
  starting: "dashboard.ddStarting",
  stopped: "dashboard.ddStopped",
  docker_down: "dashboard.missing",
  not_installed: "dashboard.ddNotInstalled",
  not_configured: "dashboard.ddNotConfigured",
  remote: "dashboard.ddUnreachable",
};

/**
 * DefectDojo's row in Production Readiness. Unlike the engine flags it is a
 * server with a lifecycle, so it gets its own row: what state it is in, why,
 * and -- when it is an instance we manage -- a way to start it from here.
 */
function DefectDojoHealth() {
  const { toast } = useToast();
  const { t } = useI18n();
  const [dd, setDd] = useState<DefectDojoStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(
    () =>
      getTransport()
        .invoke<DefectDojoStatus>("defectdojo_status")
        .then(setDd)
        .catch(() => setDd(null)),
    [],
  );

  useEffect(() => {
    void refresh();
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<DefectDojoStatus>("defectdojo:status", (e) => setDd(e.payload))
      .then((u) => {
        unlisten = u;
      })
      .catch(() => {});
    return () => unlisten?.();
  }, [refresh]);

  // Keep the row honest while the server boots (it takes ~a minute).
  useEffect(() => {
    if (dd?.state !== "starting") return undefined;
    const id = setInterval(() => void refresh(), 3000);
    return () => clearInterval(id);
  }, [dd?.state, refresh]);

  async function start() {
    setBusy(true);
    try {
      setDd(await getTransport().invoke<DefectDojoStatus>("defectdojo_start"));
    } catch (e) {
      toast({ title: t("dashboard.couldNotStartDD"), description: String(e), variant: "error" });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      setDd(await getTransport().invoke<DefectDojoStatus>("defectdojo_stop"));
    } catch (e) {
      toast({ title: t("dashboard.couldNotStopDD"), description: String(e), variant: "error" });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  const state = dd?.state;
  const ready = state === "ready";
  const starting = busy || state === "starting";
  return (
    <div className="rounded-md border border-border flex items-center gap-3" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
      <div className="flex flex-col min-w-0 flex-1">
        <span className="text-sm">DefectDojo</span>
        <span className="block text-xs text-text-muted truncate">
          {dd?.message ?? t("dashboard.checkingDD")}
        </span>
      </div>
      {dd?.managed && !ready && (
        <Button variant="outline" size="sm" onClick={() => void start()} disabled={starting}>
          {starting ? <RotateCw size={13} className="animate-spin" /> : <Play size={13} />}
          {starting ? t("dashboard.starting") : t("common.start")}
        </Button>
      )}
      {dd?.managed && (ready || state === "starting") && (
        <Button variant="outline" size="sm" onClick={() => void stop()} disabled={busy} title={t("dashboard.stopDDStack")}>
          <Square size={13} /> {t("common.stop")}
        </Button>
      )}
      <StatusBadge
        value={t(state ? DD_BADGE[state] : "dashboard.missing")}
        tone={ready ? "ok" : "warn"}
      />
    </div>
  );
}

function ReadinessItem({ ready, label, detail }: { ready: boolean; label: string; detail: string }) {
  return (
    <div className="rounded-md border border-border flex items-center gap-3" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
      <span style={{ color: ready ? "var(--success)" : "var(--text-muted)" }}>
        <CheckCircle2 size={16} />
      </span>
      <span>
        <span className="block text-sm">{label}</span>
        <span className="block text-xs text-text-muted">{detail}</span>
      </span>
    </div>
  );
}

function MetricGrid({ dashboard }: { dashboard: WorkbenchDashboard }) {
  const { t } = useI18n();
  const totals = dashboard.totals;
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 150px), 1fr))" }}>
      <Metric icon={<Crosshair size={16} />} label={t("dashboard.metricTargets")} value={totals.targets} />
      <Metric icon={<FileCode size={16} />} label={t("dashboard.metricHarnesses")} value={totals.harnesses} accent={totals.harnesses_needing_review > 0} detail={t("dashboard.reviewCount", { count: totals.harnesses_needing_review })} />
      <Metric icon={<Play size={16} />} label={t("dashboard.metricRuns")} value={totals.runs} detail={t("dashboard.activeCount", { count: totals.active_runs })} />
      <Metric icon={<Bug size={16} />} label={t("dashboard.metricCrashes")} value={totals.crashes} accent={totals.crashes_needing_triage > 0} detail={totals.crashes_needing_triage > 0 ? t("dashboard.crashesToTriage", { n: totals.crashes_needing_triage }) : undefined} />
      <Metric icon={<Activity size={16} />} label={t("dashboard.metricCorpus")} value={totals.corpus_entries} />
    </div>
  );
}

function Metric({ icon, label, value, detail, accent }: { icon: React.ReactNode; label: string; value: number; detail?: string; accent?: boolean }) {
  return (
    <div className="surface-card flex items-center gap-3" style={{ padding: "var(--space-md)" }}>
      <span className="flex items-center justify-center rounded-md" style={{ width: 32, height: 32, background: accent ? "var(--error-subtle)" : "var(--accent-subtle)", color: accent ? "var(--error)" : "var(--accent)" }}>
        {icon}
      </span>
      <span className="min-w-0">
        <span className="block text-xs text-text-muted">{label}</span>
        <span className="text-lg font-semibold text-text-primary">{value}</span>
        {detail && <span className="text-xs text-text-muted ml-2">{detail}</span>}
      </span>
    </div>
  );
}

function NextActions({ actions, items, onReport }: { actions: string[]; items: ReadinessNote[]; onReport: () => void }) {
  const { t } = useI18n();
  // Localize from the parallel notes when present; English falls back to the
  // backend prose line-for-line (correct singular/plural preserved).
  const lines = items.length
    ? items.map((item, i) => loc(t, `readiness.action.${item.code}`, actions[i] ?? item.code, { n: item.count }))
    : actions;
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between gap-3">
        <SectionHeader icon={<CheckCircle2 size={15} />} title={t("dashboard.attention")} />
        <Button variant="outline" size="sm" onClick={onReport}>
          <FileText size={13} />
          {t("dashboard.draftReport")}
        </Button>
      </div>
      <div className="flex flex-col gap-2 mt-3">
        {lines.map((action) => (
          <div key={action} className="flex items-start gap-2 text-sm text-text-secondary">
            <span className="mt-1 rounded-full" style={{ width: 6, height: 6, background: "var(--accent)", flexShrink: 0 }} />
            <span>{action}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function HarnessQueue({ items, onOpen }: { items: HarnessReviewItem[]; onOpen?: () => void }) {
  const { t } = useI18n();
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<FileCode size={15} />} title={t("dashboard.harnessReview")} count={items.length} action={<ViewAllLink onClick={onOpen} />} />
      {items.length === 0 ? (
        <EmptyState icon={<FileCode size={18} />} hint={t("dashboard.noHarnessesWaiting")} />
      ) : (
        <div className="flex flex-col gap-2 mt-3">
          {items.slice(0, 5).map((item) => (
            <HarnessRow key={item.harness_id} item={item} />
          ))}
        </div>
      )}
    </section>
  );
}

function HarnessRow({ item }: { item: HarnessReviewItem }) {
  return (
    <div className="rounded-md border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium truncate">{item.target_symbol}</div>
          <div className="text-xs text-text-muted truncate">{item.engine} / {item.status}</div>
        </div>
        <StatusBadge value={item.next_action} />
      </div>
    </div>
  );
}

function RecentRuns({ runs, onOpen }: { runs: WorkbenchRun[]; onOpen?: () => void }) {
  const { t } = useI18n();
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Play size={15} />} title={t("dashboard.recentRuns")} count={runs.length} action={<ViewAllLink onClick={onOpen} />} />
      {runs.length === 0 ? (
        <EmptyState icon={<Play size={18} />} hint={t("dashboard.noPersistedRuns")} />
      ) : (
        <div className="flex flex-col gap-1 mt-3">
          {runs.map((run) => (
            <div key={run.id} className="grid items-center gap-2 text-xs" style={{ gridTemplateColumns: "1fr auto auto" }}>
              <span className="truncate text-text-secondary">{run.engine}</span>
              <span className="text-text-muted">{run.status}</span>
              <span style={{ color: run.crash_count > 0 ? "var(--error)" : "var(--text-muted)" }}>{t("dashboard.crashesCount", { count: run.crash_count })}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function TopTargets({ targets, onOpen }: { targets: WorkbenchTarget[]; onOpen?: () => void }) {
  const { t } = useI18n();
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Crosshair size={15} />} title={t("dashboard.topTargets")} count={targets.length} action={<ViewAllLink onClick={onOpen} />} />
      {targets.length === 0 ? (
        <EmptyState icon={<Crosshair size={18} />} hint={t("dashboard.noRankedTargets")} />
      ) : (
        <div className="flex flex-col gap-2 mt-3">
          {targets.slice(0, 6).map((target) => (
            <div key={target.id} className="rounded-md border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium truncate">{target.symbol}</span>
                <span className="text-xs text-text-muted">{Math.round(target.fit_score * 100)}%</span>
              </div>
              <p className="text-xs text-text-secondary mt-1" style={{ maxHeight: 38, overflow: "hidden" }}>
                {target.rationale || target.language}
              </p>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function CrashQueue({ items, onExport, onOpen }: { items: CrashReviewItem[]; onExport: (crash: CrashReviewItem) => void; onOpen?: () => void }) {
  const { t } = useI18n();
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Bug size={15} />} title={t("dashboard.crashHandoff")} count={items.length} action={<ViewAllLink onClick={onOpen} />} />
      {items.length === 0 ? (
        <EmptyState icon={<Bug size={18} />} hint={t("dashboard.noCrashesForIssueExport")} />
      ) : (
        <div className="flex flex-col gap-2 mt-3">
          {items.slice(0, 5).map((crash) => (
            <CrashCard key={crash.crash_id} crash={crash} onExport={() => onExport(crash)} />
          ))}
        </div>
      )}
    </section>
  );
}

function SectionHeader({
  icon,
  title,
  count,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  count?: number;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-2">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <span style={{ color: "var(--accent)", display: "flex" }}>{icon}</span>
        <span>{title}</span>
        {count !== undefined && <span className="text-xs text-text-muted">{count}</span>}
      </div>
      {action}
    </div>
  );
}

/** A subtle "View all ->" deep-link to a section's canonical standalone view. */
function ViewAllLink({ onClick }: { onClick?: () => void }) {
  const { t } = useI18n();
  if (!onClick) return null;
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-0.5 text-xs transition-colors"
      style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}
      onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
      onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
    >
      {t("common.viewAll")}
      <ChevronRight size={12} />
    </button>
  );
}


function StatusBadge({ value, tone }: { value: string; tone?: "ok" | "warn" }) {
  const lower = value.toLowerCase();
  const ok = tone === "ok" || lower.includes("ready") || lower.includes("approved") || lower.includes("passed") || lower.includes("filed");
  const warn = tone === "warn" || lower.includes("needs") || lower.includes("missing") || lower.includes("draft") || lower.includes("pending");
  return (
    <span
      className="text-xs px-2 py-0.5 rounded-sm"
      style={{
        background: ok ? "rgba(34,197,94,0.12)" : warn ? "rgba(217,119,6,0.12)" : "var(--surface-active)",
        color: ok ? "var(--success)" : warn ? "#d97706" : "var(--text-secondary)",
        whiteSpace: "nowrap",
      }}
    >
      {value}
    </span>
  );
}

function InlineNotice({ tone, text }: { tone: "ok" | "warn" | "error"; text: string }) {
  const style =
    tone === "error"
      ? { background: "var(--error-subtle)", color: "var(--error)", border: "1px solid var(--error)" }
      : tone === "warn"
        ? { background: "rgba(217,119,6,0.12)", color: "#d97706", border: "1px solid rgba(217,119,6,0.35)" }
        : { background: "rgba(34,197,94,0.12)", color: "var(--success)", border: "1px solid rgba(34,197,94,0.35)" };
  return (
    <div className="flex items-start gap-2 text-xs rounded-md" style={{ padding: "var(--space-sm)", ...style }}>
      <AlertTriangle size={14} />
      <span>{text}</span>
    </div>
  );
}

function editorFromReport(report: ReportDraft): ReportEditorState {
  return {
    id: report.id,
    title: report.title,
    project: report.project,
    target: report.target ?? "",
    status: report.status,
    content: report.content,
  };
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function shortId(id: string): string {
  return id.slice(0, 8);
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

async function copyText(value: string) {
  await navigator.clipboard?.writeText(value);
}
