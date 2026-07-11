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
  Crosshair,
  Trash2,
  Users,
  Wrench,
} from "lucide-react";
import { AutoRevertBadge, type AutoRevertPolicyView } from "../components/AutoRevertBadge";
import { Button, EmptyState, Input, LoadingState, Select, Textarea, ViewHeader } from "../components/ui";
import { useToast } from "../components/ui/Toast";
import { useConfirm } from "../providers/ConfirmContext";
import { getTransport, onDataChanged } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import type {
  CrashReviewItem,
  GitLabIssueExport,
  HarnessReviewItem,
  ReportDraft,
  SystemStatus,
  WorkbenchDashboard,
  WorkbenchReadiness,
  WorkbenchRun,
  WorkbenchTarget,
  ViewType,
} from "../types";

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
    },
    next_actions: ["Run target discovery on an internal project."],
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
  const [tab, setTab] = useState<WorkbenchTab>("overview");
  const [dashboard, setDashboard] = useState<WorkbenchDashboard>(() => emptyDashboard(activeProject, target));
  const [reports, setReports] = useState<ReportDraft[]>([]);
  const [editor, setEditor] = useState<ReportEditorState>(() => emptyEditor(activeProject, target));
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issue, setIssue] = useState<GitLabIssueExport | null>(null);
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
      toast({ title: "Failed to load workbench", description: String(e), variant: "error" });
      return emptyDashboard(activeProject, target);
    }
  }, [activeProject, args, target, toast]);

  const reloadReports = useCallback(async () => {
    try {
      const next = await getTransport().invoke<ReportDraft[]>("list_report_drafts");
      setReports(next);
      return next;
    } catch (e) {
      setReports([]);
      toast({ title: "Failed to load reports", description: String(e), variant: "error" });
      return [];
    }
  }, [toast]);

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
      setError("Select an active project and target before generating a report.");
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
      setNotice("Generated a report draft from the latest campaign data.");
    } catch (e) {
      setError(`Report generation failed: ${e}`);
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
      setNotice("Report draft saved.");
    } catch (e) {
      setError(`Save failed: ${e}`);
    }
  }

  async function deleteDraft(report: ReportDraft) {
    if (!(await confirm({ title: "Delete report", message: `Delete "${report.title}"?`, danger: true, confirmLabel: "Delete" }))) return;
    setNotice(null);
    setError(null);
    try {
      await getTransport().invoke("delete_report_draft", { id: report.id });
      const next = await reloadReports();
      setEditor(next[0] ? editorFromReport(next[0]) : emptyEditor(activeProject, target));
      setNotice("Report draft deleted.");
    } catch (e) {
      setError(`Delete failed: ${e}`);
    }
  }

  async function exportCrash(crash: CrashReviewItem) {
    setError(null);
    setNotice(null);
    if (!activeProject) {
      setError("Select the project that produced this crash before exporting.");
      setTab("gitlab");
      return;
    }
    try {
      const draft = await getTransport().invoke<GitLabIssueExport>("gitlab_issue_export", {
        project: activeProject,
        crashId: crash.crash_id,
      });
      setIssue(draft);
      setTab("gitlab");
    } catch (e) {
      setError(`GitLab export failed: ${e}`);
      setTab("gitlab");
    }
  }

  const tabs = workbenchTabs(dashboard);

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0" style={{ overflowWrap: "anywhere" }}>
          <ViewHeader
            title="Dashboard"
            description={activeProject ? `${activeProject}${target ? ` / ${target}` : ""}` : "No active project selected"}
          />
        </div>
        <div className="flex items-center gap-2">
          {activeProject && autoRevert && (
            <AutoRevertBadge policy={autoRevert} overridden={autoRevert.overridden} showScope />
          )}
          <Button variant="outline" size="sm" onClick={() => void generateActiveReport()} disabled={!activeProject || !target}>
            <FileText size={14} />
            Draft report
          </Button>
          <Button variant="outline" size="sm" onClick={() => void reload()} disabled={loading}>
            <RotateCw size={14} />
            Refresh
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
            <h2 className="text-sm font-semibold text-text-primary">Choose a project to begin</h2>
            <p className="mt-1 text-sm text-text-secondary">
              The dashboard is scoped to one project at a time. Use <strong className="text-text-primary">Open project</strong> in the sidebar to open a codebase and start discovery.
            </p>
          </div>
        </section>
      )}

      <div
        className="flex flex-wrap gap-1 border-b border-border"
        role="tablist"
        aria-label="Workbench sections"
        onKeyDown={(e) => {
          const ids = tabs.map((t) => t.id);
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
        <LoadingState label="Loading workbench state..." />
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

function workbenchTabs(dashboard: WorkbenchDashboard): { id: WorkbenchTab; label: string; icon: React.ReactNode; count?: number }[] {
  return [
    { id: "overview", label: "Overview", icon: <Activity size={14} /> },
    { id: "reports", label: "Reports", icon: <FileText size={14} /> },
    { id: "repro", label: "Repro", icon: <Play size={14} /> },
    { id: "team", label: "Review", icon: <Users size={14} />, count: dashboard.harness_reviews.length + dashboard.crash_reviews.length },
    { id: "gitlab", label: "GitLab", icon: <GitPullRequest size={14} /> },
    { id: "health", label: "Health", icon: <Server size={14} /> },
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
          <NextActions actions={dashboard.next_actions} onReport={onReport} />
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
  const isReady = readiness.state === "ready" || readiness.state === "active";
  const tone = isReady ? "ok" : "warn";
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <SectionHeader icon={<ShieldCheck size={15} />} title="Operational Readiness" />
          <h2 className="mt-2 text-lg font-semibold text-text-primary">{readiness.headline}</h2>
          <p className="mt-1 text-sm text-text-secondary">{readiness.detail}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge value={readiness.state.replace(/_/g, " ")} tone={tone} />
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
      {readiness.blockers.length > 0 ? (
        <div className="flex flex-col gap-1">
          {readiness.blockers.slice(0, 4).map((blocker) => (
            <div key={blocker} className="flex items-start gap-2 text-xs text-text-secondary">
              <AlertTriangle size={13} style={{ color: "var(--warning)", flexShrink: 0, marginTop: 1 }} />
              <span>{blocker}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <CheckCircle2 size={13} style={{ color: "var(--success)" }} />
          <span>No readiness blockers in the selected scope.</span>
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
  const selectedId = editor.id;
  return (
    <div className="flex flex-wrap gap-4 min-w-0">
      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)", minHeight: 520, flex: "1 1 260px", maxWidth: 360, minWidth: 0 }}>
        <SectionHeader icon={<FileText size={15} />} title="Composed Reports" count={reports.length} />
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onBlank}>
            <FileText size={13} />
            New
          </Button>
          <Button variant="primary" size="sm" onClick={onGenerate}>
            <Wrench size={13} />
            Generate
          </Button>
        </div>
        {reports.length === 0 ? (
          <EmptyState icon={<FileText size={18} />} hint="No saved reports yet." />
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
                    {report.target || "project report"} · {formatDate(report.updated_at)}
                  </div>
                </button>
                <div className="flex justify-end mt-2">
                  <Button variant="outline" size="sm" onClick={() => onDelete(report)}>
                    <Trash2 size={13} />
                    Delete
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
            <span className="text-xs text-text-muted">Title</span>
            <Input value={editor.title} onChange={(e) => onEditor({ ...editor, title: e.target.value })} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-text-muted">Status</span>
            <Select
              value={editor.status}
              options={REPORT_STATUSES.map((status) => ({ value: status, label: status }))}
              onChange={(status) => onEditor({ ...editor, status })}
            />
          </label>
        </div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(120px, 240px)" }}>
          <label className="flex flex-col gap-1 min-w-0">
            <span className="text-xs text-text-muted">Project</span>
            <Input value={editor.project} onChange={(e) => onEditor({ ...editor, project: e.target.value })} mono />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-text-muted">Target</span>
            <Input value={editor.target} onChange={(e) => onEditor({ ...editor, target: e.target.value })} mono />
          </label>
        </div>
        <Textarea
          mono
          value={editor.content}
          onChange={(e) => onEditor({ ...editor, content: e.target.value })}
          rows={18}
          placeholder="Generate a report from the active campaign or write Markdown here."
        />
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-text-muted">{editor.content.length.toLocaleString()} characters</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => copyText(editor.content)} disabled={!editor.content}>
              <Copy size={13} />
              Copy
            </Button>
            <Button variant="primary" size="sm" onClick={onSave} disabled={!editor.content.trim() || !editor.title.trim()}>
              <Save size={13} />
              Save draft
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

function CrashCard({ crash, onExport }: { crash: CrashReviewItem; onExport: () => void }) {
  return (
    <div className="rounded-md border border-border" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold truncate">{crash.target_symbol}</div>
          <div className="text-xs text-text-muted mt-1">{crash.kind} · {crash.severity}</div>
        </div>
        <StatusBadge value={crash.has_bug_report ? "Report ready" : "Needs report"} />
      </div>
      <p className="text-xs text-text-secondary mt-3" style={{ minHeight: 34 }}>
        {crash.summary || "No summary available yet."}
      </p>
      <div className="flex flex-wrap items-center justify-between gap-2 mt-3">
        <span className="text-xs text-text-muted font-mono">{shortId(crash.crash_id)}</span>
        <Button variant="outline" size="sm" onClick={onExport}>
          <GitPullRequest size={13} />
          GitLab draft
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
  const firstHarness = harnesses[0];
  return (
    <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Play size={15} />} title="Repro Center" count={crashes.length} />
      {!project && <InlineNotice tone="warn" text="Select a project to build exact regression commands." />}
      {crashes.length === 0 ? (
        <EmptyState icon={<Play size={18} />} hint="No crash reproducers are available yet." />
      ) : (
        <div className="flex flex-col gap-3">
          {crashes.map((crash) => {
            const target = firstHarness?.target_symbol || crash.target_symbol;
            const command = project
              ? `hobot-fuzz regress ${shellQuote(project)} --target ${shellQuote(target)}`
              : "Select a project to build a command.";
            return (
              <div key={crash.crash_id} className="rounded-md border border-border" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium truncate">{crash.target_symbol}</span>
                  <StatusBadge value={crash.minimized ? "minimized" : "raw input"} />
                </div>
                <code className="block text-xs font-mono mt-3 p-2 rounded-md whitespace-pre-wrap" style={{ background: "var(--surface-code)", color: "var(--text-secondary)" }}>
                  {command}
                </code>
                <div className="flex justify-end mt-2">
                  <Button variant="outline" size="sm" onClick={() => copyText(command)} disabled={!project}>
                    <Clipboard size={13} />
                    Copy command
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
  const reportNeedsReview = reports.filter((report) => report.status === "Needs Review");
  const harnessNeedsReview = harnesses.filter((item) => item.needs_review);
  const crashNeedsReport = crashes.filter((item) => !item.has_bug_report);
  return (
    <section className="surface-card flex flex-col gap-3 min-w-0" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Users size={15} />} title="Review Flow" />
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 220px), 1fr))" }}>
        <ReviewLane
          title="Reports needing review"
          count={reportNeedsReview.length}
          items={reportNeedsReview.map((r) => ({ label: r.title, onClick: () => onOpenReport(r) }))}
        />
        <ReviewLane
          title="Harnesses needing approval"
          count={harnessNeedsReview.length}
          items={harnessNeedsReview.map((h) => ({ label: h.target_symbol, onClick: onOpenHarnesses }))}
        />
        <ReviewLane
          title="Crashes needing reports"
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
  return (
    <div className="rounded-md border border-border min-w-0" style={{ padding: "var(--space-md)", background: "var(--surface-secondary)" }}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold truncate">{title}</span>
        <span className="text-xs text-text-muted shrink-0">{count}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-text-muted mt-3">Nothing queued.</p>
      ) : (
        <div className="flex flex-col gap-0.5 mt-3">
          {items.slice(0, 6).map((item, i) => (
            <button
              key={`${item.label}:${i}`}
              onClick={item.onClick}
              title={`Open ${item.label}`}
              className="flex items-center gap-1.5 text-left text-xs text-text-secondary truncate rounded px-1.5 py-1 -mx-1.5 transition-colors hover:bg-surface-hover hover:text-text-primary"
            >
              <ChevronRight size={11} className="shrink-0 text-text-muted" />
              <span className="truncate">{item.label}</span>
            </button>
          ))}
          {items.length > 6 && (
            <span className="text-xs text-text-muted mt-1">+{items.length - 6} more</span>
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
  issue: GitLabIssueExport | null;
  onExport: (crash: CrashReviewItem) => void;
}) {
  return (
    <div className="flex flex-wrap gap-4 min-w-0">
      <section className="surface-card flex flex-col gap-3" style={{ padding: "var(--space-md)", flex: "1 1 300px", maxWidth: 440, minWidth: 0 }}>
        <SectionHeader icon={<GitPullRequest size={15} />} title="GitLab Export" count={crashes.length} />
        {!project && <InlineNotice tone="warn" text="Select a project so hobot_fuzz can resolve the GitLab remote." />}
        {crashes.length === 0 ? (
          <EmptyState icon={<GitPullRequest size={18} />} hint="No crashes are ready for issue export." />
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
        {issue ? <GitLabDraft draft={issue} /> : <EmptyState icon={<GitPullRequest size={18} />} hint="Choose a crash to preview a GitLab issue draft." />}
      </div>
    </div>
  );
}

function GitLabDraft({ draft }: { draft: GitLabIssueExport }) {
  const [copied, setCopied] = useState(false);
  async function copyBody() {
    await copyText(`${draft.title}\n\n${draft.description}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<GitPullRequest size={15} />} title="Issue Draft" />
      <div className="mt-3 flex flex-col gap-2">
        <div className="text-sm font-medium">{draft.title}</div>
        <div className="flex flex-wrap gap-1">
          {draft.labels.map((label) => (
            <span key={label} className="text-xs px-2 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-secondary)" }}>{label}</span>
          ))}
        </div>
        <Textarea value={draft.description} readOnly rows={12} />
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void copyBody()}>
            <Clipboard size={13} />
            {copied ? "Copied" : "Copy"}
          </Button>
          {draft.issue_url && (
            <Button variant="primary" size="sm" onClick={() => window.open(draft.issue_url ?? "", "_blank", "noopener,noreferrer")}>
              <ExternalLink size={13} />
              Open GitLab
            </Button>
          )}
        </div>
        {!draft.issue_url && <InlineNotice tone="warn" text="No GitLab remote or HF_GITLAB_* config was found for the selected project." />}
      </div>
    </section>
  );
}

function HealthPanel({ status, dashboard }: { status: SystemStatus | null; dashboard: WorkbenchDashboard }) {
  const checks = [
    ["Docker", status?.docker],
    ["Sandbox image", status?.sandbox_image],
    ["libFuzzer", status?.libfuzzer],
    ["AFL++", status?.aflplusplus],
    ["honggfuzz", status?.honggfuzz],
    ["ClusterFuzzLite", status?.clusterfuzzlite],
    ["syzkaller", status?.syzkaller],
  ] as const;
  return (
    <section className="surface-card flex flex-col gap-4" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<ShieldCheck size={15} />} title="Production Readiness" />
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 180px), 1fr))" }}>
        {checks.map(([label, ok]) => (
          <div key={label} className="rounded-md border border-border flex items-center justify-between gap-3" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
            <span className="text-sm">{label}</span>
            <StatusBadge value={ok ? "ready" : "missing"} tone={ok ? "ok" : "warn"} />
          </div>
        ))}
      </div>
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 220px), 1fr))" }}>
        <ReadinessItem ready={dashboard.totals.targets > 0} label="Targets discovered" detail={`${dashboard.totals.targets} target(s)`} />
        <ReadinessItem ready={dashboard.totals.harnesses > 0} label="Harness library" detail={`${dashboard.totals.harnesses} harness(es)`} />
        <ReadinessItem ready={dashboard.totals.runs > 0} label="Campaign history" detail={`${dashboard.totals.runs} run(s)`} />
        <ReadinessItem ready={dashboard.totals.harnesses_needing_review === 0} label="Harness review queue" detail={`${dashboard.totals.harnesses_needing_review} pending`} />
      </div>
    </section>
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
  const t = dashboard.totals;
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 150px), 1fr))" }}>
      <Metric icon={<Crosshair size={16} />} label="Targets" value={t.targets} />
      <Metric icon={<FileCode size={16} />} label="Harnesses" value={t.harnesses} accent={t.harnesses_needing_review > 0} detail={`${t.harnesses_needing_review} review`} />
      <Metric icon={<Play size={16} />} label="Runs" value={t.runs} detail={`${t.active_runs} active`} />
      <Metric icon={<Bug size={16} />} label="Crashes" value={t.crashes} accent={t.crashes > 0} />
      <Metric icon={<Activity size={16} />} label="Corpus" value={t.corpus_entries} />
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

function NextActions({ actions, onReport }: { actions: string[]; onReport: () => void }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <div className="flex items-center justify-between gap-3">
        <SectionHeader icon={<CheckCircle2 size={15} />} title="Attention" />
        <Button variant="outline" size="sm" onClick={onReport}>
          <FileText size={13} />
          Draft report
        </Button>
      </div>
      <div className="flex flex-col gap-2 mt-3">
        {actions.map((action) => (
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
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<FileCode size={15} />} title="Harness Review" count={items.length} action={<ViewAllLink onClick={onOpen} />} />
      {items.length === 0 ? (
        <EmptyState icon={<FileCode size={18} />} hint="No generated harnesses are waiting for review." />
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
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Play size={15} />} title="Recent Runs" count={runs.length} action={<ViewAllLink onClick={onOpen} />} />
      {runs.length === 0 ? (
        <EmptyState icon={<Play size={18} />} hint="No persisted runs yet." />
      ) : (
        <div className="flex flex-col gap-1 mt-3">
          {runs.map((run) => (
            <div key={run.id} className="grid items-center gap-2 text-xs" style={{ gridTemplateColumns: "1fr auto auto" }}>
              <span className="truncate text-text-secondary">{run.engine}</span>
              <span className="text-text-muted">{run.status}</span>
              <span style={{ color: run.crash_count > 0 ? "var(--error)" : "var(--text-muted)" }}>{run.crash_count} crashes</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function TopTargets({ targets, onOpen }: { targets: WorkbenchTarget[]; onOpen?: () => void }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Crosshair size={15} />} title="Top Targets" count={targets.length} action={<ViewAllLink onClick={onOpen} />} />
      {targets.length === 0 ? (
        <EmptyState icon={<Crosshair size={18} />} hint="No ranked targets persisted yet." />
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
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Bug size={15} />} title="Crash Handoff" count={items.length} action={<ViewAllLink onClick={onOpen} />} />
      {items.length === 0 ? (
        <EmptyState icon={<Bug size={18} />} hint="No crashes are waiting for issue export." />
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
  if (!onClick) return null;
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-0.5 text-xs transition-colors"
      style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}
      onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
      onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
    >
      View all
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
