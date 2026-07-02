import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Bug, CheckCircle2, Clipboard, ExternalLink, FileCode, GitPullRequest, Play, RefreshCw, Target } from "lucide-react";
import { Button, EmptyState, LoadingState, Textarea, ViewHeader } from "../components/ui";
import { getTransport } from "../lib";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import type { CrashReviewItem, GitLabIssueExport, HarnessReviewItem, WorkbenchDashboard, WorkbenchRun, WorkbenchTarget } from "../types";

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

function emptyDashboard(project: string | null, target: string | null): WorkbenchDashboard {
  return {
    active_project: project,
    active_target: target,
    totals: EMPTY_TOTALS,
    recent_runs: [],
    top_targets: [],
    harness_reviews: [],
    crash_reviews: [],
    next_actions: ["Run target discovery on an internal project."],
  };
}

export function DashboardView() {
  const { activeProject } = useProject();
  const { target } = useTarget();
  const [dashboard, setDashboard] = useState<WorkbenchDashboard>(() => emptyDashboard(activeProject, target));
  const [loading, setLoading] = useState(true);
  const [issue, setIssue] = useState<GitLabIssueExport | null>(null);
  const [issueError, setIssueError] = useState<string | null>(null);

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
    } catch {
      return emptyDashboard(activeProject, target);
    }
  }, [activeProject, args, target]);

  const reload = useCallback(async () => {
    setLoading(true);
    setDashboard(await loadDashboard());
    setLoading(false);
  }, [loadDashboard]);

  useEffect(() => {
    let cancelled = false;
    async function loadInitialDashboard() {
      const data = await loadDashboard();
      if (!cancelled) {
        setDashboard(data);
        setLoading(false);
      }
    }
    void loadInitialDashboard();
    return () => {
      cancelled = true;
    };
  }, [loadDashboard]);

  async function exportCrash(crash: CrashReviewItem) {
    setIssueError(null);
    setIssue(null);
    if (!activeProject) {
      setIssueError("Select the project that produced this crash before exporting.");
      return;
    }
    try {
      const draft = await getTransport().invoke<GitLabIssueExport>("gitlab_issue_export", {
        project: activeProject,
        crash_id: crash.crash_id,
      });
      setIssue(draft);
    } catch (e) {
      setIssueError(`Export failed: ${e}`);
    }
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0" style={{ overflowWrap: "anywhere" }}>
          <ViewHeader
            title="Dashboard"
            description={activeProject ? `${activeProject}${target ? ` / ${target}` : ""}` : "No active project selected"}
          />
        </div>
        <Button variant="outline" size="sm" onClick={() => void reload()} disabled={loading}>
          <RefreshCw size={14} />
          Refresh
        </Button>
      </div>

      {loading ? (
        <LoadingState label="Loading workbench state..." />
      ) : (
        <>
          <MetricGrid dashboard={dashboard} />

          <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 360px), 1fr))" }}>
            <section className="flex flex-col gap-4 min-w-0">
              <NextActions actions={dashboard.next_actions} />
              <HarnessQueue items={dashboard.harness_reviews} />
              <RecentRuns runs={dashboard.recent_runs} />
            </section>

            <section className="flex flex-col gap-4 min-w-0">
              <TopTargets targets={dashboard.top_targets} />
              <CrashQueue items={dashboard.crash_reviews} onExport={(crash) => void exportCrash(crash)} />
              {issueError && <InlineNotice tone="error" text={issueError} />}
              {issue && <GitLabDraft draft={issue} />}
            </section>
          </div>
        </>
      )}
    </div>
  );
}

function MetricGrid({ dashboard }: { dashboard: WorkbenchDashboard }) {
  const t = dashboard.totals;
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
      <Metric icon={<Target size={16} />} label="Targets" value={t.targets} />
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

function NextActions({ actions }: { actions: string[] }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<CheckCircle2 size={15} />} title="Attention" />
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

function HarnessQueue({ items }: { items: HarnessReviewItem[] }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<FileCode size={15} />} title="Harness Review" count={items.length} />
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
        <span className="text-xs px-2 py-0.5 rounded-sm" style={{ background: item.needs_review ? "var(--accent-subtle)" : "var(--surface-active)", color: item.needs_review ? "var(--accent)" : "var(--text-secondary)" }}>
          {item.next_action}
        </span>
      </div>
      <code className="block text-xs font-mono mt-2 p-2 rounded-md whitespace-pre-wrap" style={{ maxHeight: 96, overflow: "hidden", background: "var(--surface-code)", color: "var(--text-secondary)" }}>
        {item.source_preview || item.build_output}
      </code>
    </div>
  );
}

function RecentRuns({ runs }: { runs: WorkbenchRun[] }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Play size={15} />} title="Recent Runs" count={runs.length} />
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

function TopTargets({ targets }: { targets: WorkbenchTarget[] }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Target size={15} />} title="Top Targets" count={targets.length} />
      {targets.length === 0 ? (
        <EmptyState icon={<Target size={18} />} hint="No ranked targets persisted yet." />
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

function CrashQueue({ items, onExport }: { items: CrashReviewItem[]; onExport: (crash: CrashReviewItem) => void }) {
  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<Bug size={15} />} title="Crash Handoff" count={items.length} />
      {items.length === 0 ? (
        <EmptyState icon={<Bug size={18} />} hint="No crashes are waiting for issue export." />
      ) : (
        <div className="flex flex-col gap-2 mt-3">
          {items.slice(0, 5).map((crash) => (
            <div key={crash.crash_id} className="rounded-md border border-border" style={{ padding: "var(--space-sm)", background: "var(--surface-secondary)" }}>
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{crash.target_symbol}</div>
                  <div className="text-xs text-text-muted truncate">{crash.kind} / {crash.severity}</div>
                </div>
                <Button variant="outline" size="sm" onClick={() => onExport(crash)}>
                  <GitPullRequest size={13} />
                  Export
                </Button>
              </div>
              {crash.summary && (
                <p className="text-xs text-text-secondary mt-2" style={{ maxHeight: 38, overflow: "hidden" }}>
                  {crash.summary}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function GitLabDraft({ draft }: { draft: GitLabIssueExport }) {
  const [copied, setCopied] = useState(false);
  async function copyBody() {
    await navigator.clipboard?.writeText(`${draft.title}\n\n${draft.description}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="surface-card" style={{ padding: "var(--space-md)" }}>
      <SectionHeader icon={<GitPullRequest size={15} />} title="GitLab Issue Draft" />
      <div className="mt-3 flex flex-col gap-2">
        <div className="text-sm font-medium">{draft.title}</div>
        <div className="flex flex-wrap gap-1">
          {draft.labels.map((label) => (
            <span key={label} className="text-xs px-2 py-0.5 rounded-sm" style={{ background: "var(--surface-active)", color: "var(--text-secondary)" }}>{label}</span>
          ))}
        </div>
        <Textarea value={draft.description} readOnly rows={8} />
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

function SectionHeader({ icon, title, count }: { icon: React.ReactNode; title: string; count?: number }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <span style={{ color: "var(--accent)", display: "flex" }}>{icon}</span>
        <span>{title}</span>
      </div>
      {count !== undefined && <span className="text-xs text-text-muted">{count}</span>}
    </div>
  );
}

function InlineNotice({ tone, text }: { tone: "warn" | "error"; text: string }) {
  return (
    <div className="flex items-start gap-2 text-xs rounded-md" style={{ padding: "var(--space-sm)", background: tone === "error" ? "var(--error-subtle)" : "rgba(217,119,6,0.12)", color: tone === "error" ? "var(--error)" : "#d97706", border: `1px solid ${tone === "error" ? "var(--error)" : "rgba(217,119,6,0.35)"}` }}>
      <AlertTriangle size={14} />
      <span>{text}</span>
    </div>
  );
}
