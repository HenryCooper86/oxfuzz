# Routes and Views

The desktop application does not use URL routing. `AppInner` keeps an `activeView: ViewType` state and conditionally mounts one view at a time. The normal shell is `Sidebar + Header + main view + optional observation/progress rails + StatusBar`. Settings replaces that shell; DefectDojo keeps the header/status chrome but hides the sidebar and side panels.

| Internal route | View component | Source | Layout |
|---|---|---|---|
| `dashboard` | `DashboardView` | `crates/hf-gui/src/views/DashboardView.tsx` | Normal app shell |
| `chat` | `ChatView` | `crates/hf-gui/src/views/ChatView.tsx` | Normal app shell |
| `workflow` | `WorkflowView` | `crates/hf-gui/src/views/WorkflowView.tsx` | Normal app shell |
| `discover` | `DiscoverView` | `crates/hf-gui/src/views/DiscoverView.tsx` | Normal app shell |
| `harness` | `HarnessView` | `crates/hf-gui/src/views/HarnessView.tsx` | Normal app shell |
| `run` | `RunView` | `crates/hf-gui/src/views/RunView.tsx` | Normal app shell |
| `triage` | `TriageView` | `crates/hf-gui/src/views/TriageView.tsx` | Normal app shell |
| `corpus` | `CorpusView` | `crates/hf-gui/src/views/CorpusView.tsx` | Normal app shell |
| `projects` | `ProjectsView` | `crates/hf-gui/src/views/ProjectsView.tsx` | Normal app shell |
| `artifacts` | `ArtifactsView` | `crates/hf-gui/src/views/ArtifactsView.tsx` | Normal app shell |
| `reports` | `ReportsView` | `crates/hf-gui/src/views/ReportsView.tsx` | Normal app shell |
| `runs` | `RunsView` | `crates/hf-gui/src/views/RunsView.tsx` | Normal app shell |
| `audit` | `AuditView` | `crates/hf-gui/src/views/AuditView.tsx` | Normal app shell |
| `agents` | `AgentsView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `skills` | `SkillsView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `knowledge` | `KnowledgeView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `automation` | `AutomationView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `automotive` | `AutomotiveView` | `crates/hf-gui/src/views/AutomotiveView.tsx` | Normal app shell, lazy-loaded |
| `help` | `HelpView` | `crates/hf-gui/src/views/HelpView.tsx` | Normal app shell, lazy-loaded |
| `settings` | `SettingsView` | `crates/hf-gui/src/components/settings/SettingsView.tsx` | Full-window settings shell |
| `defectdojo` | `DefectDojoView` | `crates/hf-gui/src/views/DefectDojoView.tsx` | App main only; sidebar and side panels hidden |

## Key-page summaries

- Dashboard: campaign readiness, counts, attention queue, targets, harness review, recent runs, and crash handoff.
- Discovery: selects a project and identifies/ranks fuzzable functions.
- Harness: generates, sandbox-compiles, smoke-qualifies, reviews, and approves harness revisions.
- Run: starts an approved fuzz run and exposes live coverage/crash throughput.
- Triage: ingests, classifies, deduplicates, reports, and hands off crash artifacts.
- Automotive: safety-gated protocol analysis, replay, campaign synthesis, and retained evidence.
- Settings: engine availability, sandbox limits, providers, storage, integrations, and protected credentials.

## View type definition

```ts
// Shared types for oxfuzz GUI.

export type ViewType =
  | "dashboard"
  | "workflow"
  | "discover"
  | "harness"
  | "run"
  | "triage"
  | "corpus"
  | "settings"
  | "chat"
  | "projects"
  | "artifacts"
  | "reports"
  | "runs"
  | "audit"
  | "agents"
  | "skills"
  | "knowledge"
  | "automation"
  | "automotive"
  | "defectdojo"
  | "help";

export interface CoverageSample {
  t: number;
  edges: number;
  execs: number;
}

export interface RunHistoryItem {
  id: string;
  project_root: string;
  target: string | null;
  /** Service-owned key for runs with comparable coverage conditions. */
  comparison_key: string | null;
  engine: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  duration_secs: number | null;
  crashes: number;
  edges: number | null;
  execs: number | null;
  harness_rev: string | null;
  binary_rev: string | null;
  evidence_dir: string | null;
}

export interface TargetCandidate {
  id: string;
  project_root: string;
  language: string;
  symbol: string;
  kind: string;
  location: { file: string; line: number; col: number };
  signature: string | null;
  input_surface: string;
  complexity: number;
  fit_score: number;
  sanitizers: string[];
  rationale: string;
  reachable_functions?: string[];
  accumulated_complexity?: number;
}

export interface TargetInventory {
  project_root: string;
  candidates: TargetCandidate[];
  /** Project-only call adjacency (caller -> direct project callees). */
  call_graph?: Record<string, string[]>;
}

export interface CorpusEntry {
  path: string;
  sha256: string;
  size: number;
  source: string;
  coverage_hash: string | null;
}

export type CrashSeverity = "Exploitable" | "ProbablyExploitable" | "NotExploitable" | "Undefined";

/** CASR crash-analysis report attached to a triaged crash. */
export interface CasrReport {
  severity: CrashSeverity;
  severity_short: string;
  crashline: string;
  stack: string[];
  cluster: number | null;
}

export interface Crash {
  id: string;
  run_id: string;
  target_id: string;
  input_path: string;
  stack_signature: string;
  kind: string;
  summary: string;
  minimized: boolean;
  bug_report: { title: string; summary: string; repro_steps: string; stack: string; severity_guess: string } | null;
  casr: CasrReport | null;
}

/** On-demand LLM verdict for a triaged crash (matches hf-service CrashVerdict). */
export interface CrashVerdict {
  reproduces_deterministically: boolean;
  likely_target_bug: boolean;
  confidence: "low" | "medium" | "high";
  reasons: string[];
}

export interface FuzzProgress {
  type: string;
  data: unknown;
}

export interface SystemStatus {
  docker: boolean;
  sandbox_image: boolean;
  libfuzzer: boolean;
  aflplusplus: boolean;
  honggfuzz: boolean;
  clusterfuzzlite: boolean;
  syzkaller: boolean;
  /** The configured DefectDojo is answering (false also when unconfigured). */
  defectdojo: boolean;
}

/** Lifecycle state of the DefectDojo instance the app is pointed at. */
export type DefectDojoState =
  | "not_configured"
  | "remote"
  | "docker_down"
  | "not_installed"
  | "stopped"
  | "starting"
  | "ready";

export interface DefectDojoStatus {
  state: DefectDojoState;
  url: string | null;
  /** Human-readable explanation of `state`, safe to render as-is. */
  message: string;
  /** True when oxfuzz can start/stop this instance itself. */
  managed: boolean;
}

/** Engine identifiers used across the Run view and status bar. */
export type EngineId = "libfuzzer" | "afl++" | "honggfuzz" | "clusterfuzzlite" | "syzkaller";

export interface WorkbenchTotals {
  projects: number;
  targets: number;
  harnesses: number;
  harnesses_needing_review: number;
  runs: number;
  active_runs: number;
  crashes: number;
  /** Crashes with no drafted bug report yet -- what "triage required" keys on. */
  crashes_needing_triage: number;
  corpus_entries: number;
}

export interface WorkbenchRun {
  id: string;
  project_root: string;
  engine: string;
  status: string;
  started_at: string;
  ended_at: string | null;
  crash_count: number;
}

export interface WorkbenchTarget {
  id: string;
  project_root: string;
  symbol: string;
  language: string;
  fit_score: number;
  rationale: string;
}

export interface HarnessReviewItem {
  harness_id: string;
  target_id: string;
  project_root: string;
  target_symbol: string;
  engine: string;
  language: string;
  status: string;
  build_output: string;
  smoke_passed: boolean;
  smoke_execs_per_sec: number;
  needs_review: boolean;
  next_action: string;
  source_preview: string;
}

export interface CrashReviewItem {
  crash_id: string;
  run_id: string;
  target_id: string;
  target_symbol: string;
  kind: string;
  summary: string;
  severity: string;
  minimized: boolean;
  has_bug_report: boolean;
}

/** A localizable readiness/next-action note: a stable code plus a count. */
export interface ReadinessNote {
  code: string;
  count: number;
}

export interface WorkbenchReadiness {
  state: string;
  score: number;
  headline: string;
  detail: string;
  blockers: string[];
  /** Localizable form of `blockers`, parallel to it (same order and length). */
  blocker_items: ReadinessNote[];
}

export interface WorkbenchDashboard {
  active_project: string | null;
  active_target: string | null;
  totals: WorkbenchTotals;
  recent_runs: WorkbenchRun[];
  top_targets: WorkbenchTarget[];
  harness_reviews: HarnessReviewItem[];
  crash_reviews: CrashReviewItem[];
  readiness: WorkbenchReadiness;
  next_actions: string[];
  /** Localizable form of `next_actions`, parallel to it (same order/length). */
  next_action_items: ReadinessNote[];
}

export interface IssueExport {
  crash_id: string;
  title: string;
  description: string;
  labels: string[];
  /** "github" | "gitlab" -- which forge the URLs/API target. */
  provider: string;
  project_web_url: string | null;
  issue_url: string | null;
  /** True when the issue can be filed directly via the API (repo + token). */
  can_file: boolean;
}

/** The issue created by filing via the provider API. */
export interface CreatedIssue {
  url: string;
  number: number | null;
}

export interface ReportDraft {
  id: string;
  title: string;
  project: string;
  target: string | null;
  status: string;
  updated_at: string;
  content: string;
}
```

## State-based router and shell configuration

```tsx
import { lazy, Suspense, useEffect, useState } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { StatusBar } from "./components/StatusBar";
import { RecoveryBanner } from "./components/RecoveryBanner";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConfirmProvider } from "./providers/ConfirmContext";
import { TooltipProvider } from "./components/ui/Tooltip";
import { ToastProvider } from "./components/ui/Toast";
import { useToast } from "./components/ui/toastContext";
import { getTransport } from "./lib";
import { DiagnosticsPanel } from "./components/observation/DiagnosticsPanel";
import { ObservabilityPanel } from "./components/observation/ObservabilityPanel";
import { InfoPanel } from "./components/observation/InfoPanel";
import { SetupWizard } from "./components/wizard/SetupWizard";
import { SettingsView } from "./components/settings/SettingsView";
import { ChatView } from "./views/ChatView";
import { WorkflowView } from "./views/WorkflowView";
import { DashboardView } from "./views/DashboardView";
import { DiscoverView } from "./views/DiscoverView";
import { HarnessView } from "./views/HarnessView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { ProjectsView } from "./views/ProjectsView";
import { ArtifactsView } from "./views/ArtifactsView";
import { ReportsView } from "./views/ReportsView";
import { RunsView } from "./views/RunsView";
import { AuditView } from "./views/AuditView";
import { DefectDojoView } from "./views/DefectDojoView";
import { CommandPalette } from "./components/CommandPalette";
import { AgentsView, SkillsView, KnowledgeView, AutomationView } from "./views/FeatureViews";
import { LoadingState } from "./components/ui/Loading";
import { ProjectProvider } from "./providers/ProjectContext";
import { useProject } from "./providers/project";
import { PipelineProvider } from "./providers/PipelineContext";
import { PrefsProvider } from "./providers/PrefsContext";
import { usePrefs } from "./providers/prefs";
import { I18nProvider } from "./i18n";
import { useI18n } from "./i18nContext";
import { RunStatusProvider } from "./providers/RunStatusContext";
import { RunOutputProvider } from "./providers/RunOutputContext";
import { TargetProvider } from "./providers/TargetContext";
import { ProgressPanel } from "./components/ProgressPanel";
import { isTauriEnvironment, pickFolder } from "./lib";
import { MessageSquare, Crosshair, Play, Bug, Database, Settings, FileCode, FileText, History, Activity, Gauge, Info, FolderOpen, Boxes, ListChecks, Bot, Puzzle, BookOpen, Zap, LayoutDashboard, ScrollText, ShieldCheck, LifeBuoy, CarFront } from "lucide-react";

const AutomotiveView = lazy(() =>
  import("./views/AutomotiveView").then(({ AutomotiveView: View }) => ({ default: View })),
);

const HelpView = lazy(() =>
  import("./views/HelpView").then(({ HelpView: View }) => ({ default: View })),
);

/** Detect the host OS for platform-conditional window chrome. */
function detectPlatform(): "macos" | "windows" | "linux" | "unknown" {
  if (typeof navigator === "undefined") return "unknown";
  const ua = `${navigator.platform} ${navigator.userAgent}`.toLowerCase();
  if (ua.includes("mac")) return "macos";
  if (ua.includes("win")) return "windows";
  if (ua.includes("linux") || ua.includes("x11")) return "linux";
  return "unknown";
}

function AppInner() {
  const { theme, setTheme } = usePrefs();
  const { t } = useI18n();
  const { setActiveProject } = useProject();
  const [activeView, setActiveView] = useState<ViewType>("dashboard");
  const [settingsReturnView, setSettingsReturnView] = useState<ViewType>("dashboard");
  // Bumping this key remounts ChatView, clearing the conversation for a new target.
  const [chatResetKey, setChatResetKey] = useState(0);

  // Settings is a full-window editor. Preserve the originating workspace so
  // closing it never unexpectedly drops an operator into the chat surface.
  const navigate = (view: ViewType) => {
    if (view === "settings") {
      setSettingsReturnView(activeView === "settings" ? settingsReturnView : activeView);
    }
    setActiveView(view);
  };

  // "New fuzzing target": pick a project folder, make it active, and land on
  // Discover. Per-target pipeline/target state is retained, so an existing
  // project keeps its progress; a brand-new one starts fresh. Cancelling is a no-op.
  const startNewTarget = async () => {
    const path = await pickFolder();
    if (!path) return;
    setActiveProject(path);
    setChatResetKey((k) => k + 1);
    setActiveView("discover");
  };

  // Switch the active fuzzing target to an existing project. Its per-target
  // pipeline/run state is retained, so its progress reappears as it was left.
  const selectTarget = (path: string) => {
    setActiveProject(path);
    setActiveView("workflow");
  };
  const [showDiag, setShowDiag] = useState(false);
  const [showObs, setShowObs] = useState(false);
  const [showInfo, setShowInfo] = useState(false);
  const [showProgress, setShowProgress] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [setupDone, setSetupDone] = useState(localStorage.getItem("hf_setup_completed") === "true");
  const platform = detectPlatform();

  // Bootstrap platform-conditional chrome: expose host (tauri/web) and OS on
  // <html> so CSS can reserve the macOS traffic-light area, enable drag
  // regions, and let the native vibrancy material show through. (The custom
  // decorations class itself is owned by PrefsProvider.)
  useEffect(() => {
    document.documentElement.dataset.host = isTauriEnvironment() ? "tauri" : "web";
    document.documentElement.dataset.platform = detectPlatform();
  }, []);

  if (!setupDone) {
    return <SetupWizard onComplete={() => setSetupDone(true)} />;
  }

  // The embedded DefectDojo webview is a full external app; give it the whole
  // content width by hiding the app sidebar and the observation panels while it
  // is active, so DefectDojo's own responsive layout does not collapse into the
  // cramped, overlapping mode. Back out via the DefectDojo toolbar's Back button.
  const defectDojoActive = activeView === "defectdojo";
  const sidebarVisible = sidebarOpen && !defectDojoActive;

  return (
    <TooltipProvider>
      <ToastProvider>
        <CampaignCrashToaster />
        <div className="app-root flex h-full w-full bg-surface-primary text-text-primary">
        {activeView === "settings" ? (
          <SettingsView
            onBack={() => setActiveView(settingsReturnView)}
            onRunWizard={() => {
              localStorage.removeItem("hf_setup_completed");
              setSetupDone(false);
            }}
          />
        ) : (
          <>
          {sidebarVisible && <Sidebar activeView={activeView} onNavigate={navigate} onNewTarget={startNewTarget} onSelectTarget={selectTarget} />}
          <div className="app-main flex flex-1 flex-col min-w-0">
            <Header
              title={t(`title.${activeView}`)}
              icon={viewIcons[activeView]}
              theme={theme}
              onToggleSidebar={() => setSidebarOpen((o) => !o)}
              reserveLeftInset={!sidebarVisible && platform === "macos"}
              onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
              actions={
                <div className="flex items-center gap-1">
                  <HeaderToggle active={showProgress} onClick={() => setShowProgress(!showProgress)} icon={<ListChecks size={16} />} label={t("header.progress")} />
                  <HeaderToggle active={showDiag} onClick={() => setShowDiag(!showDiag)} icon={<Activity size={16} />} label={t("header.diagnostics")} />
                  <HeaderToggle active={showObs} onClick={() => setShowObs(!showObs)} icon={<Gauge size={16} />} label={t("header.observability")} />
                  <HeaderToggle active={showInfo} onClick={() => setShowInfo(!showInfo)} icon={<Info size={16} />} label={t("header.info")} />
                </div>
              }
            />
            <div className="flex flex-1 overflow-hidden">
              <main className="flex-1 min-w-0 overflow-hidden flex flex-col">
                <RecoveryBanner />
                <ErrorBoundary resetKey={activeView}>
                {activeView === "chat" && <ChatView key={chatResetKey} />}
                {activeView === "dashboard" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <DashboardView onNavigate={navigate} />
                  </div>
                )}
                {activeView === "workflow" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <WorkflowView />
                  </div>
                )}
                {activeView === "discover" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <DiscoverView />
                  </div>
                )}
                {activeView === "harness" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <HarnessView />
                  </div>
                )}
                {activeView === "run" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <RunView onNavigate={setActiveView} />
                  </div>
                )}
                {activeView === "triage" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <TriageView />
                  </div>
                )}
                {activeView === "corpus" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <CorpusView />
                  </div>
                )}
                {activeView === "projects" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <ProjectsView onNavigate={setActiveView} />
                  </div>
                )}
                {activeView === "artifacts" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <ArtifactsView />
                  </div>
                )}
                {activeView === "reports" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <ReportsView />
                  </div>
                )}
                {activeView === "runs" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <RunsView />
                  </div>
                )}
                {activeView === "audit" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <AuditView />
                  </div>
                )}
                {activeView === "agents" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <AgentsView />
                  </div>
                )}
                {activeView === "skills" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <SkillsView />
                  </div>
                )}
                {activeView === "knowledge" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <KnowledgeView />
                  </div>
                )}
                {activeView === "automation" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <AutomationView />
                  </div>
                )}
                {activeView === "automotive" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <Suspense fallback={<LoadingState />}>
                      <AutomotiveView />
                    </Suspense>
                  </div>
                )}
                {activeView === "help" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <Suspense fallback={<LoadingState />}>
                      <HelpView />
                    </Suspense>
                  </div>
                )}
                {activeView === "defectdojo" && <DefectDojoView onBack={() => navigate("dashboard")} />}
                </ErrorBoundary>
              </main>

              {/* Observation panels -- hidden while DefectDojo is embedded so it
                  gets the full content width. */}
              {!defectDojoActive && showDiag && <PanelShell title="Diagnostics"><DiagnosticsPanel /></PanelShell>}
              {!defectDojoActive && showObs && <PanelShell title="Observability"><ObservabilityPanel /></PanelShell>}
              {!defectDojoActive && showInfo && <PanelShell title="Info"><InfoPanel /></PanelShell>}

              {/* Progress sidebar (rightmost) */}
              {!defectDojoActive && showProgress && <ProgressPanel />}
            </div>
            <StatusBar />
          </div>
          </>
        )}
        <CommandPalette onNavigate={navigate} />
        </div>
      </ToastProvider>
    </TooltipProvider>
  );
}

interface CampaignCrashNotice {
  target: string;
  crashes: number;
  report_saved: boolean;
  defectdojo_pushed: boolean;
}

/**
 * Toasts when a headless scheduled campaign finds crashes, wherever the user is
 * in the app. Lives inside ToastProvider so it can raise toasts; the backend
 * emits `campaign:crash` after a scheduled run triages a crash.
 */
function CampaignCrashToaster() {
  const { toast } = useToast();
  const { t } = useI18n();
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    getTransport()
      .listen<CampaignCrashNotice>("campaign:crash", (e) => {
        const p = e.payload;
        const extras = [
          p.report_saved ? t("app.reportSaved") : null,
          p.defectdojo_pushed ? t("app.pushedDefectDojo") : null,
        ].filter(Boolean);
        toast({
          title: t("app.crashToastTitle", { n: p.crashes, target: p.target }),
          description: extras.length
            ? t("app.scheduledCampaignExtras", { extras: extras.join(", ") })
            : t("app.scheduledCampaign"),
          variant: "error",
        });
      })
      .then((u) => {
        unlisten = u;
      })
      .catch(() => {});
    return () => unlisten?.();
  }, [toast, t]);
  return null;
}

export default function App() {
  return (
    <I18nProvider>
      <PrefsProvider>
        <ProjectProvider>
          <TargetProvider>
            <PipelineProvider>
              <RunStatusProvider>
                <RunOutputProvider>
                  <ConfirmProvider>
                    <AppInner />
                  </ConfirmProvider>
                </RunOutputProvider>
              </RunStatusProvider>
            </PipelineProvider>
          </TargetProvider>
        </ProjectProvider>
      </PrefsProvider>
    </I18nProvider>
  );
}

function PanelShell({ children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      className="flex-shrink-0 border-l border-border flex flex-col"
      style={{ width: "320px", background: "var(--surface-secondary)", animation: "fadeIn 0.15s ease" }}
    >
      {children}
    </div>
  );
}

function HeaderToggle({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center justify-center rounded-md transition-all duration-150"
      style={{
        width: "32px",
        height: "32px",
        color: active ? "var(--accent)" : "var(--text-muted)",
        background: active ? "var(--accent-subtle)" : "transparent",
        border: "none",
        cursor: "pointer",
      }}
      title={label}
      aria-label={label}
    >
      {icon}
    </button>
  );
}

// Screen titles are translated at render via `t(\`title.${view}\`)` (see i18n.tsx).

const viewIcons: Record<ViewType, React.ReactNode> = {
  dashboard: <LayoutDashboard size={18} />,
  workflow: <ListChecks size={18} />,
  chat: <MessageSquare size={18} />,
  discover: <Crosshair size={18} />,
  harness: <FileCode size={18} />,
  run: <Play size={18} />,
  triage: <Bug size={18} />,
  corpus: <Database size={18} />,
  settings: <Settings size={18} />,
  projects: <FolderOpen size={18} />,
  artifacts: <Boxes size={18} />,
  reports: <FileText size={18} />,
  runs: <History size={18} />,
  audit: <ScrollText size={18} />,
  agents: <Bot size={18} />,
  skills: <Puzzle size={18} />,
  knowledge: <BookOpen size={18} />,
  automation: <Zap size={18} />,
  automotive: <CarFront size={18} />,
  defectdojo: <ShieldCheck size={18} />,
  help: <LifeBuoy size={18} />,
};
```
