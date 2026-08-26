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
import { ViewCanvas } from "./components/ui";
import { getTransport } from "./lib";
import { DiagnosticsPanel } from "./components/observation/DiagnosticsPanel";
import { ObservabilityPanel } from "./components/observation/ObservabilityPanel";
import { InfoPanel } from "./components/observation/InfoPanel";
import { SetupWizard } from "./components/wizard/SetupWizard";
import { SettingsView } from "./components/settings/SettingsView";
import { WorkflowView } from "./views/WorkflowView";
import { DiscoverView } from "./views/DiscoverView";
import { HarnessView } from "./views/HarnessView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { DashboardView } from "./views/DashboardView";
import { CorpusView } from "./views/CorpusView";
import { ProjectsView } from "./views/ProjectsView";
import { ArtifactsView } from "./views/ArtifactsView";
import { ReportsView } from "./views/ReportsView";
import { ChangesView } from "./views/ChangesView";
import { AuditView } from "./views/AuditView";
import { DefectDojoView } from "./views/DefectDojoView";
import { CommandPalette } from "./components/CommandPalette";
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
import { MessageSquare, Crosshair, Play, Bug, Database, Settings, FileCode, FileText, History, Activity, Gauge, Info, FolderOpen, Boxes, ListChecks, Bot, Puzzle, BookOpen, Zap, LayoutDashboard, ScrollText, ShieldCheck, LifeBuoy, CarFront , GitCompare} from "lucide-react";

const AutomotiveView = lazy(() =>
  import("./views/AutomotiveView").then(({ AutomotiveView: View }) => ({ default: View })),
);

const HelpView = lazy(() =>
  import("./views/HelpView").then(({ HelpView: View }) => ({ default: View })),
);

// Chat, Runs, and the four Feature views are reached only by navigation and
// are large enough that Rollup emits a real chunk for each, so they are kept
// out of the entry chunk. Dashboard is deliberately eager: it is the startup
// view, and loading it lazily would show a fallback on every launch.
//
// The other navigation-only views are imported statically on purpose. Splitting
// them was measured and made the entry chunk larger: their own code is small
// once the shared components they use -- which the entry chunk already carries
// -- are excluded, so the lazy wrapper cost more than the split saved.
const ChatView = lazy(() =>
  import("./views/ChatView").then(({ ChatView: View }) => ({ default: View })),
);

const RunsView = lazy(() =>
  import("./views/RunsView").then(({ RunsView: View }) => ({ default: View })),
);

// Agents, Skills, Knowledge, and Automation share one module, so the four
// dynamic imports resolve to a single chunk.
const AgentsView = lazy(() =>
  import("./views/FeatureViews").then(({ AgentsView: View }) => ({ default: View })),
);

const SkillsView = lazy(() =>
  import("./views/FeatureViews").then(({ SkillsView: View }) => ({ default: View })),
);

const KnowledgeView = lazy(() =>
  import("./views/FeatureViews").then(({ KnowledgeView: View }) => ({ default: View })),
);

const AutomationView = lazy(() =>
  import("./views/FeatureViews").then(({ AutomationView: View }) => ({ default: View })),
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
                {activeView === "chat" && (
                  <Suspense fallback={<LoadingState />}>
                    <ChatView key={chatResetKey} />
                  </Suspense>
                )}
                {activeView === "dashboard" && (
                  <ViewCanvas>
                    <DashboardView onNavigate={navigate} />
                  </ViewCanvas>
                )}
                {activeView === "workflow" && (
                  <ViewCanvas>
                    <WorkflowView />
                  </ViewCanvas>
                )}
                {activeView === "discover" && (
                  <ViewCanvas>
                    <DiscoverView />
                  </ViewCanvas>
                )}
                {activeView === "harness" && (
                  <ViewCanvas>
                    <HarnessView />
                  </ViewCanvas>
                )}
                {activeView === "run" && (
                  <ViewCanvas>
                    <RunView onNavigate={setActiveView} />
                  </ViewCanvas>
                )}
                {activeView === "triage" && (
                  <ViewCanvas>
                    <TriageView />
                  </ViewCanvas>
                )}
                {activeView === "corpus" && (
                  <ViewCanvas>
                    <CorpusView />
                  </ViewCanvas>
                )}
                {activeView === "projects" && (
                  <ViewCanvas>
                    <ProjectsView onNavigate={setActiveView} />
                  </ViewCanvas>
                )}
                {activeView === "artifacts" && (
                  <ViewCanvas>
                    <ArtifactsView />
                  </ViewCanvas>
                )}
                {activeView === "reports" && (
                  <ViewCanvas>
                    <ReportsView />
                  </ViewCanvas>
                )}
                {activeView === "runs" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <RunsView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "changes" && (
                  <ViewCanvas>
                    <ChangesView />
                  </ViewCanvas>
                )}
                {activeView === "audit" && (
                  <ViewCanvas>
                    <AuditView />
                  </ViewCanvas>
                )}
                {activeView === "agents" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <AgentsView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "skills" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <SkillsView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "knowledge" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <KnowledgeView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "automation" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <AutomationView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "automotive" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <AutomotiveView />
                    </Suspense>
                  </ViewCanvas>
                )}
                {activeView === "help" && (
                  <ViewCanvas>
                    <Suspense fallback={<LoadingState />}>
                      <HelpView />
                    </Suspense>
                  </ViewCanvas>
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
  changes: <GitCompare size={18} />,
  audit: <ScrollText size={18} />,
  agents: <Bot size={18} />,
  skills: <Puzzle size={18} />,
  knowledge: <BookOpen size={18} />,
  automation: <Zap size={18} />,
  automotive: <CarFront size={18} />,
  defectdojo: <ShieldCheck size={18} />,
  help: <LifeBuoy size={18} />,
};
