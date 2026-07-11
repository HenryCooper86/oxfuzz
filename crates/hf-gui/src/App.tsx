import { useState, useEffect } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { StatusBar } from "./components/StatusBar";
import { RecoveryBanner } from "./components/RecoveryBanner";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConfirmProvider } from "./providers/ConfirmContext";
import { TooltipProvider } from "./components/ui/Tooltip";
import { ToastProvider } from "./components/ui/Toast";
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
import { ProjectProvider, useProject } from "./providers/ProjectContext";
import { PipelineProvider } from "./providers/PipelineContext";
import { PrefsProvider, usePrefs } from "./providers/PrefsContext";
import { I18nProvider, useI18n } from "./i18n";
import { RunStatusProvider } from "./providers/RunStatusContext";
import { RunOutputProvider } from "./providers/RunOutputContext";
import { TargetProvider } from "./providers/TargetContext";
import { ProgressPanel } from "./components/ProgressPanel";
import { isTauriEnvironment, pickFolder } from "./lib";
import { MessageSquare, Crosshair, Play, Bug, Database, Settings, FileCode, FileText, History, Activity, Gauge, Info, FolderOpen, Boxes, ListChecks, Bot, Puzzle, BookOpen, Zap, LayoutDashboard, ScrollText, ShieldCheck } from "lucide-react";

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

  return (
    <TooltipProvider>
      <ToastProvider>
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
          {sidebarOpen && <Sidebar activeView={activeView} onNavigate={navigate} onNewTarget={startNewTarget} onSelectTarget={selectTarget} />}
          <div className="app-main flex flex-1 flex-col min-w-0">
            <Header
              title={t(`title.${activeView}`)}
              icon={viewIcons[activeView]}
              theme={theme}
              onToggleSidebar={() => setSidebarOpen((o) => !o)}
              reserveLeftInset={!sidebarOpen && platform === "macos"}
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
                {activeView === "defectdojo" && <DefectDojoView onBack={() => navigate("dashboard")} />}
                </ErrorBoundary>
              </main>

              {/* Observation panels */}
              {showDiag && <PanelShell title="Diagnostics"><DiagnosticsPanel /></PanelShell>}
              {showObs && <PanelShell title="Observability"><ObservabilityPanel /></PanelShell>}
              {showInfo && <PanelShell title="Info"><InfoPanel /></PanelShell>}

              {/* Progress sidebar (rightmost) */}
              {showProgress && <ProgressPanel />}
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
  defectdojo: <ShieldCheck size={18} />,
};
