import { useState, useEffect } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { StatusBar } from "./components/StatusBar";
import { TooltipProvider } from "./components/ui/Tooltip";
import { ToastProvider } from "./components/ui/Toast";
import { DiagnosticsPanel } from "./components/observation/DiagnosticsPanel";
import { ObservabilityPanel } from "./components/observation/ObservabilityPanel";
import { InfoPanel } from "./components/observation/InfoPanel";
import { SetupWizard } from "./components/wizard/SetupWizard";
import { SettingsView } from "./components/settings/SettingsView";
import { ChatView } from "./views/ChatView";
import { WorkflowView } from "./views/WorkflowView";
import { DiscoverView } from "./views/DiscoverView";
import { HarnessView } from "./views/HarnessView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { ProjectsView } from "./views/ProjectsView";
import { ArtifactsView } from "./views/ArtifactsView";
import { AgentsView, SkillsView, KnowledgeView, AutomationView } from "./views/FeatureViews";
import { ProjectProvider } from "./providers/ProjectContext";
import { PipelineProvider, usePipeline } from "./providers/PipelineContext";
import { PrefsProvider, usePrefs } from "./providers/PrefsContext";
import { RunStatusProvider } from "./providers/RunStatusContext";
import { RunOutputProvider } from "./providers/RunOutputContext";
import { TargetProvider, useTarget } from "./providers/TargetContext";
import { ProgressPanel } from "./components/ProgressPanel";
import { isTauriEnvironment } from "./lib";
import { MessageSquare, Target, Play, Bug, Database, Settings, FileCode, Activity, Gauge, Info, FolderOpen, Boxes, ListChecks, Bot, Puzzle, BookOpen, Zap } from "lucide-react";

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
  const { reset: resetPipeline } = usePipeline();
  const { reset: resetTarget } = useTarget();
  const [activeView, setActiveView] = useState<ViewType>("chat");
  // Bumping this key remounts ChatView, clearing the conversation for a new task.
  const [chatResetKey, setChatResetKey] = useState(0);

  // "New task": clear the chat conversation, reset pipeline progress, and return
  // to the AI Chat welcome screen -- a fresh start, not a jump into Run.
  const startNewTask = () => {
    resetPipeline();
    resetTarget();
    setChatResetKey((k) => k + 1);
    setActiveView("chat");
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
            onBack={() => setActiveView("chat")}
            onRunWizard={() => {
              localStorage.removeItem("hf_setup_completed");
              setSetupDone(false);
            }}
          />
        ) : (
          <>
          {sidebarOpen && <Sidebar activeView={activeView} onNavigate={setActiveView} onNewTask={startNewTask} />}
          <div className="app-main flex flex-1 flex-col min-w-0">
            <Header
              title={viewTitles[activeView]}
              icon={viewIcons[activeView]}
              theme={theme}
              onToggleSidebar={() => setSidebarOpen((o) => !o)}
              reserveLeftInset={!sidebarOpen && platform === "macos"}
              onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
              actions={
                <div className="flex items-center gap-1">
                  <HeaderToggle active={showProgress} onClick={() => setShowProgress(!showProgress)} icon={<ListChecks size={16} />} label="Progress" />
                  <HeaderToggle active={showDiag} onClick={() => setShowDiag(!showDiag)} icon={<Activity size={16} />} label="Diagnostics" />
                  <HeaderToggle active={showObs} onClick={() => setShowObs(!showObs)} icon={<Gauge size={16} />} label="Observability" />
                  <HeaderToggle active={showInfo} onClick={() => setShowInfo(!showInfo)} icon={<Info size={16} />} label="Info" />
                </div>
              }
            />
            <div className="flex flex-1 overflow-hidden">
              <main className="flex-1 overflow-hidden flex flex-col">
                {activeView === "chat" && <ChatView key={chatResetKey} />}
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
                    <RunView />
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
        </div>
      </ToastProvider>
    </TooltipProvider>
  );
}

export default function App() {
  return (
    <PrefsProvider>
      <ProjectProvider>
        <TargetProvider>
          <PipelineProvider>
            <RunStatusProvider>
              <RunOutputProvider>
                <AppInner />
              </RunOutputProvider>
            </RunStatusProvider>
          </PipelineProvider>
        </TargetProvider>
      </ProjectProvider>
    </PrefsProvider>
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
    >
      {icon}
    </button>
  );
}

const viewTitles: Record<ViewType, string> = {
  workflow: "Fuzzing Workflow",
  chat: "AI Assistant",
  discover: "Target Discovery",
  harness: "Harness Generation",
  run: "Fuzz Run",
  triage: "Crash Triage",
  corpus: "Corpus Management",
  settings: "Settings",
  projects: "Projects",
  artifacts: "Artifacts",
  agents: "Agents",
  skills: "Skills",
  knowledge: "Knowledge",
  automation: "Automation",
};

const viewIcons: Record<ViewType, React.ReactNode> = {
  workflow: <ListChecks size={18} />,
  chat: <MessageSquare size={18} />,
  discover: <Target size={18} />,
  harness: <FileCode size={18} />,
  run: <Play size={18} />,
  triage: <Bug size={18} />,
  corpus: <Database size={18} />,
  settings: <Settings size={18} />,
  projects: <FolderOpen size={18} />,
  artifacts: <Boxes size={18} />,
  agents: <Bot size={18} />,
  skills: <Puzzle size={18} />,
  knowledge: <BookOpen size={18} />,
  automation: <Zap size={18} />,
};