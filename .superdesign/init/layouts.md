# Shared Layouts

## Application shell

- File: `crates/hf-gui/src/App.tsx`
- Description: Owns the persistent sidebar, header, main content surface, observation/progress panels, status bar, settings shell, and state-based view routing.

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

## Sidebar

- File: `crates/hf-gui/src/components/Sidebar.tsx`
- Description: Primary application navigation, recent-project switcher, pipeline sections, library sections, and settings/help links.

```tsx
import type { ViewType } from "../types";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { useI18n } from "../i18nContext";
import { useDefectDojo } from "../lib";
import { Bot, BookOpen, Bug, Boxes, CarFront, Crosshair, Database, FileCode, FileText, FolderOpen, History, LayoutDashboard, LifeBuoy, MessageSquare, Play, Plus, Puzzle, ScrollText, Settings, ShieldCheck, Workflow, X, Zap } from "lucide-react";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
  /** Pick a project folder and start a fresh fuzzing target. */
  onNewTarget: () => void;
  /** Make an existing project the active fuzzing target. */
  onSelectTarget: (path: string) => void;
}

// Labels are resolved from i18n at render (`t(`nav.${view}`)`), so an item only
// needs its view id and icon -- no hardcoded label to drift out of sync.
// `children` renders indented sub-items, used to nest the workflow stages under
// the unified entry they belong to.
type NavItem = {
  view: ViewType;
  icon: React.ComponentType<{ size?: number }>;
  children?: NavItem[];
};

// Pipeline: the campaign lifecycle. "Fuzzing Workflow" (WorkflowView) is the
// unified accordion that drives discover -> harness -> run -> triage -> corpus
// as one connected flow and is the landing view when a target is opened, so
// those five stages are its children here -- also reachable as standalone
// deep-dive pages. Dashboard is the cross-target overview and leads the section.
const PIPELINE_ITEMS: NavItem[] = [
  { view: "dashboard", icon: LayoutDashboard },
  {
    view: "workflow",
    icon: Workflow,
    children: [
      { view: "discover", icon: Crosshair },
      { view: "harness", icon: FileCode },
      { view: "run", icon: Play },
      { view: "triage", icon: Bug },
      { view: "corpus", icon: Database },
    ],
  },
];

// Results: the durable records a campaign produces.
const RESULTS_ITEMS: NavItem[] = [
  { view: "projects", icon: FolderOpen },
  { view: "artifacts", icon: Boxes },
  { view: "reports", icon: FileText },
  { view: "runs", icon: History },
  { view: "audit", icon: ScrollText },
];

// AI system: the assistant plus the agents, skills, knowledge, and automation
// that drive it -- previously scattered between Pipeline and Library.
const AI_SYSTEM_ITEMS: NavItem[] = [
  { view: "chat", icon: MessageSquare },
  { view: "agents", icon: Bot },
  { view: "skills", icon: Puzzle },
  { view: "knowledge", icon: BookOpen },
  { view: "automation", icon: Zap },
];

function basename(path: string): string {
  return path.split("/").filter(Boolean).pop() || path;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="text-xs font-semibold uppercase mb-1"
      style={{ color: "var(--text-muted)", letterSpacing: "0.08em", padding: "7px 10px 2px" }}
    >
      {children}
    </div>
  );
}

function NavButton({
  item,
  active,
  onNavigate,
  depth = 0,
}: {
  item: NavItem;
  active: boolean;
  onNavigate: (view: ViewType) => void;
  /** Indent level; >0 marks a sub-item nested under its parent entry. */
  depth?: number;
}) {
  const { view, icon: Icon } = item;
  const { t } = useI18n();
  return (
    <button
      onClick={() => onNavigate(view)}
      className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
        active
          ? "bg-surface-active text-text-primary border border-border"
          : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
      }`}
      style={{
        padding: "7px 10px",
        paddingLeft: 10 + depth * 18,
        fontSize: "13px",
        fontWeight: 500,
        marginBottom: "2px",
      }}
    >
      <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex" }}>
        <Icon size={depth > 0 ? 16 : 18} />
      </span>
      <span>{t(`nav.${view}`)}</span>
    </button>
  );
}

/**
 * Prominent, always-present entry into the Automotive (CAN/UDS) workspace.
 * Unlike the optional Integrations, vehicle protocol fuzzing is a first-class
 * capability, so it gets a permanent, accent-highlighted slot rather than a
 * toggle-gated one -- it stands out with an accent border, a subtle tint, and a
 * CAN/UDS tag even when inactive.
 */
function AutomotiveNavButton({
  active,
  onNavigate,
}: {
  active: boolean;
  onNavigate: (view: ViewType) => void;
}) {
  const { t } = useI18n();
  return (
    <button
      onClick={() => onNavigate("automotive")}
      className="flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none hover:bg-accent-subtle"
      style={{
        padding: "8px 10px",
        fontSize: "13px",
        fontWeight: 600,
        marginBottom: "2px",
        color: "var(--text-primary)",
        border: "1px solid",
        borderColor: active ? "var(--accent)" : "var(--accent-subtle)",
        background: active ? "var(--accent-subtle)" : "transparent",
      }}
    >
      <span style={{ color: "var(--accent)", display: "flex" }}>
        <CarFront size={18} />
      </span>
      <span className="flex-1">{t("nav.automotive")}</span>
      <span
        className="text-11px font-semibold uppercase rounded"
        style={{
          color: "var(--accent)",
          background: "var(--accent-subtle)",
          letterSpacing: "0.05em",
          padding: "1px 5px",
        }}
      >
        {t("sidebar.automotiveTag")}
      </span>
    </button>
  );
}

/** Library row that opens the embedded in-app DefectDojo view. */
function DefectDojoButton({ active, onOpen }: { active: boolean; onOpen: () => void }) {
  return (
    <button
      onClick={onOpen}
      title="Open DefectDojo in the app"
      className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
        active
          ? "bg-surface-active text-text-primary border border-border"
          : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
      }`}
      style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
    >
      <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex" }}>
        <ShieldCheck size={18} />
      </span>
      <span>DefectDojo</span>
    </button>
  );
}

/** Prominent row that opens a folder picker to begin a new fuzzing target. */
function NewTargetButton({ onNewTarget }: { onNewTarget: () => void }) {
  const { t } = useI18n();
  return (
    <button
      onClick={onNewTarget}
      className="flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none bg-transparent border border-transparent text-text-primary hover:bg-accent-subtle"
      style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 600, marginBottom: "2px" }}
    >
      <Plus size={18} style={{ color: "var(--accent)" }} />
      <span>{t("sidebar.newTarget")}</span>
    </button>
  );
}

/** One entry in the TARGETS quick-switcher. */
function TargetRow({
  path,
  active,
  activeTarget,
  onSelect,
  onRemove,
}: {
  path: string;
  active: boolean;
  activeTarget: string;
  onSelect: (path: string) => void;
  onRemove: (path: string) => void;
}) {
  const { t } = useI18n();
  const name = basename(path);
  const label = active && activeTarget ? `${name} / ${activeTarget}` : name;
  return (
    <div className="flex items-center" style={{ marginBottom: "2px" }}>
      <button
        onClick={() => onSelect(path)}
        title={path}
        className={`flex items-center gap-2 flex-1 min-w-0 text-left rounded-md transition-all duration-150 outline-none ${
          active
            ? "bg-surface-active text-text-primary border border-border"
            : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
        }`}
        style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500 }}
      >
        <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex", flexShrink: 0 }}>
          <Crosshair size={16} />
        </span>
        <span className="truncate">{label}</span>
      </button>
      <button
        onClick={() => onRemove(path)}
        className="flex items-center justify-center rounded-md transition-colors duration-150 bg-transparent border-none"
        style={{ width: "26px", height: "26px", color: "var(--text-muted)", cursor: "pointer", flexShrink: 0 }}
        title={t("sidebar.removeTarget")}
        aria-label={t("sidebar.removeTarget")}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <X size={13} />
      </button>
    </div>
  );
}

export function Sidebar({ activeView, onNavigate, onNewTarget, onSelectTarget }: SidebarProps) {
  const { activeProject, recentProjects, removeRecent } = useProject();
  const { target } = useTarget();
  const { t } = useI18n();
  // DefectDojo is surfaced only once configured, so the sidebar stays clean for
  // projects that never use it. Automotive, by contrast, is always present (see
  // AutomotiveNavButton below).
  const { configured: defectDojoOn } = useDefectDojo();

  return (
    <nav
      className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none"
      style={{ width: "var(--sidebar-width, 240px)" }}
    >
      {/* Drag region / macOS traffic-light safe area */}
      <div style={{ height: "28px", flexShrink: 0 }} />

      {/* Working area: new target + the targets you are fuzzing + the pipeline. */}
      <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px 0 8px" }}>
        <NewTargetButton onNewTarget={onNewTarget} />

        <SectionLabel>{t("sidebar.targets")}</SectionLabel>
        {recentProjects.length === 0 ? (
          <div
            className="text-xs text-text-muted"
            style={{ padding: "2px 10px 6px", lineHeight: 1.5 }}
          >
            {t("sidebar.noTargets")}
          </div>
        ) : (
          recentProjects.map((path) => (
            <TargetRow
              key={path}
              path={path}
              active={path === activeProject}
              activeTarget={target}
              onSelect={onSelectTarget}
              onRemove={removeRecent}
            />
          ))
        )}

        <SectionLabel>{t("sidebar.pipeline")}</SectionLabel>
        {PIPELINE_ITEMS.map((item) => (
          <div key={item.view}>
            <NavButton item={item} active={activeView === item.view} onNavigate={onNavigate} />
            {item.children?.map((child) => (
              <NavButton
                key={child.view}
                item={child}
                active={activeView === child.view}
                onNavigate={onNavigate}
                depth={1}
              />
            ))}
          </div>
        ))}

        <SectionLabel>{t("sidebar.results")}</SectionLabel>
        {RESULTS_ITEMS.map((item) => (
          <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />
        ))}

        <SectionLabel>{t("sidebar.aiSystem")}</SectionLabel>
        {AI_SYSTEM_ITEMS.map((item) => (
          <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />
        ))}

        {/* Automotive is a permanent, first-class capability: always present and
            visually prominent, never gated behind a runtime toggle. When the
            subsystem is off or absent from the build, the workspace itself
            explains how to enable it or that it is unavailable. */}
        <SectionLabel>{t("sidebar.vehicle")}</SectionLabel>
        <AutomotiveNavButton active={activeView === "automotive"} onNavigate={onNavigate} />

        {/* DefectDojo stays an optional add-on, shown only once configured, so
            the sidebar stays uncluttered for projects that never use it. */}
        {defectDojoOn && (
          <>
            <SectionLabel>{t("sidebar.integrations")}</SectionLabel>
            <DefectDojoButton active={activeView === "defectdojo"} onOpen={() => onNavigate("defectdojo")} />
          </>
        )}
      </div>

      {/* Footer: help and settings pinned at the bottom (Apple-style nav), then
          version. These meta entries sit apart from the working sections above. */}
      <div className="border-t border-border" style={{ padding: "6px 8px 8px 8px" }}>
        <NavButton
          item={{ view: "help", icon: LifeBuoy }}
          active={activeView === "help"}
          onNavigate={onNavigate}
        />
        <NavButton
          item={{ view: "settings", icon: Settings }}
          active={activeView === "settings"}
          onNavigate={onNavigate}
        />
        <div className="text-text-muted text-center flex flex-col items-center gap-0.5" style={{ padding: "6px 10px 0", fontSize: "11px" }}>
          <span>
            Press <kbd style={{ padding: "0 3px", border: "1px solid var(--border)", borderRadius: 3 }}>⌘K</kbd> to search
          </span>
          <span>oxfuzz v0.1.0</span>
        </div>
      </div>
    </nav>
  );
}
```

## Header

- File: `crates/hf-gui/src/components/Header.tsx`
- Description: Persistent title bar with view identity, sidebar/theme controls, and panel toggles.

```tsx
import { Moon, Sun, PanelLeft } from "lucide-react";
import type { ReactNode } from "react";
import { IconButton } from "./ui/IconButton";

interface HeaderProps {
  title: string;
  icon?: ReactNode;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  actions?: ReactNode;
  onToggleSidebar?: () => void;
  /** Reserve space for the macOS traffic lights when the sidebar is hidden. */
  reserveLeftInset?: boolean;
}

export function Header({ title, icon, theme, onToggleTheme, actions, onToggleSidebar, reserveLeftInset }: HeaderProps) {
  return (
    <header
      data-tauri-drag-region
      className="flex items-center justify-between flex-shrink-0 select-none"
      style={{
        height: "52px",
        paddingTop: 0,
        paddingBottom: 0,
        paddingRight: "var(--space-lg)",
        paddingLeft: reserveLeftInset ? "78px" : "var(--space-lg)",
        background: "var(--surface-primary)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div className="flex items-center gap-2" data-tauri-drag-region>
        {onToggleSidebar && (
          <IconButton size={32} onClick={onToggleSidebar} title="Toggle sidebar" aria-label="Toggle sidebar">
            <PanelLeft size={18} />
          </IconButton>
        )}
        {icon && (
          <span data-tauri-drag-region style={{ color: "var(--accent)" }}>
            {icon}
          </span>
        )}
        <span
          data-tauri-drag-region
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "17px",
            fontWeight: 400,
            fontStyle: "italic",
            letterSpacing: "0.01em",
            opacity: 0.9,
          }}
        >
          {title}
        </span>
      </div>
      <div className="flex items-center gap-1">
        {actions}
        <IconButton size={32} onClick={onToggleTheme} title="Toggle theme" aria-label="Toggle theme">
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </IconButton>
      </div>
    </header>
  );
}
```

## Status bar

- File: `crates/hf-gui/src/components/StatusBar.tsx`
- Description: Persistent bottom health/status strip for sandbox, engines, integrations, and clock.

```tsx
import { useState, useEffect } from "react";
import { getTransport, useDefectDojo } from "../lib";
import { usePrefs } from "../providers/prefs";
import { useRunStatus } from "../providers/runStatus";
import type { SystemStatus } from "../types";
import { Container, Box, ShieldCheck } from "lucide-react";

const EMPTY_STATUS: SystemStatus = {
  docker: false,
  sandbox_image: false,
  libfuzzer: false,
  aflplusplus: false,
  honggfuzz: false,
  clusterfuzzlite: false,
  syzkaller: false,
  defectdojo: false,
};

// Engine display order + how each maps to a SystemStatus flag and the engine id
// the Run view reports while running (so we can highlight the active one).
const ENGINES: { label: string; key: keyof SystemStatus; runId: string }[] = [
  { label: "libFuzzer", key: "libfuzzer", runId: "libfuzzer" },
  { label: "AFL++", key: "aflplusplus", runId: "afl++" },
  { label: "honggfuzz", key: "honggfuzz", runId: "honggfuzz" },
  { label: "ClusterFuzzLite", key: "clusterfuzzlite", runId: "clusterfuzzlite" },
  { label: "syzkaller", key: "syzkaller", runId: "syzkaller" },
];

export function StatusBar() {
  const { sandboxArch } = usePrefs();
  const { activeEngine } = useRunStatus();
  // DefectDojo is an optional integration, so it appears in the bar only once
  // configured -- matching the sidebar entry. Green when the instance answers.
  const { configured: defectDojoOn } = useDefectDojo();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [dockerMsg, setDockerMsg] = useState<string | null>(null);
  const [cost, setCost] = useState<{ cost_usd: number; calls: number; input_tokens: number; output_tokens: number } | null>(null);
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const t = getTransport();
    let unlisten: (() => void) | undefined;

    // Live progress while Docker is brought up / the image is built.
    t.listen<{ message: string }>("docker:status", (e) => setDockerMsg(e.payload.message))
      .then((u) => { unlisten = u; })
      .catch(() => {});

    // Kick off the Docker bootstrap (start daemon + ensure the image is built
    // for the selected arch). Re-runs when the sandbox arch changes, rebuilding
    // the image for the new platform. Falls back to a plain status read.
    t.invoke<SystemStatus>("ensure_docker", { arch: sandboxArch })
      .then(setStatus)
      .catch(() =>
        t.invoke<SystemStatus>("system_status_cmd").then(setStatus).catch(() => setStatus(EMPTY_STATUS)),
      );

    // Keep runtime availability and current-session cost indicators fresh.
    // LLM spend accrues invisibly during agent turns / report+harness gen;
    // surface a running total so cost is never a surprise.
    const refreshCost = () => {
      t.invoke<{ cost_usd: number; calls: number; input_tokens: number; output_tokens: number }>("diagnostics_cost_summary")
        .then(setCost)
        // Do not keep labeling a stale value as this session's spend when the
        // diagnostics store is unavailable. The full panel surfaces the error.
        .catch(() => setCost(null));
    };
    refreshCost();

    const poll = setInterval(() => {
      t.invoke<SystemStatus>("system_status_cmd").then(setStatus).catch(() => {});
      refreshCost();
    }, 5000);

    return () => {
      if (unlisten) unlisten();
      clearInterval(poll);
    };
  }, [sandboxArch]);

  return (
    <footer
      className="flex items-center justify-between flex-shrink-0 select-none"
      style={{
        height: "28px",
        padding: "0 var(--space-lg)",
        background: "var(--surface-secondary)",
        borderTop: "1px solid var(--border)",
        fontSize: "11px",
        color: "var(--text-muted)",
      }}
    >
      <div className="flex items-center gap-3">
        {status && (
          <>
            <StatusDot label="Docker" active={status.docker} icon={<Container size={11} />} />
            <StatusDot label="Sandbox" active={status.sandbox_image} icon={<Box size={11} />} />
            <span style={{ width: "1px", height: "12px", background: "var(--border)" }} />
            {ENGINES.map((e) => (
              <StatusDot
                key={e.runId}
                label={e.label}
                active={Boolean(status[e.key])}
                running={activeEngine === e.runId}
              />
            ))}
            {defectDojoOn && (
              <>
                <span style={{ width: "1px", height: "12px", background: "var(--border)" }} />
                <StatusDot label="DefectDojo" active={status.defectdojo} icon={<ShieldCheck size={11} />} />
              </>
            )}
          </>
        )}
        {dockerMsg && !(status?.docker && status?.sandbox_image) && (
          <span style={{ color: "var(--text-secondary)" }}>{dockerMsg}</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {activeEngine && (
          <span className="flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "var(--accent)",
                animation: "pulse 1.2s ease-in-out infinite",
              }}
            />
            Fuzzing: {ENGINES.find((e) => e.runId === activeEngine)?.label ?? activeEngine}
          </span>
        )}
        {cost && cost.cost_usd > 0 && (
          <span
            title={`LLM spend this session: $${cost.cost_usd.toFixed(4)} · ${cost.calls} calls · ${(cost.input_tokens + cost.output_tokens).toLocaleString()} tokens`}
          >
            ${cost.cost_usd.toFixed(2)}
          </span>
        )}
        <span>{time}</span>
      </div>
    </footer>
  );
}

function StatusDot({
  label,
  active,
  icon,
  running,
}: {
  label: string;
  active: boolean;
  icon?: React.ReactNode;
  running?: boolean;
}) {
  const color = running ? "var(--accent)" : active ? "var(--success)" : "var(--text-muted)";
  const title = running
    ? `${label} (running)`
    : active
      ? label
      : `${label} (unavailable)`;
  return (
    <div
      className="flex items-center gap-1"
      title={title}
    >
      {icon}
      <span style={{ color }}>{label}</span>
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: color,
          opacity: active || running ? 1 : 0.4,
          animation: running ? "pulse 1.2s ease-in-out infinite" : undefined,
        }}
      />
    </div>
  );
}
```

## Progress panel

- File: `crates/hf-gui/src/components/ProgressPanel.tsx`
- Description: Right-side pipeline progress rail.

```tsx
import { useState } from "react";
import { Check, ChevronDown, ChevronRight, Minus, RotateCcw } from "lucide-react";
import { usePipeline } from "../providers/pipeline";
import { useI18n } from "../i18nContext";

export function ProgressPanel() {
  const { coreStages, reset } = usePipeline();
  const { t } = useI18n();
  const [open, setOpen] = useState(true);
  const total = coreStages.length;
  const doneCount = coreStages.filter((c) => c.done).length;
  const pct = Math.round((doneCount / total) * 100);

  return (
    <div
      className="flex-shrink-0 border-l border-border flex flex-col"
      style={{ width: "280px", background: "var(--surface-secondary)", animation: "fadeIn 0.15s ease" }}
    >
      <div style={{ padding: "var(--space-md)" }}>
        <div
          className="rounded-lg flex flex-col"
          style={{ background: "var(--surface-primary)", border: "1px solid var(--border)", overflow: "hidden" }}
        >
          {/* Header */}
          <button
            onClick={() => setOpen((o) => !o)}
            className="flex items-center justify-between w-full transition-colors duration-150"
            style={{
              padding: "10px 12px",
              background: "transparent",
              border: "none",
              cursor: "pointer",
              color: "var(--text-primary)",
            }}
          >
            <span className="flex items-center gap-2">
              <span className="text-sm font-semibold">{t("progress.title")}</span>
              <span className="text-xs text-text-muted">
                {doneCount}/{total}
              </span>
            </span>
            {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
          </button>

          {/* Progress bar */}
          <div style={{ padding: "0 12px 10px" }}>
            <div style={{ height: "4px", borderRadius: "999px", background: "var(--surface-active)", overflow: "hidden" }}>
              <div
                style={{
                  width: `${pct}%`,
                  height: "100%",
                  background: "var(--accent)",
                  transition: "width 0.3s ease",
                }}
              />
            </div>
          </div>

          {/* Steps -- the 4 core stages, matching the Fuzzing Workflow. */}
          {open && (
            <div style={{ padding: "0 6px 8px" }}>
              {coreStages.map((stage, i) => (
                <StepRow
                  key={stage.id}
                  index={i + 1}
                  label={t(`stage.${stage.id}`)}
                  done={stage.done}
                  skipped={stage.skipped}
                  current={stage.current}
                  // Show sub-progress for a multi-step stage that's underway.
                  subProgress={
                    stage.totalSteps > 1 && !stage.done
                      ? `${stage.doneSteps}/${stage.totalSteps}`
                      : undefined
                  }
                />
              ))}
            </div>
          )}
        </div>

        {doneCount > 0 && (
          <button
            onClick={reset}
            className="flex items-center gap-1.5 mt-3 text-xs transition-colors duration-150"
            style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "2px" }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-secondary)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
          >
            <RotateCcw size={12} />
            {t("progress.reset")}
          </button>
        )}
      </div>
    </div>
  );
}

function StepRow({
  index,
  label,
  done,
  skipped,
  current,
  subProgress,
}: {
  index: number;
  label: string;
  done: boolean;
  skipped: boolean;
  current: boolean;
  subProgress?: string;
}) {
  // A skipped stage counts as done but renders as a muted dash, not a check.
  const marker = skipped ? <Minus size={12} /> : done ? <Check size={12} /> : index;
  return (
    <div className="flex items-center gap-2.5" style={{ padding: "6px 8px" }}>
      <span
        className="flex items-center justify-center rounded-full shrink-0"
        style={{
          width: "20px",
          height: "20px",
          fontSize: "11px",
          fontWeight: 600,
          background: skipped ? "var(--surface-active)" : done ? "var(--accent)" : "transparent",
          border: done || skipped ? "none" : `1px solid ${current ? "var(--accent)" : "var(--border)"}`,
          color: skipped
            ? "var(--text-muted)"
            : done
              ? "var(--accent-contrast)"
              : current
                ? "var(--accent)"
                : "var(--text-muted)",
        }}
      >
        {marker}
      </span>
      <span
        className="text-sm"
        style={{
          color: done || skipped ? "var(--text-muted)" : current ? "var(--text-primary)" : "var(--text-muted)",
          fontWeight: current ? 500 : 400,
          textDecoration: done && !skipped ? "line-through" : "none",
        }}
      >
        {label}
        {skipped && <span className="text-xs text-text-muted"> (skipped)</span>}
        {subProgress && !skipped && (
          <span className="text-xs text-text-muted"> · {subProgress}</span>
        )}
      </span>
    </div>
  );
}
```

## Recovery banner

- File: `crates/hf-gui/src/components/RecoveryBanner.tsx`
- Description: Cross-page task recovery notice.

```tsx
// Surfaces fuzz runs that were interrupted by a prior crash/quit (detected on
// startup from the persistent run journal). The campaign's crashes/corpus on
// disk are intact; the user can re-run from the Run view, or dismiss here.

import { useEffect, useState } from "react";
import { AlertTriangle, X } from "lucide-react";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";

interface InterruptedRun {
  run_id: string;
  project: string;
  target: string;
  engine: string;
  started_at: number;
}

const shortPath = (p: string) => p.split("/").filter(Boolean).pop() || p;

export function RecoveryBanner() {
  const { t } = useI18n();
  const [runs, setRuns] = useState<InterruptedRun[]>([]);

  useEffect(() => {
    let cancelled = false;
    getTransport()
      .invoke<InterruptedRun[]>("interrupted_runs")
      .then((r) => !cancelled && setRuns(r))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function dismiss(id: string) {
    try {
      setRuns(await getTransport().invoke<InterruptedRun[]>("dismiss_interrupted_run", { runId: id }));
    } catch {
      /* best-effort */
    }
  }

  if (runs.length === 0) return null;

  return (
    <div
      className="rounded-md"
      style={{ background: "rgba(217,119,6,0.10)", border: "1px solid rgba(217,119,6,0.4)", padding: "var(--space-sm) var(--space-md)", margin: "var(--space-md) var(--space-lg) 0" }}
    >
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle size={14} style={{ color: "#d97706" }} />
        <span className="text-xs font-semibold" style={{ color: "#d97706" }}>
          {runs.length === 1 ? t("recovery.recoveredOne") : t("recovery.recoveredMany", { n: runs.length })}
        </span>
        <span className="text-xs text-text-muted">{t("recovery.detail")}</span>
      </div>
      <div className="flex flex-col gap-1 mt-1">
        {runs.map((r) => (
          <div key={r.run_id} className="flex items-center gap-2 text-xs">
            <span className="font-mono text-text-primary truncate">
              {shortPath(r.project)} / {r.target}
            </span>
            <span className="text-text-muted font-mono">{r.engine}</span>
            <span className="text-text-muted">· {t("recovery.started")} {new Date(r.started_at * 1000).toLocaleString()}</span>
            <button
              onClick={() => dismiss(r.run_id)}
              className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-text-muted hover:text-text-primary hover:bg-surface-hover"
              title={t("recovery.dismiss")}
            >
              <X size={12} />
              {t("recovery.dismiss")}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
```

## Command palette

- File: `crates/hf-gui/src/components/CommandPalette.tsx`
- Description: Global keyboard-driven navigation overlay.

```tsx
import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import type { ViewType } from "../types";
import { useI18n } from "../i18nContext";

// Views reachable from the palette, in a sensible order.
const VIEWS: ViewType[] = [
  "dashboard",
  "chat",
  "workflow",
  "discover",
  "harness",
  "run",
  "triage",
  "corpus",
  "projects",
  "artifacts",
  "reports",
  "runs",
  "audit",
  "agents",
  "skills",
  "knowledge",
  "automation",
  "automotive",
  "defectdojo",
  "help",
  "settings",
];

// A ⌘K / Ctrl-K command palette for fast keyboard-driven navigation, matching
// what professional tools provide. Arrow keys move, Enter navigates, Escape
// closes. Self-contained: installs its own global hotkey.
export function CommandPalette({ onNavigate }: { onNavigate: (view: ViewType) => void }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) return;
    queueMicrotask(() => {
      setQuery("");
      setActive(0);
    });
    // Focus after the element mounts.
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return VIEWS.map((v) => ({ view: v, label: t(`nav.${v}`) })).filter(
      (i) => !q || i.label.toLowerCase().includes(q) || i.view.includes(q),
    );
  }, [query, t]);

  if (!open) return null;

  const choose = (view: ViewType) => {
    onNavigate(view);
    setOpen(false);
  };

  return (
    <div
      className="fixed inset-0 z-9999 flex items-start justify-center"
      style={{ background: "rgba(0,0,0,0.4)", backdropFilter: "blur(2px)", paddingTop: "12vh" }}
      onClick={() => setOpen(false)}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t("palette.ariaLabel")}
        className="surface-card flex flex-col overflow-hidden"
        style={{ width: "min(560px, 92vw)", padding: 0, boxShadow: "var(--shadow-lg)", animation: "dialogContentIn 0.14s ease" }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
          else if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(items.length - 1, a + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === "Enter" && items[active]) {
            e.preventDefault();
            choose(items[active].view);
          }
        }}
      >
        <div className="flex items-center gap-2 border-b border-border" style={{ padding: "10px 14px" }}>
          <Search size={15} className="text-text-muted" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            placeholder={t("palette.placeholder")}
            className="flex-1 bg-transparent outline-none text-sm text-text-primary"
            style={{ border: "none" }}
          />
          <kbd className="text-xs text-text-muted">{t("palette.esc")}</kbd>
        </div>
        <div className="overflow-auto" style={{ maxHeight: "50vh" }}>
          {items.length === 0 ? (
            <div className="text-xs text-text-muted" style={{ padding: "12px 14px" }}>{t("palette.noMatches")}</div>
          ) : (
            items.map((item, i) => (
              <button
                key={item.view}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(item.view)}
                className="flex items-center w-full text-left text-sm transition-colors"
                style={{
                  padding: "9px 14px",
                  background: i === active ? "var(--surface-active)" : "transparent",
                  color: i === active ? "var(--text-primary)" : "var(--text-secondary)",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                {item.label}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
```

## Settings shell

- File: `crates/hf-gui/src/components/settings/SettingsView.tsx`
- Description: Full-window settings layout replacing the normal app shell.

```tsx
// Full-window Settings takeover, modeled after y-agent's SettingsPanel.
//
// This is the orchestrator. For the ACTIVE config-backed section it owns the
// single source of truth: the typed `value`, optional `raw` TOML text, the
// `mode` (form | raw), and a `dirty` flag. Generic sections keep lossless
// FORM/RAW conversion. Secret-bearing integrations deliberately use only typed
// public DTOs and explicit patches, so hidden values cannot be round-tripped or
// erased accidentally. ONE header "Save Changes" button persists the draft.

import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Server, Database, Info, SlidersHorizontal, Share2, GitPullRequest, Crosshair, CarFront } from "lucide-react";
import { getTransport } from "../../lib";
import { useI18n } from "../../i18nContext";
import { useToast } from "../ui/toastContext";
import { useConfirm } from "../../providers/confirm";
import { Button } from "../ui/Button";
import { LoadingState } from "../ui";
import { GeneralTab } from "./GeneralTab";
import { ProvidersTab } from "./ProvidersTab";
import { normalizeProvider, type Provider } from "./providerTypes";
import { StorageTab } from "./StorageTab";
import { IntegrationsTab } from "./IntegrationsTab";
import { IssueTrackerTab } from "./IssueTrackerTab";
import { AboutTab } from "./AboutTab";
import { FuzzingTab } from "./FuzzingTab";
import { AutomotiveSettingsTab } from "./AutomotiveSettingsTab";
import {
  getAutomotiveSettings,
  setAutomotiveSettings,
  type AutomotiveSettings,
} from "../../lib/automotive";
import { SETTINGS_SECTION_DEFINITIONS, type SectionId } from "./settingsSections";
import {
  defectDojoDraftFromPublic,
  defectDojoPatchFromDraft,
  issueTrackerDraftFromPublic,
  issueTrackerPatchFromDraft,
  type DefectDojoDraft,
  type DefectDojoPublicConfig,
  type IssueTrackerDraft,
  type IssueTrackerPublicConfig,
} from "../../lib/integrationSettings";
import {
  beginSettingsSectionLoad,
  completeSettingsSectionLoad,
  confirmSettingsNavigation,
  failSettingsSectionLoad,
  isMatchingSettingsLoad,
  isSettingsSectionReady,
  type SettingsLoadToken,
  type SettingsSectionState,
} from "../../lib/settingsViewState";

interface Section {
  id: SectionId;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  /** Raw config section name, or null when the section has no config file. */
  config: string | null;
}

const SECTION_ICONS: Record<SectionId, React.ComponentType<{ size?: number }>> = {
  general: SlidersHorizontal,
  fuzzing: Crosshair,
  automotive: CarFront,
  providers: Server,
  storage: Database,
  integrations: Share2,
  issuetracker: GitPullRequest,
  about: Info,
};

const SETTINGS_SECTIONS: readonly Section[] = SETTINGS_SECTION_DEFINITIONS.map(
  (section) => ({ ...section, icon: SECTION_ICONS[section.id] }),
);

type Cfg = Record<string, unknown>;

function FormRawToggle({ mode, onChange, disabled }: { mode: "form" | "raw"; onChange: (m: "form" | "raw") => void; disabled: boolean }) {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-2 select-none" style={{ fontSize: "11px", letterSpacing: "0.06em" }}>
      <span style={{ color: mode === "form" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>{t("settings.form")}</span>
      <button
        onClick={() => onChange(mode === "form" ? "raw" : "form")}
        disabled={disabled}
        className="relative outline-none"
        style={{
          width: "34px",
          height: "18px",
          borderRadius: "9px",
          border: "1px solid var(--border)",
          background: "var(--surface-tertiary)",
          cursor: disabled ? "not-allowed" : "pointer",
          opacity: disabled ? 0.55 : 1,
        }}
        aria-label={t("settings.toggleFormRaw")}
      >
        <span
          style={{
            position: "absolute",
            top: "2px",
            left: mode === "raw" ? "17px" : "2px",
            width: "12px",
            height: "12px",
            borderRadius: "50%",
            background: "var(--accent)",
            transition: "left 0.18s ease",
          }}
        />
      </button>
      <span style={{ color: mode === "raw" ? "var(--accent)" : "var(--text-muted)", fontWeight: 600 }}>{t("settings.raw")}</span>
    </div>
  );
}

export function SettingsView({ onBack, onRunWizard }: { onBack?: () => void; onRunWizard?: () => void }) {
  const { t } = useI18n();
  const [active, setActive] = useState<SectionId>("general");
  const [mode, setMode] = useState<"form" | "raw">("form");
  // The single source of truth for the active config-backed section. The
  // section identity and request ID travel with the draft so a late response
  // can never populate (or save through) a different section.
  const [draft, setDraft] = useState<SettingsSectionState>(() =>
    beginSettingsSectionLoad(0, "general"));
  const [saving, setSaving] = useState(false);
  const loadRequestRef = useRef(0);
  const activeSectionRef = useRef<SectionId>("general");
  const { toast } = useToast();
  const confirm = useConfirm();

  const section = SETTINGS_SECTIONS.find((s) => s.id === active)!;
  const hasConfig = section.config !== null;
  const supportsRaw = hasConfig
    && active !== "automotive"
    && active !== "integrations"
    && active !== "issuetracker";
  const sectionReady = isSettingsSectionReady(draft, active);
  const showRaw = supportsRaw && mode === "raw";
  const { value, raw, dirty, loading, error } = draft;

  const isCurrentRequest = useCallback((token: SettingsLoadToken): boolean =>
    loadRequestRef.current === token.requestId
      && activeSectionRef.current === token.sectionId, []);

  // Load a section into its form draft. Providers and integrations use typed
  // service DTOs; generic config sections keep lossless FORM/RAW conversion.
  const load = useCallback(
    async (s: Section) => {
      const token: SettingsLoadToken = {
        requestId: ++loadRequestRef.current,
        sectionId: s.id,
      };
      setDraft(beginSettingsSectionLoad(token.requestId, token.sectionId));

      if (s.config === null) {
        if (isCurrentRequest(token)) {
          setDraft((current) => completeSettingsSectionLoad(current, token, null, ""));
        }
        return;
      }

      try {
        const T = getTransport();
        let nextValue: unknown;
        let nextRaw: string;
        if (s.id === "automotive") {
          nextValue = await getAutomotiveSettings(T);
          nextRaw = "";
        } else if (s.id === "providers") {
          const list = (await T.invoke<Provider[]>("get_providers")).map(normalizeProvider);
          if (!isCurrentRequest(token)) return;
          nextValue = list;
          nextRaw = await T.invoke<string>("config_value_to_toml", { value: { providers: list } });
        } else if (s.id === "integrations") {
          const config = await T.invoke<DefectDojoPublicConfig>("get_defectdojo_config");
          if (!isCurrentRequest(token)) return;
          nextValue = defectDojoDraftFromPublic(config);
          nextRaw = "";
        } else if (s.id === "issuetracker") {
          const config = await T.invoke<IssueTrackerPublicConfig>("get_issue_tracker_config");
          if (!isCurrentRequest(token)) return;
          nextValue = issueTrackerDraftFromPublic(config);
          nextRaw = "";
        } else {
          const text = await T.invoke<string>("read_config", { name: s.config });
          if (!isCurrentRequest(token)) return;
          nextRaw = text;
          nextValue = await T.invoke<Cfg>("config_toml_to_value", { content: text });
        }
        if (isCurrentRequest(token)) {
          setDraft((current) =>
            completeSettingsSectionLoad(current, token, nextValue, nextRaw));
        }
      } catch (e) {
        if (!isCurrentRequest(token)) return;
        const message = String(e);
        setDraft((current) => failSettingsSectionLoad(current, token, message));
        toast({ title: t("settings.loadFailed"), description: message, variant: "error" });
      }
    },
    [isCurrentRequest, toast, t],
  );

  // Reload whenever the selected section changes (mode is reset to FORM by the
  // nav handler / initial state, so the effect only synchronizes with disk).
  useEffect(() => {
    activeSectionRef.current = section.id;
    void load(section);
    return () => {
      loadRequestRef.current += 1;
    };
  }, [section, load]);

  // Serialize the current form `value` to TOML text (provider arrays are wrapped
  // back into the [[providers]] table shape).
  async function serializeValue(v: unknown, sectionId: SectionId): Promise<string> {
    const T = getTransport();
    if (sectionId === "providers") {
      return T.invoke<string>("config_value_to_toml", { value: { providers: v ?? [] } });
    }
    return T.invoke<string>("config_value_to_toml", { value: (v as Cfg) ?? {} });
  }

  // Parse raw TOML text back into a form `value`.
  async function parseToValue(text: string, sectionId: SectionId): Promise<unknown> {
    const T = getTransport();
    const parsed = await T.invoke<Cfg>("config_toml_to_value", { content: text });
    if (sectionId === "providers") {
      const arr = (parsed as { providers?: Provider[] })?.providers;
      return Array.isArray(arr) ? arr : [];
    }
    return parsed ?? {};
  }

  // Lossless FORM <-> RAW switch: convert in memory, preserving unsaved edits.
  async function changeMode(m: "form" | "raw") {
    if (m === mode || !sectionReady || !supportsRaw) return;
    const token: SettingsLoadToken = {
      requestId: draft.requestId,
      sectionId: active,
    };
    try {
      if (m === "raw") {
        const nextRaw = await serializeValue(value, token.sectionId);
        if (!isCurrentRequest(token)) return;
        setDraft((current) => isMatchingSettingsLoad(current, token)
          && current.loadedSection === token.sectionId
          ? { ...current, raw: nextRaw }
          : current);
      } else {
        const nextValue = await parseToValue(raw, token.sectionId);
        if (!isCurrentRequest(token)) return;
        setDraft((current) => isMatchingSettingsLoad(current, token)
          && current.loadedSection === token.sectionId
          ? { ...current, value: nextValue }
          : current);
      }
      setMode(m);
    } catch (e) {
      toast({ title: t("settings.conversionFailed"), description: String(e), variant: "error" });
    }
  }

  function onFormChange(next: unknown) {
    setDraft((current) => current.loadedSection === active
      && current.requestedSection === active
      ? { ...current, value: next, dirty: true }
      : current);
  }

  const requestDiscardConfirmation = useCallback(() => confirm({
    title: t("settings.discardTitle"),
    message: t("settings.discardMessage"),
    danger: true,
    confirmLabel: t("settings.discardConfirm"),
  }), [confirm, t]);

  async function selectSection(id: SectionId) {
    if (id === active) return;
    if (!(await confirmSettingsNavigation(dirty, requestDiscardConfirmation))) return;
    activeSectionRef.current = id;
    const invalidationId = ++loadRequestRef.current;
    setDraft(beginSettingsSectionLoad(invalidationId, id));
    setMode("form");
    setActive(id);
  }

  async function goBack() {
    if (!(await confirmSettingsNavigation(dirty, requestDiscardConfirmation))) return;
    onBack?.();
  }

  async function save() {
    if (!section.config || !sectionReady || saving) return;
    const targetSection = section;
    const targetMode = mode;
    const targetValue = value;
    const targetRaw = raw;
    const token: SettingsLoadToken = {
      requestId: draft.requestId,
      sectionId: targetSection.id,
    };
    setSaving(true);
    try {
      const T = getTransport();
      if (targetSection.id === "automotive") {
        await setAutomotiveSettings(targetValue as AutomotiveSettings, T);
      } else if (targetSection.id === "providers") {
        const list = targetMode === "raw"
          ? await parseToValue(targetRaw, targetSection.id)
          : targetValue;
        await T.invoke("set_providers", { providers: (list as Provider[]) ?? [] });
      } else if (targetSection.id === "integrations") {
        await T.invoke("patch_defectdojo_config", {
          patch: defectDojoPatchFromDraft(targetValue as DefectDojoDraft),
        });
      } else if (targetSection.id === "issuetracker") {
        await T.invoke("patch_issue_tracker_config", {
          patch: issueTrackerPatchFromDraft(targetValue as IssueTrackerDraft),
        });
      } else {
        const content = targetMode === "raw"
          ? targetRaw
          : await serializeValue(targetValue, targetSection.id);
        await T.invoke("write_config", { name: targetSection.config, content });
      }
      toast({ title: t("settings.saved"), description: t("settings.savedDesc", { section: t(`settings.tab.${targetSection.id}`) }), variant: "success" });
      if (isCurrentRequest(token)) {
        await load(targetSection);
      }
    } catch (e) {
      toast({ title: t("settings.saveFailed"), description: String(e), variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  function renderForm() {
    const obj = value && typeof value === "object" && !Array.isArray(value) ? (value as Cfg) : {};
    switch (active) {
      case "general":
        return <GeneralTab onRunWizard={onRunWizard} />;
      case "about":
        return <AboutTab />;
      case "providers":
        return <ProvidersTab value={Array.isArray(value) ? (value as Provider[]) : []} onChange={onFormChange} />;
      case "fuzzing":
        return <FuzzingTab value={obj} onChange={onFormChange} />;
      case "automotive":
        return (
          <AutomotiveSettingsTab
            value={value as AutomotiveSettings}
            onChange={onFormChange}
          />
        );
      case "storage":
        return <StorageTab />;
      case "integrations":
        return <IntegrationsTab value={value as DefectDojoDraft} onChange={onFormChange} />;
      case "issuetracker":
        return <IssueTrackerTab value={value as IssueTrackerDraft} onChange={onFormChange} />;
      default:
        return null;
    }
  }

  return (
    <div className="flex h-full w-full">
      {/* Left sub-nav */}
      <nav className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none" style={{ width: "240px" }}>
        <div style={{ height: "28px", flexShrink: 0 }} />
        <div style={{ padding: "6px 8px 0" }}>
          <button
            onClick={() => void goBack()}
            className="flex items-center gap-2 w-full text-left rounded-md bg-transparent border border-transparent text-text-secondary hover:bg-accent-subtle hover:text-text-primary transition-all duration-150 outline-none"
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, cursor: "pointer" }}
          >
            <ArrowLeft size={16} />
            <span>{t("settings.back")}</span>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px" }}>
          {SETTINGS_SECTIONS.map(({ id, icon: Icon }) => {
            const isActive = active === id;
            return (
              <button
                key={id}
                onClick={() => void selectSection(id)}
                className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
                  isActive
                    ? "bg-surface-active text-text-primary border border-border"
                    : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
                }`}
                style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
              >
                <span style={{ color: isActive ? "var(--accent)" : "inherit", display: "flex" }}>
                  <Icon size={16} />
                </span>
                <span>{t(`settings.tab.${id}`)}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Right pane */}
      <div className="app-main flex flex-1 flex-col min-w-0">
        <header
          className="flex items-center justify-between flex-shrink-0 select-none"
          style={{ height: "52px", padding: "0 var(--space-lg)", borderBottom: "1px solid var(--border)" }}
        >
          <span
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "17px",
              fontWeight: 400,
              fontStyle: "italic",
              letterSpacing: "0.01em",
              opacity: 0.9,
            }}
          >
            {t(`settings.tab.${section.id}`)}
          </span>
          <div className="flex items-center gap-4">
            {supportsRaw && <FormRawToggle mode={mode} onChange={changeMode} disabled={!sectionReady || saving} />}
            {hasConfig && (
              <Button variant="primary" size="sm" onClick={save} disabled={!sectionReady || !dirty || saving} loading={saving}>
                {t("settings.save")}
              </Button>
            )}
          </div>
        </header>

        <div className="flex-1 overflow-y-auto" style={{ padding: "var(--space-lg)" }}>
          {!hasConfig ? (
            renderForm()
          ) : loading ? (
            <LoadingState />
          ) : !sectionReady ? (
            <div role="alert" className="text-text-secondary" style={{ fontSize: "13px" }}>
              {error ?? t("settings.loadFailed")}
            </div>
          ) : showRaw ? (
            <div className="flex flex-col h-full">
              <textarea
                value={raw}
                onChange={(e) => {
                  const nextRaw = e.target.value;
                  setDraft((current) => current.loadedSection === active
                    && current.requestedSection === active
                    ? { ...current, raw: nextRaw, dirty: true }
                    : current);
                }}
                disabled={!sectionReady || saving}
                spellCheck={false}
                className="flex-1 w-full outline-none resize-none"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: "var(--text-primary)",
                  background: "var(--surface-code)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-md)",
                  padding: "var(--space-md)",
                  minHeight: "320px",
                  tabSize: 2,
                }}
              />
            </div>
          ) : (
            renderForm()
          )}
        </div>
      </div>
    </div>
  );
}
```


