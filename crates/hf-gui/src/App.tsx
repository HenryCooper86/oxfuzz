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
import { ChatView } from "./views/ChatView";
import { DiscoverView } from "./views/DiscoverView";
import { HarnessView } from "./views/HarnessView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { SettingsView } from "./views/SettingsView";
import { MessageSquare, Target, Play, Bug, Database, Settings, FileCode, Activity, Gauge, Info } from "lucide-react";

export default function App() {
  const [activeView, setActiveView] = useState<ViewType>("chat");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [showDiag, setShowDiag] = useState(false);
  const [showObs, setShowObs] = useState(false);
  const [showInfo, setShowInfo] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <TooltipProvider>
      <ToastProvider>
        <div className="flex h-full w-full bg-surface-primary text-text-primary">
          <Sidebar activeView={activeView} onNavigate={setActiveView} />
          <div className="flex flex-1 flex-col min-w-0">
            <Header
              title={viewTitles[activeView]}
              icon={viewIcons[activeView]}
              theme={theme}
              onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
              actions={
                <div className="flex items-center gap-1">
                  <HeaderToggle active={showDiag} onClick={() => setShowDiag(!showDiag)} icon={<Activity size={16} />} label="Diagnostics" />
                  <HeaderToggle active={showObs} onClick={() => setShowObs(!showObs)} icon={<Gauge size={16} />} label="Observability" />
                  <HeaderToggle active={showInfo} onClick={() => setShowInfo(!showInfo)} icon={<Info size={16} />} label="Info" />
                </div>
              }
            />
            <div className="flex flex-1 overflow-hidden">
              <main className="flex-1 overflow-hidden flex flex-col">
                {activeView === "chat" && <ChatView />}
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
                {activeView === "settings" && (
                  <div className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
                    <SettingsView />
                  </div>
                )}
              </main>

              {/* Observation panels */}
              {showDiag && <PanelShell title="Diagnostics"><DiagnosticsPanel /></PanelShell>}
              {showObs && <PanelShell title="Observability"><ObservabilityPanel /></PanelShell>}
              {showInfo && <PanelShell title="Info"><InfoPanel /></PanelShell>}
            </div>
            <StatusBar />
          </div>
        </div>
      </ToastProvider>
    </TooltipProvider>
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
  chat: "AI Assistant",
  discover: "Target Discovery",
  harness: "Harness Generation",
  run: "Fuzz Run",
  triage: "Crash Triage",
  corpus: "Corpus Management",
  settings: "Settings",
};

const viewIcons: Record<ViewType, React.ReactNode> = {
  chat: <MessageSquare size={18} />,
  discover: <Target size={18} />,
  harness: <FileCode size={18} />,
  run: <Play size={18} />,
  triage: <Bug size={18} />,
  corpus: <Database size={18} />,
  settings: <Settings size={18} />,
};