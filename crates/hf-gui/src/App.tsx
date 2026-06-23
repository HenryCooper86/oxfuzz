import { useState, useEffect } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { StatusBar } from "./components/StatusBar";
import { ChatView } from "./views/ChatView";
import { DiscoverView } from "./views/DiscoverView";
import { HarnessView } from "./views/HarnessView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { SettingsView } from "./views/SettingsView";
import { MessageSquare, Target, Play, Bug, Database, Settings, FileCode } from "lucide-react";

export default function App() {
  const [activeView, setActiveView] = useState<ViewType>("chat");
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <div className="flex h-full w-full bg-surface-primary text-text-primary">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <div className="flex flex-1 flex-col min-w-0">
        <Header
          title={viewTitles[activeView]}
          icon={viewIcons[activeView]}
          theme={theme}
          onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
        />
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
        <StatusBar />
      </div>
    </div>
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