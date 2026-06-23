import { useState, useEffect } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { DiscoverView } from "./views/DiscoverView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { SettingsView } from "./views/SettingsView";

export default function App() {
  const [activeView, setActiveView] = useState<ViewType>("discover");
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <div className="flex h-full w-full bg-surface-primary text-text-primary">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <div className="flex flex-1 flex-col min-w-0">
        <Header theme={theme} onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))} />
        <main className="flex-1 overflow-auto" style={{ padding: "var(--space-lg)" }}>
          {activeView === "discover" && <DiscoverView />}
          {activeView === "run" && <RunView />}
          {activeView === "triage" && <TriageView />}
          {activeView === "corpus" && <CorpusView />}
          {activeView === "settings" && <SettingsView />}
        </main>
      </div>
    </div>
  );
}