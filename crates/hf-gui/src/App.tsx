import { useState } from "react";
import type { ViewType } from "./types";
import { Sidebar } from "./components/Sidebar";
import { DiscoverView } from "./views/DiscoverView";
import { RunView } from "./views/RunView";
import { TriageView } from "./views/TriageView";
import { CorpusView } from "./views/CorpusView";
import { SettingsView } from "./views/SettingsView";

export default function App() {
  const [activeView, setActiveView] = useState<ViewType>("discover");

  return (
    <div className="flex h-full w-full bg-surface-tertiary text-text-primary">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <main className="flex-1 overflow-auto p-4">
        {activeView === "discover" && <DiscoverView />}
        {activeView === "run" && <RunView />}
        {activeView === "triage" && <TriageView />}
        {activeView === "corpus" && <CorpusView />}
        {activeView === "settings" && <SettingsView />}
      </main>
    </div>
  );
}