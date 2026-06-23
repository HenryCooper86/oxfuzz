// Settings panel with sidebar nav + tab content.
// Modeled after y-agent's SettingsPanel architecture.

import { useState } from "react";
import { Settings, Server, HardDrive, Crosshair, Shield, Database, Info } from "lucide-react";
import { ProvidersTab } from "./ProvidersTab";
import { RuntimeTab } from "./RuntimeTab";
import { EnginesTab } from "./EnginesTab";
import { GuardrailsTab } from "./GuardrailsTab";
import { StorageTab } from "./StorageTab";
import { AboutTab } from "./AboutTab";

type SettingsTab = "providers" | "runtime" | "engines" | "guardrails" | "storage" | "about";

const TABS: { id: SettingsTab; label: string; icon: React.ComponentType<{ size?: number }> }[] = [
  { id: "providers", label: "Providers", icon: Server },
  { id: "runtime", label: "Runtime", icon: HardDrive },
  { id: "engines", label: "Engines", icon: Crosshair },
  { id: "guardrails", label: "Guardrails", icon: Shield },
  { id: "storage", label: "Storage", icon: Database },
  { id: "about", label: "About", icon: Info },
];

export function SettingsView() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("providers");

  return (
    <div className="flex gap-4 h-full" style={{ animation: "fadeIn 0.2s ease" }}>
      {/* Settings sidebar nav */}
      <div className="flex flex-col gap-1" style={{ width: "160px", flexShrink: 0 }}>
        <div className="text-xs font-semibold uppercase text-text-muted mb-2" style={{ letterSpacing: "0.08em", padding: "7px 10px" }}>
          <Settings size={12} className="inline mr-1" />
          Settings
        </div>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none border ${activeTab === tab.id ? "bg-surface-active text-text-primary border-border" : "bg-transparent text-text-secondary border-transparent hover:bg-accent-subtle hover:text-text-primary"}`}
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
          >
            <tab.icon size={16} />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === "providers" && <ProvidersTab />}
        {activeTab === "runtime" && <RuntimeTab />}
        {activeTab === "engines" && <EnginesTab />}
        {activeTab === "guardrails" && <GuardrailsTab />}
        {activeTab === "storage" && <StorageTab />}
        {activeTab === "about" && <AboutTab />}
      </div>
    </div>
  );
}