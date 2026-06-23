import type { ViewType } from "../types";
import { Bug, Database, Play, Settings, Target } from "lucide-react";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
}

const NAV_ITEMS: { view: ViewType; label: string; icon: React.ComponentType<{ size?: number }> }[] = [
  { view: "discover", label: "Discover", icon: Target },
  { view: "run", label: "Run", icon: Play },
  { view: "triage", label: "Triage", icon: Bug },
  { view: "corpus", label: "Corpus", icon: Database },
  { view: "settings", label: "Settings", icon: Settings },
];

export function Sidebar({ activeView, onNavigate }: SidebarProps) {
  return (
    <nav
      className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none"
      style={{ width: "var(--sidebar-width, 220px)" }}
    >
      {/* Drag region for macOS traffic lights */}
      <div style={{ height: "28px", flexShrink: 0 }} />

      {/* Nav items */}
      <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px 0 8px" }}>
        <div
          className="text-xs font-semibold uppercase mb-1"
          style={{ color: "var(--text-muted)", letterSpacing: "0.08em", padding: "7px 10px" }}
        >
          Fuzzing
        </div>
        {NAV_ITEMS.map(({ view, label, icon: Icon }) => (
          <button
            key={view}
            onClick={() => onNavigate(view)}
            className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
              activeView === view
                ? "bg-surface-active text-text-primary border border-border"
                : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
            }`}
            style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
          >
            <Icon size={18} />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* Footer */}
      <div className="border-t border-border" style={{ padding: "6px 8px 8px 8px" }}>
        <div
          className="text-xs text-text-muted text-center"
          style={{ padding: "7px 10px" }}
        >
          hobot_fuzz v0.1.0
        </div>
      </div>
    </nav>
  );
}