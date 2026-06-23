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
    <nav className="w-16 flex flex-col items-center gap-2 py-4 border-r border-border bg-surface-secondary">
      {NAV_ITEMS.map(({ view, label, icon: Icon }) => (
        <button
          key={view}
          onClick={() => onNavigate(view)}
          title={label}
          className={`w-10 h-10 flex items-center justify-center rounded-DEFAULT transition-colors ${
            activeView === view
              ? "bg-accent-subtle text-accent"
              : "text-text-muted hover:text-text-primary hover:bg-surface-hover"
          }`}
        >
          <Icon size={20} />
        </button>
      ))}
    </nav>
  );
}