import type { ViewType } from "../types";
import { Bot, BookOpen, Bug, Boxes, Database, FileCode, FolderOpen, MessageSquare, Play, Plus, Puzzle, Settings, SquarePen, Target, Zap } from "lucide-react";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
  onNewTask: () => void;
}

type NavItem = { view: ViewType; label: string; icon: React.ComponentType<{ size?: number }> };

const TOP_ITEMS: NavItem[] = [
  { view: "projects", label: "Projects", icon: FolderOpen },
  { view: "artifacts", label: "Artifacts", icon: Boxes },
  { view: "agents", label: "Agents", icon: Bot },
  { view: "skills", label: "Skills", icon: Puzzle },
  { view: "knowledge", label: "Knowledge", icon: BookOpen },
  { view: "automation", label: "Automation", icon: Zap },
];

const NAV_ITEMS: NavItem[] = [
  { view: "chat", label: "AI Chat", icon: MessageSquare },
  { view: "discover", label: "Discover", icon: Target },
  { view: "harness", label: "Harness", icon: FileCode },
  { view: "run", label: "Run", icon: Play },
  { view: "triage", label: "Triage", icon: Bug },
  { view: "corpus", label: "Corpus", icon: Database },
];

function NavButton({
  item,
  active,
  onNavigate,
}: {
  item: NavItem;
  active: boolean;
  onNavigate: (view: ViewType) => void;
}) {
  const { view, label, icon: Icon } = item;
  return (
    <button
      onClick={() => onNavigate(view)}
      className={`flex items-center gap-2 w-full text-left rounded-md transition-all duration-150 outline-none ${
        active
          ? "bg-surface-active text-text-primary border border-border"
          : "bg-transparent text-text-secondary border border-transparent hover:bg-accent-subtle hover:text-text-primary"
      }`}
      style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
    >
      <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex" }}>
        <Icon size={18} />
      </span>
      <span>{label}</span>
    </button>
  );
}

/** Prominent "start a new task" row -- clears the chat + progress, opens AI Chat. */
function NewTaskButton({ onNewTask }: { onNewTask: () => void }) {
  return (
    <div className="flex items-center" style={{ marginBottom: "2px" }}>
      <button
        onClick={onNewTask}
        className="flex items-center gap-2 flex-1 text-left rounded-md transition-all duration-150 outline-none bg-transparent border border-transparent text-text-primary hover:bg-accent-subtle"
        style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500 }}
      >
        <Plus size={18} style={{ color: "var(--text-secondary)" }} />
        <span>New task</span>
      </button>
      <button
        onClick={onNewTask}
        className="flex items-center justify-center rounded-md transition-colors duration-150 bg-transparent border-none"
        style={{ width: "30px", height: "30px", color: "var(--text-muted)", cursor: "pointer" }}
        title="New task"
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <SquarePen size={15} />
      </button>
    </div>
  );
}

export function Sidebar({ activeView, onNavigate, onNewTask }: SidebarProps) {
  return (
    <nav
      className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none"
      style={{ width: "var(--sidebar-width, 240px)" }}
    >
      {/* Drag region / macOS traffic-light safe area */}
      <div style={{ height: "28px", flexShrink: 0 }} />

      {/* Top: New task + cross-cutting sections */}
      <div style={{ padding: "6px 8px 0 8px" }}>
        <NewTaskButton onNewTask={onNewTask} />
        {TOP_ITEMS.map((item) => (
          <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />
        ))}
      </div>

      {/* Primary nav */}
      <div className="flex-1 overflow-y-auto" style={{ padding: "6px 8px 0 8px" }}>
        <div
          className="text-xs font-semibold uppercase mb-1"
          style={{ color: "var(--text-muted)", letterSpacing: "0.08em", padding: "7px 10px" }}
        >
          Workspace
        </div>
        {NAV_ITEMS.map((item) => (
          <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />
        ))}
      </div>

      {/* Footer: Settings pinned at the bottom (Apple-style nav), then version */}
      <div className="border-t border-border" style={{ padding: "6px 8px 8px 8px" }}>
        <NavButton
          item={{ view: "settings", label: "Settings", icon: Settings }}
          active={activeView === "settings"}
          onNavigate={onNavigate}
        />
        <div className="text-text-muted text-center" style={{ padding: "6px 10px 0", fontSize: "11px" }}>
          hobot_fuzz v0.1.0
        </div>
      </div>
    </nav>
  );
}
