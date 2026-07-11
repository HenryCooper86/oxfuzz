import type { ViewType } from "../types";
import { useProject } from "../providers/ProjectContext";
import { useTarget } from "../providers/TargetContext";
import { useI18n } from "../i18n";
import { Bot, BookOpen, Bug, Boxes, Crosshair, Database, FileCode, FileText, FolderOpen, History, LayoutDashboard, MessageSquare, Play, Plus, Puzzle, ScrollText, Settings, Workflow, X, Zap } from "lucide-react";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
  /** Pick a project folder and start a fresh fuzzing target. */
  onNewTarget: () => void;
  /** Make an existing project the active fuzzing target. */
  onSelectTarget: (path: string) => void;
}

type NavItem = { view: ViewType; label: string; icon: React.ComponentType<{ size?: number }> };

// The pipeline tools that operate on the active target, in fuzzing-workflow
// order: chat drives the agent, then discover -> harness -> run -> triage ->
// corpus mirrors a campaign's lifecycle.
const PIPELINE_ITEMS: NavItem[] = [
  { view: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { view: "chat", label: "AI Assistant", icon: MessageSquare },
  { view: "workflow", label: "Fuzzing Workflow", icon: Workflow },
  { view: "discover", label: "Discover", icon: Crosshair },
  { view: "harness", label: "Harness", icon: FileCode },
  { view: "run", label: "Run", icon: Play },
  { view: "triage", label: "Triage", icon: Bug },
  { view: "corpus", label: "Corpus", icon: Database },
];

// Cross-cutting resources, not tied to a single target.
const LIBRARY_ITEMS: NavItem[] = [
  { view: "projects", label: "Projects", icon: FolderOpen },
  { view: "artifacts", label: "Artifacts", icon: Boxes },
  { view: "reports", label: "Reports", icon: FileText },
  { view: "runs", label: "Run History", icon: History },
  { view: "audit", label: "Policy Audit", icon: ScrollText },
  { view: "agents", label: "Agents", icon: Bot },
  { view: "skills", label: "Skills", icon: Puzzle },
  { view: "knowledge", label: "Knowledge", icon: BookOpen },
  { view: "automation", label: "Automation", icon: Zap },
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
}: {
  item: NavItem;
  active: boolean;
  onNavigate: (view: ViewType) => void;
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
      style={{ padding: "7px 10px", fontSize: "13px", fontWeight: 500, marginBottom: "2px" }}
    >
      <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex" }}>
        <Icon size={18} />
      </span>
      <span>{t(`nav.${view}`)}</span>
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
          <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />
        ))}

        <SectionLabel>{t("sidebar.library")}</SectionLabel>
        {LIBRARY_ITEMS.map((item) => (
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
        <div className="text-text-muted text-center flex flex-col items-center gap-0.5" style={{ padding: "6px 10px 0", fontSize: "11px" }}>
          <span>
            Press <kbd style={{ padding: "0 3px", border: "1px solid var(--border)", borderRadius: 3 }}>⌘K</kbd> to search
          </span>
          <span>hobot_fuzz v0.1.0</span>
        </div>
      </div>
    </nav>
  );
}
