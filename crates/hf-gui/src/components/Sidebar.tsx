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
  // the Vehicle Security section below).
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
            never gated behind a runtime toggle. It renders as a standard nav row
            for visual consistency with the rest of the sidebar. When the
            subsystem is off or absent from the build, the workspace itself
            explains how to enable it or that it is unavailable. */}
        <SectionLabel>{t("sidebar.vehicle")}</SectionLabel>
        <NavButton
          item={{ view: "automotive", icon: CarFront }}
          active={activeView === "automotive"}
          onNavigate={onNavigate}
        />

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
