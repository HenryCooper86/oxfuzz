import type { ViewType } from "../types";
import { useProject } from "../providers/project";
import { useTarget } from "../providers/target";
import { useI18n } from "../i18nContext";
import { useDefectDojo } from "../lib";
import { APP_VERSION } from "../lib/appVersion";
import { IconButton } from "./ui/IconButton";
import { Bot, BookOpen, Bug, Boxes, CarFront, Cpu, Crosshair, Database, FileCode, FileText, FolderOpen, History, LayoutDashboard, LifeBuoy, MessageSquare, Play, Plus, Puzzle, ScrollText, Settings, ShieldCheck, Workflow, X, Zap, GitCompare } from "lucide-react";

interface SidebarProps {
  activeView: ViewType;
  onNavigate: (view: ViewType) => void;
  /** Pick a project folder and start a fresh fuzzing target. */
  onNewTarget: () => void;
  /** Make an existing project the active fuzzing target. */
  onSelectTarget: (path: string) => void;
}

type NavItem = { view: ViewType; icon: React.ComponentType<{ size?: number }> };
const PRIMARY_ITEMS: NavItem[] = [
  { view: "dashboard", icon: LayoutDashboard },
  { view: "workflow", icon: Workflow },
  { view: "triage", icon: Bug },
  { view: "runs", icon: History },
  { view: "reports", icon: FileText },
  { view: "projects", icon: FolderOpen },
  { view: "chat", icon: MessageSquare },
];
const TOOL_GROUPS: { label: string; items: NavItem[] }[] = [
  { label: "sidebar.pipeline", items: [
    { view: "discover", icon: Crosshair }, { view: "harness", icon: FileCode },
    { view: "run", icon: Play }, { view: "corpus", icon: Database }, { view: "binary", icon: Cpu },
  ] },
  { label: "sidebar.results", items: [
    { view: "artifacts", icon: Boxes }, { view: "changes", icon: GitCompare }, { view: "audit", icon: ScrollText },
  ] },
  { label: "sidebar.aiSystem", items: [
    { view: "agents", icon: Bot }, { view: "skills", icon: Puzzle },
    { view: "knowledge", icon: BookOpen }, { view: "automation", icon: Zap },
  ] },
  { label: "sidebar.vehicle", items: [{ view: "automotive", icon: CarFront }] },
];

function basename(path: string): string {
  return path.split("/").filter(Boolean).pop() || path;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-semibold uppercase"
      style={{ color: "var(--text-muted)", fontSize: "10.5px", letterSpacing: "0.09em", padding: "14px 10px 5px" }}
    >
      {children}
    </div>
  );
}

/** Shared row: every sidebar entry uses the `.hf-nav-row` look (styles/index.css). */
function NavRow({
  icon,
  label,
  active,
  onClick,
  title,
  current = "page",
}: {
  icon: React.ReactNode;
  label: React.ReactNode;
  active: boolean;
  onClick: () => void;
  title?: string;
  /** `page` for views; `true` for the selected item in a set (a target). */
  current?: "page" | "true";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-current={active ? current : undefined}
      className="hf-nav-row outline-none"
    >
      <span className="hf-nav-icon">{icon}</span>
      <span className="truncate">{label}</span>
    </button>
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
  return <NavRow icon={<Icon size={16} />} label={t(`nav.${view}`)} active={active} onClick={() => onNavigate(view)} />;
}

/** Library row that opens the embedded in-app DefectDojo view. */
function DefectDojoButton({ active, onOpen }: { active: boolean; onOpen: () => void }) {
  return (
    <NavRow
      icon={<ShieldCheck size={16} />}
      label="DefectDojo"
      active={active}
      onClick={onOpen}
      title="Open DefectDojo in the app"
    />
  );
}

/** Row that opens a folder picker to begin a new fuzzing target. */
function NewTargetButton({ onNewTarget }: { onNewTarget: () => void }) {
  const { t } = useI18n();
  return (
    <button type="button" onClick={onNewTarget} className="hf-nav-row outline-none" style={{ color: "var(--text-primary)" }}>
      <span className="hf-nav-icon" style={{ color: "var(--accent)" }}>
        <Plus size={16} />
      </span>
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
    <div className="group flex items-center gap-0.5">
      <div className="flex-1 min-w-0">
        <NavRow
          icon={<Crosshair size={15} />}
          label={label}
          active={active}
          current="true"
          onClick={() => onSelect(path)}
          title={path}
        />
      </div>
      <IconButton
        size={24}
        className="op-0 group-hover:op-100 focus-visible:op-100"
        onClick={() => onRemove(path)}
        title={t("sidebar.removeTarget")}
        aria-label={t("sidebar.removeTarget")}
      >
        <X size={13} />
      </IconButton>
    </div>
  );
}

export function Sidebar({ activeView, onNavigate, onNewTarget, onSelectTarget }: SidebarProps) {
  const { activeProject, recentProjects, removeRecent } = useProject();
  const { target } = useTarget();
  const { t } = useI18n();
  const { configured: defectDojoOn } = useDefectDojo();

  return (
    <nav
      className="flex flex-col h-full bg-surface-secondary border-r border-border flex-shrink-0 select-none"
      style={{ width: "var(--sidebar-width, 240px)" }}
    >
      {/* Drag region / macOS traffic-light safe area */}
      <div style={{ height: "28px", flexShrink: 0 }} />

      {/* Brand: logo + wordmark. Sits below the traffic-light safe area above so
          it never collides with the macOS window controls. */}
      <div className="flex items-center gap-2 flex-shrink-0" style={{ padding: "2px 14px 10px" }}>
        <img
          src="/logo.png"
          alt="oxfuzz"
          width={20}
          height={20}
          style={{ display: "block", flexShrink: 0 }}
        />
        <span
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "15px",
            fontWeight: 700,
            letterSpacing: "0.04em",
            color: "var(--text-primary)",
          }}
        >
          oxfuzz
        </span>
      </div>

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

        <SectionLabel>{t("sidebar.workspace")}</SectionLabel>
        {PRIMARY_ITEMS.map(item => <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />)}
        {TOOL_GROUPS.map(group => <div key={group.label}>
          <SectionLabel>{t(group.label)}</SectionLabel>
          {group.items.map(item => <NavButton key={item.view} item={item} active={activeView === item.view} onNavigate={onNavigate} />)}
        </div>)}
        {defectDojoOn && <>
          <SectionLabel>{t("sidebar.integrations")}</SectionLabel>
          <DefectDojoButton active={activeView === "defectdojo"} onOpen={() => onNavigate("defectdojo")} />
        </>}
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
            Press <kbd style={{ padding: "0 4px", border: "1px solid var(--border-strong)", borderRadius: 4, fontFamily: "var(--font-sans)", fontSize: "10px" }}>⌘K</kbd> to search
          </span>
          <span>oxfuzz v{APP_VERSION}</span>
        </div>
      </div>
    </nav>
  );
}
