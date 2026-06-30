import type { ViewType } from "../types";
import { useProject } from "../providers/ProjectContext";
import { pickFolder } from "../lib";
import { Button, EmptyState, ViewHeader } from "../components/ui";
import { FolderOpen, FolderPlus, Crosshair, Play, X, Folder } from "lucide-react";

export function ProjectsView({ onNavigate }: { onNavigate: (view: ViewType) => void }) {
  const { activeProject, recentProjects, setActiveProject, removeRecent } = useProject();

  async function addProject() {
    const path = await pickFolder();
    if (path) {
      setActiveProject(path);
      onNavigate("discover");
    }
  }

  function open(path: string, view: ViewType) {
    setActiveProject(path);
    onNavigate(view);
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title="Projects" description="Recent project folders you've scanned and fuzzed." />
        <Button variant="primary" onClick={addProject}>
          <FolderPlus size={14} />
          Add project
        </Button>
      </div>

      {recentProjects.length === 0 ? (
        <EmptyState
          icon={<Folder size={20} />}
          title="No projects yet"
          hint="Add a C/C++ project folder to start discovering targets."
          action={
            <Button variant="primary" onClick={addProject}>
              <FolderPlus size={14} />
              Add project
            </Button>
          }
        />
      ) : (
        <div className="flex flex-col gap-1.5">
          {recentProjects.map((path) => {
            const active = path === activeProject;
            const name = path.split("/").pop() || path;
            return (
              <div
                key={path}
                className="surface-card flex items-center gap-3"
                style={{
                  padding: "var(--space-sm) var(--space-md)",
                  borderColor: active ? "var(--border-focus)" : undefined,
                }}
              >
                <Folder size={16} style={{ color: active ? "var(--accent)" : "var(--text-muted)", flexShrink: 0 }} />
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-sm font-medium truncate">{name}</span>
                  <span className="text-xs text-text-muted truncate" style={{ fontFamily: "var(--font-mono)" }}>
                    {path}
                  </span>
                </div>
                <button
                  onClick={() => open(path, "discover")}
                  className="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-md border border-border bg-surface-primary text-text-secondary transition-all duration-150 hover:bg-surface-hover hover:text-text-primary"
                  title="Discover targets"
                >
                  <Crosshair size={13} />
                  Discover
                </button>
                <button
                  onClick={() => open(path, "run")}
                  className="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-md border border-border bg-surface-primary text-text-secondary transition-all duration-150 hover:bg-surface-hover hover:text-text-primary"
                  title="Run a fuzz campaign"
                >
                  <Play size={13} />
                  Run
                </button>
                <button
                  onClick={() => removeRecent(path)}
                  className="inline-flex items-center justify-center rounded-md transition-colors duration-150"
                  style={{ width: "28px", height: "28px", color: "var(--text-muted)", border: "none", background: "transparent", cursor: "pointer" }}
                  title="Remove from recents"
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <X size={14} />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {activeProject && (
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <FolderOpen size={13} />
          <span>
            Active: <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{activeProject}</span>
          </span>
        </div>
      )}
    </div>
  );
}
