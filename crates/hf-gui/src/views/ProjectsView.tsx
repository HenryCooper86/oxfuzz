import { useCallback, useEffect, useState } from "react";
import type { ViewType } from "../types";
import { useProject } from "../providers/ProjectContext";
import { getTransport, onDataChanged, pickFolder } from "../lib";
import { useConfirm } from "../providers/ConfirmContext";
import { useToast } from "../components/ui/Toast";
import { Button, IconButton, EmptyState, ViewHeader } from "../components/ui";
import { FolderOpen, FolderPlus, Crosshair, Play, X, Folder, Trash2 } from "lucide-react";
import { AutoRevertBadge, type AutoRevertPolicyView } from "../components/AutoRevertBadge";

type ProjectAutoRevert = AutoRevertPolicyView;

export function ProjectsView({ onNavigate }: { onNavigate: (view: ViewType) => void }) {
  const { activeProject, recentProjects, setActiveProject, removeRecent, deleteProjectData } =
    useProject();
  const confirm = useConfirm();
  const { toast } = useToast();
  // Per-project auto-revert overrides, keyed by project root. Absence = the
  // project inherits the global policy (no badge).
  const [overrides, setOverrides] = useState<Record<string, ProjectAutoRevert>>({});

  const loadOverrides = useCallback(async () => {
    try {
      const map = await getTransport().invoke<Record<string, ProjectAutoRevert>>(
        "project_auto_revert_overrides",
      );
      setOverrides(map ?? {});
    } catch {
      setOverrides({});
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => void loadOverrides());
    return onDataChanged(() => void loadOverrides());
  }, [loadOverrides]);

  async function addProject() {
    const path = await pickFolder();
    if (path) {
      setActiveProject(path);
      onNavigate("discover");
    }
  }

  async function deleteData(path: string) {
    const name = path.split("/").pop() || path;
    if (
      !(await confirm({
        title: `Delete all data for "${name}"?`,
        message:
          "This removes its targets, harnesses, corpus, crashes, and runs from the database and deletes its on-disk workspace. This cannot be undone.",
        danger: true,
        confirmLabel: "Delete data",
      }))
    ) {
      return;
    }
    try {
      await deleteProjectData(path);
      toast({ title: "Project data deleted", description: name, variant: "success" });
    } catch (e) {
      toast({ title: "Failed to delete project data", description: String(e), variant: "error" });
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
                {overrides[path] && <AutoRevertBadge policy={overrides[path]} overridden />}
                <Button variant="outline" size="sm" onClick={() => open(path, "discover")} title="Discover targets">
                  <Crosshair size={13} />
                  Discover
                </Button>
                <Button variant="outline" size="sm" onClick={() => open(path, "run")} title="Run a fuzz campaign">
                  <Play size={13} />
                  Run
                </Button>
                <IconButton
                  onClick={() => removeRecent(path)}
                  title="Remove from recents (keeps data)"
                  aria-label="Remove from recents"
                >
                  <X size={14} />
                </IconButton>
                <IconButton
                  danger
                  onClick={() => deleteData(path)}
                  title="Delete all data for this project"
                  aria-label="Delete all data for this project"
                >
                  <Trash2 size={14} />
                </IconButton>
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
