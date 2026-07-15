import { useCallback, useEffect, useState } from "react";
import type { ViewType } from "../types";
import { useProject } from "../providers/project";
import { getTransport, onDataChanged, pickFolder } from "../lib";
import { useConfirm } from "../providers/confirm";
import { useToast } from "../components/ui/toastContext";
import { Button, IconButton, EmptyState, ViewHeader } from "../components/ui";
import { FolderOpen, FolderPlus, Crosshair, Play, X, Folder, Trash2 } from "lucide-react";
import { AutoRevertBadge, type AutoRevertPolicyView } from "../components/AutoRevertBadge";
import { useI18n } from "../i18nContext";

type ProjectAutoRevert = AutoRevertPolicyView;

export function ProjectsView({ onNavigate }: { onNavigate: (view: ViewType) => void }) {
  const { activeProject, recentProjects, setActiveProject, removeRecent, deleteProjectData } =
    useProject();
  const confirm = useConfirm();
  const { toast } = useToast();
  const { t } = useI18n();
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
        title: t("projects.deleteDataTitle", { name }),
        message: t("projects.deleteDataMessage"),
        danger: true,
        confirmLabel: t("projects.deleteData"),
      }))
    ) {
      return;
    }
    try {
      await deleteProjectData(path);
      toast({ title: t("projects.dataDeleted"), description: name, variant: "success" });
    } catch (e) {
      toast({ title: t("projects.deleteFailed"), description: String(e), variant: "error" });
    }
  }

  function open(path: string, view: ViewType) {
    setActiveProject(path);
    onNavigate(view);
  }

  return (
    <div className="flex flex-col gap-4" style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="flex items-center justify-between">
        <ViewHeader title={t("projects.title")} description={t("projects.description")} />
        <Button variant="primary" onClick={addProject}>
          <FolderPlus size={14} />
          {t("projects.addProject")}
        </Button>
      </div>

      {recentProjects.length === 0 ? (
        <EmptyState
          icon={<Folder size={20} />}
          title={t("projects.empty")}
          hint={t("projects.emptyHint")}
          action={
            <Button variant="primary" onClick={addProject}>
              <FolderPlus size={14} />
              {t("projects.addProject")}
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
                <Button variant="outline" size="sm" onClick={() => open(path, "discover")} title={t("projects.discoverTooltip")}>
                  <Crosshair size={13} />
                  {t("projects.discover")}
                </Button>
                <Button variant="outline" size="sm" onClick={() => open(path, "run")} title={t("projects.runTooltip")}>
                  <Play size={13} />
                  {t("common.run")}
                </Button>
                <IconButton
                  onClick={() => removeRecent(path)}
                  title={t("projects.removeTooltip")}
                  aria-label={t("projects.removeAria")}
                >
                  <X size={14} />
                </IconButton>
                <IconButton
                  danger
                  onClick={() => deleteData(path)}
                  title={t("projects.deleteTooltip")}
                  aria-label={t("projects.deleteAria")}
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
            {t("projects.active")}{" "}
            <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{activeProject}</span>
          </span>
        </div>
      )}
    </div>
  );
}
