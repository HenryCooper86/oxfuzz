import { FolderOpen } from "lucide-react";
import { pickFolder } from "../lib";
import { useProject } from "../providers/project";
import { useI18n } from "../i18nContext";
import { Button } from "./ui";

/**
 * The one project picker. Shows the active project and changes it for the whole
 * app; every stage page renders this instead of keeping its own path, so no page
 * can work on a different project than the rest of the app.
 */
export function ActiveProjectBar() {
  const { t } = useI18n();
  const { activeProject, recentProjects, setActiveProject } = useProject();
  const projectName = activeProject ? activeProject.split("/").filter(Boolean).pop() : null;

  async function chooseProject() {
    const path = await pickFolder();
    if (path) setActiveProject(path);
  }

  return (
    <section className="surface-card" style={{ padding: "12px 14px", borderLeft: `3px solid ${activeProject ? "var(--success)" : "var(--accent)"}` }}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <FolderOpen size={16} style={{ color: activeProject ? "var(--success)" : "var(--accent)" }} />
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium">{projectName ?? t("workflow.noProjectSelected")}</span>
            <span className="text-xs text-text-muted truncate" style={{ fontFamily: activeProject ? "var(--font-mono)" : undefined }}>
              {activeProject || t("workflow.chooseProjectHint")}
            </span>
          </div>
        </div>
        <Button
          variant={activeProject ? "outline" : "primary"}
          size="sm"
          onClick={() => void chooseProject()}
          className="shrink-0"
        >
          <FolderOpen size={13} />
          {activeProject ? t("workflow.change") : t("workflow.chooseFolder")}
        </Button>
      </div>
      {!activeProject && recentProjects.length > 0 && (
        <div className="mt-3 flex flex-col gap-1">
          <span className="text-xs text-text-muted">{t("workflow.recentProjects")}</span>
          {recentProjects.slice(0, 5).map((p) => (
            <button
              key={p}
              onClick={() => setActiveProject(p)}
              className="text-left text-xs px-2 py-1.5 rounded-md text-text-secondary hover:bg-surface-hover hover:text-text-primary truncate"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {p}
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
