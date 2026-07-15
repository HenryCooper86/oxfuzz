import { useCallback, useMemo, useState } from "react";
import { getTransport, emitDataChanged } from "../lib";
import { ProjectContext } from "./project";

const STORAGE_KEY = "hf_recent_projects";
const ACTIVE_KEY = "hf_active_project";
const MAX_RECENTS = 8;

function loadRecents(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(parsed) ? parsed.filter((p): p is string => typeof p === "string") : [];
  } catch {
    return [];
  }
}

export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const [recentProjects, setRecentProjects] = useState<string[]>(loadRecents);
  // Self-heal a dangling active project: if the saved active folder is no longer
  // in recents (e.g. removed by an older build that did not clear focus), drop
  // it so stale per-project progress/run state does not surface.
  const [activeProject, setActiveProjectState] = useState<string>(() => {
    const saved = localStorage.getItem(ACTIVE_KEY) ?? "";
    if (saved && !loadRecents().includes(saved)) {
      try {
        localStorage.removeItem(ACTIVE_KEY);
      } catch {
        /* ignore */
      }
      return "";
    }
    return saved;
  });

  const persistRecents = useCallback((next: string[]) => {
    setRecentProjects(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      /* ignore quota / private-mode errors */
    }
  }, []);

  const addRecent = useCallback(
    (path: string) => {
      const p = path.trim();
      if (!p) return;
      setRecentProjects((prev) => {
        const next = [p, ...prev.filter((x) => x !== p)].slice(0, MAX_RECENTS);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        } catch {
          /* ignore */
        }
        return next;
      });
    },
    [],
  );

  const setActiveProject = useCallback(
    (path: string) => {
      const p = path.trim();
      setActiveProjectState(p);
      try {
        localStorage.setItem(ACTIVE_KEY, p);
      } catch {
        /* ignore */
      }
      addRecent(p);
    },
    [addRecent],
  );

  const removeRecent = useCallback(
    (path: string) => {
      persistRecents(recentProjects.filter((x) => x !== path));
      // Removing the active project drops focus, so per-project views (pipeline
      // progress, run output) stop showing the gone project's state.
      if (path === activeProject) {
        setActiveProjectState("");
        try {
          localStorage.removeItem(ACTIVE_KEY);
        } catch {
          /* ignore */
        }
      }
    },
    [persistRecents, recentProjects, activeProject],
  );

  const deleteProjectData = useCallback(
    async (path: string) => {
      const p = path.trim();
      if (!p) return;
      // Wipe backend records + on-disk workspace first; only forget the folder
      // locally once the backend has actually cleared it, so a failed delete
      // does not silently hide a project whose data still exists.
      await getTransport().invoke("delete_project", { project: p });
      removeRecent(p);
      emitDataChanged();
    },
    [removeRecent],
  );

  const value = useMemo(
    () => ({
      activeProject,
      recentProjects,
      setActiveProject,
      addRecent,
      removeRecent,
      deleteProjectData,
    }),
    [activeProject, recentProjects, setActiveProject, addRecent, removeRecent, deleteProjectData],
  );

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}
