import { createContext, useCallback, useContext, useMemo, useState } from "react";

const STORAGE_KEY = "hf_recent_projects";
const ACTIVE_KEY = "hf_active_project";
const MAX_RECENTS = 8;

interface ProjectContextValue {
  /** The project folder currently in focus across views. */
  activeProject: string;
  /** Most-recently-used project folders (most recent first). */
  recentProjects: string[];
  /** Set the active project (also records it in recents). */
  setActiveProject: (path: string) => void;
  /** Record a project in the recents list without changing focus. */
  addRecent: (path: string) => void;
  /** Remove a project from recents. */
  removeRecent: (path: string) => void;
}

const ProjectContext = createContext<ProjectContextValue | null>(null);

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
  const [activeProject, setActiveProjectState] = useState<string>(() => localStorage.getItem(ACTIVE_KEY) ?? "");

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

  const value = useMemo(
    () => ({ activeProject, recentProjects, setActiveProject, addRecent, removeRecent }),
    [activeProject, recentProjects, setActiveProject, addRecent, removeRecent],
  );

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}

/** Access the shared project state. Safe to call outside a provider (returns inert defaults). */
export function useProject(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) {
    return {
      activeProject: "",
      recentProjects: [],
      setActiveProject: () => {},
      addRecent: () => {},
      removeRecent: () => {},
    };
  }
  return ctx;
}
