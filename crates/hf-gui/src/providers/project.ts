import { createContext, useContext } from "react";

export interface ProjectContextValue {
  activeProject: string;
  recentProjects: string[];
  setActiveProject: (path: string) => void;
  addRecent: (path: string) => void;
  removeRecent: (path: string) => void;
  deleteProjectData: (path: string) => Promise<void>;
}

export const ProjectContext = createContext<ProjectContextValue | null>(null);

/** Access shared project state. Safe outside a provider. */
export function useProject(): ProjectContextValue {
  return (
    useContext(ProjectContext) ?? {
      activeProject: "",
      recentProjects: [],
      setActiveProject: () => {},
      addRecent: () => {},
      removeRecent: () => {},
      deleteProjectData: async () => {},
    }
  );
}
