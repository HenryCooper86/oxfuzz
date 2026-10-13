type ProjectDeletionHandler = (project: string) => void;

const handlers = new Set<ProjectDeletionHandler>();

/** Invalidate presentation caches after the service has deleted a project's data. */
export function notifyProjectDeleted(project: string): void {
  for (const handler of handlers) handler(project);
}

export function onProjectDeleted(handler: ProjectDeletionHandler): () => void {
  handlers.add(handler);
  return () => { handlers.delete(handler); };
}
