// Browser mode never receives absolute host paths: the web API replaces each
// one with this marker (hf-web `security.rs`). A redacted path is therefore
// neither an identity nor a file name; listing rows carry `name` for display.
export const REDACTED_PATH = "<redacted-path>";

export function isRedactedPath(path: string): boolean {
  return path === REDACTED_PATH;
}

/** Display name of a listed file: the server's `name`, else the path's final component. */
export function fileRowName(name: string | undefined, path: string): string {
  return name ?? path.split("/").pop() ?? "";
}
