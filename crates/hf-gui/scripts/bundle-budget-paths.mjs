/** Convert a host path into the separator format used by Vite manifests. */
export function normalizeAssetPath(path) {
  return path.replaceAll("\\", "/");
}
