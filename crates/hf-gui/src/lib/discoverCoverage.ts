export function shouldLoadCoverage(
  opening: boolean,
  covered: Set<string> | null,
  loading: boolean,
  project: string,
): boolean {
  return opening && covered === null && !loading && project.length > 0;
}
