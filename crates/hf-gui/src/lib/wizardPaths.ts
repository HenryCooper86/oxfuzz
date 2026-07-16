export interface WizardAppPaths {
  data_dir: string;
  workspace_dir: string;
}

export interface WizardStoragePaths {
  database: string;
  transcripts: string;
  workspace: string;
}

function joinDisplayPath(root: string, child: string): string {
  const trimmed = root.replace(/[\\/]+$/, "");
  const separator = trimmed.includes("\\") && !trimmed.includes("/") ? "\\" : "/";
  return `${trimmed}${separator}${child}`;
}

/** Derive setup-wizard labels from the service-resolved application paths. */
export function wizardStoragePaths(paths: WizardAppPaths): WizardStoragePaths {
  return {
    database: joinDisplayPath(paths.data_dir, "hobot_fuzz.db"),
    transcripts: joinDisplayPath(paths.data_dir, "transcripts"),
    workspace: paths.workspace_dir,
  };
}
