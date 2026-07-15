export type SectionId =
  | "general"
  | "fuzzing"
  | "automotive"
  | "providers"
  | "storage"
  | "integrations"
  | "issuetracker"
  | "about";

export interface SettingsSectionDefinition {
  id: SectionId;
  label: string;
  /** Raw config section name, or null when the section is operational UI only. */
  config: string | null;
}

/** Settings sections that are truthful about whether edits affect production. */
export const SETTINGS_SECTION_DEFINITIONS: readonly SettingsSectionDefinition[] = [
  { id: "general", label: "General", config: null },
  { id: "fuzzing", label: "Fuzzing", config: "hobot-fuzz" },
  { id: "automotive", label: "Automotive", config: "hobot-fuzz" },
  { id: "providers", label: "Providers", config: "providers" },
  { id: "storage", label: "Storage", config: null },
  { id: "integrations", label: "Integrations", config: "defectdojo" },
  { id: "issuetracker", label: "Issue Tracker", config: "issue_tracker" },
  { id: "about", label: "About", config: null },
];
