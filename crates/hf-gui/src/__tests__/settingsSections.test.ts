import { describe, expect, it } from "vitest";
import { SETTINGS_SECTION_DEFINITIONS } from "../components/settings/settingsSections";

describe("settings configuration surface", () => {
  it("only exposes service-consumed files as editable configuration", () => {
    expect(
      SETTINGS_SECTION_DEFINITIONS.filter((section) => section.config !== null).map(
        (section) => section.config,
      ),
    ).toEqual(["providers", "defectdojo", "issue_tracker"]);
  });

  it("keeps workspace cleanup available without presenting storage TOML", () => {
    const storage = SETTINGS_SECTION_DEFINITIONS.find((section) => section.id === "storage");
    expect(storage?.config).toBeNull();
  });
});
