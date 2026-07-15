import { describe, expect, it } from "vitest";
import { SETTINGS_SECTION_DEFINITIONS } from "../components/settings/settingsSections";

describe("settings configuration surface", () => {
  it("only exposes service-consumed files as editable configuration", () => {
    expect(
      SETTINGS_SECTION_DEFINITIONS.filter((section) => section.config !== null).map(
        (section) => section.config,
      ),
    ).toEqual([
      "hobot-fuzz",
      "hobot-fuzz",
      "providers",
      "defectdojo",
      "issue_tracker",
    ]);
  });

  it("restores fuzzing as a service-consumed global settings section", () => {
    expect(SETTINGS_SECTION_DEFINITIONS.find((section) => section.id === "fuzzing"))
      .toEqual({ id: "fuzzing", label: "Fuzzing", config: "hobot-fuzz" });
  });

  it("adds a typed Automotive policy editor backed by the runtime config", () => {
    expect(SETTINGS_SECTION_DEFINITIONS.find((section) => section.id === "automotive"))
      .toEqual({ id: "automotive", label: "Automotive", config: "hobot-fuzz" });
  });

  it("keeps workspace cleanup available without presenting storage TOML", () => {
    const storage = SETTINGS_SECTION_DEFINITIONS.find((section) => section.id === "storage");
    expect(storage?.config).toBeNull();
  });
});
