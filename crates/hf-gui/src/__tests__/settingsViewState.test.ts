import { describe, expect, it, vi } from "vitest";

import {
  beginSettingsSectionLoad,
  completeSettingsSectionLoad,
  confirmSettingsNavigation,
  failSettingsSectionLoad,
  isSettingsSectionReady,
} from "../lib/settingsViewState";

describe("settings section request state", () => {
  it("clears the previous section as soon as a different section starts loading", () => {
    const state = beginSettingsSectionLoad(2, "providers");

    expect(state).toMatchObject({
      requestId: 2,
      requestedSection: "providers",
      loadedSection: null,
      value: null,
      raw: "",
      dirty: false,
      loading: true,
      error: null,
    });
  });

  it("ignores stale load success responses after navigation", () => {
    const current = beginSettingsSectionLoad(2, "providers");
    const stale = completeSettingsSectionLoad(
      current,
      { requestId: 1, sectionId: "fuzzing" },
      { fuzzing: { default_engine: "afl++" } },
      "[fuzzing]",
    );

    expect(stale).toBe(current);
  });

  it("binds successfully loaded data to the requested section", () => {
    const loading = beginSettingsSectionLoad(4, "integrations");
    const loaded = completeSettingsSectionLoad(
      loading,
      { requestId: 4, sectionId: "integrations" },
      { enabled: true },
      "enabled = true",
    );

    expect(loaded).toMatchObject({
      loadedSection: "integrations",
      value: { enabled: true },
      raw: "enabled = true",
      dirty: false,
      loading: false,
      error: null,
    });
  });

  it("only enables a config surface for the section that produced its data", () => {
    const loading = beginSettingsSectionLoad(4, "providers");
    const loaded = completeSettingsSectionLoad(
      loading,
      { requestId: 4, sectionId: "providers" },
      [{ name: "local" }],
      "[[providers]]",
    );

    expect(isSettingsSectionReady(loaded, "providers")).toBe(true);
    expect(isSettingsSectionReady(loaded, "fuzzing")).toBe(false);
    expect(isSettingsSectionReady(loading, "providers")).toBe(false);
  });

  it("keeps failed and stale sections cleared", () => {
    const loading = beginSettingsSectionLoad(5, "issuetracker");
    const failed = failSettingsSectionLoad(
      loading,
      { requestId: 5, sectionId: "issuetracker" },
      "read failed",
    );

    expect(failed).toMatchObject({
      loadedSection: null,
      value: null,
      raw: "",
      dirty: false,
      loading: false,
      error: "read failed",
    });
  });
});

describe("settings dirty navigation", () => {
  it("does not prompt when the current section is clean", async () => {
    const requestConfirmation = vi.fn(async () => false);

    await expect(confirmSettingsNavigation(false, requestConfirmation)).resolves.toBe(true);
    expect(requestConfirmation).not.toHaveBeenCalled();
  });

  it("blocks both navigation actions when discarding dirty state is declined", async () => {
    const requestConfirmation = vi.fn(async () => false);

    await expect(confirmSettingsNavigation(true, requestConfirmation)).resolves.toBe(false);
    expect(requestConfirmation).toHaveBeenCalledOnce();
  });
});
