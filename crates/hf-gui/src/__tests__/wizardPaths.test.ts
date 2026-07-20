import { describe, expect, it } from "vitest";

import { wizardStoragePaths } from "../lib/wizardPaths";

describe("wizardStoragePaths", () => {
  it("uses service-resolved data and workspace locations", () => {
    expect(wizardStoragePaths({
      data_dir: "/Users/operator/Library/Application Support/oxfuzz",
      workspace_dir: "/Users/operator/fuzz-workspace",
    })).toEqual({
      database: "/Users/operator/Library/Application Support/oxfuzz/oxfuzz.db",
      transcripts: "/Users/operator/Library/Application Support/oxfuzz/transcripts",
      workspace: "/Users/operator/fuzz-workspace",
    });
  });

  it("does not duplicate a trailing separator", () => {
    expect(wizardStoragePaths({
      data_dir: "/var/lib/oxfuzz/",
      workspace_dir: "/srv/fuzz/",
    }).database).toBe("/var/lib/oxfuzz/oxfuzz.db");
  });
});
