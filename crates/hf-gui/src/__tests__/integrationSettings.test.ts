import { describe, expect, it } from "vitest";
import {
  defectDojoDraftFromPublic,
  defectDojoPatchFromDraft,
  issueTrackerDraftFromPublic,
  issueTrackerPatchFromDraft,
  type DefectDojoPublicConfig,
  type IssueTrackerPublicConfig,
} from "../lib/integrationSettings";

const dojoPublic: DefectDojoPublicConfig = {
  url: "https://dojo.example.test",
  api_token_configured: true,
  api_token_env_configured: true,
  verify_tls: true,
  product_name: "hobot_fuzz",
  product_type_name: null,
  engagement_name: null,
  auto_create: true,
  reimport: true,
  lifecycle: {
    autostart: false,
    compose_project: { configured: false, value: null },
    compose_files_configured: true,
    startup_timeout_secs: 180,
  },
};

const trackerPublic: IssueTrackerPublicConfig = {
  provider: "gitlab",
  host: "https://gitlab.example.test",
  repo: { configured: true, value: "security/hobot_fuzz" },
  api_token_configured: true,
  api_token_env_configured: false,
  username: null,
  labels: ["fuzzing", "security"],
  verify_tls: true,
};

describe("typed integration settings", () => {
  it("creates editable drafts without inventing protected values", () => {
    const dojo = defectDojoDraftFromPublic(dojoPublic);
    const tracker = issueTrackerDraftFromPublic(trackerPublic);

    expect(dojo.api_token).toEqual({ configured: true, change: "keep", replacement: "" });
    expect(dojo.api_token_env).toEqual({ configured: true, change: "keep", replacement: "" });
    expect(dojo.lifecycle.compose_files).toEqual({ configured: true, change: "keep", replacement: "" });
    expect(dojo.lifecycle.compose_project).toMatchObject({ configured: false, change: "keep" });
    expect(tracker.api_token).toEqual({ configured: true, change: "keep", replacement: "" });
    expect(tracker.api_token_env).toEqual({ configured: false, change: "keep", replacement: "" });
    expect(tracker.repo).toMatchObject({
      configured: true,
      change: "keep",
      current: "security/hobot_fuzz",
    });
  });

  it("omits protected values when saving an unchanged draft", () => {
    const dojoPatch = defectDojoPatchFromDraft(defectDojoDraftFromPublic(dojoPublic));
    const trackerPatch = issueTrackerPatchFromDraft(issueTrackerDraftFromPublic(trackerPublic));

    expect(dojoPatch).not.toHaveProperty("api_token");
    expect(dojoPatch).not.toHaveProperty("api_token_env");
    expect(dojoPatch.lifecycle).not.toHaveProperty("compose_files");
    expect(dojoPatch.lifecycle).not.toHaveProperty("compose_project");
    expect(trackerPatch).not.toHaveProperty("api_token");
    expect(trackerPatch).not.toHaveProperty("api_token_env");
    expect(trackerPatch).not.toHaveProperty("repo");
    expect(dojoPatch.product_type_name).toEqual({ operation: "clear" });
    expect(trackerPatch.labels).toEqual(["fuzzing", "security"]);
  });

  it("encodes protected replacement and clear operations explicitly", () => {
    const dojo = defectDojoDraftFromPublic(dojoPublic);
    dojo.api_token = { ...dojo.api_token, change: "replace", replacement: "new-dojo-token" };
    dojo.api_token_env = { ...dojo.api_token_env, change: "clear" };
    dojo.lifecycle.compose_files = {
      ...dojo.lifecycle.compose_files,
      change: "replace",
      replacement: "/safe/compose.yml\n/safe/override.yml",
    };
    dojo.lifecycle.compose_project = {
      ...dojo.lifecycle.compose_project,
      change: "replace",
      replacement: "dojo-main",
    };

    const tracker = issueTrackerDraftFromPublic(trackerPublic);
    tracker.api_token = { ...tracker.api_token, change: "clear" };
    tracker.api_token_env = {
      ...tracker.api_token_env,
      change: "replace",
      replacement: "HOBOT_GITLAB_TOKEN",
    };
    tracker.repo = { ...tracker.repo, change: "clear" };

    expect(defectDojoPatchFromDraft(dojo)).toMatchObject({
      api_token: { operation: "replace", value: "new-dojo-token" },
      api_token_env: { operation: "clear" },
      lifecycle: {
        compose_project: { operation: "replace", value: "dojo-main" },
        compose_files: {
          operation: "replace",
          value: ["/safe/compose.yml", "/safe/override.yml"],
        },
      },
    });
    expect(issueTrackerPatchFromDraft(tracker)).toMatchObject({
      api_token: { operation: "clear" },
      api_token_env: { operation: "replace", value: "HOBOT_GITLAB_TOKEN" },
      repo: { operation: "clear" },
    });
  });

  it("keeps hidden legacy paths opaque and never sends a redaction marker", () => {
    const dojo = defectDojoDraftFromPublic({
      ...dojoPublic,
      lifecycle: {
        ...dojoPublic.lifecycle,
        compose_project: { configured: true, value: null },
      },
    });
    const tracker = issueTrackerDraftFromPublic({
      ...trackerPublic,
      repo: { configured: true, value: null },
    });

    expect(dojo.lifecycle.compose_project).toMatchObject({ configured: true, change: "keep" });
    expect(tracker.repo).toMatchObject({ configured: true, change: "keep" });
    expect(JSON.stringify({ dojo, tracker })).not.toContain("<redacted-path>");

    const dojoPatch = defectDojoPatchFromDraft(dojo);
    const trackerPatch = issueTrackerPatchFromDraft(tracker);
    expect(dojoPatch.lifecycle).not.toHaveProperty("compose_project");
    expect(trackerPatch).not.toHaveProperty("repo");
    expect(JSON.stringify({ dojoPatch, trackerPatch })).not.toContain("<redacted-path>");
  });

  it("rejects an empty protected replacement instead of silently preserving it", () => {
    const draft = issueTrackerDraftFromPublic(trackerPublic);
    draft.api_token = { ...draft.api_token, change: "replace", replacement: "  " };

    expect(() => issueTrackerPatchFromDraft(draft)).toThrow("replacement cannot be empty");
  });
});
