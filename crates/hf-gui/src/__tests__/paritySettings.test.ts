import { describe, expect, it } from "vitest";
import {
  issueProviderLabel,
  notificationsConfigFromDraft,
  notificationsDraftFromConfig,
  parseKnowledgeLimit,
  SCHEDULE_EVENT_TYPES,
} from "../lib/paritySettings";

describe("notifications draft", () => {
  it("never copies the stored bearer token into the draft", () => {
    const draft = notificationsDraftFromConfig({
      webhook_url: "https://hooks.example.test/a",
      format: "slack",
      bearer_token: "s3cret-token",
    });
    expect(JSON.stringify(draft)).not.toContain("s3cret-token");
    expect(draft.bearer_token).toEqual({ configured: true, change: "keep", replacement: "" });
    expect(draft.format).toBe("slack");
    expect(draft.verify_tls).toBe(true);
  });

  it("keeps, replaces and clears the token on save", () => {
    const base = notificationsDraftFromConfig({ webhook_url: "", bearer_token: "old" });
    expect(notificationsConfigFromDraft(base, "old").bearer_token).toBe("old");
    const replaced = { ...base, bearer_token: { ...base.bearer_token, change: "replace" as const, replacement: "new" } };
    expect(notificationsConfigFromDraft(replaced, "old").bearer_token).toBe("new");
    const cleared = { ...base, bearer_token: { ...base.bearer_token, change: "clear" as const } };
    expect(notificationsConfigFromDraft(cleared, "old")).not.toHaveProperty("bearer_token");
  });
});

describe("limits and labels", () => {
  it("falls back to 10 for an invalid knowledge limit", () => {
    expect(parseKnowledgeLimit("")).toBe(10);
    expect(parseKnowledgeLimit("0")).toBe(10);
    expect(parseKnowledgeLimit("25")).toBe(25);
  });
  it("names Jira drafts Jira", () => {
    expect(issueProviderLabel("jira")).toBe("Jira");
    expect(issueProviderLabel("gitlab")).toBe("GitLab");
    expect(issueProviderLabel("github")).toBe("GitHub");
  });
  it("lists the service event names", () => {
    expect(SCHEDULE_EVENT_TYPES).toContain("crash.found");
  });
});
