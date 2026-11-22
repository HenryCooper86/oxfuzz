// Typed helpers for the settings and integration controls added for
// command-line parity: webhook alerts, provider thaw, limits and event
// triggers.

import type { ProtectedValueDraft } from "./integrationSettings";

export type WebhookFormat = "json" | "slack";

/** Editable webhook alert settings. The bearer token is write-only. */
export interface NotificationsDraft {
  webhook_url: string;
  format: WebhookFormat;
  bearer_token: ProtectedValueDraft;
  bearer_token_env: string;
  verify_tls: boolean;
}

/** The config section as the service stores it. */
export interface NotificationsConfig {
  webhook_url?: string;
  format?: string;
  bearer_token?: string;
  bearer_token_env?: string;
  verify_tls?: boolean;
}

export function notificationsDraftFromConfig(config: NotificationsConfig): NotificationsDraft {
  return {
    webhook_url: config.webhook_url ?? "",
    format: config.format === "slack" ? "slack" : "json",
    // The stored token is never copied into the draft: only whether one exists.
    bearer_token: {
      configured: typeof config.bearer_token === "string" && config.bearer_token.length > 0,
      change: "keep",
      replacement: "",
    },
    bearer_token_env: config.bearer_token_env ?? "",
    verify_tls: config.verify_tls ?? true,
  };
}

/**
 * Build the config object to write. `existingToken` is the token read from the
 * file; it is carried through only when the operator left the token unchanged.
 */
export function notificationsConfigFromDraft(
  draft: NotificationsDraft,
  existingToken?: string,
): NotificationsConfig {
  const config: NotificationsConfig = {
    webhook_url: draft.webhook_url.trim(),
    format: draft.format,
    bearer_token_env: draft.bearer_token_env.trim(),
    verify_tls: draft.verify_tls,
  };
  const token = draft.bearer_token;
  if (token.change === "replace") {
    if (token.replacement.length > 0) config.bearer_token = token.replacement;
  } else if (token.change === "keep" && existingToken) {
    config.bearer_token = existingToken;
  }
  return config;
}

/** Event names the scheduler accepts for an `event` trigger. */
export const SCHEDULE_EVENT_TYPES: readonly string[] = [
  "crash.found",
  "run.completed",
  "run.failed",
  "campaign.health",
];

export const AUDIT_LIMITS: readonly number[] = [50, 200, 1000];
export const DEFAULT_AUDIT_LIMIT = 200;
export const DEFAULT_KNOWLEDGE_LIMIT = 10;

/** Parse a positive integer limit, falling back to the default. */
export function parseKnowledgeLimit(text: string): number {
  const value = Number(text.trim());
  return Number.isSafeInteger(value) && value >= 1 && value <= 100 ? value : DEFAULT_KNOWLEDGE_LIMIT;
}

/** Human label for an issue-tracker provider id. */
export function issueProviderLabel(provider: string): string {
  switch (provider.trim().toLowerCase()) {
    case "github":
      return "GitHub";
    case "jira":
      return "Jira";
    case "gitlab":
      return "GitLab";
    default:
      return provider;
  }
}
