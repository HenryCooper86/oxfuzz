export type ConfigValuePatch<T> =
  | { operation: "replace"; value: T }
  | { operation: "clear" };

export type ProtectedValueChange = "keep" | "replace" | "clear";

export interface ProtectedValueDraft {
  configured: boolean;
  change: ProtectedValueChange;
  replacement: string;
  current?: string;
}

export interface PublicConfigString {
  configured: boolean;
  value: string | null;
}

export interface DefectDojoPublicLifecycle {
  autostart: boolean;
  compose_project: PublicConfigString;
  compose_files_configured: boolean;
  startup_timeout_secs: number | null;
}

export interface DefectDojoPublicConfig {
  url: string;
  api_token_configured: boolean;
  api_token_env_configured: boolean;
  verify_tls: boolean;
  product_name: string | null;
  product_type_name: string | null;
  engagement_name: string | null;
  auto_create: boolean;
  reimport: boolean;
  lifecycle: DefectDojoPublicLifecycle;
}

export interface DefectDojoDraft {
  url: string;
  api_token: ProtectedValueDraft;
  api_token_env: ProtectedValueDraft;
  verify_tls: boolean;
  product_name: string;
  product_type_name: string;
  engagement_name: string;
  auto_create: boolean;
  reimport: boolean;
  lifecycle: {
    autostart: boolean;
    compose_project: ProtectedValueDraft;
    compose_files: ProtectedValueDraft;
    startup_timeout_secs: number | null;
  };
}

export interface DefectDojoConfigPatch {
  url: string;
  api_token?: ConfigValuePatch<string>;
  api_token_env?: ConfigValuePatch<string>;
  verify_tls: boolean;
  product_name: ConfigValuePatch<string>;
  product_type_name: ConfigValuePatch<string>;
  engagement_name: ConfigValuePatch<string>;
  auto_create: boolean;
  reimport: boolean;
  lifecycle: {
    autostart: boolean;
    compose_project?: ConfigValuePatch<string>;
    compose_files?: ConfigValuePatch<string[]>;
    startup_timeout_secs: ConfigValuePatch<number>;
  };
}

export interface IssueTrackerPublicConfig {
  provider: string;
  host: string | null;
  repo: PublicConfigString;
  api_token_configured: boolean;
  api_token_env_configured: boolean;
  username: string | null;
  labels: string[];
  verify_tls: boolean;
}

export interface IssueTrackerDraft {
  provider: string;
  host: string;
  repo: ProtectedValueDraft;
  api_token: ProtectedValueDraft;
  api_token_env: ProtectedValueDraft;
  username: string;
  labels: string[];
  verify_tls: boolean;
}

export interface IssueTrackerConfigPatch {
  provider: string;
  host: ConfigValuePatch<string>;
  repo?: ConfigValuePatch<string>;
  api_token?: ConfigValuePatch<string>;
  api_token_env?: ConfigValuePatch<string>;
  username: ConfigValuePatch<string>;
  labels: string[];
  verify_tls: boolean;
}

function protectedDraft(configured: boolean, current?: string | null): ProtectedValueDraft {
  const safeCurrent = current && !current.includes("<redacted") ? current : undefined;
  return {
    configured,
    change: "keep",
    replacement: "",
    ...(safeCurrent ? { current: safeCurrent } : {}),
  };
}

function optionalStringPatch(value: string): ConfigValuePatch<string> {
  const trimmed = value.trim();
  return trimmed ? { operation: "replace", value: trimmed } : { operation: "clear" };
}

function protectedStringPatch(draft: ProtectedValueDraft): ConfigValuePatch<string> | undefined {
  if (draft.change === "keep") return undefined;
  if (draft.change === "clear") return { operation: "clear" };
  if (!draft.replacement.trim()) throw new Error("protected replacement cannot be empty");
  return { operation: "replace", value: draft.replacement };
}

function protectedListPatch(draft: ProtectedValueDraft): ConfigValuePatch<string[]> | undefined {
  if (draft.change === "keep") return undefined;
  if (draft.change === "clear") return { operation: "clear" };
  const value = draft.replacement
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (value.length === 0) throw new Error("protected replacement cannot be empty");
  return { operation: "replace", value };
}

export function defectDojoDraftFromPublic(config: DefectDojoPublicConfig): DefectDojoDraft {
  return {
    url: config.url,
    api_token: protectedDraft(config.api_token_configured),
    api_token_env: protectedDraft(config.api_token_env_configured),
    verify_tls: config.verify_tls,
    product_name: config.product_name ?? "",
    product_type_name: config.product_type_name ?? "",
    engagement_name: config.engagement_name ?? "",
    auto_create: config.auto_create,
    reimport: config.reimport,
    lifecycle: {
      autostart: config.lifecycle.autostart,
      compose_project: protectedDraft(
        config.lifecycle.compose_project.configured,
        config.lifecycle.compose_project.value,
      ),
      compose_files: protectedDraft(config.lifecycle.compose_files_configured),
      startup_timeout_secs: config.lifecycle.startup_timeout_secs,
    },
  };
}

export function defectDojoPatchFromDraft(draft: DefectDojoDraft): DefectDojoConfigPatch {
  const apiToken = protectedStringPatch(draft.api_token);
  const apiTokenEnv = protectedStringPatch(draft.api_token_env);
  const composeProject = protectedStringPatch(draft.lifecycle.compose_project);
  const composeFiles = protectedListPatch(draft.lifecycle.compose_files);
  return {
    url: draft.url.trim(),
    ...(apiToken ? { api_token: apiToken } : {}),
    ...(apiTokenEnv ? { api_token_env: apiTokenEnv } : {}),
    verify_tls: draft.verify_tls,
    product_name: optionalStringPatch(draft.product_name),
    product_type_name: optionalStringPatch(draft.product_type_name),
    engagement_name: optionalStringPatch(draft.engagement_name),
    auto_create: draft.auto_create,
    reimport: draft.reimport,
    lifecycle: {
      autostart: draft.lifecycle.autostart,
      ...(composeProject ? { compose_project: composeProject } : {}),
      ...(composeFiles ? { compose_files: composeFiles } : {}),
      startup_timeout_secs: draft.lifecycle.startup_timeout_secs === null
        ? { operation: "clear" }
        : { operation: "replace", value: draft.lifecycle.startup_timeout_secs },
    },
  };
}

export function issueTrackerDraftFromPublic(config: IssueTrackerPublicConfig): IssueTrackerDraft {
  return {
    provider: config.provider,
    host: config.host ?? "",
    repo: protectedDraft(config.repo.configured, config.repo.value),
    api_token: protectedDraft(config.api_token_configured),
    api_token_env: protectedDraft(config.api_token_env_configured),
    username: config.username ?? "",
    labels: [...config.labels],
    verify_tls: config.verify_tls,
  };
}

export function issueTrackerPatchFromDraft(draft: IssueTrackerDraft): IssueTrackerConfigPatch {
  const apiToken = protectedStringPatch(draft.api_token);
  const apiTokenEnv = protectedStringPatch(draft.api_token_env);
  const repo = protectedStringPatch(draft.repo);
  return {
    provider: draft.provider.trim().toLowerCase(),
    host: optionalStringPatch(draft.host),
    ...(repo ? { repo } : {}),
    ...(apiToken ? { api_token: apiToken } : {}),
    ...(apiTokenEnv ? { api_token_env: apiTokenEnv } : {}),
    username: optionalStringPatch(draft.username),
    labels: draft.labels.map((label) => label.trim()).filter(Boolean),
    verify_tls: draft.verify_tls,
  };
}
