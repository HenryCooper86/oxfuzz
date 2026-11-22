// Typed helpers for the discovery, run-list and scheduler controls added for
// command-line parity: Clang analysis, the ranking model policy, run-list
// filters, a run's full record, work-order export and arming another server.

import { getTransport } from "../lib";

export type RankingPolicy = "auto" | "require" | "off";
export const RANKING_POLICIES: RankingPolicy[] = ["auto", "require", "off"];

/** `oxfuzz runs --active` and `--limit`. */
export interface RunListFilter {
  activeOnly: boolean;
  limit: number | null;
}
export const RUN_LIST_LIMITS = [10, 20, 50, 100];

const ACTIVE_STATUSES = new Set(["pending", "running"]);

export function filterRuns<T extends { status: string }>(runs: T[], filter: RunListFilter): T[] {
  const kept = filter.activeOnly
    ? runs.filter((run) => ACTIVE_STATUSES.has(run.status.toLowerCase()))
    : runs;
  return filter.limit === null ? kept : kept.slice(0, filter.limit);
}

export type ClangState =
  | "staging" | "analyzing" | "validating" | "done" | "failed" | "cancelled" | "interrupted";

export interface ClangOperation {
  id: string;
  state: ClangState;
  failure: string | null;
}

export interface ClangResult {
  index: { clang_version: string; units: unknown[]; functions: unknown[]; calls: unknown[] };
}

export function clangIsTerminal(state: ClangState): boolean {
  return state === "done" || state === "failed" || state === "cancelled" || state === "interrupted";
}

export function clangSupportsLanguage(lang: string): boolean {
  return lang === "c" || lang === "cpp";
}

export type RemoteArmAction = "arm" | "disarm" | "status";

export const discoveryApi = {
  clangAvailable: () => getTransport().invoke<boolean>("clang_available"),
  clangStart: (project: string, lang: string) =>
    getTransport().invoke<ClangOperation>("clang_analysis_start", { project, lang }),
  clangStatus: (operationId: string) =>
    getTransport().invoke<ClangOperation | null>("clang_analysis_status", { operationId }),
  clangResult: (operationId: string) =>
    getTransport().invoke<ClangResult | null>("clang_analysis_result", { operationId }),
  clangCancel: (operationId: string) =>
    getTransport().invoke<ClangOperation | null>("clang_analysis_cancel", { operationId }),
  runDetail: (runId: string) =>
    getTransport().invoke<Record<string, unknown>>("run_detail", { runId }),
  remoteArm: (url: string, action: RemoteArmAction, token: string) =>
    getTransport().invoke<boolean | null>("remote_schedule_arm", {
      url,
      action,
      token: token.length > 0 ? token : undefined,
    }),
};

/** Write a work order packet to a file the operator picks. Null when cancelled. */
export function saveWorkOrderPacket<T extends { id: string }>(order: T): Promise<string | null> {
  return getTransport().invoke<string | null>("save_text_file", {
    fileName: `harness-work-order-${order.id}.json`,
    extensions: ["json"],
    contents: JSON.stringify(order, null, 2),
  });
}

export interface RestServerInfo {
  url: string;
  project_roots: string[];
}
export interface RestServerStarted extends RestServerInfo {
  token: string;
}
export const DEFAULT_REST_PORT = 8081;

export const restServerApi = {
  status: () => getTransport().invoke<RestServerInfo | null>("rest_server_status"),
  start: (port: number, projectRoots: string[]) =>
    getTransport().invoke<RestServerStarted>("rest_server_start", { port, projectRoots }),
  stop: () => getTransport().invoke<boolean>("rest_server_stop"),
};
