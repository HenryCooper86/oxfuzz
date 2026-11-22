import "../i18n.parityRun";
// Typed wrappers and option helpers for the run surfaces that mirror the
// command line: per-run options, campaigns, the CI gate, dictionaries and the
// engine preflight. The Tauri commands own all behavior; this file only shapes
// arguments and results.
import { getTransport } from "./index";

export type AiPolicy = "auto" | "require" | "off";
export type SanitizerChoice = "none" | "address" | "undefined" | "memory" | "thread";

/** Form state for the per-run options; strings so partial typing is kept. */
export interface RunOptionsState {
  seed: string;
  cpus: string;
  timeoutMs: string;
  resume: boolean;
  sanitizer: SanitizerChoice;
  cmplog: boolean;
  ai: AiPolicy;
}

export const DEFAULT_RUN_OPTIONS: RunOptionsState = {
  seed: "",
  cpus: "",
  timeoutMs: "",
  resume: false,
  sanitizer: "none",
  cmplog: false,
  ai: "auto",
};

/** The `options` argument of `run_fuzzer` (camelCase on the wire). */
export interface RunFuzzerOptions {
  cpus?: number;
  timeoutMs?: number;
  resume?: boolean;
  sanitizer?: string;
  cmplog?: boolean;
  ai?: AiPolicy;
}

const U64_MAX = 18446744073709551615n;

export function isAflEngine(engine: string): boolean {
  return engine === "afl++" || engine === "aflplusplus";
}

/** Translation key of the first invalid field, or null when all are valid. */
export function runOptionsError(
  state: RunOptionsState,
  limits: { maxCpus: number | null; showCpus?: boolean },
): string | null {
  if (state.seed !== "" && (!/^\d+$/.test(state.seed) || BigInt(state.seed) > U64_MAX)) {
    return "runOpts.seedInvalid";
  }
  if (limits.showCpus !== false && state.cpus !== "") {
    const cpus = Number(state.cpus);
    if (!Number.isInteger(cpus) || cpus < 1 || (limits.maxCpus !== null && cpus > limits.maxCpus)) {
      return "runOpts.cpusInvalid";
    }
  }
  if (state.timeoutMs !== "") {
    const timeout = Number(state.timeoutMs);
    if (!Number.isSafeInteger(timeout) || timeout < 1) return "runOpts.timeoutInvalid";
  }
  return null;
}

/**
 * Convert form state into the wire arguments. Untouched fields are omitted so
 * a plain run sends exactly what it sent before these options existed.
 */
export function buildRunOptions(
  state: RunOptionsState,
  engine: string,
  includeCpus = true,
): { seed?: string; options?: RunFuzzerOptions } {
  const options: RunFuzzerOptions = {};
  if (includeCpus && state.cpus !== "") options.cpus = Number(state.cpus);
  if (state.timeoutMs !== "") options.timeoutMs = Number(state.timeoutMs);
  if (isAflEngine(engine)) {
    if (state.resume) options.resume = true;
    if (state.cmplog) options.cmplog = true;
  }
  if (state.sanitizer !== "none") options.sanitizer = state.sanitizer;
  if (state.ai !== "auto") options.ai = state.ai;
  const built: { seed?: string; options?: RunFuzzerOptions } = {};
  if (state.seed !== "") built.seed = state.seed;
  if (Object.keys(options).length > 0) built.options = options;
  return built;
}

export interface CampaignRefine {
  note: string;
  harness_id?: string | null;
  compiled?: boolean;
  frontier_locations?: number;
}

export interface CampaignOutcome {
  target: string;
  harness_status: string;
  crashes: number;
  edges: number;
  iterations: number;
  auto_reverts: number;
  hangs?: number | null;
  termination: string;
  refine?: CampaignRefine | null;
}

export interface CiFinding {
  kind: string;
  summary: string;
}

export interface CiGateOutcome {
  passed: boolean;
  findings: CiFinding[];
  seed_warning: string | null;
  sarif: string;
}

export interface PreflightResult {
  engine: string;
  status: Record<string, boolean>;
  provider_configured: boolean | null;
  ready: boolean;
  problems: string[];
}

export interface CampaignProgress {
  type: string;
  data: unknown;
}

export interface CampaignRequest {
  project: string;
  target?: string;
  engine: string;
  lang?: string;
  durationSecs: number;
  iterations: number;
  timeoutMs?: number;
  resume?: boolean;
  sanitizer?: string;
  cmplog?: boolean;
  seed?: string;
  ai?: AiPolicy;
}

/** Assemble `run_campaign`'s `options` object from form state. */
export function campaignRequest(
  base: { project: string; target: string; engine: string; lang: string; durationSecs: number; iterations: number },
  state: RunOptionsState,
): CampaignRequest {
  const { seed, options } = buildRunOptions(state, base.engine, false);
  const request: CampaignRequest = {
    project: base.project,
    engine: base.engine,
    lang: base.lang,
    durationSecs: base.durationSecs,
    iterations: base.iterations,
  };
  if (base.target.trim() !== "") request.target = base.target.trim();
  if (seed !== undefined) request.seed = seed;
  if (options?.timeoutMs !== undefined) request.timeoutMs = options.timeoutMs;
  if (options?.resume !== undefined) request.resume = options.resume;
  if (options?.sanitizer !== undefined) request.sanitizer = options.sanitizer;
  if (options?.cmplog !== undefined) request.cmplog = options.cmplog;
  if (options?.ai !== undefined) request.ai = options.ai;
  return request;
}

/** Status flag of the preflight that matters for an engine, if it has one. */
export function engineStatusKey(engine: string): string | null {
  switch (engine) {
    case "libfuzzer":
      return "libfuzzer";
    case "afl++":
    case "aflplusplus":
      return "aflplusplus";
    case "honggfuzz":
      return "honggfuzz";
    case "syzkaller":
      return "syzkaller";
    case "atheris":
      return "atheris";
    case "jazzer":
      return "jazzer";
    case "jazzer-js":
      return "jazzer_js";
    default:
      return null;
  }
}

/**
 * A dictionary token is delimited by straight double quotes. The macOS
 * webview substitutes curly ones while the operator types, which the parser
 * refuses, so typed text is normalized. File contents are left as they are.
 */
export function straightQuotes(text: string): string {
  return text.replace(/[\u201c\u201d\u201e\u201f]/g, '"');
}

export const runApi = {
  campaign: (options: CampaignRequest) =>
    getTransport().invoke<CampaignOutcome>("run_campaign", { options }),
  ciGate: (args: { project: string; target: string; engine: string; durationSecs: number; ai?: AiPolicy }) =>
    getTransport().invoke<CiGateOutcome>("run_ci_gate", args),
  saveText: (args: { fileName: string; extensions: string[]; contents: string }) =>
    getTransport().invoke<string | null>("save_text_file", args),
  dictionary: (project: string, target: string) =>
    getTransport().invoke<string | null>("user_dictionary", { project, target }),
  setDictionary: (project: string, target: string, text: string) =>
    getTransport().invoke<number>("set_user_dictionary", { project, target, text }),
  clearDictionary: (project: string, target: string) =>
    getTransport().invoke<void>("clear_user_dictionary", { project, target }),
  preflight: (args: { engine: string; durationSecs?: number; requireProvider?: boolean }) =>
    getTransport().invoke<PreflightResult>("fuzzing_preflight", args),
};
