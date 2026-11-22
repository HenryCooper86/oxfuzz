// Typed wrappers for the harness options the command line already offers.
import { getTransport } from "./index";

export type HarnessSanitizer = "address" | "undefined" | "thread" | "memory";
export type HarnessAiPolicy = "auto" | "require" | "off";

/** Build-variant selection sent as the optional `build` argument. */
export interface HarnessBuildOptions {
  sanitizer?: HarnessSanitizer;
  cmplog?: boolean;
  persistent?: boolean;
}

/** Everything the harness options section lets a person choose. */
export interface HarnessOptions {
  sanitizer: HarnessSanitizer;
  cmplog: boolean;
  persistent: boolean;
  repairs: number;
  skipModelReview: boolean;
}

export const DEFAULT_HARNESS_OPTIONS: HarnessOptions = {
  sanitizer: "address",
  cmplog: false,
  persistent: false,
  repairs: 0,
  skipModelReview: false,
};

export const MAX_REPAIRS = 5;

export function clampRepairs(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(MAX_REPAIRS, Math.max(0, Math.trunc(value)));
}

/** `build` for draft and compile; undefined (omitted) when every choice is the default. */
export function buildOptionsFor(options: HarnessOptions, engine: string): HarnessBuildOptions | undefined {
  const aflOnly = engine === "afl++";
  const build: HarnessBuildOptions = {};
  if (options.sanitizer !== "address") build.sanitizer = options.sanitizer;
  if (aflOnly && options.cmplog) build.cmplog = true;
  if (aflOnly && options.persistent) build.persistent = true;
  return Object.keys(build).length > 0 ? build : undefined;
}

/** The plain `harness_smoke` stays in use unless a smoke-only option is set. */
export function needsSmokeOptions(options: HarnessOptions): boolean {
  return options.repairs > 0 || options.skipModelReview;
}

export interface HarnessScope {
  project: string;
  target: string;
  engine: string;
  lang: string;
}

export interface RefineResult {
  status: string;
  harness_id: string;
  repairs_used: number;
  lint: unknown;
}

export function refineHarness(scope: HarnessScope, repairs: number, ai: HarnessAiPolicy): Promise<RefineResult> {
  return getTransport().invoke<RefineResult>("harness_refine", { ...scope, repairs, ai });
}

export function adoptHarnessRevision(scope: HarnessScope, harnessId: string): Promise<{ status: string }> {
  return getTransport().invoke<{ status: string }>("harness_adopt_revision", { ...scope, harnessId });
}

export function grammarMutatorSource(grammar: string, engine: string): Promise<string> {
  return getTransport().invoke<string>("grammar_mutator_source", { grammar, engine });
}

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
