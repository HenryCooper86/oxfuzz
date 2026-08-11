export const FUZZING_ENGINE_OPTIONS = [
  { value: "libfuzzer", label: "libFuzzer" },
  { value: "afl++", label: "AFL++" },
  { value: "honggfuzz", label: "honggfuzz" },
  { value: "syzkaller", label: "syzkaller (kernel)" },
] as const;

export type FuzzingEngineId = (typeof FUZZING_ENGINE_OPTIONS)[number]["value"];

export interface FuzzingSandboxSettings {
  max_mem_mb: number;
  max_cpus: number;
  max_duration_secs: number;
}

export interface FuzzingSettings {
  enabled_engines: FuzzingEngineId[];
  default_engine: FuzzingEngineId;
  default_duration_secs: number;
  sandbox: FuzzingSandboxSettings;
}

export type FuzzingSettingsNormalization =
  | { settings: FuzzingSettings; error: null }
  | { settings: null; error: "retired_engine" };

/** A fuzzing action is available only after the typed service policy validates. */
export function fuzzingActionsEnabled(
  settings: FuzzingSettings | null,
): settings is FuzzingSettings {
  return settings !== null;
}

export const DEFAULT_FUZZING_SETTINGS: FuzzingSettings = {
  enabled_engines: FUZZING_ENGINE_OPTIONS.map((option) => option.value),
  default_engine: "libfuzzer",
  default_duration_secs: 60,
  sandbox: {
    max_mem_mb: 2048,
    max_cpus: 1,
    max_duration_secs: 7200,
  },
};

const ENGINE_IDS = new Set<string>(FUZZING_ENGINE_OPTIONS.map((option) => option.value));
const RETIRED_ENGINE_IDS = new Set(["clusterfuzzlite", "cfl", "cflite"]);

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function positiveInteger(value: unknown, fallback: number, maximum: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= maximum
    ? value
    : fallback;
}

function cloneDefaults(): FuzzingSettings {
  return {
    ...DEFAULT_FUZZING_SETTINGS,
    enabled_engines: [...DEFAULT_FUZZING_SETTINGS.enabled_engines],
    sandbox: { ...DEFAULT_FUZZING_SETTINGS.sandbox },
  };
}

function isRetiredEngineId(value: unknown): boolean {
  return typeof value === "string" && RETIRED_ENGINE_IDS.has(value.trim().toLowerCase());
}

function boundedPositiveInteger(value: unknown, maximum: number): value is number {
  return typeof value === "number"
    && Number.isSafeInteger(value)
    && value > 0
    && value <= maximum;
}

/** Validate the service-owned effective policy without widening malformed data. */
export function validateEffectiveFuzzingSettings(value: unknown): FuzzingSettings | null {
  const root = asRecord(value);
  const rawEnabled = root.enabled_engines;
  if (!Array.isArray(rawEnabled) || rawEnabled.length === 0) return null;
  if (!rawEnabled.every((engine) => typeof engine === "string" && ENGINE_IDS.has(engine))) return null;
  const enabled = rawEnabled as FuzzingEngineId[];
  if (new Set(enabled).size !== enabled.length) return null;

  const defaultEngine = root.default_engine;
  if (typeof defaultEngine !== "string" || !enabled.includes(defaultEngine as FuzzingEngineId)) return null;

  const sandbox = asRecord(root.sandbox);
  if (!boundedPositiveInteger(sandbox.max_mem_mb, 64 * 1024)) return null;
  if (!boundedPositiveInteger(sandbox.max_cpus, 64)) return null;
  if (!boundedPositiveInteger(sandbox.max_duration_secs, 7 * 24 * 60 * 60)) return null;
  if (!boundedPositiveInteger(root.default_duration_secs, sandbox.max_duration_secs)) return null;

  return {
    enabled_engines: [...enabled],
    default_engine: defaultEngine as FuzzingEngineId,
    default_duration_secs: root.default_duration_secs,
    sandbox: {
      max_mem_mb: sandbox.max_mem_mb,
      max_cpus: sandbox.max_cpus,
      max_duration_secs: sandbox.max_duration_secs,
    },
  };
}

/** Load the service-validated policy; an unavailable or malformed response is fatal. */
export async function loadEffectiveFuzzingSettings(
  invoke: (command: string) => Promise<unknown>,
): Promise<FuzzingSettings> {
  const value = await invoke("get_fuzzing_settings");
  const settings = validateEffectiveFuzzingSettings(value);
  if (!settings) throw new Error("invalid fuzzing policy response");
  return settings;
}

/** Convert the untyped global TOML value into the validated UI shape. */
export function normalizeFuzzingSettings(root: unknown): FuzzingSettingsNormalization {
  const fuzzing = asRecord(asRecord(root).fuzzing);
  const rawEnabled = Array.isArray(fuzzing.enabled_engines) ? fuzzing.enabled_engines : [];
  if (rawEnabled.some(isRetiredEngineId) || isRetiredEngineId(fuzzing.default_engine)) {
    return { settings: null, error: "retired_engine" };
  }
  const enabled = [...new Set(rawEnabled.filter(
    (engine): engine is FuzzingEngineId => typeof engine === "string" && ENGINE_IDS.has(engine),
  ))];
  if (enabled.length === 0) return { settings: cloneDefaults(), error: null };

  const sandbox = asRecord(fuzzing.sandbox);
  const maxDuration = positiveInteger(
    sandbox.max_duration_secs,
    DEFAULT_FUZZING_SETTINGS.sandbox.max_duration_secs,
    7 * 24 * 60 * 60,
  );
  const requestedDefault = positiveInteger(
    fuzzing.default_duration_secs,
    DEFAULT_FUZZING_SETTINGS.default_duration_secs,
    maxDuration,
  );
  const rawDefault = fuzzing.default_engine;
  const defaultEngine = typeof rawDefault === "string" && enabled.includes(rawDefault as FuzzingEngineId)
    ? rawDefault as FuzzingEngineId
    : enabled[0];

  return {
    settings: {
      enabled_engines: enabled,
      default_engine: defaultEngine,
      default_duration_secs: requestedDefault,
      sandbox: {
        max_mem_mb: positiveInteger(
          sandbox.max_mem_mb,
          DEFAULT_FUZZING_SETTINGS.sandbox.max_mem_mb,
          64 * 1024,
        ),
        max_cpus: positiveInteger(
          sandbox.max_cpus,
          DEFAULT_FUZZING_SETTINGS.sandbox.max_cpus,
          64,
        ),
        max_duration_secs: maxDuration,
      },
    },
    error: null,
  };
}

/** Replace only `[fuzzing]`, preserving every unrelated global setting. */
export function patchFuzzingSettings(
  root: Record<string, unknown>,
  settings: FuzzingSettings,
): Record<string, unknown> {
  return {
    ...root,
    fuzzing: {
      ...settings,
      enabled_engines: [...settings.enabled_engines],
      sandbox: { ...settings.sandbox },
    },
  };
}

interface EngineOptionFilter {
  includeSyzkaller?: boolean;
  language?: string;
}

/** Engine choices permitted by both operator policy and harness capabilities. */
export function enabledEngineOptions(
  settings: Pick<FuzzingSettings, "enabled_engines"> | { enabled_engines: readonly string[] },
  { includeSyzkaller = false, language }: EngineOptionFilter = {},
) {
  const enabled = new Set(settings.enabled_engines);
  return FUZZING_ENGINE_OPTIONS.filter((option) => {
    if (!enabled.has(option.value)) return false;
    if (language !== undefined) {
      if (option.value === "syzkaller") return false;
      if (language === "rust") return option.value === "libfuzzer";
      if (language === "go" || language === "python") {
        // Discovery scans Go/Python, but no engine adapter builds those
        // harness languages yet (EngineKind::supports_language in hf-core);
        // returning no options keeps the harness action disabled.
        return false;
      }
    }
    if (option.value === "syzkaller") return includeSyzkaller;
    return true;
  });
}
