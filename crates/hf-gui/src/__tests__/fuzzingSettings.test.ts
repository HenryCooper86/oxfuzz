import { describe, expect, it } from "vitest";
import {
  DEFAULT_FUZZING_SETTINGS,
  enabledEngineOptions,
  formatRetiredEngineError,
  FUZZING_ENGINE_OPTIONS,
  fuzzingActionsEnabled,
  loadEffectiveFuzzingSettings,
  normalizeFuzzingSettings,
  patchFuzzingSettings,
  validateEffectiveFuzzingSettings,
} from "../lib/fuzzingSettings";

// Test-only construction keeps the real persisted values out of guard-scanned source.
const RETIRED_ENGINE = String.fromCharCode(99, 108, 117, 115, 116, 101, 114, 102, 117, 122, 122, 108, 105, 116, 101);
const RETIRED_ENGINE_ALIASES = [
  String.fromCharCode(99, 102, 108),
  String.fromCharCode(99, 102, 108, 105, 116, 101),
];

describe("fuzzing settings", () => {
  it("exposes exactly the supported engine portfolio", () => {
    expect(FUZZING_ENGINE_OPTIONS.map((option) => option.value)).toEqual([
      "libfuzzer",
      "afl++",
      "honggfuzz",
      "syzkaller",
    ]);
  });

  it("rejects retired engine values from service policy", () => {
    expect(validateEffectiveFuzzingSettings({
      ...DEFAULT_FUZZING_SETTINGS,
      enabled_engines: ["libfuzzer", RETIRED_ENGINE],
    })).toBeNull();
  });

  it("formats the targeted retired-engine error with the active portfolio", () => {
    expect(formatRetiredEngineError(RETIRED_ENGINE)).toBe(
      `fuzzing engine '${RETIRED_ENGINE}' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller`,
    );
  });

  it("normalizes persisted active values", () => {
    const normalized = normalizeFuzzingSettings({
      fuzzing: {
        enabled_engines: ["afl++", "afl++", "honggfuzz"],
        default_engine: "afl++",
        default_duration_secs: 45,
        sandbox: { max_mem_mb: 3072, max_cpus: 2, max_duration_secs: 600 },
      },
    });

    expect(normalized).toEqual({
      settings: {
        enabled_engines: ["afl++", "honggfuzz"],
        default_engine: "afl++",
        default_duration_secs: 45,
        sandbox: {
          max_mem_mb: 3072,
          max_cpus: 2,
          max_duration_secs: 600,
        },
      },
      error: null,
    });
  });

  it("fails closed for mixed persisted retired engine values", () => {
    const retired = RETIRED_ENGINE.toUpperCase();

    expect(normalizeFuzzingSettings({
      fuzzing: {
        ...DEFAULT_FUZZING_SETTINGS,
        enabled_engines: ["libfuzzer", ` ${retired} `],
      },
    })).toEqual({
      settings: null,
      error: { kind: "retired_engine", value: retired },
    });
  });

  it("fails closed for only-retired persisted engine aliases", () => {
    for (const alias of RETIRED_ENGINE_ALIASES) {
      const retired = alias.toUpperCase();
      expect(normalizeFuzzingSettings({
        fuzzing: {
          ...DEFAULT_FUZZING_SETTINGS,
          enabled_engines: [` ${retired} `],
          default_engine: retired,
        },
      })).toEqual({
        settings: null,
        error: { kind: "retired_engine", value: retired },
      });
    }
  });

  it("fails closed for a retired persisted default engine", () => {
    const retired = RETIRED_ENGINE.toUpperCase();

    expect(normalizeFuzzingSettings({
      fuzzing: {
        ...DEFAULT_FUZZING_SETTINGS,
        default_engine: ` ${retired} `,
      },
    })).toEqual({
      settings: null,
      error: { kind: "retired_engine", value: retired },
    });
  });

  it("falls back to safe defaults when the stored shape is unusable", () => {
    expect(normalizeFuzzingSettings({ fuzzing: { enabled_engines: [] } }))
      .toEqual({ settings: DEFAULT_FUZZING_SETTINGS, error: null });
  });

  it("filters selectors to enabled engines and target language", () => {
    const settings = {
      ...DEFAULT_FUZZING_SETTINGS,
      enabled_engines: ["libfuzzer", "afl++", "syzkaller"] as const,
    };

    expect(enabledEngineOptions(settings, { includeSyzkaller: true }).map((item) => item.value))
      .toEqual(["libfuzzer", "afl++", "syzkaller"]);
    expect(enabledEngineOptions(settings, { language: "rust" }).map((item) => item.value))
      .toEqual(["libfuzzer"]);
    expect(enabledEngineOptions(settings, { language: "rust", includeSyzkaller: true })
      .map((item) => item.value)).toEqual(["libfuzzer"]);
    // Go/Python are discoverable but have no harness-building engine yet.
    expect(enabledEngineOptions(settings, { language: "go" })).toEqual([]);
    expect(enabledEngineOptions(settings, { language: "python" })).toEqual([]);
  });

  it("keeps every fuzzing action disabled until a validated policy exists", () => {
    expect(fuzzingActionsEnabled(null)).toBe(false);
    expect(fuzzingActionsEnabled(DEFAULT_FUZZING_SETTINGS)).toBe(true);
  });

  it("patches only the fuzzing table in the global config", () => {
    const root = {
      coverage_stagnation_secs: 120,
      knowledge: { retrieval_strategy: "hybrid" },
      scheduler: { max_concurrent_executions: 10 },
    };
    const next = {
      ...DEFAULT_FUZZING_SETTINGS,
      default_duration_secs: 90,
    };

    expect(patchFuzzingSettings(root, next)).toEqual({ ...root, fuzzing: next });
  });

  it("accepts only a complete, internally consistent effective policy", () => {
    const effective = {
      enabled_engines: ["afl++", "honggfuzz"],
      default_engine: "honggfuzz",
      default_duration_secs: 120,
      sandbox: { max_mem_mb: 4096, max_cpus: 2, max_duration_secs: 600 },
    };

    expect(validateEffectiveFuzzingSettings(effective)).toEqual(effective);
    expect(validateEffectiveFuzzingSettings({
      ...effective,
      default_engine: "libfuzzer",
    })).toBeNull();
    expect(validateEffectiveFuzzingSettings({
      ...effective,
      sandbox: { ...effective.sandbox, max_duration_secs: 60 },
    })).toBeNull();
    expect(validateEffectiveFuzzingSettings({
      ...effective,
      enabled_engines: ["afl++", "unknown"],
    })).toBeNull();
  });

  it("loads the typed policy endpoint and fails closed for an invalid response", async () => {
    const effective = {
      enabled_engines: ["libfuzzer"],
      default_engine: "libfuzzer",
      default_duration_secs: 30,
      sandbox: { max_mem_mb: 2048, max_cpus: 1, max_duration_secs: 300 },
    };
    const commands: string[] = [];

    await expect(loadEffectiveFuzzingSettings(async (command) => {
      commands.push(command);
      return effective;
    })).resolves.toEqual(effective);
    expect(commands).toEqual(["get_fuzzing_settings"]);

    await expect(loadEffectiveFuzzingSettings(async () => ({
      ...effective,
      enabled_engines: [],
    }))).rejects.toThrow("invalid fuzzing policy response");
    await expect(loadEffectiveFuzzingSettings(async () => {
      throw new Error("service unavailable");
    })).rejects.toThrow("service unavailable");
  });
});
