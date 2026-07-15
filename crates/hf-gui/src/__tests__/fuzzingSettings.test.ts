import { describe, expect, it } from "vitest";
import {
  DEFAULT_FUZZING_SETTINGS,
  enabledEngineOptions,
  fuzzingActionsEnabled,
  loadEffectiveFuzzingSettings,
  normalizeFuzzingSettings,
  patchFuzzingSettings,
  validateEffectiveFuzzingSettings,
} from "../lib/fuzzingSettings";

describe("fuzzing settings", () => {
  it("normalizes persisted values and drops unknown engines", () => {
    const settings = normalizeFuzzingSettings({
      fuzzing: {
        enabled_engines: ["unknown", "afl++", "afl++", "honggfuzz"],
        default_engine: "unknown",
        default_duration_secs: 45,
        sandbox: { max_mem_mb: 3072, max_cpus: 2, max_duration_secs: 600 },
      },
    });

    expect(settings.enabled_engines).toEqual(["afl++", "honggfuzz"]);
    expect(settings.default_engine).toBe("afl++");
    expect(settings.default_duration_secs).toBe(45);
    expect(settings.sandbox).toEqual({
      max_mem_mb: 3072,
      max_cpus: 2,
      max_duration_secs: 600,
    });
  });

  it("falls back to safe defaults when the stored shape is unusable", () => {
    expect(normalizeFuzzingSettings({ fuzzing: { enabled_engines: [] } }))
      .toEqual(DEFAULT_FUZZING_SETTINGS);
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
