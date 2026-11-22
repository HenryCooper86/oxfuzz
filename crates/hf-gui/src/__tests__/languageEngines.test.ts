import { describe, expect, it } from "vitest";
import {
  DEFAULT_FUZZING_SETTINGS,
  FUZZING_ENGINE_OPTIONS,
  enabledEngineOptions,
  engineForLanguage,
  normalizeFuzzingSettings,
  validateEffectiveFuzzingSettings,
} from "../lib/fuzzingSettings";
import { canonicalHarnessEngine, engineDisplayName } from "../lib/harnessScope";
import { parsePersistedTargetSelections } from "../providers/targetSelection";

const ALL = ["libfuzzer", "afl++", "honggfuzz", "syzkaller", "go-native", "atheris", "jazzer", "jazzer-js"];

describe("language engines", () => {
  it("lists the four language engines after the default four", () => {
    expect(FUZZING_ENGINE_OPTIONS.map((o) => o.value)).toEqual(ALL);
  });

  it("keeps the default enabled engines at the service default", () => {
    expect(DEFAULT_FUZZING_SETTINGS.enabled_engines).toEqual(["libfuzzer", "afl++", "honggfuzz", "syzkaller"]);
  });

  it("accepts the new ids in the effective policy and in raw config", () => {
    const enabled = ["libfuzzer", "go-native", "atheris", "jazzer", "jazzer-js"];
    expect(validateEffectiveFuzzingSettings({ ...DEFAULT_FUZZING_SETTINGS, enabled_engines: enabled })?.enabled_engines).toEqual(enabled);
    const normalized = normalizeFuzzingSettings({ fuzzing: { enabled_engines: enabled, default_engine: "atheris" } });
    expect(normalized.settings?.enabled_engines).toEqual(enabled);
    expect(normalized.settings?.default_engine).toBe("atheris");
  });

  it("maps each language to the engine the service pairs it with", () => {
    expect(engineForLanguage("go")).toBe("go-native");
    expect(engineForLanguage("python")).toBe("atheris");
    expect(engineForLanguage("java")).toBe("jazzer");
    expect(engineForLanguage("javascript")).toBe("jazzer-js");
    expect(engineForLanguage("c")).toBeNull();
    expect(engineForLanguage(undefined)).toBeNull();
  });

  it("offers the language engine for each language when enabled", () => {
    const settings = { enabled_engines: ALL };
    const pick = (language: string) => enabledEngineOptions(settings, { language }).map((o) => o.value);
    expect(pick("go")).toEqual(["go-native"]);
    expect(pick("python")).toEqual(["atheris"]);
    expect(pick("java")).toEqual(["jazzer"]);
    expect(pick("javascript")).toEqual(["jazzer-js"]);
    expect(pick("rust")).toEqual(["libfuzzer"]);
    expect(pick("c")).toEqual(["libfuzzer", "afl++", "honggfuzz"]);
    expect(pick("cpp")).toEqual(["libfuzzer", "afl++", "honggfuzz"]);
    expect(enabledEngineOptions({ enabled_engines: ["libfuzzer"] }, { language: "go" })).toEqual([]);
  });

  it("names and canonicalises the new engines", () => {
    expect(canonicalHarnessEngine("GoNative")).toBe("go-native");
    expect(canonicalHarnessEngine("go-native")).toBe("go-native");
    expect(canonicalHarnessEngine("Atheris")).toBe("atheris");
    expect(canonicalHarnessEngine("Jazzer")).toBe("jazzer");
    expect(canonicalHarnessEngine("JazzerJs")).toBe("jazzer-js");
    expect(canonicalHarnessEngine("jazzer-js")).toBe("jazzer-js");
    expect(engineDisplayName("GoNative")).toBe("Go native fuzzing");
    expect(engineDisplayName("atheris")).toBe("Atheris");
    expect(engineDisplayName("Jazzer")).toBe("Jazzer");
    expect(engineDisplayName("JazzerJs")).toBe("Jazzer.js");
  });

  it("accepts a persisted selection that uses a language engine", () => {
    const raw = JSON.stringify({ "/p": { target: "t", engine: "atheris", lang: "python", compiled: false } });
    expect(parsePersistedTargetSelections(raw).entries["/p"].repair).toBeNull();
  });
});
