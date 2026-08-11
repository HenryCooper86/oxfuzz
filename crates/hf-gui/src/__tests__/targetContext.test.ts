import { describe, expect, it } from "vitest";
import {
  parsePersistedTargetSelections,
  repairTargetSelectionEngine,
  serializableTargetSelections,
} from "../providers/targetSelection";

const RETIRED_CANONICAL = ["cluster", "fuzz", "lite"].join("");
const RETIRED_SHORT_ALIAS = ["c", "f", "l"].join("");
const RETIRED_LONG_ALIAS = ["c", "f", "l", "ite"].join("");
const UNICODE_SPACE = "\u00a0";

function persisted(engine: unknown) {
  return JSON.stringify({
    "/workspace/example": {
      target: "parse_input",
      engine,
      lang: "c",
      compiled: false,
    },
  });
}

describe("TargetProvider persisted selection validation", () => {
  it("keeps a valid active persisted selection available for normal defaults", () => {
    const loaded = parsePersistedTargetSelections(persisted("honggfuzz"));

    expect(loaded.entries["/workspace/example"]).toEqual({
      state: {
        target: "parse_input",
        engine: "honggfuzz",
        lang: "c",
        compiled: false,
      },
      repair: null,
    });
    expect(serializableTargetSelections(loaded, ["/workspace/example"])).toEqual({
      "/workspace/example": loaded.entries["/workspace/example"].state,
    });
  });

  it.each([
    RETIRED_CANONICAL,
    RETIRED_SHORT_ALIAS,
    RETIRED_LONG_ALIAS,
    `  ${RETIRED_CANONICAL.toUpperCase()}  `,
  ])("preserves retired engine %j in a fail-closed repair state", (engine) => {
    const loaded = parsePersistedTargetSelections(persisted(engine));
    const entry = loaded.entries["/workspace/example"];

    expect(entry.state.engine).toBe(engine);
    expect(entry.repair).toEqual({ kind: "retired_engine", value: engine });
    expect(serializableTargetSelections(loaded, ["/workspace/example"])).toBeNull();
  });

  it("keeps a mixed payload's retired selection rather than choosing a default", () => {
    const loaded = parsePersistedTargetSelections(JSON.stringify({
      "/workspace/active": {
        target: "decode",
        engine: "afl++",
        lang: "c",
        compiled: true,
      },
      "/workspace/retired": {
        target: "parse",
        engine: RETIRED_SHORT_ALIAS,
        lang: "c",
        compiled: false,
      },
    }));

    expect(loaded.entries["/workspace/active"].repair).toBeNull();
    expect(loaded.entries["/workspace/retired"].state.engine).toBe(RETIRED_SHORT_ALIAS);
    expect(loaded.entries["/workspace/retired"].repair).toEqual({
      kind: "retired_engine",
      value: RETIRED_SHORT_ALIAS,
    });
  });

  it.each([
    ["malformed JSON", "{"],
    ["non-object payload", JSON.stringify([])],
    ["invalid selection shape", JSON.stringify({ "/workspace/example": { engine: "afl++" } })],
    ["unknown engine", persisted("unknown-engine")],
  ])("fails closed for %s", (_name, raw) => {
    const loaded = parsePersistedTargetSelections(raw);
    const entry = loaded.entries["/workspace/example"];

    expect(loaded.globalRepair ?? entry?.repair).toMatchObject({ kind: "invalid_selection" });
    expect(serializableTargetSelections(loaded, ["/workspace/example"])).toBeNull();
  });

  it("clears repair and persists only after an explicit active engine selection", () => {
    const loaded = parsePersistedTargetSelections(persisted(RETIRED_CANONICAL));
    const repaired = repairTargetSelectionEngine(
      loaded.entries["/workspace/example"],
      "afl++",
    );
    const recovered = { ...loaded, entries: { "/workspace/example": repaired } };

    expect(repaired).toEqual({
      state: {
        target: "parse_input",
        engine: "afl++",
        lang: "c",
        compiled: false,
      },
      repair: null,
    });
    expect(serializableTargetSelections(recovered, ["/workspace/example"])).toEqual({
      "/workspace/example": repaired.state,
    });
  });

  it("keeps the original Unicode-whitespace spelling in the repair diagnostic", () => {
    const original = `${UNICODE_SPACE}${RETIRED_CANONICAL}${UNICODE_SPACE}`;
    const loaded = parsePersistedTargetSelections(persisted(original));

    expect(loaded.entries["/workspace/example"].state.engine).toBe(original);
    expect(loaded.entries["/workspace/example"].repair).toEqual({
      kind: "retired_engine",
      value: original,
    });
  });

  it("bounds an oversized retired diagnostic with an explicit truncation marker", () => {
    const original = `${UNICODE_SPACE.repeat(160)}${RETIRED_SHORT_ALIAS}`;
    const repair = parsePersistedTargetSelections(persisted(original)).entries["/workspace/example"].repair;

    expect(repair).toMatchObject({ kind: "retired_engine" });
    expect(repair?.kind === "retired_engine" ? repair.value.length : 0).toBeLessThan(original.length);
    expect(repair?.kind === "retired_engine" ? repair.value : "").toContain("[truncated]");
  });

  it("prunes a removed repaired project before persisting an active project", () => {
    const loaded = parsePersistedTargetSelections(JSON.stringify({
      "/workspace/active": {
        target: "decode",
        engine: "afl++",
        lang: "c",
        compiled: true,
      },
      "/workspace/removed": {
        target: "parse",
        engine: RETIRED_LONG_ALIAS,
        lang: "c",
        compiled: false,
      },
    }));

    expect(serializableTargetSelections(loaded, ["/workspace/active"])).toEqual({
      "/workspace/active": {
        target: "decode",
        engine: "afl++",
        lang: "c",
        compiled: true,
      },
    });
  });

  it("keeps persistence blocked for a retained repaired project", () => {
    const loaded = parsePersistedTargetSelections(JSON.stringify({
      "/workspace/active": {
        target: "decode",
        engine: "afl++",
        lang: "c",
        compiled: true,
      },
      "/workspace/retained": {
        target: "parse",
        engine: RETIRED_LONG_ALIAS,
        lang: "c",
        compiled: false,
      },
    }));

    expect(serializableTargetSelections(loaded, ["/workspace/active", "/workspace/retained"])).toBeNull();
    expect(loaded.entries["/workspace/active"].state.engine).toBe("afl++");
  });
});
