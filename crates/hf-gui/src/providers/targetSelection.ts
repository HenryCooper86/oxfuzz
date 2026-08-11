import { FUZZING_ENGINE_OPTIONS, type FuzzingEngineId } from "../lib/fuzzingSettings";
import { pruneToKeys } from "../lib/projectState";
import { retiredEngineValue } from "../lib/retiredEngine";
import { DEFAULT_TARGET_STATE, type TargetSelectionRepair, type TargetState } from "./target";

const ACTIVE_ENGINE_IDS = new Set<string>(FUZZING_ENGINE_OPTIONS.map((option) => option.value));
const TARGET_LANGUAGES = new Set(["c", "cpp", "rust", "go", "python"]);

export interface TargetSelectionEntry {
  state: TargetState;
  repair: TargetSelectionRepair | null;
}

export interface PersistedTargetSelections {
  entries: Record<string, TargetSelectionEntry>;
  globalRepair: TargetSelectionRepair | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidEntry(reason: Extract<TargetSelectionRepair, { kind: "invalid_selection" }>["reason"]): TargetSelectionEntry {
  return { state: { ...DEFAULT_TARGET_STATE }, repair: { kind: "invalid_selection", reason } };
}

function parseTargetSelection(value: unknown): TargetSelectionEntry {
  if (!isRecord(value)) return invalidEntry("invalid_shape");
  const { target, engine, lang, compiled } = value;
  if (typeof target !== "string" || typeof engine !== "string" || typeof lang !== "string" || typeof compiled !== "boolean") {
    return invalidEntry("invalid_shape");
  }
  const state: TargetState = { target, engine, lang, compiled };
  const retired = retiredEngineValue(engine);
  if (retired !== null) {
    return { state, repair: { kind: "retired_engine", value: retired } };
  }
  if (!ACTIVE_ENGINE_IDS.has(engine) || !TARGET_LANGUAGES.has(lang)) {
    return invalidEntry("unknown_engine");
  }
  return { state, repair: null };
}

/** Validate persisted selection data before it can reach an option fallback. */
export function parsePersistedTargetSelections(raw: string | null): PersistedTargetSelections {
  if (raw === null) return { entries: {}, globalRepair: null };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) {
      return {
        entries: {},
        globalRepair: { kind: "invalid_selection", reason: "malformed_payload" },
      };
    }
    const entries: Record<string, TargetSelectionEntry> = {};
    for (const [project, value] of Object.entries(parsed)) {
      entries[project] = parseTargetSelection(value);
    }
    return { entries, globalRepair: null };
  } catch {
    return {
      entries: {},
      globalRepair: { kind: "invalid_selection", reason: "malformed_payload" },
    };
  }
}

export function isActiveEngineId(engine: string): engine is FuzzingEngineId {
  return ACTIVE_ENGINE_IDS.has(engine);
}

/** Replace a repaired value only after the user selects an active engine. */
export function repairTargetSelectionEngine(
  entry: TargetSelectionEntry,
  engine: FuzzingEngineId,
): TargetSelectionEntry {
  return {
    state: { ...entry.state, engine, compiled: false },
    repair: null,
  };
}

/** Never overwrite unrepairable persisted data without an explicit recovery. */
export function serializableTargetSelections(
  selections: PersistedTargetSelections,
  recentProjects: string[],
): Record<string, TargetState> | null {
  if (selections.globalRepair || Object.values(selections.entries).some((entry) => entry.repair !== null)) {
    return null;
  }
  const states = Object.fromEntries(
    Object.entries(selections.entries).map(([project, entry]) => [project, entry.state]),
  );
  return pruneToKeys(states, recentProjects);
}
