import { createContext, useContext } from "react";

export interface TargetContextValue {
  target: string;
  engine: string;
  lang: string;
  compiled: boolean;
  selectionRepair: TargetSelectionRepair | null;
  storageError: TargetStorageError | null;
  setTarget: (target: string) => void;
  setEngine: (engine: string) => void;
  setLang: (language: string) => void;
  setCompiled: (compiled: boolean) => void;
  reset: () => void;
  retryStorage: () => void;
}

export type TargetState = Pick<TargetContextValue, "target" | "engine" | "lang" | "compiled">;

export type TargetSelectionIssue =
  | { kind: "retired_engine"; value: string }
  | { kind: "invalid_selection"; reason: "malformed_payload" | "invalid_shape" | "unknown_engine" };

/** A persisted repair plus the project that is authorized to resolve it. */
export interface TargetSelectionRepair {
  projectKey: string | null;
  issue: TargetSelectionIssue;
}

export interface TargetStorageError {
  operation: "read" | "write";
}

export const DEFAULT_TARGET_STATE: TargetState = {
  target: "",
  engine: "libfuzzer",
  lang: "c",
  compiled: false,
};

export const TargetContext = createContext<TargetContextValue | null>(null);

/** Access shared target selection. Safe outside a provider. */
export function useTarget(): TargetContextValue {
  return (
    useContext(TargetContext) ?? {
      ...DEFAULT_TARGET_STATE,
      selectionRepair: null,
      storageError: null,
      setTarget: () => {},
      setEngine: () => {},
      setLang: () => {},
      setCompiled: () => {},
      reset: () => {},
      retryStorage: () => {},
    }
  );
}
