import { createContext, useContext } from "react";

export interface TargetContextValue {
  target: string;
  engine: string;
  lang: string;
  compiled: boolean;
  setTarget: (target: string) => void;
  setEngine: (engine: string) => void;
  setLang: (language: string) => void;
  setCompiled: (compiled: boolean) => void;
  reset: () => void;
}

export type TargetState = Pick<TargetContextValue, "target" | "engine" | "lang" | "compiled">;

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
      setTarget: () => {},
      setEngine: () => {},
      setLang: () => {},
      setCompiled: () => {},
      reset: () => {},
    }
  );
}
