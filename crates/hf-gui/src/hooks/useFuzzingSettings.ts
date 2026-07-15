import { useEffect, useState } from "react";
import { getTransport } from "../lib";
import {
  loadEffectiveFuzzingSettings,
  type FuzzingSettings,
} from "../lib/fuzzingSettings";

export interface FuzzingSettingsState {
  settings: FuzzingSettings | null;
  loaded: boolean;
  error: string | null;
}

/** Load the service-validated global fuzzing defaults for an interactive view. */
export function useFuzzingSettings(): FuzzingSettingsState {
  const [state, setState] = useState<FuzzingSettingsState>({
    settings: null,
    loaded: false,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;
    const transport = getTransport();
    loadEffectiveFuzzingSettings((command) => transport.invoke(command))
      .then((settings) => {
        if (!cancelled) {
          setState({ settings, loaded: true, error: null });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            settings: null,
            loaded: true,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
