interface RecoveryAction {
  occurrenceId: string;
  confirm: () => Promise<boolean>;
  acknowledge: (occurrenceId: string) => Promise<unknown>;
  refresh: () => Promise<unknown>;
}

interface LatestRefreshOptions<T> {
  load: () => Promise<T>;
  commit: (value: T) => void;
  onStart?: () => void;
}

interface LatestRefresh {
  activate: () => void;
  deactivate: () => void;
  refresh: () => Promise<boolean>;
}

export function createLatestRefresh<T>({
  load,
  commit,
  onStart,
}: LatestRefreshOptions<T>): LatestRefresh {
  let active = false;
  let generation = 0;

  const activate = () => {
    active = true;
    generation += 1;
  };
  const deactivate = () => {
    active = false;
    generation += 1;
  };
  const refresh = async () => {
    if (!active) return false;
    const requestGeneration = ++generation;
    onStart?.();
    try {
      const value = await load();
      if (!active || requestGeneration !== generation) return false;
      commit(value);
      return true;
    } catch (cause) {
      if (!active || requestGeneration !== generation) return false;
      throw cause;
    }
  };

  return { activate, deactivate, refresh };
}

export interface RecoveryLoadState {
  loading: boolean;
  error: boolean;
}

export type RecoveryLoadEvent = "start" | "success" | "error";

export const initialRecoveryLoadState: RecoveryLoadState = {
  loading: true,
  error: false,
};

export function recoveryLoadReducer(
  state: RecoveryLoadState,
  event: RecoveryLoadEvent,
): RecoveryLoadState {
  if (event === "start") return { ...state, loading: true };
  if (event === "success") return { loading: false, error: false };
  return { loading: false, error: true };
}

export async function acknowledgeRecoveryWithRefresh({
  occurrenceId,
  confirm,
  acknowledge,
  refresh,
}: RecoveryAction): Promise<boolean> {
  if (!(await confirm())) return false;
  await acknowledge(occurrenceId);
  await refresh();
  return true;
}
