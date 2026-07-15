import { createContext, useContext, useMemo } from "react";

export interface ConfirmOptions {
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Style the confirm button as destructive. */
  danger?: boolean;
}

export type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>;

export const ConfirmContext = createContext<ConfirmFn | null>(null);

/** Access the themed confirm. Falls back to window.confirm outside a provider. */
export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext);
  return useMemo(
    () =>
      ctx ??
      ((opts: ConfirmOptions) =>
        Promise.resolve(window.confirm(opts.message ?? opts.title))),
    [ctx],
  );
}
