import { createContext, useContext } from "react";

export interface ToastNotification {
  id: number;
  title: string;
  description?: string;
  variant?: "default" | "success" | "error";
}

export interface ToastContextValue {
  toast: (notification: Omit<ToastNotification, "id">) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  return useContext(ToastContext) ?? { toast: () => {} };
}
