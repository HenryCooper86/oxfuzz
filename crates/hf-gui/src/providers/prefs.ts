import { createContext, useContext } from "react";

export type Theme = "dark" | "light";
export type SandboxArch = "linux/arm64" | "linux/amd64";

export interface PrefsContextValue {
  theme: Theme;
  fontSize: number;
  sendOnEnter: boolean;
  customDecorations: boolean;
  sandboxArch: SandboxArch;
  setTheme: (theme: Theme) => void;
  setFontSize: (size: number) => void;
  setSendOnEnter: (enabled: boolean) => void;
  setCustomDecorations: (enabled: boolean) => void;
  setSandboxArch: (arch: SandboxArch) => void;
}

export const PrefsContext = createContext<PrefsContextValue | null>(null);

export function usePrefs(): PrefsContextValue {
  return (
    useContext(PrefsContext) ?? {
      theme: "dark",
      fontSize: 14,
      sendOnEnter: true,
      customDecorations: false,
      sandboxArch: "linux/arm64",
      setTheme: () => {},
      setFontSize: () => {},
      setSendOnEnter: () => {},
      setCustomDecorations: () => {},
      setSandboxArch: () => {},
    }
  );
}
