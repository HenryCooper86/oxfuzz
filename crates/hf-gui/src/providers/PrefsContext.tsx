import { useCallback, useEffect, useMemo, useState } from "react";
import { getTransport } from "../lib";
import { PrefsContext, type SandboxArch, type Theme } from "./prefs";

function isMacTauri(): boolean {
  if (typeof window === "undefined") return false;
  const tauri = "__TAURI_INTERNALS__" in window;
  const mac = `${navigator.platform} ${navigator.userAgent}`.toLowerCase().includes("mac");
  return tauri && mac;
}

function load<T>(key: string, fallback: T, parse: (s: string) => T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : parse(raw);
  } catch {
    return fallback;
  }
}

function persist(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
}

export function PrefsProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() =>
    load<Theme>("hf_theme", "dark", (s) => (s === "light" ? "light" : "dark")),
  );
  const [fontSize, setFontSizeState] = useState<number>(() =>
    load<number>("hf_font_size", 14, (s) => {
      const n = Number(s);
      return Number.isFinite(n) ? Math.min(20, Math.max(12, n)) : 14;
    }),
  );
  const [sendOnEnter, setSendOnEnterState] = useState<boolean>(() =>
    load<boolean>("hf_send_on_enter", true, (s) => s !== "false"),
  );
  const [customDecorations, setCustomDecorationsState] = useState<boolean>(() =>
    load<boolean>("hf_custom_decorations", isMacTauri(), (s) => s === "true"),
  );
  const [sandboxArch, setSandboxArchState] = useState<SandboxArch>(() =>
    load<SandboxArch>("hf_sandbox_arch", "linux/arm64", (s) =>
      s === "linux/amd64" ? "linux/amd64" : "linux/arm64",
    ),
  );

  // Default the sandbox arch to the host's native platform on first run.
  useEffect(() => {
    if (localStorage.getItem("hf_sandbox_arch") !== null) return;
    getTransport()
      .invoke<string>("host_arch")
      .then((a) => {
        if (a === "linux/amd64" || a === "linux/arm64") setSandboxArchState(a);
      })
      .catch(() => {});
  }, []);

  // Apply theme to the document.
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // Apply base font size (root px). UI elements using rem scale with this.
  useEffect(() => {
    document.documentElement.style.setProperty("--app-font-size", `${fontSize}px`);
    document.documentElement.style.fontSize = `${fontSize}px`;
  }, [fontSize]);

  // Apply the macOS layered-chrome class.
  useEffect(() => {
    document.documentElement.classList.toggle("custom-decorations", customDecorations);
  }, [customDecorations]);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    persist("hf_theme", t);
  }, []);
  const setFontSize = useCallback((n: number) => {
    const clamped = Math.min(20, Math.max(12, Math.round(n)));
    setFontSizeState(clamped);
    persist("hf_font_size", String(clamped));
  }, []);
  const setSendOnEnter = useCallback((v: boolean) => {
    setSendOnEnterState(v);
    persist("hf_send_on_enter", String(v));
  }, []);
  const setCustomDecorations = useCallback((v: boolean) => {
    setCustomDecorationsState(v);
    persist("hf_custom_decorations", String(v));
  }, []);
  const setSandboxArch = useCallback((a: SandboxArch) => {
    setSandboxArchState(a);
    persist("hf_sandbox_arch", a);
  }, []);

  const value = useMemo(
    () => ({
      theme,
      fontSize,
      sendOnEnter,
      customDecorations,
      sandboxArch,
      setTheme,
      setFontSize,
      setSendOnEnter,
      setCustomDecorations,
      setSandboxArch,
    }),
    [
      theme,
      fontSize,
      sendOnEnter,
      customDecorations,
      sandboxArch,
      setTheme,
      setFontSize,
      setSendOnEnter,
      setCustomDecorations,
      setSandboxArch,
    ],
  );

  return <PrefsContext.Provider value={value}>{children}</PrefsContext.Provider>;
}
