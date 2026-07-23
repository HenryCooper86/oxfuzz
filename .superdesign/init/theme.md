# Theme and Design Tokens

## System summary

- CSS approach: UnoCSS utilities plus custom CSS variables and a small set of global component classes.
- Component approach: custom React primitives with Radix UI for dialog, select, separator, tabs, toast, and tooltip behavior.
- Default visual mode: dark neutral surfaces with muted brass/gold accent.
- Alternate mode: warm-white light surfaces with darker brass accent.
- Typography: Inter/system sans for body, SF Pro Display stack for headings/chrome, SF Mono/Fira Code stack for technical values.
- Spacing scale: 4, 8, 16, 24, and 40 pixels.
- Radius scale: 4, 8, and 12 pixels.
- Elevation: dark-mode shadows from 45% to 65% black; light-mode shadows from 8% to 16% black.
- Breakpoints: no project-level Tailwind or UnoCSS breakpoint extension; UnoCSS defaults apply.
- Motion: focused 150–200 ms transitions, reduced-motion support in global CSS.

## Global theme and component styles

- File: `crates/hf-gui/src/styles/index.css`

```css
:root,
[data-theme="dark"] {
  /* Surface hierarchy */
  --surface-primary: #0f0f0f;
  --surface-secondary: #141414;
  --surface-tertiary: #1c1c1c;
  --surface-hover: rgba(255, 255, 255, 0.045);
  --surface-code: #1a1a1a;
  --surface-active: rgba(255, 255, 255, 0.06);

  /* Text hierarchy */
  --text-primary: #e8e6e1;
  --text-secondary: #8a8680;
  --text-muted: #555250;

  /* Accent -- warm gold */
  --accent: #c8b560;
  --accent-hover: #d4c26e;
  --accent-subtle: rgba(200, 181, 96, 0.1);
  --accent-glow: rgba(200, 181, 96, 0.15);
  --accent-contrast: #0f0f0f;

  /* Semantic */
  --success: #6fcf97;
  --error: #e57373;
  --error-subtle: rgba(229, 115, 115, 0.08);
  --warning: #f0c050;
  --info: #60a5fa;
  --info-subtle: rgba(96, 165, 250, 0.12);

  /* Chart categorical series -- dataviz-validated (dark steps of the reference
     categorical ramp; CVD/normal-vision floors pass, contrast >= 3:1). Used with
     dash-pattern secondary encoding + a legend, so identity is never color-alone. */
  --chart-series-1: #3987e5;
  --chart-series-2: #d95926;
  --chart-series-3: #199e70;
  --chart-series-4: #c98500;

  /* Borders */
  --border: rgba(255, 255, 255, 0.06);
  --border-focus: rgba(255, 255, 255, 0.15);

  /* Shadows */
  --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.45);
  --shadow-md: 0 8px 24px rgba(0, 0, 0, 0.55);
  --shadow-lg: 0 16px 48px rgba(0, 0, 0, 0.65);

  /* Spacing */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 40px;

  /* Radii */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;

  /* Fonts */
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-display: "SF Pro Display", "SF Pro Icons", "Helvetica Neue", Helvetica, Arial, sans-serif;
  --font-mono: "SF Mono", "Fira Code", "Cascadia Code", "Consolas", monospace;
}

[data-theme="light"] {
  --surface-primary: #ffffff;
  --surface-secondary: #f5f4f1;
  --surface-tertiary: #edecea;
  --surface-hover: rgba(0, 0, 0, 0.04);
  --surface-code: #f1efed;
  --surface-active: rgba(0, 0, 0, 0.06);

  --text-primary: #1a1917;
  --text-secondary: #6b6560;
  --text-muted: #9c9894;

  --accent: #9a7c2a;
  --accent-hover: #7e6420;
  --accent-subtle: rgba(154, 124, 42, 0.08);
  --accent-glow: rgba(154, 124, 42, 0.12);
  --accent-contrast: #ffffff;

  --success: #3a9d6b;
  --error: #c0392b;
  --error-subtle: rgba(192, 57, 43, 0.06);
  --warning: #c0880a;
  --info: #2563eb;
  --info-subtle: rgba(37, 99, 235, 0.08);

  /* Chart categorical series -- light steps of the reference categorical ramp. */
  --chart-series-1: #2a78d6;
  --chart-series-2: #eb6834;
  --chart-series-3: #1baf7a;
  --chart-series-4: #eda100;

  --border: rgba(0, 0, 0, 0.1);
  --border-focus: rgba(0, 0, 0, 0.22);

  --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.08);
  --shadow-md: 0 8px 24px rgba(0, 0, 0, 0.12);
  --shadow-lg: 0 16px 48px rgba(0, 0, 0, 0.16);
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  font-size: 14px;
}

body {
  font-family: var(--font-sans);
  font-weight: 400;
  letter-spacing: -0.01em;
  background: var(--surface-primary);
  color: var(--text-primary);
  overflow: hidden;
  height: 100vh;
  width: 100vw;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

#root {
  width: 100vw;
  height: 100vh;
  overflow: hidden;
}

/* Scrollbars -- thin and discreet */
::-webkit-scrollbar {
  width: 4px;
  height: 4px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 2px;
}
::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.2);
}
[data-theme="light"] ::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.12);
}
[data-theme="light"] ::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 0, 0, 0.2);
}

::selection {
  background: var(--accent-subtle);
  color: var(--text-primary);
}

/* Animations */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
@keyframes slideInUp {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes dialogContentIn {
  from { transform: scale(0.96) translateY(4px); opacity: 0; }
  to { transform: scale(1) translateY(0); opacity: 1; }
}
@keyframes busyBreathe {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.68; }
}
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.35; transform: scale(0.82); }
}
/* ============================================================
   Native macOS chrome (Apple-style layered vibrancy)
   Driven by data-host/data-platform on <html> (set in App.tsx)
   and the WindowEffect::Sidebar material applied in Rust setup().
   ============================================================ */

/* Let the native frosted-glass material show through the webview so the
   rounded window corners and sidebar vibrancy render instead of an opaque
   square. Only on macOS under Tauri -- web/other platforms stay solid. */
html[data-host="tauri"][data-platform="macos"] body,
html[data-host="tauri"][data-platform="macos"] #root,
html[data-host="tauri"][data-platform="macos"] .app-root {
  background: transparent;
}

/* The sidebar sits on the design-system `surface-secondary` with only a whisper
   of the native vibrancy left translucent at the window edge. Keeping it nearly
   opaque stops the frosted "sidebar" material (and the desktop wallpaper behind
   it) from washing the tone out -- which read as an off, muddy color over bright
   wallpapers in both themes. */
html[data-host="tauri"][data-platform="macos"] .app-root nav {
  background: color-mix(in srgb, var(--surface-secondary) 92%, transparent);
}

/* Main content column stays crisp and opaque so text rendering is sharp. */
html[data-host="tauri"][data-platform="macos"] .app-main {
  background: var(--surface-primary);
}

/* Header is the draggable titlebar when we draw our own chrome; interactive
   controls inside it opt back out of the drag region. */
html.custom-decorations header {
  -webkit-app-region: drag;
}
html.custom-decorations header button,
html.custom-decorations header [role="button"],
html.custom-decorations header input,
html.custom-decorations header a {
  -webkit-app-region: no-drag;
}

/* The sidebar's top spacer is a drag handle and reserves room for the macOS
   traffic lights that float over our custom chrome. */
html.custom-decorations .app-root nav {
  -webkit-app-region: drag;
}
html.custom-decorations .app-root nav button,
html.custom-decorations .app-root nav [role="button"],
html.custom-decorations .app-root nav a {
  -webkit-app-region: no-drag;
}

/* Base button reset. Without this, a <button> with no explicit background
   renders the native WebKit/macOS chrome (a glossy light box) that clashes with
   the dark theme. Components opt into their own background/border on top. */
button {
  -webkit-appearance: none;
  appearance: none;
  background: transparent;
  color: inherit;
  font: inherit;
  cursor: pointer;
}
button:disabled {
  cursor: default;
}

/* Keyboard focus ring. The app uses `outline-none` widely (50+ call sites), so
   restoring focus via `outline` would be overridden; a box-shadow ring is not.
   `:focus-visible` shows it for keyboard navigation only (not mouse clicks),
   and the inner surface-colored ring leaves a small gap so it reads cleanly on
   any background. */
:where(button, a, input, textarea, select, summary, [role="button"], [role="tab"], [role="switch"], [tabindex]):focus-visible {
  outline: none;
  box-shadow:
    0 0 0 2px var(--surface-primary),
    0 0 0 4px var(--accent);
  border-radius: var(--radius-sm);
}

/* Themed icon/action button (row actions: edit, duplicate, reset, delete).
   Transparent at rest, revealing a subtle surface + border on hover so it reads
   as interactive and matches the app's icon buttons. */
.hf-action-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  color: var(--text-muted);
  transition: background 120ms ease, color 120ms ease, border-color 120ms ease;
}
.hf-action-btn:hover {
  background: var(--surface-active);
  color: var(--text-primary);
  border-color: var(--border);
}
.hf-action-btn.danger:hover {
  background: var(--error-subtle);
  color: var(--error);
  border-color: var(--error);
}

/* Hairline separators between consecutive settings rows inside a card. */
.settings-item + .settings-item {
  border-top: 1px solid var(--border);
}

/* Rendered Markdown in the report preview. Scoped to .markdown-body so it does
   not leak into the rest of the app's custom-styled UI. */
.markdown-body { color: var(--text-primary); font-size: 13px; line-height: 1.65; }
.markdown-body h1 { font-size: 1.5rem; font-weight: 700; margin: 0.2em 0 0.6em; }
.markdown-body h2 { font-size: 1.2rem; font-weight: 600; margin: 1.3em 0 0.5em; padding-bottom: 0.25em; border-bottom: 1px solid var(--border); }
.markdown-body h3 { font-size: 1.02rem; font-weight: 600; margin: 1.1em 0 0.4em; }
.markdown-body p { margin: 0.55em 0; }
.markdown-body ul, .markdown-body ol { margin: 0.5em 0; padding-left: 1.4em; }
.markdown-body li { margin: 0.2em 0; }
.markdown-body a { color: var(--accent); text-decoration: none; }
.markdown-body strong { color: var(--text-primary); font-weight: 650; }
.markdown-body blockquote { margin: 0.7em 0; padding: 0.1em 0.9em; border-left: 3px solid var(--border); color: var(--text-secondary); }
.markdown-body code { font-family: var(--font-mono); font-size: 0.88em; background: var(--surface-active); padding: 0.12em 0.36em; border-radius: 4px; }
.markdown-body pre { background: var(--surface-active); padding: var(--space-md); border-radius: 6px; overflow-x: auto; }
.markdown-body pre code { background: none; padding: 0; }
.markdown-body table { border-collapse: collapse; width: 100%; margin: 0.7em 0; font-size: 0.92em; }
.markdown-body th, .markdown-body td { border: 1px solid var(--border); padding: 0.4em 0.7em; text-align: left; }
.markdown-body th { background: var(--surface-active); font-weight: 600; }
.markdown-body hr { border: none; border-top: 1px solid var(--border); margin: 1.4em 0; }
.markdown-body svg { max-width: 100%; height: auto; }

/* Respect the OS "Reduce motion" setting: neutralize animations and transitions
   so users who request reduced motion don't get the app's fade/slide/scale/pulse
   effects. Durations are near-zero rather than 0 so animationend/transitionend
   handlers still fire. */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }
}
```

## UnoCSS theme configuration

- File: `crates/hf-gui/uno.config.ts`

```ts
import { defineConfig, presetUno, transformerVariantGroup } from "unocss";

export default defineConfig({
  presets: [presetUno()],
  transformers: [transformerVariantGroup()],
  theme: {
    colors: {
      surface: {
        primary: "var(--surface-primary)",
        secondary: "var(--surface-secondary)",
        tertiary: "var(--surface-tertiary)",
        hover: "var(--surface-hover)",
        code: "var(--surface-code)",
        active: "var(--surface-active)",
      },
      text: {
        primary: "var(--text-primary)",
        secondary: "var(--text-secondary)",
        muted: "var(--text-muted)",
      },
      accent: {
        DEFAULT: "var(--accent)",
        hover: "var(--accent-hover)",
        subtle: "var(--accent-subtle)",
        glow: "var(--accent-glow)",
        contrast: "var(--accent-contrast)",
      },
      success: "var(--success)",
      error: {
        DEFAULT: "var(--error)",
        subtle: "var(--error-subtle)",
      },
      warning: "var(--warning)",
      info: {
        DEFAULT: "var(--info)",
        subtle: "var(--info-subtle)",
      },
      border: "var(--border)",
    },
    borderRadius: {
      sm: "var(--radius-sm)",
      md: "var(--radius-md)",
      lg: "var(--radius-lg)",
    },
    boxShadow: {
      sm: "var(--shadow-sm)",
      md: "var(--shadow-md)",
      lg: "var(--shadow-lg)",
    },
  },
  shortcuts: {
    // Content cards are flat-with-a-hairline-border for a calm, dense layout; a
    // heavy drop shadow on every card (incl. list rows) was visually noisy.
    // Floating surfaces (modal, toast, tooltip, menus) set their own elevation.
    "surface-card":
      "bg-surface-primary border border-solid border-border rounded-lg shadow-sm",
  },
});
```


## Preference and theme provider

- File: `crates/hf-gui/src/providers/PrefsContext.tsx`

```tsx
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
```

## Application entry point

- File: `crates/hf-gui/src/main.tsx`

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "virtual:uno.css";
import "./styles/index.css";
import App from "./App";

// Set host/platform datasets for CSS platform-specific rules.
function resolveHostDataset() {
  const html = document.documentElement;
  if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) {
    html.dataset.host = "tauri";
  } else {
    html.dataset.host = "web";
  }
  const platform = navigator.platform.toLowerCase();
  if (platform.includes("mac")) html.dataset.platform = "macos";
  else if (platform.includes("linux")) html.dataset.platform = "linux";
  else html.dataset.platform = "windows";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

resolveHostDataset();
```

## Vite, Vitest, and UnoCSS configuration

- File: `crates/hf-gui/vite.config.ts`

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import uno from "unocss/vite";

export default defineConfig({
  plugins: [uno(), react()],
  test: {
    setupFiles: ["./src/__tests__/setup.ts"],
    environment: "node",
  },
  build: {
    target: "esnext",
    manifest: true,
    // Mermaid is deliberately lazy-loaded and contains diagram engines up to
    // roughly 700 kB. The stricter project-wide limits are enforced by the
    // manifest-aware bundle budget script after every production build.
    chunkSizeWarningLimit: 900,
  },
});
```

## Frontend dependency manifest

- File: `crates/hf-gui/package.json`

```json
{
  "name": "hf-gui",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "dev:web": "VITE_BACKEND=http vite",
    "build": "tsc -b && vite build && npm run check:bundle",
    "build:web": "VITE_BACKEND=http tsc -b && VITE_BACKEND=http vite build --outDir dist-web && node scripts/check-bundle-budget.mjs dist-web",
    "check:bundle": "node scripts/check-bundle-budget.mjs dist",
    "lint": "eslint . --max-warnings 0",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "dependencies": {
    "@radix-ui/react-dialog": "^1.1.15",
    "@radix-ui/react-scroll-area": "^1.2.10",
    "@radix-ui/react-select": "^2.2.6",
    "@radix-ui/react-separator": "^1.1.8",
    "@radix-ui/react-tabs": "^1.1.13",
    "@radix-ui/react-toast": "^1.2.15",
    "@radix-ui/react-tooltip": "^1.2.8",
    "@tauri-apps/api": "^2.11.0",
    "@tauri-apps/cli": "^2.11.0",
    "@tauri-apps/plugin-dialog": "^2.7.0",
    "@tauri-apps/plugin-opener": "^2.5.3",
    "lucide-react": "^0.577.0",
    "mermaid": "^11.16.0",
    "react": "^19.2.0",
    "react-dom": "^19.2.0",
    "react-markdown": "^10.1.0",
    "remark-gfm": "^4.0.1"
  },
  "devDependencies": {
    "@eslint/js": "^9.39.1",
    "@types/node": "^24.10.1",
    "@types/react": "^19.2.7",
    "@types/react-dom": "^19.2.3",
    "@unocss/preset-uno": "^66.6.7",
    "@vitejs/plugin-react": "^5.1.1",
    "eslint": "^9.39.1",
    "eslint-plugin-react-hooks": "^7.0.1",
    "eslint-plugin-react-refresh": "^0.4.24",
    "globals": "^16.5.0",
    "typescript": "~5.9.3",
    "typescript-eslint": "^8.48.0",
    "unocss": "^66.6.7",
    "vite": "^7.3.6",
    "vitest": "^4.1.1"
  }
}
```
