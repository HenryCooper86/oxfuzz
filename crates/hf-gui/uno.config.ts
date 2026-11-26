import { defineConfig, presetUno, transformerVariantGroup } from "unocss";

export default defineConfig({
  presets: [presetUno()],
  transformers: [transformerVariantGroup()],
  theme: {
    colors: {
      surface: {
        primary: "var(--surface-primary)",
        secondary: "var(--surface-secondary)",
        raised: "var(--surface-raised)",
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
        border: "var(--accent-border)",
        contrast: "var(--accent-contrast)",
      },
      success: {
        DEFAULT: "var(--success)",
        subtle: "var(--success-subtle)",
      },
      error: {
        DEFAULT: "var(--error)",
        subtle: "var(--error-subtle)",
      },
      warning: {
        DEFAULT: "var(--warning)",
        subtle: "var(--warning-subtle)",
      },
      info: {
        DEFAULT: "var(--info)",
        subtle: "var(--info-subtle)",
      },
      border: {
        DEFAULT: "var(--border)",
        strong: "var(--border-strong)",
        focus: "var(--border-focus)",
      },
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
    // Content cards sit one step above the canvas on the raised surface with a
    // hairline border and only a contact shadow -- elevation by tone, not by a
    // heavy drop shadow on every card (incl. list rows), which was noisy.
    // Floating surfaces (modal, toast, tooltip, menus) use --shadow-md/lg.
    "surface-card":
      "bg-surface-raised border border-solid border-border rounded-lg shadow-sm",
  },
});