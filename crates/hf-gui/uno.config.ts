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
      },
      success: "var(--success)",
      error: "var(--error)",
      warning: "var(--warning)",
      border: "var(--border)",
    },
    borderRadius: {
      DEFAULT: "var(--border-radius)",
    },
  },
  shortcuts: {
    "surface-card": "bg-surface-primary border border-border rounded-DEFAULT",
  },
});