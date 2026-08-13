import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import uno from "unocss/vite";

// package.json is the version Tauri bundles the installer from, so the UI reads
// the same field rather than carrying its own literal. See src/lib/appVersion.ts.
const { version } = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
) as { version: string };

export default defineConfig({
  plugins: [uno(), react()],
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
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
