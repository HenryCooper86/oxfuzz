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
