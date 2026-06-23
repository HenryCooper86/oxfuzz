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
  },
});