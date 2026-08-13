/// <reference types="vitest" />

/** Substituted at build time from package.json by vite.config.ts. */
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  readonly VITE_BACKEND?: string;
  readonly VITE_API_URL?: string;
  readonly VITE_API_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
