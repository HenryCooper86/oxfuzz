// Single source of the displayed app version.
//
// `__APP_VERSION__` is substituted at build time by vite.config.ts from
// package.json -- the same field Tauri bundles the installer from. Surfaces that
// show a version must import this constant rather than writing their own copy,
// so a release bump can never leave part of the UI reporting a stale number.

export const APP_VERSION: string = __APP_VERSION__;
