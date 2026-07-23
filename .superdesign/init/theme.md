# Theme and Design Tokens

This file records design intent and points at the files that own it. It does not
reproduce their contents: the source files listed below are authoritative, and a
copy here would silently drift from them. Read the file when you need exact
values.

## System summary

- CSS approach: UnoCSS utilities plus custom CSS variables and a small set of global component classes.
- Component approach: custom React primitives throughout. Radix UI is used in exactly one place -- `Select`. See the Radix note below before assuming otherwise.
- Default visual mode: dark neutral surfaces with muted brass/gold accent.
- Alternate mode: warm-white light surfaces with darker brass accent.
- Typography: Inter/system sans for body, SF Pro Display stack for headings/chrome, SF Mono/Fira Code stack for technical values.
- Spacing scale: 4, 8, 16, 24, and 40 pixels (`--space-xs` through `--space-xl`).
- Radius scale: 4, 8, and 12 pixels (`--radius-sm` through `--radius-lg`).
- Elevation: dark-mode shadows from 45% to 65% black; light-mode shadows from 8% to 16% black.
- Breakpoints: the UnoCSS config adds no breakpoint extension, but `index.css` hand-writes two -- `max-width: 768px` and `max-width: 1100px`. See Responsive rules below.
- Motion: focused 150-200 ms transitions, reduced-motion support in global CSS.

## Radix UI: what is actually used

Only `src/components/ui/Select.tsx` imports Radix (`@radix-ui/react-select`).
`package.json` additionally declares `@radix-ui/react-dialog`,
`react-scroll-area`, `react-separator`, `react-tabs`, `react-toast`, and
`react-tooltip`, but nothing under `src/` imports them.

This matters for design work: `Tooltip`, `Toast`, `Separator`, and the dialog
surfaces are hand-rolled. They do not inherit Radix's focus trap, roving
tabindex, dismiss-on-Escape, or `aria-describedby` wiring. `Tooltip.tsx` in
particular renders a positioned div with no ARIA association and no Escape
handling. If a redesign depends on any of that behavior, it has to be added
rather than assumed.

## Global theme and component styles

- File: `crates/hf-gui/src/styles/index.css`
- Owns: both theme token blocks (`:root, [data-theme="dark"]` and
  `[data-theme="light"]`), the spacing/radius/shadow scales, global component
  classes (`surface-card`, `view-scroll`, `view-canvas`, settings-row hairlines,
  scrollbar treatment), and the reduced-motion block.
- Token values are summarised design-side in `../design-system.md`. This file is
  the source of truth for them.

### Canvas and scroll structure

- `.view-scroll` -- `flex: 1; min-width: 0; overflow: auto;` with a
  `var(--space-lg)` (24 px) inset. This is the scrolling region.
- `.view-canvas` -- `width: 100%; max-width: 1440px; margin: 0 auto;` with a
  `var(--space-xl)` bottom pad. This is the width cap that keeps content centred
  on wide desktops.

Both are applied by the `ViewCanvas` primitive, which `App.tsx` wraps around
every routed view. A layout that drops `ViewCanvas` loses the cap and the
centring on every screen.

### Responsive rules

- `@media (max-width: 768px)` -- `.view-scroll` inset drops from 24 px to 16 px.
- `@media (max-width: 1100px)` -- `.dashboard-supporting-band` collapses from
  `minmax(0, 1fr) minmax(0, 1.35fr)` to a single column.
- `@media (prefers-reduced-motion: reduce)` -- animation and transition
  durations collapse to ~0.

## UnoCSS theme configuration

- File: `crates/hf-gui/uno.config.ts`
- Uses `presetUno()` only. Defines a `theme.colors` map and a `shortcuts` block
  that bind utility names to the CSS variables in `index.css`, so utilities and
  raw `var(--token)` styles stay in sync.
- No breakpoint extension; the responsive rules above are hand-written CSS.

## Preference and theme provider

- File: `crates/hf-gui/src/providers/PrefsContext.tsx` (types in
  `src/providers/prefs.ts`)
- Persists to `localStorage` and drives the `data-theme` attribute the token
  blocks key off.
- Stored preferences: `hf_theme` (`dark` default), font size, send-on-enter,
  custom window decorations, and sandbox architecture.

## Application entry point

- File: `crates/hf-gui/src/main.tsx`
- Mounts the React root and installs the provider stack. Nothing design-bearing
  lives here; it is listed so the shell tree is complete.

## Vite, Vitest, and UnoCSS configuration

- File: `crates/hf-gui/vite.config.ts`
- `defineConfig` from `vitest/config`, plugins `uno()` and `react()`, test
  environment `node`. The frontend tests referenced throughout these docs run
  from here.

## Frontend dependency manifest

- File: `crates/hf-gui/package.json`

Do not treat any summary of this file as complete. It carries a trailing
`overrides` block that pins transitive dependencies for supply-chain reasons:

- `dompurify` -> `3.4.12`
- `js-yaml` -> `4.3.0`
- `brace-expansion` -> `1.1.16` under `minimatch@3.1.5`, `5.0.7` under
  `minimatch@10.2.5`

`dompurify` sanitizes rendered crash/report markdown and mermaid diagrams, so
dropping the pin re-resolves the sanitizer to whatever the unpinned range
allows. These pins are invisible in the `dependencies` lists and easy to lose in
a reconciliation; preserve the `overrides` key whenever the manifest is edited.
