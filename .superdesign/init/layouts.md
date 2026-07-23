# Shared Layouts

This file records the design contract of each shell component and points at the
file that owns it. It deliberately does not reproduce the source: these are the
most frequently edited files in the frontend, and an inline copy goes stale
within days. Read the file for exact markup.

Several contracts below are enforced by tests under
`crates/hf-gui/src/__tests__/`. Where a test is named, a redesign that violates
the contract fails the suite -- treat those as hard constraints, not preferences.

## Application shell

- File: `crates/hf-gui/src/App.tsx`
- Description: Owns the persistent sidebar, header, main content surface, observation/progress panels, status bar, settings shell, and state-based view routing.
- Contract:
  - Three shell shapes: normal (`Sidebar + Header + main + optional rails +
    StatusBar`), full-window settings, and DefectDojo (header and status bar
    only, sidebar and rails hidden).
  - `AppInner` holds `activeView` and `settingsReturnView` so leaving settings
    returns to the previous destination.
  - Every routed view is wrapped in `<ViewCanvas>`. That wrapper carries the
    24 px inset and the 1440 px centred cap; a per-view `<div className="flex-1
    overflow-auto">` is the pre-extraction pattern and must not come back.
  - `viewIcons: Record<ViewType, React.ReactNode>` is the icon map shared with
    the header and command palette.

## Sidebar

- File: `crates/hf-gui/src/components/Sidebar.tsx`
- Description: Primary application navigation, recent-target switcher, and the pipeline, results, AI System, vehicle, and integrations sections.
- Width: `var(--sidebar-width, 240px)`.
- Contract:
  - Opens with the brand block: `/logo.png` plus the `oxfuzz` wordmark. This is
    the only place the product identity appears in the chrome -- the header
    carries neither. Asserted by `branding.test.ts`.
  - Below the brand: a new-target button, then six labelled sections in order --
    Recent targets, Pipeline, Results, AI System, Vehicle, Integrations.
  - Recent targets is a list (`recentProjects.map`), not a single current
    project: each row has a remove control, and an empty state renders
    `sidebar.noTargets`.
  - Pipeline nests discover/harness/run/triage/corpus as `depth={1}` children of
    workflow. It is the only section with nesting.
  - Integrations renders only when DefectDojo is configured.
  - Automotive is a plain `NavButton` in the Vehicle section -- a standard nav
    row, visually identical to every other. It is a permanent capability, never
    gated behind a runtime toggle, and it carries no accent border, badge, or
    tag. The former `AutomotiveNavButton` and its `sidebar.automotiveTag` key
    were deleted; `automotiveSurface.test.ts` asserts the key is absent.
  - Navigation is flat. `CollapsibleNavSection` and `lib/sidebarSections.ts`
    were introduced in f86383f and reverted in 41ea503;
    `sidebarLayout.test.ts` asserts no collapsible machinery remains.
  - Footer, above a top border: Help and Settings nav rows, then an 11 px muted
    centred block carrying the Cmd+K search hint and the version string.

## Header

- File: `crates/hf-gui/src/components/Header.tsx`
- Description: Persistent title bar with view identity, sidebar/theme controls, and panel toggles.
- Height: 52 px.
- Contract:
  - Left: sidebar toggle `IconButton` (32 px), then the view icon and title.
  - The title is secondary context, not display type: `--font-display`, 14 px,
    weight 500, `var(--text-secondary)`, upright. Never italic, never accent
    coloured, never enlarged -- it would duplicate the sidebar's active
    destination. Asserted by `uiPolish.test.ts`.
  - Right: caller-supplied `actions`, then the theme toggle.
  - Carries no logo and no wordmark; see the Sidebar contract.
  - `data-tauri-drag-region` on the title area makes the header the window drag
    handle. `reserveLeftInset` leaves room for macOS traffic lights when the
    sidebar is hidden.

## Status bar

- File: `crates/hf-gui/src/components/StatusBar.tsx`
- Description: Persistent bottom health/status strip for sandbox, engines, integrations, and clock.
- Height: 28 px.
- Contract:
  - Ordered dots: Docker, Sandbox, a hairline divider, then the five engines --
    libFuzzer, AFL++, honggfuzz, ClusterFuzzLite, syzkaller -- then a divider
    and DefectDojo when configured.
  - `StatusDot` pairs an 11 px Lucide icon with a text label, so state is never
    carried by colour alone.
  - Shows the active engine and a live progress sliver during a run.

## Progress panel

- File: `crates/hf-gui/src/components/ProgressPanel.tsx`
- Logic: `crates/hf-gui/src/lib/progressPanel.ts`
- Description: Right-side pipeline progress rail for the four campaign stages.
- Contract:
  - Width is a function, not a constant: 280 px open, 64 px collapsed
    (`getProgressPanelWidth`), with a 200 ms width transition. A redesign must
    supply both states.
  - Open state is derived, not hardcoded: `getInitialProgressPanelOpen` sets the
    initial value and `getProgressPanelOpenAfterCompletionChange` collapses the
    rail when the campaign completes and reopens it when it leaves completion.
    A completed campaign must not permanently occupy the full rail.
  - The toggle carries `aria-expanded={open}` and
    `aria-controls="progress-panel-details"`, and the body is a `hidden`-gated
    region with that id. Guarded by `progressPanel.test.ts`.
  - The completion affordance swaps a chevron for a check and inverts to
    `--accent` / `--accent-contrast`.

## Recovery banner

- File: `crates/hf-gui/src/components/RecoveryBanner.tsx`
- Description: Cross-page notice for runs recovered after an interrupted session.
- Contract: warning semantics (`rgba(217,119,6,...)` fill and border), singular
  and plural copy, per-run start timestamps, and a dismiss control. Sits inside
  the page inset, above view content.

## Command palette

- File: `crates/hf-gui/src/components/CommandPalette.tsx`
- Description: Global keyboard-driven navigation overlay.
- Contract:
  - Opens on Cmd/Ctrl+K. Arrow keys move, Enter navigates, Escape closes.
  - `role="dialog"`, `aria-modal="true"`, labelled by `palette.ariaLabel`.
  - `width: min(560px, 92vw)`, `--shadow-lg`, 140 ms entry animation.

## Settings shell

- File: `crates/hf-gui/src/components/settings/SettingsView.tsx`
- Description: Full-window settings layout replacing the normal app shell.
- Contract:
  - Category rail on the left, active panel on the right, save action in the
    header.
  - Every section is one draft: typed `value`, optional `raw` TOML text, a
    `mode` of `form | raw`, and a `dirty` flag. Generic sections round-trip
    losslessly through TOML.
  - `mode` resets to `form` on section change. Secret-bearing integrations are
    deliberately typed-only and never exposed through the raw editor.
  - The form/raw switch is a 34 px track with a 12 px knob; the active side is
    `--accent` at weight 600.
