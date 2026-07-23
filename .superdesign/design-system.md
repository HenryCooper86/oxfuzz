# oxfuzz Interface Design System

## Product Context

oxfuzz is a safety-first desktop operator console for AI-assisted fuzzing. It helps security engineers choose targets, generate and approve harnesses, run sandboxed fuzzers, triage crashes, manage corpora, and retain evidence. The interface must make trust boundaries, approval state, engine readiness, evidence provenance, and the next safe action immediately legible.

Primary users are security engineers, fuzzing specialists, and automotive security operators working for long sessions on technical tasks. The desktop canvas is the primary target; layouts should remain usable from roughly 1180 px upward and degrade gracefully at narrower widths.

## Information Architecture

- Persistent left rail, in order: brand block (logo plus `oxfuzz` wordmark), new-target button, then six labelled sections -- Recent targets (a list, with a per-row remove control and an empty state), Pipeline (dashboard, workflow, and its discover/harness/run/triage/corpus children), Results (projects, artifacts, reports, runs, audit), AI System (chat, agents, skills, knowledge, automation), Vehicle (automotive), and Integrations (DefectDojo, shown only once configured) -- plus a pinned footer carrying Help and Settings. All sections are flat; see the redesign constraints below.
- Persistent top header: sidebar toggle, active-view identity, progress/diagnostic/observability/info panel controls, and theme control.
- Main workspace: active route content with a standard 24 px inset on most pages.
- Optional right rail: four-stage campaign progress and observation panels.
- Persistent bottom status bar: Docker/sandbox, engines, integrations, and time.
- Settings uses a dedicated full-window shell with its own category rail.

Key journey: Dashboard -> Discover -> Harness -> Run -> Triage -> Corpus/Reports. Human approval and sandbox status must be visible before any execution step.

## Visual Character

The current identity is a restrained, technical operations console: near-black neutral surfaces, warm brass accents, sparse semantic color, compact typography, fine borders, and almost no decorative imagery. Preserve this serious, evidence-oriented character. Do not introduce gradients, neon effects, glassmorphism, decorative serif typography, oversized marketing copy, or consumer-dashboard ornament.

## Color Tokens

`crates/hf-gui/src/styles/index.css` is the authoritative source for every token
below; this list is a design-facing summary of it. If the two disagree, the
stylesheet is right and this file is stale.

The text tokens carry a deliberate accessibility floor set by commit 366d6f6:
dark muted `#8c8881` on `#0f0f0f` measures 5.43:1 and light muted `#6d6761` on
`#ffffff` measures 5.58:1, both clearing WCAG AA. Do not darken them.

### Dark theme (default)

- Primary surface: `#0f0f0f`
- Secondary surface: `#141414`
- Tertiary surface: `#1c1c1c`
- Code surface: `#1a1a1a`
- Hover surface: `rgba(255, 255, 255, 0.045)`
- Active surface: `rgba(255, 255, 255, 0.06)`
- Primary text: `#e8e6e1`
- Secondary text: `#aaa59e`
- Muted text: `#8c8881`
- Accent: `#c8b560`
- Accent hover: `#d4c26e`
- Accent subtle: `rgba(200, 181, 96, 0.1)`
- Accent glow: `rgba(200, 181, 96, 0.15)`
- Accent contrast: `#0f0f0f`
- Border: `rgba(255, 255, 255, 0.08)`
- Focus border: `rgba(255, 255, 255, 0.15)`

### Light theme

- Primary surface: `#ffffff`
- Secondary surface: `#f5f4f1`
- Tertiary surface: `#edecea`
- Code surface: `#f1efed`
- Hover surface: `rgba(0, 0, 0, 0.04)`
- Active surface: `rgba(0, 0, 0, 0.06)`
- Primary text: `#1a1917`
- Secondary text: `#6b6560`
- Muted text: `#6d6761`
- Accent: `#9a7c2a`
- Accent hover: `#7e6420`
- Accent subtle: `rgba(154, 124, 42, 0.08)`
- Accent glow: `rgba(154, 124, 42, 0.12)`
- Accent contrast: `#ffffff`
- Border: `rgba(0, 0, 0, 0.13)`
- Focus border: `rgba(0, 0, 0, 0.22)`

### Semantic colors

- Success: dark `#6fcf97`, light `#3a9d6b`
- Error/danger: dark `#e57373`, light `#c0392b`
- Warning: dark `#f0c050`, light `#c0880a`
- Information: dark `#60a5fa`, light `#2563eb`
- Semantic color is reserved for real state. Brass indicates focus, selection, brand, and the primary recommended action; it must not masquerade as success or warning.

## Typography

- Body/UI: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`
- Display/chrome: `"SF Pro Display", "SF Pro Icons", "Helvetica Neue", Helvetica, Arial, sans-serif`
- Code/identifiers: `"SF Mono", "Fira Code", "Cascadia Code", Consolas, monospace`
- Body baseline: 13–14 px with 1.45–1.55 line height.
- Navigation and labels: 12–13 px; section eyebrows may use 10–11 px uppercase with tracking.
- View title: 20–24 px, semibold. Card title: 13–15 px, semibold.
- Technical numbers use tabular numerals where alignment matters.
- Do not use italic type for primary view identity; italics may appear only in secondary metadata.

## Spacing and Geometry

- Spacing scale: 4, 8, 16, 24, and 40 px (`--space-xs` through `--space-xl`).
- Standard page inset: 24 px.
- Dense control gap: 8 px. Related group gap: 16 px. Major-section gap: 24 px.
- Radius scale: 4 px controls, 8 px cards/inputs, 12 px large panels and modal shells.
- Borders are one pixel and subtle; use surface shifts before adding more borders.
- Left navigation is 240 px (`--sidebar-width`, with 240 px as the fallback). The right progress rail is 280 px expanded and 64 px collapsed; a redesign must supply both states.
- View content sits in a canvas capped at 1440 px and centred (`.view-canvas`), inside a 24 px-inset scroll region (`.view-scroll`). Below 768 px the inset drops to 16 px; below 1100 px the dashboard supporting band collapses from two columns to one.
- Maintain a clear 44 px minimum pointer target for primary controls even when the visible control is visually compact.

## Elevation

- Dark: `0 2px 8px rgba(0,0,0,.45)`, `0 8px 24px rgba(0,0,0,.55)`, `0 16px 48px rgba(0,0,0,.65)`.
- Light: `0 2px 8px rgba(0,0,0,.08)`, `0 8px 24px rgba(0,0,0,.12)`, `0 16px 48px rgba(0,0,0,.16)`.
- Keep ordinary cards flat; reserve elevation for menus, dialogs, tooltips, and temporary overlays.

## Components

- Buttons: primary brass fill with dark contrast text; secondary uses a subtle border; ghost blends into chrome; danger uses error semantics. One clear primary action per local task region.
- Inputs/selects: secondary surface, one-pixel border, 8 px radius, strong visible focus ring, mono text for paths and identifiers.
- Cards/panels: secondary surface on primary canvas, 8–12 px radius, low-contrast border, 16 px internal padding.
- Badges: short, compact, semantic, and never the sole carrier of state; pair color with text/icon.
- Tables/lists: 40–48 px rows, aligned technical columns, sticky heading where scrolling is long, hover only for actionable rows.
- Empty states: explain why the region is empty and provide one safe next action. Do not leave the majority of the canvas blank without guidance.
- Safety notices: shield/lock identity, explicit sandbox and approval language, semantic state, and a direct link to evidence or policy details.
- Progress: show current state and next action. Completed progress should collapse to a compact summary rather than permanently consuming the full rail.

## Interaction and Motion

- Default transitions: 150–200 ms ease for color, border, opacity, and small transforms.
- Panels may slide/fade no more than 8–12 px; avoid large spatial movement in an operations console.
- Loading indicators must not imply a fuzzing operation is running unless it is actually executing.
- Honor `prefers-reduced-motion` by removing nonessential animation.
- Keyboard navigation, command palette access, visible focus, and Escape-to-close are first-class desktop behaviors.

## Accessibility and Safety Constraints

- Meet WCAG AA text contrast, including secondary labels and disabled states. The shipped muted tokens already clear AA (see Color Tokens); any redesign must keep them at or above that ratio rather than reverting to the darker pre-366d6f6 values.
- Never communicate ready/approved/sandboxed/error state by color alone.
- Destructive actions require clear labels, red semantics, and confirmation.
- Execution controls must name the sandbox/engine context and approval prerequisite nearby.
- Preserve long paths and hashes with ellipsis plus a copy/reveal affordance.
- Prioritize scanability: state, evidence, and next action should appear before descriptive prose.

## Layout Conventions for Design Exploration

- Keep the current app shell, product palette, fonts, semantic colors, safety language, and core navigation taxonomy.
- A conservative polish may improve contrast, typography, density, title duplication, completed-progress behavior, card hierarchy, and empty states without moving major destinations.
- A structural redesign may regroup the Dashboard around `Needs attention`, `Campaign state`, and `Evidence`, and may collapse the right-hand progress and observation panels, but it must not remove human approval, sandbox status, or provenance cues.
- Sidebar navigation stays flat. Collapsible secondary sections were tried in f86383f and deliberately reverted in 41ea503, which deleted `CollapsibleNavSection` and `lib/sidebarSections.ts`; `crates/hf-gui/src/__tests__/sidebarLayout.test.ts` now asserts that machinery is absent. Do not put Results or AI System behind disclosure toggles.
- Product identity lives in the sidebar brand block only. The header carries no logo or wordmark, and `crates/hf-gui/src/__tests__/branding.test.ts` asserts both halves of that split.
- The header view title is secondary context, not display type: 14 px, weight 500, `--text-secondary`, never italic (`crates/hf-gui/src/__tests__/uiPolish.test.ts`).
- Use ONLY the fonts, colors, spacing, radii, shadows, and component styles defined here and in `crates/hf-gui/src/styles/index.css`.
