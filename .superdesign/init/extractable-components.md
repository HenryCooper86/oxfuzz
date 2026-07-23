# Extractable Superdesign Components

"Extractable props" below are *proposed* parameters for a standalone design
mockup -- the knobs a static extraction would need to show the component in its
interesting states. They are not the live component signatures. Several of these
components take no props at all in the app and read from context or poll a
status endpoint instead (`ProgressPanel`, `SandboxBanner`).

For real signatures see `components.md` or the source file. Where a proposed
prop would collide with or misrepresent the real API, that is called out in the
entry.

## Layout Components

## Sidebar

- Source: `crates/hf-gui/src/components/Sidebar.tsx`
- Category: layout
- Description: Persistent project-aware navigation: brand block, new-target button, then the Recent targets, Pipeline, Results, AI System, Vehicle, and Integrations sections, with Help and Settings pinned in the footer.
- Extractable props: `activeItem` (string, default: `dashboard`), `showRecentProject` (boolean, default: `true`), `recentProjectName` (string, default: `libfuzzer_fuzzme`)
- Hardcoded: product structure, section labels, Lucide icon choices, open-project button, footer hint, spacing, colors, and all CSS classes

## Header

- Source: `crates/hf-gui/src/components/Header.tsx`
- Category: layout
- Description: Persistent top bar with sidebar control, active-view identity, utility-panel toggles, and theme control.
- Extractable props: `title` (string, default: `Dashboard`), `theme` (string, default: `dark`), `showPanelToggles` (boolean, default: `true`), `reserveLeftInset` (boolean, default: `false`)
- Hardcoded: title treatment, Lucide icon styling, window drag behavior, dimensions, and chrome styling

## StatusBar

- Source: `crates/hf-gui/src/components/StatusBar.tsx`
- Category: layout
- Description: Bottom operational-health strip for sandbox, engines, integrations, and local time.
- Extractable props: `sandboxReady` (boolean, default: `true`), `activeEngineCount` (number, default: `5`), `defectDojoReady` (boolean, default: `true`)
- Hardcoded: provider names, status-dot styling, separators, typography, and clock position

## ProgressPanel

- Source: `crates/hf-gui/src/components/ProgressPanel.tsx`
- Category: layout
- Description: Right-hand campaign progress rail showing the four fuzzing lifecycle stages.
- Real signature: no props. It reads `usePipeline()` and derives its open state from stage completion (see `lib/progressPanel.ts`).
- Extractable props: `currentStep` (string, default: `triage`), `completedCount` (number, default: `4`), `isCollapsed` (boolean, default: `false`)
- Hardcoded: four workflow stage labels, icons, progress-line styling, and reset affordance

## SettingsView

- Source: `crates/hf-gui/src/components/settings/SettingsView.tsx`
- Category: layout
- Description: Full-window settings editor with category rail, form/raw modes, save action, and active panel.
- Extractable props: `activeTab` (string, default: `fuzzing`), `mode` (string, default: `form`), `hasUnsavedChanges` (boolean, default: `false`)
- Hardcoded: settings categories, icon choices, header arrangement, side rail dimensions, and content spacing

## CommandPalette

- Source: `crates/hf-gui/src/components/CommandPalette.tsx`
- Category: layout
- Description: Global modal command/search surface for keyboard navigation.
- Extractable props: `isOpen` (boolean, default: `true`), `query` (string, default: `Search`), `activeItem` (string, default: `Dashboard`)
- Hardcoded: command taxonomy, shortcuts, icons, dialog treatment, and matching behavior

## Basic Components

## ViewHeader

- Source: `crates/hf-gui/src/components/ui/ViewHeader.tsx`
- Category: basic
- Description: Standard view heading and optional supporting description.
- Extractable props: `title` (string, default: `Dashboard`), `description` (string, default: `Campaign readiness and next actions`)
- Hardcoded: heading sizes, vertical rhythm, typography, and color tokens

## Button

- Source: `crates/hf-gui/src/components/ui/Button.tsx`
- Category: basic
- Description: Shared action control with primary, secondary, ghost, and danger treatments.
- Extractable props: `variant` (string, default: `primary`), `disabled` (boolean, default: `false`)
- Hardcoded: sizing, font weight, focus treatment, radius, and all visual classes

## Badge

- Source: `crates/hf-gui/src/components/ui/Badge.tsx`
- Category: basic
- Description: Compact semantic label used for readiness, engines, severity, and workflow state.
- Extractable props: `variant` (string, default: `default`), `size` (string, default: `xs`)
- Hardcoded: text casing, radii, token mapping, padding, and border treatment

## SettingsGroup

- Source: `crates/hf-gui/src/components/ui/SettingsGroup.tsx`
- Category: basic
- Description: Reusable settings section with explanatory copy and bordered rows.
- Extractable props: `title` (string, default: `Run defaults`), `description` (string, default: `Defaults for new interactive runs`)
- Hardcoded: section rhythm, row dividers, typography, and responsive layout

## SandboxBanner

- Source: `crates/hf-gui/src/components/SandboxBanner.tsx`
- Category: basic
- Description: Safety-state banner showing whether builds and execution are isolated.
- Extractable props: `sandboxReady` (boolean, default: `true`), `showDetails` (boolean, default: `true`)
- Hardcoded: shield icon, safety language, semantic colors, and banner styling

## FuzzingPolicyNotice

- Source: `crates/hf-gui/src/components/FuzzingPolicyNotice.tsx`
- Category: basic
- Description: Policy-load failure notice for safety-sensitive actions. It is rendered only where the policy is missing (all three call sites guard on `{!fuzzingSettings && ...}`), so it has no success state to show.
- Real signature: `{ loaded: boolean; error: string | null }` -- there is no `hasError` prop.
- Careful: the `loaded` flag reads backwards. `loaded === true` selects the *failure* branch (error border, error text, `AlertTriangle`, `fuzzing.policyUnavailable`); `loaded === false` renders the spinner. A mockup built from "loaded, no error" will show the red banner, not a benign confirmation.
- Extractable props: `loaded` (boolean, default: `false` for the loading state; set `true` to show the failure banner), `error` (string or null, default: `null`)
- Hardcoded: policy copy, severity mapping, icons, and notice layout

## ReportPreview

- Source: `crates/hf-gui/src/components/ReportPreview.tsx`
- Category: basic
- Description: Structured report preview used before exporting or handing off findings.
- Extractable props: `isOpen` (boolean, default: `true`), `reportTitle` (string, default: `Campaign report`)
- Hardcoded: report field hierarchy, action placement, modal styling, and technical typography
