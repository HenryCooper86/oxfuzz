# Extractable Superdesign Components

## Layout Components

## Sidebar

- Source: `crates/hf-gui/src/components/Sidebar.tsx`
- Category: layout
- Description: Persistent project-aware navigation for pipeline, library, automotive, support, and settings destinations.
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
- Description: Explicit policy-load and failure notice for safety-sensitive actions.
- Extractable props: `loaded` (boolean, default: `true`), `hasError` (boolean, default: `false`)
- Hardcoded: policy copy, severity mapping, icons, and notice layout

## ReportPreview

- Source: `crates/hf-gui/src/components/ReportPreview.tsx`
- Category: basic
- Description: Structured report preview used before exporting or handing off findings.
- Extractable props: `isOpen` (boolean, default: `true`), `reportTitle` (string, default: `Campaign report`)
- Hardcoded: report field hierarchy, action placement, modal styling, and technical typography
