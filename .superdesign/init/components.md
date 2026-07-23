# Shared UI Primitives

Framework: React 19 with TypeScript. Every primitive below is hand-written;
Radix UI backs exactly one of them (`Select`). Styling combines UnoCSS utility
classes with CSS variables from `src/styles/index.css`.

Each entry lists the file and its exported surface. The file is authoritative --
props change, and a copy of the source here would drift. `SettingsGroup` aside,
everything here is re-exported from `crates/hf-gui/src/components/ui/index.ts`.

## Button

- File: `crates/hf-gui/src/components/ui/Button.tsx`
- Description: Primary action button primitive; `forwardRef`, extends native button attributes.
- Variants: `primary | ghost | danger | outline | icon`. Sizes: `sm | md`.

## IconButton

- File: `crates/hf-gui/src/components/ui/IconButton.tsx`
- Description: Compact icon-only action primitive; `forwardRef`, extends native button attributes.
- Props: `size` (number, default 28), `danger`.

## Input

- File: `crates/hf-gui/src/components/ui/Input.tsx`
- Description: Text input primitive with shared focus and disabled states. Exports both `Input` and `Textarea`, each `forwardRef` over its native element.

## Select

- File: `crates/hf-gui/src/components/ui/Select.tsx`
- Description: The one Radix-backed primitive (`@radix-ui/react-select`).
- Props: `value`, `options` (`{ value, label }[]`), `onChange`, `mono`, `disabled`, `placeholder`.
- Note: Radix reserves the empty string for "no selection", so an item may not use it. An empty `options` list plus `placeholder` is how a select with nothing to offer says so instead of rendering a blank box.

## Badge

- File: `crates/hf-gui/src/components/ui/Badge.tsx`
- Description: Compact semantic status label.
- Variants: `default | accent | success | error | warning`. Sizes: `sm | xs` (default `xs`).

## SeverityBadge

- File: `crates/hf-gui/src/components/ui/SeverityBadge.tsx`
- Description: Crash-severity status badge.
- Props: `severity` (string), `title`.

## Switch

- File: `crates/hf-gui/src/components/ui/Switch.tsx`
- Description: Boolean preference control.
- Props: `checked`, `onChange`, `label`, `ariaLabel`, `disabled`.

## Separator

- File: `crates/hf-gui/src/components/ui/Separator.tsx`
- Description: Visual divider. A styled `div`, not the Radix separator.
- Props: `orientation` (`horizontal | vertical`, default `horizontal`).

## ViewCanvas

- File: `crates/hf-gui/src/components/ui/ViewCanvas.tsx`
- Description: The per-view content wrapper `App.tsx` applies to every routed view. Renders a `.view-scroll` region around a `.view-canvas` child, supplying the 24 px inset, the 1440 px cap, and the centring. Part of the shell contract rather than a per-view choice.
- Props: `children`.

## ViewHeader

- File: `crates/hf-gui/src/components/ui/ViewHeader.tsx`
- Description: Standard page title and optional supporting description.
- Props: `title`, `description`.

## EmptyState

- File: `crates/hf-gui/src/components/ui/EmptyState.tsx`
- Description: Empty-result guidance state.
- Props: `icon` (required), `hint` (required), `title`, `action`.

## Loading

- File: `crates/hf-gui/src/components/ui/Loading.tsx`
- Description: Shared loading indicators. Exports `Spinner` (`size`, default 16), `LoadingState` (`label`), and `Skeleton`.

## ErrorState

- File: `crates/hf-gui/src/components/ui/ErrorState.tsx`
- Description: Recoverable error presentation.
- Props: `message` (required), `title`, `action`.

## Tooltip

- File: `crates/hf-gui/src/components/ui/Tooltip.tsx`
- Description: Hand-rolled tooltip built on React context and `useState`, not Radix. Exports `TooltipProvider` and `Tooltip` (`text`, `children`).
- Gap: renders a positioned div with no ARIA association to its trigger and no Escape handling. Do not assume Radix tooltip semantics.

## Toast

- File: `crates/hf-gui/src/components/ui/Toast.tsx`
- Description: Hand-rolled toast viewport and provider, not Radix. Exports `ToastProvider`; consumers use `useToast` from `./toastContext`.

## SettingsGroup

- File: `crates/hf-gui/src/components/ui/SettingsGroup.tsx`
- Description: Grouped settings section and row primitives. Exports `SettingsGroup` (`title`, `description`, `children`) and `SettingsItem` (`title`, `description`, `children`, `stacked`).
