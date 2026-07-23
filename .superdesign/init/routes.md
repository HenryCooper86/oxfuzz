# Routes and Views

The desktop application does not use URL routing. `AppInner` keeps an `activeView: ViewType` state and conditionally mounts one view at a time. The normal shell is `Sidebar + Header + main view + optional observation/progress rails + StatusBar`. Settings replaces that shell; DefectDojo keeps the header/status chrome but hides the sidebar and side panels.

Every routed view is wrapped in the `ViewCanvas` primitive
(`crates/hf-gui/src/components/ui/ViewCanvas.tsx`), which supplies the 24 px
scroll inset and the 1440 px centred content cap. Treat that wrapper as part of
the shell, not as per-view styling.

| Internal route | View component | Source | Layout |
|---|---|---|---|
| `dashboard` | `DashboardView` | `crates/hf-gui/src/views/DashboardView.tsx` | Normal app shell |
| `chat` | `ChatView` | `crates/hf-gui/src/views/ChatView.tsx` | Normal app shell |
| `workflow` | `WorkflowView` | `crates/hf-gui/src/views/WorkflowView.tsx` | Normal app shell |
| `discover` | `DiscoverView` | `crates/hf-gui/src/views/DiscoverView.tsx` | Normal app shell |
| `harness` | `HarnessView` | `crates/hf-gui/src/views/HarnessView.tsx` | Normal app shell |
| `run` | `RunView` | `crates/hf-gui/src/views/RunView.tsx` | Normal app shell |
| `triage` | `TriageView` | `crates/hf-gui/src/views/TriageView.tsx` | Normal app shell |
| `corpus` | `CorpusView` | `crates/hf-gui/src/views/CorpusView.tsx` | Normal app shell |
| `projects` | `ProjectsView` | `crates/hf-gui/src/views/ProjectsView.tsx` | Normal app shell |
| `artifacts` | `ArtifactsView` | `crates/hf-gui/src/views/ArtifactsView.tsx` | Normal app shell |
| `reports` | `ReportsView` | `crates/hf-gui/src/views/ReportsView.tsx` | Normal app shell |
| `runs` | `RunsView` | `crates/hf-gui/src/views/RunsView.tsx` | Normal app shell |
| `audit` | `AuditView` | `crates/hf-gui/src/views/AuditView.tsx` | Normal app shell |
| `agents` | `AgentsView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `skills` | `SkillsView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `knowledge` | `KnowledgeView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `automation` | `AutomationView` | `crates/hf-gui/src/views/FeatureViews.tsx` | Normal app shell |
| `automotive` | `AutomotiveView` | `crates/hf-gui/src/views/AutomotiveView.tsx` | Normal app shell, lazy-loaded |
| `help` | `HelpView` | `crates/hf-gui/src/views/HelpView.tsx` | Normal app shell, lazy-loaded |
| `settings` | `SettingsView` | `crates/hf-gui/src/components/settings/SettingsView.tsx` | Full-window settings shell |
| `defectdojo` | `DefectDojoView` | `crates/hf-gui/src/views/DefectDojoView.tsx` | App main only; sidebar and side panels hidden |

## Key-page summaries

- Dashboard: campaign readiness, counts, attention queue, targets, harness review, recent runs, and crash handoff.
- Discovery: selects a project and identifies/ranks fuzzable functions.
- Harness: generates, sandbox-compiles, smoke-qualifies, reviews, and approves harness revisions.
- Run: starts an approved fuzz run and exposes live coverage/crash throughput.
- Triage: ingests, classifies, deduplicates, reports, and hands off crash artifacts.
- Automotive: safety-gated protocol analysis, replay, campaign synthesis, and retained evidence.
- Settings: engine availability, sandbox limits, providers, storage, integrations, and protected credentials.

## View type definition

- File: `crates/hf-gui/src/types/index.ts`
- `ViewType` is the union of the 21 internal route names in the table above. It
  is the single place a new destination has to be declared; the sidebar item
  lists, the icon map in `App.tsx`, and the command palette all key off it.

## State-based router and shell configuration

- File: `crates/hf-gui/src/App.tsx`
- `AppInner` holds `activeView` and `settingsReturnView`, exposes `navigate`,
  and decides which of the three shell shapes to render (normal, full-window
  settings, DefectDojo). It also owns the `viewIcons: Record<ViewType, ...>` map
  used by the header and palette.
- Each routed view is mounted inside `<ViewCanvas>`. Do not reintroduce a raw
  `<div className="flex-1 overflow-auto">` wrapper per view; that predates the
  `ViewCanvas` extraction and drops the width cap and responsive inset.
