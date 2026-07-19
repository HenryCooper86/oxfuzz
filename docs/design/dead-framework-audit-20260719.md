# Dead-framework audit (wire-or-delete) -- 2026-07-19

Verifies the meta-finding in `grok-build-lessons-20260719.md` per-module before any
deletion. **Outcome: do not bulk-delete.** What the report called "dead framework" is,
on inspection, *deliberately-retained, self-tested, publicly-exported* scaffolding -- and
part of it is now wired. Removing it is an owner decision, not mechanical dead-code removal.
The genuine trust hazard (docs/prompt advertising capabilities that do not exist) is already
fixed (MR !103, !104).

## Method

For each candidate: count references outside its defining crate's `src` (excluding
comments); check re-exports; check intra-crate consumers; note any documented retention
decision. A candidate is "orphaned" only with zero real uses AND no documented intent to keep.

## Findings

| Item | Crate | Status | Evidence |
|---|---|---|---|
| `IntraTurnPruner` / `pruning` | hf-context | **WIRED** | `hf-agent/src/lib.rs:621` calls `IntraTurnPruner::from_config`. Report was stale. |
| `simple::*`, `CompactionEngine`, `CompactionLlm` | hf-context | **WIRED** | the active agent context path (this session's L3 work). |
| `MemoryClient`, `ExperienceStore` | hf-core | **USED** | 2 and 1 impl/dyn/bound uses outside hf-core. Report was stale. |
| `ContextPipeline`, `ContextManager`, `RecallStore`, `ContextWindowGuard`, `WorkingMemory` | hf-context | **DELIBERATELY RETAINED** | `hf-agent/src/lib.rs:9-20` documents these as "deliberately not wired" with a rationale. Exported + self-tested. |
| `DynamicToolManager`, `ToolTaxonomy`, `ToolActivationSet`, `ResultFormatter` | hf-tools | **RETAINED (undocumented)** | 0 external uses, but each is exported and has its own unit tests. Self-contained, maintained. |
| `SkillRegistry` (trait), `AgentRunner` (trait) | hf-core | **ORPHANED** | 0 real uses (only comments). Note: `hf-skills::SkillRegistry` is a *separate real struct* -- the hf-core trait is shadowed and unused. |

## Recommendation

1. **Do not delete the retained context/tools framework.** It is documented as deliberate
   (hf-context), or exported + self-tested (hf-tools). Deleting removes public API and a
   foundation the team ported on purpose, and contradicts the "deliberately not wired" note.
   Wiring or removing it is a product/architecture call for the owner.
2. **The two orphaned hf-core traits** (`SkillRegistry`, `AgentRunner`) are the only clean
   delete candidates -- they define behavior nothing provides or consumes. But they are
   base-crate *public contracts* and may be intended scaffolding, so they still warrant an
   explicit owner decision before removal (and their modules hold other used types, so a
   removal must be surgical, not whole-file).
3. **The real fix already shipped**: the docs/prompt no longer advertise nonexistent
   self-evolution/meta-agents (MR !103, !104). That was the trust/maintenance hazard; the
   retained scaffolding, honestly labeled, is not one.

## Per-candidate deletion checklist (if the owner opts in)

1. `grep -rn "<Sym>" crates/` -> zero non-comment, non-self, non-test references.
2. Confirm no re-export is consumed (an unused `pub use` is itself removable).
3. Remove the item (surgically -- keep sibling types in the same module), then
   `cargo build --workspace --all-features` and the full suite must stay green.
