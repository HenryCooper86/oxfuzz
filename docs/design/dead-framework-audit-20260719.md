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
| `MemoryClient`, `ExperienceStore` | hf-core | **REMOVED 2026-08-27** | Was used by the hf-context memory/working-memory subsystems; those were cut, leaving `hf_core::memory` with no consumer under any feature. |
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

## Follow-up -- 2026-08-27

A re-run of the same method (module-path uses, grouped and glob re-exports, and a
`cargo check --workspace --all-targets --all-features` with the module removed)
found six modules that had become orphaned since this audit and carried no
retention decision. They were removed: `hf_core::memory` and `hf_core::trust`
(a `TrustTier` shadowed by the live `hf_skills::TrustTier`),
`hf_session::scheduling` and `hf_session::tree`, and `hf_knowledge::classifier`
and `hf_knowledge::quality`.

The hf-tools framework this audit deliberately retained -- `DynamicToolManager`,
`ToolTaxonomy`, `ToolActivationSet`, `ResultFormatter`, plus the `parser` module
(`parse_tool_calls`, `PROMPT_TOOL_CALL_SYNTAX`, ~1.9k LOC) that this audit did not
cover -- is still unreachable: the agent uses its own JSON step protocol in the
system prompt, not the `<tool_call>` XML syntax the parser reads. It stays put
pending the owner decision this audit called for.
