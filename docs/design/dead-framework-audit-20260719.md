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
| `DynamicToolManager`, `ToolTaxonomy`, `ToolActivationSet`, `ResultFormatter` | hf-tools | **REMOVED 2026-08-28** | The owner decision this audit called for. Still 0 external uses a year on; deleted with the `parser` module. See the follow-up below. |
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

## Follow-up -- 2026-08-28 (the hf-tools decision)

The owner decided: delete. All five modules -- `activation`, `dynamic`,
`formatter`, `parser`, `taxonomy` -- are gone (3,776 lines, of which ~1,780 were
their own unit tests; those tests were the only callers).

The recommendation above ("do not delete... it is exported + self-tested") did
not survive re-examination. Being exported and self-tested is what made these
modules look maintained; it is not evidence that anything needs them. Each was
re-verified unreachable before removal, under every feature flag -- there are
none in `hf-tools` or `hf-agent` -- with the type-name search that would catch a
use through any re-export chain. The only mention outside the crate was a doc
comment in `hf-core`.

Two of the five were dead for reasons no amount of retention would fix:

- `parser` implements a `<tool_call>` XML grammar the agent never emits. The
  shipped prompt (`config/prompts/core_tool_protocol.txt`) instructs the model
  to reply with one JSON object, and `hf-agent` decodes it with
  `serde_json::from_str::<Step>`.
- `taxonomy` parses a TOML category tree. No such TOML exists anywhere in the
  repo, so `from_toml` had no production input, and the design doc it cites
  (`docs/design/tool-search-design.md`) does not exist either.

`dynamic` additionally rejected two of its three kinds (`HttpApi`, `Composite`)
at both validation and execution with "not enabled in the current phase".

The seven live modules -- `builtin`, `config`, `error`, `executor`, `index`,
`registry`, `validator` -- were untouched. `docs/standards/TOOL_CALL_PROTOCOL.md`
sections 2 and 5, which promised the removed modules as retained extension and
integration infrastructure, were corrected in the same change: a standard that
promises a capability the code does not have is worse than one that stays quiet.
