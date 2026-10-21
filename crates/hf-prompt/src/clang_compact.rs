//! Prompt-local compact serialization of modeled Clang exploration contexts.
//!
//! The durable `ClangTargetContext` repeats unit-qualified declaration
//! identities in every path, call, witness and branch record. This module
//! renders the same evidence with deterministic zero-based symbol indices
//! into a `symbols` table that states each original declaration identity
//! exactly once. No record, constraint, outcome, provenance or limit is
//! dropped; references outside the retained declaration set keep an
//! identity-only entry instead of dangling.

use std::collections::HashMap;

use hf_core::clang_analysis::{
    ClangCfgBlock, ClangCfgStatus, ClangCondition, ClangDispatch, ClangExploration,
    ClangExplorationLimits, ClangFunction, ClangHarnessPlan, ClangInputConstraint, ClangLocation,
    ClangTargetAssociation, ClangTargetContext,
};
use serde::Serialize;

/// Serialize a modeled context with prompt-local symbol references. The
/// caller supplies the retained exploration so both borrow from the context.
///
/// # Errors
/// Returns a serialization error; the view never fails on its own.
pub(crate) fn to_string(
    context: &ClangTargetContext,
    exploration: &ClangExploration,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&CompactContext::new(context, exploration))
}

/// The compact document: `symbols` replaces `functions`, and every identity
/// reference becomes a table index.
#[derive(Serialize)]
struct CompactContext<'a> {
    association: AssociationRef,
    target: Option<u32>,
    paths: Vec<Vec<u32>>,
    symbols: Vec<SymbolEntry<'a>>,
    calls: Vec<GraphCallView<'a>>,
    omitted_calls: usize,
    unresolved_calls: usize,
    omitted_functions: usize,
    exploration: ExplorationView<'a>,
    plan: Option<&'a ClangHarnessPlan>,
}

/// Durable association shape with the exact identity as a symbol index.
#[derive(Serialize)]
#[serde(untagged)]
enum AssociationRef {
    /// The matched declaration as a symbol index.
    Exact { exact: u32 },
    /// A named non-exact association, serialized as the bare variant name.
    Kind(&'static str),
}

/// One symbols-table entry: a full retained declaration, or the identity of
/// a referenced declaration that was not retained.
#[derive(Serialize)]
#[serde(untagged)]
enum SymbolEntry<'a> {
    /// Retained declaration metadata, serialized losslessly.
    Declaration(&'a ClangFunction),
    /// Identity-only entry; no metadata is fabricated.
    Identity { id: &'a str },
}

/// Interns declaration identities into prompt-local indices.
struct SymbolTable<'a> {
    entries: Vec<SymbolEntry<'a>>,
    indices: HashMap<&'a str, u32>,
}

impl<'a> SymbolTable<'a> {
    /// State the target declaration (when present) with full metadata, then
    /// every retained declaration, in order. The target is not necessarily in
    /// `functions`, so it is interned explicitly; a duplicate identity keeps
    /// its records without rewriting the index.
    fn new(functions: &'a [ClangFunction], target: Option<&'a ClangFunction>) -> Self {
        let mut table = Self {
            entries: Vec::new(),
            indices: HashMap::new(),
        };
        if let Some(target) = target {
            let index = table.entries.len() as u32;
            table.entries.push(SymbolEntry::Declaration(target));
            table.indices.insert(target.id.as_str(), index);
        }
        for function in functions {
            if target.is_some_and(|target| target.id == function.id) {
                continue;
            }
            let index = table.entries.len() as u32;
            table.entries.push(SymbolEntry::Declaration(function));
            table.indices.entry(function.id.as_str()).or_insert(index);
        }
        table
    }

    /// Return the index for `id`, adding an identity-only entry when the
    /// declaration was not retained.
    fn intern(&mut self, id: &'a str) -> u32 {
        if let Some(index) = self.indices.get(id) {
            return *index;
        }
        let index = self.entries.len() as u32;
        self.entries.push(SymbolEntry::Identity { id });
        self.indices.insert(id, index);
        index
    }
}

/// A static call record with caller and callee as symbol indices.
#[derive(Serialize)]
struct GraphCallView<'a> {
    caller: u32,
    callee: Option<u32>,
    dispatch: &'a ClangDispatch,
    location: &'a ClangLocation,
}

/// Modeled exploration with every identity reference as a symbol index.
#[derive(Serialize)]
struct ExplorationView<'a> {
    engine: &'a str,
    limits: &'a ClangExplorationLimits,
    roots: Vec<u32>,
    cfgs: Vec<CfgView<'a>>,
    calls: Vec<WitnessView<'a>>,
    branches: Vec<BranchView<'a>>,
    exhausted: bool,
    omitted_records: usize,
}

/// A retained root CFG; blocks serialize unchanged.
#[derive(Serialize)]
struct CfgView<'a> {
    function: u32,
    status: &'a ClangCfgStatus,
    blocks: &'a [ClangCfgBlock],
}

/// A modeled call witness with argument origins and root constraints intact.
#[derive(Serialize)]
struct WitnessView<'a> {
    root: u32,
    caller: u32,
    callee: Option<u32>,
    location: &'a ClangLocation,
    arguments: Vec<ArgumentFlowView<'a>>,
    constraints: &'a [ClangInputConstraint],
    path: Vec<u32>,
}

/// One modeled argument: root-parameter origins, concrete scalar, producer.
#[derive(Serialize)]
struct ArgumentFlowView<'a> {
    argument: usize,
    parameters: &'a [usize],
    constant: Option<&'a str>,
    producer: Option<ProducerView<'a>>,
}

/// A previous call that produced a subsequently passed symbol.
#[derive(Serialize)]
struct ProducerView<'a> {
    function: u32,
    location: &'a ClangLocation,
}

/// A state-specific branch observation with outcomes intact.
#[derive(Serialize)]
struct BranchView<'a> {
    root: u32,
    caller: u32,
    condition: &'a ClangCondition,
    constraints: &'a [ClangInputConstraint],
    true_state: bool,
    false_state: bool,
}

impl<'a> CompactContext<'a> {
    /// Build the compact view in one deterministic traversal: retained
    /// declarations first, then references in document order.
    fn new(context: &'a ClangTargetContext, exploration: &'a ClangExploration) -> Self {
        let mut symbols = SymbolTable::new(&context.functions, context.target.as_ref());
        let association = match &context.association {
            ClangTargetAssociation::Exact(id) => AssociationRef::Exact {
                exact: symbols.intern(id),
            },
            ClangTargetAssociation::Unavailable => AssociationRef::Kind("unavailable"),
            ClangTargetAssociation::Ambiguous => AssociationRef::Kind("ambiguous"),
        };
        let target = context.target.as_ref().map(|t| symbols.intern(&t.id));
        let paths = context
            .paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|id| symbols.intern(id))
                    .collect::<Vec<u32>>()
            })
            .collect();
        let calls = context
            .calls
            .iter()
            .map(|call| GraphCallView {
                caller: symbols.intern(&call.caller),
                callee: call.callee.as_ref().map(|id| symbols.intern(id)),
                dispatch: &call.dispatch,
                location: &call.location,
            })
            .collect();
        let roots = exploration
            .roots
            .iter()
            .map(|id| symbols.intern(id))
            .collect::<Vec<u32>>();
        let cfgs = exploration
            .cfgs
            .iter()
            .map(|cfg| CfgView {
                function: symbols.intern(&cfg.function),
                status: &cfg.status,
                blocks: &cfg.blocks,
            })
            .collect();
        let witnesses = exploration
            .calls
            .iter()
            .map(|witness| WitnessView {
                root: symbols.intern(&witness.root),
                caller: symbols.intern(&witness.caller),
                callee: witness.callee.as_ref().map(|id| symbols.intern(id)),
                location: &witness.location,
                arguments: witness
                    .arguments
                    .iter()
                    .map(|flow| ArgumentFlowView {
                        argument: flow.argument,
                        parameters: &flow.parameters,
                        constant: flow.constant.as_deref(),
                        producer: flow.producer.as_ref().map(|producer| ProducerView {
                            function: symbols.intern(&producer.function),
                            location: &producer.location,
                        }),
                    })
                    .collect(),
                constraints: &witness.constraints,
                path: witness.path.iter().map(|id| symbols.intern(id)).collect(),
            })
            .collect();
        let branches = exploration
            .branches
            .iter()
            .map(|branch| BranchView {
                root: symbols.intern(&branch.root),
                caller: symbols.intern(&branch.caller),
                condition: &branch.condition,
                constraints: &branch.constraints,
                true_state: branch.true_state,
                false_state: branch.false_state,
            })
            .collect();
        Self {
            association,
            target,
            paths,
            symbols: symbols.entries,
            calls,
            omitted_calls: context.omitted_calls,
            unresolved_calls: context.unresolved_calls,
            omitted_functions: context.omitted_functions,
            exploration: ExplorationView {
                engine: &exploration.engine,
                limits: &exploration.limits,
                roots,
                cfgs,
                calls: witnesses,
                branches,
                exhausted: exploration.exhausted,
                omitted_records: exploration.omitted_records,
            },
            plan: context.plan.as_ref(),
        }
    }
}
