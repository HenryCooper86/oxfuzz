//! Persistable Clang semantic analysis evidence; no execution or approval authority.
//!
//! | Type | Purpose |
//! | --- | --- |
//! | [`ClangIndex`] | Versioned compiler-resolved declarations and call sites |
//! | [`ClangLimits`] | Explicit service-resolved analysis budgets |
//! | [`ClangTargetContext`] | Advisory target facts supplied to a provider |

use serde::{Deserialize, Serialize};

/// Explicitly resolved collection and execution limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangLimits {
    /// Shortlisted target ceiling.
    pub max_targets: usize,
    /// Compiler invocation ceiling.
    pub max_translation_units: usize,
    /// Staged input byte ceiling.
    pub max_snapshot_bytes: u64,
    /// JSON output byte ceiling.
    pub max_output_bytes: usize,
    /// Function record ceiling.
    pub max_functions: usize,
    /// Call record ceiling.
    pub max_calls: usize,
    /// Total runtime deadline.
    pub timeout_secs: u64,
    /// Sandbox memory budget.
    pub memory_mb: u64,
    /// Sandbox CPU budget.
    pub cpus: u32,
    /// Model-visible section byte ceiling.
    pub max_context_bytes: usize,
}

/// Project-relative source coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangLocation {
    /// Project-relative file using slash separators.
    pub file: String,
    /// One-based line.
    pub line: u32,
    /// One-based column.
    pub column: u32,
}

/// One captured compiler invocation and its declared linked scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangUnit {
    /// SHA-256 of normalized argv and working directory.
    pub id: String,
    /// Relative main source file.
    pub file: String,
    /// Explicit linked scope, or the unit ID without such an assumption.
    pub scope: String,
}

/// Compiler-resolved parameter declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangParameter {
    /// Declared parameter name; may be empty.
    pub name: String,
    /// Clang's canonical printed parameter type.
    pub type_name: String,
}

/// Unit-qualified USR identity.
pub type ClangFunctionId = String;

/// Whether a declaration requires a C++ receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClangMethodKind {
    /// An ordinary function.
    Function,
    /// An instance method requiring a receiver.
    Instance,
    /// A static method with no receiver.
    Static,
}

/// A function declaration, optionally carrying a project definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangFunction {
    /// Unit-qualified canonical declaration identity.
    pub id: ClangFunctionId,
    /// Owning invocation ID.
    pub unit: String,
    /// Canonical Clang USR, local to its owning invocation.
    pub usr: String,
    /// Qualified declaration name.
    pub name: String,
    /// Project definition/declaration location, absent for external headers.
    pub location: Option<ClangLocation>,
    /// Project declaration locations, including headers, separate from the definition.
    pub declarations: Vec<ClangLocation>,
    /// Canonical result type.
    pub result_type: String,
    /// Ordered parameter declarations.
    pub parameters: Vec<ClangParameter>,
    /// Whether extra variadic arguments are accepted.
    pub variadic: bool,
    /// Clang declaration linkage.
    pub linkage: String,
    /// C++ access specifier, or none.
    pub access: String,
    /// Function, instance method, or static method.
    pub method_kind: ClangMethodKind,
    /// Whether the indexed project contains this body in this unit.
    pub definition: bool,
}

/// Static dispatch evidence; only direct calls provide exact declaration edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClangDispatch {
    /// Resolved direct declaration.
    Direct,
    /// Declared virtual method; runtime override is unknown.
    Virtual,
    /// Function-pointer or other indirect dispatch.
    Indirect,
    /// No declaration could be resolved.
    Unresolved,
}

/// One syntactic call with semantic declaration resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangCall {
    /// Caller declaration identity.
    pub caller: ClangFunctionId,
    /// Declared callee, absent when not resolved.
    pub callee: Option<ClangFunctionId>,
    /// Dispatch classification.
    pub dispatch: ClangDispatch,
    /// Project call-site location.
    pub location: ClangLocation,
}

/// Strict version-1 helper output, independent of discovery candidate scores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangIndex {
    /// Wire version, currently one.
    pub schema_version: u32,
    /// Full Clang toolchain version.
    pub clang_version: String,
    /// SHA-256 of the dispatched helper executable.
    pub helper_sha256: String,
    /// Parsed invocations, including explicit linked scope assumptions.
    pub units: Vec<ClangUnit>,
    /// Canonical function declarations.
    pub functions: Vec<ClangFunction>,
    /// Located call records, including unresolved calls.
    pub calls: Vec<ClangCall>,
}

/// Association between a discovery candidate and compiler declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClangTargetAssociation {
    /// A unique definition was matched by file, position, and name.
    Exact(ClangFunctionId),
    /// No matching project definition was indexed.
    Unavailable,
    /// Several build variants or definitions match.
    Ambiguous,
}

/// Bounded advisory metadata for a selected target; not path-feasibility evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangTargetContext {
    /// Candidate-to-declaration association.
    pub association: ClangTargetAssociation,
    /// The matched target when unambiguous.
    pub target: Option<ClangFunction>,
    /// Shortest potential direct-call routes, including their entry identity.
    pub paths: Vec<Vec<ClangFunctionId>>,
    /// Declarations needed to interpret routes and direct callers.
    pub functions: Vec<ClangFunction>,
    /// Bounded located call sites supporting the static routes.
    pub calls: Vec<ClangCall>,
    /// Call-site records omitted from context.
    pub omitted_calls: usize,
    /// Virtual, indirect, unresolved, or externally undefined calls in the slice.
    pub unresolved_calls: usize,
    /// Records omitted from bounded context.
    pub omitted_functions: usize,
}
