//! Project build context extracted from a compile database.
//!
//! A C/C++ project's real compile command carries the include directories,
//! preprocessor defines, and language standard its sources need. oxfuzz compiles
//! a generated harness against those same sources, so it needs the same values;
//! guessing them is the largest single cause of a first-draft harness failing to
//! build.
//!
//! The types here are inert. Parsing and validating a compile database into a
//! [`BuildContext`] is `hf-discovery`'s job, and every value on a `BuildContext`
//! has already passed that validation.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One translation unit as recorded by a compile database.
///
/// Fields are verbatim project input: nothing here has been validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileEntry {
    /// Source file, as recorded. May be absolute or relative to `directory`.
    pub file: PathBuf,
    /// Working directory the recorded command was run from.
    pub directory: PathBuf,
    /// The recorded compiler argument vector.
    pub arguments: Vec<String>,
}

/// Portable compile context extracted from a project's compile database.
///
/// Every field has passed the allowlist in `hf_discovery::build_context`; no
/// value here is raw project input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildContext {
    /// Include directories, absolute and confined to the project root.
    pub include_dirs: Vec<PathBuf>,
    /// Accepted `-D` tokens, e.g. `-DHAVE_CONFIG_H=1`.
    pub defines: Vec<String>,
    /// Accepted language-standard token, e.g. `-std=c11`.
    pub std_flag: Option<String>,
    /// Accepted no-argument flags that change code generation.
    pub extra_flags: Vec<String>,
    /// Translation units the database recorded.
    pub entry_count: usize,
    /// Distinct rejected argument tokens, capped, so an operator can see what
    /// the allowlist dropped instead of guessing.
    pub dropped: Vec<String>,
}

impl BuildContext {
    /// Whether this context carries anything a compiler or a prompt can use.
    ///
    /// A database that parsed cleanly but yielded no include directory, define,
    /// or standard is worth nothing downstream, and callers treat it the same
    /// as a project with no database at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include_dirs.is_empty()
            && self.defines.is_empty()
            && self.std_flag.is_none()
            && self.extra_flags.is_empty()
    }
}
