//! State a property, check it on every input, and identify what violated it.
//!
//! A sanitizer finds memory-safety faults. It does not find a decoder that
//! returns the wrong answer, a round-trip that loses data, or an invariant that
//! quietly stops holding. An oracle is a property, stated by a human, checked on
//! every input.
//!
//! This module owns the specification vocabulary, its validation, deterministic
//! scaffold rendering, and violation classification. Building and running an
//! oracle harness use the existing approved compile, smoke, and campaign paths;
//! nothing here executes.
//!
//! See `docs/design/oracle-studio-design.md`.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Schema version of the oracle specification.
pub const ORACLE_SCHEMA_VERSION: u32 = 1;

/// Line an oracle scaffold writes when its property is violated. Retained in
/// the finding's output, which is what makes the classification
/// reconstructable.
pub const ORACLE_VIOLATION_MARKER: &str = "OXFUZZ_ORACLE_VIOLATION";

/// Longest accepted symbol. Identifiers this long are not real, and the value
/// is interpolated into generated source.
const MAX_SYMBOL_LEN: usize = 128;

/// Longest accepted property description.
const MAX_DESCRIPTION_LEN: usize = 1024;

/// Which property an oracle checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    Differential,
    RoundTrip,
    Invariant,
}

impl OracleKind {
    /// Stable wire identifier, matching the serde form and the marker line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Differential => "differential",
            Self::RoundTrip => "round_trip",
            Self::Invariant => "invariant",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "differential" => Some(Self::Differential),
            "round_trip" => Some(Self::RoundTrip),
            "invariant" => Some(Self::Invariant),
            _ => None,
        }
    }
}

/// The property itself, with the symbols it compares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OracleProperty {
    /// `target` and `reference` must agree on every input.
    Differential { reference: String },
    /// `decode(encode(x))` must reproduce `x`.
    RoundTrip { encode: String, decode: String },
    /// `predicate` must hold after every call to the target.
    Invariant { predicate: String },
}

/// One human-authored, reviewable oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSpec {
    pub id: Uuid,
    pub target_symbol: String,
    pub property: OracleProperty,
    /// What the property means, in the author's words. Retained so a later
    /// reader knows what was claimed, not merely which symbols were compared.
    pub description: String,
}

impl OracleSpec {
    /// Which kind of property this specification states.
    #[must_use]
    pub fn kind(&self) -> OracleKind {
        match self.property {
            OracleProperty::Differential { .. } => OracleKind::Differential,
            OracleProperty::RoundTrip { .. } => OracleKind::RoundTrip,
            OracleProperty::Invariant { .. } => OracleKind::Invariant,
        }
    }

    /// Every symbol this specification interpolates into generated source.
    fn symbols(&self) -> Vec<(&'static str, &str)> {
        let mut symbols = vec![("target", self.target_symbol.as_str())];
        match &self.property {
            OracleProperty::Differential { reference } => {
                symbols.push(("reference", reference.as_str()));
            }
            OracleProperty::RoundTrip { encode, decode } => {
                symbols.push(("encode", encode.as_str()));
                symbols.push(("decode", decode.as_str()));
            }
            OracleProperty::Invariant { predicate } => {
                symbols.push(("predicate", predicate.as_str()));
            }
        }
        symbols
    }
}

/// A recorded violation of a named property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OracleViolation {
    pub oracle_id: Uuid,
    pub kind: OracleKind,
}

/// Why a specification was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OracleError {
    /// A symbol is not a plain identifier. This is the injection boundary: the
    /// value would otherwise be interpolated into generated C source.
    #[error(
        "the {role} symbol must be a plain C identifier, bounded to {MAX_SYMBOL_LEN} characters"
    )]
    Symbol { role: &'static str },
    /// The description is empty or over-long.
    #[error("the property description must be present and under {MAX_DESCRIPTION_LEN} characters")]
    Description,
}

/// Validate a specification before it can reach generated source.
///
/// Fails closed: a symbol is accepted only if it is a leading letter or
/// underscore followed by letters, digits, or underscores.
///
/// # Errors
/// Returns the first offending symbol or description problem.
pub fn validate_spec(spec: &OracleSpec) -> Result<(), OracleError> {
    for (role, symbol) in spec.symbols() {
        if !is_plain_identifier(symbol) {
            return Err(OracleError::Symbol { role });
        }
    }
    let description = spec.description.trim();
    if description.is_empty() || spec.description.len() > MAX_DESCRIPTION_LEN {
        return Err(OracleError::Description);
    }
    Ok(())
}

/// Render the deterministic C harness for a specification.
///
/// The same specification always produces the same source, so a reviewer who
/// approved a scaffold approved exactly what gets built.
///
/// # Errors
/// Returns an error when the specification does not validate.
pub fn render_oracle_harness(spec: &OracleSpec) -> Result<String, OracleError> {
    validate_spec(spec)?;
    let kind = spec.kind();
    let target = spec.target_symbol.as_str();
    let id = spec.id;

    let mut source = String::new();
    let _ = writeln!(
        source,
        "// oxfuzz oracle harness (schema {ORACLE_SCHEMA_VERSION})."
    );
    let _ = writeln!(
        source,
        "// Property ({}): {}",
        kind.as_str(),
        sanitize_comment(&spec.description)
    );
    let _ = writeln!(source, "// Oracle id: {id}");
    // Recorded for every kind, including round-trip, whose subject is the
    // encode/decode pair rather than the target itself.
    let _ = writeln!(source, "// Discovered target: {target}");
    let _ = writeln!(source, "//");
    let _ = writeln!(
        source,
        "// This harness deliberately terminates when the property is violated."
    );
    let _ = writeln!(
        source,
        "// That is the signal being sought; see docs/design/oracle-studio-design.md."
    );
    source.push_str(PRELUDE);
    let _ = writeln!(source, "{}", violation_macro(id, kind));

    match &spec.property {
        OracleProperty::Differential { reference } => {
            let _ = writeln!(source, "int {target}(const uint8_t *data, size_t size);");
            let _ = writeln!(source, "int {reference}(const uint8_t *data, size_t size);");
            let _ = write!(
                source,
                "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n\
                 \x20   int actual = {target}(data, size);\n\
                 \x20   int expected = {reference}(data, size);\n\
                 \x20   if (actual != expected) {{\n\
                 \x20       oxfuzz_oracle_violation();\n\
                 \x20   }}\n\
                 \x20   return 0;\n\
                 }}\n"
            );
        }
        OracleProperty::RoundTrip { encode, decode } => {
            let _ = writeln!(
                source,
                "int {encode}(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);"
            );
            let _ = writeln!(
                source,
                "int {decode}(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);"
            );
            let _ = write!(
                source,
                "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n\
                 \x20   if (size == 0 || size > OXFUZZ_ORACLE_MAX) {{\n\
                 \x20       return 0;\n\
                 \x20   }}\n\
                 \x20   static uint8_t encoded[OXFUZZ_ORACLE_MAX * 2];\n\
                 \x20   static uint8_t decoded[OXFUZZ_ORACLE_MAX * 2];\n\
                 \x20   size_t encoded_len = sizeof(encoded);\n\
                 \x20   size_t decoded_len = sizeof(decoded);\n\
                 \x20   if ({encode}(data, size, encoded, &encoded_len) != 0) {{\n\
                 \x20       return 0;\n\
                 \x20   }}\n\
                 \x20   if ({decode}(encoded, encoded_len, decoded, &decoded_len) != 0) {{\n\
                 \x20       return 0;\n\
                 \x20   }}\n\
                 \x20   /* A rejected input is not a violation; a round trip that\n\
                 \x20      succeeds and changes the value is. */\n\
                 \x20   if (decoded_len != size || memcmp(decoded, data, size) != 0) {{\n\
                 \x20       oxfuzz_oracle_violation();\n\
                 \x20   }}\n\
                 \x20   return 0;\n\
                 }}\n"
            );
        }
        OracleProperty::Invariant { predicate } => {
            let _ = writeln!(source, "int {target}(const uint8_t *data, size_t size);");
            let _ = writeln!(source, "int {predicate}(void);");
            let _ = write!(
                source,
                "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n\
                 \x20   {target}(data, size);\n\
                 \x20   if ({predicate}() == 0) {{\n\
                 \x20       oxfuzz_oracle_violation();\n\
                 \x20   }}\n\
                 \x20   return 0;\n\
                 }}\n"
            );
        }
    }
    Ok(source)
}

/// Classify a finding's retained output as an oracle violation.
///
/// Only the marker makes a finding an oracle violation: an oracle harness can
/// also dereference a null pointer, and that is a memory-safety finding rather
/// than a violated property. Absence of a marker means no violation was
/// recorded, not that the property holds.
#[must_use]
pub fn classify_oracle_violation(output: &str) -> Option<OracleViolation> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(ORACLE_VIOLATION_MARKER)?;
        let mut fields = rest.split_whitespace();
        let oracle_id = Uuid::parse_str(fields.next()?).ok()?;
        let kind = OracleKind::parse(fields.next()?)?;
        Some(OracleViolation { oracle_id, kind })
    })
}

/// Shared prelude. `OXFUZZ_ORACLE_MAX` bounds the round-trip scratch buffers.
const PRELUDE: &str = "\n#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\n#define OXFUZZ_ORACLE_MAX 4096\n\n";

/// The failure path: record the marker as retained evidence, flush so it
/// survives termination, then stop.
///
/// `__builtin_trap()` rather than `assert`, which `NDEBUG` removes and would
/// leave an oracle that silently checks nothing.
fn violation_macro(id: Uuid, kind: OracleKind) -> String {
    format!(
        "static void oxfuzz_oracle_violation(void) {{\n\
         \x20   fprintf(stderr, \"{ORACLE_VIOLATION_MARKER} {id} {}\\n\");\n\
         \x20   fflush(stderr);\n\
         \x20   __builtin_trap();\n\
         }}\n",
        kind.as_str()
    )
}

/// Whether a value is a plain C identifier of bounded length.
fn is_plain_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_SYMBOL_LEN {
        return false;
    }
    let mut chars = value.chars();
    let first = chars.next().unwrap_or('\0');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Keep a description from closing the comment it is rendered into.
fn sanitize_comment(description: &str) -> String {
    description.replace("*/", "* /").replace(['\n', '\r'], " ")
}

/// Request to render a specification for review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleScaffoldRequest {
    pub spec: OracleSpec,
}

/// The scaffold a specification produces, for review before anything is built.
#[derive(Debug, Clone, Serialize)]
pub struct OracleScaffoldView {
    pub schema_version: u32,
    pub spec: OracleSpec,
    pub kind: OracleKind,
    /// The exact source that will be built, shown in full before it is.
    pub source: String,
    /// Non-blocking lint findings, for the reviewer.
    pub lint: Vec<String>,
    /// Whether the lint would refuse this source. A scaffold that cannot build
    /// is not worth reviewing.
    pub blocking_lint: bool,
}

impl crate::container::ServiceContainer {
    /// Render a specification into the harness it produces, for review.
    ///
    /// Executes nothing. Building and running the result use the existing
    /// approved compile, smoke, and campaign paths.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the specification does not
    /// validate.
    pub fn oracle_scaffold(
        &self,
        req: OracleScaffoldRequest,
    ) -> Result<OracleScaffoldView, hf_core::error::ClassifiedError> {
        use hf_core::error::ClassifiedError;

        let source = render_oracle_harness(&req.spec)
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let findings = hf_harness::lint_harness_source(&source, hf_core::target::TargetLanguage::C);
        Ok(OracleScaffoldView {
            schema_version: ORACLE_SCHEMA_VERSION,
            kind: req.spec.kind(),
            spec: req.spec,
            blocking_lint: hf_harness::has_blocking_finding(&findings),
            lint: findings
                .iter()
                .map(|finding| format!("{}: {}", finding.rule, finding.message))
                .collect(),
            source,
        })
    }

    /// Classify one retained finding as an oracle violation, if its log says so.
    ///
    /// Reads the sanitizer log ingest paired with the crash input. Only the
    /// marker makes a finding an oracle violation: an oracle harness can also
    /// dereference a null pointer, which is a memory-safety finding rather than
    /// a violated property.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable or the
    /// finding is unknown.
    pub async fn oracle_violation_for_crash(
        &self,
        crash_id: Uuid,
    ) -> Result<Option<OracleViolation>, hf_core::error::ClassifiedError> {
        use hf_core::error::ClassifiedError;

        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("oracle classification requires persistent storage".to_owned())
        })?;
        let crash = store
            .get_crash(crash_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("finding {crash_id} not found")))?;
        let run_dir = crash
            .input_path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        let Some(log) = hf_crash::ingest::crash_log_for_input(&crash.input_path, &run_dir) else {
            // No retained log is not evidence that the property holds.
            return Ok(None);
        };
        Ok(classify_oracle_violation(&log))
    }
}
