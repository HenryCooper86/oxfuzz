use std::collections::BTreeMap;

/// Current JSONL envelope schema understood by the Rust domain contract.
pub const AUTOMOTIVE_SCHEMA_VERSION: u16 = 1;

pub(crate) const MAX_EVENTS: u32 = 1_000_000;
pub(crate) const MAX_PAYLOAD_BYTES: u32 = 1024 * 1024;
pub(crate) const MAX_DURATION_MS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const MAX_RATE_PER_SECOND: u32 = 100_000;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_METADATA_ENTRIES: usize = 128;

/// Validation failure for an automotive sidecar request or result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// The JSONL envelope uses a schema this crate does not understand.
    #[error("unsupported automotive schema {actual}; expected {expected}")]
    UnsupportedSchema {
        /// Supported schema version.
        expected: u16,
        /// Received schema version.
        actual: u16,
    },
    /// A mandatory string, collection, or value was absent.
    #[error("required field '{field}' is missing")]
    MissingField {
        /// Domain field name.
        field: &'static str,
    },
    /// A field was present but malformed.
    #[error("invalid field '{field}': {reason}")]
    InvalidField {
        /// Domain field name.
        field: &'static str,
        /// Human-readable invariant that failed.
        reason: String,
    },
    /// A bounded value exceeds its domain maximum.
    #[error("field '{field}' exceeds maximum {maximum}: {actual}")]
    LimitExceeded {
        /// Domain field name.
        field: &'static str,
        /// Maximum accepted value.
        maximum: u64,
        /// Received value.
        actual: u64,
    },
    /// A transcript or replay plan repeats a sequence identifier.
    #[error("duplicate sequence number {sequence}")]
    DuplicateSequence {
        /// Repeated sequence number.
        sequence: u64,
    },
    /// Related fields disagree about protocol, mode, count, or digest.
    #[error("inconsistent field '{field}': {reason}")]
    InconsistentField {
        /// Domain field name.
        field: &'static str,
        /// Human-readable invariant that failed.
        reason: String,
    },
    /// Canonical serialization unexpectedly failed.
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

/// Fail-closed validation shared by schema envelopes and their payloads.
pub trait Validate {
    /// Check all local domain invariants without performing I/O.
    ///
    /// # Errors
    /// Returns a structured [`ContractError`] for the first failed invariant.
    fn validate(&self) -> Result<(), ContractError>;
}

pub(crate) fn nonempty_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::MissingField { field });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ContractError::LimitExceeded {
            field,
            maximum: MAX_TEXT_BYTES as u64,
            actual: value.len() as u64,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::InvalidField {
            field,
            reason: "control characters are forbidden".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn safe_virtual_interface(value: &str) -> Result<(), ContractError> {
    nonempty_text("mode.interface", value)?;
    let Some(suffix) = value.strip_prefix("vcan") else {
        return Err(ContractError::InvalidField {
            field: "mode.interface",
            reason: "virtual CAN interfaces must use the form vcanN".to_owned(),
        });
    };
    if suffix.is_empty() || suffix.len() > 3 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ContractError::InvalidField {
            field: "mode.interface",
            reason: "virtual CAN interfaces must use vcan plus one to three digits".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn safe_physical_interface(value: &str) -> Result<(), ContractError> {
    nonempty_text("mode.interface", value)?;
    if value.len() > 32
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ContractError::InvalidField {
            field: "mode.interface",
            reason: "expected a 1-32 byte non-path interface identifier".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn safe_artifact_id(value: &str) -> Result<(), ContractError> {
    nonempty_text("artifact.artifact_id", value)?;
    let mut bytes = value.bytes();
    let starts_safely = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if value.len() > 128
        || !starts_safely
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidField {
            field: "artifact.artifact_id",
            reason: "expected a 1-128 byte staged identifier, not a path".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn lower_hex(
    field: &'static str,
    value: &str,
    allow_empty: bool,
) -> Result<(), ContractError> {
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(ContractError::MissingField { field })
        };
    }
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidField {
            field,
            reason: "expected an even-length lowercase hexadecimal string".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn bounded_metadata(
    field: &'static str,
    values: &BTreeMap<String, String>,
) -> Result<(), ContractError> {
    if values.len() > MAX_METADATA_ENTRIES {
        return Err(ContractError::LimitExceeded {
            field,
            maximum: MAX_METADATA_ENTRIES as u64,
            actual: values.len() as u64,
        });
    }
    for (key, value) in values {
        nonempty_text(field, key)?;
        nonempty_text(field, value)?;
    }
    Ok(())
}

pub(crate) fn positive_bounded(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ContractError> {
    if value == 0 {
        return Err(ContractError::MissingField { field });
    }
    if value > maximum {
        return Err(ContractError::LimitExceeded {
            field,
            maximum,
            actual: value,
        });
    }
    Ok(())
}
