use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::model::{AutomotiveProtocol, TranscriptEvent};
use super::validation::{
    bounded_metadata, lower_hex, ContractError, Validate, AUTOMOTIVE_SCHEMA_VERSION,
};

/// Validated lowercase SHA-256 digest used by automotive evidence contracts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse an externally supplied lowercase SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`ContractError`] when the value is not exactly 32 encoded bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let digest = Self(value.into());
        digest.validate()?;
        Ok(digest)
    }

    /// Borrow the lowercase hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn hash(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }
}

impl Validate for Sha256Digest {
    fn validate(&self) -> Result<(), ContractError> {
        lower_hex("sha256", &self.0, false)?;
        if self.0.len() != 64 {
            return Err(ContractError::InvalidField {
                field: "sha256",
                reason: "expected exactly 64 hexadecimal characters".to_owned(),
            });
        }
        Ok(())
    }
}

/// Stable protocol state fingerprint derived from sorted string observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSignature {
    /// Protocol whose state machine produced the observations.
    pub protocol: AutomotiveProtocol,
    /// SHA-256 of the schema, protocol, and sorted observations.
    pub digest: Sha256Digest,
    /// Bounded state properties, sorted by key for canonical serialization.
    pub observations: BTreeMap<String, String>,
}

impl StateSignature {
    /// Build a deterministic state signature without accessing a transport.
    ///
    /// # Errors
    /// Returns [`ContractError`] for empty or oversized observations or an
    /// unexpected serialization failure.
    pub fn from_observations(
        protocol: AutomotiveProtocol,
        observations: BTreeMap<String, String>,
    ) -> Result<Self, ContractError> {
        if observations.is_empty() {
            return Err(ContractError::MissingField {
                field: "state.observations",
            });
        }
        bounded_metadata("state.observations", &observations)?;
        let digest = hash_serializable(&(
            AUTOMOTIVE_SCHEMA_VERSION,
            "automotive-state",
            protocol,
            &observations,
        ))?;
        Ok(Self {
            protocol,
            digest,
            observations,
        })
    }
}

impl Validate for StateSignature {
    fn validate(&self) -> Result<(), ContractError> {
        self.digest.validate()?;
        let expected = Self::from_observations(self.protocol, self.observations.clone())?;
        if self.digest != expected.digest {
            return Err(ContractError::InconsistentField {
                field: "state.digest",
                reason: "digest does not match canonical observations".to_owned(),
            });
        }
        Ok(())
    }
}

/// Hash transcript events after sorting by sequence and serializing only
/// schema-defined fields. Metadata maps are `BTreeMap`s, so key insertion order
/// cannot affect the result.
///
/// # Errors
/// Returns [`ContractError`] for an empty or malformed transcript, duplicate
/// sequence numbers, or an unexpected serialization failure.
pub fn canonical_transcript_hash(
    events: &[TranscriptEvent],
) -> Result<Sha256Digest, ContractError> {
    if events.is_empty() {
        return Err(ContractError::MissingField {
            field: "transcript.events",
        });
    }
    let mut canonical = events.to_vec();
    canonical.sort_by_key(|event| event.sequence);
    let mut sequences = BTreeSet::new();
    for event in &canonical {
        event.validate()?;
        if !sequences.insert(event.sequence) {
            return Err(ContractError::DuplicateSequence {
                sequence: event.sequence,
            });
        }
    }
    hash_serializable(&(
        AUTOMOTIVE_SCHEMA_VERSION,
        "automotive-transcript",
        canonical,
    ))
}

fn hash_serializable(value: &impl Serialize) -> Result<Sha256Digest, ContractError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
    Ok(Sha256Digest::hash(&bytes))
}
