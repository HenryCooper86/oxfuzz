use super::{
    CoverageExperimentBuildComparison, CoverageExperimentEdgeComparison,
    CoverageExperimentInputChange, CoverageExperimentLimitation, CoverageExperimentRecord,
    CoverageExperimentResultEvidenceV1, CoverageExperimentRunEvidenceV1, CoverageExperimentStatus,
    DateTime, Deserialize, RunKind, RunStatus, Serialize, Utc, Uuid,
};
use crate::{harness_build_input_sha256, StorageError};
use chrono::{Datelike, SecondsFormat, Timelike};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

pub(super) fn invalid(field: &str) -> StorageError {
    StorageError::InvalidData(format!("coverage experiment: {field}"))
}
pub(super) fn uuid(id: Uuid) -> Result<(), StorageError> {
    if id.is_nil() {
        return Err(invalid("nil UUID"));
    }
    Ok(())
}
pub(super) fn parse_uuid(value: &str) -> Result<Uuid, StorageError> {
    let id = Uuid::parse_str(value).map_err(|_| invalid("UUID"))?;
    uuid(id)?;
    if id.to_string() != value {
        return Err(invalid("noncanonical UUID"));
    }
    Ok(id)
}
pub(super) fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}
pub(super) fn valid_time(time: DateTime<Utc>) -> Result<(), StorageError> {
    if !(1..=9999).contains(&time.year()) || time.nanosecond() >= 1_000_000_000 {
        return Err(invalid("timestamp"));
    }
    Ok(())
}
pub(super) fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    let time = value
        .parse::<DateTime<Utc>>()
        .map_err(|_| invalid("timestamp"))?;
    valid_time(time)?;
    if timestamp(time) != value {
        return Err(invalid("noncanonical timestamp"));
    }
    Ok(time)
}
pub(super) fn project(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > 4096 {
        return Err(invalid("project path length"));
    }
    crate::build_profile_store::validate_project(value)
}
pub(super) fn text(value: &str, limit: usize, multiline: bool) -> Result<(), StorageError> {
    if value.is_empty()
        || value.len() > limit
        || value.trim() != value
        || value
            .chars()
            .any(|ch| ch.is_control() && !(multiline && matches!(ch, '\n' | '\t')))
    {
        return Err(invalid("text"));
    }
    Ok(())
}
fn digest(value: &str) -> Result<(), StorageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid("SHA-256"));
    }
    Ok(())
}
pub(super) fn run(run: &CoverageExperimentRunEvidenceV1) -> Result<(), StorageError> {
    if run.schema_version != 1 {
        return Err(invalid("run schema_version"));
    }
    for id in [run.run_id, run.target_id, run.harness_id] {
        uuid(id)?;
    }
    if let Some(id) = run.replay_of {
        uuid(id)?;
    }
    project(&run.project_root)?;
    text(&run.target_symbol, 1024, false)?;
    if let Some(path) = &run.seed_corpus {
        if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
            return Err(invalid("seed corpus path"));
        }
    }
    if run.kind != RunKind::Campaign
        || !matches!(
            run.status,
            RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
        )
    {
        return Err(invalid("terminal campaign required"));
    }
    valid_time(run.started_at)?;
    valid_time(run.ended_at)?;
    if run.started_at > run.ended_at {
        return Err(StorageError::CoverageExperimentInvalidChronology);
    }
    if !(1..=604_800).contains(&run.duration_secs)
        || run.max_mem_mb == 0
        || run.max_mem_mb > i64::MAX as u64
        || run.max_cpus == 0
        || run.edges.is_some_and(|v| v > i64::MAX as u64)
    {
        return Err(invalid("run settings or edges"));
    }
    if run.engine_env.len() > 128 || run.engine_args.len() > 128 {
        return Err(invalid("environment or argument count"));
    }
    for (key, value) in &run.engine_env {
        if key.is_empty()
            || key.len() > 256
            || value.len() > 4096
            || key.contains('\0')
            || value.contains('\0')
        {
            return Err(invalid("environment"));
        }
    }
    if run
        .engine_args
        .iter()
        .any(|s| s.len() > 4096 || s.contains('\0'))
    {
        return Err(invalid("engine arguments"));
    }
    for value in [
        &run.harness_rev,
        &run.binary_rev,
        &run.source_rev,
        &run.corpus_rev,
    ] {
        digest(value)?;
    }
    if let Some(value) = &run.context_rev {
        digest(value)?;
    }
    let image_digest = run
        .sandbox_rev
        .strip_prefix("docker-image-id-sha256:")
        .ok_or_else(|| invalid("sandbox revision"))?;
    digest(image_digest)?;
    if let Some(inputs) = &run.build_inputs {
        uuid(inputs.harness_id)?;
        project(&inputs.project_root)?;
        valid_time(inputs.created_at)?;
        if inputs.harness_id != run.harness_id || inputs.project_root != run.project_root {
            return Err(invalid("build input owner"));
        }
        if inputs.created_at > run.started_at {
            return Err(StorageError::CoverageExperimentInvalidChronology);
        }
        for value in [
            inputs.profile_sha256.as_deref(),
            inputs.compile_database_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            digest(value)?;
        }
        digest(&inputs.compile_flags_sha256)?;
        digest(&inputs.build_input_sha256)?;
        if inputs.profile_sha256.is_some() && inputs.compile_database_sha256.is_none() {
            return Err(invalid("configured build database"));
        }
        let image =
            hf_core::runtime::ImmutableImageReference::from_sha256_id(&inputs.sandbox_image_id)
                .map_err(|_| invalid("build image"))?;
        if image.reference() != format!("sha256:{image_digest}") {
            return Err(invalid("build image differs from run sandbox"));
        }
        if harness_build_input_sha256(
            inputs.profile_sha256.as_deref(),
            inputs.compile_database_sha256.as_deref(),
            &inputs.compile_flags_sha256,
            &inputs.sandbox_image_id,
        )? != inputs.build_input_sha256
        {
            return Err(invalid("combined build digest"));
        }
    }
    json_text(run)?;
    Ok(())
}
pub(super) fn record(record: &CoverageExperimentRecord) -> Result<(), StorageError> {
    uuid(record.id)?;
    if record.id.get_version_num() != 4
        || record.id.get_variant() != uuid::Variant::RFC4122
        || record.schema_version != 1
    {
        return Err(invalid("proposal identity or version"));
    }
    project(&record.project_root)?;
    uuid(record.target_id)?;
    uuid(record.baseline_run_id)?;
    text(&record.target_symbol, 1024, false)?;
    text(&record.goal_function, 1024, false)?;
    text(&record.hypothesis, 4096, true)?;
    run(&record.baseline)?;
    let b = &record.baseline;
    if b.run_id != record.baseline_run_id
        || b.project_root != record.project_root
        || b.target_id != record.target_id
        || b.target_symbol != record.target_symbol
        || b.duration_secs != record.duration_secs
    {
        return Err(invalid("baseline relational identity"));
    }
    valid_time(record.created_at)?;
    valid_time(record.updated_at)?;
    if record.updated_at < record.created_at || b.ended_at > record.created_at {
        return Err(StorageError::CoverageExperimentInvalidChronology);
    }
    if let Some(end) = record.ended_at {
        valid_time(end)?;
    }
    match record.status {
        CoverageExperimentStatus::Prepared
            if record.result.is_none()
                && record.cancellation_reason.is_none()
                && record.ended_at.is_none()
                && record.updated_at == record.created_at => {}
        CoverageExperimentStatus::Cancelled
            if record.result.is_none()
                && record.cancellation_reason.is_some()
                && record.ended_at == Some(record.updated_at) =>
        {
            text(
                record
                    .cancellation_reason
                    .as_deref()
                    .ok_or_else(|| invalid("reason"))?,
                4096,
                true,
            )?;
        }
        CoverageExperimentStatus::Completed
            if record.result.is_some()
                && record.cancellation_reason.is_none()
                && record.ended_at == Some(record.updated_at) =>
        {
            let result = record.result.as_ref().ok_or_else(|| invalid("result"))?;
            validate_result(record, result)?;
        }
        _ => return Err(invalid("state fields")),
    }
    Ok(())
}
fn validate_result(
    record: &CoverageExperimentRecord,
    result: &CoverageExperimentResultEvidenceV1,
) -> Result<(), StorageError> {
    run(&result.run)?;
    if result.schema_version != 1
        || result.run.run_id == record.baseline_run_id
        || result.run.project_root != record.project_root
        || result.run.target_id != record.target_id
    {
        return Err(invalid("result relational identity or version"));
    }
    if result.run.started_at <= record.created_at || result.run.ended_at > record.updated_at {
        return Err(StorageError::CoverageExperimentInvalidChronology);
    }
    if result.limitations.len() > 16 {
        return Err(invalid("limitations count"));
    }
    let codes: Vec<_> = result
        .limitations
        .iter()
        .map(enum_text)
        .collect::<Result<_, _>>()?;
    if codes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("limitations must be sorted and unique"));
    }
    if !result
        .limitations
        .contains(&CoverageExperimentLimitation::AggregateEdgesNotFunctionEntry)
    {
        return Err(invalid("aggregate edge limitation is required"));
    }
    if result.build_comparison
        != CoverageExperimentBuildComparison::from_snapshots(&record.baseline, &result.run)
        || result.input_change
            != CoverageExperimentInputChange::from_snapshots(
                record.kind,
                &record.baseline,
                &result.run,
            )
        || result.edge_comparison
            != CoverageExperimentEdgeComparison::from_snapshots(&record.baseline, &result.run)?
    {
        return Err(invalid("comparison metadata differs from snapshots"));
    }
    json_text(result)?;
    Ok(())
}
pub(super) fn enum_text<T: Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("enum"))
}
pub(super) fn enum_from<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.into()))?)
}
// The wire encoding always uses nanosecond UTC timestamps, including nested
// Phase 6 inputs whose general-purpose serde formatter has variable precision.
fn canonical_times(value: &mut Value) -> Result<(), StorageError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "started_at" | "ended_at" | "created_at") {
                    if let Value::String(s) = value {
                        let time = s
                            .parse::<DateTime<Utc>>()
                            .map_err(|_| invalid("timestamp"))?;
                        valid_time(time)?;
                        *s = timestamp(time);
                    }
                } else {
                    canonical_times(value)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                canonical_times(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn json_text<T: Serialize>(value: &T) -> Result<String, StorageError> {
    let mut value = serde_json::to_value(value)?;
    canonical_times(&mut value)?;
    let text = serde_json::to_string(&value)?;
    if text.len() > 65_536 {
        return Err(invalid("evidence exceeds 65536 bytes"));
    }
    Ok(text)
}
pub(super) fn strict_json<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, StorageError> {
    if text.len() > 65_536 {
        return Err(invalid("evidence exceeds 65536 bytes"));
    }
    let value = unique_json(text)?;
    let result: T = serde_json::from_value(value.clone())?;
    let canonical: Value = serde_json::from_str(&json_text(&result)?)?;
    if canonical != value {
        return Err(invalid("noncanonical or missing evidence fields"));
    }
    Ok(result)
}
/// Parse arbitrary retained source JSON without silently accepting duplicate keys.
pub(super) fn unique_json(text: &str) -> Result<Value, StorageError> {
    Ok(serde_json::from_str::<UniqueValue>(text)?.0)
}
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = serde_json::Map::new();
                while let Some((key, value)) = access.next_entry::<String, UniqueValue>()? {
                    if map.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueValue(Value::Object(map)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
