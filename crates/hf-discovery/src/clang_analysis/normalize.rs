use super::ClangAnalysisError;
use hf_core::clang_analysis::{ClangIndex, ClangLimits, ClangLocation};
use std::collections::HashSet;

fn bounded(value: &str, max: usize) -> bool {
    value.len() <= max && !value.contains('\0')
}

fn relative(value: &str) -> bool {
    !value.is_empty()
        && bounded(value, 4096)
        && !value.contains(['\\', ':'])
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn location(value: &ClangLocation) -> bool {
    relative(&value.file) && value.line > 0 && value.column > 0
}

/// Decode bounded foreign JSON and validate references and project coordinates.
///
/// # Errors
/// Rejects unsupported versions, invalid identities, paths, and collection limits.
pub fn normalize_index(
    bytes: &[u8],
    limits: &ClangLimits,
) -> Result<ClangIndex, ClangAnalysisError> {
    let invalid = || ClangAnalysisError("schema, reference, or collection limit".into());
    if bytes.len() > limits.max_output_bytes {
        return Err(invalid());
    }
    let mut index: ClangIndex =
        serde_json::from_slice(bytes).map_err(|e| ClangAnalysisError(e.to_string()))?;
    if index.schema_version != 1
        || index.units.is_empty()
        || index.units.len() > limits.max_translation_units
        || index.functions.len() > limits.max_functions
        || index.calls.len() > limits.max_calls
        || !bounded(&index.clang_version, 4096)
        || index.clang_version.is_empty()
        || index.helper_sha256.len() != 64
        || !index
            .helper_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid());
    }
    let mut units = HashSet::new();
    for unit in &index.units {
        if unit.id.is_empty()
            || !bounded(&unit.id, 1024)
            || !relative(&unit.file)
            || unit.scope.is_empty()
            || !bounded(&unit.scope, 1024)
            || !units.insert(&unit.id)
        {
            return Err(invalid());
        }
    }
    let mut ids = HashSet::new();
    for f in &index.functions {
        if f.id.is_empty()
            || f.usr.is_empty()
            || !bounded(&f.id, 1024)
            || !bounded(&f.usr, 1024)
            || !units.contains(&f.unit)
            || !ids.insert(&f.id)
            || [&f.name, &f.result_type, &f.linkage, &f.access]
                .iter()
                .any(|v| !bounded(v, 4096))
            || f.location.as_ref().is_some_and(|v| !location(v))
            || (f.definition && f.location.is_none())
            || f.parameters.len() > 1024
            || f.parameters
                .iter()
                .any(|p| !bounded(&p.name, 4096) || !bounded(&p.type_name, 4096))
        {
            return Err(invalid());
        }
    }
    for call in &index.calls {
        if !ids.contains(&call.caller)
            || !location(&call.location)
            || call.callee.as_ref().is_some_and(|c| !ids.contains(c))
            || (call.dispatch == hf_core::clang_analysis::ClangDispatch::Direct
                && call.callee.is_none())
        {
            return Err(invalid());
        }
    }
    index.units.sort_by(|a, b| a.id.cmp(&b.id));
    index.functions.sort_by(|a, b| a.id.cmp(&b.id));
    index.calls.sort_by(|a, b| {
        (
            &a.caller,
            &a.location.file,
            a.location.line,
            a.location.column,
            &a.callee,
        )
            .cmp(&(
                &b.caller,
                &b.location.file,
                b.location.line,
                b.location.column,
                &b.callee,
            ))
    });
    Ok(index)
}
