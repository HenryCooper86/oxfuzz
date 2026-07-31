//! Project and target identity resolution.
//!
//! A project is addressed by path from three presentation layers and stored
//! canonically. A target is addressed by bare symbol or by the file-scoped
//! `file::symbol` qualifier introduced in migration 0019. Both resolutions live
//! here so callers cannot invent their own matching rules.

use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;

/// A human-readable `DefectDojo` product name for a project: its directory
/// basename, falling back to the full path when there is no basename.
pub(super) fn defectdojo_project_name(project: &Path) -> String {
    project
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| project.to_string_lossy().into_owned())
}

pub(super) fn canonical_project_root(project: &Path) -> Result<PathBuf, ClassifiedError> {
    let canonical = std::fs::canonicalize(project).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve project root {}: {error}",
            project.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect project root {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "project root {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

pub(super) fn stored_project_matches(stored: &Path, canonical: &Path) -> bool {
    stored == canonical || std::fs::canonicalize(stored).is_ok_and(|resolved| resolved == canonical)
}

pub(super) fn project_lookup_identity(project: &Path) -> PathBuf {
    std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf())
}

/// Select the candidate referenced by `target` from `candidates`.
///
/// `target` is either a plain symbol or a file-qualified `file::symbol` (the
/// file relative to the project root, matching `TargetCandidate::relative_file`).
/// A plain symbol matching zero candidates yields `Ok(None)` (the caller
/// reports "not found"); exactly one yields that candidate; more than one is a
/// `Validation` error listing the file-qualified forms so the user can
/// disambiguate. When no plain match exists and the string carries a `::`
/// qualifier, the part before the last `::` is matched exactly against each
/// candidate's root-relative file. The plain match is tried first so a symbol
/// that itself contains `::` (C++-style) still resolves.
pub(super) fn select_target_candidate<'c>(
    candidates: &'c [TargetCandidate],
    target: &str,
) -> Result<Option<&'c TargetCandidate>, ClassifiedError> {
    let mut plain = candidates.iter().filter(|c| c.symbol == target);
    if let Some(first) = plain.next() {
        if plain.next().is_some() {
            let mut qualified: Vec<String> = candidates
                .iter()
                .filter(|c| c.symbol == target)
                .map(|c| format!("{}::{}", c.relative_file(), c.symbol))
                .collect();
            qualified.sort();
            qualified.dedup();
            return Err(ClassifiedError::Validation(format!(
                "target '{target}' is ambiguous; qualify it with the defining file: {}",
                qualified.join(", ")
            )));
        }
        return Ok(Some(first));
    }
    if let Some((file, symbol)) = target.rsplit_once("::") {
        if !file.is_empty() && !symbol.is_empty() {
            return Ok(candidates
                .iter()
                .find(|c| c.symbol == symbol && c.relative_file() == file));
        }
    }
    Ok(None)
}

/// A per-project workspace directory name: the human-readable basename plus a
/// short deterministic hash of the full path. The hash disambiguates projects
/// that share a basename (e.g. `/a/libfoo` and `/b/libfoo`) so their persistent
/// workspaces -- and thus compiled binaries, corpora, and crash reproducers --
/// never collide, while the basename keeps the directory recognizable. Stable
/// across processes (SHA-256, unlike `DefaultHasher`), so the same project maps
/// to the same workspace on every invocation.
pub(super) fn project_slug(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    let identity = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
    let name = identity
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    let mut hasher = Sha256::new();
    hasher.update(identity.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{name}-{}", &digest[..8])
}

#[cfg(test)]
mod target_resolution_tests {
    use super::select_target_candidate;
    use hf_core::error::ClassifiedError;
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use std::path::PathBuf;

    fn candidate(file: &str, symbol: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from("/proj"),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from(file),
                line: 1,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: 0.5,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        }
    }

    #[test]
    fn unique_plain_symbol_resolves() {
        let candidates = vec![candidate("/proj/src/a.c", "parse_opts")];
        let found = select_target_candidate(&candidates, "parse_opts").unwrap();
        assert_eq!(found.map(|c| c.id), Some(candidates[0].id));
    }

    #[test]
    fn unknown_plain_symbol_is_not_found() {
        let candidates = vec![candidate("/proj/src/a.c", "parse_opts")];
        assert!(select_target_candidate(&candidates, "missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn ambiguous_plain_symbol_errors_with_file_qualified_forms() {
        let candidates = vec![
            candidate("/proj/src/a.c", "parse_opts"),
            candidate("/proj/src/b.c", "parse_opts"),
            candidate("/proj/src/c.c", "unique_fn"),
        ];
        let Err(ClassifiedError::Validation(message)) =
            select_target_candidate(&candidates, "parse_opts")
        else {
            panic!("an ambiguous symbol must be a validation error");
        };
        assert!(
            message.contains("src/a.c::parse_opts"),
            "lists the src/a.c qualifier: {message}"
        );
        assert!(
            message.contains("src/b.c::parse_opts"),
            "lists the src/b.c qualifier: {message}"
        );
        assert!(
            !message.contains("unique_fn"),
            "unrelated symbols are not listed: {message}"
        );
    }

    #[test]
    fn file_qualified_symbol_resolves_exactly() {
        let candidates = vec![
            candidate("/proj/src/a.c", "parse_opts"),
            candidate("/proj/src/b.c", "parse_opts"),
        ];
        let found = select_target_candidate(&candidates, "src/b.c::parse_opts").unwrap();
        assert_eq!(found.map(|c| c.id), Some(candidates[1].id));
    }

    #[test]
    fn file_qualified_symbol_with_unknown_file_is_not_found() {
        let candidates = vec![candidate("/proj/src/a.c", "parse_opts")];
        assert!(
            select_target_candidate(&candidates, "src/missing.c::parse_opts")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn symbol_containing_colons_prefers_the_plain_match() {
        // A symbol that itself contains `::` (C++-style) still resolves as a
        // plain symbol; the qualifier split is only a fallback.
        let candidates = vec![candidate("/proj/src/ns.c", "ns::func")];
        let found = select_target_candidate(&candidates, "ns::func").unwrap();
        assert_eq!(found.map(|c| c.id), Some(candidates[0].id));
    }
}
