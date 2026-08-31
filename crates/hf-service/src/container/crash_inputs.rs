//! Crash artifact and CASR report collection.
//!
//! Engines lay out their findings differently, and older runs used a flat
//! layout. This module normalizes both into the input paths and CASR reports
//! triage consumes, and derives the stable crash identity used for dedup.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;
use uuid::Uuid;

pub(super) fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn is_regular_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

pub(super) fn stage_crash_inputs(engine: EngineKind, out_dir: &Path, staging: &Path) -> usize {
    if !is_regular_directory(out_dir)
        || std::fs::create_dir_all(staging).is_err()
        || !is_regular_directory(staging)
    {
        return 0;
    }
    let mut staged = 0usize;
    for path in collect_crash_inputs(engine, out_dir) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if std::fs::copy(&path, staging.join(name)).is_ok() {
            staged += 1;
        }
    }
    staged
}

/// Collect crash input file paths from a run output directory, skipping engine
/// bookkeeping. Looks both at the top level (flat-output engines) and one level
/// down under `<instance>/crashes/` (AFL++ output layout).
pub(super) fn collect_crash_inputs(engine: EngineKind, out_dir: &Path) -> Vec<PathBuf> {
    hf_crash::ingest_for_engine(out_dir, engine, Uuid::nil(), Uuid::nil()).map_or_else(
        |error| {
            tracing::warn!(path = %out_dir.display(), %error, "crash artifact scan failed");
            Vec::new()
        },
        |result| {
            if result.is_truncated() {
                tracing::warn!(
                    path = %out_dir.display(),
                    artifact_limit_reached = result.artifact_limit_reached,
                    report_limit_reached = result.report_limit_reached,
                    "crash artifact scan reached a safety limit"
                );
            }
            result
                .crashes
                .into_iter()
                .map(|crash| crash.input_path)
                .collect()
        },
    )
}

pub(super) fn collect_legacy_crash_inputs(out_dir: &Path) -> Vec<PathBuf> {
    hf_crash::ingest(out_dir, Uuid::nil(), Uuid::nil()).map_or_else(
        |_| Vec::new(),
        |crashes| crashes.into_iter().map(|crash| crash.input_path).collect(),
    )
}

/// Collect legacy flat evidence plus every isolated run output for a target.
pub(super) fn collect_workspace_crash_inputs(workspace: &Path) -> Vec<PathBuf> {
    let mut inputs = collect_legacy_crash_inputs(&workspace.join("out"));
    let runs = workspace.join("runs");
    if !is_regular_directory(&runs) {
        return inputs;
    }
    if let Ok(entries) = std::fs::read_dir(runs) {
        for entry in entries.flatten() {
            let run = entry.path();
            if is_regular_directory(&run) {
                inputs.extend(collect_legacy_crash_inputs(&run.join("out")));
            }
        }
    }
    inputs
}

#[cfg(all(test, unix))]
mod crash_input_boundary_tests {
    use super::{collect_crash_inputs, stage_crash_inputs};
    use hf_core::engine::EngineKind;

    #[test]
    fn crash_staging_and_collection_ignore_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        let staging = root.path().join("staging");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("crash-real"), b"real crash").unwrap();

        let outside = root.path().join("outside-secret");
        std::fs::write(&outside, b"must not be staged").unwrap();
        symlink(&outside, out.join("crash-link")).unwrap();

        let collected = collect_crash_inputs(EngineKind::LibFuzzer, &out);
        assert_eq!(collected, vec![out.join("crash-real")]);
        assert_eq!(stage_crash_inputs(EngineKind::LibFuzzer, &out, &staging), 1);
        assert_eq!(
            std::fs::read(staging.join("crash-real")).unwrap(),
            b"real crash"
        );
        assert!(!staging.join("crash-link").exists());

        let external_out = root.path().join("external-out");
        std::fs::create_dir_all(&external_out).unwrap();
        std::fs::write(external_out.join("crash-secret"), b"outside").unwrap();
        let linked_out = root.path().join("linked-out");
        symlink(&external_out, &linked_out).unwrap();
        assert!(collect_crash_inputs(EngineKind::LibFuzzer, &linked_out).is_empty());
        assert_eq!(
            stage_crash_inputs(
                EngineKind::LibFuzzer,
                &linked_out,
                &root.path().join("linked-staging")
            ),
            0
        );
    }
}

/// Recursively collect and parse every `.casrep` report under `dir`.
/// Collapse crashes that CASR placed in the same cluster to one representative
/// (the first seen). Crashes without a cluster id pass through unchanged, so
/// this only ever tightens dedup, never loses an un-clustered crash.
pub(super) fn bucket_by_cluster(crashes: Vec<hf_core::crash::Crash>) -> Vec<hf_core::crash::Crash> {
    let mut seen_clusters = std::collections::HashSet::new();
    let mut kept = Vec::with_capacity(crashes.len());
    for crash in crashes {
        match crash.casr.as_ref().and_then(|c| c.cluster) {
            Some(cluster) if !seen_clusters.insert(cluster) => {} // duplicate cluster -> drop
            _ => kept.push(crash),
        }
    }
    kept
}

pub(super) fn collect_casreps(dir: &Path) -> Vec<(PathBuf, hf_core::crash::CasrReport)> {
    let mut collection = CasrepCollection::default();
    if is_regular_directory(dir) {
        collect_casreps_into(dir, 0, &mut collection);
    }
    if collection.truncated {
        tracing::warn!(
            path = %dir.display(),
            reports = collection.reports.len(),
            bytes = collection.bytes,
            "CASR report collection reached a safety limit"
        );
    }
    collection.reports
}

#[cfg(test)]
mod casrep_collection_boundary_tests {
    use super::collect_casreps;

    const REPORT: &str = r#"{"CrashLine":"parse.c:1:1","Stacktrace":["parse"]}"#;

    #[cfg(unix)]
    #[test]
    fn casrep_collection_never_follows_report_or_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let reports = root.path().join("reports");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(reports.join("real.casrep"), REPORT).unwrap();
        std::fs::write(outside.join("secret.casrep"), REPORT).unwrap();
        symlink(outside.join("secret.casrep"), reports.join("linked.casrep")).unwrap();
        symlink(&outside, reports.join("linked-dir")).unwrap();

        let collected = collect_casreps(&reports);

        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, reports.join("real.casrep"));
    }

    #[test]
    fn casrep_collection_rejects_an_oversized_normalized_report() {
        let root = tempfile::tempdir().unwrap();
        let mut oversized = REPORT.to_owned();
        oversized.push_str(&" ".repeat(hf_crash::MAX_SANITIZER_REPORT_BYTES));
        std::fs::write(root.path().join("oversized.casrep"), oversized).unwrap();

        assert!(collect_casreps(root.path()).is_empty());
    }
}

const MAX_CASREP_DEPTH: usize = 8;

#[derive(Default)]
struct CasrepCollection {
    reports: Vec<(PathBuf, hf_core::crash::CasrReport)>,
    bytes: usize,
    truncated: bool,
}

fn collect_casreps_into(dir: &Path, depth: usize, collection: &mut CasrepCollection) {
    if depth > MAX_CASREP_DEPTH || collection.reports.len() >= hf_crash::MAX_CRASH_ARTIFACTS {
        collection.truncated = true;
        return;
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        tracing::warn!(path = %dir.display(), "could not enumerate CASR report directory");
        return;
    };
    let mut entries = Vec::new();
    for entry in read_dir {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                tracing::warn!(path = %dir.display(), %error, "could not inspect CASR directory entry");
            }
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_dir() {
            collect_casreps_into(&path, depth + 1, collection);
            continue;
        }
        if !metadata.file_type().is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("casrep")
        {
            continue;
        }
        if collection.reports.len() >= hf_crash::MAX_CRASH_ARTIFACTS
            || metadata.len() > hf_crash::MAX_SANITIZER_REPORT_BYTES as u64
            || collection.bytes.saturating_add(metadata.len() as usize)
                > hf_crash::MAX_AGGREGATE_REPORT_BYTES
        {
            collection.truncated = true;
            continue;
        }
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(opened) = file.metadata() else {
            continue;
        };
        if !opened.is_file() || opened.len() != metadata.len() {
            continue;
        }
        let mut content = String::new();
        if file
            .take((hf_crash::MAX_SANITIZER_REPORT_BYTES + 1) as u64)
            .read_to_string(&mut content)
            .is_err()
            || content.len() > hf_crash::MAX_SANITIZER_REPORT_BYTES
        {
            collection.truncated = true;
            continue;
        }
        if let Ok(mut report) = hf_crash::parse_casrep(&content) {
            // CASR groups equivalent crashes into `cl<N>` dirs; carry the
            // cluster id so triage can bucket by it.
            report.cluster = hf_crash::cluster_from_path(&path);
            collection.bytes += content.len();
            collection.reports.push((path, report));
            if collection.reports.len() >= hf_crash::MAX_CRASH_ARTIFACTS {
                collection.truncated = true;
            }
        }
    }
}

/// Map a `.casrep` path back to the crash input it analyzed. CASR names each
/// report after its input file (`id:000….casrep` -> `id:000…`); match that
/// filename against the actual crash inputs so an AFL++ input nested under
/// `out/<instance>/crashes/` resolves to its real location rather than a
/// nonexistent `out/<name>` (which broke `verify_regressions`/reproduce). Falls
/// back to the flat `out_dir/<name>` layout (libFuzzer) when not found.
pub(super) fn casrep_input_path(
    out_dir: &Path,
    casrep: &Path,
    crash_inputs: &[PathBuf],
) -> PathBuf {
    let Some(stem) = casrep.file_stem().and_then(|s| s.to_str()) else {
        return casrep.to_path_buf();
    };
    crash_inputs
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(stem))
        .cloned()
        .unwrap_or_else(|| out_dir.join(stem))
}

/// A stable crash id derived from its run, stack signature, and input file, so
/// re-triaging the same run replaces each crash row rather than inserting a new
/// one (the `crashes` table is keyed on `id`; a fresh random UUID per triage
/// pass would accumulate identical duplicate rows). The input filename keeps
/// distinct crashes apart even when they share (or lack) a signature.
pub(super) fn deterministic_crash_id(run_id: Uuid, signature: &str, input: &Path) -> Uuid {
    let file = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let name = format!("{run_id}|{signature}|{file}");
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}

#[cfg(test)]
mod casrep_path_tests {
    use super::casrep_input_path;
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_afl_nested_crash_input() {
        // AFL++ nests the input under out/<instance>/crashes/; the casrep sits in
        // casr_out. The resolved path must point at the real nested file.
        let out = Path::new("/work/out");
        let nested = PathBuf::from("/work/out/default/crashes/id:000001,sig:06");
        let inputs = vec![nested.clone()];
        let casrep = Path::new("/work/casr_out/id:000001,sig:06.casrep");
        assert_eq!(casrep_input_path(out, casrep, &inputs), nested);
    }

    #[test]
    fn falls_back_to_flat_layout_for_libfuzzer() {
        // libFuzzer crashes sit directly in out/; when the input list does not
        // contain a match, fall back to out/<name>.
        let out = Path::new("/work/out");
        let casrep = Path::new("/work/casr_out/crash-abc.casrep");
        assert_eq!(
            casrep_input_path(out, casrep, &[]),
            PathBuf::from("/work/out/crash-abc")
        );
    }
}

#[cfg(test)]
mod crash_id_tests {
    use super::deterministic_crash_id;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn same_run_signature_and_input_yield_the_same_id() {
        // Re-triaging the same crash must produce the same id (idempotent
        // persistence -> INSERT OR REPLACE collapses the duplicate).
        let run = Uuid::new_v4();
        let a = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        let b = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_runs_or_signatures_yield_distinct_ids() {
        let run = Uuid::new_v4();
        let base = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        // Different input file -> different id (keeps distinct crashes apart).
        assert_ne!(
            base,
            deterministic_crash_id(run, "sig", Path::new("/work/out/crash-def"))
        );
        // Different signature -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(run, "other", Path::new("/work/out/crash-abc"))
        );
        // Different run -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(Uuid::new_v4(), "sig", Path::new("/work/out/crash-abc"))
        );
    }
}
