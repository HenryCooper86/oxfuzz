//! Engine-specific crash artifact ingestion contract tests.

use std::fs;

use hf_core::{crash::CrashKind, engine::EngineKind};
use hf_crash::{
    ingest_for_engine, MAX_AGGREGATE_REPORT_BYTES, MAX_CRASH_ARTIFACTS, MAX_SANITIZER_REPORT_BYTES,
};
use tempfile::TempDir;
use uuid::Uuid;

const ASAN_PREFIX: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n";

fn ingest(dir: &TempDir, engine: EngineKind) -> hf_crash::CrashIngestResult {
    ingest_for_engine(dir.path(), engine, Uuid::new_v4(), Uuid::new_v4()).unwrap()
}

#[test]
fn honggfuzz_accepts_only_signal_pc_artifacts() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path()
            .join("SIGSEGV.PC.7ffff7a9c0c0.STACK.18d50d2e.fuzz"),
        b"crash",
    )
    .unwrap();
    fs::write(dir.path().join("coverage.fuzz"), b"coverage input").unwrap();
    fs::write(dir.path().join("crash-coverage"), b"coverage input").unwrap();
    fs::write(dir.path().join("coverage.log"), ASAN_PREFIX).unwrap();
    fs::write(dir.path().join("SIGSEGV.STACK.no-pc.fuzz"), b"not valid").unwrap();
    fs::write(dir.path().join("SIGsegv.PC.123.fuzz"), b"not valid").unwrap();

    let result = ingest(&dir, EngineKind::Honggfuzz);

    assert_eq!(result.crashes.len(), 1);
    assert_eq!(
        result.crashes[0].input_path.file_name().unwrap(),
        "SIGSEGV.PC.7ffff7a9c0c0.STACK.18d50d2e.fuzz"
    );
    assert_eq!(result.crashes[0].kind, CrashKind::Other);
    assert_eq!(
        result.report_bytes_read, 0,
        "coverage logs are not sanitizer report candidates"
    );
}

#[test]
fn afl_excludes_readme_case_insensitively() {
    let dir = TempDir::new().unwrap();
    let crashes = dir.path().join("default").join("crashes");
    fs::create_dir_all(&crashes).unwrap();
    // ':' is illegal on NTFS and the name is opaque to the ingester; the
    // README exclusion under test is unaffected.
    fs::write(crashes.join("id_000000,sig_06,src_000000"), b"crash").unwrap();
    fs::write(crashes.join("README.txt"), b"metadata").unwrap();
    fs::write(crashes.join("readme.TXT"), b"metadata").unwrap();
    fs::write(crashes.join("ReadMe.TxT"), b"metadata").unwrap();

    let result = ingest(&dir, EngineKind::AflPlusPlus);

    assert_eq!(result.crashes.len(), 1);
    assert_eq!(
        result.crashes[0].input_path.file_name().unwrap(),
        "id_000000,sig_06,src_000000"
    );
}

#[test]
fn libfuzzer_accepts_only_known_artifact_prefixes() {
    let dir = TempDir::new().unwrap();
    for name in ["crash-a", "leak-b", "timeout-c", "oom-d"] {
        fs::write(dir.path().join(name), b"crash").unwrap();
    }
    for name in [
        "slow-unit-e",
        "input.profraw",
        "coverage.dat",
        "SIGSEGV.PC.123.fuzz",
        "README.txt",
    ] {
        fs::write(dir.path().join(name), b"not a crash").unwrap();
    }

    let result = ingest(&dir, EngineKind::LibFuzzer);
    let names: Vec<_> = result
        .crashes
        .iter()
        .map(|crash| crash.input_path.file_name().unwrap().to_owned())
        .collect();

    assert_eq!(names, ["crash-a", "leak-b", "oom-d", "timeout-c"]);
}

#[test]
fn syzkaller_does_not_ingest_userspace_artifacts() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("crash-userspace"),
        b"not syzkaller evidence",
    )
    .unwrap();

    let result = ingest(&dir, EngineKind::Syzkaller);

    assert!(result.crashes.is_empty());
    assert!(!result.artifact_limit_reached);
}

#[test]
fn artifact_flood_is_sorted_and_truncated_deterministically() {
    let dir = TempDir::new().unwrap();
    for index in (0..MAX_CRASH_ARTIFACTS + 7).rev() {
        fs::write(dir.path().join(format!("crash-{index:05}")), b"crash").unwrap();
    }

    let first = ingest(&dir, EngineKind::LibFuzzer);
    let second = ingest(&dir, EngineKind::LibFuzzer);
    let first_paths: Vec<_> = first
        .crashes
        .iter()
        .map(|crash| crash.input_path.clone())
        .collect();
    let second_paths: Vec<_> = second
        .crashes
        .iter()
        .map(|crash| crash.input_path.clone())
        .collect();

    assert_eq!(first.crashes.len(), MAX_CRASH_ARTIFACTS);
    assert!(first.artifact_limit_reached);
    assert_eq!(first_paths, second_paths);
    assert!(first_paths.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        first_paths
            .last()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy(),
        format!("crash-{:05}", MAX_CRASH_ARTIFACTS - 1)
    );
}

#[test]
fn oversized_sanitizer_report_is_read_within_per_file_limit() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("crash-aaa"), b"crash").unwrap();
    let mut report = ASAN_PREFIX.as_bytes().to_vec();
    report.resize(MAX_SANITIZER_REPORT_BYTES + 1_024, b'x');
    fs::write(dir.path().join("log-aaa.txt"), report).unwrap();

    let result = ingest(&dir, EngineKind::LibFuzzer);

    assert_eq!(result.crashes.len(), 1);
    assert_eq!(result.crashes[0].kind, CrashKind::Asan);
    assert!(result.report_limit_reached);
    assert_eq!(result.report_bytes_read, MAX_SANITIZER_REPORT_BYTES);
}

#[test]
fn aggregate_sanitizer_reports_are_bounded() {
    let dir = TempDir::new().unwrap();
    let report_count = MAX_AGGREGATE_REPORT_BYTES / MAX_SANITIZER_REPORT_BYTES + 1;
    for index in 0..report_count {
        fs::write(dir.path().join(format!("crash-{index:03}")), b"crash").unwrap();
        let mut report = ASAN_PREFIX.as_bytes().to_vec();
        report.resize(MAX_SANITIZER_REPORT_BYTES, b'x');
        fs::write(dir.path().join(format!("log-{index:03}.txt")), report).unwrap();
    }

    let result = ingest(&dir, EngineKind::LibFuzzer);

    assert_eq!(result.crashes.len(), report_count);
    assert!(result.report_limit_reached);
    assert_eq!(result.report_bytes_read, MAX_AGGREGATE_REPORT_BYTES);
}

#[cfg(unix)]
#[test]
fn engine_specific_ingestion_ignores_symlinked_artifacts_and_reports() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("crash"), b"external crash").unwrap();
    fs::write(outside.path().join("report"), ASAN_PREFIX).unwrap();
    symlink(
        outside.path().join("crash"),
        dir.path().join("crash-linked"),
    )
    .unwrap();
    symlink(
        outside.path().join("report"),
        dir.path().join("log-linked.txt"),
    )
    .unwrap();

    let result = ingest(&dir, EngineKind::LibFuzzer);

    assert!(result.crashes.is_empty());
    assert_eq!(result.report_bytes_read, 0);
}
