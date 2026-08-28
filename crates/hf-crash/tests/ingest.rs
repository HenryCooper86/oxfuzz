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

/// syz-manager writes each distinct kernel bug into its own `crashes/<hash>/`
/// directory. That nested shape is the documented exception to the flat
/// userspace artifact layout, so it needs its own walk.
#[test]
fn syzkaller_ingests_one_crash_per_kernel_report_directory() {
    let dir = TempDir::new().unwrap();
    let crashes = dir.path().join("crashes");

    let with_repro = crashes.join("0123abcd");
    fs::create_dir_all(&with_repro).unwrap();
    fs::write(
        with_repro.join("description"),
        b"KASAN: slab-out-of-bounds Read in ext4_xattr_set_entry",
    )
    .unwrap();
    fs::write(
        with_repro.join("report0"),
        b"BUG: KASAN: slab-out-of-bounds in ext4_xattr_set_entry+0x12/0x34 fs/ext4/xattr.c:1650\n\
          Call Trace:\n ext4_xattr_set_entry+0x12/0x34 fs/ext4/xattr.c:1650\n",
    )
    .unwrap();
    fs::write(with_repro.join("repro.prog"), b"syscall-sequence").unwrap();

    let without_repro = crashes.join("beef0001");
    fs::create_dir_all(&without_repro).unwrap();
    fs::write(
        without_repro.join("description"),
        b"WARNING in ext4_write_inode",
    )
    .unwrap();
    fs::write(
        without_repro.join("report0"),
        b"WARNING: CPU: 0 PID: 12 at fs/ext4/inode.c:99 ext4_write_inode+0x1/0x2\n\
          Call Trace:\n ext4_write_inode+0x1/0x2 fs/ext4/inode.c:99\n",
    )
    .unwrap();

    let run_id = uuid::Uuid::new_v4();
    let target_id = uuid::Uuid::new_v4();
    let result = hf_crash::ingest::ingest_syzkaller(dir.path(), run_id, target_id).unwrap();

    assert_eq!(result.crashes.len(), 2, "one crash per hash directory");
    for crash in &result.crashes {
        assert_eq!(crash.kind, hf_core::crash::CrashKind::KernelBug);
        assert_eq!(crash.run_id, run_id);
        assert_eq!(crash.target_id, target_id);
        assert!(
            !crash.stack_signature.is_empty(),
            "a kernel crash must dedup by its frames, not fall back to keep-all"
        );
        assert!(!crash.summary.is_empty());
        assert!(!crash.minimized, "syzkaller has no minimization path");
    }

    // The reproducer is the input when syz-manager captured one; otherwise the
    // report itself is the evidence the crash points at.
    let kasan = result
        .crashes
        .iter()
        .find(|c| c.summary.contains("slab-out-of-bounds"))
        .expect("the KASAN crash is ingested");
    assert_eq!(kasan.input_path, with_repro.join("repro.prog"));
    let warning = result
        .crashes
        .iter()
        .find(|c| c.summary.contains("ext4_write_inode"))
        .expect("the WARNING crash is ingested");
    assert_eq!(warning.input_path, without_repro.join("report0"));

    // Distinct bugs must not collapse.
    assert_ne!(
        result.crashes[0].stack_signature,
        result.crashes[1].stack_signature
    );
}

#[test]
fn syzkaller_ingest_skips_a_directory_with_no_kernel_report() {
    let dir = TempDir::new().unwrap();
    let empty = dir.path().join("crashes").join("cafe0002");
    fs::create_dir_all(&empty).unwrap();
    fs::write(empty.join("machineInfo"), b"qemu").unwrap();

    let result =
        hf_crash::ingest::ingest_syzkaller(dir.path(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
            .unwrap();
    assert!(result.crashes.is_empty());
}
