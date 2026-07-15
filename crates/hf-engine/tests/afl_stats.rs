use std::fs;

use hf_engine::afl::{
    parse_fuzzer_stats, read_fuzzer_stats, AflFuzzerStats, MAX_FUZZER_STATS_BYTES,
};

#[test]
fn parses_only_exact_fuzzer_stats_keys() {
    let stats = parse_fuzzer_stats(
        b"start_time        : 1700000000\n\
          execs_per_sec     : 1234.50\n\
          edges_found       : 42\n\
          total_edges       : 128\n\
          saved_crashes     : 3\n\
          old_execs_per_sec : 999999\n\
          saved_crashes_note: 999999\n",
    )
    .expect("valid AFL++ statistics");

    assert_eq!(
        stats,
        AflFuzzerStats {
            execs_per_sec: Some(1234.5),
            edges_found: Some(42),
            total_edges: Some(128),
            saved_crashes: Some(3),
        }
    );
}

#[test]
fn malformed_recognized_value_fails_instead_of_becoming_zero() {
    assert!(parse_fuzzer_stats(b"saved_crashes : unknown\n").is_err());
    assert!(parse_fuzzer_stats(b"execs_per_sec : NaN\n").is_err());
    assert!(parse_fuzzer_stats(b"execs_per_sec : -1\n").is_err());
}

#[test]
fn parser_rejects_oversized_snapshots() {
    let oversized = vec![b'x'; MAX_FUZZER_STATS_BYTES + 1];
    assert!(parse_fuzzer_stats(&oversized).is_err());
}

#[test]
fn reader_uses_only_the_run_owned_default_instance() {
    let run_output = tempfile::tempdir().unwrap();
    fs::create_dir(run_output.path().join("default")).unwrap();
    fs::write(
        run_output.path().join("default/fuzzer_stats"),
        b"execs_per_sec : 50\nedges_found : 10\ntotal_edges : 20\nsaved_crashes : 0\n",
    )
    .unwrap();
    fs::write(
        run_output.path().join("fuzzer_stats"),
        b"execs_per_sec : 999999\n",
    )
    .unwrap();

    let stats = read_fuzzer_stats(run_output.path())
        .expect("safe run-owned statistics")
        .expect("statistics file exists");
    assert_eq!(stats.execs_per_sec, Some(50.0));
    assert_eq!(stats.edges_found, Some(10));
    assert_eq!(stats.total_edges, Some(20));
    assert_eq!(stats.saved_crashes, Some(0));
}

#[test]
fn reader_reports_missing_snapshot_without_fabricating_stats() {
    let run_output = tempfile::tempdir().unwrap();
    fs::create_dir(run_output.path().join("default")).unwrap();
    assert_eq!(read_fuzzer_stats(run_output.path()).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn reader_rejects_symlinked_stats_files() {
    use std::os::unix::fs::symlink;

    let run_output = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), b"saved_crashes : 999\n").unwrap();
    fs::create_dir(run_output.path().join("default")).unwrap();
    symlink(
        outside.path(),
        run_output.path().join("default/fuzzer_stats"),
    )
    .unwrap();

    assert!(read_fuzzer_stats(run_output.path()).is_err());
}
