use hf_core::engine::HONGGFUZZ_STATS_FILE;
use hf_engine::honggfuzz::read_stats;

#[test]
fn reads_latest_complete_csv_snapshot_and_ignores_an_unfinished_write() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_stats(dir.path()).unwrap().is_none());
    std::fs::write(dir.path().join(HONGGFUZZ_STATS_FILE),
        "# unix_time, last_cov_update, total_exec, exec_per_sec, crashes, unique_crashes, hangs, edge_cov, block_cov\n100, 90, 500, 50, 2, 1, 3, 12, 8\n102, 90, 700, 70, 5, 2, 4, 15, 9\n103, 90, 800").unwrap();
    let snapshot = read_stats(dir.path()).unwrap().unwrap();
    assert_eq!(snapshot.observed_at, 102);
    assert_eq!(snapshot.stats.execs_total, Some(700));
    assert_eq!(snapshot.stats.execs_per_sec, Some(70.0));
    assert_eq!(snapshot.stats.edges_covered, Some(15));
    assert_eq!(snapshot.stats.hangs, Some(4));
    assert_eq!(snapshot.stats.last_find_age_secs, Some(12));
}

#[test]
fn tails_large_append_only_files_and_rejects_invalid_complete_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(HONGGFUZZ_STATS_FILE);
    let mut contents = "100, 90, 500, 50, 2, 1, 3, 12, 8\n".repeat(100_000);
    contents.push_str("102, 90, 700, 70, 5, 2, 4, 15, 9\n");
    std::fs::write(&path, contents).unwrap();
    assert_eq!(
        read_stats(dir.path()).unwrap().unwrap().stats.edges_covered,
        Some(15)
    );
    for bad in [
        "102, 90, 700, NaN, 5, 2, 4, 15, 9\n",
        "102, 90, 700, 70, 5, 2, 4, -1, 9\n",
        "102, 90, 700\n",
    ] {
        std::fs::write(&path, bad).unwrap();
        assert!(read_stats(dir.path()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn refuses_symlink_files_and_output_directories() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join(HONGGFUZZ_STATS_FILE),
        "100, 90, 500, 50, 2, 1, 3, 12, 8\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        outside.path().join(HONGGFUZZ_STATS_FILE),
        dir.path().join(HONGGFUZZ_STATS_FILE),
    )
    .unwrap();
    assert!(read_stats(dir.path()).is_err());
    let link = dir.path().join("linked-output");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    assert!(read_stats(&link).is_err());
}
