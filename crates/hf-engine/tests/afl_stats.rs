use std::fs;

use hf_core::engine::EngineStats;
use hf_engine::afl::{
    parse_fuzzer_stats, read_fuzzer_stats, AflFuzzerStats, MAX_FUZZER_STATS_BYTES,
};

/// A realistic AFL++ 4.x `fuzzer_stats` snapshot, as flushed by `afl-fuzz`
/// (afl-fuzz-stats.c `write_stats_file`).
const AFLPP_SNAPSHOT: &[u8] = b"start_time        : 1700000000\n\
     last_update       : 1700000153\n\
     run_time          : 153\n\
     fuzzer_pid        : 1234\n\
     cycles_done       : 2\n\
     cycles_wo_finds   : 1\n\
     time_wo_finds     : 60\n\
     execs_done        : 128934\n\
     execs_per_sec     : 842.05\n\
     execs_ps_last_min : 900.13\n\
     corpus_count      : 91\n\
     corpus_favored    : 20\n\
     corpus_found      : 85\n\
     corpus_imported   : 0\n\
     max_depth         : 4\n\
     cur_item          : 88\n\
     pending_favs      : 3\n\
     pending_total     : 40\n\
     corpus_variable   : 0\n\
     stability         : 96.50%\n\
     bitmap_cvg        : 0.50%\n\
     saved_crashes     : 1\n\
     saved_hangs       : 2\n\
     total_tmouts      : 5\n\
     last_find         : 1700000139\n\
     last_crash        : 0\n\
     last_hang         : 1700000100\n\
     execs_since_crash : 128934\n\
     exec_timeout      : 1000\n\
     slowest_exec_ms   : 12\n\
     peak_rss_mb       : 128\n\
     cpu_affinity      : 1\n\
     edges_found       : 1523\n\
     total_edges       : 4096\n\
     var_byte_count    : 40\n\
     havoc_expansion   : 5\n\
     auto_dict_entries : 0\n\
     testcache_size    : 91\n\
     testcache_count   : 0\n\
     afl_banner        : fuzzme\n\
     afl_version       : ++4.10c\n\
     target_mode       : default\n\
     command_line      : afl-fuzz -i in -o out -- /work/fuzzme @@\n";

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
            start_time_epoch: Some(1_700_000_000),
            ..AflFuzzerStats::default()
        }
    );
}

#[test]
fn parses_the_full_aflplusplus_snapshot_field_set() {
    let stats = parse_fuzzer_stats(AFLPP_SNAPSHOT).expect("valid AFL++ statistics");

    assert_eq!(
        stats,
        AflFuzzerStats {
            execs_per_sec: Some(842.05),
            edges_found: Some(1523),
            total_edges: Some(4096),
            saved_crashes: Some(1),
            execs_done: Some(128_934),
            cycles_done: Some(2),
            corpus_count: Some(91),
            stability_pct: Some(96.5),
            saved_hangs: Some(2),
            start_time_epoch: Some(1_700_000_000),
            last_update_epoch: Some(1_700_000_153),
            last_find_epoch: Some(1_700_000_139),
            run_time_secs: Some(153),
        }
    );
}

#[test]
fn legacy_classic_afl_keys_fill_corpus_and_hangs() {
    // Classic AFL wrote `paths_total`/`unique_hangs` where AFL++ writes
    // `corpus_count`/`saved_hangs`; both name the same run metrics.
    let stats = parse_fuzzer_stats(b"paths_total : 37\nunique_hangs : 4\n")
        .expect("valid classic AFL statistics");
    assert_eq!(stats.corpus_count, Some(37));
    assert_eq!(stats.saved_hangs, Some(4));
}

#[test]
fn a_zero_last_find_is_no_find_yet_not_an_epoch() {
    let stats = parse_fuzzer_stats(b"last_find : 0\nlast_update : 1700000153\n")
        .expect("valid AFL++ statistics");
    assert_eq!(stats.last_find_epoch, None);
    assert_eq!(stats.last_update_epoch, Some(1_700_000_153));
}

#[test]
fn malformed_values_for_the_new_fields_fail_loudly() {
    assert!(parse_fuzzer_stats(b"execs_done : many\n").is_err());
    assert!(parse_fuzzer_stats(b"cycles_done : -1\n").is_err());
    assert!(parse_fuzzer_stats(b"stability : unstable\n").is_err());
    assert!(parse_fuzzer_stats(b"stability : -3.00%\n").is_err());
    assert!(parse_fuzzer_stats(b"saved_hangs : none\n").is_err());
    assert!(parse_fuzzer_stats(b"last_find : soon\n").is_err());
    assert!(parse_fuzzer_stats(b"run_time : a while\n").is_err());
}

#[test]
fn projection_onto_engine_stats_derives_find_age_and_uptime() {
    let stats = parse_fuzzer_stats(AFLPP_SNAPSHOT).expect("valid AFL++ statistics");
    let engine_stats = stats.to_engine_stats();
    assert_eq!(
        engine_stats,
        EngineStats {
            execs_total: Some(128_934),
            execs_per_sec: Some(842.05),
            edges_covered: Some(1523),
            cycles_done: Some(2),
            corpus_count: Some(91),
            stability_pct: Some(96.5),
            hangs: Some(2),
            last_find_age_secs: Some(14),
            uptime_secs: Some(153),
        }
    );
}

#[test]
fn projection_reports_no_find_age_before_the_first_find() {
    let stats = parse_fuzzer_stats(
        b"last_update : 1700000153\nlast_find : 0\nexecs_done : 10\nrun_time : 3\n",
    )
    .expect("valid AFL++ statistics");
    let engine_stats = stats.to_engine_stats();
    assert_eq!(engine_stats.last_find_age_secs, None);
    assert_eq!(engine_stats.uptime_secs, Some(3));
}

#[test]
fn projection_falls_back_to_start_time_for_uptime() {
    // A snapshot flushed before `run_time` appears still yields an uptime.
    let stats = parse_fuzzer_stats(b"start_time : 1700000000\nlast_update : 1700000153\n")
        .expect("valid AFL++ statistics");
    assert_eq!(stats.to_engine_stats().uptime_secs, Some(153));
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
fn reader_aggregates_every_instance_snapshot_run_wide() {
    let run_output = tempfile::tempdir().unwrap();
    for (instance, stats) in [
        (
            "main",
            "execs_per_sec : 100\nedges_found : 40\ntotal_edges : 128\nsaved_crashes : 2\n",
        ),
        (
            "s1",
            "execs_per_sec : 60\nedges_found : 45\ntotal_edges : 128\nsaved_crashes : 1\n",
        ),
        (
            "s2",
            "execs_per_sec : 40\nedges_found : 30\ntotal_edges : 100\nsaved_crashes : 0\n",
        ),
    ] {
        fs::create_dir(run_output.path().join(instance)).unwrap();
        fs::write(run_output.path().join(instance).join("fuzzer_stats"), stats).unwrap();
    }

    let stats = read_fuzzer_stats(run_output.path())
        .expect("safe run-owned statistics")
        .expect("statistics file exists");
    // Throughput and saved crashes are per-instance execution streams: sum.
    assert_eq!(stats.execs_per_sec, Some(200.0));
    assert_eq!(stats.saved_crashes, Some(3));
    // The instances share one coverage bitmap: run-wide edges are the max.
    assert_eq!(stats.edges_found, Some(45));
    assert_eq!(stats.total_edges, Some(128));
}

#[test]
fn reader_reports_missing_snapshot_without_fabricating_stats() {
    let run_output = tempfile::tempdir().unwrap();
    fs::create_dir(run_output.path().join("default")).unwrap();
    assert_eq!(read_fuzzer_stats(run_output.path()).unwrap(), None);
}

#[test]
fn reader_aggregates_the_new_fields_run_wide() {
    let run_output = tempfile::tempdir().unwrap();
    for (instance, stats) in [
        (
            "main",
            "execs_done : 1000\ncycles_done : 2\ncorpus_count : 50\n\
             stability : 98.00%\nsaved_hangs : 1\nstart_time : 100\n\
             last_update : 200\nlast_find : 190\nrun_time : 100\n",
        ),
        (
            "s1",
            "execs_done : 500\ncycles_done : 3\ncorpus_count : 41\n\
             stability : 90.00%\nsaved_hangs : 2\nstart_time : 110\n\
             last_update : 210\nlast_find : 205\nrun_time : 100\n",
        ),
    ] {
        fs::create_dir(run_output.path().join(instance)).unwrap();
        fs::write(run_output.path().join(instance).join("fuzzer_stats"), stats).unwrap();
    }

    let stats = read_fuzzer_stats(run_output.path())
        .expect("safe run-owned statistics")
        .expect("statistics file exists");
    // Per-instance execution streams and queues sum; shared progress
    // (cycles, recency) takes the most advanced value; the least stable
    // instance bounds the run's stability claim.
    assert_eq!(stats.execs_done, Some(1500));
    assert_eq!(stats.corpus_count, Some(91));
    assert_eq!(stats.saved_hangs, Some(3));
    assert_eq!(stats.cycles_done, Some(3));
    assert_eq!(stats.last_find_epoch, Some(205));
    assert_eq!(stats.last_update_epoch, Some(210));
    assert_eq!(stats.start_time_epoch, Some(100));
    assert_eq!(stats.run_time_secs, Some(100));
    assert_eq!(stats.stability_pct, Some(90.0));
    let engine_stats = stats.to_engine_stats();
    assert_eq!(engine_stats.last_find_age_secs, Some(5));
    assert_eq!(engine_stats.hangs, Some(3));
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
