//! Tests for corpus management operations.

use hf_core::corpus::CorpusSource;
use hf_corpus::{
    absorb, grow, list, list_with_limits, merge, merge_snapshot, merge_snapshot_with_limits,
    minimize, prune, seed, seed_with_limits, snapshot, snapshot_with_limits, CorpusLimits,
    DEFAULT_CORPUS_LIMITS,
};
use std::fs::{self, File};
use tempfile::TempDir;
use uuid::Uuid;

fn target_id() -> Uuid {
    Uuid::new_v4()
}

#[tokio::test]
async fn seed_writes_inputs_and_computes_sha256() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let inputs = vec![
        (b"hello".to_vec(), "seed1".to_owned()),
        (b"world".to_vec(), "seed2".to_owned()),
    ];
    let corpus = seed(target_id(), &corpus_root, inputs).await.unwrap();
    assert_eq!(corpus.entries.len(), 2);
    assert!(corpus_root.join("seed1").exists());
    assert!(corpus_root.join("seed2").exists());
    // sha256 of "hello" is known.
    let hello_entry = corpus
        .entries
        .iter()
        .find(|e| e.path.file_name().unwrap() == "seed1")
        .unwrap();
    assert_eq!(
        hello_entry.sha256,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert!(matches!(hello_entry.source, CorpusSource::Seed));
}

#[tokio::test]
async fn seed_replaces_an_existing_entry() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");

    seed(
        target_id(),
        &corpus_root,
        vec![(b"first".to_vec(), "stable-name".to_owned())],
    )
    .await
    .unwrap();
    seed(
        target_id(),
        &corpus_root,
        vec![(b"replacement".to_vec(), "stable-name".to_owned())],
    )
    .await
    .unwrap();

    assert_eq!(
        fs::read(corpus_root.join("stable-name")).unwrap(),
        b"replacement"
    );
}

#[tokio::test]
async fn seed_rejects_names_that_escape_the_corpus_root() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");

    let result = seed(
        target_id(),
        &corpus_root,
        vec![(b"escaped".to_vec(), "../escaped-seed".to_owned())],
    )
    .await;

    assert!(result.is_err());
    assert!(!dir.path().join("escaped-seed").exists());
}

#[tokio::test]
async fn seed_rejects_inputs_outside_the_corpus_budget() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let oversized = vec![0; DEFAULT_CORPUS_LIMITS.max_input_bytes as usize + 1];

    let result = seed(
        target_id(),
        &corpus_root,
        vec![(oversized, "too-large".to_owned())],
    )
    .await;

    assert!(result.is_err());
    assert!(!corpus_root.join("too-large").exists());
}

#[tokio::test]
async fn seed_preflights_the_resulting_corpus_budget_before_writing() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::write(corpus_root.join("existing"), b"old").unwrap();
    let limits = CorpusLimits {
        max_total_bytes: 5,
        ..DEFAULT_CORPUS_LIMITS
    };

    let result = seed_with_limits(
        target_id(),
        &corpus_root,
        vec![(b"new".to_vec(), "new".to_owned())],
        limits,
    )
    .await;

    assert!(result.is_err());
    assert!(!corpus_root.join("new").exists());
    assert_eq!(fs::read(corpus_root.join("existing")).unwrap(), b"old");
}

#[tokio::test]
async fn grow_copies_new_inputs_from_engine_output() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let engine_out = dir.path().join("out");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&engine_out).unwrap();
    // Seed the corpus first.
    seed(
        target_id(),
        &corpus_root,
        vec![(b"old".to_vec(), "seed1".to_owned())],
    )
    .await
    .unwrap();
    // Simulate engine output with new coverage-inducing inputs.
    fs::write(engine_out.join("new_input_1"), b"new1").unwrap();
    fs::write(engine_out.join("new_input_2"), b"new2").unwrap();
    // Also write a file that already exists in corpus (by content).
    fs::write(engine_out.join("dup"), b"old").unwrap();

    let grown = grow(&corpus_root, &engine_out).unwrap();
    assert!(
        grown.entries.len() >= 3,
        "should have at least 3 entries after grow"
    );
    assert!(corpus_root.join("new_input_1").exists());
    assert!(corpus_root.join("new_input_2").exists());
}

#[tokio::test]
async fn grow_pulls_afl_queue_and_skips_artifacts() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let out = dir.path().join("out");
    fs::create_dir_all(&corpus_root).unwrap();

    // Single-instance AFL++ layout: coverage inputs in out/default/queue/, with
    // crashes and bookkeeping that must NOT be pulled into the corpus.
    let queue = out.join("default").join("queue");
    fs::create_dir_all(&queue).unwrap();
    fs::write(queue.join("id:000000,orig:seed"), b"cov-input-a").unwrap();
    fs::write(queue.join("id:000001,src:000000"), b"cov-input-b").unwrap();
    fs::create_dir_all(out.join("default").join("crashes")).unwrap();
    fs::write(out.join("default").join("fuzzer_stats"), b"stats...").unwrap();
    // A libFuzzer-style crash artifact at the top level must be skipped.
    fs::write(out.join("crash-deadbeef"), b"crashing-input").unwrap();

    let grown = grow(&corpus_root, &out).unwrap();
    let contents: Vec<String> = grown
        .entries
        .iter()
        .map(|e| fs::read_to_string(&e.path).unwrap_or_default())
        .collect();

    assert!(
        contents.iter().any(|c| c == "cov-input-a"),
        "queue input a missing"
    );
    assert!(
        contents.iter().any(|c| c == "cov-input-b"),
        "queue input b missing"
    );
    assert!(
        !contents.iter().any(|c| c == "crashing-input"),
        "crash artifact was pulled into the corpus"
    );
    assert!(
        !contents.iter().any(|c| c == "stats..."),
        "bookkeeping was pulled into the corpus"
    );
}

#[tokio::test]
async fn grow_rejects_an_oversized_engine_input_without_copying_it() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let engine_out = dir.path().join("out");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&engine_out).unwrap();
    let oversized = File::create(engine_out.join("oversized-input")).unwrap();
    oversized
        .set_len(DEFAULT_CORPUS_LIMITS.max_input_bytes + 1)
        .unwrap();

    let result = grow(&corpus_root, &engine_out);

    assert!(result.is_err());
    assert!(fs::read_dir(&corpus_root).unwrap().next().is_none());
}

#[tokio::test]
async fn grow_processes_engine_inputs_in_filename_order() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let engine_out = dir.path().join("out");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&engine_out).unwrap();
    fs::write(engine_out.join("z-input"), b"z").unwrap();
    fs::write(engine_out.join("a-input"), b"a").unwrap();

    let names: Vec<_> = grow(&corpus_root, &engine_out)
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.path.file_name().unwrap().to_owned())
        .collect();

    assert_eq!(names, ["a-input", "z-input"]);
}

#[tokio::test]
async fn prune_removes_duplicate_coverage_entries() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    // Create entries with duplicate coverage_hash.
    fs::write(corpus_root.join("a"), b"aaa").unwrap();
    fs::write(corpus_root.join("b"), b"bbb").unwrap();
    fs::write(corpus_root.join("c"), b"ccc").unwrap();
    let mut corpus = list(&corpus_root).unwrap();
    // Assign coverage hashes: a and b share the same hash, c is different.
    corpus.entries[0].coverage_hash = Some("hash1".to_owned());
    corpus.entries[1].coverage_hash = Some("hash1".to_owned());
    corpus.entries[2].coverage_hash = Some("hash2".to_owned());

    let pruned = prune(corpus).unwrap();
    // a and b share hash1 -> one removed. c kept. => 2 entries.
    assert_eq!(pruned.entries.len(), 2, "should prune to 2");
}

#[tokio::test]
async fn prune_never_deletes_a_path_outside_the_corpus_root() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::write(corpus_root.join("a"), b"aaa").unwrap();
    fs::write(corpus_root.join("b"), b"bbb").unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, b"must survive").unwrap();
    let mut corpus = list(&corpus_root).unwrap();
    corpus.entries[0].coverage_hash = Some("same-coverage".to_owned());
    corpus.entries[1].coverage_hash = Some("same-coverage".to_owned());
    corpus.entries[1].path = outside.clone();

    let _ = prune(corpus).unwrap();

    assert_eq!(fs::read(outside).unwrap(), b"must survive");
}

#[cfg(unix)]
#[tokio::test]
async fn prune_propagates_a_failed_removal() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::write(corpus_root.join("a"), b"aaa").unwrap();
    fs::write(corpus_root.join("b"), b"bbb").unwrap();
    let mut corpus = list(&corpus_root).unwrap();
    // a and b share a coverage hash: prune keeps one and must delete the other.
    corpus.entries[0].coverage_hash = Some("dup".to_owned());
    corpus.entries[1].coverage_hash = Some("dup".to_owned());

    let original = fs::metadata(&corpus_root).unwrap().permissions();
    // A read-only directory blocks removal of the redundant entry inside it.
    fs::set_permissions(&corpus_root, fs::Permissions::from_mode(0o555)).unwrap();

    // Skip where directory permissions are not enforced (e.g. running as root):
    // the deletion would succeed and there would be nothing to propagate.
    let enforced = fs::write(corpus_root.join(".probe"), b"x").is_err();
    if !enforced {
        fs::remove_file(corpus_root.join(".probe")).ok();
        fs::set_permissions(&corpus_root, original).unwrap();
        return;
    }

    let result = prune(corpus);
    // Restore write permission so the TempDir can be cleaned up.
    fs::set_permissions(&corpus_root, original).unwrap();

    assert!(
        result.is_err(),
        "prune must return an error when a redundant entry cannot be removed"
    );
}

#[tokio::test]
async fn merge_combines_without_duplicates() {
    let dir = TempDir::new().unwrap();
    let root_a = dir.path().join("a");
    let root_b = dir.path().join("b");
    fs::create_dir_all(&root_a).unwrap();
    fs::create_dir_all(&root_b).unwrap();
    fs::write(root_a.join("file1"), b"content1").unwrap();
    fs::write(root_b.join("file2"), b"content2").unwrap();
    fs::write(root_b.join("file1_dup"), b"content1").unwrap(); // same content as file1

    let _tid = target_id();
    let a = list(&root_a).unwrap();
    let b = list(&root_b).unwrap();
    let merged = merge(a, b).unwrap();
    // file1 and file1_dup have the same sha256 -> deduped. file2 is unique.
    assert_eq!(merged.entries.len(), 2, "should merge to 2 unique entries");
}

#[tokio::test]
async fn minimize_swaps_in_the_minimized_set_and_tags_it() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let minimized = dir.path().join("corpus_min");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&minimized).unwrap();
    // The live corpus has three inputs.
    fs::write(corpus_root.join("a"), b"aaa").unwrap();
    fs::write(corpus_root.join("b"), b"bbb").unwrap();
    fs::write(corpus_root.join("c"), b"ccc").unwrap();
    // A coverage-guided merge kept only the two that contribute coverage.
    fs::write(minimized.join("a"), b"aaa").unwrap();
    fs::write(minimized.join("c"), b"ccc").unwrap();

    let result = minimize(&corpus_root, &minimized).unwrap();

    assert_eq!(
        result.entries.len(),
        2,
        "should keep only the minimized set"
    );
    assert!(corpus_root.join("a").exists());
    assert!(corpus_root.join("c").exists());
    assert!(!corpus_root.join("b").exists(), "redundant input removed");
    assert!(
        result
            .entries
            .iter()
            .all(|e| matches!(e.source, CorpusSource::Minimized)),
        "survivors tagged Minimized"
    );
}

#[test]
fn minimize_does_not_duplicate_a_survivor_when_the_merge_renames_it() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let minimized = dir.path().join("corpus_min");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&minimized).unwrap();
    fs::write(corpus_root.join("original"), b"surviving bytes").unwrap();
    fs::write(corpus_root.join("redundant"), b"drop these bytes").unwrap();
    fs::write(minimized.join("renamed"), b"surviving bytes").unwrap();

    let result = minimize(&corpus_root, &minimized).unwrap();
    let on_disk = list(&corpus_root).unwrap();

    assert_eq!(result.entries.len(), 1);
    assert_eq!(on_disk.entries.len(), 1, "one survivor must remain on disk");
    assert_eq!(result.entries[0].path, corpus_root.join("original"));
    assert_eq!(on_disk.entries[0].path, corpus_root.join("original"));
    assert!(!corpus_root.join("renamed").exists());
    assert!(!corpus_root.join("redundant").exists());
}

#[tokio::test]
async fn minimize_rejects_oversized_output_before_deleting_the_live_corpus() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let minimized = dir.path().join("corpus_min");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&minimized).unwrap();
    fs::write(corpus_root.join("retained"), b"must survive").unwrap();
    File::create(minimized.join("oversized"))
        .unwrap()
        .set_len(DEFAULT_CORPUS_LIMITS.max_input_bytes + 1)
        .unwrap();

    let result = minimize(&corpus_root, &minimized);

    assert!(result.is_err());
    assert_eq!(
        fs::read(corpus_root.join("retained")).unwrap(),
        b"must survive"
    );
}

#[tokio::test]
async fn absorb_adds_unique_crash_inputs_and_skips_dups() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    // The corpus already contains one input.
    fs::write(corpus_root.join("existing"), b"already-here").unwrap();

    // Crash reproducers found during triage: one new, one a content-dup of the
    // existing entry.
    let crash_dir = dir.path().join("crashes");
    fs::create_dir_all(&crash_dir).unwrap();
    let new_crash = crash_dir.join("crash-001");
    let dup_crash = crash_dir.join("crash-002");
    fs::write(&new_crash, b"boom").unwrap();
    fs::write(&dup_crash, b"already-here").unwrap();

    let (corpus, added) = absorb(&corpus_root, &[new_crash, dup_crash]).unwrap();

    assert_eq!(added, 1, "only the genuinely new crash is absorbed");
    assert_eq!(corpus.entries.len(), 2);
    // The new crash now lives in the corpus, tagged as fuzzer-derived.
    let absorbed = corpus
        .entries
        .iter()
        .find(|e| std::fs::read(&e.path).unwrap() == b"boom")
        .expect("new crash present");
    assert!(matches!(absorbed.source, CorpusSource::Fuzzer));
}

#[tokio::test]
async fn absorb_keeps_distinct_inputs_that_share_a_basename() {
    // Two different crash reproducers pulled from different run dirs can share a
    // file name. Absorb must keep both on disk, not silently overwrite one.
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();

    let run_a = dir.path().join("a");
    let run_b = dir.path().join("b");
    fs::create_dir_all(&run_a).unwrap();
    fs::create_dir_all(&run_b).unwrap();
    let crash_a = run_a.join("crash-abc");
    let crash_b = run_b.join("crash-abc"); // same basename, different content
    fs::write(&crash_a, b"first-distinct-input").unwrap();
    fs::write(&crash_b, b"second-distinct-input").unwrap();

    let (corpus, added) = absorb(&corpus_root, &[crash_a, crash_b]).unwrap();

    assert_eq!(added, 2, "both distinct inputs are absorbed");
    // Both byte payloads must survive on disk under distinct files.
    let has_first = corpus
        .entries
        .iter()
        .any(|e| std::fs::read(&e.path).unwrap() == b"first-distinct-input");
    let has_second = corpus
        .entries
        .iter()
        .any(|e| std::fs::read(&e.path).unwrap() == b"second-distinct-input");
    assert!(has_first && has_second, "neither input was overwritten");
}

#[tokio::test]
async fn absorb_rejects_an_oversized_crash_input_without_copying_it() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let crash_dir = dir.path().join("crashes");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&crash_dir).unwrap();
    let crash = crash_dir.join("crash-oversized");
    File::create(&crash)
        .unwrap()
        .set_len(DEFAULT_CORPUS_LIMITS.max_input_bytes + 1)
        .unwrap();

    let result = absorb(&corpus_root, &[crash]);

    assert!(result.is_err());
    assert!(fs::read_dir(&corpus_root).unwrap().next().is_none());
}

#[tokio::test]
async fn list_returns_correct_metadata() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::write(corpus_root.join("x"), b"12345").unwrap();
    let corpus = list(&corpus_root).unwrap();
    assert_eq!(corpus.entries.len(), 1);
    let entry = &corpus.entries[0];
    assert_eq!(entry.size, 5);
    assert!(!entry.sha256.is_empty());
    assert!(matches!(entry.source, CorpusSource::Manual));
}

#[tokio::test]
async fn list_orders_entries_deterministically() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    for name in ["z-last", "a-first", "m-middle"] {
        fs::write(corpus_root.join(name), name).unwrap();
    }

    let names: Vec<_> = list(&corpus_root)
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.path.file_name().unwrap().to_owned())
        .collect();

    assert_eq!(names, ["a-first", "m-middle", "z-last"]);
}

#[tokio::test]
async fn list_rejects_oversized_inputs_before_allocating_their_contents() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    File::create(corpus_root.join("sparse-oversized"))
        .unwrap()
        .set_len(DEFAULT_CORPUS_LIMITS.max_input_bytes + 1)
        .unwrap();

    assert!(list(&corpus_root).is_err());
}

#[tokio::test]
async fn list_rejects_directories_with_excessive_entries() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    for name in ["a", "b", "c"] {
        fs::write(corpus_root.join(name), name).unwrap();
    }
    let limits = CorpusLimits {
        max_entries: 2,
        ..DEFAULT_CORPUS_LIMITS
    };

    assert!(list_with_limits(&corpus_root, limits).is_err());
}

#[tokio::test]
async fn explicit_limits_cannot_raise_the_corpus_safety_ceiling() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    let limits = CorpusLimits {
        max_input_bytes: DEFAULT_CORPUS_LIMITS.max_input_bytes + 1,
        ..DEFAULT_CORPUS_LIMITS
    };

    assert!(list_with_limits(&corpus_root, limits).is_err());
}

#[tokio::test]
async fn merge_snapshot_adds_only_new_regular_inputs() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let snapshot = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&snapshot).unwrap();
    fs::write(corpus_root.join("retained"), b"existing").unwrap();
    fs::write(snapshot.join("retained-copy"), b"existing").unwrap();
    fs::write(snapshot.join("new-input"), b"new coverage").unwrap();
    let (merged, added) = merge_snapshot(&corpus_root, &snapshot).unwrap();

    assert_eq!(added, 1);
    assert_eq!(merged.entries.len(), 2);
    assert!(merged
        .entries
        .iter()
        .any(|entry| entry.source == CorpusSource::Fuzzer
            && fs::read(&entry.path).unwrap() == b"new coverage"));
}

#[tokio::test]
async fn snapshot_copies_a_flat_corpus_in_deterministic_order() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let run_root = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&run_root).unwrap();
    fs::write(corpus_root.join("z"), b"last").unwrap();
    fs::write(corpus_root.join("a"), b"first").unwrap();

    let copied = snapshot(&corpus_root, &run_root).unwrap();
    let names: Vec<_> = copied
        .entries
        .iter()
        .map(|entry| entry.path.file_name().unwrap())
        .collect();

    assert_eq!(names, ["a", "z"]);
    assert_eq!(fs::read(run_root.join("a")).unwrap(), b"first");
    assert_eq!(fs::read(run_root.join("z")).unwrap(), b"last");
}

#[tokio::test]
async fn snapshot_preflights_limits_before_writing() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let run_root = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&run_root).unwrap();
    fs::write(corpus_root.join("a"), b"one").unwrap();
    fs::write(corpus_root.join("b"), b"two").unwrap();
    let limits = CorpusLimits {
        max_total_bytes: 5,
        ..DEFAULT_CORPUS_LIMITS
    };

    let result = snapshot_with_limits(&corpus_root, &run_root, limits);

    assert!(result.is_err());
    assert!(fs::read_dir(&run_root).unwrap().next().is_none());
}

#[tokio::test]
async fn snapshot_rejects_a_nonempty_run_destination() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let run_root = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&run_root).unwrap();
    fs::write(corpus_root.join("source"), b"source").unwrap();
    fs::write(run_root.join("stale"), b"stale").unwrap();

    assert!(snapshot(&corpus_root, &run_root).is_err());
    assert_eq!(fs::read(run_root.join("stale")).unwrap(), b"stale");
    assert!(!run_root.join("source").exists());
}

#[tokio::test]
async fn snapshot_and_merge_reject_non_regular_entries() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let run_root = dir.path().join("run-corpus");
    fs::create_dir_all(corpus_root.join("nested-directory")).unwrap();
    fs::create_dir_all(&run_root).unwrap();

    assert!(snapshot(&corpus_root, &run_root).is_err());

    fs::remove_dir(corpus_root.join("nested-directory")).unwrap();
    fs::create_dir(run_root.join("nested-directory")).unwrap();
    assert!(merge_snapshot(&corpus_root, &run_root).is_err());
    assert!(fs::read_dir(&corpus_root).unwrap().next().is_none());
}

#[tokio::test]
async fn merge_snapshot_obeys_the_combined_corpus_budget() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let snapshot = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&snapshot).unwrap();
    fs::write(corpus_root.join("existing"), b"a").unwrap();
    fs::write(snapshot.join("new"), b"b").unwrap();
    let limits = CorpusLimits {
        max_entries: 1,
        ..DEFAULT_CORPUS_LIMITS
    };

    let result = merge_snapshot_with_limits(&corpus_root, &snapshot, limits);

    assert!(result.is_err());
    assert!(!corpus_root.join("new").exists());
}

#[tokio::test]
async fn merge_snapshot_never_overwrites_a_same_named_retained_input() {
    let dir = TempDir::new().unwrap();
    let corpus_root = dir.path().join("corpus");
    let snapshot = dir.path().join("run-corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    fs::create_dir_all(&snapshot).unwrap();
    fs::write(corpus_root.join("same-name"), b"retained").unwrap();
    fs::write(snapshot.join("same-name"), b"new discovery").unwrap();

    let (merged, added) = merge_snapshot(&corpus_root, &snapshot).unwrap();

    assert_eq!(added, 1);
    assert_eq!(
        fs::read(corpus_root.join("same-name")).unwrap(),
        b"retained"
    );
    assert!(merged
        .entries
        .iter()
        .any(|entry| fs::read(&entry.path).unwrap() == b"new discovery"));
}

#[cfg(unix)]
#[tokio::test]
async fn corpus_operations_ignore_symlinked_inputs() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let host_file = outside.join("host-data");
    fs::write(&host_file, b"must-not-be-ingested").unwrap();

    let corpus_root = dir.path().join("corpus");
    fs::create_dir_all(&corpus_root).unwrap();
    symlink(&host_file, corpus_root.join("linked-entry")).unwrap();
    assert!(
        list(&corpus_root).unwrap().entries.is_empty(),
        "corpus listing followed a symlink"
    );
    let snapshot_destination = dir.path().join("snapshot-destination");
    fs::create_dir_all(&snapshot_destination).unwrap();
    assert!(
        snapshot(&corpus_root, &snapshot_destination).is_err(),
        "snapshot accepted a symlink in the retained corpus"
    );
    assert!(fs::read_dir(&snapshot_destination)
        .unwrap()
        .next()
        .is_none());

    let engine_out = dir.path().join("out");
    fs::create_dir_all(&engine_out).unwrap();
    symlink(&host_file, engine_out.join("queue-entry")).unwrap();
    assert!(
        grow(&corpus_root, &engine_out).unwrap().entries.is_empty(),
        "corpus growth followed a symlink"
    );

    let (corpus, added) = absorb(&corpus_root, &[engine_out.join("queue-entry")]).unwrap();
    assert_eq!(added, 0, "crash absorption followed a symlink");
    assert!(corpus.entries.is_empty());

    let external_corpus = outside.join("external-corpus");
    fs::create_dir_all(&external_corpus).unwrap();
    fs::write(external_corpus.join("host-seed"), b"outside corpus").unwrap();
    let linked_corpus = dir.path().join("linked-corpus");
    symlink(&external_corpus, &linked_corpus).unwrap();
    assert!(
        list(&linked_corpus).is_err(),
        "a symlink must not become a writable corpus root"
    );
    assert!(seed(
        target_id(),
        &linked_corpus,
        vec![(b"write".to_vec(), "new-seed".to_owned())],
    )
    .await
    .is_err());
    assert!(!external_corpus.join("new-seed").exists());

    let linked_engine_out = dir.path().join("linked-engine-out");
    symlink(&external_corpus, &linked_engine_out).unwrap();
    let grown = grow(&corpus_root, &linked_engine_out).unwrap();
    assert!(grown.entries.is_empty());

    let clean_corpus = dir.path().join("clean-corpus");
    fs::create_dir_all(&clean_corpus).unwrap();
    let run_snapshot = dir.path().join("run-snapshot");
    fs::create_dir_all(&run_snapshot).unwrap();
    symlink(&host_file, run_snapshot.join("linked-discovery")).unwrap();
    fs::create_dir(run_snapshot.join("nested-directory")).unwrap();
    assert!(
        merge_snapshot(&clean_corpus, &run_snapshot).is_err(),
        "snapshot merge accepted a symlink"
    );
    assert!(fs::read_dir(&clean_corpus).unwrap().next().is_none());

    let minimized = dir.path().join("minimized");
    fs::create_dir_all(&minimized).unwrap();
    fs::write(minimized.join("keep"), b"safe survivor").unwrap();
    symlink(&host_file, corpus_root.join("keep")).unwrap();
    let result = minimize(&corpus_root, &minimized).unwrap();
    assert_eq!(
        fs::read(corpus_root.join("keep")).unwrap(),
        b"safe survivor"
    );
    assert!(result
        .entries
        .iter()
        .any(|entry| entry.path == corpus_root.join("keep")));
    assert_eq!(fs::read(&host_file).unwrap(), b"must-not-be-ingested");
}
