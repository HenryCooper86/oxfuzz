//! Tests for corpus management operations.

use hf_core::corpus::CorpusSource;
use hf_corpus::{absorb, grow, list, merge, minimize, prune, seed};
use std::fs;
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
