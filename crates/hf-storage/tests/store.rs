//! Integration tests for the `SQLite` [`Store`].

use std::path::PathBuf;

use chrono::Utc;
use hf_core::corpus::{CorpusEntry, CorpusSource};
use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_storage::{
    AutoRevertEvent, ProjectAutoRevert, RunKind, RunRecord, RunStatus, StorageError, Store,
};
use uuid::Uuid;

async fn temp_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let store = Store::connect(&path).await.expect("connect");
    (store, dir)
}

#[test]
fn applied_run_revision_migration_remains_byte_for_byte_immutable() {
    // sqlx stores a checksum for every applied migration. Editing an old SQL
    // file, including its comments, prevents existing databases from opening.
    assert_eq!(
        include_str!("../migrations/0009_run_harness_rev.sql"),
        "-- Record which harness revision a run used, as a short content hash of the\n\
         -- harness source. Lets run history tie a coverage jump to the harness change\n\
         -- that produced it. Nullable; forward-only.\n\
         ALTER TABLE runs ADD COLUMN harness_rev TEXT;\n"
    );
}

fn sample_target(project: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from(project),
        language: TargetLanguage::C,
        symbol: "parse_value".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/json.c"),
            line: 12,
            col: 1,
        },
        signature: Some("int parse_value(const char*)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 7,
        fit_score: 0.82,
        sanitizers: vec![Sanitizer::Address],
        rationale: "hot parser path".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    }
}

#[tokio::test]
async fn project_auto_revert_override_upserts_and_clears() {
    let (store, _dir) = temp_store().await;
    let project = "/home/user/proj-a";

    // No override initially -> None (inherit global).
    assert_eq!(store.project_auto_revert(project).await.unwrap(), None);

    // Set an override and read it back verbatim.
    let over = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 42.5,
        notify_only: true,
    };
    store.set_project_auto_revert(project, over).await.unwrap();
    assert_eq!(
        store.project_auto_revert(project).await.unwrap(),
        Some(over)
    );

    // Upsert replaces the row rather than duplicating it.
    let updated = ProjectAutoRevert {
        enabled: false,
        threshold_pct: 10.0,
        notify_only: false,
    };
    store
        .set_project_auto_revert(project, updated)
        .await
        .unwrap();
    assert_eq!(
        store.project_auto_revert(project).await.unwrap(),
        Some(updated)
    );

    // A different project is independent.
    assert_eq!(
        store
            .project_auto_revert("/home/user/proj-b")
            .await
            .unwrap(),
        None
    );

    // Clearing removes the override (back to inherit).
    store.clear_project_auto_revert(project).await.unwrap();
    assert_eq!(store.project_auto_revert(project).await.unwrap(), None);
}

#[tokio::test]
async fn all_project_auto_reverts_lists_only_overridden_projects() {
    let (store, _dir) = temp_store().await;
    assert!(store.all_project_auto_reverts().await.unwrap().is_empty());

    let a = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 25.0,
        notify_only: false,
    };
    let b = ProjectAutoRevert {
        enabled: false,
        threshold_pct: 15.0,
        notify_only: true,
    };
    store.set_project_auto_revert("/p/a", a).await.unwrap();
    store.set_project_auto_revert("/p/b", b).await.unwrap();

    let all: std::collections::HashMap<String, ProjectAutoRevert> = store
        .all_project_auto_reverts()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(all.len(), 2);
    assert_eq!(all.get("/p/a"), Some(&a));
    assert_eq!(all.get("/p/b"), Some(&b));

    // Cleared projects drop out of the listing.
    store.clear_project_auto_revert("/p/a").await.unwrap();
    let all = store.all_project_auto_reverts().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, "/p/b");
}

#[tokio::test]
async fn auto_revert_events_record_list_scope_and_order() {
    let (store, _dir) = temp_store().await;
    assert!(store
        .list_auto_revert_events(None, 50)
        .await
        .unwrap()
        .is_empty());

    let mk = |id: &str, ts: &str, project: &str, reverted: bool| AutoRevertEvent {
        id: id.to_owned(),
        ts: ts.to_owned(),
        project_root: project.to_owned(),
        target: "parse".to_owned(),
        run_id: "run-1".to_owned(),
        from_rev: "aaaaaaaaaaaa".to_owned(),
        to_rev: "bbbbbbbbbbbb".to_owned(),
        previous_edges: 1000,
        regressed_edges: 700,
        drop_pct: 30.0,
        reverted,
    };
    store
        .record_auto_revert_event(&mk("e1", "2026-07-01T10:00:00Z", "/p/a", true))
        .await
        .unwrap();
    store
        .record_auto_revert_event(&mk("e2", "2026-07-02T10:00:00Z", "/p/a", false))
        .await
        .unwrap();
    store
        .record_auto_revert_event(&mk("e3", "2026-07-03T10:00:00Z", "/p/b", true))
        .await
        .unwrap();

    // Newest first, across all projects.
    let all = store.list_auto_revert_events(None, 50).await.unwrap();
    assert_eq!(
        all.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["e3", "e2", "e1"]
    );

    // Scoped to one project.
    let a = store
        .list_auto_revert_events(Some("/p/a"), 50)
        .await
        .unwrap();
    assert_eq!(
        a.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["e2", "e1"]
    );
    assert!(!a[0].reverted, "e2 was notify-only");

    // Limit caps the rows.
    assert_eq!(
        store.list_auto_revert_events(None, 1).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn append_message_assigns_monotonic_seq_and_orders_history() {
    let (store, _dir) = temp_store().await;
    let session = store.create_session(None, Utc::now()).await.unwrap();

    store
        .append_message(session, "user", "first", Utc::now())
        .await
        .unwrap();
    store
        .append_message(session, "assistant", "second", Utc::now())
        .await
        .unwrap();
    store
        .append_message(session, "user", "third", Utc::now())
        .await
        .unwrap();

    let history = store.session_history(session).await.unwrap();
    assert_eq!(
        history,
        vec![
            ("user".to_owned(), "first".to_owned()),
            ("assistant".to_owned(), "second".to_owned()),
            ("user".to_owned(), "third".to_owned()),
        ]
    );
}

#[tokio::test]
async fn concurrent_appends_get_distinct_seqs() {
    // The atomic INSERT...SELECT must not assign duplicate seq under concurrency.
    let (store, _dir) = temp_store().await;
    let store = std::sync::Arc::new(store);
    let session = store.create_session(None, Utc::now()).await.unwrap();

    let mut handles = Vec::new();
    for i in 0..20 {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            s.append_message(session, "user", &format!("m{i}"), Utc::now())
                .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    // Every append got a distinct, gapless seq 0..20 (no collision, none lost).
    let seqs: Vec<i64> =
        sqlx::query_scalar("SELECT seq FROM messages WHERE session_id = ?1 ORDER BY seq ASC")
            .bind(session.to_string())
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(
        seqs,
        (0..20).collect::<Vec<i64>>(),
        "seqs must be distinct 0..20"
    );
}

#[tokio::test]
async fn dedupe_crashes_collapses_same_run_and_signature() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let target = Uuid::new_v4();
    let mk = |sig: &str| Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target,
        input_path: PathBuf::from("out/crash"),
        stack_signature: sig.to_owned(),
        kind: CrashKind::Asan,
        summary: "boom".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };
    // Two rows share a signature (legacy duplicate); one distinct signature;
    // two empty-signature rows that must NOT be collapsed.
    for c in [mk("S"), mk("S"), mk("T"), mk(""), mk("")] {
        store.upsert_crash(&c).await.unwrap();
    }
    assert_eq!(store.list_crashes_by_run(run.id).await.unwrap().len(), 5);

    store.dedupe_crashes().await.unwrap();

    // "S" collapses to 1, "T" stays, both empty-sig rows stay -> 4.
    let remaining = store.list_crashes_by_run(run.id).await.unwrap();
    assert_eq!(remaining.len(), 4, "got {:?}", remaining.len());
    assert_eq!(
        remaining
            .iter()
            .filter(|c| c.stack_signature == "S")
            .count(),
        1
    );
    assert_eq!(
        remaining
            .iter()
            .filter(|c| c.stack_signature.is_empty())
            .count(),
        2
    );

    // Idempotent: a second pass removes nothing.
    store.dedupe_crashes().await.unwrap();
    assert_eq!(store.list_crashes_by_run(run.id).await.unwrap().len(), 4);
}

fn sample_harness(target_id: Uuid) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(...) { return 0; }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec!["-fsanitize=fuzzer,address".to_owned()],
            output: PathBuf::from("fuzz_parse_value"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    }
}

#[tokio::test]
async fn run_roundtrip_and_status_update() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::AflPlusPlus, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();

    let fetched = store.get_run(id).await.unwrap().expect("run exists");
    assert_eq!(fetched.id, id);
    assert_eq!(fetched.status, RunStatus::Pending);
    assert_eq!(fetched.kind, RunKind::Campaign);
    assert_eq!(fetched.engine, EngineKind::AflPlusPlus);

    let ended = Utc::now();
    store
        .set_run_status(id, RunStatus::Done, Some(ended))
        .await
        .unwrap();
    let after = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(after.status, RunStatus::Done);
    assert!(after.ended_at.is_some());

    let listed = store.list_runs(Some("/proj")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(store.list_runs(Some("/other")).await.unwrap().is_empty());
}

#[tokio::test]
async fn target_and_harness_roundtrip() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    let target_id = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();

    // Idempotent upsert: replacing the same id keeps a single row.
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let targets = store.list_targets("/proj").await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].symbol, "parse_value");

    let harness = sample_harness(target_id);
    let hid = harness.id;
    store.upsert_harness(&harness).await.unwrap();
    let got = store.get_harness(hid).await.unwrap().unwrap();
    assert_eq!(got.target_id, target_id);
    assert_eq!(store.list_harnesses(target_id).await.unwrap().len(), 1);
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
}

#[tokio::test]
async fn rediscovering_a_symbol_does_not_accumulate_duplicates() {
    let (store, _dir) = temp_store().await;

    // Each discovery pass assigns a fresh id to the same symbol (as the scanner
    // does). The store must keep one stable row per (project, symbol), not pile
    // up or invalidate harness/corpus/crash foreign-key attribution.
    let stable_id = sample_target("/proj").id;
    for _ in 0..5 {
        let mut t = sample_target("/proj");
        t.id = stable_id;
        store.upsert_target(&t, Utc::now()).await.unwrap();
    }
    let harness = sample_harness(stable_id);
    store.upsert_harness(&harness).await.unwrap();
    let mut rediscovered = sample_target("/proj");
    rediscovered.id = Uuid::new_v4();
    store
        .upsert_target(&rediscovered, Utc::now())
        .await
        .unwrap();
    let targets = store.list_targets("/proj").await.unwrap();
    assert_eq!(targets.len(), 1, "same symbol must collapse to one row");
    assert_eq!(targets[0].symbol, "parse_value");
    assert_eq!(
        targets[0].id, stable_id,
        "target identity must remain stable"
    );
    assert_eq!(
        store.list_harnesses(stable_id).await.unwrap().len(),
        1,
        "rediscovery must not orphan the target's harnesses"
    );

    // A different symbol in the same project is kept separately.
    let mut other = sample_target("/proj");
    other.id = Uuid::new_v4();
    other.symbol = "parse_header".to_owned();
    store.upsert_target(&other, Utc::now()).await.unwrap();
    assert_eq!(store.list_targets("/proj").await.unwrap().len(), 2);
}

#[tokio::test]
async fn clear_knowledge_empties_all_domain_tables() {
    let (store, _dir) = temp_store().await;

    // Seed one of every domain record, linked as they would be in practice.
    let target = sample_target("/proj");
    let target_id = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&sample_harness(target_id))
        .await
        .unwrap();
    let entry = CorpusEntry {
        path: PathBuf::from("corpus/seed_1"),
        sha256: "abc123".to_owned(),
        size: 42,
        source: CorpusSource::Seed,
        coverage_hash: None,
    };
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    let run = RunRecord::new("/proj".to_owned(), EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id,
        input_path: PathBuf::from("out/crash-1"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "boom".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };
    store.upsert_crash(&crash).await.unwrap();

    store.clear_knowledge().await.unwrap();

    // Every table is emptied -- no orphaned harnesses or corpus left behind.
    assert!(store.list_targets("/proj").await.unwrap().is_empty());
    assert!(store.list_runs(Some("/proj")).await.unwrap().is_empty());
    assert!(store.list_crashes_by_run(run.id).await.unwrap().is_empty());
    assert!(store.list_all_harnesses().await.unwrap().is_empty());
    assert!(store.list_all_corpus_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_project_cascades_and_isolates_other_projects() {
    let (store, _dir) = temp_store().await;

    // Seed two projects with a full record set each.
    let seed = |root: &'static str| {
        let store = &store;
        async move {
            let mut target = sample_target(root);
            target.id = Uuid::new_v4();
            let target_id = target.id;
            store.upsert_target(&target, Utc::now()).await.unwrap();
            store
                .upsert_harness(&sample_harness(target_id))
                .await
                .unwrap();
            let entry = CorpusEntry {
                path: PathBuf::from("corpus/seed"),
                sha256: "sha".to_owned(),
                size: 10,
                source: CorpusSource::Seed,
                coverage_hash: None,
            };
            store.upsert_corpus_entry(target_id, &entry).await.unwrap();
            let run = RunRecord::new(root.to_owned(), EngineKind::LibFuzzer, None, Utc::now());
            let run_id = run.id;
            store.insert_run(&run).await.unwrap();
            store
                .upsert_crash(&Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path: PathBuf::from("out/crash"),
                    stack_signature: "sig".to_owned(),
                    kind: CrashKind::Asan,
                    summary: "boom".to_owned(),
                    minimized: false,
                    bug_report: None,
                    casr: None,
                })
                .await
                .unwrap();
            (target_id, run_id)
        }
    };
    let (_gone_target, gone_run) = seed("/gone").await;
    let (kept_target, kept_run) = seed("/kept").await;

    // Both projects also carry a policy override and an audit event.
    let over = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 20.0,
        notify_only: false,
    };
    store.set_project_auto_revert("/gone", over).await.unwrap();
    store.set_project_auto_revert("/kept", over).await.unwrap();
    let ev = |project: &str| AutoRevertEvent {
        id: Uuid::new_v4().to_string(),
        ts: "2026-07-09T10:00:00Z".to_owned(),
        project_root: project.to_owned(),
        target: "parse".to_owned(),
        run_id: "run".to_owned(),
        from_rev: "aaaaaaaaaaaa".to_owned(),
        to_rev: "bbbbbbbbbbbb".to_owned(),
        previous_edges: 1000,
        regressed_edges: 700,
        drop_pct: 30.0,
        reverted: true,
    };
    store.record_auto_revert_event(&ev("/gone")).await.unwrap();
    store.record_auto_revert_event(&ev("/kept")).await.unwrap();

    store.delete_project("/gone").await.unwrap();

    // The deleted project is gone across every table.
    assert!(store.list_targets("/gone").await.unwrap().is_empty());
    assert!(store.list_runs(Some("/gone")).await.unwrap().is_empty());
    assert!(store
        .list_crashes_by_run(gone_run)
        .await
        .unwrap()
        .is_empty());
    // Its policy override and audit events are cascaded too.
    assert_eq!(store.project_auto_revert("/gone").await.unwrap(), None);
    assert!(store
        .list_auto_revert_events(Some("/gone"), 50)
        .await
        .unwrap()
        .is_empty());

    // The other project is fully intact.
    assert_eq!(store.list_targets("/kept").await.unwrap().len(), 1);
    assert_eq!(store.list_runs(Some("/kept")).await.unwrap().len(), 1);
    assert_eq!(store.list_harnesses(kept_target).await.unwrap().len(), 1);
    assert_eq!(
        store.list_corpus_entries(kept_target).await.unwrap().len(),
        1
    );
    assert_eq!(store.list_crashes_by_run(kept_run).await.unwrap().len(), 1);
    assert_eq!(
        store.project_auto_revert("/kept").await.unwrap(),
        Some(over)
    );
    assert_eq!(
        store
            .list_auto_revert_events(Some("/kept"), 50)
            .await
            .unwrap()
            .len(),
        1
    );
    // No orphaned children survive the delete.
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
    assert_eq!(store.list_all_corpus_entries().await.unwrap().len(), 1);
}

#[tokio::test]
async fn delete_orphans_removes_dangling_children_keeps_valid() {
    let (store, _dir) = temp_store().await;

    // A valid target with a linked harness/corpus.
    let target = sample_target("/proj");
    let valid_target = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&sample_harness(valid_target))
        .await
        .unwrap();

    // An orphaned harness/corpus/crash pointing at a target that never existed
    // (as older partial clears left behind -- these render as "unknown").
    let ghost = Uuid::new_v4();
    store.upsert_harness(&sample_harness(ghost)).await.unwrap();
    store
        .upsert_corpus_entry(
            ghost,
            &CorpusEntry {
                path: PathBuf::from("c"),
                sha256: "x".to_owned(),
                size: 1,
                source: CorpusSource::Seed,
                coverage_hash: None,
            },
        )
        .await
        .unwrap();
    let run_id = Uuid::new_v4();
    store
        .upsert_crash(&Crash {
            id: Uuid::new_v4(),
            run_id,
            target_id: ghost,
            input_path: PathBuf::from("out/crash"),
            stack_signature: "sig".to_owned(),
            kind: CrashKind::Asan,
            summary: "boom".to_owned(),
            minimized: false,
            bug_report: None,
            casr: None,
        })
        .await
        .unwrap();

    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 2);

    store.delete_orphans().await.unwrap();

    // The valid harness survives; the ghosts are purged.
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
    assert_eq!(store.list_harnesses(valid_target).await.unwrap().len(), 1);
    assert!(store.list_all_corpus_entries().await.unwrap().is_empty());
    assert!(store.list_crashes_by_run(run_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn crash_and_corpus_roundtrip() {
    let (store, _dir) = temp_store().await;
    let run_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id,
        target_id,
        input_path: PathBuf::from("out/crash-abc"),
        stack_signature: "deadbeef".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
    };
    store.upsert_crash(&crash).await.unwrap();
    let crashes = store.list_crashes_by_run(run_id).await.unwrap();
    assert_eq!(crashes.len(), 1);
    assert_eq!(crashes[0].kind, CrashKind::Asan);
    assert!(crashes[0].minimized);

    let entry = CorpusEntry {
        path: PathBuf::from("corpus/seed_1"),
        sha256: "abc123".to_owned(),
        size: 42,
        source: CorpusSource::Seed,
        coverage_hash: None,
    };
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    // Same (target, sha) upserts in place rather than duplicating.
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    let entries = store.list_corpus_entries(target_id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 42);
}

#[tokio::test]
async fn corpus_replacement_is_exact_and_preserves_richer_metadata() {
    let (store, _dir) = temp_store().await;
    let target_id = Uuid::new_v4();
    let stale = CorpusEntry {
        path: PathBuf::from("corpus/stale"),
        sha256: "stale".to_owned(),
        size: 5,
        source: CorpusSource::Fuzzer,
        coverage_hash: Some("old-coverage".to_owned()),
    };
    let retained = CorpusEntry {
        path: PathBuf::from("corpus/original"),
        sha256: "retained".to_owned(),
        size: 8,
        source: CorpusSource::Seed,
        coverage_hash: Some("coverage".to_owned()),
    };
    store.upsert_corpus_entry(target_id, &stale).await.unwrap();
    store
        .upsert_corpus_entry(target_id, &retained)
        .await
        .unwrap();

    let rediscovered = CorpusEntry {
        path: PathBuf::from("corpus/current"),
        sha256: retained.sha256.clone(),
        size: retained.size,
        source: CorpusSource::Manual,
        coverage_hash: None,
    };
    store
        .replace_corpus_entries(target_id, &[rediscovered])
        .await
        .unwrap();

    let entries = store.list_corpus_entries(target_id).await.unwrap();
    assert_eq!(entries.len(), 1, "stale rows must be removed");
    assert_eq!(entries[0].path, PathBuf::from("corpus/current"));
    assert_eq!(entries[0].source, CorpusSource::Seed);
    assert_eq!(entries[0].coverage_hash.as_deref(), Some("coverage"));
}

#[tokio::test]
async fn corpus_deletion_is_scoped_to_the_owning_target() {
    let (store, _dir) = temp_store().await;
    let first_target = Uuid::new_v4();
    let second_target = Uuid::new_v4();
    let entry = CorpusEntry {
        path: PathBuf::from("corpus/shared"),
        sha256: "same-content".to_owned(),
        size: 12,
        source: CorpusSource::Manual,
        coverage_hash: None,
    };
    store
        .upsert_corpus_entry(first_target, &entry)
        .await
        .unwrap();
    store
        .upsert_corpus_entry(second_target, &entry)
        .await
        .unwrap();

    store
        .delete_corpus_entry(first_target, &entry.sha256)
        .await
        .unwrap();

    assert!(store
        .list_corpus_entries(first_target)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_corpus_entries(second_target)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn schedule_executions_round_trip_and_latest_fire() {
    let (store, _dir) = temp_store().await;

    store
        .upsert_schedule_execution(
            "e1",
            "s1",
            "2026-07-01T01:00:00+00:00",
            "completed",
            r#"{"k":1}"#,
        )
        .await
        .unwrap();
    store
        .upsert_schedule_execution(
            "e2",
            "s1",
            "2026-07-01T02:00:00+00:00",
            "failed",
            r#"{"k":2}"#,
        )
        .await
        .unwrap();

    let recent = store.list_schedule_executions(10).await.unwrap();
    assert_eq!(recent.len(), 2);
    // Newest first.
    assert_eq!(recent[0], r#"{"k":2}"#);

    let fires: std::collections::HashMap<String, String> = store
        .latest_schedule_fires()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(fires.get("s1").unwrap(), "2026-07-01T02:00:00+00:00");

    // Upsert replaces by id (no duplicate).
    store
        .upsert_schedule_execution(
            "e2",
            "s1",
            "2026-07-01T02:00:00+00:00",
            "completed",
            r#"{"k":3}"#,
        )
        .await
        .unwrap();
    assert_eq!(store.list_schedule_executions(10).await.unwrap().len(), 2);
}

#[tokio::test]
async fn chat_checkpoints_survive_a_reconnect() {
    use hf_core::session::{ChatCheckpoint, ChatCheckpointStore};
    use hf_core::types::SessionId;
    use hf_storage::SqliteChatCheckpointStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.db");
    let session = SessionId("s-1".to_owned());

    let cp = |id: &str, turn: u32| ChatCheckpoint {
        checkpoint_id: id.to_owned(),
        session_id: session.clone(),
        turn_number: turn,
        message_count_before: turn * 2,
        journal_scope_id: format!("scope-{turn}"),
        invalidated: false,
        created_at: Utc::now(),
    };

    // Persist two checkpoints, then drop the store (simulating app exit).
    {
        let store = Store::connect(&path).await.expect("connect");
        let cps = SqliteChatCheckpointStore::new(store.pool().clone());
        cps.save(&cp("cp-1", 1)).await.unwrap();
        cps.save(&cp("cp-2", 2)).await.unwrap();
    }

    // Reconnect (simulating a restart) -- the checkpoints must still be there,
    // which is exactly what the in-memory store lost (making rollback a no-op).
    let store = Store::connect(&path).await.expect("reconnect");
    let cps = SqliteChatCheckpointStore::new(store.pool().clone());

    let all = cps.list_by_session(&session).await.unwrap();
    assert_eq!(all.len(), 2, "checkpoints must persist across a restart");
    // list_by_session is turn_number DESC.
    assert_eq!(all[0].turn_number, 2);

    let latest = cps.latest(&session).await.unwrap().expect("a latest");
    assert_eq!(latest.checkpoint_id, "cp-2");

    let loaded = cps.load("cp-1").await.unwrap();
    assert_eq!(loaded.message_count_before, 2);

    // Rolling back past turn 1 invalidates every later checkpoint.
    let invalidated = cps.invalidate_after(&session, 1).await.unwrap();
    assert_eq!(invalidated, 1);
    assert_eq!(
        cps.latest(&session).await.unwrap().map(|c| c.checkpoint_id),
        Some("cp-1".to_owned()),
        "the latest non-invalidated checkpoint is now cp-1"
    );
}

#[tokio::test]
async fn reopening_a_store_self_heals_orphaned_children() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("heal.db");

    // First connection: a valid target+harness, plus an orphaned harness whose
    // target never existed (as an older partial clear would have left behind).
    {
        let store = Store::connect(&path).await.unwrap();
        let target = sample_target("/proj");
        let valid = target.id;
        store.upsert_target(&target, Utc::now()).await.unwrap();
        store.upsert_harness(&sample_harness(valid)).await.unwrap();
        store
            .upsert_harness(&sample_harness(Uuid::new_v4()))
            .await
            .unwrap();
        assert_eq!(store.list_all_harnesses().await.unwrap().len(), 2);
    }

    // Reconnecting runs the on-open cleanup, dropping the orphan.
    let store = Store::connect(&path).await.unwrap();
    let remaining = store.list_all_harnesses().await.unwrap();
    assert_eq!(remaining.len(), 1);
}

#[tokio::test]
async fn set_run_stats_persists_edges_and_execs() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();

    // Fresh run has no stats yet.
    assert!(store.get_run(id).await.unwrap().unwrap().edges.is_none());

    store.set_run_stats(id, 142, 3800.0, 5).await.unwrap();

    let got = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(got.edges, Some(142));
    assert_eq!(got.execs, Some(3800.0));
    assert_eq!(got.crash_count, Some(5));
    // Round-trips through list_runs too.
    let listed = store.list_runs(Some("/proj")).await.unwrap();
    assert_eq!(listed[0].edges, Some(142));
}

#[tokio::test]
async fn run_samples_roundtrip() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    assert!(store.run_samples(id).await.unwrap().is_none());

    let json = r#"[{"t":0.0,"edges":3,"execs":100.0},{"t":5.0,"edges":9,"execs":250.0}]"#;
    store.set_run_samples(id, json).await.unwrap();
    assert_eq!(store.run_samples(id).await.unwrap().as_deref(), Some(json));
}

#[tokio::test]
async fn run_harness_rev_roundtrips() {
    let (store, _dir) = temp_store().await;
    let mut run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    run.harness_rev = Some("a".repeat(64));
    run.binary_rev = Some("b".repeat(64));
    run.evidence_dir = Some("runs/7b6f2c7f/out".to_owned());
    run.kind = RunKind::Smoke;
    run.context_rev = Some("c".repeat(64));
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    let got = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(got.harness_rev.as_deref(), Some("a".repeat(64).as_str()));
    assert_eq!(got.binary_rev.as_deref(), Some("b".repeat(64).as_str()));
    assert_eq!(got.evidence_dir.as_deref(), Some("runs/7b6f2c7f/out"));
    assert_eq!(got.kind, RunKind::Smoke);
    assert_eq!(got.context_rev.as_deref(), Some("c".repeat(64).as_str()));
}

#[tokio::test]
async fn run_mutations_fail_when_the_run_does_not_exist() {
    let (store, _dir) = temp_store().await;
    let missing = Uuid::new_v4();

    assert!(matches!(
        store
            .set_run_status(missing, RunStatus::Failed, Some(Utc::now()))
            .await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_stats(missing, 1, 1.0, 0).await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_samples(missing, "[]").await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_harness_source(missing, "source").await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.delete_run(&missing.to_string()).await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn run_harness_source_roundtrips() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    assert!(store.run_harness_source(id).await.unwrap().is_none());
    store
        .set_run_harness_source(id, "int LLVMFuzzerTestOneInput(){return 0;}")
        .await
        .unwrap();
    assert_eq!(
        store.run_harness_source(id).await.unwrap().as_deref(),
        Some("int LLVMFuzzerTestOneInput(){return 0;}")
    );
}
