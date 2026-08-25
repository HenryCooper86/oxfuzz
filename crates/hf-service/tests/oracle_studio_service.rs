//! Oracle Studio service contract.
//!
//! The scaffold is produced for review and nothing is executed. A finding is an
//! oracle violation only when the retained log carries the marker.

#![cfg(feature = "oracle-studio")]

use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::EngineKind;
use hf_service::oracle_studio::{OracleKind, OracleProperty, OracleSpec, ORACLE_VIOLATION_MARKER};
use hf_service::{OracleScaffoldRequest, ServiceContainer};
use hf_storage::{RunRecord, Store};
use uuid::Uuid;

fn spec(id: Uuid) -> OracleSpec {
    OracleSpec {
        id,
        target_symbol: "parse_packet".to_owned(),
        property: OracleProperty::Invariant {
            predicate: "arena_is_balanced".to_owned(),
        },
        description: "the arena stays balanced after every parse".to_owned(),
    }
}

#[tokio::test]
async fn the_scaffold_is_produced_for_review_and_nothing_is_executed() {
    let container = ServiceContainer::stubbed();
    let view = container
        .oracle_scaffold(OracleScaffoldRequest {
            spec: spec(Uuid::nil()),
        })
        .expect("a valid specification renders");

    assert_eq!(view.kind, OracleKind::Invariant);
    assert!(view.source.contains("arena_is_balanced"));
    assert!(view.source.contains(ORACLE_VIOLATION_MARKER));
    assert!(
        !view.blocking_lint,
        "a scaffold that could not build is not worth reviewing"
    );
}

#[tokio::test]
async fn an_invalid_specification_is_refused_rather_than_rendered() {
    let container = ServiceContainer::stubbed();
    let mut candidate = spec(Uuid::nil());
    candidate.property = OracleProperty::Invariant {
        predicate: "evil(); system(\"id\"); //".to_owned(),
    };
    let error = container
        .oracle_scaffold(OracleScaffoldRequest { spec: candidate })
        .expect_err("a hostile symbol never renders");
    assert!(error.to_string().contains("identifier"));
}

/// Build a store holding one crash whose retained log is `log`.
async fn crash_with_log(log: &str) -> (ServiceContainer, Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::connect(dir.path().join("oracle.db")).await.unwrap());
    let run = RunRecord::new(
        dir.path().to_string_lossy(),
        EngineKind::LibFuzzer,
        None,
        Utc::now(),
    );
    store.insert_run(&run).await.unwrap();

    // Ingest's conventional pairing: `log-<stem>.txt` beside the input.
    let crash_input = dir.path().join("crash-abc123");
    std::fs::write(&crash_input, b"input").unwrap();
    std::fs::write(dir.path().join("log-abc123.txt"), log).unwrap();

    let crash_id = Uuid::new_v4();
    store
        .upsert_crash(&Crash {
            id: crash_id,
            run_id: run.id,
            target_id: Uuid::new_v4(),
            input_path: crash_input,
            stack_signature: "signature".to_owned(),
            kind: CrashKind::Abort,
            summary: "trap".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin: CrashOrigin::Target,
        })
        .await
        .unwrap();
    (ServiceContainer::stubbed().with_store(store), crash_id, dir)
}

#[tokio::test]
async fn a_finding_whose_log_carries_the_marker_is_an_oracle_violation() {
    let oracle_id = Uuid::new_v4();
    let log = format!(
        "==1== ERROR: libFuzzer: deadly signal\n\
         {ORACLE_VIOLATION_MARKER} {oracle_id} invariant\n"
    );
    let (container, crash_id, _dir) = crash_with_log(&log).await;

    let violation = container
        .oracle_violation_for_crash(crash_id)
        .await
        .expect("classification reads retained evidence")
        .expect("the marker is present");
    assert_eq!(violation.oracle_id, oracle_id);
    assert_eq!(violation.kind, OracleKind::Invariant);
}

#[tokio::test]
async fn a_memory_safety_crash_in_an_oracle_harness_is_not_a_violation() {
    let log = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n\
               READ of size 1 at 0x602 thread T0\n";
    let (container, crash_id, _dir) = crash_with_log(log).await;

    assert!(
        container
            .oracle_violation_for_crash(crash_id)
            .await
            .expect("classification reads retained evidence")
            .is_none(),
        "only the marker makes a finding an oracle violation"
    );
}
