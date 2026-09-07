//! Shared retained campaign fixture for experiment presentation tests.
use chrono::{DateTime, Duration, Utc};
use hf_core::{
    engine::{EngineKind, FuzzRunConfig},
    harness::{BuildCommand, Harness, HarnessStatus},
    target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    },
};
use hf_storage::{RunRecord, RunStatus, Store};
use std::{path::PathBuf, time::Duration as StdDuration};
use uuid::Uuid;
/// Insert exact retained target, harness, config and campaign evidence.
///
/// # Panics
/// Panics when the disposable fixture database cannot retain valid evidence.
pub async fn retained_campaign(store: &Store, project: &str, start: DateTime<Utc>) -> RunRecord {
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.into(),
        language: TargetLanguage::C,
        symbol: "parse_value".into(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: "parser.c".into(),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 0.8,
        sanitizers: vec![Sanitizer::Address],
        rationale: "parser".into(),
        reachable_functions: vec![],
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, start).await.unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "abc".into(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".into(),
            args: vec![],
            output: "parser".into(),
            extra_flags: vec![],
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();
    let config = FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(StdDuration::from_secs(60)),
        max_mem_mb: 1024,
        max_cpus: 1,
        seed_corpus: Some(PathBuf::from("/corpus")),
        sanitizer: harness.sanitizer,
        env: vec![("A".into(), "secret".into()), ("A".into(), "second".into())],
        extra_args: vec![String::new(), "-x".into()],
        seed: Some(u64::MAX),
        replay_of: None,
    };
    let mut run = RunRecord::new(project, harness.engine, Some(config), start);
    run.status = RunStatus::Done;
    run.ended_at = Some(start + Duration::seconds(60));
    run.harness_rev =
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into());
    run.binary_rev = Some("b".repeat(64));
    run.source_rev = Some("c".repeat(64));
    run.corpus_rev = Some("d".repeat(64));
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "e".repeat(64)));
    run.edges = Some(0);
    store.insert_run(&run).await.unwrap();
    run
}
