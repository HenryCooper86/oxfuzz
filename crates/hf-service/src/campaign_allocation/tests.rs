use super::*;

fn candidate(name: &str) -> AllocationCandidate {
    AllocationCandidate {
        target: format!("{name}.c::{name}"),
        dispatch_target: name.into(),
        engine: "libfuzzer".into(),
        language: "c".into(),
        target_id: Uuid::new_v4(),
        harness_id: Uuid::new_v4(),
        source_sha256: "a".repeat(64),
    }
}
fn proposal(project: &Path) -> AllocationProposal {
    make_proposal(
        project,
        vec![candidate("alpha"), candidate("bravo")],
        &[],
        5,
        51,
    )
    .unwrap()
}

#[test]
fn quotas_reserve_every_target_and_account_for_unallocated_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let plan = proposal(dir.path());
    assert_eq!(
        plan.entries
            .iter()
            .map(|entry| entry.max_runs)
            .collect::<Vec<_>>(),
        [3, 2]
    );
    assert_eq!(plan.per_run_secs, 10);
    assert_eq!(plan.unallocated_secs, 1);
    assert!(make_proposal(dir.path(), vec![candidate("a"), candidate("b")], &[], 1, 10).is_err());
}

#[test]
fn approval_binds_exact_proposal_and_reservations_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let store = AllocationStore::new(&dir.path().join("state"), project.clone());
    let plan = store.propose(proposal(&project)).unwrap();
    let ids = plan
        .proposal
        .entries
        .iter()
        .map(|entry| entry.candidate.clone())
        .collect::<Vec<_>>();
    assert!(store.reserve("schedule-a", &ids, 100).is_err());
    assert!(store.review(plan.proposal.id, "wrong", true).is_err());
    store.review(plan.proposal.id, &plan.digest, true).unwrap();
    let first = store.reserve("schedule-a", &ids, 100).unwrap().unwrap();
    assert_eq!(first.duration_secs, 10);
    drop(store);
    let store = AllocationStore::new(&dir.path().join("state"), project);
    assert_eq!(store.inspect().unwrap().unwrap().reservations.len(), 1);
    let only_first = vec![ids[0].clone()];
    for _ in 0..2 {
        store
            .reserve("fast-schedule", &only_first, 100)
            .unwrap()
            .unwrap();
    }
    assert!(store.reserve("fast-schedule", &only_first, 100).is_err());
    for _ in 0..2 {
        store
            .reserve("slow-schedule", &ids[1..], 100)
            .unwrap()
            .unwrap();
    }
    assert!(store.reserve("schedule-a", &ids, 100).is_err());
    assert_eq!(
        store
            .inspect()
            .unwrap()
            .unwrap()
            .reservations
            .iter()
            .map(|grant| grant.duration_secs)
            .sum::<u64>(),
        50
    );
}

#[test]
fn concurrent_schedules_cannot_spend_one_quota_twice() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let root = dir.path().join("state");
    let store = AllocationStore::new(&root, project.clone());
    let plan = store.propose(proposal(&project)).unwrap();
    let candidates = plan
        .proposal
        .entries
        .iter()
        .map(|entry| entry.candidate.clone())
        .collect::<Vec<_>>();
    store.review(plan.proposal.id, &plan.digest, true).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..12 {
            let project = project.clone();
            let root = root.clone();
            let candidates = candidates.clone();
            scope.spawn(move || {
                // Admission may be busy or exhausted; neither outcome starts work.
                let _denied_or_reserved =
                    AllocationStore::new(&root, project).reserve("overlap", &candidates, 10);
            });
        }
    });
    let after = store.inspect().unwrap().unwrap();
    assert!(!after.reservations.is_empty());
    assert!(after.reservations.len() <= 5);
    for entry in &after.proposal.entries {
        assert!(
            after
                .reservations
                .iter()
                .filter(|grant| grant.candidate.harness_id == entry.candidate.harness_id)
                .count()
                <= entry.max_runs as usize
        );
    }
}

#[test]
fn revoked_corrupt_and_changed_harness_plans_deny_admission() {
    let dir = tempfile::tempdir().unwrap();
    let store = AllocationStore::new(&dir.path().join("state"), dir.path().to_owned());
    let plan = store.propose(proposal(dir.path())).unwrap();
    let mut candidates = plan
        .proposal
        .entries
        .iter()
        .map(|entry| entry.candidate.clone())
        .collect::<Vec<_>>();
    store.review(plan.proposal.id, &plan.digest, true).unwrap();
    for candidate in &mut candidates {
        candidate.harness_id = Uuid::new_v4();
    }
    assert!(store.reserve("s", &candidates, 10).is_err());
    store.review(plan.proposal.id, &plan.digest, false).unwrap();
    assert!(store.reserve("s", &candidates, 10).is_err());
    std::fs::write(store.path(), "{}").unwrap();
    assert!(store.inspect().is_err());
    assert!(store.reserve("s", &candidates, 10).is_err());
}

fn observation(candidate: &AllocationCandidate, order: u8, edges: u64) -> RunHistoryItem {
    RunHistoryItem {
        id: format!("run-{order}"),
        target_id: Some(candidate.target_id),
        requested_duration_secs: Some(10),
        project_root: "/project".into(),
        target: Some(candidate.target.clone()),
        target_selector: Some(candidate.target.clone()),
        comparison_key: Some(format!("setup-{}", candidate.target_id)),
        kind: "Campaign".into(),
        engine: "LibFuzzer".into(),
        status: "Done".into(),
        started_at: format!("2026-09-10T00:00:0{order}Z"),
        ended_at: None,
        duration_secs: Some(10),
        crashes: 0,
        edges: Some(edges),
        execs: None,
        harness_rev: Some(candidate.source_sha256.clone()),
        binary_rev: Some("b".repeat(64)),
        evidence_dir: None,
    }
}

#[test]
fn comparable_growth_changes_only_the_retained_target_share_deterministically() {
    let a = candidate("alpha");
    let b = candidate("bravo");
    let history = vec![
        observation(&a, 1, 10),
        observation(&a, 2, 12),
        observation(&b, 3, 10000),
        observation(&b, 4, 10000),
    ];
    let first = make_proposal(
        Path::new("/project"),
        vec![b.clone(), a.clone()],
        &history,
        8,
        80,
    )
    .unwrap();
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| (entry.weight, entry.max_runs))
            .collect::<Vec<_>>(),
        [(2, 5), (1, 3)]
    );
    let mut reversed = history.clone();
    reversed.reverse();
    let second = make_proposal(
        Path::new("/project"),
        vec![a.clone(), b.clone()],
        &reversed,
        8,
        80,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&first.entries).unwrap(),
        serde_json::to_value(&second.entries).unwrap()
    );
    let mut incompatible = history;
    incompatible[1].binary_rev = Some("c".repeat(64));
    let fallback = make_proposal(Path::new("/project"), vec![a, b], &incompatible, 8, 80).unwrap();
    assert_eq!(fallback.entries[0].weight, 1);
    assert!(fallback.entries[0].reason.contains("unavailable"));
}
