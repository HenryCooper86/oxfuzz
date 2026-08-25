//! Harness Tournament ranking contract.
//!
//! Ranking is deterministic and objective: no model opinion enters it, and
//! throughput never outranks a better verdict.

#![cfg(feature = "harness-tournament")]

use hf_service::harness_tournament::{
    rank_candidates, CandidateOrigin, HarnessCandidateEvidence, SmokeEvidence, MAX_CANDIDATES,
};
use hf_service::verification::VerdictLevel;

fn candidate(index: usize) -> HarnessCandidateEvidence {
    HarnessCandidateEvidence {
        index,
        origin: CandidateOrigin::Llm,
        source_sha256: format!("{index:064}"),
        compiled: true,
        repairs_used: 0,
        compile_error: None,
        smoke: Some(SmokeEvidence {
            verdict: VerdictLevel::Pass,
            execs_per_sec: 1000.0,
            crashes: 0,
        }),
    }
}

#[test]
fn a_compiling_candidate_always_outranks_one_that_never_built() {
    let mut built = candidate(0);
    let mut unbuilt = candidate(1);
    unbuilt.compiled = false;
    unbuilt.smoke = None;
    unbuilt.compile_error = Some("undefined reference to parse_packet".to_owned());
    // Give the failed candidate every other advantage it could have.
    built.repairs_used = 3;
    built.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Suspect,
        execs_per_sec: 1.0,
        crashes: 0,
    });

    assert_eq!(rank_candidates(&[unbuilt, built]), vec![0, 1]);
}

#[test]
fn a_better_smoke_verdict_outranks_higher_throughput() {
    let mut passing = candidate(0);
    passing.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Pass,
        execs_per_sec: 10.0,
        crashes: 0,
    });
    let mut fast_but_suspect = candidate(1);
    fast_but_suspect.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Suspect,
        execs_per_sec: 100_000.0,
        crashes: 0,
    });

    // A harness that does nothing quickly is not better than one that works.
    assert_eq!(rank_candidates(&[passing, fast_but_suspect]), vec![0, 1]);
}

#[test]
fn equal_verdicts_prefer_fewer_repairs_then_throughput_then_index() {
    let mut clean = candidate(0);
    clean.repairs_used = 0;
    let mut repaired = candidate(1);
    repaired.repairs_used = 2;
    assert_eq!(rank_candidates(&[repaired, clean]), vec![0, 1]);

    let mut slow = candidate(0);
    slow.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Pass,
        execs_per_sec: 10.0,
        crashes: 0,
    });
    let mut fast = candidate(1);
    fast.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Pass,
        execs_per_sec: 20.0,
        crashes: 0,
    });
    assert_eq!(rank_candidates(&[slow, fast]), vec![1, 0]);

    // Identical evidence keeps a stable, index-ordered result.
    assert_eq!(rank_candidates(&[candidate(0), candidate(1)]), vec![0, 1]);
}

#[test]
fn a_smoke_failure_ranks_below_a_suspect_result_but_above_a_failed_build() {
    let mut failed_smoke = candidate(0);
    failed_smoke.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Fail,
        execs_per_sec: 0.0,
        crashes: 0,
    });
    let mut suspect = candidate(1);
    suspect.smoke = Some(SmokeEvidence {
        verdict: VerdictLevel::Suspect,
        execs_per_sec: 0.0,
        crashes: 1,
    });
    let mut unbuilt = candidate(2);
    unbuilt.compiled = false;
    unbuilt.smoke = None;

    assert_eq!(
        rank_candidates(&[failed_smoke, suspect, unbuilt]),
        vec![1, 0, 2]
    );
}

#[test]
fn a_compiled_candidate_with_no_smoke_evidence_ranks_below_one_that_passed() {
    let passed = candidate(0);
    let mut unsmoked = candidate(1);
    unsmoked.smoke = None;
    assert_eq!(rank_candidates(&[unsmoked, passed]), vec![0, 1]);
}

#[test]
fn the_candidate_count_is_bounded_because_each_costs_a_model_call_and_two_sandbox_runs() {
    assert!(
        (2..=8).contains(&MAX_CANDIDATES),
        "a tournament is bounded, not unbounded: {MAX_CANDIDATES}"
    );
}

#[test]
fn an_empty_tournament_ranks_nothing_rather_than_panicking() {
    assert!(rank_candidates(&[]).is_empty());
}
