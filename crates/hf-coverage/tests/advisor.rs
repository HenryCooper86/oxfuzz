#![cfg(feature = "campaign-advisor")]

use hf_core::engine::EngineKind;
use hf_coverage::campaign_advisor::{
    advise, AdvisorError, CampaignAction, CampaignAdviceRequest, CampaignBudget,
    CampaignObservation, EngineCostRate,
};
use uuid::Uuid;

/// Tolerance for comparing computed `f64` economics against exact expected values.
const EPS: f64 = 1e-9;

fn observation(sequence: u64, engine: EngineKind, new_edges: u64) -> CampaignObservation {
    CampaignObservation {
        run_id: Uuid::from_u128(u128::from(sequence) + 1),
        sequence,
        engine,
        duration_secs: 3_600,
        new_edges,
        crashes: 0,
        corpus_additions: 0,
        model_cost_usd: 0.0,
    }
}

fn request(observations: Vec<CampaignObservation>) -> CampaignAdviceRequest {
    CampaignAdviceRequest {
        current_engine: EngineKind::LibFuzzer,
        enabled_engines: vec![EngineKind::LibFuzzer, EngineKind::AflPlusPlus],
        engine_rates: vec![
            EngineCostRate {
                engine: EngineKind::LibFuzzer,
                usd_per_hour: 1.0,
            },
            EngineCostRate {
                engine: EngineKind::AflPlusPlus,
                usd_per_hour: 2.0,
            },
        ],
        observations,
        budget: CampaignBudget {
            max_total_cost_usd: 100.0,
            min_edges_per_dollar: 1.0,
            plateau_runs: 2,
        },
    }
}

#[test]
fn budget_exhaustion_stops_before_optimization() {
    let mut input = request(vec![observation(0, EngineKind::LibFuzzer, 100)]);
    input.budget.max_total_cost_usd = 1.0;

    let advice = advise(&input).expect("valid advice");
    assert_eq!(advice.action, CampaignAction::Stop);
    assert!(!advice.requires_human_approval);
    assert!((advice.total_cost_usd - 1.0).abs() < EPS);
}

#[test]
fn a_plateau_recommends_an_untried_enabled_engine() {
    let input = request(vec![
        observation(0, EngineKind::LibFuzzer, 0),
        observation(1, EngineKind::LibFuzzer, 0),
    ]);

    let advice = advise(&input).expect("valid advice");
    assert_eq!(
        advice.action,
        CampaignAction::SwitchEngine {
            from: EngineKind::LibFuzzer,
            to: EngineKind::AflPlusPlus,
        }
    );
    assert!(advice.requires_human_approval);
    assert!(advice.evidence.iter().any(|item| item.contains("plateau")));
}

#[test]
fn equivalent_history_is_order_independent() {
    let first = observation(0, EngineKind::LibFuzzer, 20);
    let second = observation(1, EngineKind::AflPlusPlus, 80);
    let forward = advise(&request(vec![first.clone(), second.clone()])).unwrap();
    let reverse = advise(&request(vec![second, first])).unwrap();
    assert_eq!(forward, reverse);
}

#[test]
fn higher_yield_engine_is_recommended_with_measured_economics() {
    let input = request(vec![
        observation(0, EngineKind::LibFuzzer, 10),
        observation(1, EngineKind::AflPlusPlus, 100),
    ]);

    let advice = advise(&input).expect("valid advice");
    assert_eq!(
        advice.action,
        CampaignAction::SwitchEngine {
            from: EngineKind::LibFuzzer,
            to: EngineKind::AflPlusPlus,
        }
    );
    assert!((advice.total_cost_usd - 3.0).abs() < EPS);
    assert!((advice.marginal_edges_per_dollar - 10.0).abs() < EPS);
}

#[test]
fn malformed_or_duplicate_economics_fail_closed() {
    let mut non_finite = request(Vec::new());
    non_finite.engine_rates[0].usd_per_hour = f64::NAN;
    assert_eq!(advise(&non_finite), Err(AdvisorError::InvalidRate));

    let duplicate = observation(0, EngineKind::LibFuzzer, 1);
    let duplicate_id = CampaignObservation {
        sequence: 1,
        ..duplicate.clone()
    };
    assert_eq!(
        advise(&request(vec![duplicate, duplicate_id])),
        Err(AdvisorError::DuplicateRun)
    );

    let mut overflowing = request(vec![observation(0, EngineKind::LibFuzzer, 1)]);
    overflowing.engine_rates[0].usd_per_hour = f64::MAX;
    overflowing.observations[0].duration_secs = u64::MAX;
    assert_eq!(advise(&overflowing), Err(AdvisorError::InvalidObservation));
}
