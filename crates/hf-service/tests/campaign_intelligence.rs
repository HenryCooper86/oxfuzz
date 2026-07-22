#![cfg(feature = "proof-carrying")]

use hf_core::engine::EngineKind;
use hf_service::campaign_intelligence::{
    CampaignAction, CampaignAdviceRequest, CampaignBudget, CampaignObservation, EngineCostRate,
};
use hf_service::ServiceContainer;
use uuid::Uuid;

#[test]
fn service_advisor_is_read_only_and_returns_evidence() {
    let request = CampaignAdviceRequest {
        current_engine: EngineKind::LibFuzzer,
        enabled_engines: vec![EngineKind::LibFuzzer, EngineKind::AflPlusPlus],
        engine_rates: vec![
            EngineCostRate {
                engine: EngineKind::LibFuzzer,
                usd_per_hour: 1.0,
            },
            EngineCostRate {
                engine: EngineKind::AflPlusPlus,
                usd_per_hour: 1.0,
            },
        ],
        observations: vec![CampaignObservation {
            run_id: Uuid::from_u128(1),
            sequence: 1,
            engine: EngineKind::LibFuzzer,
            duration_secs: 3_600,
            new_edges: 0,
            crashes: 0,
            corpus_additions: 0,
            model_cost_usd: 0.0,
        }],
        budget: CampaignBudget {
            max_total_cost_usd: 10.0,
            min_edges_per_dollar: 1.0,
            plateau_runs: 1,
        },
    };

    let advice = ServiceContainer::stubbed()
        .campaign_advice(&request)
        .expect("valid bounded advice");

    assert_eq!(
        advice.action,
        CampaignAction::SwitchEngine {
            from: EngineKind::LibFuzzer,
            to: EngineKind::AflPlusPlus,
        }
    );
    assert!(!advice.evidence.is_empty());
    assert!(advice.requires_human_approval);
}
