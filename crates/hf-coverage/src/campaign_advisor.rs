//! Pure, deterministic coverage-per-cost campaign advice.
//!
//! This module has no execution, storage, provider, or tool dependency. It can
//! recommend an action, but cannot perform one.

use std::collections::{HashMap, HashSet};

use hf_core::engine::EngineKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_OBSERVATIONS: usize = 256;

/// One comparable completed campaign measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignObservation {
    /// Durable run identity.
    pub run_id: Uuid,
    /// Stable chronological sequence used instead of input insertion order.
    pub sequence: u64,
    /// Engine that produced this measurement.
    pub engine: EngineKind,
    /// Measured run duration.
    pub duration_secs: u64,
    /// New comparable source edges attributed to the run.
    pub new_edges: u64,
    /// New unique crashes attributed to the run.
    pub crashes: u64,
    /// New corpus entries retained from the run.
    pub corpus_additions: u64,
    /// Attributable model cost used to prepare or interpret this run.
    pub model_cost_usd: f64,
}

/// Operator-supplied compute price for one enabled engine.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EngineCostRate {
    /// Engine priced by this rate.
    pub engine: EngineKind,
    /// Compute cost per wall-clock hour.
    pub usd_per_hour: f64,
}

/// Economic and plateau bounds applied to one advice request.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CampaignBudget {
    /// Stop proposing spend when observed cost reaches this amount.
    pub max_total_cost_usd: f64,
    /// Minimum acceptable marginal edge yield.
    pub min_edges_per_dollar: f64,
    /// Consecutive zero-edge runs that constitute a plateau.
    pub plateau_runs: usize,
}

/// Complete, side-effect-free advisor input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignAdviceRequest {
    /// Engine used by the most recent campaign strategy.
    pub current_engine: EngineKind,
    /// Engines allowed by effective service policy.
    pub enabled_engines: Vec<EngineKind>,
    /// Cost rates for every enabled engine.
    pub engine_rates: Vec<EngineCostRate>,
    /// Bounded comparable run history.
    pub observations: Vec<CampaignObservation>,
    /// Operator-owned economic bounds.
    pub budget: CampaignBudget,
}

/// Proposed next campaign action. No variant carries execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CampaignAction {
    /// Continue with the named engine under the existing approval boundary.
    Continue {
        /// Engine to continue using.
        engine: EngineKind,
    },
    /// Improve seeds, dictionaries, or mutation strategy before more spend.
    ImproveCorpus,
    /// Review a new harness revision; generation and promotion remain separate.
    ReviewHarness,
    /// Consider another enabled engine.
    SwitchEngine {
        /// Current engine.
        from: EngineKind,
        /// Recommended enabled engine.
        to: EngineKind,
    },
    /// Stop spending on this target under the current evidence.
    Stop,
}

/// Deterministic advice and the measurements that justify it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignAdvice {
    /// Proposed action.
    pub action: CampaignAction,
    /// Observed compute plus attributable model cost.
    pub total_cost_usd: f64,
    /// Latest current-engine edge yield per dollar.
    pub marginal_edges_per_dollar: f64,
    /// Stable, operator-readable supporting facts.
    pub evidence: Vec<String>,
    /// Whether acting on the proposal requires the normal human boundary.
    pub requires_human_approval: bool,
}

/// Invalid or ambiguous advisor input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdvisorError {
    /// No enabled engine, or the current engine is not enabled.
    #[error("current engine must be present in a non-empty enabled engine set")]
    InvalidEngineSet,
    /// An enabled engine is duplicated.
    #[error("enabled engines must be unique")]
    DuplicateEngine,
    /// A rate is absent, duplicated, non-finite, or not positive.
    #[error("every enabled engine requires one finite positive hourly rate")]
    InvalidRate,
    /// Budget fields are invalid.
    #[error("campaign budget must be finite, positive, and bounded")]
    InvalidBudget,
    /// Too many observations were supplied.
    #[error("campaign history exceeds the bounded observation limit")]
    TooManyObservations,
    /// A run id is duplicated.
    #[error("campaign history contains a duplicate run id")]
    DuplicateRun,
    /// A chronological sequence number is duplicated.
    #[error("campaign history contains a duplicate sequence")]
    DuplicateSequence,
    /// An observation is malformed or refers to a disabled engine.
    #[error("campaign history contains an invalid observation")]
    InvalidObservation,
}

fn validate(input: &CampaignAdviceRequest) -> Result<HashMap<EngineKind, f64>, AdvisorError> {
    if input.enabled_engines.is_empty() || !input.enabled_engines.contains(&input.current_engine) {
        return Err(AdvisorError::InvalidEngineSet);
    }
    let enabled: HashSet<_> = input.enabled_engines.iter().copied().collect();
    if enabled.len() != input.enabled_engines.len() {
        return Err(AdvisorError::DuplicateEngine);
    }
    if !input.budget.max_total_cost_usd.is_finite()
        || input.budget.max_total_cost_usd <= 0.0
        || !input.budget.min_edges_per_dollar.is_finite()
        || input.budget.min_edges_per_dollar < 0.0
        || !(1..=32).contains(&input.budget.plateau_runs)
    {
        return Err(AdvisorError::InvalidBudget);
    }
    if input.observations.len() > MAX_OBSERVATIONS {
        return Err(AdvisorError::TooManyObservations);
    }

    let mut rates = HashMap::new();
    for rate in &input.engine_rates {
        if !enabled.contains(&rate.engine)
            || !rate.usd_per_hour.is_finite()
            || rate.usd_per_hour <= 0.0
            || rates.insert(rate.engine, rate.usd_per_hour).is_some()
        {
            return Err(AdvisorError::InvalidRate);
        }
    }
    if rates.len() != enabled.len() {
        return Err(AdvisorError::InvalidRate);
    }

    let mut run_ids = HashSet::new();
    let mut sequences = HashSet::new();
    let mut total_cost = 0.0;
    for observation in &input.observations {
        if !run_ids.insert(observation.run_id) {
            return Err(AdvisorError::DuplicateRun);
        }
        if !sequences.insert(observation.sequence) {
            return Err(AdvisorError::DuplicateSequence);
        }
        if !enabled.contains(&observation.engine)
            || observation.duration_secs == 0
            || !observation.model_cost_usd.is_finite()
            || observation.model_cost_usd < 0.0
        {
            return Err(AdvisorError::InvalidObservation);
        }
        let cost = observation_cost(observation, rates[&observation.engine]);
        total_cost += cost;
        if !cost.is_finite() || cost <= 0.0 || !total_cost.is_finite() {
            return Err(AdvisorError::InvalidObservation);
        }
    }
    Ok(rates)
}

fn observation_cost(observation: &CampaignObservation, hourly_rate: f64) -> f64 {
    (observation.duration_secs as f64 / 3_600.0).mul_add(hourly_rate, observation.model_cost_usd)
}

fn requires_human_approval(action: CampaignAction) -> bool {
    !matches!(action, CampaignAction::Stop)
}

/// Produce deterministic coverage-per-cost advice without performing an action.
///
/// # Errors
/// Returns [`AdvisorError`] when input is malformed, ambiguous, or unbounded.
pub fn advise(input: &CampaignAdviceRequest) -> Result<CampaignAdvice, AdvisorError> {
    let rates = validate(input)?;
    let mut observations = input.observations.clone();
    observations.sort_by_key(|observation| (observation.sequence, observation.run_id));

    let total_cost_usd = observations.iter().fold(0.0, |total, observation| {
        total + observation_cost(observation, rates[&observation.engine])
    });
    let current: Vec<_> = observations
        .iter()
        .filter(|observation| observation.engine == input.current_engine)
        .collect();
    let marginal_edges_per_dollar = current.last().map_or(0.0, |observation| {
        observation.new_edges as f64
            / observation_cost(observation, rates[&observation.engine]).max(f64::EPSILON)
    });
    let mut evidence = vec![format!(
        "{} comparable run(s) cost ${total_cost_usd:.4}",
        observations.len()
    )];

    let action = if total_cost_usd >= input.budget.max_total_cost_usd {
        evidence.push(format!(
            "observed cost reached the ${:.4} budget",
            input.budget.max_total_cost_usd
        ));
        CampaignAction::Stop
    } else if current.len() >= input.budget.plateau_runs
        && current[current.len() - input.budget.plateau_runs..]
            .iter()
            .all(|observation| observation.new_edges == 0)
    {
        evidence.push(format!(
            "coverage plateaued for {} consecutive current-engine run(s)",
            input.budget.plateau_runs
        ));
        let observed_engines: HashSet<_> = observations
            .iter()
            .map(|observation| observation.engine)
            .collect();
        let mut untried: Vec<_> = input
            .enabled_engines
            .iter()
            .copied()
            .filter(|engine| !observed_engines.contains(engine))
            .collect();
        untried.sort_by_key(|engine| engine.as_str());
        if let Some(to) = untried.first().copied() {
            CampaignAction::SwitchEngine {
                from: input.current_engine,
                to,
            }
        } else if current
            .last()
            .is_some_and(|observation| observation.corpus_additions == 0)
        {
            CampaignAction::ImproveCorpus
        } else {
            CampaignAction::ReviewHarness
        }
    } else {
        let mut yields = input
            .enabled_engines
            .iter()
            .copied()
            .filter_map(|engine| {
                let measurements: Vec<_> = observations
                    .iter()
                    .filter(|observation| observation.engine == engine)
                    .collect();
                if measurements.is_empty() {
                    return None;
                }
                let edges: u64 = measurements
                    .iter()
                    .map(|observation| observation.new_edges)
                    .sum();
                let cost = measurements.iter().fold(0.0, |total, observation| {
                    total + observation_cost(observation, rates[&engine])
                });
                Some((engine, edges as f64 / cost.max(f64::EPSILON)))
            })
            .collect::<Vec<_>>();
        yields.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.as_str().cmp(right.0.as_str()))
        });
        let current_yield = yields
            .iter()
            .find(|(engine, _)| *engine == input.current_engine)
            .map_or(0.0, |(_, value)| *value);
        if let Some((best, best_yield)) = yields.first().copied() {
            if best != input.current_engine && best_yield > current_yield * 1.25 {
                evidence.push(format!(
                    "{} yielded {best_yield:.4} edges/$ versus {current_yield:.4} for {}",
                    best.as_str(),
                    input.current_engine.as_str()
                ));
                CampaignAction::SwitchEngine {
                    from: input.current_engine,
                    to: best,
                }
            } else if !current.is_empty()
                && marginal_edges_per_dollar < input.budget.min_edges_per_dollar
            {
                evidence.push(format!(
                    "marginal yield {marginal_edges_per_dollar:.4} edges/$ is below the {:.4} floor",
                    input.budget.min_edges_per_dollar
                ));
                CampaignAction::ImproveCorpus
            } else {
                CampaignAction::Continue {
                    engine: input.current_engine,
                }
            }
        } else {
            evidence.push("no completed campaign measurement is available yet".to_owned());
            CampaignAction::Continue {
                engine: input.current_engine,
            }
        }
    };

    Ok(CampaignAdvice {
        action,
        total_cost_usd,
        marginal_edges_per_dollar,
        evidence,
        requires_human_approval: requires_human_approval(action),
    })
}
