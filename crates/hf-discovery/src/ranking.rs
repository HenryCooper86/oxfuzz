//! LLM-assisted ranking of discovered targets.

use hf_core::error::ClassifiedError;
use hf_core::provider::LlmProvider;
use hf_core::target::TargetInventory;
use hf_core::types::{Message, Role};
use hf_prompt::render_discovery_prompt;
use serde::Deserialize;

/// Refine target fit scores and rationale using an LLM.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails. Invalid JSON from the
/// LLM is tolerated: candidates keep their heuristic scores.
pub async fn rank(
    mut inventory: TargetInventory,
    llm: Box<dyn LlmProvider>,
) -> Result<TargetInventory, ClassifiedError> {
    let prompt = render_discovery_prompt(&inventory.candidates);
    let messages = vec![Message {
        role: Role::User,
        content: prompt,
    }];
    let resp = llm.complete(messages).await?;
    let updates: Vec<RankUpdate> = match serde_json::from_str(&resp.content) {
        Ok(v) => v,
        Err(_) => {
            // LLM returned non-JSON; keep heuristic scores.
            return Ok(inventory);
        }
    };
    for update in updates {
        if let Some(c) = inventory
            .candidates
            .iter_mut()
            .find(|c| c.symbol == update.symbol)
        {
            if (0.0..=1.0).contains(&update.fit_score) {
                c.fit_score = update.fit_score;
            }
            if !update.rationale.is_empty() {
                c.rationale = update.rationale;
            }
        }
    }
    // Sort by fit score descending.
    inventory.candidates.sort_by(|a, b| {
        b.fit_score
            .partial_cmp(&a.fit_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(inventory)
}

#[derive(Debug, Deserialize)]
struct RankUpdate {
    symbol: String,
    fit_score: f64,
    rationale: String,
}
