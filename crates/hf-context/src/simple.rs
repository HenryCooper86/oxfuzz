//! Lightweight token-budget assembly (hobot's original API), kept so the agent
//! loop's simple trimming keeps working alongside the ported y-agent pipeline.

use hf_core::types::{Message, Role};

/// Default assembly budget in tokens (leaves headroom under a 128k window).
pub const DEFAULT_BUDGET_TOKENS: usize = 96_000;

/// Estimate the token count of a string (~4 chars/token heuristic).
#[must_use]
pub fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

/// Total estimated tokens across a message slice.
#[must_use]
pub fn total_tokens(messages: &[Message]) -> usize {
    messages.iter().map(|m| estimate_tokens(&m.content)).sum()
}

/// Trim `messages` to fit within `max_tokens`, preserving original order.
/// System messages are always retained; non-system kept newest-first.
#[must_use]
pub fn assemble(messages: &[Message], max_tokens: usize) -> Vec<Message> {
    let system_tokens: usize = messages
        .iter()
        .filter(|m| matches!(m.role, Role::System))
        .map(|m| estimate_tokens(&m.content))
        .sum();
    let mut budget = max_tokens.saturating_sub(system_tokens);
    let mut keep = vec![false; messages.len()];
    for (i, m) in messages.iter().enumerate().rev() {
        if matches!(m.role, Role::System) {
            keep[i] = true;
            continue;
        }
        let cost = estimate_tokens(&m.content);
        if cost <= budget {
            budget -= cost;
            keep[i] = true;
        }
    }
    messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| keep[i])
        .map(|(_, m)| m.clone())
        .collect()
}
