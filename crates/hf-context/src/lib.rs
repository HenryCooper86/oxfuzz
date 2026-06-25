//! hf-context: token-budget-aware prompt assembly.
//!
//! The agent's history can grow past the model's context window. [`assemble`]
//! trims a message list to fit a token budget while preserving order: system
//! messages are always kept, and the most recent non-system turns are kept
//! until the budget is exhausted (oldest dropped first).

use hf_core::types::{Message, Role};

/// Default assembly budget in tokens (leaves headroom under a 128k window).
pub const DEFAULT_BUDGET_TOKENS: usize = 96_000;

/// Estimate the token count of a string. Uses the common ~4-chars-per-token
/// heuristic; deliberately conservative and provider-agnostic.
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
///
/// System messages are always retained. Non-system messages are kept from the
/// most recent backwards until the budget runs out; older ones are dropped. If
/// the system messages alone exceed the budget they are still returned (the
/// caller decides what to do with an over-budget system prompt).
#[must_use]
pub fn assemble(messages: &[Message], max_tokens: usize) -> Vec<Message> {
    let system_tokens: usize = messages
        .iter()
        .filter(|m| matches!(m.role, Role::System))
        .map(|m| estimate_tokens(&m.content))
        .sum();

    let mut budget = max_tokens.saturating_sub(system_tokens);

    // Walk non-system messages newest-first, marking those that fit.
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
        // Older messages are still considered in case they are smaller, keeping
        // as much recent context as the budget allows.
    }

    messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| keep[i])
        .map(|(_, m)| m.clone())
        .collect()
}
