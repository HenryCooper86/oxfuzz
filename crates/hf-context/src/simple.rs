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
/// System messages are always retained; the remaining non-system messages are
/// kept as a contiguous newest window.
///
/// Once a non-system message does not fit, no older non-system message is
/// retained. This prevents dropping a newer message (e.g. the user's current
/// query) while keeping an older, smaller one -- which would both lose the live
/// turn and risk orphaning a tool result from its originating call.
#[must_use]
pub fn assemble(messages: &[Message], max_tokens: usize) -> Vec<Message> {
    let system_tokens: usize = messages
        .iter()
        .filter(|m| matches!(m.role, Role::System))
        .map(|m| estimate_tokens(&m.content))
        .sum();
    let mut budget = max_tokens.saturating_sub(system_tokens);
    let mut keep = vec![false; messages.len()];
    let mut window_closed = false;
    for (i, m) in messages.iter().enumerate().rev() {
        if matches!(m.role, Role::System) {
            keep[i] = true;
            continue;
        }
        if window_closed {
            continue;
        }
        let cost = estimate_tokens(&m.content);
        if cost <= budget {
            budget -= cost;
            keep[i] = true;
        } else {
            // Stop extending the window to older messages.
            window_closed = true;
        }
    }
    messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| keep[i])
        .map(|(_, m)| m.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_keeps_a_contiguous_newest_window() {
        // ~10, ~100, ~10 tokens respectively (len/4).
        let oldest = Message::user("o".repeat(40));
        let middle = Message::user("m".repeat(400));
        let newest = Message::user("n".repeat(40));
        let msgs = vec![oldest, middle, newest.clone()];

        // Budget fits the newest (10) but not the middle (100). The oldest must
        // NOT be resurrected past the dropped middle -- the old code kept the
        // oldest, yielding a non-contiguous window that dropped a newer message.
        let kept = assemble(&msgs, 40);
        assert_eq!(kept.len(), 1, "expected only the newest message");
        assert_eq!(kept[0].content, newest.content);
    }

    #[test]
    fn assemble_always_retains_system_messages() {
        let sys = Message::system("s".repeat(40));
        let huge = Message::user("u".repeat(4000));
        let kept = assemble(&[sys.clone(), huge], 5);
        assert!(kept
            .iter()
            .any(|m| m.role == Role::System && m.content == sys.content));
    }
}
