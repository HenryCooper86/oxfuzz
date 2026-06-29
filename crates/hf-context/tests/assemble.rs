//! Tests for token-budget context assembly.

use hf_context::{assemble, estimate_tokens, total_tokens};
use hf_core::types::{Message, Role};

fn msg(role: Role, content: &str) -> Message {
    Message::new(role, content)
}

#[test]
fn estimate_is_roughly_chars_over_four() {
    assert_eq!(estimate_tokens(""), 0);
    assert_eq!(estimate_tokens("abcd"), 1);
    assert_eq!(estimate_tokens("abcde"), 2);
}

#[test]
fn keeps_system_and_recent_drops_oldest() {
    // ~4 tokens each (16 chars). Budget allows system + ~2 turns.
    let messages = vec![
        msg(Role::System, "you are the system prompt here!!"), // ~8 tokens
        msg(Role::User, "oldest user message 16char"),
        msg(Role::Assistant, "old assistant reply  16ch"),
        msg(Role::User, "recent user message here!"),
        msg(Role::Assistant, "newest assistant reply!!!"),
    ];
    let sys = estimate_tokens(&messages[0].content);
    // Budget: system + the two newest non-system messages.
    let budget =
        sys + estimate_tokens(&messages[3].content) + estimate_tokens(&messages[4].content);

    let out = assemble(&messages, budget);

    // System always kept.
    assert!(matches!(out[0].role, Role::System));
    // The two newest non-system are present; the two oldest are dropped.
    assert!(out.iter().any(|m| m.content == "recent user message here!"));
    assert!(out.iter().any(|m| m.content == "newest assistant reply!!!"));
    assert!(!out
        .iter()
        .any(|m| m.content == "oldest user message 16char"));
    // Order is preserved (system first, then chronological).
    assert!(total_tokens(&out) <= budget);
}

#[test]
fn over_budget_system_still_returned() {
    let messages = vec![msg(Role::System, "a very long system prompt that exceeds")];
    let out = assemble(&messages, 1);
    assert_eq!(out.len(), 1);
}
