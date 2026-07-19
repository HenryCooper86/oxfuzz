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
    // The newest-window cut above is role-blind, so the first kept non-system
    // message can be an `assistant` or `tool` turn -- which providers reject
    // (Anthropic: "first message must use the user role") and which orphans a
    // tool result from its originating call. Drop any leading non-system kept
    // messages until the first one is a `user` turn.
    for (i, m) in messages.iter().enumerate() {
        if matches!(m.role, Role::System) || !keep[i] {
            continue;
        }
        if matches!(m.role, Role::User) {
            break;
        }
        keep[i] = false;
    }
    messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| keep[i])
        .map(|(_, m)| m.clone())
        .collect()
}

/// Tool results within this many of the newest are kept in full.
pub const KEEP_RECENT_TOOL_RESULTS: usize = 3;
/// Tool results older than this (counting newest-first) are hard-cleared; those
/// between the two thresholds are soft-trimmed to a head+tail excerpt.
pub const HARD_CLEAR_TOOL_RESULTS_AFTER: usize = 10;

/// Chars of head and of tail kept when a tool result is soft-trimmed.
const SOFT_TRIM_KEEP_CHARS: usize = 500;
/// Placeholder a hard-cleared tool result is replaced with.
const HARD_CLEAR_PLACEHOLDER: &str = "[tool result omitted -- superseded by newer output]";

/// Cheaply shrink old tool-result messages in place, with NO model call: the
/// newest [`KEEP_RECENT_TOOL_RESULTS`] are left intact, the next band is
/// soft-trimmed to a head+tail excerpt, and anything older than
/// [`HARD_CLEAR_TOOL_RESULTS_AFTER`] is replaced with a short placeholder.
///
/// Recency is counted over tool results newest-first (one per `ReAct` iteration),
/// not user turns, so a single long agent turn still sheds its stale, high-volume
/// output (fuzzer logs, coverage/crash dumps) while its recent results stay
/// intact. Runs before the expensive LLM compaction and is idempotent -- an
/// already-trimmed result is under the threshold and a cleared one is skipped.
pub fn prune_tool_results_by_age(messages: &mut [Message]) {
    let mut rank = 0usize;
    for message in messages.iter_mut().rev() {
        if message.role != Role::Tool {
            continue;
        }
        if rank >= HARD_CLEAR_TOOL_RESULTS_AFTER {
            if message.content != HARD_CLEAR_PLACEHOLDER {
                HARD_CLEAR_PLACEHOLDER.clone_into(&mut message.content);
            }
        } else if rank >= KEEP_RECENT_TOOL_RESULTS {
            soft_trim_in_place(&mut message.content);
        }
        rank += 1;
    }
}

fn soft_trim_in_place(content: &mut String) {
    let total = content.chars().count();
    // Leave short results alone; this also makes the trim idempotent (a trimmed
    // result is already under the threshold).
    if total <= SOFT_TRIM_KEEP_CHARS * 2 + 80 {
        return;
    }
    let head: String = content.chars().take(SOFT_TRIM_KEEP_CHARS).collect();
    let tail: String = content.chars().skip(total - SOFT_TRIM_KEEP_CHARS).collect();
    let dropped = total - SOFT_TRIM_KEEP_CHARS * 2;
    *content = format!(
        "{head}\n[... {dropped} chars trimmed to fit context; oldest output first ...]\n{tail}"
    );
}

/// A single fresh tool result larger than this is capped to a head+tail excerpt
/// before it enters the conversation, so no one result can blow the budget.
pub const MAX_FRESH_TOOL_RESULT_CHARS: usize = 12_000;
/// Chars of head and of tail kept when capping an oversized fresh tool result.
const FRESH_TOOL_RESULT_KEEP_CHARS: usize = 4_000;

/// If `content` exceeds [`MAX_FRESH_TOOL_RESULT_CHARS`], return a head+tail
/// excerpt (with an omission marker) that bounds its context cost; otherwise
/// `None` (keep it verbatim). This bounds a FRESH result on the iteration it
/// arrives, complementing [`prune_tool_results_by_age`], which shrinks results
/// only once they have aged. Disk-paging the full output for later retrieval is a
/// deferred follow-on -- our file-inspection tools are rooted at the user's
/// project, so there is no scratch area they can both write and read yet.
#[must_use]
pub fn cap_fresh_tool_result(content: &str) -> Option<String> {
    let total = content.chars().count();
    if total <= MAX_FRESH_TOOL_RESULT_CHARS {
        return None;
    }
    let head: String = content.chars().take(FRESH_TOOL_RESULT_KEEP_CHARS).collect();
    let tail: String = content
        .chars()
        .skip(total - FRESH_TOOL_RESULT_KEEP_CHARS)
        .collect();
    let omitted = total - FRESH_TOOL_RESULT_KEEP_CHARS * 2;
    Some(format!(
        "{head}\n[... {omitted} chars omitted: this tool produced a large result; only its head \
         and tail are kept to fit context ...]\n{tail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(content: &str) -> Message {
        Message::new(Role::Tool, content.to_owned())
    }

    #[test]
    fn keeps_recent_tool_results_then_trims_then_clears_older_ones() {
        let big = "x".repeat(4000);
        let mut msgs = vec![Message::system("s"), Message::user("go")];
        for _ in 0..12 {
            msgs.push(Message::new(Role::Assistant, "call".to_owned()));
            msgs.push(tool(&big));
        }
        prune_tool_results_by_age(&mut msgs);

        let tools: Vec<&Message> = msgs.iter().filter(|m| m.role == Role::Tool).collect();
        // tools[11] is newest (rank 0); tools[0] is oldest (rank 11).
        assert_eq!(tools[11].content, big, "newest kept full");
        assert_eq!(tools[9].content, big, "rank 2 kept full");
        assert!(
            tools[8].content.contains("chars trimmed"),
            "rank 3 soft-trimmed"
        );
        assert!(tools[8].content.len() < big.len(), "soft-trim shrank it");
        assert!(tools[1].content.contains("omitted"), "rank 10 hard-cleared");
        assert!(tools[0].content.contains("omitted"), "oldest hard-cleared");
    }

    #[test]
    fn non_tool_messages_are_never_touched() {
        let big = "y".repeat(4000);
        let mut msgs = vec![
            Message::system(big.clone()),
            Message::user(big.clone()),
            Message::new(Role::Assistant, big.clone()),
        ];
        for _ in 0..12 {
            msgs.push(tool("t"));
        }
        prune_tool_results_by_age(&mut msgs);
        assert_eq!(msgs[0].content, big, "system untouched");
        assert_eq!(msgs[1].content, big, "user untouched");
        assert_eq!(msgs[2].content, big, "assistant untouched");
    }

    #[test]
    fn small_fresh_results_are_kept_verbatim() {
        assert!(cap_fresh_tool_result("small result").is_none());
        assert!(cap_fresh_tool_result(&"x".repeat(MAX_FRESH_TOOL_RESULT_CHARS)).is_none());
    }

    #[test]
    fn a_large_fresh_result_is_capped_to_head_and_tail() {
        let big = format!("HEAD{}TAIL", "x".repeat(MAX_FRESH_TOOL_RESULT_CHARS));
        let capped = cap_fresh_tool_result(&big).expect("an over-threshold result is capped");
        assert!(
            capped.chars().count() < big.chars().count(),
            "capping shrinks it"
        );
        assert!(capped.contains("chars omitted"), "marks the omission");
        assert!(capped.starts_with("HEAD"), "keeps the head");
        assert!(capped.ends_with("TAIL"), "keeps the tail");
    }

    #[test]
    fn pruning_is_idempotent() {
        let big = "z".repeat(8000);
        let mut once = vec![Message::user("go")];
        for _ in 0..12 {
            once.push(tool(&big));
        }
        let mut twice = once.clone();
        prune_tool_results_by_age(&mut once);
        prune_tool_results_by_age(&mut twice);
        prune_tool_results_by_age(&mut twice);
        let once_c: Vec<&str> = once.iter().map(|m| m.content.as_str()).collect();
        let twice_c: Vec<&str> = twice.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(once_c, twice_c, "a second pass changes nothing");
    }

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

    #[test]
    fn assemble_never_starts_with_a_non_user_message() {
        // A window whose newest turns are (assistant, tool) -- e.g. a big tool
        // result -- must not be sent with the user turn trimmed away: providers
        // reject a leading assistant/tool message. The leading non-user turns are
        // dropped until the first kept non-system message is a user turn.
        let sys = Message::system("sys");
        let user = Message::user("do the thing");
        let assistant = Message::new(Role::Assistant, "calling a tool".to_owned());
        let tool = Message::new(Role::Tool, "z".repeat(4000)); // huge tool result
        let msgs = vec![sys.clone(), user, assistant, tool];

        // Budget fits only the newest ~1000-token tool message, so the role-blind
        // cut would keep [sys, tool] and start with a tool turn.
        let kept = assemble(&msgs, 1200);
        let first_non_system = kept.iter().find(|m| m.role != Role::System);
        // Either the first non-system message is a user turn, or the window
        // collapsed to system-only -- never a leading assistant/tool.
        assert!(
            first_non_system.is_none_or(|m| m.role == Role::User),
            "assembled window must not start with a non-user message: {:?}",
            first_non_system.map(|m| m.role),
        );
    }
}
