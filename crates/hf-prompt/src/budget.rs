//! Token budget enforcement for prompt sections.

/// Estimate the number of tokens in a text string.
///
/// Uses the heuristic: 1 token per 4 bytes of UTF-8 text, matching the
/// estimators in `hf-context` and `hf-core` so budgets are enforced
/// consistently across crates (a chars/4 count would under-estimate
/// multibyte text ~3x). The default provides a reasonable estimate
/// that is within 10% for English text.
pub fn estimate_tokens(text: &str) -> u32 {
    let tokens = text.len().div_ceil(4);
    u32::try_from(tokens).unwrap_or(u32::MAX)
}

/// Truncate text to fit within a token budget.
///
/// Returns the (possibly truncated) text and whether truncation occurred.
/// If truncated, appends a `[truncated]` marker.
pub fn truncate_to_budget(text: &str, max_tokens: u32) -> (String, bool) {
    let current = estimate_tokens(text);
    if current <= max_tokens {
        return (text.to_string(), false);
    }

    let marker = "\n[truncated]";
    let byte_limit = usize::try_from(max_tokens)
        .unwrap_or(usize::MAX)
        .saturating_mul(4);
    let marker_bytes = marker.len();

    if byte_limit == 0 || byte_limit < marker_bytes {
        return (String::new(), true);
    }

    let effective_limit = byte_limit.saturating_sub(marker_bytes);

    // Truncate at a char boundary so multibyte text stays valid UTF-8.
    let truncated = if effective_limit >= text.len() {
        text.to_string()
    } else {
        let mut boundary = effective_limit;
        while boundary > 0 && !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        format!("{}{marker}", &text[..boundary])
    };

    (truncated, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_tokens_simple() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1); // 1 char → ceil(1/4) = 1
        assert_eq!(estimate_tokens("abcd"), 1); // 4 chars → 1 token
        assert_eq!(estimate_tokens("abcde"), 2); // 5 chars → ceil(5/4) = 2
    }

    #[test]
    fn test_estimate_tokens_longer() {
        // 100 chars → 25 tokens.
        let text = "a".repeat(100);
        assert_eq!(estimate_tokens(&text), 25);
    }

    #[test]
    fn test_estimate_tokens_counts_multibyte_as_bytes() {
        // Byte-length/4 heuristic, matching the hf-context and hf-core
        // estimators: multibyte text must not be under-estimated (chars/4
        // would report ~3x fewer tokens for CJK text).
        let text = "你好你好"; // 4 chars, 12 UTF-8 bytes
        assert_eq!(estimate_tokens(text), 3);
        assert_eq!(
            estimate_tokens(text),
            u32::try_from(text.len() / 4).unwrap()
        );
        let heavy = "你好世界".repeat(25); // 300 bytes
        assert_eq!(
            estimate_tokens(&heavy),
            u32::try_from(heavy.len() / 4).unwrap()
        );
    }

    #[test]
    fn test_truncate_within_budget() {
        let text = "Hello, world!"; // 13 chars → ~4 tokens.
        let (result, truncated) = truncate_to_budget(text, 10);
        assert_eq!(result, text);
        assert!(!truncated);
    }

    #[test]
    fn test_truncate_exceeds_budget() {
        let text = "a".repeat(200); // 200 chars → 50 tokens.
        let (result, truncated) = truncate_to_budget(&text, 10);
        assert!(truncated);
        assert!(result.ends_with("[truncated]"));
        // Result should be within ~10 tokens worth of characters + marker.
        assert!(result.len() < 60);
    }

    #[test]
    fn test_truncate_zero_budget() {
        let text = "Some content here.";
        let (result, truncated) = truncate_to_budget(text, 0);
        assert!(truncated);
        assert!(result.is_empty());
    }

    #[test]
    fn test_truncate_result_stays_within_budget() {
        let text = "a".repeat(200); // 50 tokens.
        let (result, truncated) = truncate_to_budget(&text, 2);
        assert!(truncated);
        assert!(estimate_tokens(&result) <= 2);
    }

    #[test]
    fn test_truncate_multibyte_text_stays_within_budget() {
        let text = "你好".repeat(100);
        let (result, truncated) = truncate_to_budget(&text, 10);
        assert!(truncated);
        assert!(estimate_tokens(&result) <= 10);
    }
}
