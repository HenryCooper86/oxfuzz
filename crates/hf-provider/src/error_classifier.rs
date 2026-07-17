//! Error classifier: normalizes provider errors into a `StandardError` enum.
//!
//! Design reference: providers-design.md §Error Classification
//!
//! The classifier examines HTTP status codes and error body content to
//! categorize provider failures into standard types. These standard errors
//! drive freeze duration decisions, alerting, and retry strategies.

use std::time::Duration;

/// Standardized error classification for provider failures.
///
/// All provider-specific errors are normalized to one of these variants,
/// which then drive the freeze/retry logic in the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
    /// Context window exceeded (too many tokens).
    ContextWindowExceeded,
    /// Rate limited by the provider.
    RateLimited {
        /// Suggested retry delay from the provider (Retry-After header).
        retry_after: Option<Duration>,
    },
    /// API quota or billing limit exhausted.
    QuotaExhausted,
    /// Authentication failed (invalid credentials format, etc.).
    AuthenticationFailed,
    /// API key is invalid or revoked.
    KeyInvalid,
    /// Account has insufficient balance/credits.
    InsufficientBalance,
    /// Requested model does not exist or is not accessible.
    ModelNotFound,
    /// Server-side error (5xx).
    ServerError,
    /// Network connectivity issue.
    NetworkError,
    /// Content was filtered by the provider's safety system.
    ContentFiltered,
    /// Unclassified error.
    Unknown,
}

impl StandardError {
    /// Recommended freeze duration for this error type.
    ///
    /// Returns `None` for errors that should cause permanent freeze
    /// (requiring manual intervention).
    ///
    /// These are *upper bounds*: the pool clamps every returned duration to the
    /// configured `max_freeze_duration_secs` (default 1h), so with the default
    /// cap the longer values below (auth failure, model-not-found) freeze for at
    /// most 1h before the provider is retried. `AuthenticationFailed` is
    /// deliberately transient (a 401 that is not an outright invalid key, e.g. a
    /// clock-skew or token-service blip): it backs off long, then retries,
    /// rather than freezing permanently like [`KeyInvalid`](Self::KeyInvalid).
    pub fn freeze_duration(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => {
                Some(retry_after.unwrap_or(Duration::from_mins(1)))
            }
            Self::ServerError => Some(Duration::from_mins(5)),
            Self::NetworkError => Some(Duration::from_secs(30)),
            Self::ModelNotFound => Some(Duration::from_hours(1)),
            // Long backoff, clamped to max_freeze_duration_secs by the pool.
            Self::AuthenticationFailed => Some(Duration::from_hours(24)),
            Self::Unknown => Some(Duration::from_mins(1)),
            // Not a provider issue (context window, content filter) — don't freeze.
            // Permanent errors (key invalid, quota, balance) — freeze duration
            // is effectively infinite, handled by freeze_permanent().
            Self::ContextWindowExceeded
            | Self::ContentFiltered
            | Self::KeyInvalid
            | Self::QuotaExhausted
            | Self::InsufficientBalance => None,
        }
    }

    /// Whether this error should cause a permanent freeze (no auto-thaw).
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::KeyInvalid | Self::QuotaExhausted | Self::InsufficientBalance
        )
    }

    /// Whether this error is a transient provider issue (freeze + retry).
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError | Self::NetworkError | Self::Unknown
        )
    }

    /// Whether this error should NOT cause a provider freeze.
    ///
    /// Some errors (context window, content filter) are request-specific
    /// and don't indicate a provider problem, so they never freeze. Network
    /// errors, by contrast, are transient provider issues ([`is_transient`])
    /// with a defined [`freeze_duration`] (30s): they freeze briefly so the
    /// pool fails over instead of hammering an unreachable provider.
    ///
    /// [`is_transient`]: Self::is_transient
    /// [`freeze_duration`]: Self::freeze_duration
    pub fn should_freeze(&self) -> bool {
        !matches!(self, Self::ContextWindowExceeded | Self::ContentFiltered)
    }
}

/// Classify a provider error from HTTP status code and response body.
///
/// This function examines the status code first, then falls back to
/// regex-like pattern matching on the error body for more specific
/// classification.
pub fn classify(status: u16, body: &str) -> StandardError {
    // 1. Status-code based classification.
    match status {
        401 => classify_auth_error(body),
        403 => classify_forbidden_error(body),
        429 => StandardError::RateLimited { retry_after: None },
        404 => {
            if body_contains_any(body, &["model", "not found", "does not exist"]) {
                StandardError::ModelNotFound
            } else {
                StandardError::Unknown
            }
        }
        400 => classify_bad_request(body),
        500..=599 => StandardError::ServerError,
        0 => StandardError::NetworkError, // Status 0 indicates network failure.
        _ => classify_from_body(body),
    }
}

/// Classify a provider error from a `ProviderError` enum.
///
/// This provides a bridge from the existing `ProviderError` type to
/// the new `StandardError` classification.
pub fn classify_provider_error(error: &hf_core::provider::ProviderError) -> StandardError {
    use hf_core::provider::ProviderError;
    match error {
        ProviderError::RateLimited {
            retry_after_secs, ..
        } => StandardError::RateLimited {
            retry_after: Some(Duration::from_secs(*retry_after_secs)),
        },
        ProviderError::QuotaExhausted { .. } => StandardError::QuotaExhausted,
        ProviderError::AuthenticationFailed { .. } => StandardError::AuthenticationFailed,
        ProviderError::KeyInvalid { .. } => StandardError::KeyInvalid,
        ProviderError::ServerError { message, .. } => {
            classify_http_message(message).unwrap_or_else(|| {
                // Fallback for messages without the `HTTP {status}:` prefix:
                // sub-classify server errors from the body alone.
                if message.contains("context") && message.contains("length") {
                    StandardError::ContextWindowExceeded
                } else {
                    StandardError::ServerError
                }
            })
        }
        ProviderError::NetworkError { .. } => StandardError::NetworkError,
        ProviderError::NoProviderAvailable { .. }
        | ProviderError::Cancelled
        | ProviderError::ParseError { .. } => StandardError::Unknown,
        ProviderError::Other { message } => {
            classify_http_message(message).unwrap_or_else(|| classify_from_body(message))
        }
    }
}

/// Recover a status-aware classification from a provider HTTP failure message
/// of the form `HTTP {status}: {body}` (`{status}` may carry a canonical
/// reason phrase, e.g. `400 Bad Request`).
///
/// Returns `None` when the message does not carry a parseable status, so the
/// caller can fall back to body-only classification.
fn classify_http_message(message: &str) -> Option<StandardError> {
    let rest = message.strip_prefix("HTTP ")?;
    let digit_len = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let status: u16 = rest[..digit_len].parse().ok()?;
    Some(classify(status, rest))
}

/// Build a [`ProviderError`] for an authentication-class HTTP failure (401/403),
/// sub-classifying the response body so a permanently-dead key or an exhausted
/// account reaches a permanent freeze instead of an hourly auth backoff.
///
/// Reuses [`classify_auth_error`]/[`classify_forbidden_error`] rather than
/// duplicating the substring lists:
/// - a revoked / invalid / expired / deactivated key maps to
///   [`ProviderError::KeyInvalid`] (permanent);
/// - an insufficient balance or exhausted quota maps to
///   [`ProviderError::QuotaExhausted`] (permanent — `ProviderError` has no
///   dedicated `InsufficientBalance` variant, so quota/balance collapse onto it);
/// - anything else stays [`ProviderError::AuthenticationFailed`] (transient).
///
/// The dead-key signal can appear under either a 401 or a 403, so the body is
/// the source of truth here and the status code is not needed.
///
/// [`ProviderError`]: hf_core::provider::ProviderError
/// [`ProviderError::KeyInvalid`]: hf_core::provider::ProviderError::KeyInvalid
/// [`ProviderError::QuotaExhausted`]: hf_core::provider::ProviderError::QuotaExhausted
/// [`ProviderError::AuthenticationFailed`]: hf_core::provider::ProviderError::AuthenticationFailed
pub(crate) fn auth_failure_to_provider_error(
    provider_id: &str,
    body: &str,
) -> hf_core::provider::ProviderError {
    use hf_core::provider::ProviderError;
    // Check the key-death signal first (401 rules), then fall back to the
    // quota/balance signal (403 rules); either can appear on either status.
    let classified = match classify_auth_error(body) {
        StandardError::KeyInvalid => StandardError::KeyInvalid,
        _ => classify_forbidden_error(body),
    };
    match classified {
        StandardError::KeyInvalid => ProviderError::KeyInvalid {
            provider: provider_id.to_string(),
            message: body.to_string(),
        },
        StandardError::QuotaExhausted | StandardError::InsufficientBalance => {
            ProviderError::QuotaExhausted {
                provider: provider_id.to_string(),
                message: body.to_string(),
            }
        }
        _ => ProviderError::AuthenticationFailed {
            provider: provider_id.to_string(),
            message: body.to_string(),
        },
    }
}

/// Build a [`ProviderError`] for a generic HTTP failure (anything not already
/// handled as rate-limit/auth/billing by the caller), routing the status code
/// and response body through the status-aware [`classify`] so request-specific
/// errors — most importantly a context-window 400 — do not masquerade as
/// server errors and freeze the provider.
///
/// Sub-classifications with a dedicated [`ProviderError`] variant map onto it
/// directly. The rest (`ContextWindowExceeded`, `ContentFiltered`,
/// `ModelNotFound`, `ServerError`, `Unknown`) keep the
/// `HTTP {status}: {body}` message shape so [`classify_provider_error`]
/// recovers the same sub-classification when the pool decides whether to
/// freeze.
///
/// [`ProviderError`]: hf_core::provider::ProviderError
pub(crate) fn http_failure_to_provider_error(
    provider_id: &str,
    status: u16,
    body: &str,
) -> hf_core::provider::ProviderError {
    use hf_core::provider::ProviderError;
    let message = format!("HTTP {status}: {body}");
    match classify(status, body) {
        StandardError::RateLimited { retry_after } => ProviderError::RateLimited {
            provider: provider_id.to_string(),
            retry_after_secs: retry_after.map_or(60, |d| d.as_secs()),
        },
        StandardError::KeyInvalid => ProviderError::KeyInvalid {
            provider: provider_id.to_string(),
            message,
        },
        StandardError::QuotaExhausted | StandardError::InsufficientBalance => {
            ProviderError::QuotaExhausted {
                provider: provider_id.to_string(),
                message,
            }
        }
        StandardError::AuthenticationFailed => ProviderError::AuthenticationFailed {
            provider: provider_id.to_string(),
            message,
        },
        StandardError::NetworkError => ProviderError::NetworkError { message },
        _ => ProviderError::ServerError {
            provider: provider_id.to_string(),
            message,
        },
    }
}

// ---------------------------------------------------------------------------
// Internal classification helpers
// ---------------------------------------------------------------------------

fn classify_auth_error(body: &str) -> StandardError {
    let lower = body.to_lowercase();
    if (lower.contains("invalid") && lower.contains("key"))
        || lower.contains("expired")
        || lower.contains("revoked")
        || lower.contains("deactivated")
    {
        StandardError::KeyInvalid
    } else {
        StandardError::AuthenticationFailed
    }
}

fn classify_forbidden_error(body: &str) -> StandardError {
    let lower = body.to_lowercase();
    if lower.contains("quota") || (lower.contains("exceeded") && lower.contains("limit")) {
        StandardError::QuotaExhausted
    } else if lower.contains("balance")
        || lower.contains("insufficient")
        || lower.contains("billing")
        || lower.contains("payment")
    {
        StandardError::InsufficientBalance
    } else {
        StandardError::AuthenticationFailed
    }
}

fn classify_bad_request(body: &str) -> StandardError {
    let lower = body.to_lowercase();
    if (lower.contains("context") && (lower.contains("length") || lower.contains("window")))
        || (lower.contains("maximum") && lower.contains("token"))
    {
        StandardError::ContextWindowExceeded
    } else if lower.contains("content_filter") || lower.contains("content filter") {
        StandardError::ContentFiltered
    } else if lower.contains("model") && lower.contains("not") {
        StandardError::ModelNotFound
    } else {
        StandardError::Unknown
    }
}

fn classify_from_body(body: &str) -> StandardError {
    let lower = body.to_lowercase();
    if lower.contains("rate limit") || lower.contains("rate_limit") {
        StandardError::RateLimited { retry_after: None }
    } else if lower.contains("quota") || (lower.contains("exceeded") && lower.contains("limit")) {
        StandardError::QuotaExhausted
    } else if lower.contains("invalid api key") || lower.contains("invalid_api_key") {
        StandardError::KeyInvalid
    } else if lower.contains("insufficient") && lower.contains("balance") {
        StandardError::InsufficientBalance
    } else if lower.contains("context") && lower.contains("length") {
        StandardError::ContextWindowExceeded
    } else if lower.contains("content_filter") || lower.contains("content filter") {
        StandardError::ContentFiltered
    } else {
        StandardError::Unknown
    }
}

/// Check if body contains any of the given substrings (case-insensitive).
fn body_contains_any(body: &str, patterns: &[&str]) -> bool {
    let lower = body.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Status-code based classification
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_rate_limited() {
        let err = classify(429, "rate limit exceeded");
        assert_eq!(err, StandardError::RateLimited { retry_after: None });
    }

    #[test]
    fn test_classify_auth_failed() {
        let err = classify(401, "unauthorized");
        assert_eq!(err, StandardError::AuthenticationFailed);
    }

    #[test]
    fn test_classify_invalid_key() {
        let err = classify(401, "Invalid API key provided");
        assert_eq!(err, StandardError::KeyInvalid);
    }

    #[test]
    fn test_classify_quota_exhausted() {
        let err = classify(403, "quota exceeded");
        assert_eq!(err, StandardError::QuotaExhausted);
    }

    #[test]
    fn test_classify_insufficient_balance() {
        let err = classify(403, "insufficient balance");
        assert_eq!(err, StandardError::InsufficientBalance);
    }

    #[test]
    fn test_classify_billing_issue() {
        let err = classify(403, "billing hard limit reached, payment required");
        assert_eq!(err, StandardError::InsufficientBalance);
    }

    #[test]
    fn test_classify_model_not_found() {
        let err = classify(404, "The model gpt-5 does not exist");
        assert_eq!(err, StandardError::ModelNotFound);
    }

    #[test]
    fn test_classify_context_window_exceeded() {
        let err = classify(400, "maximum context length exceeded");
        assert_eq!(err, StandardError::ContextWindowExceeded);
    }

    #[test]
    fn test_classify_context_token_limit() {
        let err = classify(400, "maximum token limit reached");
        assert_eq!(err, StandardError::ContextWindowExceeded);
    }

    #[test]
    fn test_classify_content_filtered() {
        let err = classify(400, "content_filter triggered");
        assert_eq!(err, StandardError::ContentFiltered);
    }

    #[test]
    fn test_classify_server_error() {
        let err = classify(500, "internal server error");
        assert_eq!(err, StandardError::ServerError);
    }

    #[test]
    fn test_classify_bad_gateway() {
        let err = classify(502, "Bad Gateway");
        assert_eq!(err, StandardError::ServerError);
    }

    #[test]
    fn test_classify_network_error() {
        let err = classify(0, "connection refused");
        assert_eq!(err, StandardError::NetworkError);
    }

    #[test]
    fn test_classify_unknown_status() {
        let err = classify(418, "I'm a teapot");
        assert_eq!(err, StandardError::Unknown);
    }

    // -----------------------------------------------------------------------
    // ProviderError bridge
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_provider_error_rate_limited() {
        use hf_core::provider::ProviderError;
        let err = ProviderError::RateLimited {
            provider: "test".into(),
            retry_after_secs: 120,
        };
        let std_err = classify_provider_error(&err);
        assert_eq!(
            std_err,
            StandardError::RateLimited {
                retry_after: Some(Duration::from_mins(2))
            }
        );
    }

    #[test]
    fn test_classify_provider_error_key_invalid() {
        use hf_core::provider::ProviderError;
        let err = ProviderError::KeyInvalid {
            provider: "test".into(),
            message: String::new(),
        };
        assert_eq!(classify_provider_error(&err), StandardError::KeyInvalid);
    }

    // -----------------------------------------------------------------------
    // Auth-failure -> ProviderError sub-classification (dead-key permanent path)
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_key_401_body_yields_permanent_freeze() {
        // A 401 whose body names an invalid key must escalate to KeyInvalid so
        // the pool freezes the provider permanently (no auto-thaw -> retry loop).
        let err = auth_failure_to_provider_error("openai", "Invalid API key provided");
        assert!(matches!(
            err,
            hf_core::provider::ProviderError::KeyInvalid { .. }
        ));
        assert!(classify_provider_error(&err).is_permanent());
    }

    #[test]
    fn generic_401_body_stays_transient() {
        // A generic 401 (e.g. a token-service blip) must remain a transient
        // AuthenticationFailed so the provider is retried after a backoff.
        let err = auth_failure_to_provider_error("openai", "unauthorized");
        assert!(matches!(
            err,
            hf_core::provider::ProviderError::AuthenticationFailed { .. }
        ));
        let std_err = classify_provider_error(&err);
        assert!(!std_err.is_permanent());
        assert!(std_err.is_transient() || std_err == StandardError::AuthenticationFailed);
    }

    #[test]
    fn revoked_and_deactivated_keys_are_permanent() {
        for body in [
            "API key revoked",
            "this key has expired",
            "account deactivated",
        ] {
            let err = auth_failure_to_provider_error("p", body);
            assert!(
                matches!(err, hf_core::provider::ProviderError::KeyInvalid { .. }),
                "expected KeyInvalid for body {body:?}"
            );
        }
    }

    #[test]
    fn insufficient_balance_or_quota_maps_to_permanent_quota() {
        for body in [
            "insufficient balance",
            "insufficient_quota",
            "billing hard limit reached",
        ] {
            let err = auth_failure_to_provider_error("p", body);
            assert!(
                matches!(err, hf_core::provider::ProviderError::QuotaExhausted { .. }),
                "expected QuotaExhausted for body {body:?}"
            );
            assert!(classify_provider_error(&err).is_permanent());
        }
    }

    #[test]
    fn test_classify_provider_error_network() {
        use hf_core::provider::ProviderError;
        let err = ProviderError::NetworkError {
            message: "connection reset".into(),
        };
        assert_eq!(classify_provider_error(&err), StandardError::NetworkError);
    }

    // -----------------------------------------------------------------------
    // Generic HTTP-failure mapping (status-aware, non-freezing 4xx)
    // -----------------------------------------------------------------------

    #[test]
    fn anthropic_prompt_too_long_400_does_not_freeze() {
        // Anthropic rejects an over-long prompt with HTTP 400 and a body that
        // mentions neither "context" nor "length"; the request-specific error
        // must not freeze the provider as a server error.
        let err = http_failure_to_provider_error(
            "anthropic",
            400,
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 200001 tokens > 199999 maximum"}}"#,
        );
        let std_err = classify_provider_error(&err);
        assert_eq!(std_err, StandardError::ContextWindowExceeded);
        assert!(!std_err.should_freeze());
        assert_eq!(std_err.freeze_duration(), None);
    }

    #[test]
    fn generic_500_still_freezes_as_server_error() {
        use hf_core::provider::ProviderError;
        let err = http_failure_to_provider_error("openai", 500, "internal server error");
        assert!(matches!(err, ProviderError::ServerError { .. }));
        let std_err = classify_provider_error(&err);
        assert_eq!(std_err, StandardError::ServerError);
        assert!(std_err.should_freeze());
    }

    #[test]
    fn classify_provider_error_recovers_status_from_http_message() {
        // Providers format generic HTTP failures as `HTTP {status}: {body}`
        // (the status may carry a canonical reason phrase); the classifier must
        // use the recovered status instead of body-only sniffing.
        use hf_core::provider::ProviderError;
        let err = ProviderError::ServerError {
            provider: "anthropic".into(),
            message: "HTTP 400 Bad Request: prompt is too long: 200001 tokens > 199999 maximum"
                .into(),
        };
        assert_eq!(
            classify_provider_error(&err),
            StandardError::ContextWindowExceeded
        );
    }

    #[test]
    fn server_error_without_http_prefix_stays_server_error() {
        use hf_core::provider::ProviderError;
        let err = ProviderError::ServerError {
            provider: "mock".into(),
            message: "mock failure".into(),
        };
        assert_eq!(classify_provider_error(&err), StandardError::ServerError);
    }

    // -----------------------------------------------------------------------
    // Freeze behavior
    // -----------------------------------------------------------------------

    #[test]
    fn test_permanent_errors() {
        assert!(StandardError::KeyInvalid.is_permanent());
        assert!(StandardError::QuotaExhausted.is_permanent());
        assert!(StandardError::InsufficientBalance.is_permanent());
        assert!(!StandardError::RateLimited { retry_after: None }.is_permanent());
        assert!(!StandardError::ServerError.is_permanent());
    }

    #[test]
    fn test_transient_errors() {
        assert!(StandardError::RateLimited { retry_after: None }.is_transient());
        assert!(StandardError::ServerError.is_transient());
        assert!(StandardError::NetworkError.is_transient());
        assert!(!StandardError::KeyInvalid.is_transient());
    }

    #[test]
    fn test_should_freeze() {
        assert!(!StandardError::ContextWindowExceeded.should_freeze());
        assert!(!StandardError::ContentFiltered.should_freeze());
        assert!(StandardError::RateLimited { retry_after: None }.should_freeze());
        assert!(StandardError::KeyInvalid.should_freeze());
        // Network errors are transient with a 30s freeze duration, so they must
        // freeze (enabling failover) rather than being excluded.
        assert!(StandardError::NetworkError.should_freeze());
        assert!(StandardError::NetworkError.is_transient());
        assert_eq!(
            StandardError::NetworkError.freeze_duration(),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn test_freeze_durations() {
        // Rate limited: default 60s.
        let rl = StandardError::RateLimited { retry_after: None };
        assert_eq!(rl.freeze_duration(), Some(Duration::from_mins(1)));

        // Rate limited with custom retry-after.
        let rl_custom = StandardError::RateLimited {
            retry_after: Some(Duration::from_mins(2)),
        };
        assert_eq!(rl_custom.freeze_duration(), Some(Duration::from_mins(2)));

        // Server error: 5min.
        assert_eq!(
            StandardError::ServerError.freeze_duration(),
            Some(Duration::from_mins(5))
        );

        // Auth: 24h.
        assert_eq!(
            StandardError::AuthenticationFailed.freeze_duration(),
            Some(Duration::from_hours(24))
        );

        // Key invalid: permanent (None).
        assert_eq!(StandardError::KeyInvalid.freeze_duration(), None);

        // Quota: permanent (None).
        assert_eq!(StandardError::QuotaExhausted.freeze_duration(), None);

        // Context window: no freeze (None).
        assert_eq!(StandardError::ContextWindowExceeded.freeze_duration(), None);
    }
}
