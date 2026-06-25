//! Classify a failed completion into a retry/failover decision.
//!
//! A single provider blip (a 429, a 5xx, a dropped connection) must not kill an
//! in-flight fuzzing campaign. The pool reacts to a failed `complete()` by
//! classifying the error here, then freezing the offending provider and failing
//! over to the next candidate.
//!
//! This is a pragmatic adaptation of y-agent's `error_classifier`: rather than a
//! full `StandardError` taxonomy, the pool only needs to know "can another
//! attempt (here or elsewhere) plausibly succeed, and how long should we back
//! off this provider?". So we collapse everything into [`FailureClass`].

use std::time::Duration;

use hf_core::error::ClassifiedError;

/// Base backoff applied to a rate-limited (429) provider before exponential
/// scaling by the freeze registry.
const BACKOFF_RATE_LIMIT: Duration = Duration::from_mins(1);
/// Base backoff for a transient server-side (5xx) failure.
const BACKOFF_SERVER: Duration = Duration::from_secs(30);
/// Base backoff for a network/timeout failure.
const BACKOFF_NETWORK: Duration = Duration::from_secs(15);
/// Base backoff for an otherwise-unclassified provider error. We still treat it
/// as retryable so failover can try a healthy peer.
const BACKOFF_UNKNOWN: Duration = Duration::from_secs(30);
/// Freeze applied to a fatal (auth/config) failure: long enough to take the
/// provider out of rotation, but not literally permanent so operators can
/// recover without a restart once they fix credentials.
const BACKOFF_FATAL: Duration = Duration::from_hours(1);

/// How the pool should react to a failed completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClass {
    /// A transient failure: freeze this provider for `backoff` (scaled
    /// exponentially on repeated freezes) and try the next candidate.
    Retryable {
        /// Base backoff before exponential scaling.
        backoff: Duration,
    },
    /// A fatal failure (bad credentials, missing model, malformed request):
    /// retrying the same provider will not help. Freeze it for a long window
    /// and fail over.
    Fatal {
        /// Backoff used to park the provider out of rotation.
        backoff: Duration,
    },
}

impl FailureClass {
    /// The base backoff the pool should freeze the provider for.
    #[must_use]
    pub fn backoff(&self) -> Duration {
        match self {
            Self::Retryable { backoff } | Self::Fatal { backoff } => *backoff,
        }
    }
}

/// Classify a failed `complete()` result into a [`FailureClass`].
///
/// The `openai_compat` layer encodes the HTTP status into the error message as
/// `http <status>: <body>` (e.g. `http 429 Too Many Requests: {...}`), so we
/// recover the status code when present and fall back to keyword matching on the
/// message otherwise.
#[must_use]
pub fn classify(error: &ClassifiedError) -> FailureClass {
    match error {
        // A timeout is always worth retrying elsewhere.
        ClassifiedError::Timeout => FailureClass::Retryable {
            backoff: BACKOFF_NETWORK,
        },
        ClassifiedError::Provider(msg) => classify_provider_message(msg),
        // Validation and other local errors are not provider faults; do not
        // treat them as retryable failover candidates.
        _ => FailureClass::Fatal {
            backoff: BACKOFF_FATAL,
        },
    }
}

fn classify_provider_message(msg: &str) -> FailureClass {
    if let Some(status) = extract_http_status(msg) {
        return classify_status(status);
    }
    // No HTTP status: this is a transport/parse error from the sender layer
    // (e.g. "http: connection refused", "decode: ...", "parse: ...").
    let lower = msg.to_lowercase();
    if lower.starts_with("http:")
        || lower.contains("connection")
        || lower.contains("network")
        || lower.contains("dns")
        || lower.contains("timed out")
    {
        return FailureClass::Retryable {
            backoff: BACKOFF_NETWORK,
        };
    }
    // Unknown provider error: still retryable so failover can try a peer.
    FailureClass::Retryable {
        backoff: BACKOFF_UNKNOWN,
    }
}

/// Map an HTTP status code to a [`FailureClass`].
fn classify_status(status: u16) -> FailureClass {
    match status {
        429 => FailureClass::Retryable {
            backoff: BACKOFF_RATE_LIMIT,
        },
        500..=599 => FailureClass::Retryable {
            backoff: BACKOFF_SERVER,
        },
        // Auth / forbidden / not-found / bad-request: a config or request fault.
        // Retrying the same provider with the same input will not help.
        400..=499 => FailureClass::Fatal {
            backoff: BACKOFF_FATAL,
        },
        // Any other unexpected status: retry elsewhere.
        _ => FailureClass::Retryable {
            backoff: BACKOFF_UNKNOWN,
        },
    }
}

/// Extract the numeric HTTP status from an `http <status>: ...` message.
fn extract_http_status(msg: &str) -> Option<u16> {
    let rest = msg.strip_prefix("http ")?;
    // The status is the leading run of ASCII digits (reqwest renders the status
    // as e.g. "429 Too Many Requests").
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_is_retryable() {
        let err = ClassifiedError::Provider("http 429 Too Many Requests: {}".to_owned());
        assert_eq!(
            classify(&err),
            FailureClass::Retryable {
                backoff: BACKOFF_RATE_LIMIT
            }
        );
    }

    #[test]
    fn server_error_is_retryable() {
        let err = ClassifiedError::Provider("http 503 Service Unavailable: {}".to_owned());
        assert_eq!(
            classify(&err),
            FailureClass::Retryable {
                backoff: BACKOFF_SERVER
            }
        );
    }

    #[test]
    fn auth_error_is_fatal() {
        let err = ClassifiedError::Provider("http 401 Unauthorized: {}".to_owned());
        assert!(matches!(classify(&err), FailureClass::Fatal { .. }));
    }

    #[test]
    fn forbidden_is_fatal() {
        let err = ClassifiedError::Provider("http 403 Forbidden: {}".to_owned());
        assert!(matches!(classify(&err), FailureClass::Fatal { .. }));
    }

    #[test]
    fn network_error_is_retryable() {
        let err = ClassifiedError::Provider("http: connection refused".to_owned());
        assert_eq!(
            classify(&err),
            FailureClass::Retryable {
                backoff: BACKOFF_NETWORK
            }
        );
    }

    #[test]
    fn timeout_is_retryable() {
        assert_eq!(
            classify(&ClassifiedError::Timeout),
            FailureClass::Retryable {
                backoff: BACKOFF_NETWORK
            }
        );
    }

    #[test]
    fn validation_is_fatal() {
        let err = ClassifiedError::Validation("bad arg".to_owned());
        assert!(matches!(classify(&err), FailureClass::Fatal { .. }));
    }

    #[test]
    fn unknown_provider_error_is_retryable() {
        let err = ClassifiedError::Provider("no choices in response".to_owned());
        assert_eq!(
            classify(&err),
            FailureClass::Retryable {
                backoff: BACKOFF_UNKNOWN
            }
        );
    }

    #[test]
    fn extracts_status_code() {
        assert_eq!(
            extract_http_status("http 429 Too Many Requests: {}"),
            Some(429)
        );
        assert_eq!(extract_http_status("http: connection refused"), None);
        assert_eq!(extract_http_status("decode: bad json"), None);
    }
}
