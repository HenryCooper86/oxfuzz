//! Process-global environment ownership for web security startup.
//!
//! This integration target is its own process, so it owns `HF_WEB_TOKEN` for
//! its duration and exercises the fallible `try_from_env` path that `oxfuzz
//! serve` uses to fail loudly on a weak token.

use hf_web::{SecurityConfigError, WebSecurityConfig};

#[test]
fn try_from_env_rejects_a_short_token_but_accepts_a_strong_one() {
    // An explicitly configured token below the entropy floor must surface as
    // an error, never as a silently deny-all policy.
    std::env::set_var("HF_WEB_TOKEN", "short-token");
    assert!(matches!(
        WebSecurityConfig::try_from_env(),
        Err(SecurityConfigError::InvalidToken)
    ));

    // A strong visible-ASCII token resolves into a configured policy.
    std::env::set_var("HF_WEB_TOKEN", "correct-horse-battery-staple");
    let config = WebSecurityConfig::try_from_env().expect("a strong token is valid");
    assert!(config.token_configured());
}
