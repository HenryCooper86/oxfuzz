//! hf-web: REST API + SSE streaming for `oxfuzz`.

pub mod router;
mod security;

pub use router::{
    build, build_bootstrapped, build_bootstrapped_with_security, build_with_state,
    build_with_state_and_security, AppState, SseEvent,
};
pub use security::{validate_bind_addr, BindAddressError, SecurityConfigError, WebSecurityConfig};
