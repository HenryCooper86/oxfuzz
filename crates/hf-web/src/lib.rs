//! hf-web: REST API + SSE streaming for `hobot_fuzz`.

pub mod router;

pub use router::{build, build_bootstrapped, build_with_state, AppState, SseEvent};
