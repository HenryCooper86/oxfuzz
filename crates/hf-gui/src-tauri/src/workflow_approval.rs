//! Approval supplied by an explicit desktop workflow action.
//!
//! The scoped gate lives in `hf-service` so the web server derives the same
//! rule from the same place.

pub(crate) use hf_service::workflow_approval::{with_user_approval, ExplicitAction};
