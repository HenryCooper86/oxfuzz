//! hf-service: Business logic and orchestration for `hobot_fuzz`.
//!
//! See `docs/design/service-orchestration-design.md`.

#![allow(dead_code)]

pub mod service;

pub use service::DefaultFuzzService;
