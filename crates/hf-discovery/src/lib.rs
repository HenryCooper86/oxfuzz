//! hf-discovery: Target discovery for fuzzing.
//!
//! See `docs/design/target-discovery-design.md`.

#![allow(dead_code)]

pub mod scanner;

pub use scanner::discover;
