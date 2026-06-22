//! hf-prompt: Prompt templates for discovery, harness, and triage.
//!
//! Templates are embedded in code for now; loading from TOML is a future
//! enhancement (see `config/prompts/prompts.example.toml`).

pub mod render;

pub use render::{render_discovery_prompt, render_harness_prompt};
