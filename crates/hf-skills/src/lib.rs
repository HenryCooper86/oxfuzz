//! hf-skills: the fuzzing skill registry.
//!
//! A skill is a versioned instruction playbook (`root.md`) plus a `skill.toml`
//! manifest. Built-in fuzzing skills are embedded in the binary; user skills
//! live under `skills/<name>/`. Agents reference skills by name, and the
//! registry renders the referenced playbooks into the agent's prompt.

mod registry;

pub use registry::{SkillDefinition, SkillError, SkillRegistry, TrustTier};
