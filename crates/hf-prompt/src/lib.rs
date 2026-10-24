//! hf-prompt: canonical prompt assembly and fuzzing prompt templates.
//!
//! - `render`: oxfuzz's fuzzing prompt renderers (harness, triage, ranking).
//! - `agent`: the invariant, token-budgeted system prompt used by `hf-agent`.
//! - `budget`: the byte-based token estimator and truncator shared with the
//!   system-prompt budget.
//! - `builtins`: the compile-time prompt sections embedded in the binary.

pub mod agent;

mod clang_compact;

pub mod render;

pub mod budget;
mod builtins;

pub use render::{
    clang_context_wrapper_bytes, clang_renderer_version, render_accepted_examples_section,
    render_ai_ranking_prompt, render_build_context_section, render_crash_verify_prompt,
    render_dictionary_prompt, render_harness_pre_execution_review_prompt, render_harness_prompt,
    render_harness_prompt_with_context, render_harness_prompt_with_examples,
    render_harness_refine_prompt, render_harness_repair_prompt, render_persistent_harness_prompt,
    render_persistent_harness_prompt_with_examples, render_persistent_harness_refine_prompt,
    render_persistent_harness_repair_prompt, render_related_context_section, render_seed_prompt,
    AcceptedExample, PromptSizeError, RelatedContext, MAX_ACCEPTED_EXAMPLE_CHARS,
    MAX_RELATED_CONTEXT_CHARS,
};

pub use agent::{build_agent_system_prompt, AgentPromptInput, AGENT_SYSTEM_PROMPT_TOKEN_BUDGET};

pub use budget::{estimate_tokens, truncate_to_budget};

pub use render::render_clang_context;
