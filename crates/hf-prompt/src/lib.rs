//! hf-prompt: canonical prompt assembly and fuzzing prompt templates.
//!
//! - `render`: hobot's fuzzing prompt renderers (discovery, harness, triage).
//! - `agent`: the invariant, token-budgeted system prompt used by `hf-agent`.
//! - `budget`/`builtins`/`section`/`store`/`template`: structured prompt
//!   sections, templates, and section store (used by `hf-context`).

pub mod agent;

pub mod render;

pub mod budget;
pub mod builtins;
pub mod section;
pub mod store;
pub mod template;

pub use render::{
    render_discovery_prompt, render_harness_prompt, render_harness_prompt_with_context,
    render_harness_refine_prompt, render_harness_repair_prompt, render_related_context_section,
    render_seed_prompt, RelatedContext, MAX_RELATED_CONTEXT_CHARS,
};

pub use agent::{build_agent_system_prompt, AgentPromptInput, AGENT_SYSTEM_PROMPT_TOKEN_BUDGET};

pub use budget::{
    estimate_tokens, truncate_to_budget, truncate_tool_result, MAX_TOOL_RESULT_CHARS,
};
pub use builtins::{
    builtin_section_store, builtin_section_store_with_overrides, default_template,
    tool_protocol_for, BUILTIN_PROMPT_FILES, PROMPT_TOOL_PROTOCOL, PROMPT_TOOL_PROTOCOL_REMOTE,
};
pub use section::{
    ContentSource, PromptContext, PromptSection, SectionCategory, SectionCondition, SectionId,
    TemplateId,
};
pub use store::{SectionStore, StoreError};
pub use template::{EffectiveSection, ModeOverlay, PromptTemplate, SectionRef};
