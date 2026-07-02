//! hf-prompt: prompt templates + the ported y-agent prompt section/template
//! system.
//!
//! - `render`: hobot's fuzzing prompt renderers (discovery, harness, triage).
//! - `budget`/`builtins`/`section`/`store`/`template`: y-agent's structured
//!   prompt sections, templates, and section store (used by hf-context).

pub mod render;

pub mod budget;
pub mod builtins;
pub mod section;
pub mod store;
pub mod template;

pub use render::{
    render_discovery_prompt, render_harness_prompt, render_harness_refine_prompt,
    render_harness_repair_prompt, render_seed_prompt,
};

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
