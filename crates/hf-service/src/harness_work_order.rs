//! Service-owned, provider-free harness authoring packet.
//!
//! Every harness-authoring path in oxfuzz requires a configured LLM provider.
//! That excludes two real cases: an operator who wants to write the harness
//! themselves, and an environment where no provider credential may be present.
//!
//! A work order is everything needed to author one harness for one candidate,
//! with no provider involved at any point.
//!
//! See `docs/design/harness-work-order-design.md`.
//!
//! The rendering is deterministic: the same retained state produces the same
//! bytes, so two exports can be diffed. Nothing is read from the environment,
//! because no part of this needs it.

use hf_core::build::BuildContext;
use hf_harness::{harness_rules, HarnessRuleSummary, LintSeverity};
use serde::Serialize;

/// Current serialized Harness Work Order schema.
pub const HARNESS_WORK_ORDER_SCHEMA_VERSION: u32 = 1;

/// Everything gathered for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOrderInputs {
    /// The candidate function.
    pub target_symbol: String,
    /// Its recorded signature, when discovery captured one.
    pub signature: Option<String>,
    /// `file:line` of its definition.
    pub location: String,
    /// Why discovery ranked it.
    pub rationale: String,
    /// Source language, as the harness will be written in.
    pub language: String,
    /// A bounded excerpt of the candidate's source.
    pub source_excerpt: String,
    /// The compile context for its translation unit.
    pub build_context: BuildContext,
    /// Retained corpus entries and repository fixtures worth seeding from.
    pub seed_suggestions: Vec<String>,
    /// The project path, as it appears in the validation commands.
    pub project_display: String,
}

/// One rule an author must satisfy, as the packet states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkOrderRule {
    /// Stable rule identifier, matching the lint finding a violation produces.
    pub id: String,
    /// Whether a violation blocks compilation.
    pub blocking: bool,
    /// What is wrong and why it matters.
    pub message: String,
}

/// One authoring packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HarnessWorkOrder {
    /// Serialization version of this packet.
    pub schema_version: u32,
    /// The candidate function.
    pub target_symbol: String,
    /// Its recorded signature, when discovery captured one.
    pub signature: Option<String>,
    /// `file:line` of its definition.
    pub location: String,
    /// Why discovery ranked it.
    pub rationale: String,
    /// Source language.
    pub language: String,
    /// A bounded excerpt of the candidate's source.
    pub source_excerpt: String,
    /// Include directories the harness must be compiled with.
    pub include_dirs: Vec<String>,
    /// Defines the harness must be compiled with.
    pub defines: Vec<String>,
    /// The language standard, when the compile database recorded one.
    pub std_flag: Option<String>,
    /// Other code-generation flags the compile database recorded.
    pub extra_flags: Vec<String>,
    /// Translation units the compile database recorded. Zero means the flags
    /// above are not the project's own.
    pub compile_units: usize,
    /// The rules the lint enforces, so an author sees them before writing.
    pub harness_rules: Vec<WorkOrderRule>,
    /// Inputs worth seeding the corpus from.
    pub seed_suggestions: Vec<String>,
    /// Exactly how to check the result.
    pub validation_commands: Vec<String>,
}

/// Assemble the packet for one candidate.
///
/// Calls no provider and reads no environment variable.
#[must_use]
pub fn build_work_order(inputs: &WorkOrderInputs) -> HarnessWorkOrder {
    HarnessWorkOrder {
        schema_version: HARNESS_WORK_ORDER_SCHEMA_VERSION,
        target_symbol: inputs.target_symbol.clone(),
        signature: inputs.signature.clone(),
        location: inputs.location.clone(),
        rationale: inputs.rationale.clone(),
        language: inputs.language.clone(),
        source_excerpt: inputs.source_excerpt.clone(),
        include_dirs: inputs
            .build_context
            .include_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        defines: inputs.build_context.defines.clone(),
        std_flag: inputs.build_context.std_flag.clone(),
        extra_flags: inputs.build_context.extra_flags.clone(),
        compile_units: inputs.build_context.entry_count,
        harness_rules: rules_for(&inputs.language),
        seed_suggestions: inputs.seed_suggestions.clone(),
        validation_commands: validation_commands(&inputs.project_display, &inputs.target_symbol),
    }
}

/// The lint's own rules, filtered to the ones that apply to this language.
fn rules_for(language: &str) -> Vec<WorkOrderRule> {
    let is_cpp = matches!(language.to_lowercase().as_str(), "cpp" | "c++" | "cxx");
    harness_rules()
        .into_iter()
        .filter(|rule: &HarnessRuleSummary| is_cpp || !rule.cpp_only)
        .map(|rule| WorkOrderRule {
            id: rule.id,
            blocking: rule.severity == LintSeverity::Error,
            message: rule.message,
        })
        .collect()
}

/// The commands that check the authored harness, in the order to run them.
fn validation_commands(project: &str, target: &str) -> Vec<String> {
    vec![
        format!("oxfuzz harness {project} --target {target} --engine libfuzzer"),
        format!("oxfuzz run {project} --target {target} --engine libfuzzer --duration 5m"),
        format!("oxfuzz coverage {project} --target {target}"),
    ]
}

/// The candidate's rationale, or a statement that discovery recorded none.
///
/// An empty field would render as a dangling label, which reads as a bug in the
/// packet rather than as absent evidence.
fn rationale_of(order: &HarnessWorkOrder) -> &str {
    let trimmed = order.rationale.trim();
    if trimmed.is_empty() {
        "not recorded by discovery"
    } else {
        trimmed
    }
}

/// Render the packet as a document a person reads.
///
/// Deterministic: no timestamp, no identifier, and no iteration over an
/// unordered collection, so the same retained state yields the same bytes.
#[must_use]
pub fn render_work_order(order: &HarnessWorkOrder) -> String {
    let mut out = String::new();
    let line = |out: &mut String, text: &str| {
        out.push_str(text);
        out.push('\n');
    };

    line(
        &mut out,
        &format!("# Harness work order: {}", order.target_symbol),
    );
    line(&mut out, "");
    line(&mut out, "## Candidate");
    line(&mut out, "");
    line(&mut out, &format!("- Function: `{}`", order.target_symbol));
    match &order.signature {
        Some(signature) => line(&mut out, &format!("- Signature: `{signature}`")),
        None => line(
            &mut out,
            "- Signature: not recorded by discovery; read it from the source below.",
        ),
    }
    line(&mut out, &format!("- Defined at: `{}`", order.location));
    line(&mut out, &format!("- Language: `{}`", order.language));
    line(
        &mut out,
        &format!("- Why it was ranked: {}", rationale_of(order)),
    );
    line(&mut out, "");

    line(&mut out, "## Source");
    line(&mut out, "");
    line(&mut out, "```");
    line(&mut out, order.source_excerpt.trim_end());
    line(&mut out, "```");
    line(&mut out, "");

    line(&mut out, "## Compile context");
    line(&mut out, "");
    if order.compile_units == 0 {
        line(
            &mut out,
            "No compile database was available for this project, so the flags below are \
             oxfuzz's defaults rather than the project's own. Expect to adjust them.",
        );
        line(&mut out, "");
    } else {
        line(
            &mut out,
            &format!(
                "From the project's compile database ({} translation unit(s)).",
                order.compile_units
            ),
        );
        line(&mut out, "");
    }
    if order.include_dirs.is_empty() {
        line(&mut out, "- Include directories: none recorded");
    } else {
        line(&mut out, "- Include directories:");
        for dir in &order.include_dirs {
            line(&mut out, &format!("  - `{dir}`"));
        }
    }
    if order.defines.is_empty() {
        line(&mut out, "- Defines: none recorded");
    } else {
        line(&mut out, "- Defines:");
        for define in &order.defines {
            line(&mut out, &format!("  - `{define}`"));
        }
    }
    match &order.std_flag {
        Some(flag) => line(&mut out, &format!("- Language standard: `{flag}`")),
        None => line(&mut out, "- Language standard: none recorded"),
    }
    if !order.extra_flags.is_empty() {
        line(&mut out, "- Other flags:");
        for flag in &order.extra_flags {
            line(&mut out, &format!("  - `{flag}`"));
        }
    }
    line(&mut out, "");

    line(&mut out, "## Rules the build will enforce");
    line(&mut out, "");
    line(
        &mut out,
        "These are checked by the harness lint before compilation. A blocking rule \
         fails the build.",
    );
    line(&mut out, "");
    for rule in &order.harness_rules {
        let severity = if rule.blocking {
            "blocking"
        } else {
            "advisory"
        };
        line(
            &mut out,
            &format!("- `{}` ({severity}): {}", rule.id, rule.message),
        );
    }
    line(&mut out, "");

    line(&mut out, "## Seeds");
    line(&mut out, "");
    if order.seed_suggestions.is_empty() {
        line(
            &mut out,
            "No seed candidates were found in the retained corpus or the repository. \
             Write a valid input by hand before the first run; an empty corpus is the \
             single most common reason a campaign reaches nothing.",
        );
    } else {
        for seed in &order.seed_suggestions {
            line(&mut out, &format!("- `{seed}`"));
        }
    }
    line(&mut out, "");

    line(&mut out, "## Validation");
    line(&mut out, "");
    line(&mut out, "Run these in order once the harness is written.");
    line(&mut out, "");
    for command in &order.validation_commands {
        line(&mut out, &format!("```\n{command}\n```"));
    }
    out
}
