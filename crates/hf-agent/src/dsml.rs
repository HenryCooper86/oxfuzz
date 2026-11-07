//! Recovery of `DeepSeek` DSML function-call markup from assistant text.
//!
//! The agent speaks a prompt-based JSON step protocol, so its requests carry
//! no provider-native tool definitions. `DeepSeek` models nonetheless sometimes
//! answer a step in their native DSML call syntax:
//!
//! ```text
//! <｜DSML｜function_calls>
//! <｜DSML｜invoke name="run">
//! <｜DSML｜parameter name="target" string="true">doprocessing</｜DSML｜parameter>
//! <｜DSML｜parameter name="duration_secs" string="false">10</｜DSML｜parameter>
//! </｜DSML｜invoke>
//! </｜DSML｜function_calls>
//! ```
//!
//! With no tools in the request the provider API does not parse that markup
//! into structured calls, so it arrives as plain `content`. This module decodes
//! it into tool name plus JSON arguments so the agent loop can treat it as the
//! step the model meant. The input is untrusted model output: the parser is
//! strict, bounded, and returns `None` for anything it does not fully accept,
//! so malformed markup is never turned into an invented call.

use serde_json::{Map, Value};

/// Largest assistant reply, in bytes, that is examined for DSML markup.
const MAX_CONTENT_BYTES: usize = 64 * 1024;

/// Most `invoke` elements accepted in one `function_calls` block.
const MAX_INVOKES: usize = 8;

/// Most `parameter` elements accepted in one `invoke`.
const MAX_PARAMETERS: usize = 32;

/// Longest tool or parameter name accepted.
const MAX_NAME_CHARS: usize = 64;

const OPEN_CALLS: &str = "<｜DSML｜function_calls>";
const CLOSE_CALLS: &str = "</｜DSML｜function_calls>";
const OPEN_INVOKE: &str = "<｜DSML｜invoke name=\"";
const CLOSE_INVOKE: &str = "</｜DSML｜invoke>";
const OPEN_PARAMETER: &str = "<｜DSML｜parameter name=\"";
const CLOSE_PARAMETER: &str = "</｜DSML｜parameter>";
const STRING_ATTRIBUTE: &str = " string=\"";

/// One decoded `invoke` element.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DsmlCall {
    /// The invoked tool name.
    pub name: String,
    /// Parameters as a JSON object: `string="true"` values are JSON strings,
    /// `string="false"` values are parsed as JSON.
    pub arguments: Map<String, Value>,
}

/// A decoded `function_calls` block and the prose that preceded it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DsmlBlock {
    /// Trimmed text before the block; empty when the reply opens with it.
    pub preamble: String,
    /// The invokes in emission order; never empty.
    pub calls: Vec<DsmlCall>,
}

/// Decode a reply that ends in exactly one DSML `function_calls` block.
///
/// Returns `None` when the reply contains no block, is larger than
/// [`MAX_CONTENT_BYTES`], has non-whitespace text after the block, or when any
/// part of the block is malformed or exceeds a bound.
pub(crate) fn parse(content: &str) -> Option<DsmlBlock> {
    if content.len() > MAX_CONTENT_BYTES {
        return None;
    }
    let start = content.find(OPEN_CALLS)?;
    let preamble = content[..start].trim().to_owned();
    let mut rest = &content[start + OPEN_CALLS.len()..];
    let mut calls = Vec::new();
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix(CLOSE_CALLS) {
            let accepted = !calls.is_empty() && after.trim().is_empty();
            return accepted.then_some(DsmlBlock { preamble, calls });
        }
        if calls.len() == MAX_INVOKES {
            return None;
        }
        let (call, after) = parse_invoke(rest)?;
        calls.push(call);
        rest = after;
    }
}

/// Decode one `invoke` element at the start of `input`, returning the call and
/// the text after its closing tag.
fn parse_invoke(input: &str) -> Option<(DsmlCall, &str)> {
    let (name, rest) = read_name(input.strip_prefix(OPEN_INVOKE)?)?;
    let mut rest = rest.strip_prefix('>')?;
    let mut arguments = Map::new();
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix(CLOSE_INVOKE) {
            return Some((DsmlCall { name, arguments }, after));
        }
        if arguments.len() == MAX_PARAMETERS {
            return None;
        }
        let (parameter, value, after) = parse_parameter(rest)?;
        if arguments.insert(parameter, value).is_some() {
            // A repeated parameter has no single meaning; refuse to pick one.
            return None;
        }
        rest = after;
    }
}

/// Decode one `parameter` element at the start of `input`, returning its name,
/// typed value, and the text after its closing tag.
fn parse_parameter(input: &str) -> Option<(String, Value, &str)> {
    let (name, rest) = read_name(input.strip_prefix(OPEN_PARAMETER)?)?;
    let rest = rest.strip_prefix(STRING_ATTRIBUTE)?;
    let (is_string, rest) = if let Some(rest) = rest.strip_prefix("true\">") {
        (true, rest)
    } else {
        (false, rest.strip_prefix("false\">")?)
    };
    let end = rest.find(CLOSE_PARAMETER)?;
    let raw = &rest[..end];
    let value = if is_string {
        Value::String(raw.to_owned())
    } else {
        // Swallowed: a non-string value that is not valid JSON makes the whole
        // block malformed, which `parse` reports as `None`; the reply is then
        // handled as ordinary text and nothing is executed.
        serde_json::from_str(raw).ok()?
    };
    Some((name, value, &rest[end + CLOSE_PARAMETER.len()..]))
}

/// Read a quoted attribute value up to its closing `"` and validate it as a
/// tool or parameter name: 1 to [`MAX_NAME_CHARS`] ASCII letters, digits, `_`,
/// or `-`.
fn read_name(input: &str) -> Option<(String, &str)> {
    let end = input.find('"')?;
    let name = &input[..end];
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid.then(|| (name.to_owned(), &input[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::{parse, DsmlCall, MAX_CONTENT_BYTES, MAX_INVOKES, MAX_PARAMETERS};
    use serde_json::json;

    fn invoke(name: &str, params: &[(&str, bool, &str)]) -> String {
        let parameters: Vec<String> = params
            .iter()
            .map(|(param, is_string, value)| {
                format!(
                    "<｜DSML｜parameter name=\"{param}\" string=\"{is_string}\">{value}</｜DSML｜parameter>\n"
                )
            })
            .collect();
        format!(
            "<｜DSML｜invoke name=\"{name}\">\n{}</｜DSML｜invoke>\n",
            parameters.concat()
        )
    }

    fn block(invokes: &[String]) -> String {
        format!(
            "<｜DSML｜function_calls>\n{}</｜DSML｜function_calls>",
            invokes.concat()
        )
    }

    fn arguments(call: &DsmlCall) -> serde_json::Value {
        serde_json::Value::Object(call.arguments.clone())
    }

    #[test]
    fn decodes_the_observed_deepseek_run_call() {
        let content = block(&[invoke(
            "run",
            &[
                ("target", true, "doprocessing"),
                ("engine", true, "libfuzzer"),
                ("duration_secs", false, "10"),
            ],
        )]);
        let parsed = parse(&content).expect("well-formed block");
        assert_eq!(parsed.preamble, "");
        assert_eq!(parsed.calls.len(), 1);
        assert_eq!(parsed.calls[0].name, "run");
        assert_eq!(
            arguments(&parsed.calls[0]),
            json!({"target": "doprocessing", "engine": "libfuzzer", "duration_secs": 10})
        );
    }

    #[test]
    fn decodes_multiple_invokes_in_order() {
        let content = block(&[
            invoke("discover", &[("lang", true, "c")]),
            invoke("triage", &[("target", true, "parse")]),
        ]);
        let parsed = parse(&content).expect("well-formed block");
        let names: Vec<&str> = parsed.calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["discover", "triage"]);
        assert_eq!(arguments(&parsed.calls[1]), json!({"target": "parse"}));
    }

    #[test]
    fn non_string_parameters_are_parsed_as_json() {
        let content = block(&[invoke(
            "corpus",
            &[
                ("dry_run", false, "true"),
                ("ratio", false, " 0.5 "),
                ("filters", false, r#"{"min": 1, "tags": ["a"]}"#),
                ("none", false, "null"),
            ],
        )]);
        let parsed = parse(&content).expect("well-formed block");
        assert_eq!(
            arguments(&parsed.calls[0]),
            json!({"dry_run": true, "ratio": 0.5, "filters": {"min": 1, "tags": ["a"]}, "none": null})
        );
    }

    #[test]
    fn string_parameters_keep_their_text_verbatim() {
        // A string value that looks like JSON stays a string, and multi-line text
        // survives unchanged.
        let content = block(&[invoke(
            "delegate",
            &[
                ("agent", true, "run-operator"),
                ("task", true, "line one\n{\"x\": 1}\n"),
            ],
        )]);
        let parsed = parse(&content).expect("well-formed block");
        assert_eq!(
            arguments(&parsed.calls[0]),
            json!({"agent": "run-operator", "task": "line one\n{\"x\": 1}\n"})
        );
    }

    #[test]
    fn an_invoke_without_parameters_has_empty_arguments() {
        let parsed = parse(&block(&[invoke("discover", &[])])).expect("well-formed block");
        assert_eq!(arguments(&parsed.calls[0]), json!({}));
    }

    #[test]
    fn prose_before_the_block_becomes_the_preamble() {
        let content = format!(
            "  I will start the campaign now.\n\n{}\n  ",
            block(&[invoke("run", &[("target", true, "t")])])
        );
        let parsed = parse(&content).expect("well-formed block");
        assert_eq!(parsed.preamble, "I will start the campaign now.");
        assert_eq!(parsed.calls[0].name, "run");
    }

    #[test]
    fn content_without_markup_is_not_a_block() {
        assert!(parse("Here is the answer.").is_none());
        assert!(parse(r#"{"tool":"run","args":{}}"#).is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn truncated_markup_is_left_alone() {
        let full = block(&[invoke("run", &[("target", true, "doprocessing")])]);
        // Every proper prefix that cuts into the block must be rejected, including
        // cuts inside a multi-byte delimiter character.
        let start = full.find("<｜DSML｜function_calls>").unwrap();
        for (cut, _) in full.char_indices().filter(|(i, _)| *i > start) {
            assert!(
                parse(&full[..cut]).is_none(),
                "accepted a truncated block: {:?}",
                &full[..cut]
            );
        }
    }

    #[test]
    fn text_after_the_block_is_rejected() {
        let content = format!(
            "{}\nDone, the run finished.",
            block(&[invoke("run", &[("target", true, "t")])])
        );
        assert!(parse(&content).is_none());
    }

    #[test]
    fn an_empty_block_is_rejected() {
        assert!(parse(&block(&[])).is_none());
    }

    #[test]
    fn unknown_elements_and_stray_text_inside_the_block_are_rejected() {
        let stray = "<｜DSML｜function_calls>\nhello\n</｜DSML｜function_calls>";
        assert!(parse(stray).is_none());
        let inside_invoke = block(&[
            "<｜DSML｜invoke name=\"run\">\nnot a parameter\n</｜DSML｜invoke>\n".to_owned(),
        ]);
        assert!(parse(&inside_invoke).is_none());
    }

    #[test]
    fn invalid_json_in_a_non_string_parameter_is_rejected() {
        let content = block(&[invoke("run", &[("duration_secs", false, "ten")])]);
        assert!(parse(&content).is_none());
    }

    #[test]
    fn a_missing_or_unknown_string_attribute_is_rejected() {
        let missing = block(&[
            "<｜DSML｜invoke name=\"run\">\n<｜DSML｜parameter name=\"target\">t</｜DSML｜parameter>\n</｜DSML｜invoke>\n"
                .to_owned(),
        ]);
        assert!(parse(&missing).is_none());
        let unknown = block(&[
            "<｜DSML｜invoke name=\"run\">\n<｜DSML｜parameter name=\"target\" string=\"maybe\">t</｜DSML｜parameter>\n</｜DSML｜invoke>\n"
                .to_owned(),
        ]);
        assert!(parse(&unknown).is_none());
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert!(parse(&block(&[invoke("", &[])])).is_none());
        assert!(parse(&block(&[invoke("run tool", &[])])).is_none());
        assert!(parse(&block(&[invoke(&"a".repeat(65), &[])])).is_none());
        assert!(parse(&block(&[invoke("run", &[("bad name", true, "x")])])).is_none());
    }

    #[test]
    fn duplicate_parameters_are_rejected() {
        let content = block(&[invoke(
            "run",
            &[("target", true, "a"), ("target", true, "b")],
        )]);
        assert!(parse(&content).is_none());
    }

    #[test]
    fn a_second_block_is_rejected() {
        let one = block(&[invoke("run", &[("target", true, "t")])]);
        assert!(parse(&format!("{one}\n{one}")).is_none());
    }

    #[test]
    fn size_bounds_are_enforced() {
        let at_limit: Vec<String> = (0..MAX_INVOKES).map(|_| invoke("discover", &[])).collect();
        assert!(parse(&block(&at_limit)).is_some());
        let over: Vec<String> = (0..=MAX_INVOKES).map(|_| invoke("discover", &[])).collect();
        assert!(parse(&block(&over)).is_none(), "too many invokes");

        let names: Vec<String> = (0..=MAX_PARAMETERS).map(|i| format!("p{i}")).collect();
        let params: Vec<(&str, bool, &str)> =
            names.iter().map(|n| (n.as_str(), true, "v")).collect();
        assert!(
            parse(&block(&[invoke("run", &params)])).is_none(),
            "too many parameters"
        );

        let big = "x".repeat(MAX_CONTENT_BYTES);
        let oversized = block(&[invoke("run", &[("target", true, &big)])]);
        assert!(oversized.len() > MAX_CONTENT_BYTES);
        assert!(parse(&oversized).is_none(), "oversized reply");
    }
}
