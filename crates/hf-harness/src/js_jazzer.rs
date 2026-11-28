//! JavaScript (Jazzer.js) harness: the fixed template, its lint, and the
//! syntax-only build.
//!
//! The supported target class is a function a Node.js module exports by
//! name, each of whose required parameters is documented in the `JSDoc`
//! block directly above the function as `Buffer`, `Uint8Array`, `string`,
//! `number`, or `boolean`. One `Buffer` or `string` parameter gets the fuzz
//! input itself; any other accepted list is filled from the input by
//! Jazzer.js's `FuzzedDataProvider`. JavaScript has no types to read, and
//! guessing one would turn the harness's own mistake into a finding, so an
//! undocumented parameter is refused with the line to add. The harness is
//! generated from the selected function alone, with no model call, and the
//! lint accepts nothing but that generated text: a JavaScript harness runs
//! with Node.js's full power the moment it is loaded, so there is no
//! reviewed subset of edits to allow yet.
//! See `docs/design/javascript-jazzerjs-fuzzing-design.md`.

use std::fmt::Write as _;
use std::path::PathBuf;

use hf_core::error::ClassifiedError;
use hf_core::harness::BuildCommand;
use hf_core::target::TargetCandidate;

use crate::lint::{LintFinding, LintSeverity};

/// The harness source file written at the workspace root for the build.
pub const HARNESS_FILE: &str = "harness.mjs";

/// The directive line that records what the harness fuzzes:
/// `// oxfuzz:js-target <file> <export> <types>`, where `<file>` is the
/// module's path below the project root and `<types>` is the comma-separated
/// list of what each required parameter takes (`buffer`, `string`, `number`,
/// `boolean`).
pub const TARGET_DIRECTIVE: &str = "// oxfuzz:js-target ";

/// The directory beside a run's harness that holds the run's retained
/// project sources. When it exists the harness loads the module from it, so
/// a run and its historical replay use the sources captured at run start.
pub const RETAINED_SOURCES_DIR: &str = "source-context";

/// The file whose presence at the project root makes the project a Node.js
/// project, and which says whether it has dependencies to carry.
pub const MANIFEST_FILE: &str = "package.json";

/// Where a project carries the packages its modules load. Nothing is
/// installed or downloaded: the directory is staged as it is when the
/// manifest declares dependencies.
pub const DEPENDENCIES_DIR: &str = "node_modules";

/// The file extensions of a module the harness can load.
pub const MODULE_EXTENSIONS: [&str; 3] = ["js", "mjs", "cjs"];

/// The most bytes a `Buffer` or `string` argument that is not the last one
/// takes; the last one takes whatever input is left.
const MAX_INNER_ARGUMENT_BYTES: u32 = 4096;

/// The most required parameters one harness fills.
const MAX_PARAMETERS: usize = 8;

/// The types a documented parameter may have, as the refusal names them.
const SUPPORTED_TYPES: &str = "Buffer, Uint8Array, string, number, boolean";

/// Parses the harness and the selected module without loading either, then
/// installs the harness as an executable file. Loading is execution and
/// waits for the smoke approval; a syntax error fails here instead.
const BUILD_SCRIPT: &str = "[ -f \"$2\" ] || { echo \"oxfuzz: the selected module is not in \
                            the staged project: $2\" >&2; exit 1; }; \
                            \"$0\" --check \"$1\" && \"$0\" --check \"$2\" && cp \"$1\" \"$3\" \
                            && chmod 755 \"$3\"";

const RESERVED_WORDS: [&str; 46] = [
    "arguments",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "eval",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "interface",
    "let",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
];

fn invalid(message: String) -> ClassifiedError {
    ClassifiedError::Validation(message)
}

/// What the fuzz callback hands the selected function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsInputKind {
    /// The raw fuzz input as a `Buffer` (which is a `Uint8Array`).
    Bytes,
    /// The input decoded as UTF-8 with replacement.
    Text,
    /// A double taken from the input, including infinities and `NaN`.
    Number,
    /// One bit of the input.
    Boolean,
}

impl JsInputKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "buffer",
            Self::Text => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "buffer" => Some(Self::Bytes),
            "string" => Some(Self::Text),
            "number" => Some(Self::Number),
            "boolean" => Some(Self::Boolean),
            _ => None,
        }
    }

    /// The kind a `JSDoc` type expression names. The capitalized wrapper
    /// names are accepted because documentation uses them for the primitive.
    fn documented(kind: &str) -> Option<Self> {
        match kind {
            "Buffer" | "Uint8Array" => Some(Self::Bytes),
            "string" | "String" => Some(Self::Text),
            "number" | "Number" => Some(Self::Number),
            "boolean" | "Boolean" => Some(Self::Boolean),
            _ => None,
        }
    }

    /// The expression that takes this argument from the data provider. The
    /// last parameter takes all remaining input when it is bytes or text.
    fn consume(self, last: bool) -> String {
        let length = format!("provider.consumeIntegralInRange(0, {MAX_INNER_ARGUMENT_BYTES})");
        match (self, last) {
            (Self::Bytes, true) => "Buffer.from(provider.consumeRemainingAsBytes())".to_owned(),
            (Self::Bytes, false) => format!("Buffer.from(provider.consumeBytes({length}))"),
            (Self::Text, true) => "provider.consumeRemainingAsString()".to_owned(),
            (Self::Text, false) => format!("provider.consumeString({length})"),
            (Self::Number, _) => "provider.consumeNumber()".to_owned(),
            (Self::Boolean, _) => "provider.consumeBoolean()".to_owned(),
        }
    }
}

/// The function one harness fuzzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTarget {
    /// The module's path below the project root, with `/` separators.
    pub file: String,
    /// The name the module exports the function under.
    pub export: String,
    /// What each of the function's required parameters takes, in order.
    pub inputs: Vec<JsInputKind>,
    /// The constructor names of the errors the module rejects an input with
    /// ([`module_errors`]); the harness lets those pass and reports any other
    /// throw or rejection. Empty: every error is a finding.
    pub expected_errors: Vec<String>,
}

/// One `@param` line of a `JSDoc` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentedParameter {
    /// The parameter's name.
    pub name: String,
    /// The type expression between the braces, trimmed.
    pub kind: String,
    /// Whether the line marks the parameter optional (`[name]` or `{type=}`).
    pub optional: bool,
}

/// Whether `text` is an ASCII JavaScript identifier that is not reserved.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_' || first == '$')
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        })
        && !RESERVED_WORDS.contains(&text)
}

/// Whether `relative` names a module below the project root that the harness
/// can load: `/`-separated components of plain characters, none of them a
/// dot directory or the dependency directory, ending in a module extension.
/// The path is written into the harness as a string, so nothing that could
/// end that string or climb out of the project is accepted.
#[must_use]
pub fn is_module_path(relative: &str) -> bool {
    let plain = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part != DEPENDENCIES_DIR
            && part.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '@' | '+')
            })
    };
    relative.split('/').all(plain)
        && relative.rsplit_once('.').is_some_and(|(stem, extension)| {
            !stem.is_empty() && MODULE_EXTENSIONS.contains(&extension)
        })
}

/// The `@param` lines of the `JSDoc` block that ends on the line directly
/// above `line` (1-based) of `source`. A function with no such block
/// documents nothing.
#[must_use]
pub fn documented_parameters(source: &str, line: u32) -> Vec<DocumentedParameter> {
    let lines: Vec<&str> = source.lines().collect();
    let Some(mut index) = usize::try_from(line)
        .ok()
        .and_then(|line| line.checked_sub(2))
    else {
        return Vec::new();
    };
    if !lines
        .get(index)
        .is_some_and(|above| above.trim_end().ends_with("*/"))
    {
        return Vec::new();
    }
    let mut block = Vec::new();
    loop {
        let Some(text) = lines.get(index) else {
            return Vec::new();
        };
        block.push(*text);
        if text.trim_start().starts_with("/**") {
            break;
        }
        if text.trim_start().starts_with("/*") {
            // An ordinary comment is not documentation.
            return Vec::new();
        }
        let Some(previous) = index.checked_sub(1) else {
            return Vec::new();
        };
        index = previous;
    }
    block
        .iter()
        .rev()
        .filter_map(|text| documented_parameter(text))
        .collect()
}

/// The parameter one comment line documents, when it is a `@param` line with
/// a type in braces. A line about a property of a parameter (`options.depth`)
/// documents no parameter.
fn documented_parameter(line: &str) -> Option<DocumentedParameter> {
    let text = line
        .trim()
        .trim_start_matches("/**")
        .trim_start_matches('*')
        .trim_end_matches("*/")
        .trim();
    let rest = ["@param", "@argument", "@arg"]
        .iter()
        .find_map(|tag| text.strip_prefix(tag))?;
    let rest = rest.strip_prefix(char::is_whitespace)?.trim_start();
    let rest = rest.strip_prefix('{')?;
    let (kind, rest) = rest.split_once('}')?;
    let word = rest.split_whitespace().next()?;
    let bracketed = word.starts_with('[');
    let name: String = word
        .trim_start_matches('[')
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '.')
        })
        .collect();
    if name.contains('.') || !is_identifier(&name) {
        return None;
    }
    let kind = kind.trim();
    Some(DocumentedParameter {
        name,
        kind: kind.trim_end_matches('=').trim().to_owned(),
        optional: bracketed || kind.ends_with('='),
    })
}

/// Split a parameter list on its top-level commas.
fn split_parameters(parameters: &str) -> Vec<String> {
    let mut depth = 0_i32;
    let mut current = String::new();
    let mut out = Vec::new();
    for character in parameters.chars() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(current.trim().to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(character);
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    out
}

/// The text between the first `(` and its matching `)`.
fn parameter_list(signature: &str) -> Option<&str> {
    let open = signature.find('(')?;
    let mut depth = 0_i32;
    for (offset, character) in signature[open..].char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&signature[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// What each of the selected function's required parameters takes, read
/// from its recorded signature (`[async ]function name(parameters)`) and the
/// documentation above it.
///
/// # Errors
/// Returns `ClassifiedError::Validation` naming the reason the function is
/// outside the supported class.
pub fn input_kinds(
    signature: &str,
    documented: &[DocumentedParameter],
    symbol: &str,
) -> Result<Vec<JsInputKind>, ClassifiedError> {
    let parameters = parameter_list(signature.trim()).ok_or_else(|| {
        invalid(format!(
            "{symbol} has no recorded parameter list to read its inputs from"
        ))
    })?;
    let mut required: Vec<String> = Vec::new();
    let mut optional_seen: Option<String> = None;
    for parameter in split_parameters(parameters) {
        if parameter.starts_with("...") {
            // A rest parameter takes nothing by default.
            break;
        }
        if parameter.starts_with('{') || parameter.starts_with('[') {
            return Err(invalid(format!(
                "{symbol} takes a destructured parameter ('{parameter}'); the JavaScript harness \
                 passes {SUPPORTED_TYPES} values, not objects or arrays"
            )));
        }
        let name = parameter
            .split_once('=')
            .map_or(parameter.as_str(), |(name, _)| name)
            .trim()
            .to_owned();
        if !is_identifier(&name) {
            return Err(invalid(format!(
                "{symbol} has the parameter '{parameter}', which is not a plain name"
            )));
        }
        let optional = parameter.contains('=')
            || documented
                .iter()
                .any(|entry| entry.name == name && entry.optional);
        if optional {
            optional_seen.get_or_insert(name);
            continue;
        }
        if let Some(earlier) = &optional_seen {
            return Err(invalid(format!(
                "{symbol} has the required parameter '{name}' after the optional '{earlier}'; \
                 the JavaScript harness passes the required parameters in order and leaves the \
                 optional ones out"
            )));
        }
        required.push(name);
    }
    if required.is_empty() {
        return Err(invalid(format!(
            "{symbol} has no required parameter for the fuzz input to go to"
        )));
    }
    // A function with no `@param` line at all (js-yaml's `load(input,
    // options)`, like most JavaScript) takes the input as text in its first
    // parameter; the others are left out, as a JavaScript caller may. The
    // recorded directive shows the choice to the reviewer.
    if documented.is_empty() {
        return Ok(vec![JsInputKind::Text]);
    }
    if required.len() > MAX_PARAMETERS {
        return Err(invalid(format!(
            "{symbol} has {} required parameters; the JavaScript harness fills at most \
             {MAX_PARAMETERS}",
            required.len()
        )));
    }
    required
        .iter()
        .map(|name| {
            let entry = documented.iter().find(|entry| &entry.name == name);
            let Some(entry) = entry else {
                return Err(invalid(format!(
                    "{symbol} does not document the type of '{name}'; JavaScript has no types \
                     to read, so the harness takes each one from a '@param {{type}} {name}' line \
                     in the JSDoc block directly above the function ({SUPPORTED_TYPES})"
                )));
            };
            JsInputKind::documented(&entry.kind).ok_or_else(|| {
                invalid(format!(
                    "{symbol} documents '{name}' as '{}'; the JavaScript harness supports \
                     parameters that are {SUPPORTED_TYPES}",
                    entry.kind
                ))
            })
        })
        .collect()
}

/// The harness target of a discovered JavaScript candidate. `target_source`
/// is the text of the candidate's file, which holds the documentation the
/// parameter types are read from.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the candidate is outside the
/// supported class (a name that is not exported as an identifier, a file the
/// harness cannot name, or an unsupported parameter list).
pub fn target_of(
    candidate: &TargetCandidate,
    target_source: &str,
) -> Result<JsTarget, ClassifiedError> {
    let symbol = candidate.symbol.as_str();
    if !is_identifier(symbol) {
        return Err(invalid(format!(
            "'{symbol}' is not a function a module exports by name; the JavaScript harness \
             supports exported functions, because a method needs an object the harness cannot \
             construct"
        )));
    }
    let file = candidate.relative_file().replace('\\', "/");
    if !is_module_path(&file) {
        return Err(invalid(format!(
            "'{file}' cannot be loaded by the JavaScript harness: the path must stay inside \
             the project, outside {DEPENDENCIES_DIR}, use only letters, digits, and '._-@+' in \
             each component, and end in .js, .mjs, or .cjs"
        )));
    }
    let signature = candidate.signature.as_deref().ok_or_else(|| {
        invalid(format!(
            "{symbol} has no recorded signature to read its parameters from"
        ))
    })?;
    let documented = documented_parameters(target_source, candidate.location.line);
    Ok(JsTarget {
        file,
        export: symbol.to_owned(),
        inputs: input_kinds(signature, &documented, symbol)?,
        expected_errors: module_errors(target_source),
    })
}

/// Most error classes one harness lets pass.
const MAX_EXPECTED_ERRORS: usize = 8;

/// The errors a module rejects an input with: the constructors it defines or
/// binds, named with a capital and ending in `Error` or `Exception` (`class
/// ParseError extends Error`, `function FormatError(...)`, `const
/// YAMLException = require('./exception')`, `import TokenError from ...`).
/// A built-in such as `RangeError` stays a finding even when the module
/// throws it: in JavaScript that marks a bug as often as a rejection, and a
/// helper such as `function throwError(...)` is not a constructor.
#[must_use]
pub fn module_errors(module_source: &str) -> Vec<String> {
    let builtin = [
        "Error",
        "TypeError",
        "RangeError",
        "SyntaxError",
        "ReferenceError",
        "EvalError",
        "URIError",
        "AggregateError",
    ];
    let mut found: Vec<String> = Vec::new();
    let add = |name: &str, found: &mut Vec<String>| {
        if is_identifier(name)
            && !found.iter().any(|seen| seen == name)
            && found.len() < MAX_EXPECTED_ERRORS
        {
            found.push(name.to_owned());
        }
    };
    let leading_name = |text: &str| -> String {
        text.trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect()
    };
    for line in module_source.lines() {
        let line = line.trim_start();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let name = if let Some(rest) = line.strip_prefix("class ") {
            leading_name(rest)
        } else if let Some(rest) = line.strip_prefix("function ") {
            leading_name(rest)
        } else if let Some(rest) = line.strip_prefix("import ") {
            let name = leading_name(rest);
            if rest.contains(" from ") {
                name
            } else {
                String::new()
            }
        } else if let Some(rest) = ["const ", "let ", "var "]
            .iter()
            .find_map(|keyword| line.strip_prefix(keyword))
        {
            let name = leading_name(rest);
            let value = rest[name.len()..]
                .trim_start()
                .strip_prefix('=')
                .unwrap_or_default()
                .trim_start();
            if value.starts_with("require(") || value.starts_with("class") {
                name
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        if name.starts_with(|c: char| c.is_ascii_uppercase())
            && (name.ends_with("Error") || name.ends_with("Exception"))
            && !builtin.contains(&name.as_str())
        {
            add(&name, &mut found);
        }
    }
    found
}

/// Render the harness of one target. The text is a pure function of the
/// target, which is what lets [`lint`] hold a source to it exactly.
///
/// The harness is an ES module that `import()`s the selected module, which
/// is how Jazzer.js instruments an ES module and still instruments a
/// `CommonJS` one; a `CommonJS` module's exports arrive as the default
/// export when Node.js cannot name them. The harness returns what the
/// function returns, so Jazzer.js awaits a promise and reports its
/// rejection like a thrown exception.
#[must_use]
pub fn render(target: &JsTarget) -> String {
    let kinds: Vec<&str> = target.inputs.iter().map(|kind| kind.as_str()).collect();
    let export = target.export.as_str();
    let (provider_import, provider, callback) = match target.inputs.as_slice() {
        [JsInputKind::Bytes] => (
            "",
            String::new(),
            guarded_call(&format!("target.{export}(data)"), target),
        ),
        [JsInputKind::Text] => (
            "",
            String::new(),
            guarded_call(&format!("target.{export}(data.toString('utf-8'))"), target),
        ),
        inputs => {
            let mut body = String::from("  const provider = new FuzzedDataProvider(data);\n");
            let mut names = Vec::with_capacity(inputs.len());
            for (index, kind) in inputs.iter().enumerate() {
                let name = format!("a{index}");
                let _ = writeln!(
                    body,
                    "  const {name} = {};",
                    kind.consume(index + 1 == inputs.len())
                );
                names.push(name);
            }
            body.push_str(&guarded_call(
                &format!("target.{export}({})", names.join(", ")),
                target,
            ));
            (
                "import { createRequire } from 'node:module';\n",
                format!(
                    "const {{ FuzzedDataProvider }} = createRequire(import.meta.url)('{}');\n",
                    hf_engine::jazzerjs::API_MODULE
                ),
                body,
            )
        }
    };
    let expects = if target.expected_errors.is_empty() {
        String::new()
    } else {
        format!(" expects:{}", target.expected_errors.join(","))
    };
    let rejection = if target.expected_errors.is_empty() {
        String::new()
    } else {
        let names = target
            .expected_errors
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "const expected = [{names}];\n\
             function rejection(error) {{\n\
             \x20 const name = error && error.constructor && error.constructor.name;\n\
             \x20 if (!expected.includes(name)) {{\n\
             \x20   throw error;\n\
             \x20 }}\n\
             }}\n"
        )
    };
    format!(
        "{launcher}\
         {directive}{file} {export} {inputs}{expects}\n\
         import fs from 'node:fs';\n\
         {provider_import}\
         import path from 'node:path';\n\
         import {{ pathToFileURL }} from 'node:url';\n\
         \n\
         const here = process.env.{directory};\n\
         const retained = path.join(here, '{retained}');\n\
         const base = fs.existsSync(retained) ? retained : here;\n\
         const loaded = await import(pathToFileURL(path.join(base, '{file}')).href);\n\
         const target = typeof loaded.{export} === 'function' ? loaded : loaded.default;\n\
         if (!target || typeof target.{export} !== 'function') {{\n\
         \x20 throw new Error('oxfuzz: {file} does not export a function named {export}');\n\
         }}\n\
         {provider}\
         {rejection}\
         \n\
         export function fuzz(data) {{\n\
         {callback}\
         }}\n",
        launcher = hf_engine::jazzerjs::launcher_lines(),
        directive = TARGET_DIRECTIVE,
        file = target.file,
        inputs = kinds.join(","),
        directory = hf_engine::jazzerjs::HARNESS_DIR_ENV,
        retained = RETAINED_SOURCES_DIR,
    )
}

/// The call to the target inside `fuzz`: returned as is, or, when the module
/// has expected errors, with those let pass whether thrown or rejected.
fn guarded_call(call: &str, target: &JsTarget) -> String {
    if target.expected_errors.is_empty() {
        return format!("  return {call};\n");
    }
    format!(
        "  try {{\n\
         \x20   const result = {call};\n\
         \x20   if (result && typeof result.then === 'function') {{\n\
         \x20     return result.catch(rejection);\n\
         \x20   }}\n\
         \x20   return result;\n\
         \x20 }} catch (error) {{\n\
         \x20   rejection(error);\n\
         \x20 }}\n"
    )
}

/// The harness for a discovered candidate.
///
/// # Errors
/// See [`target_of`].
pub fn template(
    candidate: &TargetCandidate,
    target_source: &str,
) -> Result<String, ClassifiedError> {
    Ok(render(&target_of(candidate, target_source)?))
}

/// The target a harness source records in its directive line.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the directive is missing or
/// malformed.
pub fn recorded_target(source: &str) -> Result<JsTarget, ClassifiedError> {
    let malformed = || {
        invalid(format!(
            "the JavaScript harness has no well-formed '{}<file> <export> <types>' line",
            TARGET_DIRECTIVE.trim_end()
        ))
    };
    let line = source
        .lines()
        .find_map(|line| line.strip_prefix(TARGET_DIRECTIVE))
        .ok_or_else(malformed)?;
    let fields: Vec<&str> = line.split(' ').collect();
    let (file, export, inputs, expects) = match fields.as_slice() {
        [file, export, inputs] => (file, export, inputs, None),
        [file, export, inputs, expects] => (file, export, inputs, Some(*expects)),
        _ => return Err(malformed()),
    };
    let expected_errors: Vec<String> = match expects {
        None => Vec::new(),
        Some(field) => {
            let names: Vec<String> = field
                .strip_prefix("expects:")
                .ok_or_else(malformed)?
                .split(',')
                .map(str::to_owned)
                .collect();
            if names.len() > MAX_EXPECTED_ERRORS || !names.iter().all(|name| is_identifier(name)) {
                return Err(malformed());
            }
            names
        }
    };
    if !is_module_path(file) || !is_identifier(export) {
        return Err(malformed());
    }
    let inputs = inputs
        .split(',')
        .map(JsInputKind::parse)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(malformed)?;
    if inputs.len() > MAX_PARAMETERS {
        return Err(malformed());
    }
    Ok(JsTarget {
        file: (*file).to_owned(),
        export: (*export).to_owned(),
        inputs,
        expected_errors,
    })
}

/// Hold a harness source to the generated template of the selected function.
///
/// `symbol` is the selected function; empty skips the selection check (a
/// source linted without a target in hand).
#[must_use]
pub fn lint(source: &str, symbol: &str) -> Vec<LintFinding> {
    let finding = |line: usize, rule: &str, message: String| LintFinding {
        severity: LintSeverity::Error,
        rule: rule.to_owned(),
        message,
        line: u32::try_from(line).unwrap_or(u32::MAX),
    };
    let target = match recorded_target(source) {
        Ok(target) => target,
        Err(reason) => return vec![finding(1, "js-target-directive", reason.to_string())],
    };
    let mut findings = Vec::new();
    if !symbol.is_empty() && target.export != symbol {
        findings.push(finding(
            3,
            "js-target-mismatch",
            format!(
                "the harness fuzzes {}, but the selected function is {symbol}",
                target.export
            ),
        ));
    }
    let expected = render(&target);
    let mut expected_lines = expected.lines();
    let mut actual_lines = source.lines();
    let mut number = 0_usize;
    loop {
        number += 1;
        match (expected_lines.next(), actual_lines.next()) {
            (None, None) => break,
            (Some(expected), Some(actual)) if expected == actual.trim_end() => {}
            (None, Some(actual)) if actual.trim().is_empty() => {}
            _ => {
                findings.push(finding(
                    number,
                    "js-fixed-template",
                    format!(
                        "line {number} differs from the generated harness for {} in {}; a \
                         JavaScript harness must be the generated template unchanged",
                        target.export, target.file
                    ),
                ));
                break;
            }
        }
    }
    findings
}

/// The syntax-only build of a harness source: one shell invocation, run with
/// the workspace as its working directory, that has the image's Node.js
/// parse the harness and the selected module and installs the harness as
/// `output_name`. `node --check` compiles without running anything.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the source records no target.
pub fn build_command(source: &str, output_name: &str) -> Result<BuildCommand, ClassifiedError> {
    let target = recorded_target(source)?;
    Ok(BuildCommand {
        compiler: "sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            BUILD_SCRIPT.to_owned(),
            hf_engine::jazzerjs::NODE.to_owned(),
            HARNESS_FILE.to_owned(),
            target.file,
            output_name.to_owned(),
        ],
        output: PathBuf::from(output_name),
        extra_flags: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, Sanitizer, SourceLocation, TargetKind, TargetLanguage};

    const FRAMES: &str = "'use strict';\n\
                          \n\
                          /**\n\
                          \x20* Parse one frame.\n\
                          \x20* @param {Buffer} data the frame\n\
                          \x20* @param {number} depth how deep to go\n\
                          \x20* @param {boolean} [strict] refuse trailing bytes\n\
                          \x20* @returns {number}\n\
                          \x20*/\n\
                          function parse(data, depth, strict) {\n\
                          \x20 return data.length + depth;\n\
                          }\n\
                          \n\
                          function plain(text) {\n\
                          \x20 return text.length;\n\
                          }\n\
                          \n\
                          module.exports = { parse, plain };\n";

    fn candidate(file: &str, symbol: &str, line: u32, signature: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from("/project"),
            language: TargetLanguage::JavaScript,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("/project").join(file),
                line,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: Some(signature.to_owned()),
            input_surface: InputSurface::Bytes,
            complexity: 2,
            fit_score: 0.8,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        }
    }

    fn documented(entries: &[(&str, &str, bool)]) -> Vec<DocumentedParameter> {
        entries
            .iter()
            .map(|(name, kind, optional)| DocumentedParameter {
                name: (*name).to_owned(),
                kind: (*kind).to_owned(),
                optional: *optional,
            })
            .collect()
    }

    #[test]
    fn the_documentation_is_the_block_directly_above_the_function() {
        assert_eq!(
            documented_parameters(FRAMES, 10),
            documented(&[
                ("data", "Buffer", false),
                ("depth", "number", false),
                ("strict", "boolean", true),
            ])
        );
        // No block above: nothing is documented, and a block further up
        // belongs to another function.
        assert!(documented_parameters(FRAMES, 14).is_empty());
        assert!(documented_parameters(FRAMES, 1).is_empty());
        assert!(documented_parameters(FRAMES, 0).is_empty());
        assert!(documented_parameters(FRAMES, 400).is_empty());

        let forms = "/** @param {string} text */\n\
                     function one(text) {}\n\
                     /*\n\
                     \x20* @param {string} text\n\
                     \x20*/\n\
                     function two(text) {}\n\
                     /**\n\
                     \x20* @arg {Uint8Array=} bytes\n\
                     \x20* @argument {string} [name='x'] the name\n\
                     \x20* @param {object} options\n\
                     \x20* @param {number} options.depth\n\
                     \x20* @param text no type\n\
                     \x20* @param { string | null } both\n\
                     \x20*/\n\
                     function three(bytes, name, options, text, both) {}\n";
        assert_eq!(
            documented_parameters(forms, 2),
            documented(&[("text", "string", false)])
        );
        // An ordinary comment is not documentation.
        assert!(documented_parameters(forms, 6).is_empty());
        assert_eq!(
            documented_parameters(forms, 15),
            documented(&[
                ("bytes", "Uint8Array", true),
                ("name", "string", true),
                ("options", "object", false),
                ("both", "string | null", false),
            ])
        );
    }

    #[test]
    fn the_input_kinds_are_the_documented_types_of_the_required_parameters() {
        use JsInputKind::{Boolean, Bytes, Number, Text};
        let docs = documented(&[
            ("data", "Buffer", false),
            ("view", "Uint8Array", false),
            ("text", "string", false),
            ("depth", "Number", false),
            ("strict", "boolean", false),
            ("mode", "string", true),
            ("table", "object", false),
        ]);
        let kinds = |signature: &str| input_kinds(signature, &docs, "parse");
        assert_eq!(kinds("function parse(data)").unwrap(), [Bytes]);
        assert_eq!(kinds("async function parse(text)").unwrap(), [Text]);
        assert_eq!(
            kinds("function parse(view, text, depth, strict)").unwrap(),
            [Bytes, Text, Number, Boolean]
        );
        // A default, a documented optional, and a rest parameter are left out.
        assert_eq!(
            kinds("function parse(data, depth = 4, mode, ...rest)").unwrap(),
            [Bytes]
        );
        assert_eq!(
            kinds("function parse(data, limits = { depth: (1, 2) })").unwrap(),
            [Bytes]
        );
        for (signature, reason) in [
            ("function parse()", "no required parameter"),
            ("function parse(...parts)", "no required parameter"),
            ("function parse(depth = 1)", "no required parameter"),
            (
                "function parse(input)",
                "does not document the type of 'input'",
            ),
            ("function parse(input)", "@param {type} input"),
            (
                "function parse(data, table)",
                "documents 'table' as 'object'",
            ),
            ("function parse({ data })", "destructured"),
            ("function parse([head])", "destructured"),
            ("function parse(mode, data)", "after the optional 'mode'"),
            (
                "function parse(depth = 1, data)",
                "after the optional 'depth'",
            ),
            ("function parse", "no recorded parameter list"),
        ] {
            let error = kinds(signature).unwrap_err().to_string();
            assert!(error.contains(reason), "{signature}: {error}");
        }
        let many = documented(
            &["a", "b", "c", "d", "e", "f", "g", "h", "i"].map(|name| (name, "number", false)),
        );
        let error = input_kinds("function parse(a, b, c, d, e, f, g, h, i)", &many, "parse")
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most 8"), "{error}");
    }

    #[test]
    fn a_module_path_stays_inside_the_project_and_is_plain() {
        for accepted in [
            "index.js",
            "src/frames.js",
            "lib/codec.mjs",
            "lib/@scope/x-y_z+1/a.b.cjs",
        ] {
            assert!(is_module_path(accepted), "{accepted}");
        }
        for refused in [
            "",
            "frames",
            "frames.ts",
            ".js",
            "../frames.js",
            "src/../frames.js",
            "./frames.js",
            "/abs/frames.js",
            "src//frames.js",
            "src/it's.js",
            "src/a b.js",
            "src/a\\b.js",
            "node_modules/pkg/index.js",
            "src/node_modules/pkg/index.js",
        ] {
            assert!(!is_module_path(refused), "{refused}");
        }
        assert!(is_identifier("parse$_1"));
        for refused in ["", "1x", "default", "class", "a.b", "a-b", "pars\u{e9}"] {
            assert!(!is_identifier(refused), "{refused}");
        }
    }

    #[test]
    fn the_template_loads_the_module_and_returns_what_the_function_returns() {
        let text = "/** @param {string} text */\nexport async function decode(text) {}\n";
        let source = template(
            &candidate("src/codec.mjs", "decode", 2, "async function decode(text)"),
            text,
        )
        .unwrap();
        let mut lines = source.lines();
        assert_eq!(lines.next(), Some("#!/bin/sh"));
        assert!(lines.next().unwrap().starts_with("':' //; "));
        assert_eq!(
            lines.next(),
            Some("// oxfuzz:js-target src/codec.mjs decode string")
        );
        for expected in [
            "const here = process.env.OXFUZZ_HARNESS_DIR;\n",
            "const retained = path.join(here, 'source-context');\n",
            "const base = fs.existsSync(retained) ? retained : here;\n",
            // Imported, not required: that is what instruments an ES module.
            "const loaded = await import(pathToFileURL(path.join(base, \
             'src/codec.mjs')).href);\n",
            // A CommonJS module's exports are the default export.
            "const target = typeof loaded.decode === 'function' ? loaded : loaded.default;\n",
            "if (!target || typeof target.decode !== 'function') {\n  throw new \
             Error('oxfuzz: src/codec.mjs does not export a function named decode');\n}\n",
            // The promise is returned, so Jazzer.js awaits it.
            "export function fuzz(data) {\n  return \
             target.decode(data.toString('utf-8'));\n}\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert!(!source.contains("FuzzedDataProvider"));
        assert_eq!(
            recorded_target(&source).unwrap(),
            JsTarget {
                file: "src/codec.mjs".to_owned(),
                export: "decode".to_owned(),
                inputs: vec![JsInputKind::Text],
                expected_errors: Vec::new(),
            }
        );

        let raw = template(
            &candidate(
                "frames.js",
                "parse",
                10,
                "function parse(data, depth, strict)",
            ),
            &FRAMES.replace("@param {number} depth", "@param {number} [depth]"),
        )
        .unwrap();
        assert!(raw.contains("// oxfuzz:js-target frames.js parse buffer\n"));
        assert!(raw.contains("  return target.parse(data);\n"));
    }

    #[test]
    fn a_typed_target_takes_its_arguments_from_the_data_provider() {
        let text = "/**\n\
                    \x20* @param {string} name\n\
                    \x20* @param {number} depth\n\
                    \x20* @param {boolean} strict\n\
                    \x20* @param {Uint8Array} head\n\
                    \x20* @param {Buffer} body\n\
                    \x20*/\n\
                    exports.parse = function (name, depth, strict, head, body) {};\n";
        let source = template(
            &candidate(
                "lib/frames.js",
                "parse",
                8,
                "function parse(name, depth, strict, head, body)",
            ),
            text,
        )
        .unwrap();
        assert!(source.contains(
            "// oxfuzz:js-target lib/frames.js parse string,number,boolean,buffer,buffer\n"
        ));
        for expected in [
            "import { createRequire } from 'node:module';\n",
            "const { FuzzedDataProvider } = \
             createRequire(import.meta.url)('/opt/jazzerjs/node_modules/@jazzer.js/core');\n",
            "export function fuzz(data) {\n  const provider = new FuzzedDataProvider(data);\n",
            "  const a0 = provider.consumeString(provider.consumeIntegralInRange(0, 4096));\n",
            "  const a1 = provider.consumeNumber();\n",
            "  const a2 = provider.consumeBoolean();\n",
            "  const a3 = Buffer.from(provider.consumeBytes(provider.consumeIntegralInRange(0, \
             4096)));\n",
            // The last bytes or text parameter takes whatever is left.
            "  const a4 = Buffer.from(provider.consumeRemainingAsBytes());\n",
            "  return target.parse(a0, a1, a2, a3, a4);\n}\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert!(
            lint(&source, "parse").is_empty(),
            "{:?}",
            lint(&source, "parse")
        );
        let edited = source.replace("consumeNumber()", "consumeIntegral(1)");
        assert_eq!(lint(&edited, "parse")[0].rule, "js-fixed-template");
        let forged = source.replace("string,number,boolean", "string,number,object");
        assert_eq!(lint(&forged, "parse")[0].rule, "js-target-directive");

        let last_text = template(
            &candidate("codec.js", "join", 5, "function join(count, text)"),
            "/**\n * @param {number} count\n * @param {string} text\n */\nfunction join(count, \
             text) {}\n",
        )
        .unwrap();
        assert!(last_text.contains("  const a1 = provider.consumeRemainingAsString();\n"));
    }

    #[test]
    fn a_target_outside_the_class_is_refused_with_its_reason() {
        let refuse = |file: &str, symbol: &str, line: u32, signature: &str| {
            template(&candidate(file, symbol, line, signature), FRAMES)
                .unwrap_err()
                .to_string()
        };
        let method = refuse("frames.js", "Codec.decode", 10, "function decode(data)");
        assert!(
            method.contains("not a function a module exports by name"),
            "{method}"
        );
        let path = refuse("my tool/run.js", "parse", 10, "function parse(data)");
        assert!(
            path.contains("cannot be loaded by the JavaScript harness"),
            "{path}"
        );
    }

    #[test]
    fn an_undocumented_function_takes_the_input_as_text_in_its_first_parameter() {
        // js-yaml 4.1.0: `function load(input, options)` has no JSDoc, like
        // most real JavaScript, and was refused. With no `@param` line at all,
        // the first parameter takes the input as a string and the rest are
        // left out, as a JavaScript caller may; the directive shows the
        // choice to the reviewer.
        let plain = template(
            &candidate("frames.js", "plain", 14, "function plain(text)"),
            FRAMES,
        )
        .unwrap();
        assert!(plain.contains(" frames.js plain string\n"), "{plain}");
        assert!(
            plain.contains("  return target.plain(data.toString('utf-8'));\n"),
            "{plain}"
        );

        let loader = "var YAMLException = require('./exception');\n\
                      function load(input, options) {\n  throw new YAMLException('bad');\n}\n\
                      module.exports.load = load;\n";
        let source = template(
            &candidate("lib/loader.js", "load", 2, "function load(input, options)"),
            loader,
        )
        .unwrap();
        assert!(
            source.contains(" lib/loader.js load string expects:YAMLException\n"),
            "{source}"
        );
        for expected in [
            "const expected = ['YAMLException'];\n",
            "  try {\n    const result = target.load(data.toString('utf-8'));\n",
            "      return result.catch(rejection);\n",
            "  } catch (error) {\n    rejection(error);\n  }\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert_eq!(render(&recorded_target(&source).unwrap()), source);
        assert!(
            lint(&source, "load").is_empty(),
            "{:?}",
            lint(&source, "load")
        );
        // A partly documented function still names the parameter it lacks.
        let partly = template(
            &candidate(
                "frames.js",
                "parse",
                10,
                "function parse(data, depth, extra, strict)",
            ),
            FRAMES,
        )
        .unwrap_err()
        .to_string();
        assert!(
            partly.contains("does not document the type of 'extra'"),
            "{partly}"
        );
    }

    #[test]
    fn the_modules_own_error_classes_are_expected() {
        let source = "const YAMLException = require('./exception');\n\
                      class ParseError extends Error {}\n\
                      function FormatError(message) { this.message = message; }\n\
                      import TokenError from './token.js';\n\
                      function throwError(state, message) { throw generateError(state, message); }\n\
                      const limit = () => { throw new RangeError('deep'); };\n";
        assert_eq!(
            super::module_errors(source),
            ["YAMLException", "ParseError", "FormatError", "TokenError"]
        );
    }

    #[test]
    fn lint_accepts_only_the_generated_template_of_the_selected_function() {
        let source = template(
            &candidate(
                "frames.js",
                "parse",
                10,
                "function parse(data, depth, strict)",
            ),
            FRAMES,
        )
        .unwrap();
        assert!(
            lint(&source, "parse").is_empty(),
            "{:?}",
            lint(&source, "parse")
        );
        assert!(lint(&format!("{source}\n"), "parse").is_empty());

        let other = lint(&source, "decode");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].rule, "js-target-mismatch");

        let edited = source.replace(
            "  return target.parse(a0, a1);\n",
            "  try { return target.parse(a0, a1); } catch (error) {}\n",
        );
        assert_ne!(edited, source);
        let findings = lint(&edited, "parse");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "js-fixed-template");

        let appended = format!("{source}import 'node:child_process';\n");
        assert_eq!(lint(&appended, "parse")[0].rule, "js-fixed-template");
        // The launcher line is part of the fixed text.
        let other_launcher = source.replace("exec jazzer-js", "exec sh");
        assert_eq!(lint(&other_launcher, "parse")[0].rule, "js-fixed-template");
        assert_eq!(lint(&other_launcher, "parse")[0].line, 2);

        let missing = lint("export function fuzz() {}\n", "parse");
        assert_eq!(missing[0].rule, "js-target-directive");
        let traversal = source.replace("js-target frames.js", "js-target ../frames.js");
        assert_eq!(lint(&traversal, "parse")[0].rule, "js-target-directive");
        let quoted = source.replace("js-target frames.js", "js-target a');x('.js");
        assert_eq!(lint(&quoted, "parse")[0].rule, "js-target-directive");
    }

    #[test]
    fn the_build_parses_without_loading_and_installs_the_harness() {
        let source = template(
            &candidate(
                "frames.js",
                "parse",
                10,
                "function parse(data, depth, strict)",
            ),
            FRAMES,
        )
        .unwrap();
        let build = build_command(&source, "fuzz_parse").unwrap();
        assert_eq!(build.compiler, "sh");
        assert_eq!(build.args[0], "-c");
        assert!(build.args[1].contains("\"$0\" --check \"$1\" && \"$0\" --check \"$2\""));
        assert!(build.args[1].contains("cp \"$1\" \"$3\" && chmod 755 \"$3\""));
        assert!(!build.args[1].contains("require"));
        assert_eq!(
            &build.args[2..],
            [
                "/opt/node/bin/node",
                "harness.mjs",
                "frames.js",
                "fuzz_parse"
            ]
        );
        assert_eq!(build.output, PathBuf::from("fuzz_parse"));
        assert!(build_command("console.log(1);\n", "fuzz_parse").is_err());
    }
}
