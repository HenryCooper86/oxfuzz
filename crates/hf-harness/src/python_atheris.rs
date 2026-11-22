//! Python (Atheris) harness: the fixed template, its lint, and the
//! syntax-only build.
//!
//! The supported target class is a top-level synchronous function of an
//! importable pure-Python module whose required parameters each take
//! `bytes`, `str`, `int`, `float`, or `bool`. One `bytes` or `str` parameter
//! gets the fuzz input itself; any other accepted list is filled from the
//! input by `atheris.FuzzedDataProvider`. Pure-Python third-party packages
//! the project vendors under `vendor/python` are importable. The harness is
//! generated from the selected function alone, with
//! no model call, and the lint accepts nothing but that generated text: a
//! Python harness runs with the interpreter's full power the moment it is
//! imported, so there is no reviewed subset of edits to allow yet.
//! See `docs/design/python-atheris-fuzzing-design.md`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::harness::BuildCommand;
use hf_core::target::TargetCandidate;

use crate::lint::{LintFinding, LintSeverity};

/// The harness source file written at the workspace root for the build.
pub const HARNESS_FILE: &str = "harness.py";

/// The directive line that records what the harness fuzzes:
/// `# oxfuzz:python-target <root> <module>:<function> <types>`, where
/// `<types>` is the comma-separated list of what each required parameter
/// takes (`bytes`, `str`, `int`, `float`, `bool`).
pub const TARGET_DIRECTIVE: &str = "# oxfuzz:python-target ";

/// The directory beside a run's harness script that holds the run's retained
/// project sources. When it exists the script imports from it, so a run and
/// its historical replay use the sources captured at run start.
pub const RETAINED_SOURCES_DIR: &str = "source-context";

/// Where a project keeps the pure-Python third-party packages its modules
/// import (`pip install --target vendor/python ...`). The directory is
/// staged with the project like any other source and is searched after the
/// project's own import root. Nothing is installed or downloaded.
pub const VENDORED_PACKAGES_DIR: &str = "vendor/python";

/// The most bytes a `bytes` or `str` argument that is not the last one
/// takes; the last one takes whatever input is left.
const MAX_INNER_ARGUMENT_BYTES: u32 = 4096;

/// A source directory that is itself the import root (`src/pkg/mod.py` is the
/// module `pkg.mod`).
const SOURCE_ROOT: &str = "src";

/// Marks "the project root is the import root" in the directive.
const PROJECT_ROOT_MARK: &str = ".";

/// Parses the harness and the selected module without importing either, then
/// installs the harness as an executable script. Importing is execution and
/// waits for the smoke approval; a syntax error fails here instead.
const BUILD_SCRIPT: &str = r#"import ast, os, shutil, sys
harness, output, base = sys.argv[1], sys.argv[2], sys.argv[3]
def check(path):
    with open(path, encoding="utf-8") as handle:
        ast.parse(handle.read(), path)
check(harness)
candidates = [base + ".py", os.path.join(base, "__init__.py")]
found = [path for path in candidates if os.path.isfile(path)]
if not found:
    sys.exit("oxfuzz: the selected module is not in the staged project: " + " or ".join(candidates))
check(found[0])
shutil.copyfile(harness, output)
os.chmod(output, 0o755)
"#;

const KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

fn invalid(message: String) -> ClassifiedError {
    ClassifiedError::Validation(message)
}

/// What the fuzz callback hands the selected function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonInputKind {
    /// The raw fuzz input.
    Bytes,
    /// The input decoded as UTF-8 with replacement.
    Text,
    /// A signed 64-bit integer taken from the input.
    Int,
    /// A float taken from the input, including infinities and NaN.
    Float,
    /// One bit of the input.
    Bool,
}

impl PythonInputKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Text => "str",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "bytes" => Some(Self::Bytes),
            "str" => Some(Self::Text),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "bool" => Some(Self::Bool),
            _ => None,
        }
    }

    /// The expression that takes this argument from the data provider. The
    /// last parameter takes all remaining input when it is bytes or text.
    fn consume(self, last: bool) -> String {
        let length = if last {
            "provider.remaining_bytes()".to_owned()
        } else {
            format!("provider.ConsumeIntInRange(0, {MAX_INNER_ARGUMENT_BYTES})")
        };
        match self {
            Self::Bytes => format!("provider.ConsumeBytes({length})"),
            Self::Text => format!("provider.ConsumeUnicodeNoSurrogates({length})"),
            Self::Int => "provider.ConsumeInt(8)".to_owned(),
            Self::Float => "provider.ConsumeFloat()".to_owned(),
            Self::Bool => "provider.ConsumeBool()".to_owned(),
        }
    }
}

/// The function one harness fuzzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonTarget {
    /// The import root relative to the project root: empty or `src`.
    pub root: String,
    /// The dotted module path, e.g. `pkg.frames`.
    pub module: String,
    /// The top-level function name.
    pub function: String,
    /// What each of the function's required parameters takes, in order.
    pub inputs: Vec<PythonInputKind>,
}

impl PythonTarget {
    /// The module's path below the workspace without a suffix, e.g.
    /// `src/pkg/frames`; the module is that path plus `.py`, or the package
    /// `__init__.py` inside it.
    #[must_use]
    pub fn module_base(&self) -> String {
        let module = self.module.replace('.', "/");
        if self.root.is_empty() {
            module
        } else {
            format!("{}/{module}", self.root)
        }
    }
}

/// Whether `text` is an ASCII Python identifier that is not a keyword.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !KEYWORDS.contains(&text)
}

/// The import root and dotted module path of a project-relative `.py` file.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the path is not a `.py` file
/// whose every component is an importable name.
pub fn module_of(relative_file: &Path) -> Result<(String, String), ClassifiedError> {
    let refuse = || {
        invalid(format!(
            "'{}' is not importable as a module: every path component must be a Python \
             identifier and the file must end in .py",
            relative_file.display()
        ))
    };
    if relative_file.extension().and_then(|value| value.to_str()) != Some("py") {
        return Err(refuse());
    }
    let mut parts = Vec::new();
    for component in relative_file.with_extension("").components() {
        let std::path::Component::Normal(part) = component else {
            return Err(refuse());
        };
        parts.push(part.to_str().ok_or_else(refuse)?.to_owned());
    }
    let root = if parts.len() > 1 && parts[0] == SOURCE_ROOT {
        parts.remove(0);
        SOURCE_ROOT.to_owned()
    } else {
        String::new()
    };
    if parts.last().is_some_and(|last| last == "__init__") {
        parts.pop();
    }
    if parts.is_empty() || !parts.iter().all(|part| is_identifier(part)) {
        return Err(refuse());
    }
    Ok((root, parts.join(".")))
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
/// from its `def` line.
///
/// # Errors
/// Returns `ClassifiedError::Validation` naming the reason the function is
/// outside the supported class.
pub fn input_kinds(signature: &str, symbol: &str) -> Result<Vec<PythonInputKind>, ClassifiedError> {
    let signature = signature.trim();
    if signature.starts_with("async ") {
        return Err(invalid(format!(
            "{symbol} is an async function; the Python harness calls synchronous functions only"
        )));
    }
    let parameters = parameter_list(signature).ok_or_else(|| {
        invalid(format!(
            "the parameter list of {symbol} does not fit on its def line, so its input type \
             cannot be read"
        ))
    })?;
    let mut required = Vec::new();
    let mut keyword_only = false;
    for parameter in split_parameters(parameters) {
        if parameter == "/" {
            continue;
        }
        if parameter == "*" {
            keyword_only = true;
            continue;
        }
        if parameter.starts_with('*') {
            // *args and **kwargs take nothing by default.
            keyword_only = true;
            continue;
        }
        if parameter.contains('=') {
            continue;
        }
        if keyword_only {
            return Err(invalid(format!(
                "{symbol} has the required keyword-only parameter '{parameter}'; the Python \
                 harness passes positional arguments"
            )));
        }
        required.push(parameter);
    }
    if required.is_empty() {
        return Err(invalid(format!(
            "{symbol} has no required parameter for the fuzz input to go to"
        )));
    }
    required
        .iter()
        .map(|parameter| {
            let annotation = parameter.split_once(':').map(|(_, kind)| kind.trim());
            match annotation {
                None | Some("bytes" | "bytearray" | "memoryview") => Ok(PythonInputKind::Bytes),
                Some("str") => Ok(PythonInputKind::Text),
                Some("int") => Ok(PythonInputKind::Int),
                Some("float") => Ok(PythonInputKind::Float),
                Some("bool") => Ok(PythonInputKind::Bool),
                Some(other) => Err(invalid(format!(
                    "{symbol} takes '{other}'; the Python harness supports parameters that are \
                     bytes, str, int, float, bool, or unannotated"
                ))),
            }
        })
        .collect()
}

/// The harness target of a discovered Python candidate.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the candidate is outside the
/// supported class (a method, an async function, an unsupported parameter
/// list, or a file that is not importable by path).
pub fn target_of(candidate: &TargetCandidate) -> Result<PythonTarget, ClassifiedError> {
    let symbol = candidate.symbol.as_str();
    if symbol.contains('.') {
        return Err(invalid(format!(
            "{symbol} is a method; the Python harness supports top-level functions, because a \
             method needs an object the harness cannot construct"
        )));
    }
    if !is_identifier(symbol) {
        return Err(invalid(format!("'{symbol}' is not a Python function name")));
    }
    let (root, module) = module_of(Path::new(&candidate.relative_file()))?;
    let signature = candidate.signature.as_deref().ok_or_else(|| {
        invalid(format!(
            "{symbol} has no recorded signature to read its input type from"
        ))
    })?;
    Ok(PythonTarget {
        root,
        module,
        function: symbol.to_owned(),
        inputs: input_kinds(signature, symbol)?,
    })
}

/// Render the harness script of one target. The text is a pure function of
/// the target, which is what lets [`lint`] hold a source to it exactly.
#[must_use]
pub fn render(target: &PythonTarget) -> String {
    let root_mark = if target.root.is_empty() {
        PROJECT_ROOT_MARK
    } else {
        target.root.as_str()
    };
    let import_root = if target.root.is_empty() {
        "_base".to_owned()
    } else {
        format!("os.path.join(_base, \"{}\")", target.root)
    };
    let kinds: Vec<&str> = target.inputs.iter().map(|kind| kind.as_str()).collect();
    let callback = match target.inputs.as_slice() {
        [PythonInputKind::Bytes] => {
            format!("\x20   oxfuzz_target.{}(data)\n", target.function)
        }
        [PythonInputKind::Text] => format!(
            "\x20   oxfuzz_target.{}(data.decode(\"utf-8\", \"replace\"))\n",
            target.function
        ),
        inputs => {
            let mut body = String::from("\x20   provider = atheris.FuzzedDataProvider(data)\n");
            let mut names = Vec::with_capacity(inputs.len());
            for (index, kind) in inputs.iter().enumerate() {
                let name = format!("a{index}");
                let _ = writeln!(
                    body,
                    "\x20   {name} = {}",
                    kind.consume(index + 1 == inputs.len())
                );
                names.push(name);
            }
            let _ = writeln!(
                body,
                "\x20   oxfuzz_target.{}({})",
                target.function,
                names.join(", ")
            );
            body
        }
    };
    let vendored = VENDORED_PACKAGES_DIR
        .split('/')
        .map(|part| format!("\"{part}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{interpreter}\n\
         {directive}{root_mark} {module}:{function} {input}\n\
         import os\n\
         import sys\n\
         \n\
         _here = os.path.dirname(os.path.abspath(__file__))\n\
         _retained = os.path.join(_here, \"{retained}\")\n\
         _base = _retained if os.path.isdir(_retained) else _here\n\
         sys.path.insert(0, {import_root})\n\
         sys.path.insert(1, os.path.join(_base, {vendored}))\n\
         \n\
         import atheris\n\
         \n\
         with atheris.instrument_imports():\n\
         \x20   import {module} as oxfuzz_target\n\
         \n\
         \n\
         def TestOneInput(data):\n\
         {callback}\
         \n\
         \n\
         atheris.Setup(sys.argv, TestOneInput)\n\
         atheris.Fuzz()\n",
        interpreter = hf_engine::atheris::INTERPRETER_LINE,
        directive = TARGET_DIRECTIVE,
        module = target.module,
        function = target.function,
        input = kinds.join(","),
        retained = RETAINED_SOURCES_DIR,
    )
}

/// The harness for a discovered candidate.
///
/// # Errors
/// See [`target_of`].
pub fn template(candidate: &TargetCandidate) -> Result<String, ClassifiedError> {
    Ok(render(&target_of(candidate)?))
}

/// The target a harness source records in its directive line.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the directive is missing or
/// malformed.
pub fn recorded_target(source: &str) -> Result<PythonTarget, ClassifiedError> {
    let malformed = || {
        invalid(format!(
            "the Python harness has no well-formed '{}<root> <module>:<function> <types>' line",
            TARGET_DIRECTIVE.trim_end()
        ))
    };
    let line = source
        .lines()
        .find_map(|line| line.strip_prefix(TARGET_DIRECTIVE))
        .ok_or_else(malformed)?;
    let fields: Vec<&str> = line.split(' ').collect();
    let [root, target, input] = fields.as_slice() else {
        return Err(malformed());
    };
    let root = match *root {
        PROJECT_ROOT_MARK => String::new(),
        SOURCE_ROOT => SOURCE_ROOT.to_owned(),
        _ => return Err(malformed()),
    };
    let (module, function) = target.split_once(':').ok_or_else(malformed)?;
    if !module.split('.').all(is_identifier) || !is_identifier(function) {
        return Err(malformed());
    }
    Ok(PythonTarget {
        root,
        module: module.to_owned(),
        function: function.to_owned(),
        inputs: input
            .split(',')
            .map(PythonInputKind::parse)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?,
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
        Err(reason) => return vec![finding(1, "python-target-directive", reason.to_string())],
    };
    let mut findings = Vec::new();
    if !symbol.is_empty() && target.function != symbol {
        findings.push(finding(
            2,
            "python-target-mismatch",
            format!(
                "the harness fuzzes {}, but the selected function is {symbol}",
                target.function
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
                    "python-fixed-template",
                    format!(
                        "line {number} differs from the generated harness for {}:{}; a Python \
                         harness must be the generated template unchanged",
                        target.module, target.function
                    ),
                ));
                break;
            }
        }
    }
    findings
}

/// The syntax-only build of a harness source: one interpreter invocation,
/// run with the workspace as its working directory, that parses the harness
/// and the selected module and installs the harness as `output_name`.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the source records no target.
pub fn build_command(source: &str, output_name: &str) -> Result<BuildCommand, ClassifiedError> {
    let target = recorded_target(source)?;
    Ok(BuildCommand {
        compiler: "python3".to_owned(),
        args: vec![
            "-I".to_owned(),
            "-c".to_owned(),
            BUILD_SCRIPT.to_owned(),
            HARNESS_FILE.to_owned(),
            output_name.to_owned(),
            target.module_base(),
        ],
        output: PathBuf::from(output_name),
        extra_flags: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, Sanitizer, SourceLocation, TargetKind, TargetLanguage};

    fn candidate(file: &str, symbol: &str, signature: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from("/project"),
            language: TargetLanguage::Python,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("/project").join(file),
                line: 3,
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

    #[test]
    fn a_module_path_comes_from_the_file_and_a_src_root_is_the_import_root() {
        let module = |path: &str| module_of(Path::new(path)).unwrap();
        assert_eq!(module("codec.py"), (String::new(), "codec".to_owned()));
        assert_eq!(
            module("pkg/frames.py"),
            (String::new(), "pkg.frames".to_owned())
        );
        assert_eq!(module("pkg/__init__.py"), (String::new(), "pkg".to_owned()));
        assert_eq!(
            module("src/pkg/frames.py"),
            ("src".to_owned(), "pkg.frames".to_owned())
        );
        for refused in [
            "my-tool/run.py",
            "pkg/class.py",
            "pkg/frames.txt",
            "__init__.py",
            "../x.py",
            "3d/mesh.py",
        ] {
            assert!(module_of(Path::new(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn the_input_kinds_are_read_from_the_required_parameters() {
        use PythonInputKind::{Bool, Bytes, Float, Int, Text};
        let kinds = |signature: &str| input_kinds(signature, "parse");
        assert_eq!(kinds("def parse(data)").unwrap(), [Bytes]);
        assert_eq!(
            kinds("def parse(data: bytes, strict=False) -> int").unwrap(),
            [Bytes]
        );
        assert_eq!(
            kinds("def parse(text: str, *, limit: int = 4, **options)").unwrap(),
            [Text]
        );
        assert_eq!(kinds("def parse(data, /, table=(1, 2))").unwrap(), [Bytes]);
        // Every required parameter is supplied; the ones with defaults are
        // left to their defaults.
        assert_eq!(
            kinds("def parse(name: str, depth: int, strict: bool, scale: float, body: bytes)")
                .unwrap(),
            [Text, Int, Bool, Float, Bytes]
        );
        assert_eq!(
            kinds("def parse(data, size: int, mode=0)").unwrap(),
            [Bytes, Int]
        );
        for (signature, reason) in [
            ("async def parse(data)", "async"),
            ("def parse(*parts)", "no required parameter"),
            ("def parse(mode=0)", "no required parameter"),
            ("def parse(data: dict[str, int])", "dict[str, int]"),
            ("def parse(data: bytes, table: list[int])", "list[int]"),
            ("def parse(data, *, strict)", "keyword-only"),
            ("def parse(", "def line"),
        ] {
            let error = kinds(signature).unwrap_err().to_string();
            assert!(error.contains(reason), "{signature}: {error}");
        }
    }

    #[test]
    fn a_typed_target_takes_its_arguments_from_a_data_provider() {
        let source = template(&candidate(
            "pkg/frames.py",
            "parse",
            "def parse(name: str, depth: int, strict: bool, scale: float, head: bytes, body: bytes)",
        ))
        .unwrap();
        assert!(source.contains(
            "# oxfuzz:python-target . pkg.frames:parse str,int,bool,float,bytes,bytes\n"
        ));
        for expected in [
            "def TestOneInput(data):\n    provider = atheris.FuzzedDataProvider(data)\n",
            "    a0 = provider.ConsumeUnicodeNoSurrogates(provider.ConsumeIntInRange(0, 4096))\n",
            "    a1 = provider.ConsumeInt(8)\n",
            "    a2 = provider.ConsumeBool()\n",
            "    a3 = provider.ConsumeFloat()\n",
            "    a4 = provider.ConsumeBytes(provider.ConsumeIntInRange(0, 4096))\n",
            // The last bytes or str parameter takes whatever is left.
            "    a5 = provider.ConsumeBytes(provider.remaining_bytes())\n",
            "    oxfuzz_target.parse(a0, a1, a2, a3, a4, a5)\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        // The generated text is what the directive says, so lint holds it.
        assert!(
            lint(&source, "parse").is_empty(),
            "{:?}",
            lint(&source, "parse")
        );
        assert_eq!(
            recorded_target(&source).unwrap().inputs,
            [
                PythonInputKind::Text,
                PythonInputKind::Int,
                PythonInputKind::Bool,
                PythonInputKind::Float,
                PythonInputKind::Bytes,
                PythonInputKind::Bytes
            ]
        );
        let edited = source.replace("ConsumeInt(8)", "ConsumeInt(1)");
        assert_eq!(lint(&edited, "parse")[0].rule, "python-fixed-template");
        let forged = source.replace("str,int,bool", "str,int,dict");
        assert_eq!(lint(&forged, "parse")[0].rule, "python-target-directive");

        // One scalar parameter is a typed target too; one bytes or str
        // parameter still gets the raw input.
        let scalar = template(&candidate("codec.py", "level", "def level(n: int)")).unwrap();
        assert!(scalar.contains("    a0 = provider.ConsumeInt(8)\n    oxfuzz_target.level(a0)\n"));
        let last_text = template(&candidate(
            "codec.py",
            "join",
            "def join(n: int, text: str)",
        ))
        .unwrap();
        assert!(last_text.contains(
            "    a1 = provider.ConsumeUnicodeNoSurrogates(provider.remaining_bytes())\n"
        ));
        let raw = template(&candidate("codec.py", "decode", "def decode(data)")).unwrap();
        assert!(raw.contains("    oxfuzz_target.decode(data)\n"));
        assert!(!raw.contains("FuzzedDataProvider"));
    }

    #[test]
    fn vendored_packages_are_importable_after_the_project() {
        let source = template(&candidate("src/pkg/frames.py", "parse", "def parse(data)")).unwrap();
        // The project's own modules win over a vendored package of the same
        // name; the vendored directory is searched before the interpreter's.
        assert!(source.contains(
            "sys.path.insert(0, os.path.join(_base, \"src\"))\n\
             sys.path.insert(1, os.path.join(_base, \"vendor\", \"python\"))\n"
        ));
        assert_eq!(VENDORED_PACKAGES_DIR, "vendor/python");
    }

    #[test]
    fn the_template_imports_the_module_under_instrumentation_and_calls_the_function() {
        let source = template(&candidate(
            "src/pkg/frames.py",
            "parse",
            "def parse(text: str)",
        ))
        .unwrap();
        assert!(source.starts_with("#!/usr/bin/python3 -I\n"), "{source}");
        assert!(source.contains("# oxfuzz:python-target src pkg.frames:parse str\n"));
        assert!(source.contains("sys.path.insert(0, os.path.join(_base, \"src\"))\n"));
        assert!(source.contains(
            "with atheris.instrument_imports():\n    import pkg.frames as oxfuzz_target\n"
        ));
        assert!(source.contains(
            "def TestOneInput(data):\n    oxfuzz_target.parse(data.decode(\"utf-8\", \"replace\"))\n"
        ));
        assert!(source.ends_with("atheris.Setup(sys.argv, TestOneInput)\natheris.Fuzz()\n"));
        assert_eq!(
            recorded_target(&source).unwrap(),
            PythonTarget {
                root: "src".to_owned(),
                module: "pkg.frames".to_owned(),
                function: "parse".to_owned(),
                inputs: vec![PythonInputKind::Text],
            }
        );

        let flat = template(&candidate("codec.py", "decode", "def decode(data)")).unwrap();
        assert!(flat.contains("# oxfuzz:python-target . codec:decode bytes\n"));
        assert!(flat.contains("sys.path.insert(0, _base)\n"));
        assert!(flat.contains("    oxfuzz_target.decode(data)\n"));
    }

    #[test]
    fn a_method_or_an_unimportable_file_is_refused_with_its_reason() {
        let method = template(&candidate(
            "codec.py",
            "Codec.decode",
            "def decode(self, data)",
        ))
        .unwrap_err()
        .to_string();
        assert!(method.contains("is a method"), "{method}");
        let path = template(&candidate("my-tool/run.py", "run", "def run(data)"))
            .unwrap_err()
            .to_string();
        assert!(path.contains("not importable as a module"), "{path}");
    }

    #[test]
    fn lint_accepts_only_the_generated_template_of_the_selected_function() {
        let source = template(&candidate("pkg/frames.py", "parse", "def parse(data)")).unwrap();
        assert!(lint(&source, "parse").is_empty());
        assert!(lint(&format!("{source}\n"), "parse").is_empty());

        let other = lint(&source, "decode");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].rule, "python-target-mismatch");

        let edited = source.replace(
            "    oxfuzz_target.parse(data)\n",
            "    try:\n        oxfuzz_target.parse(data)\n    except Exception:\n        pass\n",
        );
        let findings = lint(&edited, "parse");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "python-fixed-template");
        assert_eq!(findings[0].line, 19);

        let appended = format!("{source}import subprocess\n");
        assert_eq!(lint(&appended, "parse")[0].rule, "python-fixed-template");

        let other_interpreter = source.replace("#!/usr/bin/python3 -I", "#!/bin/sh");
        assert_eq!(
            lint(&other_interpreter, "parse")[0].rule,
            "python-fixed-template"
        );

        let missing = lint("import atheris\n", "parse");
        assert_eq!(missing[0].rule, "python-target-directive");
        let traversal = source.replace("pkg.frames:parse", "pkg/../x:parse");
        assert_eq!(lint(&traversal, "parse")[0].rule, "python-target-directive");
    }

    #[test]
    fn the_build_parses_without_importing_and_installs_the_script() {
        let source = template(&candidate("src/pkg/frames.py", "parse", "def parse(data)")).unwrap();
        let build = build_command(&source, "fuzz_parse").unwrap();
        assert_eq!(build.compiler, "python3");
        assert_eq!(build.args[0], "-I");
        assert_eq!(build.args[1], "-c");
        assert!(build.args[2].contains("ast.parse"));
        assert!(!build.args[2].contains("import_module"));
        assert_eq!(
            &build.args[3..],
            ["harness.py", "fuzz_parse", "src/pkg/frames"]
        );
        assert_eq!(build.output, PathBuf::from("fuzz_parse"));
        assert!(build_command("print(1)\n", "fuzz_parse").is_err());
    }
}
