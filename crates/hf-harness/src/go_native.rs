//! Go native fuzz test source: its fixed names, the template, the build
//! command, and the checks specific to Go.
//!
//! See `docs/design/go-native-fuzzing-design.md`. A Go harness is one
//! `FuzzXxx(*testing.F)` function in a `_test.go` file placed beside the
//! selected function's package, inside the staged copy of the module (never
//! the operator's checkout). It is compiled with `go test -c -fuzz=...`, which
//! links fuzz instrumentation in without running any test, and the compiled
//! test binary is what smoke runs and campaigns execute.
//!
//! The supported target class is a package-level exported function whose
//! parameters are each `[]byte`, `string`, `bool`, an integer type, a float
//! type, or an `any` (`interface{}`) decode destination, at least one of
//! them read from the input. A function taking exactly one `[]byte` or `string` is fuzzed
//! with that Go type directly; any other accepted parameter list is filled
//! from one `[]byte` fuzz input by a small decoder written into the harness,
//! so the corpus format is the same for every Go target.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::harness::BuildCommand;
use hf_core::target::TargetCandidate;
use hf_crash::go_corpus::GoInputKind;

use crate::lint::{LintFinding, LintSeverity};

/// The harness file name. The `_test.go` suffix makes it a test file of the
/// package it is placed in, so it is compiled only by `go test`.
pub const HARNESS_FILE: &str = "oxfuzz_fuzz_test.go";

/// The source line that records which package directory (relative to the
/// module root, `.` for the root package) the harness is compiled in. It is
/// part of the reviewed source, so the directory a build runs in is decided
/// by text the reviewer saw.
pub const PACKAGE_DIR_DIRECTIVE: &str = "// oxfuzz:package-dir ";

/// Where the sandbox mounts the workspace.
const CONTAINER_WORKSPACE: &str = "/work";

/// Go's build cache and module path for one build, in the container's own
/// temporary directory: discarded with the container, so a build leaves only
/// the test binary in the workspace and every build starts from the staged
/// sources alone.
const GO_CACHE_DIR: &str = "/tmp/oxfuzz-go";

fn invalid(message: String) -> ClassifiedError {
    ClassifiedError::Harness(message)
}

/// Whether `symbol` is an exported Go identifier this path accepts: an ASCII
/// uppercase letter followed by ASCII letters, digits, or underscores. Go
/// also exports identifiers starting with a non-ASCII uppercase letter; those
/// are not accepted, because the symbol becomes part of a file name and a
/// test-name pattern.
#[must_use]
pub fn is_exported_symbol(symbol: &str) -> bool {
    let mut chars = symbol.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && symbol.len() <= 128
}

/// The fuzz test name for `symbol`: `Fuzz<Symbol>`.
#[must_use]
pub fn fuzz_test_name(symbol: &str) -> String {
    format!("Fuzz{symbol}")
}

/// The Go type of the single parameter of `signature`, when the function is
/// in the supported class: exactly one parameter of type `[]byte` or
/// `string`, and no receiver or type parameters.
#[must_use]
pub fn input_kind(signature: &str, symbol: &str) -> Option<GoInputKind> {
    let rest = signature.trim().strip_prefix("func")?.trim_start();
    // A method has its receiver here; a generic function has `[T any]` after
    // the name. Neither is in the supported class.
    let rest = rest.strip_prefix(symbol)?.trim_start();
    let rest = rest.strip_prefix('(')?;
    let close = rest.find(')')?;
    let parameters = rest[..close].trim();
    if parameters.contains(',') || parameters.contains("...") {
        return None;
    }
    let mut words = parameters.split_whitespace();
    let (first, second, third) = (words.next()?, words.next(), words.next());
    if third.is_some() {
        return None;
    }
    // `name type`, or an unnamed parameter that is only a type.
    let parameter_type = second.unwrap_or(first);
    match parameter_type {
        "[]byte" => Some(GoInputKind::Bytes),
        "string" => Some(GoInputKind::String),
        _ => None,
    }
}

/// One parameter of a Go function in the supported class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoParameter {
    Bytes,
    String,
    Bool,
    /// An integer type and the number of input bytes it is built from.
    Integer {
        name: &'static str,
        bytes: u8,
    },
    /// A float type and the number of input bytes its bits are read from.
    Float {
        name: &'static str,
        bytes: u8,
    },
    /// An `any` or `interface{}` parameter: the value a decoder fills
    /// (`json.Unmarshal(data, v)`). It reads no input and is passed a fresh
    /// `*map[string]interface{}`, which JSON, TOML and YAML decoders accept.
    Destination,
}

/// Integer types the decoder can build, with the input bytes each takes.
const INTEGER_TYPES: [(&str, u8); 12] = [
    ("int", 8),
    ("int8", 1),
    ("int16", 2),
    ("int32", 4),
    ("int64", 8),
    ("uint", 8),
    ("uint8", 1),
    ("uint16", 2),
    ("uint32", 4),
    ("uint64", 8),
    ("byte", 1),
    ("rune", 4),
];

impl GoParameter {
    fn of_type(name: &str) -> Option<Self> {
        match name {
            "[]byte" => Some(Self::Bytes),
            "string" => Some(Self::String),
            "bool" => Some(Self::Bool),
            "float32" => Some(Self::Float {
                name: "float32",
                bytes: 4,
            }),
            "float64" => Some(Self::Float {
                name: "float64",
                bytes: 8,
            }),
            "any" | "interface{}" => Some(Self::Destination),
            _ => INTEGER_TYPES
                .iter()
                .find(|(integer, _)| *integer == name)
                .map(|&(name, bytes)| Self::Integer { name, bytes }),
        }
    }

    /// The Go expression that takes this argument from the decoder `in`.
    /// The last parameter of a function takes all remaining input when it is
    /// a slice or a string.
    fn decode(self, last: bool) -> String {
        match self {
            Self::Bytes if last => "in.rest()".to_owned(),
            Self::Bytes => "in.sized()".to_owned(),
            Self::String if last => "string(in.rest())".to_owned(),
            Self::String => "string(in.sized())".to_owned(),
            Self::Bool => "in.number(1)&1 == 1".to_owned(),
            Self::Integer { name, bytes } => format!("{name}(in.number({bytes}))"),
            Self::Float { bytes: 4, .. } => "math.Float32frombits(uint32(in.number(4)))".to_owned(),
            Self::Float { .. } => "math.Float64frombits(in.number(8))".to_owned(),
            Self::Destination => "&map[string]interface{}{}".to_owned(),
        }
    }

    /// Whether the argument is read from the fuzz input.
    fn reads_input(self) -> bool {
        self != Self::Destination
    }
}

/// The parameters of `signature`, when every one of them is a type the
/// harness can supply and the function has no receiver or type parameters.
/// `Some` of an empty list for a function that takes nothing.
#[must_use]
pub fn parameters(signature: &str, symbol: &str) -> Option<Vec<GoParameter>> {
    let rest = signature.trim().strip_prefix("func")?.trim_start();
    let rest = rest.strip_prefix(symbol)?.trim_start();
    let rest = rest.strip_prefix('(')?;
    let close = rest.find(')')?;
    let list = rest[..close].trim();
    if list.is_empty() {
        return Some(Vec::new());
    }
    if list.contains("...") || list.contains('(') {
        return None;
    }
    let pieces: Vec<Vec<&str>> = list
        .split(',')
        .map(|piece| piece.split_whitespace().collect())
        .collect();
    if pieces
        .iter()
        .any(|words| words.is_empty() || words.len() > 2)
    {
        return None;
    }
    if pieces.iter().all(|words| words.len() == 1) {
        // An unnamed list: every piece is a type.
        return pieces
            .iter()
            .map(|words| GoParameter::of_type(words[0]))
            .collect();
    }
    // A named list: `a, b string` gives `a` the type that follows it.
    let mut types = Vec::with_capacity(pieces.len());
    let mut following = None;
    for words in pieces.iter().rev() {
        if let [_, kind] = words.as_slice() {
            following = Some(GoParameter::of_type(kind)?);
        }
        types.push(following?);
    }
    types.reverse();
    Some(types)
}

/// The decoder a typed harness carries: it hands out arguments from one fuzz
/// input, with zero bytes once the input runs out.
const DECODER: &str = "// oxfuzzInput hands out typed arguments from one fuzz input.\n\
type oxfuzzInput struct {\n\
\tdata []byte\n\
}\n\
\n\
func (in *oxfuzzInput) take(n int) []byte {\n\
\tif n > len(in.data) {\n\
\t\tn = len(in.data)\n\
\t}\n\
\tout := in.data[:n]\n\
\tin.data = in.data[n:]\n\
\treturn out\n\
}\n\
\n\
func (in *oxfuzzInput) number(n int) uint64 {\n\
\tvar value uint64\n\
\tfor _, b := range in.take(n) {\n\
\t\tvalue = value<<8 | uint64(b)\n\
\t}\n\
\treturn value\n\
}\n\
\n\
func (in *oxfuzzInput) sized() []byte {\n\
\treturn in.take(int(in.number(2)))\n\
}\n\
\n\
func (in *oxfuzzInput) rest() []byte {\n\
\treturn in.take(len(in.data))\n\
}\n";

/// The package name declared by a Go source file.
#[must_use]
pub fn package_name(source: &str) -> Option<&str> {
    source.lines().find_map(|line| {
        let name = line.trim().strip_prefix("package")?;
        if !name.starts_with(char::is_whitespace) {
            return None;
        }
        let name = name.split("//").next()?.trim();
        let valid = !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit());
        valid.then_some(name)
    })
}

/// The directory of `file` relative to the module root as a forward-slash
/// path, `.` for the root. `None` when it is not a plain relative path.
#[must_use]
pub fn package_dir_of(relative_file: &Path) -> Option<String> {
    let parent = relative_file.parent()?;
    let mut parts = Vec::new();
    for component in parent.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?);
    }
    if parts.iter().any(|part| !is_plain_path_segment(part)) {
        return None;
    }
    Some(if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    })
}

/// A path segment that is safe inside a `bash -c` script without quoting and
/// cannot be read as an option.
fn is_plain_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.starts_with('-')
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// The package directory recorded in harness `source`.
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when the directive is missing or
/// names anything but a plain relative directory.
pub fn recorded_package_dir(source: &str) -> Result<String, ClassifiedError> {
    let recorded = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(PACKAGE_DIR_DIRECTIVE))
        .map(str::trim)
        .ok_or_else(|| {
            invalid(format!(
                "the Go harness does not record its package directory; keep the \
                 '{}<dir>' line the draft was generated with",
                PACKAGE_DIR_DIRECTIVE.trim_end()
            ))
        })?;
    if recorded == "." || recorded.split('/').all(is_plain_path_segment) {
        return Ok(recorded.to_owned());
    }
    Err(invalid(format!(
        "the Go harness records the package directory '{recorded}', which is not a plain \
         relative directory"
    )))
}

/// The one fuzz test a Go harness defines, as the symbol it fuzzes (the name
/// without its `Fuzz` prefix).
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when the source defines no fuzz test,
/// more than one, or one whose name is not `Fuzz` plus an accepted exported
/// symbol.
pub fn fuzzed_symbol(source: &str) -> Result<String, ClassifiedError> {
    let mut names = source.lines().filter_map(|line| {
        let rest = line.trim().strip_prefix("func Fuzz")?;
        let (name, parameters) = rest.split_once('(')?;
        parameters.contains("testing.F").then(|| name.trim())
    });
    let (Some(symbol), None) = (names.next(), names.next()) else {
        return Err(invalid(
            "a Go harness defines exactly one fuzz test: func Fuzz<Symbol>(f *testing.F)"
                .to_owned(),
        ));
    };
    if !is_exported_symbol(symbol) {
        return Err(invalid(format!(
            "the Go fuzz test is named 'Fuzz{symbol}', which is not Fuzz plus an exported \
             ASCII identifier"
        )));
    }
    Ok(symbol.to_owned())
}

/// The harness template for one target: registers small deterministic seeds
/// and passes every fuzz input to the selected function.
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when the target is not a package-level
/// exported function taking one `[]byte` or `string`, or its file's package
/// clause or directory cannot be determined.
pub fn template(target: &TargetCandidate, target_source: &str) -> Result<String, ClassifiedError> {
    let symbol = target.symbol.as_str();
    if !is_exported_symbol(symbol) {
        return Err(invalid(format!(
            "'{symbol}' is not an exported Go function; the Go harness is a test file in the \
             same package and fuzzes an exported, package-level function"
        )));
    }
    let signature = target.signature.as_deref();
    let kind = signature.and_then(|signature| input_kind(signature, symbol));
    let typed = signature
        .and_then(|signature| parameters(signature, symbol))
        .filter(|parameters| parameters.iter().any(|parameter| parameter.reads_input()))
        .ok_or_else(|| {
            invalid(format!(
                "'{symbol}' is not in the supported Go target class: a package-level function \
                 whose parameters are each []byte, string, bool, an integer type, a float \
                 type, or an `any` destination, at least one of them input{}",
                signature
                    .map(|signature| format!(" (found: {signature})"))
                    .unwrap_or_default()
            ))
        })?;
    let package = package_name(target_source).ok_or_else(|| {
        invalid(format!(
            "could not read the package clause of {}",
            target.relative_file()
        ))
    })?;
    if package == "main" {
        return Err(invalid(format!(
            "'{symbol}' is in package main; move the function into an importable package to \
             fuzz it"
        )));
    }
    let directory = package_dir_of(Path::new(&target.relative_file())).ok_or_else(|| {
        invalid(format!(
            "the directory of {} is not a plain relative path",
            target.relative_file()
        ))
    })?;
    let test = fuzz_test_name(symbol);
    let Some(kind) = kind else {
        return Ok(typed_template(&directory, package, symbol, &typed));
    };
    let parameter = match kind {
        GoInputKind::Bytes => "data []byte",
        GoInputKind::String => "data string",
    };
    // No `f.Add` seeds: Go reports a failing seed-corpus entry without
    // saving a failing input, so a target that fails on a seed would leave
    // nothing to triage. With an empty corpus Go starts from the zero value
    // and saves every failing input (verified with Go 1.26.5 in the pinned
    // image).
    Ok(format!(
        "{PACKAGE_DIR_DIRECTIVE}{directory}\n\
         package {package}\n\
         \n\
         import \"testing\"\n\
         \n\
         func {test}(f *testing.F) {{\n\
         \tf.Fuzz(func(t *testing.T, {parameter}) {{\n\
         \t\t{symbol}(data)\n\
         \t}})\n\
         }}\n"
    ))
}

/// The harness for a function whose arguments are decoded from one `[]byte`
/// fuzz input.
fn typed_template(
    directory: &str,
    package: &str,
    symbol: &str,
    parameters: &[GoParameter],
) -> String {
    let test = fuzz_test_name(symbol);
    let imports = if parameters
        .iter()
        .any(|parameter| matches!(parameter, GoParameter::Float { .. }))
    {
        "import (\n\t\"math\"\n\t\"testing\"\n)\n"
    } else {
        "import \"testing\"\n"
    };
    let mut arguments = String::new();
    let mut names = Vec::with_capacity(parameters.len());
    // The last parameter that reads input takes what is left of it.
    let last_input = parameters
        .iter()
        .rposition(|parameter| parameter.reads_input());
    for (index, parameter) in parameters.iter().enumerate() {
        let name = format!("a{index}");
        let _ = writeln!(
            arguments,
            "\t\t{name} := {}",
            parameter.decode(Some(index) == last_input)
        );
        names.push(name);
    }
    format!(
        "{PACKAGE_DIR_DIRECTIVE}{directory}\n\
         package {package}\n\
         \n\
         {imports}\
         \n\
         {DECODER}\
         \n\
         func {test}(f *testing.F) {{\n\
         \tf.Fuzz(func(t *testing.T, data []byte) {{\n\
         \t\tin := oxfuzzInput{{data: data}}\n\
         {arguments}\
         \t\t{symbol}({})\n\
         \t}})\n\
         }}\n",
        names.join(", ")
    )
}

/// The Go type of the fuzz callback's input in harness `source`: the second
/// parameter of the function passed to `f.Fuzz`. `None` when the callback is
/// not the one-argument `[]byte` or `string` shape the harness path supports.
#[must_use]
pub fn harness_input_kind(source: &str) -> Option<GoInputKind> {
    let (_, callback) = source.split_once("f.Fuzz(func(")?;
    let (parameters, _) = callback.split_once(')')?;
    let mut parameters = parameters.split(',').map(str::trim);
    let _testing_t = parameters.next()?;
    let input = parameters.next()?;
    if parameters.next().is_some() {
        return None;
    }
    match input.split_whitespace().last()? {
        "[]byte" => Some(GoInputKind::Bytes),
        "string" => Some(GoInputKind::String),
        _ => None,
    }
}

/// The build command for a Go harness: `go test -c` with the fuzz selector,
/// which compiles the instrumented test binary into `output_name` at the
/// workspace root and runs nothing.
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when `source` does not define exactly
/// one accepted fuzz test or does not record a plain package directory, or
/// `output_name` is not a plain file name.
pub fn build_command(source: &str, output_name: &str) -> Result<BuildCommand, ClassifiedError> {
    let symbol = fuzzed_symbol(source)?;
    let directory = recorded_package_dir(source)?;
    if !is_plain_path_segment(output_name) {
        return Err(invalid(format!(
            "the Go harness output name '{output_name}' is not a plain file name"
        )));
    }
    let output = output_name.to_owned();
    Ok(BuildCommand {
        compiler: "go".to_owned(),
        args: vec![
            "test".to_owned(),
            "-c".to_owned(),
            format!("-fuzz=^{}$", fuzz_test_name(&symbol)),
            "-o".to_owned(),
            format!("{CONTAINER_WORKSPACE}/{output}"),
            format!("./{directory}"),
        ],
        output: PathBuf::from(output),
        extra_flags: Vec::new(),
    })
}

/// Where the harness file is written for a build: beside the package it
/// tests, relative to the workspace.
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when `source` records no plain
/// package directory.
pub fn harness_path(source: &str) -> Result<PathBuf, ClassifiedError> {
    let directory = recorded_package_dir(source)?;
    Ok(if directory == "." {
        PathBuf::from(HARNESS_FILE)
    } else {
        Path::new(&directory).join(HARNESS_FILE)
    })
}

/// The `bash -c` script that compiles a Go harness from the module root.
/// Every interpolated value is one this module validated as a plain
/// identifier or path segment.
#[must_use]
pub fn build_script(build: &BuildCommand) -> String {
    format!(
        "mkdir -p {GO_CACHE_DIR}/cache {GO_CACHE_DIR}/path && cd {CONTAINER_WORKSPACE} && {} {}",
        build.compiler,
        build
            .args
            .iter()
            .map(|argument| format!("'{argument}'"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// The sandbox environment of a Go build: no module downloads, no toolchain
/// switching, and caches in the container's temporary directory.
#[must_use]
pub fn sandbox_env() -> HashMap<String, String> {
    [
        ("GOPROXY", "off".to_owned()),
        ("GOSUMDB", "off".to_owned()),
        ("GOTOOLCHAIN", "local".to_owned()),
        ("GOFLAGS", "-buildvcs=false".to_owned()),
        ("GOCACHE", format!("{GO_CACHE_DIR}/cache")),
        ("GOPATH", format!("{GO_CACHE_DIR}/path")),
        ("HOME", GO_CACHE_DIR.to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

/// Imports a Go harness may not use: each reaches outside the fuzz input or
/// outside the sandbox's intent.
const FORBIDDEN_IMPORTS: [(&str, &str); 7] = [
    ("os/exec", "starts other processes"),
    ("net", "opens network connections"),
    ("net/http", "opens network connections"),
    ("syscall", "makes raw system calls"),
    ("unsafe", "bypasses Go memory safety"),
    ("C", "uses cgo, which this build path does not qualify"),
    ("plugin", "loads code at run time"),
];

/// Calls that end or stall the fuzz process on ordinary input, with the
/// shared rule id each falls under.
const FORBIDDEN_CALLS: [(&str, &str, &str); 4] = [
    ("os.Exit(", "no-process-exit", "ends the fuzz process"),
    ("log.Fatal", "no-process-exit", "ends the fuzz process"),
    ("time.Sleep(", "no-sleep", "stalls every execution"),
    (
        "os.Getenv(",
        "no-environment-input",
        "branches on something other than the input",
    ),
];

/// [`lint`] for a caller that does not know the selected function: the fuzz
/// test's own name decides which function the callback must call. The
/// service separately requires that name to match the selected target.
#[must_use]
pub fn lint_source(source: &str) -> Vec<LintFinding> {
    match fuzzed_symbol(source) {
        Ok(symbol) => lint(source, &symbol),
        // `lint` reports the missing or malformed fuzz test; no function name
        // is known, so the call check is against a name nothing can match.
        Err(_) => lint(source, ""),
    }
}

/// The checks on Go harness source: the structure the build relies on,
/// forbidden imports and calls, package-level side effects, and that the fuzz
/// callback calls the selected function.
#[must_use]
pub fn lint(source: &str, symbol: &str) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let mut error = |line: usize, rule: &str, message: String| {
        findings.push(LintFinding {
            severity: LintSeverity::Error,
            rule: rule.to_owned(),
            message,
            line: u32::try_from(line).unwrap_or(u32::MAX),
        });
    };
    match fuzzed_symbol(source) {
        Ok(found) if found == symbol || symbol.is_empty() => {}
        Ok(found) => error(
            1,
            "go-fuzz-test-name",
            format!("the fuzz test is Fuzz{found}, but the selected function is {symbol}"),
        ),
        Err(reason) => error(1, "go-fuzz-test-name", reason.to_string()),
    }
    if let Err(reason) = recorded_package_dir(source) {
        error(1, "go-package-dir", reason.to_string());
    }
    let mut calls_target = false;
    let mut in_import_block = false;
    for (index, raw) in source.lines().enumerate() {
        let number = index + 1;
        let line = raw.split("//").next().unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("import (") {
            in_import_block = true;
        } else if in_import_block && line.starts_with(')') {
            in_import_block = false;
        }
        if in_import_block || line.starts_with("import ") {
            for (path, why) in FORBIDDEN_IMPORTS {
                if line.contains(&format!("\"{path}\"")) {
                    error(
                        number,
                        "go-forbidden-import",
                        format!("the harness imports \"{path}\", which {why}"),
                    );
                }
            }
        }
        if line.starts_with("func init(") || line.starts_with("func TestMain(") {
            error(
                number,
                "go-package-side-effect",
                "the harness defines init or TestMain, which run outside the fuzz callback"
                    .to_owned(),
            );
        }
        if line.contains("f.Add(") {
            error(
                number,
                "go-inline-seed",
                "the harness seeds the fuzz test with f.Add; Go reports a failing seed without \
                 saving the failing input, so seeds belong in the corpus directory"
                    .to_owned(),
            );
        }
        if line.starts_with("func Test") && !line.starts_with("func TestMain(") {
            error(
                number,
                "go-extra-test",
                "the harness defines an ordinary test; it must define only the fuzz test"
                    .to_owned(),
            );
        }
        for (call, rule, why) in FORBIDDEN_CALLS {
            if line.contains(call) {
                error(
                    number,
                    rule,
                    format!(
                        "the harness calls {}, which {why}",
                        call.trim_end_matches('(')
                    ),
                );
            }
        }
        if !symbol.is_empty() && !line.starts_with("func ") && contains_call(line, symbol) {
            calls_target = true;
        }
    }
    if !calls_target {
        let name = if symbol.is_empty() {
            "the selected function"
        } else {
            symbol
        };
        error(
            1,
            "go-target-not-called",
            format!("the fuzz callback never calls {name}"),
        );
    }
    findings.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.rule.cmp(&b.rule)));
    findings
}

/// Whether `line` calls `symbol` as a bare package-level function.
fn contains_call(line: &str, symbol: &str) -> bool {
    let needle = format!("{symbol}(");
    line.match_indices(&needle).any(|(at, _)| {
        line[..at].chars().next_back().is_none_or(|before| {
            !(before.is_ascii_alphanumeric() || before == '_' || before == '.')
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, SourceLocation, TargetKind, TargetLanguage};

    fn candidate(file: &str, symbol: &str, signature: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from("/p"),
            language: TargetLanguage::Go,
            symbol: symbol.to_owned(),
            kind: TargetKind::Function,
            location: SourceLocation {
                file: PathBuf::from("/p").join(file),
                line: 3,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: Some(signature.to_owned()),
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: 1.0,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    #[test]
    fn only_one_bytes_or_string_parameter_is_in_the_supported_class() {
        let kind = |signature: &str| input_kind(signature, "Parse");
        assert_eq!(
            kind("func Parse(data []byte) int"),
            Some(GoInputKind::Bytes)
        );
        assert_eq!(
            kind("func Parse(s string) (int, error)"),
            Some(GoInputKind::String)
        );
        assert_eq!(kind("func Parse([]byte)"), Some(GoInputKind::Bytes));
        assert_eq!(kind("func Parse(data []byte, offset int) bool"), None);
        assert_eq!(kind("func Parse(n int) bool"), None);
        assert_eq!(kind("func Parse() bool"), None);
        assert_eq!(kind("func Parse(parts ...string)"), None);
        assert_eq!(kind("func (p *Parser) Parse(data []byte)"), None);
        assert_eq!(kind("func Parse[T any](data []byte)"), None);
        assert_eq!(kind("func ParseAll(data []byte)"), None);
    }

    #[test]
    fn typed_parameters_are_read_from_named_grouped_and_unnamed_lists() {
        use GoParameter::{Bool, Bytes, Float, Integer, String};
        let read = |signature: &str| parameters(signature, "Parse");
        assert_eq!(
            read("func Parse(data []byte, offset int) bool"),
            Some(vec![
                Bytes,
                Integer {
                    name: "int",
                    bytes: 8
                }
            ])
        );
        // Go groups names that share a type.
        assert_eq!(
            read("func Parse(name, value string, strict bool, n uint16) error"),
            Some(vec![
                String,
                String,
                Bool,
                Integer {
                    name: "uint16",
                    bytes: 2
                }
            ])
        );
        assert_eq!(
            read("func Parse(string, float64, rune, byte)"),
            Some(vec![
                String,
                Float {
                    name: "float64",
                    bytes: 8
                },
                Integer {
                    name: "rune",
                    bytes: 4
                },
                Integer {
                    name: "byte",
                    bytes: 1
                }
            ])
        );
        assert_eq!(
            read("func Parse(x float32)"),
            Some(vec![Float {
                name: "float32",
                bytes: 4
            }])
        );
        assert_eq!(read("func Parse()"), Some(Vec::new()));
        for outside in [
            "func Parse(p *Packet)",
            "func Parse(options Options)",
            "func Parse(parts []string)",
            "func Parse(data []byte, more ...string)",
            "func Parse(m map[string]int)",
            "func Parse(visit func(int) bool)",
            "func Parse(a, b)",
            "func (p *Parser) Parse(data []byte, n int)",
            "func Parse[T any](data []byte, n int)",
            "func ParseAll(data []byte, n int)",
        ] {
            assert_eq!(read(outside), None, "{outside}");
        }
    }

    #[test]
    fn a_decode_destination_gets_a_fresh_map_and_takes_no_input() {
        // BurntSushi/toml: `func Decode(data string, v any) (MetaData, error)`,
        // the shape of every Go decoder (`json.Unmarshal`), was outside the
        // supported class, and Go harnesses have no model-written path.
        let target = candidate(
            "decode.go",
            "Decode",
            "func Decode(data string, v any) (MetaData, error)",
        );
        let source = template(&target, "package toml\n").unwrap();
        for expected in [
            // The input parameter is the last one that reads input, so it
            // takes the whole input: a raw TOML corpus file works as is.
            "\t\ta0 := string(in.rest())\n",
            "\t\ta1 := &map[string]interface{}{}\n",
            "\t\tDecode(a0, a1)\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert!(
            lint(&source, "Decode").is_empty(),
            "{:?}",
            lint(&source, "Decode")
        );
        assert_eq!(
            parameters(
                "func Unmarshal(data []byte, v interface{}) error",
                "Unmarshal"
            ),
            Some(vec![GoParameter::Bytes, GoParameter::Destination])
        );
        // A destination alone gives the fuzzer nothing to vary.
        assert!(template(
            &candidate("p.go", "Fill", "func Fill(v any) error"),
            "package p\n"
        )
        .is_err());
    }

    #[test]
    fn a_typed_target_decodes_its_arguments_from_one_byte_slice() {
        let target = candidate(
            "pkg/wire/parse.go",
            "Parse",
            "func Parse(name string, depth int, strict bool, body []byte) error",
        );
        let source = template(&target, "package wire\n").unwrap();
        // The fuzz callback still takes one []byte: corpus files, replay and
        // triage see the same input shape as for a one-parameter target.
        assert_eq!(harness_input_kind(&source), Some(GoInputKind::Bytes));
        assert!(source.contains("f.Fuzz(func(t *testing.T, data []byte) {\n"));
        for expected in [
            "\t\tin := oxfuzzInput{data: data}\n",
            "\t\ta0 := string(in.sized())\n",
            "\t\ta1 := int(in.number(8))\n",
            "\t\ta2 := in.number(1)&1 == 1\n",
            // The last slice or string takes whatever is left.
            "\t\ta3 := in.rest()\n",
            "\t\tParse(a0, a1, a2, a3)\n",
            "type oxfuzzInput struct {",
            "import \"testing\"\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert!(!source.contains("\"math\""));
        assert!(
            lint(&source, "Parse").is_empty(),
            "{:?}",
            lint(&source, "Parse")
        );
        assert_eq!(fuzzed_symbol(&source).unwrap(), "Parse");
        assert!(build_command(&source, "fuzz_Parse").is_ok());

        // Floats are rebuilt from their bits, which needs one more import.
        let floats = candidate(
            "p.go",
            "Scale",
            "func Scale(x float64, y float32, n int8) bool",
        );
        let source = template(&floats, "package p\n").unwrap();
        for expected in [
            "import (\n\t\"math\"\n\t\"testing\"\n)\n",
            "\t\ta0 := math.Float64frombits(in.number(8))\n",
            "\t\ta1 := math.Float32frombits(uint32(in.number(4)))\n",
            "\t\ta2 := int8(in.number(1))\n",
            "\t\tScale(a0, a1, a2)\n",
        ] {
            assert!(source.contains(expected), "{expected:?}\n{source}");
        }
        assert!(lint(&source, "Scale").is_empty());

        // A slice that is not last is length-prefixed, so the next argument
        // still gets input.
        let two = candidate("p.go", "Join", "func Join(a []byte, b string) int");
        let source = template(&two, "package p\n").unwrap();
        assert!(source.contains("\t\ta0 := in.sized()\n\t\ta1 := string(in.rest())\n"));

        // One scalar parameter is a typed target too.
        let scalar = candidate("p.go", "Level", "func Level(n uint32) string");
        let source = template(&scalar, "package p\n").unwrap();
        assert!(source.contains("\t\ta0 := uint32(in.number(4))\n\t\tLevel(a0)\n"));
    }

    #[test]
    fn the_template_fuzzes_the_selected_function_from_its_own_package() {
        let target = candidate("pkg/wire/parse.go", "Parse", "func Parse(data []byte) int");
        let source = template(
            &target,
            "// Package wire.\npackage wire // codec\n\nfunc Parse(data []byte) int { return 0 }\n",
        )
        .unwrap();
        assert!(source.starts_with("// oxfuzz:package-dir pkg/wire\npackage wire\n"));
        assert!(source.contains("func FuzzParse(f *testing.F) {"));
        assert!(source.contains("f.Fuzz(func(t *testing.T, data []byte) {\n\t\tParse(data)"));
        assert!(
            lint(&source, "Parse").is_empty(),
            "{:?}",
            lint(&source, "Parse")
        );
        assert_eq!(harness_input_kind(&source), Some(GoInputKind::Bytes));
        assert_eq!(
            harness_input_kind(&source.replace("data []byte", "text string")),
            Some(GoInputKind::String)
        );
        assert_eq!(
            harness_input_kind(&source.replace("data []byte", "a []byte, b int")),
            None
        );
        assert_eq!(
            harness_input_kind(&source.replace("data []byte", "n int")),
            None
        );
        assert_eq!(harness_input_kind("package p\n"), None);
        // An inline seed that fails is reported by Go without a saved
        // failing input; the template starts from Go's zero-value entry.
        assert!(!source.contains("f.Add("));

        let build = build_command(&source, "fuzz_Parse").unwrap();
        assert_eq!(build.compiler, "go");
        assert_eq!(
            build.args,
            [
                "test",
                "-c",
                "-fuzz=^FuzzParse$",
                "-o",
                "/work/fuzz_Parse",
                "./pkg/wire"
            ]
        );
        assert_eq!(build.output, PathBuf::from("fuzz_Parse"));
        assert_eq!(
            harness_path(&source).unwrap(),
            Path::new("pkg/wire").join(HARNESS_FILE)
        );
        assert!(build_script(&build)
            .ends_with("go 'test' '-c' '-fuzz=^FuzzParse$' '-o' '/work/fuzz_Parse' './pkg/wire'"));

        let root = candidate("parse.go", "Decode", "func Decode(s string) error");
        let source = template(&root, "package codec\n").unwrap();
        assert!(source.starts_with("// oxfuzz:package-dir .\npackage codec\n"));
        assert!(source.contains("data string"));
        assert_eq!(harness_path(&source).unwrap(), PathBuf::from(HARNESS_FILE));
        assert_eq!(
            build_command(&source, "fuzz_Decode").unwrap().args[5],
            "./."
        );
        assert!(build_command(&source, "a b").is_err());
        assert!(build_command(&source, "../x").is_err());
    }

    #[test]
    fn targets_outside_the_supported_class_are_refused_by_name() {
        let refused = |target: &TargetCandidate, source: &str| {
            template(target, source).unwrap_err().to_string()
        };
        for signature in [
            "func ParsePacket(p *Packet, offset int) bool",
            "func ParsePacket(data []byte, options Options) bool",
            "func ParsePacket(parts []string) bool",
            "func ParsePacket(data []byte, more ...string) bool",
            "func ParsePacket() bool",
        ] {
            let outside = candidate("p.go", "ParsePacket", signature);
            let message = refused(&outside, "package p\n");
            assert!(
                message.contains("not in the supported Go target class")
                    && message.contains(
                        "[]byte, string, bool, an integer type, a float type, or an `any` destination"
                    )
                    && message.contains(signature),
                "{signature}: {message}"
            );
        }
        let private = candidate("p.go", "parse", "func parse(data []byte)");
        assert!(refused(&private, "package p\n").contains("not an exported Go function"));
        let main = candidate("main.go", "Parse", "func Parse(data []byte)");
        assert!(refused(&main, "package main\n").contains("package main"));
        let odd = candidate("my dir/p.go", "Parse", "func Parse(data []byte)");
        assert!(refused(&odd, "package p\n").contains("not a plain relative path"));
        let none = candidate("p.go", "Parse", "func Parse(data []byte)");
        assert!(refused(&none, "// no clause\n").contains("package clause"));
    }

    #[test]
    fn the_build_is_decided_only_by_validated_source_text() {
        let good = "// oxfuzz:package-dir a/b\npackage b\nimport \"testing\"\nfunc FuzzX(f *testing.F) {}\n";
        assert!(build_command(good, "fuzz_X").is_ok());
        for directory in ["../up", "/abs", "a/../b", "-flag", "a b", "a;b", "$(x)", ""] {
            let source = good.replace("a/b", directory);
            assert!(build_command(&source, "fuzz_X").is_err(), "{directory}");
        }
        assert!(build_command(&good.replace("// oxfuzz:package-dir a/b\n", ""), "fuzz_X").is_err());
        assert!(build_command(&good.replace("FuzzX", "Fuzzx"), "fuzz_X").is_err());
        assert!(build_command(&good.replace("FuzzX", "FuzzX$y"), "fuzz_X").is_err());
        let two = format!("{good}func FuzzY(f *testing.F) {{}}\n");
        assert!(build_command(&two, "fuzz_X").is_err());
    }

    #[test]
    fn go_lint_rejects_what_the_design_excludes() {
        let base = "// oxfuzz:package-dir .\npackage p\n\nimport \"testing\"\n\nfunc FuzzParse(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, data []byte) {\n\t\tParse(data)\n\t})\n}\n";
        assert!(lint(base, "Parse").is_empty());
        let rules = |source: &str| -> Vec<String> {
            lint(source, "Parse")
                .into_iter()
                .map(|finding| finding.rule)
                .collect()
        };
        assert_eq!(
            rules(&base.replace("\t\tParse(data)\n", "")),
            ["go-target-not-called"]
        );
        assert_eq!(
            rules(&base.replace(
                "\t\tParse(data)\n",
                "\t\tother.Parse(data)\n\t\tReParse(data)\n"
            )),
            ["go-target-not-called"]
        );
        assert_eq!(
            rules(&base.replace(
                "import \"testing\"",
                "import (\n\t\"os/exec\"\n\t\"testing\"\n\t\"unsafe\"\n)"
            )),
            ["go-forbidden-import", "go-forbidden-import"]
        );
        assert_eq!(
            rules(&base.replace("import \"testing\"", "import \"C\"\nimport \"testing\"")),
            ["go-forbidden-import"]
        );
        assert_eq!(
            rules(&format!(
                "{base}func init() {{}}\nfunc TestMain(m *testing.M) {{}}\n"
            )),
            ["go-package-side-effect", "go-package-side-effect"]
        );
        assert_eq!(
            rules(&format!("{base}func TestOther(t *testing.T) {{}}\n")),
            ["go-extra-test"]
        );
        assert_eq!(
            rules(&base.replace("FuzzParse", "FuzzOther")),
            ["go-fuzz-test-name"]
        );
        assert_eq!(
            rules(&base.replace("\tf.Fuzz(", "\tf.Add([]byte{})\n\tf.Fuzz(")),
            ["go-inline-seed"]
        );
        assert_eq!(
            rules(&base.replace("// oxfuzz:package-dir .\n", "")),
            ["go-package-dir"]
        );
        // A quoted import inside a comment is not an import.
        assert!(lint(
            &base.replace("package p", "package p // not \"os/exec\""),
            "Parse"
        )
        .is_empty());
    }

    #[test]
    fn the_sandbox_environment_forbids_downloads_and_keeps_caches_out_of_the_workspace() {
        let env = sandbox_env();
        assert_eq!(env["GOPROXY"], "off");
        assert_eq!(env["GOSUMDB"], "off");
        assert_eq!(env["GOTOOLCHAIN"], "local");
        assert!(env["GOCACHE"].starts_with("/tmp/"));
        assert!(env["GOPATH"].starts_with("/tmp/"));
    }
}
