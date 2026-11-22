//! JVM (Jazzer) harness: the fixed template class, its lint, and the build
//! script.
//!
//! The supported target class is a `public static` method of a top-level
//! class whose parameters are each a `byte[]`, a `String` or a primitive, in
//! a project that compiles with `javac` and the jars it carries under `lib/`
//! or `libs/`. The harness is generated from the selected method with no
//! model call, and the lint accepts nothing but that generated text.
//! See `docs/design/jvm-jazzer-fuzzing-design.md`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::harness::BuildCommand;
use hf_core::target::TargetCandidate;

use crate::lint::{LintFinding, LintSeverity};

/// The harness source file written at the workspace root for the build.
pub const HARNESS_FILE: &str = "OxfuzzFuzzTarget.java";

/// The directive line that records what the harness fuzzes:
/// `// oxfuzz:java-target <qualified class>#<method> <bytes|string>`.
pub const TARGET_DIRECTIVE: &str = "// oxfuzz:java-target ";

/// Scratch directory of one build, inside the container.
const BUILD_DIR: &str = "/tmp/oxfuzz-jvm";

/// The class a decoded harness takes its arguments from.
const DATA_PROVIDER: &str = "com.code_intelligence.jazzer.api.FuzzedDataProvider";

/// The image's Jazzer jar, which carries that class. It is on the compile
/// class path only: at run time Jazzer supplies its own API.
const JAZZER_API_JAR: &str = "/opt/jazzer/jazzer_standalone.jar";

/// The project directories whose jars the build puts on the class path: the
/// places a project keeps the dependency jars it carries with it. Nothing is
/// resolved or downloaded; a Maven or Gradle project supplies its
/// dependencies by copying them here.
pub const LIBRARY_DIRS: [&str; 2] = ["lib", "libs"];

/// Whether `relative` (a project-relative path) is a jar directly inside one
/// of [`LIBRARY_DIRS`].
#[must_use]
pub fn is_vendored_library(relative: &Path) -> bool {
    let mut components = relative.components();
    let (Some(directory), Some(_file), None) =
        (components.next(), components.next(), components.next())
    else {
        return false;
    };
    LIBRARY_DIRS
        .iter()
        .any(|name| directory.as_os_str() == std::ffi::OsStr::new(name))
        && relative
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("jar")
}

const KEYWORDS: [&str; 53] = [
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
];

fn invalid(message: String) -> ClassifiedError {
    ClassifiedError::Validation(message)
}

/// What the fuzz callback hands one parameter of the selected method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaInputKind {
    /// A `byte[]`.
    Bytes,
    /// A `String`.
    Text,
    /// A `boolean`.
    Boolean,
    /// A `byte`.
    Byte,
    /// A `short`.
    Short,
    /// An `int`.
    Int,
    /// A `long`.
    Long,
    /// A `char`.
    Char,
    /// A `float`.
    Float,
    /// A `double`.
    Double,
}

/// The longest `byte[]` or `String` a parameter other than the last is
/// given; the last one takes whatever input remains.
const MAX_INNER_LENGTH: u32 = 4096;

impl JavaInputKind {
    const ALL: [Self; 10] = [
        Self::Bytes,
        Self::Text,
        Self::Boolean,
        Self::Byte,
        Self::Short,
        Self::Int,
        Self::Long,
        Self::Char,
        Self::Float,
        Self::Double,
    ];

    /// The name the directive line records.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Text => "string",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Int => "int",
            Self::Long => "long",
            Self::Char => "char",
            Self::Float => "float",
            Self::Double => "double",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// The Java type of a local holding the value.
    const fn java_type(self) -> &'static str {
        match self {
            Self::Bytes => "byte[]",
            Self::Text => "String",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Int => "int",
            Self::Long => "long",
            Self::Char => "char",
            Self::Float => "float",
            Self::Double => "double",
        }
    }

    /// The data-provider call that produces the value. `last` is whether
    /// this is the method's final parameter.
    fn consume(self, last: bool) -> String {
        match (self, last) {
            (Self::Bytes, true) => "data.consumeRemainingAsBytes()".to_owned(),
            (Self::Bytes, false) => {
                format!("data.consumeBytes(data.consumeInt(0, {MAX_INNER_LENGTH}))")
            }
            (Self::Text, true) => "data.consumeRemainingAsString()".to_owned(),
            (Self::Text, false) => {
                format!("data.consumeString(data.consumeInt(0, {MAX_INNER_LENGTH}))")
            }
            (Self::Boolean, _) => "data.consumeBoolean()".to_owned(),
            (Self::Byte, _) => "data.consumeByte()".to_owned(),
            (Self::Short, _) => "data.consumeShort()".to_owned(),
            (Self::Int, _) => "data.consumeInt()".to_owned(),
            (Self::Long, _) => "data.consumeLong()".to_owned(),
            (Self::Char, _) => "data.consumeChar()".to_owned(),
            (Self::Float, _) => "data.consumeFloat()".to_owned(),
            (Self::Double, _) => "data.consumeDouble()".to_owned(),
        }
    }
}

/// The types a parameter may have, as the refusal messages list them.
const SUPPORTED_TYPES: &str =
    "byte[], String, boolean, byte, short, int, long, char, float or double";

/// The most parameters a harness decodes; a longer list is not a function a
/// byte stream explores usefully.
const MAX_PARAMETERS: usize = 8;

/// The method one harness fuzzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaTarget {
    /// The qualified class name, e.g. `com.example.Frames`.
    pub class: String,
    /// The static method name.
    pub method: String,
    /// What each of the method's parameters takes, in order.
    pub inputs: Vec<JavaInputKind>,
}

impl JavaTarget {
    /// The `Class.method` form discovery uses as the candidate symbol.
    #[must_use]
    pub fn symbol(&self) -> String {
        let class = self.class.rsplit('.').next().unwrap_or(&self.class);
        format!("{class}.{}", self.method)
    }
}

/// Whether `text` is an ASCII Java identifier that is not a reserved word.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_' || first == '$')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        && !KEYWORDS.contains(&text)
}

/// The package a Java source file declares, or the empty string for the
/// default package. `None` when a `package` clause is present but malformed.
#[must_use]
pub fn package_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("package ") else {
            // The clause precedes every import and type declaration.
            if line.starts_with("import ")
                || line.contains("class ")
                || line.contains("interface ")
                || line.contains("enum ")
                || line.contains("record ")
            {
                break;
            }
            continue;
        };
        let name = rest.split(';').next()?.trim();
        return name.split('.').all(is_identifier).then(|| name.to_owned());
    }
    Some(String::new())
}

/// What each parameter of the selected method takes, read from its
/// declaration line.
///
/// # Errors
/// Returns `ClassifiedError::Validation` naming the reason the method is
/// outside the supported class.
pub fn input_kinds(signature: &str, symbol: &str) -> Result<Vec<JavaInputKind>, ClassifiedError> {
    let open = signature.find('(');
    let close = signature.rfind(')');
    let (Some(open), Some(close)) = (open, close) else {
        return Err(invalid(format!(
            "the parameter list of {symbol} does not fit on its declaration line, so its input \
             types cannot be read"
        )));
    };
    let head = &signature[..open];
    let modifiers: Vec<&str> = head.split_whitespace().collect();
    if !modifiers.contains(&"static") {
        return Err(invalid(format!(
            "{symbol} is not static; the Java harness calls static methods only, because an \
             instance method needs an object the harness cannot construct"
        )));
    }
    if !modifiers.contains(&"public") {
        return Err(invalid(format!(
            "{symbol} is not public; the Java harness is a separate class and can call public \
             methods only"
        )));
    }
    if head.contains('<') {
        return Err(invalid(format!(
            "{symbol} is generic; the Java harness supports non-generic methods"
        )));
    }
    let parameters = signature[open + 1..close].trim();
    let count = if parameters.is_empty() {
        0
    } else {
        parameters.split(',').count()
    };
    if count == 0 || count > MAX_PARAMETERS {
        return Err(invalid(format!(
            "{symbol} takes {count} parameters; the Java harness supports a method with 1 to \
             {MAX_PARAMETERS}, each {SUPPORTED_TYPES}"
        )));
    }
    parameters
        .split(',')
        .map(|parameter| parameter_kind(parameter.trim(), symbol))
        .collect()
}

/// The kind of one `<type> <name>` parameter.
fn parameter_kind(parameter: &str, symbol: &str) -> Result<JavaInputKind, ClassifiedError> {
    // `final byte[] data`, `byte data[]`, `@Nonnull String text`.
    let words: Vec<&str> = parameter
        .split_whitespace()
        .filter(|word| *word != "final" && !word.starts_with('@'))
        .collect();
    let [kind, name] = words.as_slice() else {
        return Err(invalid(format!(
            "the parameter '{parameter}' of {symbol} is not a plain '<type> <name>'"
        )));
    };
    let found = match (*kind, name.ends_with("[]")) {
        ("byte[]", false) | ("byte", true) => Some(JavaInputKind::Bytes),
        ("String" | "java.lang.String", false) => Some(JavaInputKind::Text),
        (primitive, false) => JavaInputKind::ALL
            .into_iter()
            .filter(|kind| !matches!(kind, JavaInputKind::Bytes | JavaInputKind::Text))
            .find(|kind| kind.java_type() == primitive),
        _ => None,
    };
    found.ok_or_else(|| {
        invalid(format!(
            "{symbol} takes '{kind}'; the Java harness supports parameters that are \
             {SUPPORTED_TYPES}"
        ))
    })
}

/// The harness target of a discovered Java candidate. `target_source` is the
/// text of the file that declares it, read for its `package` clause.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the candidate is outside the
/// supported class.
pub fn target_of(
    candidate: &TargetCandidate,
    target_source: &str,
) -> Result<JavaTarget, ClassifiedError> {
    let symbol = candidate.symbol.as_str();
    let Some((class, method)) = symbol.split_once('.') else {
        return Err(invalid(format!("'{symbol}' is not a Class.method name")));
    };
    if !is_identifier(class) || !is_identifier(method) {
        return Err(invalid(format!(
            "'{symbol}' names a nested class or is not a Class.method name; the Java harness \
             supports methods of top-level classes"
        )));
    }
    let relative = candidate.relative_file();
    let file_class = std::path::Path::new(&relative)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if file_class != class {
        return Err(invalid(format!(
            "{class} is declared in {relative}; the Java harness supports the public top-level \
             class of a file, which is named after the file"
        )));
    }
    let package = package_name(target_source).ok_or_else(|| {
        invalid(format!(
            "the package clause of {relative} could not be read"
        ))
    })?;
    let signature = candidate.signature.as_deref().ok_or_else(|| {
        invalid(format!(
            "{symbol} has no recorded signature to read its input type from"
        ))
    })?;
    let inputs = input_kinds(signature, symbol)?;
    let class = if package.is_empty() {
        // A class in the default package cannot be named from another
        // compilation unit's qualified reference, but the harness is in the
        // default package too, so the simple name resolves.
        class.to_owned()
    } else {
        format!("{package}.{class}")
    };
    Ok(JavaTarget {
        class,
        method: method.to_owned(),
        inputs,
    })
}

/// Render the harness class of one target. The text is a pure function of
/// the target, which is what lets [`lint`] hold a source to it exactly.
///
/// A method of one `byte[]` or `String` is handed the raw input. Any other
/// parameter list is decoded from the input through Jazzer's
/// `FuzzedDataProvider`, in declaration order.
#[must_use]
pub fn render(target: &JavaTarget) -> String {
    let kinds = target
        .inputs
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let header = format!(
        "{TARGET_DIRECTIVE}{class}#{method} {kinds}\n\
         public final class {harness} {{\n\
         \x20   private {harness}() {{}}\n\
         \n",
        class = target.class,
        method = target.method,
        harness = hf_engine::jazzer::TARGET_CLASS,
    );
    let raw = match target.inputs.as_slice() {
        [JavaInputKind::Bytes] => Some("data"),
        [JavaInputKind::Text] => Some("new String(data, java.nio.charset.StandardCharsets.UTF_8)"),
        _ => None,
    };
    let body = if let Some(argument) = raw {
        format!(
            "\x20   public static void fuzzerTestOneInput(byte[] data) {{\n\
             \x20       {class}.{method}({argument});\n",
            class = target.class,
            method = target.method,
        )
    } else {
        let mut body =
            format!("\x20   public static void fuzzerTestOneInput({DATA_PROVIDER} data) {{\n");
        let last = target.inputs.len().saturating_sub(1);
        for (index, kind) in target.inputs.iter().enumerate() {
            let _ = writeln!(
                body,
                "\x20       {} a{index} = {};",
                kind.java_type(),
                kind.consume(index == last)
            );
        }
        let arguments = (0..target.inputs.len())
            .map(|index| format!("a{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            body,
            "\x20       {class}.{method}({arguments});",
            class = target.class,
            method = target.method,
        );
        body
    };
    format!("{header}{body}\x20   }}\n}}\n")
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
pub fn recorded_target(source: &str) -> Result<JavaTarget, ClassifiedError> {
    let malformed = || {
        invalid(format!(
            "the Java harness has no well-formed '{}<class>#<method> <types>' line",
            TARGET_DIRECTIVE.trim_end()
        ))
    };
    let line = source
        .lines()
        .find_map(|line| line.strip_prefix(TARGET_DIRECTIVE))
        .ok_or_else(malformed)?;
    let (target, input) = line.split_once(' ').ok_or_else(malformed)?;
    let (class, method) = target.split_once('#').ok_or_else(malformed)?;
    if !class.split('.').all(is_identifier) || !is_identifier(method) {
        return Err(malformed());
    }
    Ok(JavaTarget {
        class: class.to_owned(),
        method: method.to_owned(),
        inputs: recorded_inputs(input).ok_or_else(malformed)?,
    })
}

/// The parameter kinds a directive line records: a comma-separated list.
fn recorded_inputs(text: &str) -> Option<Vec<JavaInputKind>> {
    let kinds: Vec<JavaInputKind> = text
        .split(',')
        .map(JavaInputKind::parse)
        .collect::<Option<_>>()?;
    (kinds.len() <= MAX_PARAMETERS).then_some(kinds)
}

/// Hold a harness source to the generated template of the selected method.
///
/// `symbol` is the selected `Class.method`; empty skips the selection check.
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
        Err(reason) => return vec![finding(1, "java-target-directive", reason.to_string())],
    };
    let mut findings = Vec::new();
    if !symbol.is_empty() && target.symbol() != symbol {
        findings.push(finding(
            1,
            "java-target-mismatch",
            format!(
                "the harness fuzzes {}, but the selected method is {symbol}",
                target.symbol()
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
                    "java-fixed-template",
                    format!(
                        "line {number} differs from the generated harness for {}#{}; a Java \
                         harness must be the generated template unchanged",
                        target.class, target.method
                    ),
                ));
                break;
            }
        }
    }
    findings
}

/// Whether `name` is safe to place unquoted-equivalent in the build script:
/// one path component of letters, digits, `_`, `-`, and `.`.
fn is_plain_output_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

/// The build of a harness source, recorded as the compiler it runs and the
/// output it writes. The command that actually runs is [`build_script`].
///
/// # Errors
/// Returns `ClassifiedError::Validation` when the source records no target or
/// the output name is not one plain path component.
pub fn build_command(source: &str, output_name: &str) -> Result<BuildCommand, ClassifiedError> {
    recorded_target(source)?;
    if !is_plain_output_name(output_name) {
        return Err(invalid(format!(
            "'{output_name}' is not a plain file name for a Java harness artifact"
        )));
    }
    Ok(BuildCommand {
        compiler: "javac".to_owned(),
        args: vec![
            "-nowarn".to_owned(),
            "-encoding".to_owned(),
            "UTF-8".to_owned(),
        ],
        output: PathBuf::from(output_name),
        extra_flags: Vec::new(),
    })
}

/// The fixed build script, run with the workspace mounted at `/work`: unpack
/// the project's vendored jars into the class directory, compile every
/// staged `.java` file outside `test` directories and run history together
/// with the harness class against them, pack the classes into a jar, and
/// write the artifact (the launcher stub followed by the jar). The project's
/// own classes are compiled last and so replace a vendored class of the same
/// name.
///
/// # Errors
/// Returns `ClassifiedError::Validation` for an output that is not one plain
/// path component (see [`build_command`]).
pub fn build_script(build: &BuildCommand) -> Result<String, ClassifiedError> {
    let output = build
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_plain_output_name(name))
        .ok_or_else(|| {
            invalid(format!(
                "'{}' is not a plain file name for a Java harness artifact",
                build.output.display()
            ))
        })?;
    let stub = hf_engine::jazzer::launcher_stub();
    let mut stub_lines = stub.lines();
    let interpreter = stub_lines.next().unwrap_or_default();
    let launcher = stub_lines.next().unwrap_or_default();
    Ok(format!(
        "set -eu\n\
         mkdir -p {dir}/classes\n\
         for jar in {jars}; do\n\
         \x20 if [ -f \"$jar\" ]; then (cd {dir}/classes && jar xf \"$jar\"); fi\n\
         done\n\
         find {dir}/classes -maxdepth 2 -path '*/META-INF/*' \\( -name MANIFEST.MF \
         -o -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' -o -name '*.EC' \\) -delete\n\
         rm -f {dir}/classes/module-info.class\n\
         find /work -type f -name '*.java' -not -name module-info.java \
         -not -path '*/test/*' -not -path '*/tests/*' -not -path '/work/runs/*' \
         -not -path '/work/out/*' -not -path '/work/corpus/*' \
         | LC_ALL=C sort | sed 's/.*/\"&\"/' > {dir}/sources\n\
         javac {flags} -cp {dir}/classes:{api} -d {dir}/classes @{dir}/sources\n\
         jar --create --file {dir}/harness.jar -C {dir}/classes .\n\
         printf '%s\\n' '{interpreter}' '{launcher}' > /work/{output}\n\
         cat {dir}/harness.jar >> /work/{output}\n\
         chmod 0755 /work/{output}\n",
        dir = BUILD_DIR,
        api = JAZZER_API_JAR,
        flags = build.args.join(" "),
        jars = LIBRARY_DIRS
            .iter()
            .map(|directory| format!("/work/{directory}/*.jar"))
            .collect::<Vec<_>>()
            .join(" "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, Sanitizer, SourceLocation, TargetKind, TargetLanguage};

    fn candidate(file: &str, symbol: &str, signature: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from("/project"),
            language: TargetLanguage::Java,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("/project").join(file),
                line: 6,
                col: 5,
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

    const FRAMES: &str = "// Frame reader.\npackage com.example;\n\nimport java.util.List;\n\npublic final class Frames {\n}\n";

    #[test]
    fn the_package_clause_is_read_before_any_type() {
        assert_eq!(package_name(FRAMES).as_deref(), Some("com.example"));
        assert_eq!(
            package_name("public class Frames {}\n").as_deref(),
            Some("")
        );
        assert_eq!(
            package_name("import a.B;\npackage late;\n").as_deref(),
            Some("")
        );
        assert_eq!(package_name("package com.1bad;\n"), None);
    }

    #[test]
    fn the_input_kinds_are_read_from_the_parameters_of_a_public_static_method() {
        let kinds = |signature: &str| input_kinds(signature, "Frames.parse");
        assert_eq!(
            kinds("public static int parse(byte[] data) {").unwrap(),
            [JavaInputKind::Bytes]
        );
        assert_eq!(
            kinds("public static void parse(final byte data[]) throws IOException {").unwrap(),
            [JavaInputKind::Bytes]
        );
        assert_eq!(
            kinds("static public Frame parse(@Nonnull String text)").unwrap(),
            [JavaInputKind::Text]
        );
        assert_eq!(
            kinds("public static int parse(byte[] data, int size, final boolean strict) {")
                .unwrap(),
            [
                JavaInputKind::Bytes,
                JavaInputKind::Int,
                JavaInputKind::Boolean
            ]
        );
        assert_eq!(
            kinds("public static void set(byte b, short s, long l, char c, float f, double d)")
                .unwrap(),
            [
                JavaInputKind::Byte,
                JavaInputKind::Short,
                JavaInputKind::Long,
                JavaInputKind::Char,
                JavaInputKind::Float,
                JavaInputKind::Double
            ]
        );
        for (signature, reason) in [
            ("public int parse(byte[] data) {", "not static"),
            ("static int parse(byte[] data) {", "not public"),
            ("public static <T> T parse(byte[] data) {", "generic"),
            ("public static int parse() {", "0 parameters"),
            (
                "public static int parse(int a, int b, int c, int d, int e, int f, int g, int h, int i)",
                "9 parameters",
            ),
            ("public static int parse(InputStream in) {", "'InputStream'"),
            (
                "public static int parse(byte[] data, Options options) {",
                "'Options'",
            ),
            ("public static int parse(int[] values) {", "'int[]'"),
            ("public static int parse(int... values) {", "'int...'"),
            ("public static int parse(", "declaration line"),
        ] {
            let error = kinds(signature).unwrap_err().to_string();
            assert!(error.contains(reason), "{signature}: {error}");
        }
    }

    #[test]
    fn a_typed_method_takes_its_arguments_from_the_data_provider() {
        let source = template(
            &candidate(
                "src/main/java/com/example/Frames.java",
                "Frames.read",
                "public static int read(String name, int offset, boolean strict, byte[] data) {",
            ),
            FRAMES,
        )
        .unwrap();
        assert_eq!(
            source,
            "// oxfuzz:java-target com.example.Frames#read string,int,boolean,bytes\n\
             public final class OxfuzzFuzzTarget {\n\
             \x20   private OxfuzzFuzzTarget() {}\n\
             \n\
             \x20   public static void fuzzerTestOneInput(\
             com.code_intelligence.jazzer.api.FuzzedDataProvider data) {\n\
             \x20       String a0 = data.consumeString(data.consumeInt(0, 4096));\n\
             \x20       int a1 = data.consumeInt();\n\
             \x20       boolean a2 = data.consumeBoolean();\n\
             \x20       byte[] a3 = data.consumeRemainingAsBytes();\n\
             \x20       com.example.Frames.read(a0, a1, a2, a3);\n\
             \x20   }\n\
             }\n"
        );
        // The recorded directive reproduces the same text, so the template
        // lint holds a typed harness to it as well.
        let recorded = recorded_target(&source).unwrap();
        assert_eq!(recorded.symbol(), "Frames.read");
        assert_eq!(render(&recorded), source);
        assert!(lint(&source, "Frames.read").is_empty());
        assert!(!lint(
            &source.replace("consumeInt()", "consumeInt(0, 1)"),
            "Frames.read"
        )
        .is_empty());
        // A single primitive is decoded too; only one byte[] or String is raw.
        let single = template(
            &candidate(
                "Codec.java",
                "Codec.step",
                "public static void step(long seed)",
            ),
            "public class Codec {}\n",
        )
        .unwrap();
        assert!(single.contains("long a0 = data.consumeLong();\n"));
        assert!(single.contains("Codec.step(a0);\n"));
    }

    #[test]
    fn the_template_calls_the_qualified_method_from_the_default_package() {
        let source = template(
            &candidate(
                "src/main/java/com/example/Frames.java",
                "Frames.parse",
                "public static int parse(byte[] data) {",
            ),
            FRAMES,
        )
        .unwrap();
        assert_eq!(
            source,
            "// oxfuzz:java-target com.example.Frames#parse bytes\n\
             public final class OxfuzzFuzzTarget {\n\
             \x20   private OxfuzzFuzzTarget() {}\n\
             \n\
             \x20   public static void fuzzerTestOneInput(byte[] data) {\n\
             \x20       com.example.Frames.parse(data);\n\
             \x20   }\n\
             }\n"
        );
        assert_eq!(recorded_target(&source).unwrap().symbol(), "Frames.parse");

        let text = template(
            &candidate(
                "Codec.java",
                "Codec.decode",
                "public static void decode(String text)",
            ),
            "public class Codec {}\n",
        )
        .unwrap();
        assert!(text.contains("// oxfuzz:java-target Codec#decode string\n"));
        assert!(text.contains(
            "Codec.decode(new String(data, java.nio.charset.StandardCharsets.UTF_8));\n"
        ));
    }

    #[test]
    fn a_nested_or_misfiled_class_is_refused_with_its_reason() {
        let nested = template(
            &candidate(
                "Frames.java",
                "Frames.Inner.parse",
                "public static int parse(byte[] d)",
            ),
            FRAMES,
        )
        .unwrap_err()
        .to_string();
        assert!(nested.contains("top-level classes"), "{nested}");
        let misfiled = template(
            &candidate(
                "Other.java",
                "Frames.parse",
                "public static int parse(byte[] d)",
            ),
            FRAMES,
        )
        .unwrap_err()
        .to_string();
        assert!(misfiled.contains("named after the file"), "{misfiled}");
    }

    #[test]
    fn lint_accepts_only_the_generated_template_of_the_selected_method() {
        let source = template(
            &candidate(
                "Frames.java",
                "Frames.parse",
                "public static int parse(byte[] data)",
            ),
            FRAMES,
        )
        .unwrap();
        assert!(lint(&source, "Frames.parse").is_empty());
        assert!(lint(&source, "").is_empty());
        assert_eq!(
            lint(&source, "Frames.decode")[0].rule,
            "java-target-mismatch"
        );

        let edited = source.replace(
            "        com.example.Frames.parse(data);\n",
            "        try { com.example.Frames.parse(data); } catch (Throwable ignored) {}\n",
        );
        let findings = lint(&edited, "Frames.parse");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "java-fixed-template");
        assert_eq!(findings[0].line, 6);

        let appended = format!("{source}class Extra {{ static {{ System.exit(0); }} }}\n");
        assert_eq!(
            lint(&appended, "Frames.parse")[0].rule,
            "java-fixed-template"
        );
        assert_eq!(
            lint("public class OxfuzzFuzzTarget {}\n", "Frames.parse")[0].rule,
            "java-target-directive"
        );
        let injected = source.replace("com.example.Frames#parse", "a;Runtime#exec");
        assert_eq!(lint(&injected, "")[0].rule, "java-target-directive");
    }

    #[test]
    fn the_build_compiles_staged_sources_and_writes_a_self_starting_jar() {
        let source = template(
            &candidate(
                "Frames.java",
                "Frames.parse",
                "public static int parse(byte[] data)",
            ),
            FRAMES,
        )
        .unwrap();
        let build = build_command(&source, "fuzz_Frames.parse").unwrap();
        assert_eq!(build.compiler, "javac");
        let script = build_script(&build).unwrap();
        assert!(script.starts_with("set -eu\n"));
        assert!(script.contains("-not -path '*/test/*'"));
        assert!(script.contains("-not -path '/work/runs/*'"));
        assert!(script.contains("-not -name module-info.java"));
        assert!(script.contains(
            "javac -nowarn -encoding UTF-8 \
             -cp /tmp/oxfuzz-jvm/classes:/opt/jazzer/jazzer_standalone.jar \
             -d /tmp/oxfuzz-jvm/classes @/tmp/oxfuzz-jvm/sources\n"
        ));
        // The project's vendored jars are unpacked into the class directory
        // before the compile, so the project compiles against them and the
        // artifact stays one file that carries them.
        assert_eq!(LIBRARY_DIRS, ["lib", "libs"]);
        let unpack = script
            .find("for jar in /work/lib/*.jar /work/libs/*.jar; do")
            .expect("vendored jars are unpacked");
        assert!(script.contains("(cd /tmp/oxfuzz-jvm/classes && jar xf \"$jar\")"));
        assert!(unpack < script.find("javac ").unwrap());
        // A signed dependency's signature does not cover the merged jar.
        for signature in ["'*.SF'", "'*.RSA'", "'*.DSA'", "'*.EC'", "MANIFEST.MF"] {
            assert!(script.contains(signature), "{signature}");
        }
        assert!(is_vendored_library(Path::new("lib/codec-1.2.jar")));
        assert!(is_vendored_library(Path::new("libs/codec.jar")));
        for other in [
            "codec.jar",
            "lib/nested/codec.jar",
            "target/codec.jar",
            "lib/codec.zip",
            "lib/notes.txt",
        ] {
            assert!(!is_vendored_library(Path::new(other)), "{other}");
        }
        assert!(script.contains(
            "printf '%s\\n' '#!/bin/sh' 'exec jazzer --cp=\"$0\" --target_class=OxfuzzFuzzTarget \
             --reproducer_path=/tmp \"$@\"' > /work/fuzz_Frames.parse\n"
        ));
        assert!(script.ends_with("chmod 0755 /work/fuzz_Frames.parse\n"));

        for refused in ["", "a b", "../x", "x;y", ".hidden", "a/b"] {
            assert!(build_command(&source, refused).is_err(), "{refused:?}");
        }
        assert!(build_command("class X {}\n", "fuzz_x").is_err());
    }
}
