//! Target discovery scanner.
//!
//! Walks a project with the `ignore` crate, parses C/C++ source with
//! Tree-sitter, scans Rust/Go/Python with dependency-free lexical scanners,
//! extracts function definitions, filters trivial ones, scores them with
//! input-surface and complexity heuristics, and returns a `TargetInventory`.
//!
//! See `docs/design/target-discovery-design.md`.

use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetInventory, TargetKind,
    TargetLanguage,
};
use ignore::WalkBuilder;
use tree_sitter::Parser as TsParser;
use uuid::Uuid;

/// Discover fuzzing targets in a project.
///
/// # Errors
/// Returns `ClassifiedError` if the project root cannot be read.
pub async fn discover(
    project_root: &Path,
    lang: TargetLanguage,
) -> Result<TargetInventory, ClassifiedError> {
    tokio::task::yield_now().await;
    let project_root = canonical_project_root(project_root)?;
    let (mut candidates, call_graph) = match lang {
        TargetLanguage::C | TargetLanguage::Cpp => scan_c(&project_root, lang)?,
        TargetLanguage::Rust => scan_rust(&project_root)?,
        TargetLanguage::Go => scan_go(&project_root)?,
        TargetLanguage::Python => scan_python(&project_root)?,
    };
    // Stamp the project root onto every candidate so downstream consumers
    // (persistence dedup keyed on (project, symbol, file), reports, ranking)
    // can tell which project a target belongs to. The scanner builds
    // candidates without it, so set it once here in the single discovery
    // entry point.
    //
    // Also derive a deterministic id from (project_root, relative_file,
    // symbol). A random per-pass id would orphan every harness/corpus/crash/run
    // stored against the target the next time discovery ran. A UUIDv5 over
    // the identity key keeps the id stable across passes and processes while
    // distinct definitions still get distinct ids.
    for c in &mut candidates {
        c.project_root.clone_from(&project_root);
        c.id = deterministic_target_id(c);
    }
    Ok(TargetInventory {
        project_root,
        candidates,
        call_graph,
    })
}

fn canonical_project_root(project_root: &Path) -> Result<PathBuf, ClassifiedError> {
    let canonical = std::fs::canonicalize(project_root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve project root {}: {error}",
            project_root.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect project root {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "project root {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// Fixed namespace for `hobot_fuzz` target ids so `UUIDv5` derivation is stable
/// across builds and processes.
const TARGET_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x2a, 0x1c, 0x9b, 0x4d, 0x6e, 0x47, 0x3a, 0xa1, 0x02, 0x9c, 0x3e, 0x5f, 0x71, 0x8b, 0x40,
]);

/// Derive a deterministic target id from the persistence identity
/// `(project_root, relative_file, symbol)`. Same identity always yields the
/// same id.
///
/// The file component is the candidate's path relative to the canonical
/// project root, so two same-named functions in different files of one
/// project are distinct persisted targets instead of shadowing each other.
/// Storage re-homes onto the row matching the same key
/// (`Store::upsert_target`), so rediscovery keeps the first persisted id.
fn deterministic_target_id(candidate: &TargetCandidate) -> Uuid {
    let key = format!(
        "{}::{}::{}",
        candidate.project_root.display(),
        candidate.relative_file(),
        candidate.symbol
    );
    Uuid::new_v5(&TARGET_ID_NAMESPACE, key.as_bytes())
}

/// File extensions considered per language.
fn exts_for(lang: TargetLanguage) -> &'static [&'static str] {
    match lang {
        TargetLanguage::C => &["c", "h"],
        TargetLanguage::Cpp => &["cc", "cpp", "cxx", "hpp", "hh"],
        TargetLanguage::Rust => &["rs"],
        TargetLanguage::Go => &["go"],
        TargetLanguage::Python => &["py"],
    }
}

type ScanResult = (
    Vec<TargetCandidate>,
    std::collections::HashMap<String, Vec<String>>,
);

/// Shared walker for the dependency-free lexical scanners (Rust, Go,
/// Python): visit every file with a matching extension, skipping files
/// `skip_file` rejects, and run `extract` over the text. Like the Rust
/// scanner precedent, no call edges are extracted, so the call graph comes
/// back empty and candidates flow into ranking unannotated.
fn scan_lexical(
    root: &Path,
    exts: &'static [&'static str],
    skip_file: fn(&Path) -> bool,
    extract: fn(&str, &Path, &mut Vec<TargetCandidate>),
) -> Result<ScanResult, ClassifiedError> {
    let walker = WalkBuilder::new(root).hidden(true).git_ignore(true).build();
    let mut candidates = Vec::new();
    for entry in walker {
        let entry = entry.map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !exts.contains(&ext) || skip_file(path) {
            continue;
        }
        let src = std::fs::read_to_string(path).map_err(|error| {
            ClassifiedError::Internal(format!("read {}: {error}", path.display()))
        })?;
        extract(&src, path, &mut candidates);
    }
    Ok((candidates, std::collections::HashMap::new()))
}

/// Discover Rust fuzz targets with a dependency-free lexical scan.
///
/// Rust grammar is not vendored here, so this extracts public function
/// definitions (`pub fn`, incl. `async`/`unsafe`) lexically rather than via a
/// full parse. It finds the functions worth a `cargo-fuzz` harness -- public,
/// parameter-bearing, non-test -- and scores them with the same heuristics as
/// the C scanner. It is intentionally conservative: a missed multi-line
/// signature is a lost candidate, never a wrong one.
fn scan_rust(root: &Path) -> Result<ScanResult, ClassifiedError> {
    scan_lexical(
        root,
        exts_for(TargetLanguage::Rust),
        |_| false,
        extract_rust_functions,
    )
}

/// Discover Go fuzz targets with a dependency-free lexical scan, in the same
/// conservative style as the Rust scanner: exported (capitalized)
/// package-level functions and methods with at least one parameter.
fn scan_go(root: &Path) -> Result<ScanResult, ClassifiedError> {
    scan_lexical(
        root,
        exts_for(TargetLanguage::Go),
        skip_go_file,
        extract_go_functions,
    )
}

/// Go test files hold tests, not fuzzable library surface, and `vendor/`
/// holds third-party dependencies rather than the project's own targets.
fn skip_go_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with("_test.go"))
        || path.components().any(|c| c.as_os_str() == "vendor")
}

/// Discover Python fuzz targets with a dependency-free lexical scan, in the
/// same conservative style as the Rust scanner: top-level `def`s and class
/// methods (incl. `async`/decorated) with at least one parameter besides
/// `self`/`cls`.
fn scan_python(root: &Path) -> Result<ScanResult, ClassifiedError> {
    scan_lexical(
        root,
        exts_for(TargetLanguage::Python),
        |_| false,
        extract_python_functions,
    )
}

/// Extract public, parameter-bearing function definitions from Rust source.
fn extract_rust_functions(src: &str, path: &Path, out: &mut Vec<TargetCandidate>) {
    let mut byte_off = 0usize;
    // Iterate with `split_inclusive` so each piece carries its own line
    // terminator: `byte_off += raw.len()` then stays exact on both LF and CRLF
    // files. (`str::lines()` strips a preceding '\r' too, so `line.len() + 1`
    // under-counted by one byte per CRLF line, drifting `line_start` into the
    // previous line and reading parameter lists from the wrong span.)
    for (idx, raw) in src.split_inclusive('\n').enumerate() {
        let line_start = byte_off;
        byte_off += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let Some(after_fn) = strip_pub_fn(line.trim_start()) else {
            continue;
        };
        let name = read_ident(after_fn);
        if name.is_empty() || name == "main" || name.starts_with("test_") {
            continue;
        }
        // Parameters: the argument list is the first balanced `(...)` that
        // follows the identifier and any generic section, so a generic bound
        // such as `Fn(u8)` is not mistaken for the parameter list.
        let Some(params) = extract_rust_param_list(&src[line_start..]) else {
            continue;
        };
        let param_count = if params.trim().is_empty() {
            0
        } else {
            params.split(',').filter(|p| !p.trim().is_empty()).count()
        };
        if param_count == 0 {
            continue; // no untrusted input to feed
        }
        let input_surface = rust_input_surface(&params);
        let kind = if ["parse", "decode", "read", "deserialize", "from_bytes"]
            .iter()
            .any(|k| name.contains(k))
        {
            TargetKind::Parser
        } else {
            TargetKind::Function
        };
        let complexity = rust_body_complexity(&src[line_start..]);
        let fit_score = compute_fit_score(kind, input_surface, complexity, param_count);
        let signature = line.trim().trim_end_matches('{').trim().to_owned();
        out.push(TargetCandidate {
            id: Uuid::new_v4(),
            project_root: PathBuf::new(),
            language: TargetLanguage::Rust,
            symbol: name,
            kind,
            location: SourceLocation {
                file: path.to_path_buf(),
                line: (idx + 1) as u32,
                col: 1,
            },
            signature: Some(signature),
            input_surface,
            complexity,
            fit_score,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        });
    }
}

/// Extract exported, parameter-bearing function and method definitions from
/// Go source. Methods are named `Receiver.Method` so same-named methods of
/// different types do not collide in the name-keyed inventory. Conservative
/// like the Rust scanner: a missed multi-line signature is a lost candidate,
/// never a wrong one.
fn extract_go_functions(src: &str, path: &Path, out: &mut Vec<TargetCandidate>) {
    let mut byte_off = 0usize;
    // Same `split_inclusive` offset discipline as the Rust scanner: CRLF
    // sources must not drift the offsets (see `extract_rust_functions`).
    for (idx, raw) in src.split_inclusive('\n').enumerate() {
        let line_start = byte_off;
        byte_off += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        let Some(after_func) = trimmed.strip_prefix("func ") else {
            continue;
        };
        // Byte offset of `after_func` within `src`, so multi-line signatures
        // are read from the full source rather than from this line alone.
        let mut cursor = line_start + (line.len() - trimmed.len()) + "func ".len();
        let after_func = after_func.trim_start();
        cursor += trimmed["func ".len()..].len() - after_func.len();
        // Two declaration forms:
        //   func Name(params) ...             -- package-level function
        //   func (r *Receiver) Name(params)   -- method with a receiver
        let (receiver, rest) = match paren_group_end(after_func) {
            Some(end) => (
                go_receiver_type(&after_func[1..end - 1]),
                after_func[end..].trim_start(),
            ),
            None => (String::new(), after_func),
        };
        cursor += after_func.len() - rest.len();
        let name = read_ident(rest);
        // Only exported (capitalized) API is reachable from a harness; this
        // also excludes the `main`/`init` entry points. Test helpers follow
        // the same exported shape, so they are filtered by name (their
        // `_test.go` files are skipped by the walker too).
        if name.is_empty()
            || !name.chars().next().is_some_and(char::is_uppercase)
            || name.starts_with("Test")
            || name.starts_with("Benchmark")
        {
            continue;
        }
        // The declaration slice starts at the function name, so the first
        // balanced `(...)` is the parameter list (past the receiver for
        // methods and past any `[T ...]` generic section).
        let decl = &src[cursor..];
        let Some(params) = extract_paren_group(decl) else {
            continue;
        };
        let param_count = if params.trim().is_empty() {
            0
        } else {
            params.split(',').filter(|p| !p.trim().is_empty()).count()
        };
        if param_count == 0 {
            continue; // no untrusted input to feed
        }
        let input_surface = go_input_surface(&params);
        let lower = name.to_ascii_lowercase();
        let kind = if [
            "parse",
            "decode",
            "unmarshal",
            "read",
            "scan",
            "deserialize",
        ]
        .iter()
        .any(|k| lower.contains(k))
        {
            TargetKind::Parser
        } else {
            TargetKind::Function
        };
        let symbol = if receiver.is_empty() {
            name
        } else {
            format!("{receiver}.{name}")
        };
        let complexity = go_body_complexity(decl);
        let fit_score = compute_fit_score(kind, input_surface, complexity, param_count);
        let signature = line.trim().trim_end_matches('{').trim().to_owned();
        out.push(TargetCandidate {
            id: Uuid::new_v4(),
            project_root: PathBuf::new(),
            language: TargetLanguage::Go,
            symbol,
            kind,
            location: SourceLocation {
                file: path.to_path_buf(),
                line: (idx + 1) as u32,
                col: 1,
            },
            signature: Some(signature),
            input_surface,
            complexity,
            fit_score,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        });
    }
}

/// The type name of a Go method receiver: `d *Decoder` -> `Decoder`.
/// Generic instantiations (`*List[T]`) reduce to the base type.
fn go_receiver_type(receiver: &str) -> String {
    let last = receiver.split_whitespace().next_back().unwrap_or("");
    let base = last.trim_start_matches('*');
    let end = base.find('[').unwrap_or(base.len());
    base[..end].to_owned()
}

/// Infer the input surface from a Go parameter list.
fn go_input_surface(params: &str) -> InputSurface {
    // Byte slices, strings, and io readers are all direct untrusted-input
    // surfaces a fuzzer can feed raw bytes into.
    let byte_like = ["[]byte", "string", "io.Reader", "io.ReadCloser"];
    if byte_like.iter().any(|p| params.contains(p)) {
        InputSurface::Bytes
    } else {
        InputSurface::Structured
    }
}

/// Go cyclomatic estimate over the same balanced-brace heuristic as Rust.
fn go_body_complexity(s: &str) -> u32 {
    brace_body_complexity(s, &["if ", "for ", "case ", "&&", "||"])
}

/// Extract parameter-bearing `def` definitions from Python source. Top-level
/// functions and direct class methods are candidates; closures nested inside
/// another `def` are not importable from a harness and are skipped. Methods
/// are named `Class.method` so same-named methods of different classes do not
/// collide, and `self`/`cls` are excluded from the parameter count.
/// Conservative like the Rust scanner: a missed multi-line signature is a
/// lost candidate, never a wrong one.
fn extract_python_functions(src: &str, path: &Path, out: &mut Vec<TargetCandidate>) {
    // Indentation scopes: (indent, class name when the scope is a class).
    // A def is a candidate at module level (empty stack) or directly inside
    // a class; defs push a scope so deeper-nested defs stay non-candidates.
    let mut scopes: Vec<(usize, Option<String>)> = Vec::new();
    let mut byte_off = 0usize;
    for (idx, raw) in src.split_inclusive('\n').enumerate() {
        let line_start = byte_off;
        byte_off += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        // A line at this indent closes every block that began deeper in.
        while scopes
            .last()
            .is_some_and(|&(scope_indent, _)| indent <= scope_indent)
        {
            scopes.pop();
        }
        if let Some(after_class) = trimmed.strip_prefix("class ") {
            scopes.push((indent, Some(read_ident(after_class))));
            continue;
        }
        let Some(after_def) = trimmed
            .strip_prefix("async def ")
            .or_else(|| trimmed.strip_prefix("def "))
        else {
            continue;
        };
        let class = scopes.last().and_then(|(_, class)| class.as_ref()).cloned();
        let nested_in_def = scopes.last().is_some_and(|(_, class)| class.is_none());
        scopes.push((indent, None));
        let name = read_ident(after_def);
        // Underscore-privates (incl. dunders) and test functions are not
        // library surface, and a nested closure is not importable.
        if name.is_empty() || name.starts_with('_') || name.starts_with("test_") || nested_in_def {
            continue;
        }
        // The declaration slice starts at the function name, so the first
        // balanced `(...)` is the parameter list even when it spans lines.
        let name_off =
            line_start + (line.len() - trimmed.len()) + (trimmed.len() - after_def.len());
        let decl = &src[name_off..];
        let Some(params) = extract_paren_group(decl) else {
            continue;
        };
        let mut param_count = if params.trim().is_empty() {
            0
        } else {
            params.split(',').filter(|p| !p.trim().is_empty()).count()
        };
        if class.is_some() {
            // self/cls bind the instance/class; they are not untrusted input.
            param_count = param_count.saturating_sub(
                params
                    .split(',')
                    .filter(|p| matches!(p.trim(), "self" | "cls"))
                    .count(),
            );
        }
        if param_count == 0 {
            continue; // no untrusted input to feed
        }
        let input_surface = python_input_surface(&params);
        let kind = if [
            "parse",
            "decode",
            "deserialize",
            "load",
            "read",
            "from_bytes",
        ]
        .iter()
        .any(|k| name.contains(k))
        {
            TargetKind::Parser
        } else {
            TargetKind::Function
        };
        let symbol = match &class {
            Some(class) => format!("{class}.{name}"),
            None => name,
        };
        let complexity = python_body_complexity(decl, indent);
        let fit_score = compute_fit_score(kind, input_surface, complexity, param_count);
        let signature = line.trim().trim_end_matches(':').trim().to_owned();
        out.push(TargetCandidate {
            id: Uuid::new_v4(),
            project_root: PathBuf::new(),
            language: TargetLanguage::Python,
            symbol,
            kind,
            location: SourceLocation {
                file: path.to_path_buf(),
                line: (idx + 1) as u32,
                col: (indent + 1) as u32,
            },
            signature: Some(signature),
            input_surface,
            complexity,
            fit_score,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        });
    }
}

/// Infer the input surface from a Python parameter list.
fn python_input_surface(params: &str) -> InputSurface {
    // Python parameters are usually untyped, so surface inference keys on the
    // conventional byte-carrying names and annotations.
    let byte_like = [
        "bytes",
        "bytearray",
        "data",
        "buf",
        "raw",
        "payload",
        ": str",
    ];
    if byte_like.iter().any(|p| params.contains(p)) {
        InputSurface::Bytes
    } else {
        InputSurface::Structured
    }
}

/// Python cyclomatic estimate: 1 plus the control-flow keywords in the
/// indented body. The body is every line indented past `def_indent`; the
/// first non-blank line back at or left of it ends the block. Lexical, so it
/// is an estimate, not exact.
fn python_body_complexity(s: &str, def_indent: usize) -> u32 {
    let mut count = 1u32;
    for raw in s.split_inclusive('\n').skip(1) {
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if line.len() - trimmed.len() <= def_indent {
            break;
        }
        for kw in [
            "if ", "if(", "elif ", "for ", "while ", "except", "match ", "case ",
        ] {
            if trimmed.starts_with(kw) {
                count += 1;
                break;
            }
        }
        count += u32::try_from(trimmed.matches(" and ").count() + trimmed.matches(" or ").count())
            .unwrap_or(0);
    }
    count.min(200)
}

/// If `line` (already left-trimmed) declares a public function, return the slice
/// starting at the function name. Skips `pub(crate)`/`pub(super)` (not public
/// API) and `extern` (FFI declarations).
fn strip_pub_fn(line: &str) -> Option<&str> {
    let mut rest = line.strip_prefix("pub")?.trim_start();
    if rest.starts_with('(') {
        return None; // pub(crate) / pub(super): not public API
    }
    loop {
        if let Some(r) = rest.strip_prefix("async ") {
            rest = r.trim_start();
        } else if let Some(r) = rest.strip_prefix("unsafe ") {
            rest = r.trim_start();
        } else if let Some(r) = rest.strip_prefix("const ") {
            rest = r.trim_start();
        } else if rest.starts_with("extern") {
            return None;
        } else {
            break;
        }
    }
    rest.strip_prefix("fn ").map(str::trim_start)
}

/// Read a leading Rust identifier (letters, digits, `_`).
fn read_ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Return the Rust parameter list of the first `fn` in `s` (a slice beginning
/// at the function's line), skipping a leading generic parameter section so a
/// generic bound like `Fn(u8)` or `Fn() -> bool` is not mistaken for the
/// argument list. Returns `None` if no `fn`/argument list is found.
fn extract_rust_param_list(s: &str) -> Option<String> {
    let fn_at = s.find("fn ")?;
    // Skip whitespace after `fn`, then the function identifier.
    let after_fn = s[fn_at + 3..].trim_start();
    let ident_len: usize = after_fn
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .map(char::len_utf8)
        .sum();
    let mut rest = after_fn[ident_len..].trim_start();
    // Skip an optional generic section `<...>`, which may itself contain
    // parentheses (`Fn(u8)`) and return arrows (`-> bool`).
    if rest.starts_with('<') {
        rest = &rest[skip_generics(rest)..];
    }
    // The next balanced `(...)` is the real argument list.
    extract_paren_group(rest)
}

/// Given `s` starting at a `<`, return the byte index just past the matching
/// `>`, balancing nested angle brackets. A `>` immediately preceded by `-`
/// (the `->` return arrow inside a bound) does not close a generic.
fn skip_generics(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' if i == 0 || bytes[i - 1] != b'-' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s.len()
}

/// Return the contents of the first balanced `(...)` group in `s`, or `None`.
fn extract_paren_group(s: &str) -> Option<String> {
    let start = s.find('(')?;
    let mut depth = 0i32;
    let mut out = String::new();
    for ch in s[start..].chars() {
        match ch {
            '(' => {
                depth += 1;
                if depth == 1 {
                    continue;
                }
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
            }
            _ => {}
        }
        out.push(ch);
    }
    None
}

/// If `s` starts with `(`, return the byte index just past the matching `)`.
fn paren_group_end(s: &str) -> Option<usize> {
    if !s.starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Infer the input surface from a Rust parameter list.
fn rust_input_surface(params: &str) -> InputSurface {
    // Byte slices/vectors and string types are all direct untrusted-input
    // surfaces a fuzzer can feed raw bytes into.
    let byte_like = ["[u8]", "Vec<u8>", "&[ u8", "&str", "String"];
    if byte_like.iter().any(|p| params.contains(p)) {
        InputSurface::Bytes
    } else {
        InputSurface::Structured
    }
}

/// Approximate cyclomatic complexity: 1 plus the number of control-flow
/// keywords/operators in the function body (the first balanced `{...}` after
/// the signature). Lexical, so it is an estimate, not exact.
fn brace_body_complexity(s: &str, keywords: &[&str]) -> u32 {
    let Some(open) = s.find('{') else {
        return 1;
    };
    let mut depth = 0i32;
    let mut body = String::new();
    for ch in s[open..].chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        body.push(ch);
    }
    let mut count = 1u32;
    for kw in keywords {
        count += u32::try_from(body.matches(kw).count()).unwrap_or(0);
    }
    count.min(200)
}

/// Rust cyclomatic estimate over the balanced-brace body heuristic.
fn rust_body_complexity(s: &str) -> u32 {
    brace_body_complexity(
        s,
        &["if ", "match ", "for ", "while ", "loop ", "&&", "||", "?"],
    )
}

fn scan_c(root: &Path, lang: TargetLanguage) -> Result<ScanResult, ClassifiedError> {
    let mut parser = TsParser::new();
    match lang {
        TargetLanguage::C => {
            parser
                .set_language(&tree_sitter_c::LANGUAGE.into())
                .map_err(|e| ClassifiedError::Internal(format!("tree-sitter-c: {e}")))?;
        }
        TargetLanguage::Cpp => {
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .map_err(|e| ClassifiedError::Internal(format!("tree-sitter-cpp: {e}")))?;
        }
        _ => {}
    }

    let exts = exts_for(lang);
    let walker = WalkBuilder::new(root).hidden(true).git_ignore(true).build();

    let mut candidates = Vec::new();
    // Call graph accumulated across all files: function name -> direct callees,
    // and function name -> complexity (membership = project-defined).
    let mut calls: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut complexity_map: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for entry in walker {
        let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !exts.contains(&ext) {
            continue;
        }
        let src = std::fs::read_to_string(path)
            .map_err(|e| ClassifiedError::Internal(format!("read {}: {e}", path.display())))?;
        let tree = parser.parse(&src, None).ok_or_else(|| {
            ClassifiedError::Internal(format!("parse {}: parser returned no tree", path.display()))
        })?;
        extract_functions(
            &tree,
            path,
            &src,
            lang,
            &mut candidates,
            &mut calls,
            &mut complexity_map,
        );
    }
    // Annotate candidates with reachability + accumulated complexity.
    crate::reachability::analyze(&mut candidates, &calls, &complexity_map);
    // Project-only call adjacency (drop library/self edges) for the call-tree view.
    let mut call_graph: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (caller, callees) in &calls {
        let mut project: Vec<String> = callees
            .iter()
            .filter(|c| *c != caller && complexity_map.contains_key(*c))
            .cloned()
            .collect();
        project.sort();
        project.dedup();
        if !project.is_empty() {
            call_graph.insert(caller.clone(), project);
        }
    }
    Ok((candidates, call_graph))
}

fn extract_functions(
    tree: &tree_sitter::Tree,
    path: &Path,
    src: &str,
    lang: TargetLanguage,
    out: &mut Vec<TargetCandidate>,
    calls: &mut std::collections::HashMap<String, Vec<String>>,
    complexity_map: &mut std::collections::HashMap<String, u32>,
) {
    let root = tree.root_node();

    let mut f = |node: tree_sitter::Node| {
        if node.kind() != "function_definition" {
            return;
        }
        // Skip static functions: they have internal linkage and cannot be
        // called from a separately-compiled harness translation unit.
        if has_storage_class_specifier(node, src, "static") {
            return;
        }
        let Some(declarator) = node.child_by_field_name("declarator") else {
            return;
        };
        let name_node = find_identifier(&declarator);
        let Some(name_node) = name_node else {
            return;
        };
        let symbol = name_node.utf8_text(src.as_bytes()).unwrap_or("").to_owned();

        let params = count_parameters(&declarator, src);
        if params == 0 {
            return;
        }

        let kind = classify(&symbol);
        let input_surface = infer_input_surface(&declarator, src);
        let complexity = compute_complexity(node);
        let fit_score = compute_fit_score(kind, input_surface, complexity, params);
        // Record the call graph for interprocedural reachability analysis.
        // Identity is name-keyed by design, so two same-named definitions in
        // different files share one slot: merge rather than overwrite, or the
        // second definition would silently drop the first's edges. The union
        // is sorted + deduped for determinism; complexity keeps the max.
        complexity_map
            .entry(symbol.clone())
            .and_modify(|existing| *existing = (*existing).max(complexity))
            .or_insert(complexity);
        let edges = calls.entry(symbol.clone()).or_default();
        edges.extend(extract_calls(node, src));
        edges.sort();
        edges.dedup();
        // Capture only the function prototype (declarator), not the whole
        // definition body -- otherwise the signature spans many lines and
        // downstream consumers (e.g. harness generation) leak body code.
        let signature = Some(
            declarator
                .utf8_text(src.as_bytes())
                .unwrap_or("")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
        let start = name_node.start_position();
        let location = SourceLocation {
            file: path.to_path_buf(),
            line: (start.row + 1) as u32,
            col: (start.column + 1) as u32,
        };
        out.push(TargetCandidate {
            id: Uuid::new_v4(),
            project_root: PathBuf::new(),
            language: lang,
            symbol,
            kind,
            location,
            signature,
            input_surface,
            complexity,
            fit_score,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        });
    };
    walk_nodes(root, &mut f);
}

/// Check whether a function definition has a `storage_class_specifier`
/// child matching `keyword` (e.g. "static").
fn has_storage_class_specifier(node: tree_sitter::Node, src: &str, keyword: &str) -> bool {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "storage_class_specifier" {
                let text = child.utf8_text(src.as_bytes()).unwrap_or("").trim();
                if text == keyword {
                    return true;
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    false
}

/// Collect the names of functions directly called within `func` -- the callee
/// identifier of each `call_expression` whose target is a plain identifier
/// (direct calls; function-pointer/method calls are ignored).
fn extract_calls(func: tree_sitter::Node, src: &str) -> Vec<String> {
    let mut callees = Vec::new();
    let mut f = |n: tree_sitter::Node| {
        if n.kind() == "call_expression" {
            if let Some(callee) = n.child_by_field_name("function") {
                if callee.kind() == "identifier" {
                    if let Ok(name) = callee.utf8_text(src.as_bytes()) {
                        callees.push(name.to_owned());
                    }
                }
            }
        }
    };
    walk_nodes(func, &mut f);
    callees
}

fn walk_nodes(node: tree_sitter::Node, f: &mut dyn FnMut(tree_sitter::Node)) {
    f(node);
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            walk_nodes(cursor.node(), f);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn find_identifier<'a>(node: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "identifier" {
                return Some(child);
            }
            // Recurse into child (e.g. function_declarator wraps identifier).
            if let Some(nested) = find_identifier(&child) {
                return Some(nested);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

fn count_parameters(declarator: &tree_sitter::Node<'_>, src: &str) -> usize {
    let mut cursor = declarator.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "parameter_list" {
                let mut count = 0;
                let mut pc = child.walk();
                if pc.goto_first_child() {
                    loop {
                        // A prototype `(void)` parses as a single
                        // parameter_declaration whose type is the primitive
                        // `void` with no declarator. It carries no argument, so
                        // it must count as zero -- otherwise the `params == 0`
                        // filter never fires and `(void)` functions become
                        // bogus fuzz candidates.
                        if pc.node().kind() == "parameter_declaration"
                            && !is_void_placeholder(&pc.node(), src)
                        {
                            count += 1;
                        }
                        if !pc.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return count;
            }
            // Recurse (function_declarator may wrap another declarator).
            let nested = count_parameters(&child, src);
            if nested > 0 {
                return nested;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    0
}

/// Whether a `parameter_declaration` is the `void` placeholder of a `(void)`
/// prototype: its type is the primitive `void` and it has no declarator (so
/// `void *p`, which has a pointer declarator, is a real parameter and not a
/// placeholder).
fn is_void_placeholder(param: &tree_sitter::Node<'_>, src: &str) -> bool {
    if param.child_by_field_name("declarator").is_some() {
        return false;
    }
    param
        .child_by_field_name("type")
        .is_some_and(|t| t.kind() == "primitive_type" && t.utf8_text(src.as_bytes()) == Ok("void"))
}

fn classify(symbol: &str) -> TargetKind {
    let lower = symbol.to_ascii_lowercase();
    if lower.starts_with("parse_") || lower.contains("parse") {
        TargetKind::Parser
    } else if lower.contains("_ffi") || lower.starts_with("java_") {
        TargetKind::Ffi
    } else {
        TargetKind::Function
    }
}

fn infer_input_surface(declarator: &tree_sitter::Node<'_>, src: &str) -> InputSurface {
    let text = declarator.utf8_text(src.as_bytes()).unwrap_or("");
    if text.contains("FILE") {
        InputSurface::File
    } else if text.contains("stdin") {
        InputSurface::Stdin
    } else {
        InputSurface::Bytes
    }
}

fn compute_complexity(func: tree_sitter::Node) -> u32 {
    let mut score = 1u32;
    let mut f = |n: tree_sitter::Node| match n.kind() {
        "if_statement" | "for_statement" | "while_statement" | "do_statement"
        | "case_statement" => {
            score += 1;
        }
        "binary_expression" => score += 1,
        _ => {}
    };
    walk_nodes(func, &mut f);
    score.min(100)
}

fn compute_fit_score(
    kind: TargetKind,
    input_surface: InputSurface,
    complexity: u32,
    params: usize,
) -> f64 {
    let mut score = 0.3; // base: has params + untrusted input potential
    if matches!(kind, TargetKind::Parser) {
        score += 0.3;
    }
    if matches!(
        input_surface,
        InputSurface::Bytes | InputSurface::Structured
    ) {
        score += 0.2;
    }
    score += (f64::from(complexity) / 100.0) * 0.2;
    if params >= 2 {
        score += 0.05;
    }
    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::{extract_go_functions, extract_python_functions};
    use hf_core::target::{InputSurface, TargetCandidate, TargetKind, TargetLanguage};
    use std::path::Path;

    fn go_candidates(src: &str) -> Vec<TargetCandidate> {
        let mut out = Vec::new();
        extract_go_functions(src, Path::new("parser.go"), &mut out);
        out
    }

    fn python_candidates(src: &str) -> Vec<TargetCandidate> {
        let mut out = Vec::new();
        extract_python_functions(src, Path::new("codec.py"), &mut out);
        out
    }

    #[test]
    fn go_finds_exported_functions_only() {
        let out = go_candidates(
            "package parser\n\
             func ParsePacket(data []byte, offset int) bool {\n\
             \treturn len(data) > offset\n\
             }\n\
             func helper(x int) int { return x + 1 }\n\
             func main() {}\n\
             func init() {}\n",
        );
        // Only the exported, parameter-bearing function is a candidate;
        // unexported helpers and the main/init entry points are not.
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "ParsePacket");
        assert_eq!(out[0].language, TargetLanguage::Go);
        assert_eq!(out[0].kind, TargetKind::Parser);
        assert_eq!(out[0].location.line, 2);
    }

    #[test]
    fn go_qualifies_methods_with_the_receiver_type() {
        let out = go_candidates(
            "package parser\n\
             func (d *Decoder) DecodeFrame(buf []byte) error { return nil }\n\
             func (d Decoder) Name() string { return d.name }\n",
        );
        // The exported method is a candidate named by receiver type so two
        // types with same-named methods do not collide; the unexported
        // zero-parameter method is not fuzzable input.
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "Decoder.DecodeFrame");
        assert_eq!(out[0].kind, TargetKind::Parser);
    }

    #[test]
    fn go_skips_test_and_benchmark_functions() {
        let out = go_candidates(
            "package parser\n\
             func TestParse(t *testing.T) {}\n\
             func BenchmarkParse(b *testing.B) {}\n\
             func ParseReal(data []byte) bool { return len(data) > 0 }\n",
        );
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "ParseReal");
    }

    #[test]
    fn go_requires_at_least_one_parameter() {
        let out = go_candidates(
            "package parser\n\
             func Version() string { return \"1.0\" }\n\
             func ReadChunk(buf []byte, n int) int { return n }\n",
        );
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "ReadChunk");
    }

    #[test]
    fn go_infers_byte_surface_from_byte_slice_string_and_reader_params() {
        let out = go_candidates(
            "package parser\n\
             func ParseBytes(data []byte) bool { return len(data) > 0 }\n\
             func ParseString(s string) bool { return s != \"\" }\n\
             func ParseReader(r io.Reader) bool { return r != nil }\n\
             func Compute(n int) int { return n }\n",
        );
        assert_eq!(out.len(), 4, "unexpected candidates: {out:?}");
        for symbol in ["ParseBytes", "ParseString", "ParseReader"] {
            let c = out
                .iter()
                .find(|c| c.symbol == symbol)
                .unwrap_or_else(|| panic!("{symbol} must be present"));
            assert_eq!(
                c.input_surface,
                InputSurface::Bytes,
                "{symbol} should read untrusted bytes"
            );
        }
        let compute = out.iter().find(|c| c.symbol == "Compute").unwrap();
        assert_eq!(compute.input_surface, InputSurface::Structured);
    }

    #[test]
    fn go_complexity_grows_with_control_flow() {
        let out = go_candidates(
            "package parser\n\
             func Trivial(x int) int { return x }\n\
             func ScanTokens(data []byte) int {\n\
             \tn := 0\n\
             \tfor i := 0; i < len(data); i++ {\n\
             \t\tif data[i] == 0x7f && n < 10 {\n\
             \t\t\tn++\n\
             \t\t}\n\
             \t}\n\
             \treturn n\n\
             }\n",
        );
        let trivial = out.iter().find(|c| c.symbol == "Trivial").unwrap();
        let scan = out.iter().find(|c| c.symbol == "ScanTokens").unwrap();
        assert_eq!(trivial.complexity, 1);
        // 1 + for + if + && -- the branchy scanner is strictly more complex.
        assert!(
            scan.complexity >= 4,
            "ScanTokens complexity {} should reflect its control flow",
            scan.complexity
        );
    }

    #[test]
    fn python_finds_top_level_defs() {
        let out = python_candidates(
            "def parse_packet(data, offset=0):\n\
             \x20   if not data:\n\
             \x20       return None\n\
             \x20   return data[offset:]\n\
             def helper():\n\
             \x20   return 1\n",
        );
        // The parameter-bearing parser is a candidate; the zero-arg helper
        // has no untrusted input to feed.
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "parse_packet");
        assert_eq!(out[0].language, TargetLanguage::Python);
        assert_eq!(out[0].kind, TargetKind::Parser);
        assert_eq!(out[0].location.line, 1);
    }

    #[test]
    fn python_tolerates_decorators_and_async_defs() {
        let out = python_candidates(
            "@functools.lru_cache(maxsize=None)\n\
             def decode_frame(buf):\n\
             \x20   return buf\n\
             async def fetch_payload(url, timeout=10):\n\
             \x20   return url\n",
        );
        let symbols: Vec<&str> = out.iter().map(|c| c.symbol.as_str()).collect();
        assert!(
            symbols.contains(&"decode_frame"),
            "decorated def must count; got {symbols:?}"
        );
        assert!(
            symbols.contains(&"fetch_payload"),
            "async def must count; got {symbols:?}"
        );
    }

    #[test]
    fn python_class_methods_exclude_self_and_cls_from_params() {
        let out = python_candidates(
            "class Decoder:\n\
             \x20   def decode_frame(self, buf):\n\
             \x20       return buf\n\
             \x20   def name(self):\n\
             \x20       return self._name\n\
             \x20   @classmethod\n\
             \x20   def load(cls, raw, strict=False):\n\
             \x20       return raw\n\
             \x20   @staticmethod\n\
             \x20   def from_bytes(payload):\n\
             \x20       return payload\n",
        );
        let symbols: Vec<&str> = out.iter().map(|c| c.symbol.as_str()).collect();
        // `name(self)` has no input parameter once self is excluded.
        assert!(
            !symbols.contains(&"Decoder.name"),
            "self-only method must not be a candidate; got {symbols:?}"
        );
        for symbol in ["Decoder.decode_frame", "Decoder.load", "Decoder.from_bytes"] {
            assert!(
                symbols.contains(&symbol),
                "{symbol} must be a candidate; got {symbols:?}"
            );
        }
        let from_bytes = out
            .iter()
            .find(|c| c.symbol == "Decoder.from_bytes")
            .unwrap();
        assert_eq!(from_bytes.kind, TargetKind::Parser);
    }

    #[test]
    fn python_skips_underscore_test_and_dunder_defs() {
        let out = python_candidates(
            "def _helper(data):\n\
             \x20   return data\n\
             def __repr__(self):\n\
             \x20   return \"x\"\n\
             def test_parse(data):\n\
             \x20   return data\n\
             def parse_real(data):\n\
             \x20   return data\n",
        );
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "parse_real");
    }

    #[test]
    fn python_nested_defs_are_not_candidates() {
        let out = python_candidates(
            "def outer(data):\n\
             \x20   def inner(chunk):\n\
             \x20       return chunk\n\
             \x20   return inner(data)\n",
        );
        // A closure nested inside another def is not importable from a
        // harness, so only the outer function is a candidate.
        assert_eq!(out.len(), 1, "unexpected candidates: {out:?}");
        assert_eq!(out[0].symbol, "outer");
    }

    #[test]
    fn python_complexity_stops_at_the_indented_block_end() {
        let out = python_candidates(
            "def branchy(data):\n\
             \x20   if data:\n\
             \x20       for b in data:\n\
             \x20           if b > 0 and b < 10:\n\
             \x20               return True\n\
             \x20   return False\n\
             def other(x):\n\
             \x20   if x:\n\
             \x20       return 1\n\
             \x20   return 0\n",
        );
        let branchy = out.iter().find(|c| c.symbol == "branchy").unwrap();
        let other = out.iter().find(|c| c.symbol == "other").unwrap();
        // 1 + if + for + if + and; the dedented `def other` ends the block,
        // so its `if x` must not leak into branchy's score.
        assert_eq!(branchy.complexity, 5);
        assert_eq!(other.complexity, 2);
    }

    #[tokio::test]
    async fn same_named_functions_in_different_files_get_distinct_stable_ids() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/a.c"),
            "int parse_opts(const char *s) { return s[0]; }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/b.c"),
            "int parse_opts(const char *s) { return s[1]; }\n",
        )
        .unwrap();

        let inventory = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();
        let parse_opts: Vec<&TargetCandidate> = inventory
            .candidates
            .iter()
            .filter(|c| c.symbol == "parse_opts")
            .collect();
        assert_eq!(
            parse_opts.len(),
            2,
            "each file's definition is its own candidate"
        );
        assert_ne!(
            parse_opts[0].id, parse_opts[1].id,
            "persistence identity is file-scoped"
        );

        // A rescan derives the same id for the same (file, symbol), so
        // storage can re-home onto the already-persisted row.
        let rescan = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();
        let mut ids: Vec<_> = parse_opts.iter().map(|c| c.id).collect();
        let mut rescan_ids: Vec<_> = rescan
            .candidates
            .iter()
            .filter(|c| c.symbol == "parse_opts")
            .map(|c| c.id)
            .collect();
        ids.sort();
        rescan_ids.sort();
        assert_eq!(ids, rescan_ids, "ids are deterministic across scans");
    }
}
