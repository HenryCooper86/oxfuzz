//! Target discovery scanner.
//!
//! Walks a project with the `ignore` crate, parses C/C++ source with
//! Tree-sitter, scans Rust/Go/Python with dependency-free lexical scanners,
//! extracts function definitions, filters trivial ones, scores them with
//! input-surface and complexity heuristics, and returns a `TargetInventory`.
//!
//! See `docs/design/target-discovery-design.md`.

use std::path::{Path, PathBuf};

use hf_core::c_unit::{classify_unit, UnitRole};
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
    discover_with_signals(project_root, lang)
        .await
        .map(|(inventory, _signals)| inventory)
}

/// Discover fuzzing targets and the native static-analysis signals produced by
/// the same parse.
///
/// The signals come from the trees the scan already built, so obtaining them
/// costs a query-cursor pass rather than a second walk of the project. Feed
/// them to [`crate::enrichment::score_overlay`] with the returned inventory.
///
/// Empty without the `native-analysis` feature, and for any language scanned
/// lexically, since those carry no tree to match against.
///
/// # Errors
/// Returns `ClassifiedError` if the project root cannot be read.
pub async fn discover_with_signals(
    project_root: &Path,
    lang: TargetLanguage,
) -> Result<(TargetInventory, Vec<crate::enrichment::EnrichmentSignal>), ClassifiedError> {
    // The recursive walk plus a tree-sitter parse of every source file is
    // seconds of blocking work on a large tree; running it inline would
    // monopolize a tokio worker and stall every other task on it. Off it goes
    // to the blocking pool, the same shape as `hf_corpus::seed_with_limits`.
    let project_root = project_root.to_path_buf();
    tokio::task::spawn_blocking(move || discover_blocking(&project_root, lang))
        .await
        .map_err(|error| ClassifiedError::Internal(format!("discovery task failed: {error}")))?
}

fn discover_blocking(
    project_root: &Path,
    lang: TargetLanguage,
) -> Result<(TargetInventory, Vec<crate::enrichment::EnrichmentSignal>), ClassifiedError> {
    let project_root = canonical_project_root(project_root)?;
    let (mut candidates, call_graph, signals) = match lang {
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
    Ok((
        TargetInventory {
            project_root,
            candidates,
            call_graph,
        },
        signals,
    ))
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

/// Fixed namespace for `oxfuzz` target ids so `UUIDv5` derivation is stable
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
    // Source of truth lives on `TargetLanguage` (hf-core), so adding a language
    // does not require editing this crate's dispatch.
    lang.extensions()
}

/// Return the canonical C/C++ discovery source set as sorted project-relative paths.
///
/// The walk deliberately uses the same hidden-file and git-ignore semantics as
/// normal target discovery. Paths are retained only when they name a regular,
/// non-symlink file that resolves beneath `canonical_root`.
///
/// # Errors
/// Returns a validation error for an unsupported language, a non-canonical
/// project root, or an unsafe source path. Walker failures are surfaced rather
/// than returning a partial source set.
pub fn discoverable_source_files(
    canonical_root: &Path,
    lang: TargetLanguage,
) -> Result<Vec<PathBuf>, ClassifiedError> {
    let mut relative_paths = discoverable_source_files_in_walk_order(canonical_root, lang)?;
    relative_paths.sort();
    Ok(relative_paths)
}

fn discoverable_source_files_in_walk_order(
    canonical_root: &Path,
    lang: TargetLanguage,
) -> Result<Vec<PathBuf>, ClassifiedError> {
    if !matches!(lang, TargetLanguage::C | TargetLanguage::Cpp) {
        return Err(ClassifiedError::Validation(format!(
            "Semgrep source discovery does not support {}",
            lang.as_str()
        )));
    }
    let resolved_root = std::fs::canonicalize(canonical_root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve project root {}: {error}",
            canonical_root.display()
        ))
    })?;
    if resolved_root != canonical_root {
        return Err(ClassifiedError::Validation(format!(
            "project root is not canonical: {}",
            canonical_root.display()
        )));
    }
    let root_metadata = std::fs::symlink_metadata(canonical_root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect project root {}: {error}",
            canonical_root.display()
        ))
    })?;
    if !root_metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "project root is not a regular directory: {}",
            canonical_root.display()
        )));
    }

    let walker = WalkBuilder::new(canonical_root)
        .hidden(true)
        .git_ignore(true)
        .build();
    let extensions = exts_for(lang);
    let mut relative_paths = Vec::new();
    for entry in walker {
        let entry = entry.map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !extensions.contains(&extension) {
            continue;
        }
        let relative = path.strip_prefix(canonical_root).map_err(|_| {
            ClassifiedError::Validation(format!(
                "discovered source escaped project root: {}",
                path.display()
            ))
        })?;
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || !relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(ClassifiedError::Validation(format!(
                "discovered source has an unsafe relative path: {}",
                relative.display()
            )));
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect discovered source {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(ClassifiedError::Validation(format!(
                "discovered source is not a regular file: {}",
                path.display()
            )));
        }
        let resolved = std::fs::canonicalize(path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "resolve discovered source {}: {error}",
                path.display()
            ))
        })?;
        if resolved != path || !resolved.starts_with(canonical_root) {
            return Err(ClassifiedError::Validation(format!(
                "discovered source escaped its canonical project root: {}",
                path.display()
            )));
        }
        relative_paths.push(relative.to_path_buf());
    }
    Ok(relative_paths)
}

type ScanResult = (
    Vec<TargetCandidate>,
    std::collections::HashMap<String, Vec<String>>,
    Vec<crate::enrichment::EnrichmentSignal>,
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
    let mut files = Vec::new();
    for entry in walker {
        let entry = entry.map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        // A directory whose name looks like a source file (e.g. `pkg.go/`) has a
        // matching extension; without this guard `read_to_string` would fail with
        // "is a directory" and the `?` below would abort the entire scan.
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !exts.contains(&ext) || skip_file(path) {
            continue;
        }
        files.push(path.to_path_buf());
    }
    // Sorted, not raw walk order: readdir order is filesystem-dependent, and
    // candidate order must be identical on every machine.
    files.sort();
    let mut candidates = Vec::new();
    for path in files {
        // A single unreadable or non-UTF-8 source file must not lose every
        // candidate found so far -- skip it and continue the pass.
        let src = match std::fs::read_to_string(&path) {
            Ok(src) => src,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping unreadable source file");
                continue;
            }
        };
        extract(&src, &path, &mut candidates);
    }
    Ok((candidates, std::collections::HashMap::new(), Vec::new()))
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
        let fit_score = compute_fit_score(
            kind,
            input_surface,
            complexity,
            param_count,
            // A slice or string carries its own length.
            input_surface == InputSurface::Bytes,
        );
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
                end_line: None,
                end_col: None,
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
        let fit_score = compute_fit_score(
            kind,
            input_surface,
            complexity,
            param_count,
            // A slice or string carries its own length.
            input_surface == InputSurface::Bytes,
        );
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
                end_line: None,
                end_col: None,
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
        let fit_score = compute_fit_score(
            kind,
            input_surface,
            complexity,
            param_count,
            // A slice or string carries its own length.
            input_surface == InputSurface::Bytes,
        );
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
                end_line: None,
                end_col: None,
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

    let mut candidates = Vec::new();
    // Call graph accumulated across all files: function name -> direct callees,
    // and function name -> complexity (membership = project-defined).
    let mut calls: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut complexity_map: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut signals: Vec<crate::enrichment::EnrichmentSignal> = Vec::new();
    // Header file -> the function names it declares, for the public-entry bonus.
    let mut header_declarations: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    // Sorted, not raw walk order: readdir order is filesystem-dependent, and
    // candidate order must be identical on every machine.
    for relative in discoverable_source_files(root, lang)? {
        let path = root.join(&relative);
        // Non-UTF-8 or unreadable sources are common in the wild (Latin-1
        // comments, permission gaps); skip the file rather than aborting the
        // whole project scan. tree-sitter requires `&str`, so a genuinely
        // non-UTF-8 file can only be skipped here regardless.
        let src = match std::fs::read_to_string(&path) {
            Ok(src) => src,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable source file");
                continue;
            }
        };
        let tree = parser.parse(&src, None).ok_or_else(|| {
            ClassifiedError::Internal(format!("parse {}: parser returned no tree", path.display()))
        })?;
        extract_functions(
            &tree,
            &path,
            &src,
            lang,
            &mut candidates,
            &mut calls,
            &mut complexity_map,
        );
        // Same tree, same source: the marginal cost of a signal is a query
        // cursor pass, not another parse.
        signals.extend(analyze_unit(&tree, &src, &relative, lang));
        if is_header(&relative) {
            for name in called_or_declared_names(&src) {
                header_declarations
                    .entry(name.to_owned())
                    .or_default()
                    .push(relative.clone());
            }
        }
    }
    // Annotate candidates with reachability + accumulated complexity.
    crate::reachability::analyze(&mut candidates, &calls, &complexity_map);
    mark_public_entry_points(&mut candidates, root, &header_declarations);
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
    Ok((candidates, call_graph, signals))
}

/// Score added to a function its project declares in a public header.
const PUBLIC_ENTRY_BONUS: f64 = 0.08;

/// Directory names that hold a project's public headers.
const PUBLIC_HEADER_DIRS: [&str; 4] = ["include", "inc", "api", "public"];

fn is_header(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "h" | "hh" | "hpp" | "hxx"))
}

/// The function names `text` declares or calls: every identifier followed by
/// `(`, allowing whitespace, and every identifier closing a macro wrapper as
/// in `API(name) (`.
fn called_or_declared_names(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let skip_space = |mut at: usize| {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        at
    };
    let mut names = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !is_identifier(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && is_identifier(bytes[at]) {
            at += 1;
        }
        let after = skip_space(at);
        let opens = bytes.get(after) == Some(&b'(');
        let wrapped =
            bytes.get(after) == Some(&b')') && bytes.get(skip_space(after + 1)) == Some(&b'(');
        if opens || wrapped {
            names.push(&text[start..at]);
        }
    }
    names
}

/// Raise the candidates a project exposes: those declared in a header that
/// sits nearer the project root than the definition, or under a directory
/// conventionally holding public headers. In a library whose stage decoders
/// share the entry point's buffer signature, this is what tells them apart.
fn mark_public_entry_points(
    candidates: &mut [TargetCandidate],
    root: &Path,
    header_declarations: &std::collections::HashMap<String, Vec<PathBuf>>,
) {
    for candidate in candidates {
        let Some(headers) = header_declarations.get(&candidate.symbol) else {
            continue;
        };
        let definition = candidate
            .location
            .file
            .strip_prefix(root)
            .unwrap_or(&candidate.location.file);
        let depth = definition.components().count();
        let public = headers.iter().any(|header| {
            header.components().count() < depth
                || header.components().any(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .is_some_and(|name| PUBLIC_HEADER_DIRS.contains(&name))
                })
        });
        if public {
            candidate.fit_score = (candidate.fit_score + PUBLIC_ENTRY_BONUS).clamp(0.0, 1.0);
            if candidate.kind == TargetKind::Function {
                candidate.kind = TargetKind::ApiEntry;
            }
        }
    }
}

/// Native static-analysis signals for one translation unit.
///
/// Paths are relative to the project root, matching what the enrichment join
/// compares against; an absolute path here would silently attribute nothing.
#[cfg(feature = "native-analysis")]
fn analyze_unit(
    tree: &tree_sitter::Tree,
    src: &str,
    relative: &Path,
    lang: TargetLanguage,
) -> Vec<crate::enrichment::EnrichmentSignal> {
    let Some(rules) = hf_analysis::rules_for(lang) else {
        return Vec::new();
    };
    let analysis = rules.analyze_bounded(tree, src);
    if analysis.truncated {
        tracing::warn!(
            file = %relative.display(),
            "static analysis truncated at the per-file finding cap"
        );
    }
    analysis
        .findings
        .into_iter()
        .map(|finding| crate::enrichment::EnrichmentSignal {
            relative_path: relative.to_path_buf(),
            start_line: finding.span.start_line,
            start_col: finding.span.start_col,
            rule_key: finding.rule_id.to_owned(),
            weight: finding.severity.weight(),
        })
        .collect()
}

/// Native analysis is not built in, so no signals are produced.
#[cfg(not(feature = "native-analysis"))]
fn analyze_unit(
    _tree: &tree_sitter::Tree,
    _src: &str,
    _relative: &Path,
    _lang: TargetLanguage,
) -> Vec<crate::enrichment::EnrichmentSignal> {
    Vec::new()
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
    // A unit that is itself a fuzz harness is left out of the harness link
    // (`hf_core::c_unit`), so nothing it defines can be called from a
    // generated harness. Its functions still feed the call graph.
    let shipped_harness = classify_unit(src) == UnitRole::FuzzEntry;

    let mut f = |node: tree_sitter::Node| {
        if node.kind() != "function_definition" {
            return;
        }
        let Some(declarator) = node.child_by_field_name("declarator") else {
            return;
        };
        // `int API(name) (params)` parses as a function `API` returning a
        // function: the real name is the macro's argument and the real
        // parameters are the outer list.
        let wrapped = macro_wrapped_name(declarator);
        let name_node = wrapped
            .or_else(|| function_name_node(declarator))
            .or_else(|| find_identifier(&declarator));
        let Some(name_node) = name_node else {
            return;
        };
        let symbol = name_node.utf8_text(src.as_bytes()).unwrap_or("").to_owned();
        let complexity = compute_complexity(node);
        // Record the call graph for interprocedural reachability analysis
        // before deciding whether this function is itself a candidate: a
        // function a harness cannot call (internal linkage, no parameters,
        // `main`) is still code its callers reach, and in C most of a
        // parser's depth sits in `static` helpers.
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

        // Static functions have internal linkage and cannot be called from a
        // separately-compiled harness translation unit. Projects often spell
        // the specifier through a macro (`MEM_STATIC`, `FORCE_INLINE`).
        if has_storage_class_specifier(node, src, "static")
            || has_linkage_macro(node, name_node, src)
        {
            return;
        }
        // A C function defined in a header is an inline helper compiled into
        // every unit that includes it, not an entry point of the project.
        if lang == TargetLanguage::C
            && path.extension().and_then(|extension| extension.to_str()) == Some("h")
        {
            return;
        }
        // The C++ equivalents: an anonymous namespace gives internal linkage,
        // and a private or protected member is not callable from a harness.
        if lang == TargetLanguage::Cpp
            && (in_anonymous_namespace(node) || !is_public_member(node, src))
        {
            return;
        }
        let parameter_list = if wrapped.is_some() {
            declarator.child_by_field_name("parameters")
        } else {
            find_parameter_list(declarator)
        };
        let params = parameter_list.map_or(0, |list| count_parameter_list(&list, src));
        if params == 0 {
            return;
        }
        let parameter_text = parameter_list
            .and_then(|list| list.utf8_text(src.as_bytes()).ok())
            .unwrap_or("");
        // `main` is the program entry point: a harness cannot call it and the
        // engine driver defines its own. `LLVMFuzzer*` functions are the
        // callbacks of a fuzz harness the project already ships.
        if shipped_harness || symbol == "main" || symbol.starts_with("LLVMFuzzer") {
            return;
        }

        let kind = classify(&symbol);
        let input_surface = infer_input_surface(parameter_text);
        let fit_score = compute_fit_score(
            kind,
            input_surface,
            complexity,
            params,
            has_buffer_and_length(parameter_text),
        );
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
        let start = node.start_position();
        let end = node.end_position();
        let location = SourceLocation {
            file: path.to_path_buf(),
            line: u32::try_from(start.row + 1).unwrap_or(u32::MAX),
            col: u32::try_from(start.column + 1).unwrap_or(u32::MAX),
            end_line: Some(u32::try_from(end.row + 1).unwrap_or(u32::MAX)),
            end_col: Some(u32::try_from(end.column + 1).unwrap_or(u32::MAX)),
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

/// Whether a C++ definition sits inside an unnamed `namespace { ... }`.
fn in_anonymous_namespace(node: tree_sitter::Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "namespace_definition"
            && ancestor.child_by_field_name("name").is_none()
        {
            return true;
        }
        current = ancestor.parent();
    }
    false
}

/// Whether a C++ definition is reachable from outside its class: true for
/// free functions, and for members under `public:` (or a `struct`'s default
/// public access when no specifier precedes them).
fn is_public_member(node: tree_sitter::Node<'_>, src: &str) -> bool {
    let Some(body) = node
        .parent()
        .filter(|parent| parent.kind() == "field_declaration_list")
    else {
        return true;
    };
    let mut sibling = node.prev_sibling();
    while let Some(previous) = sibling {
        if previous.kind() == "access_specifier" {
            return previous
                .utf8_text(src.as_bytes())
                .is_ok_and(|text| text.trim().trim_end_matches(':').trim() == "public");
        }
        sibling = previous.prev_sibling();
    }
    body.parent()
        .is_some_and(|owner| owner.kind() == "struct_specifier")
}

/// The node naming a function, reached through the declarator's own
/// `declarator` / `name` fields rather than by searching for the first
/// identifier: in C++ an in-class method is named by a `field_identifier`,
/// and a plain search would land on a parameter name instead. `None` when the
/// chain ends somewhere unexpected; the caller then falls back to
/// [`find_identifier`].
fn function_name_node(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" | "destructor_name" | "operator_name" => Some(node),
        "qualified_identifier" | "template_function" => node
            .child_by_field_name("name")
            .and_then(function_name_node),
        _ => node
            .child_by_field_name("declarator")
            .and_then(function_name_node),
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

/// The first parameter list under a function declarator.
fn find_parameter_list(declarator: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cursor = declarator.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let child = cursor.node();
        if child.kind() == "parameter_list" {
            return Some(child);
        }
        // A function declarator may wrap another declarator.
        if let Some(nested) = find_parameter_list(child) {
            return Some(nested);
        }
        if !cursor.goto_next_sibling() {
            return None;
        }
    }
}

/// How many arguments a parameter list declares.
///
/// A prototype `(void)` parses as a single `parameter_declaration` whose type is
/// the primitive `void` with no declarator. It carries no argument, so it
/// counts as zero -- otherwise the `params == 0` filter never fires and
/// `(void)` functions become bogus fuzz candidates.
fn count_parameter_list(list: &tree_sitter::Node<'_>, src: &str) -> usize {
    let mut count = 0;
    let mut cursor = list.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node().kind() == "parameter_declaration"
                && !is_void_placeholder(&cursor.node(), src)
            {
                count += 1;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    count
}

/// The function name of a definition written `ret MACRO(name) (params)`.
///
/// The grammar reads it as a function `MACRO` whose parameter list is the one
/// bare type name `name`, returning a function. Only that exact form matches,
/// so an ordinary function returning a function pointer is left alone.
fn macro_wrapped_name(declarator: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    if declarator.kind() != "function_declarator" {
        return None;
    }
    let inner = declarator.child_by_field_name("declarator")?;
    if inner.kind() != "function_declarator"
        || inner.child_by_field_name("declarator")?.kind() != "identifier"
    {
        return None;
    }
    let arguments = inner.child_by_field_name("parameters")?;
    let mut cursor = arguments.walk();
    let mut only = None;
    for child in arguments.named_children(&mut cursor) {
        if only.is_some() || child.kind() != "parameter_declaration" {
            return None;
        }
        only = Some(child);
    }
    let only = only?;
    if only.child_by_field_name("declarator").is_some() {
        return None;
    }
    let name = only.child_by_field_name("type")?;
    (name.kind() == "type_identifier").then_some(name)
}

/// Whether the text before a definition's name carries a macro that spells
/// internal linkage or inlining, such as `MEM_STATIC` or `FORCE_INLINE`.
///
/// An export macro (`ZSTDLIB_STATIC_API`) names the opposite and is excluded.
fn has_linkage_macro(
    definition: tree_sitter::Node<'_>,
    name: tree_sitter::Node<'_>,
    src: &str,
) -> bool {
    let prefix = src
        .get(definition.start_byte()..name.start_byte())
        .unwrap_or("");
    prefix
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            let upper = token.to_ascii_uppercase();
            // A lowercase `static`/`inline` is a keyword the grammar reports.
            token
                .chars()
                .any(|character| character.is_ascii_uppercase())
                && !upper.contains("API")
                && !upper.contains("EXPORT")
                && (upper.contains("INLINE") || upper.ends_with("STATIC"))
        })
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

/// Name fragments of functions that turn untrusted bytes into structure: the
/// functions whose defects fuzzing finds most often. Matched anywhere in the
/// lowercased symbol.
const PARSER_NAME_PARTS: [&str; 8] = [
    "parse",
    "decode",
    "deserial",
    "unmarshal",
    "unpack",
    "inflate",
    "decompress",
    "tokeniz",
];

fn classify(symbol: &str) -> TargetKind {
    let lower = symbol.to_ascii_lowercase();
    if PARSER_NAME_PARTS.iter().any(|part| lower.contains(part)) {
        TargetKind::Parser
    } else if lower.contains("_ffi") || lower.starts_with("java_") {
        TargetKind::Ffi
    } else {
        TargetKind::Function
    }
}

fn infer_input_surface(parameters: &str) -> InputSurface {
    if parameters.contains("FILE") {
        InputSurface::File
    } else if parameters.contains("stdin") {
        InputSurface::Stdin
    } else if split_parameters(parameters).any(is_buffer_parameter) {
        InputSurface::Bytes
    } else {
        // Scalars, or pointers to the project's own state: a harness has to
        // build the arguments from the fuzzer's bytes, as it does for a Rust
        // function without a slice.
        InputSurface::Structured
    }
}

/// The parameters of a parenthesized list, split at top-level commas.
fn split_parameters(parameters: &str) -> impl Iterator<Item = &str> {
    let inner = parameters
        .trim()
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(parameters);
    let mut depth = 0_i32;
    inner
        .split(move |character: char| {
            match character {
                '(' | '<' | '[' => depth += 1,
                ')' | '>' | ']' => depth -= 1,
                _ => {}
            }
            character == ',' && depth == 0
        })
        .map(str::trim)
        .filter(|parameter| !parameter.is_empty())
}

/// Type names whose pointer, array, or reference is a run of raw bytes.
const BYTE_TYPES: [&str; 12] = [
    "char", "void", "uint8_t", "int8_t", "u8", "uint8", "byte", "uchar", "bytef", "u_char",
    "wchar_t", "char8_t",
];

/// Standard containers that own a run of bytes.
const BYTE_CONTAINERS: [&str; 6] = [
    "string",
    "string_view",
    "u8string",
    "vector",
    "span",
    "array",
];

/// Whether one C or C++ parameter can receive the fuzzer's bytes directly: a
/// pointer, array, or reference to a byte type, or a standard byte container.
/// A pointer to the project's own state (`DState *s`) cannot.
fn is_buffer_parameter(parameter: &str) -> bool {
    let lower = parameter.to_ascii_lowercase();
    let mut tokens = lower
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty());
    if tokens.clone().any(|token| BYTE_CONTAINERS.contains(&token)) {
        return true;
    }
    parameter.contains(['*', '[', '&']) && tokens.any(|token| BYTE_TYPES.contains(&token))
}

/// Whether a parameter list pairs a byte buffer with an integer right after
/// it: the `(data, len)` signature a harness can call with no decoding.
fn has_buffer_and_length(parameters: &str) -> bool {
    let list: Vec<&str> = split_parameters(parameters).collect();
    list.windows(2).any(|pair| {
        is_buffer_parameter(pair[0]) && !pair[1].contains(['*', '[', '&']) && {
            let lower = pair[1].to_ascii_lowercase();
            [
                "size_t", "int", "long", "unsigned", "uint", "u32", "u64", "short",
            ]
            .iter()
            .any(|integer| lower.contains(integer))
        }
    })
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

/// The heuristic score before the reachability and public-declaration
/// bonuses (`crate::reachability`). The weights sum to 0.77, which with those
/// two bonuses (0.15 and 0.08) tops out at 1.0, so the best target of a large
/// project is not tied with dozens of others at a clamped maximum.
fn compute_fit_score(
    kind: TargetKind,
    input_surface: InputSurface,
    complexity: u32,
    params: usize,
    buffer_and_length: bool,
) -> f64 {
    let mut score = 0.15; // base: has parameters
    if matches!(kind, TargetKind::Parser) {
        score += 0.25;
    }
    // A raw byte surface needs no input decoding in the harness; a structured
    // one is still fuzzable, through a harness that builds the arguments.
    score += match input_surface {
        InputSurface::Bytes => 0.15,
        InputSurface::Structured => 0.05,
        InputSurface::File | InputSurface::Stdin => 0.0,
    };
    if buffer_and_length {
        score += 0.10;
    }
    score += (f64::from(complexity) / 100.0) * 0.10;
    if params >= 2 {
        score += 0.02;
    }
    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::{
        deterministic_target_id, discoverable_source_files, extract_functions,
        extract_go_functions, extract_python_functions,
    };
    use hf_core::target::{
        InputSurface, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
    };
    use ignore::WalkBuilder;
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };
    use tree_sitter::Parser as TsParser;

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

    fn cpp_candidates(src: &str) -> Vec<TargetCandidate> {
        let mut parser = TsParser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut out = Vec::new();
        extract_functions(
            &tree,
            Path::new("parser.cpp"),
            src,
            TargetLanguage::Cpp,
            &mut out,
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        out
    }

    #[test]
    fn cpp_methods_are_named_by_their_own_name_not_a_parameter() {
        // In-class method definitions name the method with a field_identifier;
        // the first plain identifier underneath is a parameter, which used to
        // become the symbol (`p`), colliding every such method into one slot.
        let src = "struct LineParser {\n\
                   int parse_line(const char *p, unsigned n) { return p[0] + n; }\n\
                   };\n\
                   int LineParser_parse_out(const char *q, unsigned n);\n\
                   int Codec::decode(const unsigned char *data, unsigned long size) { return size; }\n\
                   namespace cfg { int parse_config(const unsigned char *buf, unsigned long len) { return len; } }\n";

        let symbols: Vec<String> = cpp_candidates(src).into_iter().map(|c| c.symbol).collect();

        assert!(symbols.contains(&"parse_line".to_owned()), "{symbols:?}");
        assert!(
            !symbols.contains(&"p".to_owned()),
            "a parameter is never the symbol: {symbols:?}"
        );
        assert!(
            symbols.contains(&"decode".to_owned()),
            "out-of-class method keeps its name: {symbols:?}"
        );
        assert!(symbols.contains(&"parse_config".to_owned()), "{symbols:?}");
    }

    #[test]
    fn cpp_internal_linkage_and_non_public_members_are_skipped() {
        // Like a C `static`, anything in an anonymous namespace has internal
        // linkage, and private/protected members cannot be called from a
        // harness translation unit. Public members and named namespaces stay.
        let src = "namespace {\n\
                   int hidden_parse(const char *data, unsigned long n) { return n; }\n\
                   }\n\
                   class Reader {\n\
                   int private_parse(const char *data, unsigned long n) { return n; }\n\
                   public:\n\
                   int read_record(const char *data, unsigned long n) { return n; }\n\
                   protected:\n\
                   int protected_parse(const char *data, unsigned long n) { return n; }\n\
                   };\n\
                   struct Open {\n\
                   int open_parse(const char *data, unsigned long n) { return n; }\n\
                   private:\n\
                   int closed_parse(const char *data, unsigned long n) { return n; }\n\
                   };\n\
                   namespace api { int api_parse(const char *data, unsigned long n) { return n; } }\n";

        let symbols: Vec<String> = cpp_candidates(src).into_iter().map(|c| c.symbol).collect();

        for kept in ["read_record", "open_parse", "api_parse"] {
            assert!(
                symbols.contains(&kept.to_owned()),
                "{kept} kept: {symbols:?}"
            );
        }
        for skipped in [
            "hidden_parse",
            "private_parse",
            "protected_parse",
            "closed_parse",
        ] {
            assert!(
                !symbols.contains(&skipped.to_owned()),
                "{skipped} skipped: {symbols:?}"
            );
        }
    }

    #[test]
    fn functions_of_a_shipped_fuzz_harness_are_not_candidates() {
        // A unit that is itself a fuzz harness is left out of the harness
        // link, so a helper it defines has no linked definition: offering it
        // ends in "undefined reference". Its call edges still count.
        let libfuzzer = "unsigned int psk_callback(void *ssl, const char *hint) { return hint[0]; }\n\
                         int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return psk_callback(0, (const char *)d); }\n";
        let persistent = "int parse_record(const char *data, int n) { return data[0] + n; }\n\
                          int run(int argc, char **argv) { while (HF_ITER(0, 0)) { parse_record(argv[0], argc); } return 0; }\n";
        for (unit, caller, callee) in [
            (libfuzzer, "LLVMFuzzerTestOneInput", "psk_callback"),
            (persistent, "run", "parse_record"),
        ] {
            assert!(c_candidates(unit).is_empty(), "{unit}");
            assert!(cpp_candidates(unit).is_empty(), "{unit}");

            let mut parser = TsParser::new();
            parser
                .set_language(&tree_sitter_c::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(unit, None).unwrap();
            let mut calls = HashMap::new();
            extract_functions(
                &tree,
                Path::new("client.c"),
                unit,
                TargetLanguage::C,
                &mut Vec::new(),
                &mut calls,
                &mut HashMap::new(),
            );
            assert!(
                calls
                    .get(caller)
                    .is_some_and(|callees| callees.contains(&callee.to_owned())),
                "{caller} still records {callee}: {calls:?}"
            );
        }

        // Library code that only mentions the callback is still a target.
        let library = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n);\n\
                       int parse_record(const char *data, int n) { return data[0] + n; }\n";
        let symbols: Vec<String> = c_candidates(library)
            .into_iter()
            .map(|c| c.symbol)
            .collect();
        assert_eq!(symbols, vec!["parse_record".to_owned()]);
    }

    #[test]
    fn c_and_cpp_main_is_not_a_candidate() {
        // `main` is the program entry point: a harness cannot call it, and the
        // engine driver defines its own. It still feeds the call graph.
        let src = "int main(int argc, char **argv) { return parse_input(argv[1], argc); }\n\
                   int parse_input(const char *data, int n) { return data[0] + n; }\n";

        for symbols in [
            c_candidates(src)
                .into_iter()
                .map(|c| c.symbol)
                .collect::<Vec<_>>(),
            cpp_candidates(src)
                .into_iter()
                .map(|c| c.symbol)
                .collect::<Vec<_>>(),
        ] {
            assert_eq!(symbols, vec!["parse_input".to_owned()]);
        }

        // A project's own fuzz harness defines the libFuzzer callbacks; they
        // are entry points of that harness, not code under test.
        let harness = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return parse_input((const char *)d, n); }\n\
                       int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }\n";
        assert!(c_candidates(harness).is_empty());

        let mut parser = TsParser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut calls = HashMap::new();
        extract_functions(
            &tree,
            Path::new("main.c"),
            src,
            TargetLanguage::C,
            &mut Vec::new(),
            &mut calls,
            &mut HashMap::new(),
        );
        assert!(
            calls
                .get("main")
                .is_some_and(|callees| callees.contains(&"parse_input".to_owned())),
            "main still records its callees: {calls:?}"
        );
    }

    fn c_candidates(src: &str) -> Vec<TargetCandidate> {
        let mut parser = TsParser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut out = Vec::new();
        extract_functions(
            &tree,
            Path::new("parser.c"),
            src,
            TargetLanguage::C,
            &mut out,
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        out
    }

    #[test]
    fn c_and_cpp_source_selection_is_sorted_and_language_specific() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "z.h",
            "a.c",
            "one.cc",
            "two.cpp",
            "three.cxx",
            "four.hpp",
            "five.hh",
            "skip.rs",
        ] {
            std::fs::write(dir.path().join(name), b"source").unwrap();
        }
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            discoverable_source_files(&canonical, TargetLanguage::C).unwrap(),
            vec![PathBuf::from("a.c"), PathBuf::from("z.h")]
        );
        assert_eq!(
            discoverable_source_files(&canonical, TargetLanguage::Cpp).unwrap(),
            vec![
                PathBuf::from("five.hh"),
                PathBuf::from("four.hpp"),
                PathBuf::from("one.cc"),
                PathBuf::from("three.cxx"),
                PathBuf::from("two.cpp"),
            ]
        );
        assert!(
            discoverable_source_files(&canonical, TargetLanguage::Rust).is_err(),
            "Semgrep source selection accepts only C and C++"
        );
    }

    #[tokio::test]
    async fn lexical_walk_orders_candidates_by_sorted_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("b.rs"),
            b"pub fn parse_b(data: &[u8]) -> usize { data.len() }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("a.rs"),
            b"pub fn parse_a(data: &[u8]) -> usize { data.len() }\n",
        )
        .unwrap();

        let result = super::discover(dir.path(), TargetLanguage::Rust)
            .await
            .unwrap();
        let symbols: Vec<_> = result
            .candidates
            .iter()
            .map(|candidate| candidate.symbol.clone())
            .collect();
        assert_eq!(symbols, vec!["parse_a".to_owned(), "parse_b".to_owned()]);
    }

    #[test]
    fn c_function_without_a_buffer_parameter_is_not_a_byte_surface() {
        // `scale` cannot be handed the fuzzer's bytes: a harness has to carve
        // integers out of them. It was scored as a raw byte surface, level
        // with a real buffer consumer of the same size.
        let candidates = c_candidates(
            "int scale(int value, int factor) { if (factor > 3) return value; return value * factor; }\n\
             int checksum(const unsigned char *data, unsigned long len) { if (len > 3) return data[0]; return data[0] * 2; }\n",
        );
        let by_symbol = |symbol: &str| {
            candidates
                .iter()
                .find(|candidate| candidate.symbol == symbol)
                .unwrap()
        };
        assert_eq!(by_symbol("scale").input_surface, InputSurface::Structured);
        assert_eq!(by_symbol("checksum").input_surface, InputSurface::Bytes);
        assert!(by_symbol("checksum").fit_score > by_symbol("scale").fit_score);
    }

    #[test]
    fn cpp_reference_and_container_parameters_are_byte_surfaces() {
        let candidates = cpp_candidates(
            "#include <string>\n#include <vector>\n\
             int a(const std::string &text) { return text.size() > 2; }\n\
             int b(std::vector<unsigned char> bytes) { return bytes.size() > 2; }\n\
             int c(std::string_view text) { return text.size() > 2; }\n\
             int d(long count) { return count > 2; }\n",
        );
        let surface = |symbol: &str| {
            candidates
                .iter()
                .find(|candidate| candidate.symbol == symbol)
                .unwrap()
                .input_surface
        };
        assert_eq!(surface("a"), InputSurface::Bytes);
        assert_eq!(surface("b"), InputSurface::Bytes);
        assert_eq!(surface("c"), InputSurface::Bytes);
        assert_eq!(surface("d"), InputSurface::Structured);
    }

    #[test]
    fn decoders_and_deserializers_are_classified_as_parsers() {
        // The bundled `decode_utf8` example is a textbook parser target and
        // was classified as a plain function because only "parse" matched.
        for symbol in [
            "decode_utf8",
            "tlv_record_decode",
            "deserialize_header",
            "msg_unmarshal",
            "unpack_frame",
            "inflate_block",
            "png_decompress",
            "tokenize_line",
            "parse_number",
        ] {
            assert_eq!(super::classify(symbol), TargetKind::Parser, "{symbol}");
        }
        for symbol in ["encode_utf8", "tlv_cursor_init", "checksum", "decorate"] {
            assert_eq!(super::classify(symbol), TargetKind::Function, "{symbol}");
        }
    }

    // The next tests come from scanning real bzip2 1.0.8 and zstd 1.5.7.

    #[test]
    fn a_macro_wrapped_definition_is_named_by_its_function_not_the_macro() {
        // bzip2 defines its whole public API as `int BZ_API(name) (params)`.
        // Every one of those functions was recorded as the target `BZ_API`.
        let candidates = c_candidates(
            "int BZ_API(BZ2_bzBuffToBuffDecompress) ( char* dest, unsigned int* destLen, char* source, unsigned int sourceLen ) { return source[0] + dest[0]; }\n\
             int BZ_API(BZ2_bzDecompressEnd) ( bz_stream *strm ) { return strm != 0; }\n",
        );
        let symbols: Vec<_> = candidates.iter().map(|c| c.symbol.as_str()).collect();
        assert_eq!(
            symbols,
            ["BZ2_bzBuffToBuffDecompress", "BZ2_bzDecompressEnd"]
        );
        assert_eq!(candidates[0].input_surface, InputSurface::Bytes);
    }

    #[test]
    fn linkage_hidden_behind_a_macro_still_excludes_a_helper() {
        // zstd spells `static inline` as MEM_STATIC, FORCE_INLINE_TEMPLATE and
        // HINT_INLINE; those helpers filled the top of the ranking.
        let candidates = c_candidates(
            "MEM_STATIC unsigned a(const unsigned char *p, unsigned long n) { return p[0] + n; }\n\
             FORCE_INLINE_TEMPLATE unsigned b(const unsigned char *p, unsigned long n) { return p[0] + n; }\n\
             HINT_INLINE unsigned c(const unsigned char *p, unsigned long n) { return p[0] + n; }\n\
             ZSTDLIB_API unsigned d(const unsigned char *p, unsigned long n) { return p[0] + n; }\n\
             unsigned e(const unsigned char *p, unsigned long n) { return a(p, n) + b(p, n) + c(p, n); }\n",
        );
        let symbols: Vec<_> = candidates.iter().map(|c| c.symbol.as_str()).collect();
        assert_eq!(symbols, ["d", "e"]);
    }

    #[test]
    fn a_pointer_to_state_is_not_a_byte_buffer() {
        // `BZ2_decompress(DState* s)` outranked the buffer-to-buffer entry
        // point: any pointer counted as the fuzzer's bytes.
        let candidates = c_candidates(
            "int step(DState* s) { return s->pos > 3; }\n\
             int both(FSE_DState_t* state, BIT_DStream_t* bits) { return state != bits; }\n\
             unsigned long plain(void* dst, unsigned long cap, const void* src, unsigned long n) { return cap + n; }\n\
             int text(const char *s) { return s[0]; }\n\
             int bytes(const BYTE* ip, const BYTE* iend) { return ip < iend; }\n",
        );
        let surface = |symbol: &str| {
            candidates
                .iter()
                .find(|candidate| candidate.symbol == symbol)
                .unwrap()
                .input_surface
        };
        assert_eq!(surface("step"), InputSurface::Structured);
        assert_eq!(surface("both"), InputSurface::Structured);
        assert_eq!(surface("plain"), InputSurface::Bytes);
        assert_eq!(surface("text"), InputSurface::Bytes);
        assert_eq!(surface("bytes"), InputSurface::Bytes);
    }

    #[test]
    fn a_buffer_with_its_length_outranks_a_lone_pointer() {
        let candidates = c_candidates(
            "int with_len(const unsigned char *data, unsigned long len) { if (len > 3) return data[0]; return 1; }\n\
             int lone(const unsigned char *data) { if (data[1] > 3) return data[0]; return 1; }\n",
        );
        assert!(
            candidates[0].fit_score > candidates[1].fit_score,
            "{candidates:?}"
        );
    }

    #[tokio::test]
    async fn a_library_entry_point_outranks_its_internal_decoders() {
        // The shape of zstd: the public function is declared in the header at
        // the library root and reaches everything; the stage decoders have the
        // same buffer signature and are declared in an internal header. All
        // of them scored exactly 1.0, in path order.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("common")).unwrap();
        std::fs::create_dir_all(root.join("decompress")).unwrap();
        std::fs::write(
            root.join("lib.h"),
            b"unsigned long LIB_decompress(void* dst, unsigned long cap, const void* src, unsigned long n);\n",
        )
        .unwrap();
        std::fs::write(
            root.join("common/stage.h"),
            b"unsigned long STG_decompress_body(void* dst, unsigned long cap, const void* src, unsigned long n);\n",
        )
        .unwrap();
        std::fs::write(
            root.join("common/stage.c"),
            b"#include \"stage.h\"\n\
              unsigned long STG_decompress_body(void* dst, unsigned long cap, const void* src, unsigned long n) {\n\
                  const unsigned char *p = src; unsigned long i = 0;\n\
                  while (i < n && i < cap) { if (p[i] > 3) i += 2; else i += 1; }\n\
                  return i;\n\
              }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("decompress/lib_decompress.c"),
            b"#include \"../lib.h\"\n#include \"../common/stage.h\"\n\
              unsigned long LIB_decompress(void* dst, unsigned long cap, const void* src, unsigned long n) {\n\
                  if (n < 4) return 0;\n\
                  return STG_decompress_body(dst, cap, src, n);\n\
              }\n",
        )
        .unwrap();

        let inventory = super::discover(root, TargetLanguage::C).await.unwrap();

        let score = |symbol: &str| {
            inventory
                .candidates
                .iter()
                .find(|candidate| candidate.symbol == symbol)
                .unwrap()
                .fit_score
        };
        assert!(
            score("LIB_decompress") > score("STG_decompress_body"),
            "{:?}",
            inventory.candidates
        );
        assert!(
            score("LIB_decompress") < 1.0,
            "the top score keeps headroom"
        );
    }

    #[tokio::test]
    async fn c_functions_defined_in_headers_are_not_candidates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bits.h"),
            b"unsigned read_bits(const unsigned char *p, unsigned long n) { return p[0] + n; }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("use.c"),
            b"#include \"bits.h\"\nunsigned parse_all(const unsigned char *p, unsigned long n) { return read_bits(p, n); }\n",
        )
        .unwrap();
        let inventory = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();
        let symbols: Vec<_> = inventory
            .candidates
            .iter()
            .map(|c| c.symbol.as_str())
            .collect();
        assert_eq!(symbols, ["parse_all"]);
        assert_eq!(inventory.candidates[0].reachable_functions, ["read_bits"]);
    }

    #[tokio::test]
    async fn c_reachability_follows_internal_linkage_helpers() {
        // Most of a C parser's depth sits in `static` helpers. They cannot be
        // fuzzed directly, but the entry point that calls them reaches their
        // code; leaving them out of the call graph made such an entry point
        // look like a leaf and ranked it below shallower functions.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("msg.c"),
            b"#include <stddef.h>\n\
              static void reset_state(void) { }\n\
              static int read_field(const unsigned char *p, size_t n) {\n\
                  if (n < 2) return -1;\n\
                  if (p[0] > 3) return -2;\n\
                  return p[1];\n\
              }\n\
              int msg_decode(const unsigned char *p, size_t n) {\n\
                  reset_state();\n\
                  return read_field(p, n);\n\
              }\n",
        )
        .unwrap();

        let inventory = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();

        let symbols: Vec<_> = inventory
            .candidates
            .iter()
            .map(|candidate| candidate.symbol.as_str())
            .collect();
        assert_eq!(symbols, ["msg_decode"], "helpers are not candidates");
        let entry = &inventory.candidates[0];
        assert_eq!(entry.reachable_functions, ["read_field", "reset_state"]);
        assert!(
            entry.accumulated_complexity > entry.complexity,
            "the helpers' complexity counts toward what the entry point exercises"
        );
    }

    #[tokio::test]
    async fn cpp_reachability_follows_anonymous_namespace_helpers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cfg.cpp"),
            b"#include <cstddef>\n\
              namespace {\n\
              int scan_key(const char *p, std::size_t n) {\n\
                  if (n == 0) return -1;\n\
                  return p[0] == '=' ? 1 : 0;\n\
              }\n\
              }\n\
              int parse_config(const char *p, std::size_t n) { return scan_key(p, n); }\n",
        )
        .unwrap();

        let inventory = super::discover(dir.path(), TargetLanguage::Cpp)
            .await
            .unwrap();

        assert_eq!(inventory.candidates.len(), 1);
        assert_eq!(inventory.candidates[0].symbol, "parse_config");
        assert_eq!(inventory.candidates[0].reachable_functions, ["scan_key"]);
    }

    #[tokio::test]
    async fn centralized_c_walk_preserves_candidate_ids_and_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.c"),
            b"int parse_a(const char *s) { return s[0]; }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.c"),
            b"int parse_b(const char *s) { return s[0]; }\n",
        )
        .unwrap();

        let first = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();
        let second = super::discover(dir.path(), TargetLanguage::C)
            .await
            .unwrap();
        let first_identity: Vec<_> = first
            .candidates
            .iter()
            .map(|candidate| (candidate.symbol.clone(), candidate.id))
            .collect();
        let second_identity: Vec<_> = second
            .candidates
            .iter()
            .map(|candidate| (candidate.symbol.clone(), candidate.id))
            .collect();
        assert_eq!(
            first_identity,
            vec![
                ("parse_a".to_owned(), first_identity[0].1),
                ("parse_b".to_owned(), first_identity[1].1),
            ]
        );
        assert_eq!(second_identity, first_identity);
    }

    fn legacy_c_inventory_oracle(root: &Path) -> TargetInventory {
        let mut parser = TsParser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        let mut candidates = Vec::new();
        let mut calls = HashMap::new();
        let mut complexity_map = HashMap::new();
        let walker = WalkBuilder::new(root).hidden(true).git_ignore(true).build();
        let mut paths = Vec::new();
        for entry in walker {
            let entry = entry.unwrap();
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let path = entry.path();
            if !path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| TargetLanguage::C.extensions().contains(&extension))
            {
                continue;
            }
            paths.push(path.to_path_buf());
        }
        // The production walk sorts for cross-machine determinism; the oracle
        // mirrors that so the comparison pins fields and IDs, not readdir luck.
        paths.sort();
        for path in &paths {
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            let tree = parser.parse(&source, None).unwrap();
            extract_functions(
                &tree,
                path,
                &source,
                TargetLanguage::C,
                &mut candidates,
                &mut calls,
                &mut complexity_map,
            );
        }
        crate::reachability::analyze(&mut candidates, &calls, &complexity_map);
        let mut call_graph = HashMap::new();
        for (caller, callees) in &calls {
            let mut project: Vec<String> = callees
                .iter()
                .filter(|callee| *callee != caller && complexity_map.contains_key(*callee))
                .cloned()
                .collect();
            project.sort();
            project.dedup();
            if !project.is_empty() {
                call_graph.insert(caller.clone(), project);
            }
        }
        for candidate in &mut candidates {
            candidate.project_root = root.to_path_buf();
            candidate.id = deterministic_target_id(candidate);
        }
        TargetInventory {
            project_root: root.to_path_buf(),
            candidates,
            call_graph,
        }
    }

    #[tokio::test]
    async fn c_discovery_matches_the_complete_pre_refactor_oracle() {
        let dir = tempfile::tempdir().unwrap();
        for index in (0..32).rev() {
            std::fs::write(
                dir.path().join(format!("{index:02}.c")),
                format!("int parse_{index:02}(const char *s) {{ return s[0] + {index}; }}\n"),
            )
            .unwrap();
        }
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let oracle = legacy_c_inventory_oracle(&canonical);
        let actual = super::discover(&canonical, TargetLanguage::C)
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(oracle).unwrap(),
            "candidate fields, deterministic IDs, call graph, and legacy order changed"
        );
    }

    #[test]
    fn c_candidate_span_covers_the_complete_definition() {
        let candidates = c_candidates(
            "int parse_packet(const unsigned char *data) {\n\
             if (data[0]) { return 1; }\n\
             return 0;\n\
         }\n",
        );
        let span = &candidates[0].location;
        assert_eq!((span.line, span.col), (1, 1));
        assert_eq!((span.end_line, span.end_col), (Some(4), Some(2)));
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
