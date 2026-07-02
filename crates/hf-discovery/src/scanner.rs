//! Target discovery scanner.
//!
//! Walks a project with the `ignore` crate, parses C/C++ source with
//! Tree-sitter, extracts function definitions, filters trivial ones, scores
//! them with input-surface and complexity heuristics, and returns a
//! `TargetInventory`.
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
    let (mut candidates, call_graph) = match lang {
        TargetLanguage::C | TargetLanguage::Cpp => scan_c(project_root, lang)?,
        TargetLanguage::Rust => scan_rust(project_root),
        _ => {
            return Err(ClassifiedError::Validation(format!(
                "language {lang:?} not yet supported by the scanner"
            )));
        }
    };
    // Stamp the project root onto every candidate so downstream consumers
    // (persistence dedup keyed on (project, symbol), reports, ranking) can tell
    // which project a target belongs to. The scanner builds candidates without
    // it, so set it once here in the single discovery entry point.
    //
    // Also derive a deterministic id from (project_root, symbol). Storage
    // identity is (project, symbol); a random per-pass id would orphan every
    // harness/corpus/crash/run stored against the target the next time
    // discovery ran. A UUIDv5 over the identity key keeps the id stable across
    // passes and processes while distinct symbols still get distinct ids.
    for c in &mut candidates {
        c.project_root = project_root.to_path_buf();
        c.id = deterministic_target_id(project_root, &c.symbol);
    }
    Ok(TargetInventory {
        project_root: project_root.to_path_buf(),
        candidates,
        call_graph,
    })
}

/// Fixed namespace for `hobot_fuzz` target ids so `UUIDv5` derivation is stable
/// across builds and processes.
const TARGET_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x2a, 0x1c, 0x9b, 0x4d, 0x6e, 0x47, 0x3a, 0xa1, 0x02, 0x9c, 0x3e, 0x5f, 0x71, 0x8b, 0x40,
]);

/// Derive a deterministic target id from the persistence identity
/// `(project_root, symbol)`. Same identity always yields the same id.
fn deterministic_target_id(project_root: &Path, symbol: &str) -> Uuid {
    let key = format!("{}::{}", project_root.display(), symbol);
    Uuid::new_v5(&TARGET_ID_NAMESPACE, key.as_bytes())
}

/// File extensions considered for C vs C++.
fn exts_for(lang: TargetLanguage) -> &'static [&'static str] {
    match lang {
        TargetLanguage::C => &["c", "h"],
        TargetLanguage::Cpp => &["cc", "cpp", "cxx", "hpp", "hh"],
        _ => &[],
    }
}

type ScanResult = (
    Vec<TargetCandidate>,
    std::collections::HashMap<String, Vec<String>>,
);

/// Discover Rust fuzz targets with a dependency-free lexical scan.
///
/// Rust grammar is not vendored here, so this extracts public function
/// definitions (`pub fn`, incl. `async`/`unsafe`) lexically rather than via a
/// full parse. It finds the functions worth a `cargo-fuzz` harness -- public,
/// parameter-bearing, non-test -- and scores them with the same heuristics as
/// the C scanner. It is intentionally conservative: a missed multi-line
/// signature is a lost candidate, never a wrong one.
fn scan_rust(root: &Path) -> ScanResult {
    let walker = WalkBuilder::new(root).hidden(true).git_ignore(true).build();
    let mut candidates = Vec::new();
    for entry in walker.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(path) {
            extract_rust_functions(&src, path, &mut candidates);
        }
    }
    (candidates, std::collections::HashMap::new())
}

/// Extract public, parameter-bearing function definitions from Rust source.
fn extract_rust_functions(src: &str, path: &Path, out: &mut Vec<TargetCandidate>) {
    let mut byte_off = 0usize;
    for (idx, line) in src.lines().enumerate() {
        let line_start = byte_off;
        byte_off += line.len() + 1; // account for the '\n' lines() stripped
        let Some(after_fn) = strip_pub_fn(line.trim_start()) else {
            continue;
        };
        let name = read_ident(after_fn);
        if name.is_empty() || name == "main" || name.starts_with("test_") {
            continue;
        }
        // Parameters: balance parens starting at the first '(' on/after the line.
        let Some(params) = extract_paren_group(&src[line_start..]) else {
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
fn rust_body_complexity(s: &str) -> u32 {
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
    for kw in ["if ", "match ", "for ", "while ", "loop ", "&&", "||", "?"] {
        count += u32::try_from(body.matches(kw).count()).unwrap_or(0);
    }
    count.min(200)
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
        let Some(tree) = parser.parse(&src, None) else {
            continue;
        };
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

#[allow(clippy::too_many_arguments)]
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

        let params = count_parameters(&declarator);
        if params == 0 {
            return;
        }

        let kind = classify(&symbol);
        let input_surface = infer_input_surface(&declarator, src);
        let complexity = compute_complexity(node);
        let fit_score = compute_fit_score(kind, input_surface, complexity, params);
        // Record the call graph for interprocedural reachability analysis.
        complexity_map.insert(symbol.clone(), complexity);
        calls.insert(symbol.clone(), extract_calls(node, src));
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

fn count_parameters(declarator: &tree_sitter::Node<'_>) -> usize {
    let mut cursor = declarator.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "parameter_list" {
                let mut count = 0;
                let mut pc = child.walk();
                if pc.goto_first_child() {
                    loop {
                        if pc.node().kind() == "parameter_declaration" {
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
            let nested = count_parameters(&child);
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
