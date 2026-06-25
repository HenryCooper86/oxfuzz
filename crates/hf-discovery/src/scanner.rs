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
    let candidates = match lang {
        TargetLanguage::C | TargetLanguage::Cpp => scan_c(project_root, lang)?,
        _ => {
            return Err(ClassifiedError::Validation(format!(
                "language {lang:?} not yet supported by the scanner"
            )));
        }
    };
    Ok(TargetInventory {
        project_root: project_root.to_path_buf(),
        candidates,
    })
}

/// File extensions considered for C vs C++.
fn exts_for(lang: TargetLanguage) -> &'static [&'static str] {
    match lang {
        TargetLanguage::C => &["c", "h"],
        TargetLanguage::Cpp => &["cc", "cpp", "cxx", "hpp", "hh"],
        _ => &[],
    }
}

fn scan_c(root: &Path, lang: TargetLanguage) -> Result<Vec<TargetCandidate>, ClassifiedError> {
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
        extract_functions(&tree, path, &src, lang, &mut candidates);
    }
    Ok(candidates)
}

fn extract_functions(
    tree: &tree_sitter::Tree,
    path: &Path,
    src: &str,
    lang: TargetLanguage,
    out: &mut Vec<TargetCandidate>,
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
                        if pc.node().kind() == "parameter_declaration" {
                            count += 1;
                        }
                        if !pc.goto_next_sibling() {
                            break;
                        }
                    }
                }
                let _ = src;
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
