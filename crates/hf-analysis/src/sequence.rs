//! Intra-procedural reasoning for bug classes that are a relationship between
//! statements rather than the shape of one.
//!
//! Scope is one function body: no aliasing, no interprocedural reasoning, no
//! path sensitivity. Anything the pass cannot prove harmless counts against
//! reporting, because a missed finding costs one function a slightly-low
//! ranking while a false one costs trust in the whole signal.

use tree_sitter::Node;

/// The `compound_statement` directly containing `node`'s statement, and that
/// statement's index among the block's named children.
///
/// Indices are `u32` because that is what tree-sitter's child accessors take;
/// carrying `usize` here would mean a conversion at every call site.
///
/// `None` when the node is not inside a block, which is how a match at file
/// scope is excluded without a special case.
pub(crate) fn enclosing_statement(node: Node) -> Option<(Node, u32)> {
    let mut current = node;
    loop {
        let parent = current.parent()?;
        if parent.kind() == "compound_statement" {
            let count = u32::try_from(parent.named_child_count()).ok()?;
            let index = (0..count).find(|index| {
                parent
                    .named_child(*index)
                    .is_some_and(|child| child.id() == current.id())
            })?;
            return Some((parent, index));
        }
        current = parent;
    }
}

/// The statements strictly between two positions in one block.
///
/// Empty when the positions are adjacent, equal, or out of order, so a caller
/// never needs to check the ordering itself.
pub(crate) fn statements_between(block: Node<'_>, first: u32, second: u32) -> Vec<Node<'_>> {
    if second <= first + 1 {
        return Vec::new();
    }
    ((first + 1)..second)
        .filter_map(|index| block.named_child(index))
        .collect()
}

/// Statement kinds whose presence between two sites means the statements do not
/// simply execute in the order they appear.
const CONTROL_FLOW_KINDS: [&str; 9] = [
    "if_statement",
    "while_statement",
    "do_statement",
    "for_statement",
    "switch_statement",
    "goto_statement",
    "labeled_statement",
    "return_statement",
    "break_statement",
];

/// Whether any statement in `between` could have changed what `name` refers to.
///
/// Deliberately over-approximating: a statement this cannot prove harmless
/// counts as a kill and suppresses the finding. A missed finding costs one
/// function a slightly-low ranking; a false one costs operator trust in the
/// whole signal, and trust does not come back.
///
/// The expensive case is rule 4 below. Passing the variable to any call kills,
/// because the callee may free or reassign it through a pointer-to-pointer
/// parameter and this pass cannot see into it. That suppresses a real double
/// free written as `free(p); log("freed", p); free(p);`, which is the intended
/// trade.
pub(crate) fn is_killed(between: &[Node], source: &str, name: &str) -> bool {
    between
        .iter()
        .any(|statement| statement_kills(*statement, source, name))
}

fn statement_kills(statement: Node, source: &str, name: &str) -> bool {
    let mut stack = vec![statement];
    while let Some(node) = stack.pop() {
        if CONTROL_FLOW_KINDS.contains(&node.kind()) {
            return true;
        }
        match node.kind() {
            // 1. Assignment to the variable, including compound assignments.
            "assignment_expression" => {
                if names(node.child_by_field_name("left"), source) == Some(name) {
                    return true;
                }
            }
            // 2. Declaring it with an initializer shadows or re-initializes it.
            "init_declarator" => {
                if declared_name(node.child_by_field_name("declarator"), source) == Some(name) {
                    return true;
                }
            }
            // 3. Taking its address lets a callee write through the pointer.
            //    `&p` and `*p` are the same node kind, so read the operator.
            "pointer_expression" => {
                if operator_is(node, source, "&")
                    && names(node.child_by_field_name("argument"), source) == Some(name)
                {
                    return true;
                }
            }
            // 4. Passing it to any call: the callee may free or reassign it.
            "call_expression" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let count = u32::try_from(arguments.named_child_count()).unwrap_or(u32::MAX);
                    for index in 0..count {
                        if names(arguments.named_child(index), source) == Some(name) {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
        let count = u32::try_from(node.child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }
    false
}

/// The text of `node` when it is a bare identifier.
fn names<'a>(node: Option<Node>, source: &'a str) -> Option<&'a str> {
    let node = node?;
    (node.kind() == "identifier")
        .then(|| node.utf8_text(source.as_bytes()).ok())
        .flatten()
}

/// The identifier a declarator ultimately declares, through any pointer or
/// array layers.
fn declared_name<'a>(node: Option<Node>, source: &'a str) -> Option<&'a str> {
    let mut current = node?;
    loop {
        if current.kind() == "identifier" {
            return current.utf8_text(source.as_bytes()).ok();
        }
        current = current.child_by_field_name("declarator")?;
    }
}

/// Whether a node's operator token is `symbol`.
fn operator_is(node: Node, source: &str, symbol: &str) -> bool {
    node.child(0)
        .and_then(|child| child.utf8_text(source.as_bytes()).ok())
        == Some(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .expect("tree-sitter-c loads");
        parser.parse(source, None).expect("fixture parses")
    }

    /// Every `call_expression` whose function name is `name`, in source order.
    fn calls_named<'t>(tree: &'t tree_sitter::Tree, source: &str, name: &str) -> Vec<Node<'t>> {
        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression"
                && node
                    .child_by_field_name("function")
                    .and_then(|function| function.utf8_text(source.as_bytes()).ok())
                    == Some(name)
            {
                found.push(node);
            }
            let count = u32::try_from(node.child_count()).unwrap_or(u32::MAX);
            for index in 0..count {
                if let Some(child) = node.child(index) {
                    stack.push(child);
                }
            }
        }
        found.sort_by_key(tree_sitter::Node::start_byte);
        found
    }

    fn kills(source: &str, name: &str) -> bool {
        let tree = parse(source);
        let calls = calls_named(&tree, source, "free");
        let (block, first) = enclosing_statement(calls[0]).unwrap();
        let (_, second) = enclosing_statement(calls[calls.len() - 1]).unwrap();
        let between = statements_between(block, first, second);
        is_killed(&between, source, name)
    }

    #[test]
    fn an_unrelated_statement_does_not_kill() {
        assert!(!kills("void f(char*p){ free(p); g(); free(p); }", "p"));
    }

    #[test]
    fn a_direct_assignment_kills() {
        assert!(kills("void f(char*p){ free(p); p = 0; free(p); }", "p"));
    }

    #[test]
    fn a_compound_assignment_kills() {
        assert!(kills("void f(char*p){ free(p); p += 1; free(p); }", "p"));
    }

    #[test]
    fn a_declaration_with_an_initializer_kills() {
        assert!(kills(
            "void f(char*q){ free(q); char *p = q; free(p); }",
            "p"
        ));
    }

    #[test]
    fn taking_the_address_kills() {
        assert!(kills("void f(char*p){ free(p); h(&p); free(p); }", "p"));
    }

    #[test]
    fn dereferencing_does_not_kill() {
        // `&p` and `*p` are both `pointer_expression`; only the operator tells
        // them apart. Treating every pointer_expression as address-taken would
        // suppress most true findings, so this is the test that catches it.
        assert!(!kills(
            "void f(char**p){ free(*p); g(**p); free(*p); }",
            "p"
        ));
    }

    #[test]
    fn passing_the_variable_to_a_call_kills() {
        // The callee may free or reassign through a pointer-to-pointer
        // parameter, which this pass cannot see.
        assert!(kills("void f(char*p){ free(p); log_it(p); free(p); }", "p"));
    }

    #[test]
    fn a_branch_between_the_sites_kills() {
        assert!(kills(
            "void f(char*p, int c){ free(p); if (c) { p = 0; } free(p); }",
            "p"
        ));
    }

    #[test]
    fn a_loop_between_the_sites_kills() {
        assert!(kills(
            "void f(char*p, int n){ free(p); while (n--) { g(); } free(p); }",
            "p"
        ));
    }

    #[test]
    fn a_different_variable_is_not_killed() {
        assert!(!kills(
            "void f(char*p, char*q){ free(p); q = 0; free(p); }",
            "p"
        ));
    }

    #[test]
    fn a_call_reports_its_enclosing_block_and_index() {
        let source = "void f(char*p){ g(); free(p); h(); }";
        let tree = parse(source);
        let free = calls_named(&tree, source, "free")[0];

        let (block, index) = enclosing_statement(free).expect("free is inside a block");

        assert_eq!(block.kind(), "compound_statement");
        assert_eq!(index, 1, "free is the second statement");
    }

    #[test]
    fn statements_between_excludes_the_endpoints() {
        let source = "void f(char*p){ free(p); g(); h(); free(p); }";
        let tree = parse(source);
        let frees = calls_named(&tree, source, "free");
        let (block, first) = enclosing_statement(frees[0]).unwrap();
        let (_, second) = enclosing_statement(frees[1]).unwrap();

        let between = statements_between(block, first, second);

        assert_eq!(between.len(), 2, "g() and h(), not the two frees");
    }

    #[test]
    fn adjacent_statements_have_nothing_between_them() {
        let source = "void f(char*p){ free(p); free(p); }";
        let tree = parse(source);
        let frees = calls_named(&tree, source, "free");
        let (block, first) = enclosing_statement(frees[0]).unwrap();
        let (_, second) = enclosing_statement(frees[1]).unwrap();

        assert!(statements_between(block, first, second).is_empty());
    }

    #[test]
    fn out_of_order_positions_yield_nothing() {
        // Callers pair sites in source order; a reversed pair must not be
        // treated as a zero-distance match.
        let source = "void f(char*p){ free(p); g(); free(p); }";
        let tree = parse(source);
        let frees = calls_named(&tree, source, "free");
        let (block, first) = enclosing_statement(frees[0]).unwrap();
        let (_, second) = enclosing_statement(frees[1]).unwrap();

        assert!(statements_between(block, second, first).is_empty());
    }

    #[test]
    fn sites_in_different_blocks_are_not_comparable() {
        // The pass reasons within one block. A free in a branch and a free
        // after it are not a sequence it can judge, so a caller must be able to
        // tell they do not share a block.
        let source = "void f(char*p, int c){ if (c) { free(p); } free(p); }";
        let tree = parse(source);
        let frees = calls_named(&tree, source, "free");
        let (inner, _) = enclosing_statement(frees[0]).unwrap();
        let (outer, _) = enclosing_statement(frees[1]).unwrap();

        assert_ne!(inner.id(), outer.id());
    }
}
