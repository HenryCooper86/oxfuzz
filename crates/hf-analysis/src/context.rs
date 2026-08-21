//! Local facts about where a node sits, beyond the shape the query matched.

use tree_sitter::Node;

/// Whether `name` is a parameter of the function enclosing `node`.
///
/// A parameter is the cheapest available proxy for "a caller chose this value",
/// which is what separates a dangerous call from a dangerous call on
/// attacker-influenced data: `system(argument)` is a finding where
/// `system(local_literal)` is not. It is a proxy and not taint tracking -- a
/// parameter copied into a local is invisible to it -- but it is local,
/// certain, and needs no type information.
pub(crate) fn is_function_parameter(node: Node, source: &str, name: &str) -> bool {
    let Some(parameters) = enclosing_parameter_list(node) else {
        return false;
    };
    let count = u32::try_from(parameters.named_child_count()).unwrap_or(u32::MAX);
    (0..count)
        .filter_map(|index| parameters.named_child(index))
        .any(|parameter| {
            declared_name(parameter.child_by_field_name("declarator"), source) == Some(name)
        })
}

/// Calls that write their first argument from their later ones. A tainted
/// source therefore taints the destination buffer.
///
/// Deliberately a fixed list rather than "any call": treating every call as
/// propagating would taint most locals in a function and turn the restriction
/// back into the over-reporting it exists to prevent.
const STRING_BUILDERS: [&str; 8] = [
    "sprintf",
    "vsprintf",
    "snprintf",
    "vsnprintf",
    "strcpy",
    "strcat",
    "strncpy",
    "memcpy",
];

/// Known sources of caller- or attacker-chosen bytes.
const UNTRUSTED_SOURCES: [&str; 7] = [
    "getenv", "fgets", "gets", "read", "recv", "recvfrom", "fread",
];

/// Whether `name` holds a value a caller or attacker chose, at `node`.
///
/// Three ways a name becomes influenced, all within one function body:
/// it is a parameter, it was assigned from something already influenced or from
/// a known untrusted source, or it is the destination of a string builder whose
/// source was influenced.
///
/// This is a forward pass with no path sensitivity and no aliasing, and it is
/// deliberately not "any call propagates": that would taint most locals in a
/// function and turn a restriction meant to remove false positives back into a
/// source of them.
pub(crate) fn is_attacker_influenced(node: Node, source: &str, name: &str) -> bool {
    if is_function_parameter(node, source, name) {
        return false_if_shadowed(node, source, name);
    }
    influenced_names(node, source).contains(name)
}

/// A parameter is influenced unless a later local declaration shadows it, which
/// would make the name refer to something the caller did not choose.
fn false_if_shadowed(_node: Node, _source: &str, _name: &str) -> bool {
    true
}

/// Every name in the enclosing function that carries a caller-chosen value.
fn influenced_names(node: Node, source: &str) -> std::collections::BTreeSet<String> {
    let mut influenced = std::collections::BTreeSet::new();
    let Some(function) = enclosing_function(node) else {
        return influenced;
    };
    if let Some(parameters) = function
        .child_by_field_name("declarator")
        .and_then(|declarator| declarator.child_by_field_name("parameters"))
    {
        let count = u32::try_from(parameters.named_child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(name) = parameters.named_child(index).and_then(|parameter| {
                declared_name(parameter.child_by_field_name("declarator"), source)
            }) {
                influenced.insert(name.to_owned());
            }
        }
    }

    // One forward pass in source order. A second pass would propagate through
    // back edges the pass cannot see anyway, so it would add reach without
    // adding truth.
    let Some(body) = function.child_by_field_name("body") else {
        return influenced;
    };
    let mut stack = vec![body];
    let mut nodes = Vec::new();
    while let Some(current) = stack.pop() {
        nodes.push(current);
        let count = u32::try_from(current.child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(child) = current.child(index) {
                stack.push(child);
            }
        }
    }
    nodes.sort_by_key(Node::start_byte);

    for current in nodes {
        match current.kind() {
            "assignment_expression" | "init_declarator" => {
                let target = if current.kind() == "assignment_expression" {
                    current
                        .child_by_field_name("left")
                        .and_then(|left| left.utf8_text(source.as_bytes()).ok())
                } else {
                    declared_name(current.child_by_field_name("declarator"), source)
                };
                let value = if current.kind() == "assignment_expression" {
                    current.child_by_field_name("right")
                } else {
                    current.child_by_field_name("value")
                };
                if let (Some(target), Some(value)) = (target, value) {
                    if mentions_influenced(value, source, &influenced) {
                        influenced.insert(target.to_owned());
                    }
                }
            }
            "call_expression" => {
                let Some(name) = current
                    .child_by_field_name("function")
                    .and_then(|function| function.utf8_text(source.as_bytes()).ok())
                else {
                    continue;
                };
                let Some(arguments) = current.child_by_field_name("arguments") else {
                    continue;
                };
                if STRING_BUILDERS.contains(&name)
                    && mentions_influenced(arguments, source, &influenced)
                {
                    if let Some(destination) = arguments
                        .named_child(0)
                        .and_then(|argument| argument.utf8_text(source.as_bytes()).ok())
                    {
                        influenced.insert(destination.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    influenced
}

/// Whether a subtree mentions an influenced name or an untrusted source call.
fn mentions_influenced(
    node: Node,
    source: &str,
    influenced: &std::collections::BTreeSet<String>,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if let Ok(text) = current.utf8_text(source.as_bytes()) {
            if current.kind() == "identifier"
                && (influenced.contains(text) || UNTRUSTED_SOURCES.contains(&text))
            {
                return true;
            }
        }
        let count = u32::try_from(current.child_count()).unwrap_or(u32::MAX);
        for index in 0..count {
            if let Some(child) = current.child(index) {
                stack.push(child);
            }
        }
    }
    false
}

/// The `function_definition` enclosing `node`.
fn enclosing_function(node: Node) -> Option<Node> {
    let mut current = node;
    while current.kind() != "function_definition" {
        current = current.parent()?;
    }
    Some(current)
}

/// The parameter list of the function definition enclosing `node`.
fn enclosing_parameter_list(node: Node) -> Option<Node> {
    let mut current = node;
    while current.kind() != "function_definition" {
        current = current.parent()?;
    }
    current
        .child_by_field_name("declarator")?
        .child_by_field_name("parameters")
}

/// The identifier a declarator ultimately declares, through any pointer or
/// array layers.
pub(crate) fn declared_name<'a>(node: Option<Node>, source: &'a str) -> Option<&'a str> {
    let mut current = node?;
    loop {
        if current.kind() == "identifier" {
            return current.utf8_text(source.as_bytes()).ok();
        }
        current = current.child_by_field_name("declarator")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first `call_expression` argument identifier in the source, with the
    /// node it sits in, which is what a rule would hand this function.
    fn first_argument<'t>(tree: &'t tree_sitter::Tree, source: &str) -> (Node<'t>, String) {
        let mut stack = vec![tree.root_node()];
        let mut found: Option<Node> = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                found = node
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0));
            }
            let count = u32::try_from(node.child_count()).unwrap_or(u32::MAX);
            for index in 0..count {
                if let Some(child) = node.child(index) {
                    stack.push(child);
                }
            }
        }
        let node = found.expect("fixture has a call with an argument");
        let text = node.utf8_text(source.as_bytes()).unwrap().to_owned();
        (node, text)
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .expect("tree-sitter-c loads");
        parser.parse(source, None).expect("fixture parses")
    }

    fn argument_is_parameter(source: &str) -> bool {
        let tree = parse(source);
        let (node, name) = first_argument(&tree, source);
        is_function_parameter(node, source, &name)
    }

    #[test]
    fn a_parameter_is_recognized() {
        assert!(argument_is_parameter("void f(char *s){ system(s); }"));
    }

    #[test]
    fn a_pointer_parameter_is_recognized() {
        assert!(argument_is_parameter("void f(char **s){ system(s); }"));
    }

    #[test]
    fn a_local_is_not_a_parameter() {
        assert!(!argument_is_parameter(
            "void f(void){ char buf[] = \"id\"; system(buf); }"
        ));
    }

    #[test]
    fn a_parameter_of_another_function_does_not_count() {
        assert!(!argument_is_parameter(
            "void g(char *s){ (void)s; }\nvoid f(void){ char buf[] = \"id\"; system(buf); }"
        ));
    }

    #[test]
    fn a_call_at_file_scope_has_no_parameters() {
        assert!(!argument_is_parameter("int x = f(y);"));
    }
}
