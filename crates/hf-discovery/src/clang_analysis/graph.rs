use super::ClangAnalysisError;
use hf_core::clang_analysis::{
    ClangDispatch, ClangIndex, ClangLimits, ClangTargetAssociation, ClangTargetContext,
};
use hf_core::target::TargetCandidate;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn adjacency(index: &ClangIndex) -> BTreeMap<&str, BTreeSet<&str>> {
    let functions: BTreeMap<_, _> = index.functions.iter().map(|f| (f.id.as_str(), f)).collect();
    let scopes: BTreeMap<_, _> = index
        .units
        .iter()
        .map(|u| (u.id.as_str(), u.scope.as_str()))
        .collect();
    let mut external: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for f in &index.functions {
        if f.definition && f.linkage == "external" {
            if let Some(scope) = scopes.get(f.unit.as_str()) {
                external.entry((scope, &f.usr)).or_default().push(&f.id);
            }
        }
    }
    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for call in &index.calls {
        if call.dispatch != ClangDispatch::Direct {
            continue;
        }
        let Some(f) = call.callee.as_deref().and_then(|id| functions.get(id)) else {
            continue;
        };
        let resolved = if f.definition {
            Some(f.id.as_str())
        } else if f.linkage == "external" {
            scopes
                .get(f.unit.as_str())
                .and_then(|scope| external.get(&(scope, f.usr.as_str())))
                .and_then(|definitions| match definitions.as_slice() {
                    [id] => Some(*id),
                    _ => None,
                })
        } else {
            None
        };
        if let Some(callee) = resolved {
            edges.entry(&call.caller).or_default().insert(callee);
        }
    }
    edges
}

/// Reachable project definitions through resolved direct edges, excluding start.
#[must_use]
pub fn reachable_functions(index: &ClangIndex, start: &str) -> Vec<String> {
    parents(index, start)
        .into_keys()
        .filter(|id| id != start)
        .collect()
}

fn parents(index: &ClangIndex, start: &str) -> BTreeMap<String, Option<String>> {
    let edges = adjacency(index);
    let mut found = BTreeMap::from([(start.to_owned(), None)]);
    let mut queue = VecDeque::from([start.to_owned()]);
    while let Some(id) = queue.pop_front() {
        if let Some(next) = edges.get(id.as_str()) {
            for callee in next {
                if !found.contains_key(*callee) {
                    found.insert((*callee).to_owned(), Some(id.clone()));
                    queue.push_back((*callee).to_owned());
                }
            }
        }
    }
    found
}

/// Associate a candidate by file, definition line, and qualified or terminal name.
#[must_use]
pub fn associate_target(index: &ClangIndex, target: &TargetCandidate) -> ClangTargetAssociation {
    let matches: Vec<_> = index
        .functions
        .iter()
        .filter(|f| {
            f.definition
                && f.location.as_ref().is_some_and(|l| {
                    l.file == target.relative_file() && l.line == target.location.line
                })
                && (f.name == target.symbol
                    || f.name.rsplit("::").next() == Some(target.symbol.as_str()))
        })
        .collect();
    match matches.as_slice() {
        [f] => ClangTargetAssociation::Exact(f.id.clone()),
        [] => ClangTargetAssociation::Unavailable,
        _ => ClangTargetAssociation::Ambiguous,
    }
}

/// Build deterministic typed context without asserting executable reachability.
///
/// # Errors
/// Returns an error if context cannot retain its target within the byte budget.
pub fn target_context(
    index: &ClangIndex,
    target: &TargetCandidate,
    limits: &ClangLimits,
) -> Result<ClangTargetContext, ClangAnalysisError> {
    let association = associate_target(index, target);
    let ClangTargetAssociation::Exact(ref id) = association else {
        return Ok(ClangTargetContext {
            association,
            target: None,
            paths: vec![],
            functions: vec![],
            unresolved_calls: 0,
            omitted_functions: 0,
        });
    };
    let routes = parents(index, id);
    let mut selected: BTreeSet<String> = routes.keys().cloned().collect();
    for call in &index.calls {
        if call.dispatch == ClangDispatch::Direct && call.callee.as_ref() == Some(id) {
            selected.insert(call.caller.clone());
        }
    }
    let target_function = index.functions.iter().find(|f| &f.id == id).cloned();
    let unresolved_calls = index
        .calls
        .iter()
        .filter(|c| {
            selected.contains(&c.caller)
                && (c.dispatch != ClangDispatch::Direct
                    || c.callee.as_ref().is_none_or(|callee| {
                        !index
                            .functions
                            .iter()
                            .any(|f| &f.id == callee && f.definition)
                    }))
        })
        .count();
    let mut context = ClangTargetContext {
        association,
        target: target_function,
        paths: Vec::new(),
        functions: index
            .functions
            .iter()
            .filter(|f| selected.contains(&f.id))
            .cloned()
            .collect(),
        unresolved_calls,
        omitted_functions: 0,
    };
    loop {
        let size = serde_json::to_vec(&context)
            .map_err(|e| ClangAnalysisError(e.to_string()))?
            .len();
        if size <= limits.max_context_bytes / 2 {
            let retained: BTreeSet<_> = context.functions.iter().map(|f| f.id.as_str()).collect();
            let mut path_bytes = 0;
            for function in &context.functions {
                let mut path = Vec::new();
                let mut current = Some(function.id.as_str());
                while let Some(node) = current {
                    if !retained.contains(node) {
                        path.clear();
                        break;
                    }
                    path_bytes += node.len();
                    if path_bytes > limits.max_context_bytes / 4 {
                        path.clear();
                        break;
                    }
                    path.push(node.to_owned());
                    current = routes.get(node).and_then(|parent| parent.as_deref());
                }
                if !path.is_empty() {
                    path.reverse();
                    context.paths.push(path);
                }
            }
            return Ok(context);
        }
        let Some(removed) = context.functions.pop() else {
            return Err(ClangAnalysisError("target exceeds context budget".into()));
        };
        context.paths.retain(|path| !path.contains(&removed.id));
        context.omitted_functions += 1;
    }
}
