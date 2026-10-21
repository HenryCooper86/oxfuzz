use super::ClangAnalysisError;
use hf_core::clang_analysis::{
    ClangCall, ClangDispatch, ClangFunction, ClangIndex, ClangLimits, ClangTargetAssociation,
    ClangTargetContext, ClangTargetSelector,
};
use hf_core::target::TargetCandidate;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

type Edges<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;
struct Resolution<'a> {
    index: &'a ClangIndex,
    functions: BTreeMap<&'a str, &'a ClangFunction>,
    scopes: BTreeMap<&'a str, &'a str>,
    external: BTreeMap<(&'a str, &'a str), Vec<&'a str>>,
}
impl<'a> Resolution<'a> {
    fn new(index: &'a ClangIndex) -> Self {
        let scopes: BTreeMap<_, _> = index
            .units
            .iter()
            .map(|u| (u.id.as_str(), u.scope.as_str()))
            .collect();
        let mut external: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for f in &index.functions {
            if f.definition && f.linkage == "external" {
                if let Some(scope) = scopes.get(f.unit.as_str()) {
                    external
                        .entry((*scope, f.usr.as_str()))
                        .or_default()
                        .push(f.id.as_str());
                }
            }
        }
        Self {
            index,
            functions: index.functions.iter().map(|f| (f.id.as_str(), f)).collect(),
            scopes,
            external,
        }
    }
    fn callee(&self, call: &ClangCall) -> Option<&'a str> {
        if call.dispatch != ClangDispatch::Direct {
            return None;
        }
        let f = *self.functions.get(call.callee.as_deref()?)?;
        if f.definition {
            return Some(f.id.as_str());
        }
        if f.linkage != "external" {
            return None;
        }
        let scope = self.scopes.get(f.unit.as_str())?;
        match self.external.get(&(*scope, f.usr.as_str()))?.as_slice() {
            [id] => Some(*id),
            _ => None,
        }
    }
    fn edges(&self) -> Edges<'a> {
        let mut edges: Edges<'a> = BTreeMap::new();
        for call in &self.index.calls {
            if let Some(callee) = self.callee(call) {
                if let Some(caller) = self.functions.get(call.caller.as_str()) {
                    edges.entry(caller.id.as_str()).or_default().insert(callee);
                }
            }
        }
        edges
    }
}
fn parents(edges: &Edges<'_>, start: &str) -> BTreeMap<String, Option<String>> {
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
/// Reachable project definitions through resolved direct edges, excluding start.
#[must_use]
pub fn reachable_functions(index: &ClangIndex, start: &str) -> Vec<String> {
    parents(&Resolution::new(index).edges(), start)
        .into_keys()
        .filter(|id| id != start)
        .collect()
}
/// Associate by defining file, declaration range, and qualified or terminal name.
#[must_use]
pub fn associate_target(index: &ClangIndex, target: &TargetCandidate) -> ClangTargetAssociation {
    let selector = ClangTargetSelector::from(target);
    let matches: Vec<_> = index
        .functions
        .iter()
        .filter(|f| matches_selector(f, &selector))
        .collect();
    match matches.as_slice() {
        [f] => ClangTargetAssociation::Exact(f.id.clone()),
        [] => ClangTargetAssociation::Unavailable,
        _ => ClangTargetAssociation::Ambiguous,
    }
}
fn matches_selector(f: &ClangFunction, target: &ClangTargetSelector) -> bool {
    f.definition
        && f.location.as_ref().is_some_and(|l| {
            l.file == target.file
                && (l.line, l.column) >= (target.line, target.column)
                && (l.line, l.column) < (target.end_line, target.end_column)
        })
        && (f.name == target.symbol || f.name.rsplit("::").next() == Some(target.symbol.as_str()))
}
/// Resolve every selected root, preserving separate build variants.
#[must_use]
pub fn selected_roots(index: &ClangIndex, targets: &[ClangTargetSelector]) -> BTreeSet<String> {
    index
        .functions
        .iter()
        .filter(|f| targets.iter().any(|t| matches_selector(f, t)))
        .map(|f| f.id.clone())
        .collect()
}
fn encoded_size<T: serde::Serialize>(value: &T) -> Result<usize, ClangAnalysisError> {
    Ok(serde_json::to_vec(value)
        .map_err(|e| ClangAnalysisError(e.to_string()))?
        .len())
}
/// Collect bounded declarations, located calls, and shortest forward/reverse routes.
///
/// # Errors
/// Rejects a target declaration that cannot fit in the explicit context budget.
pub fn target_context(
    index: &ClangIndex,
    target: &TargetCandidate,
    limits: &ClangLimits,
) -> Result<ClangTargetContext, ClangAnalysisError> {
    let association = associate_target(index, target);
    let mut context = ClangTargetContext {
        association: association.clone(),
        target: None,
        paths: vec![],
        functions: vec![],
        calls: vec![],
        omitted_calls: 0,
        unresolved_calls: 0,
        omitted_functions: 0,
        exploration: None,
        plan: None,
    };
    let ClangTargetAssociation::Exact(id) = association else {
        return Ok(context);
    };
    let resolution = Resolution::new(index);
    let edges = resolution.edges();
    let forward = parents(&edges, &id);
    let mut reversed: Edges<'_> = BTreeMap::new();
    for (caller, callees) in &edges {
        for callee in callees {
            reversed.entry(callee).or_default().insert(caller);
        }
    }
    let reverse = parents(&reversed, &id);
    let extra = super::exploration::referenced_functions(index, &id);
    let selected: BTreeSet<_> = forward
        .keys()
        .chain(reverse.keys())
        .map(String::as_str)
        .chain(extra.iter().map(String::as_str))
        .collect();
    let graph_budget = if index.exploration.is_some() {
        limits.max_context_bytes / 2
    } else {
        limits.max_context_bytes
    };
    context.target = resolution.functions.get(id.as_str()).map(|f| (*f).clone());
    context.unresolved_calls = index
        .calls
        .iter()
        .filter(|c| selected.contains(c.caller.as_str()) && resolution.callee(c).is_none())
        .count();
    let mut used = encoded_size(&context)?;
    if used > graph_budget / 2 {
        return Err(ClangAnalysisError("target exceeds context budget".into()));
    }
    for f in &index.functions {
        if f.id == id || !selected.contains(f.id.as_str()) {
            continue;
        }
        let bytes = encoded_size(f)? + 1;
        if used + bytes > graph_budget / 2 {
            context.omitted_functions += 1;
            continue;
        }
        used += bytes;
        context.functions.push(f.clone());
    }
    let retained: BTreeSet<_> = context
        .functions
        .iter()
        .map(|f| f.id.as_str())
        .chain(std::iter::once(id.as_str()))
        .collect();
    let mut paths_used = 0;
    for node in &retained {
        if !forward.contains_key(*node) && !reverse.contains_key(*node) {
            continue;
        }
        let (map, backwards) = if forward.contains_key(*node) {
            (&forward, true)
        } else {
            (&reverse, false)
        };
        let mut route = Vec::new();
        let mut current = Some(*node);
        let mut bytes = 0;
        while let Some(step) = current {
            if !retained.contains(step) {
                route.clear();
                break;
            }
            bytes += step.len() + 4;
            if bytes + paths_used > graph_budget / 4 {
                route.clear();
                break;
            }
            route.push(step.to_owned());
            current = map.get(step).and_then(|p| p.as_deref());
        }
        if !route.is_empty() {
            if backwards {
                route.reverse();
            }
            paths_used += bytes;
            context.paths.push(route);
        }
    }
    context.paths.sort();
    context.paths.dedup();
    let mut calls_used = 0;
    for call in &index.calls {
        if !selected.contains(call.caller.as_str()) {
            continue;
        }
        let bytes = encoded_size(call)? + 1;
        if calls_used + bytes > graph_budget / 8 || !retained.contains(call.caller.as_str()) {
            context.omitted_calls += 1;
            continue;
        }
        calls_used += bytes;
        context.calls.push(call.clone());
    }
    super::exploration::attach(index, &mut context, limits.max_context_bytes)?;
    Ok(context)
}
