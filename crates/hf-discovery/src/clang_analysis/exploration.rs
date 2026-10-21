use super::{
    normalize::{bounded, location},
    ClangAnalysisError,
};
use hf_core::clang_analysis::{
    ClangCallWitness, ClangCfgStatus, ClangCondition, ClangExploration, ClangFunction,
    ClangHarnessPlan, ClangIndex, ClangInputConstraint, ClangMethodKind, ClangPlanArgument,
    ClangTargetContext,
};
use std::collections::{BTreeMap, BTreeSet};

fn decimal(value: &str) -> Option<(bool, &str)> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |v| (true, v));
    if value.len() > 4096 || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let magnitude = digits.trim_start_matches('0');
    Some((negative && !magnitude.is_empty(), magnitude))
}
fn ordered(min: &str, max: &str) -> bool {
    let (Some((a_negative, a)), Some((b_negative, b))) = (decimal(min), decimal(max)) else {
        return false;
    };
    if a_negative != b_negative {
        return a_negative;
    }
    let order = (a.len(), a).cmp(&(b.len(), b));
    if a_negative {
        !order.is_lt()
    } else {
        !order.is_gt()
    }
}
fn indices(values: &[usize], count: usize) -> bool {
    values.len() <= count
        && values.iter().all(|v| *v < count)
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn condition(value: &ClangCondition, function: &ClangFunction) -> bool {
    location(&value.location)
        && value.text.as_ref().is_none_or(|s| bounded(s, 4096))
        && indices(&value.parameters, function.parameters.len())
}
fn constraints(values: &[ClangInputConstraint], root: &ClangFunction) -> bool {
    indices(
        &values.iter().map(|v| v.parameter).collect::<Vec<_>>(),
        root.parameters.len(),
    ) && values.iter().all(|v| {
        v.min.as_deref().is_none_or(|s| decimal(s).is_some())
            && v.max.as_deref().is_none_or(|s| decimal(s).is_some())
            && v.min
                .as_deref()
                .zip(v.max.as_deref())
                .is_none_or(|(a, b)| ordered(a, b))
            && (v.nonnull.is_none() || (v.min.is_none() && v.max.is_none()))
    })
}

pub(super) fn validate(index: &ClangIndex) -> Result<(), ClangAnalysisError> {
    let invalid = || ClangAnalysisError("invalid exploration references, values, or limits".into());
    let Some(e) = &index.exploration else {
        return Ok(());
    };
    let l = &e.limits;
    if e.engine != "clang-static-analyzer-range-v1"
        || l.validate().is_err()
        || e.calls.len().saturating_add(e.branches.len()) > l.max_records
        || e.roots.len() > index.functions.len()
        || e.cfgs.len() != e.roots.len()
        || e.cfgs.iter().map(|c| c.blocks.len()).sum::<usize>() > l.max_cfg_blocks
        || (e.omitted_records > 0 && !e.exhausted)
    {
        return Err(invalid());
    }
    let functions: BTreeMap<_, _> = index.functions.iter().map(|f| (f.id.as_str(), f)).collect();
    let call_sites: BTreeSet<_> = index
        .calls
        .iter()
        .map(|c| {
            (
                &c.caller,
                &c.callee,
                &c.location.file,
                c.location.line,
                c.location.column,
            )
        })
        .collect();
    let unresolved_sites: BTreeSet<_> = index
        .calls
        .iter()
        .filter(|c| c.callee.is_none())
        .map(|c| {
            (
                &c.caller,
                &c.location.file,
                c.location.line,
                c.location.column,
            )
        })
        .collect();
    let edges: BTreeSet<_> = index
        .calls
        .iter()
        .filter_map(|c| c.callee.as_ref().map(|callee| (&c.caller, callee)))
        .collect();
    let unresolved_callers: BTreeSet<_> = index
        .calls
        .iter()
        .filter(|c| c.callee.is_none())
        .map(|c| &c.caller)
        .collect();
    let producer_sites: BTreeSet<_> = index
        .calls
        .iter()
        .filter_map(|c| {
            c.callee
                .as_ref()
                .map(|callee| (callee, &c.location.file, c.location.line, c.location.column))
        })
        .collect();
    let roots: BTreeSet<_> = e.roots.iter().map(String::as_str).collect();
    if roots.len() != e.roots.len()
        || roots
            .iter()
            .any(|r| !functions.get(r).is_some_and(|f| f.definition))
    {
        return Err(invalid());
    }
    let mut cfgs = BTreeSet::new();
    for cfg in &e.cfgs {
        if !roots.contains(cfg.function.as_str()) || !cfgs.insert(&cfg.function) {
            return Err(invalid());
        }
        let function = functions[cfg.function.as_str()];
        let blocks: BTreeSet<_> = cfg.blocks.iter().map(|b| b.id).collect();
        if blocks.len() != cfg.blocks.len()
            || (cfg.status != ClangCfgStatus::Complete && !cfg.blocks.is_empty())
            || (cfg.status == ClangCfgStatus::Complete && cfg.blocks.is_empty())
            || (cfg.status == ClangCfgStatus::Truncated && !e.exhausted)
            || cfg.blocks.iter().any(|b| {
                b.successors.len() > 100_000
                    || b.successors.iter().flatten().any(|id| !blocks.contains(id))
                    || b.condition
                        .as_ref()
                        .is_some_and(|c| !condition(c, function))
            })
        {
            return Err(invalid());
        }
    }
    for call in &e.calls {
        let Some(root) = functions
            .get(call.root.as_str())
            .filter(|_| roots.contains(call.root.as_str()))
        else {
            return Err(invalid());
        };
        let Some(caller) = functions.get(call.caller.as_str()) else {
            return Err(invalid());
        };
        let unknown_destination = call
            .callee
            .as_deref()
            .is_some_and(|id| !functions.contains_key(id));
        if unknown_destination
            || caller.unit != root.unit
            || !location(&call.location)
            || !constraints(&call.constraints, root)
            || call.arguments.len() > 1024
            || call.arguments.iter().enumerate().any(|(i, a)| {
                a.argument != i
                    || !indices(&a.parameters, root.parameters.len())
                    || a.constant.as_deref().is_some_and(|s| decimal(s).is_none())
                    || a.producer.as_ref().is_some_and(|p| {
                        functions
                            .get(p.function.as_str())
                            .is_none_or(|f| f.unit != root.unit)
                            || !location(&p.location)
                            || !producer_sites.contains(&(
                                &p.function,
                                &p.location.file,
                                p.location.line,
                                p.location.column,
                            ))
                    })
            })
            || call.path.len() > l.max_inline_depth as usize + 2
            || call.path.first() != Some(&call.root)
            || call.path.last() != call.callee.as_ref().or(Some(&call.caller))
            || call.callee.is_some()
                && call.path.get(call.path.len().saturating_sub(2)) != Some(&call.caller)
            || call.path.iter().any(|id| {
                functions
                    .get(id.as_str())
                    .is_none_or(|f| f.unit != root.unit)
            })
            || call.path.windows(2).any(|pair| {
                !edges.contains(&(&pair[0], &pair[1])) && !unresolved_callers.contains(&pair[0])
            })
            || !call_sites.contains(&(
                &call.caller,
                &call.callee,
                &call.location.file,
                call.location.line,
                call.location.column,
            )) && !unresolved_sites.contains(&(
                &call.caller,
                &call.location.file,
                call.location.line,
                call.location.column,
            ))
        {
            return Err(invalid());
        }
    }
    for branch in &e.branches {
        let Some(root) = functions
            .get(branch.root.as_str())
            .filter(|_| roots.contains(branch.root.as_str()))
        else {
            return Err(invalid());
        };
        let Some(caller) = functions.get(branch.caller.as_str()) else {
            return Err(invalid());
        };
        if caller.unit != root.unit
            || !condition(&branch.condition, caller)
            || !constraints(&branch.constraints, root)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn referenced_functions(index: &ClangIndex, id: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    if let Some(e) = &index.exploration {
        for call in e.calls.iter().filter(|c| c.root == id) {
            ids.insert(call.caller.clone());
            ids.extend(call.callee.clone());
            ids.extend(call.path.iter().cloned());
            ids.extend(
                call.arguments
                    .iter()
                    .filter_map(|a| a.producer.as_ref().map(|p| p.function.clone())),
            );
        }
        ids.extend(
            e.branches
                .iter()
                .filter(|b| b.root == id)
                .map(|b| b.caller.clone()),
        );
    }
    ids
}

fn argument_plan(
    call: &ClangCallWitness,
    index: usize,
) -> (Vec<ClangPlanArgument>, Vec<ClangPlanArgument>) {
    let mut inputs = vec![];
    let mut producers = vec![];
    for argument in &call.arguments {
        let reference = ClangPlanArgument {
            call: index,
            argument: argument.argument,
        };
        if !argument.parameters.is_empty() {
            inputs.push(reference.clone());
        }
        if argument.producer.is_some() {
            producers.push(reference);
        }
    }
    (inputs, producers)
}
fn encoded<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ClangAnalysisError> {
    serde_json::to_vec(value).map_err(|e| ClangAnalysisError(e.to_string()))
}

/// Prompt-escaped JSON length without rebuilding the serialized record.
fn escaped_len(bytes: &[u8]) -> usize {
    bytes.len()
        + 5 * bytes
            .iter()
            .copied()
            .filter(|b| *b == b'<' || *b == b'>' || *b == b'&')
            .count()
}

fn size<T: serde::Serialize>(value: &T) -> Result<usize, ClangAnalysisError> {
    Ok(escaped_len(&encoded(value)?))
}

pub(super) fn attach(
    index: &ClangIndex,
    context: &mut ClangTargetContext,
    budget: usize,
) -> Result<(), ClangAnalysisError> {
    let Some(target) = &context.target else {
        return Ok(());
    };
    let id = target.id.clone();
    let Some(all) = index.exploration.as_ref().filter(|e| e.roots.contains(&id)) else {
        return Ok(());
    };
    let retained: BTreeSet<_> = context
        .functions
        .iter()
        .map(|f| f.id.clone())
        .chain([id.clone()])
        .collect();
    let mut evidence = ClangExploration {
        engine: all.engine.clone(),
        limits: all.limits.clone(),
        roots: vec![id.clone()],
        cfgs: vec![],
        calls: vec![],
        branches: vec![],
        exhausted: all.exhausted,
        omitted_records: all.omitted_records,
    };
    context.exploration = Some(evidence.clone());
    let mut plan = ClangHarnessPlan {
        inputs: vec![],
        guards: vec![],
        producer_uses: vec![],
        caller_paths: vec![],
    };
    for (i, path) in context.paths.iter().enumerate() {
        if path.len() > 1
            && path.last() == Some(&id)
            && path
                .first()
                .and_then(|first| context.functions.iter().find(|f| &f.id == first))
                .is_some_and(|f| {
                    f.linkage == "external"
                        && f.method_kind != ClangMethodKind::Instance
                        && ["none", "public"].contains(&f.access.as_str())
                })
        {
            plan.caller_paths.push(i);
        }
    }
    context.plan = Some(plan.clone());
    let mut used = size(context)?.saturating_add(hf_prompt::clang_context_wrapper_bytes(context));
    if used > budget {
        return Err(ClangAnalysisError(
            "exploration metadata exceeds context budget".into(),
        ));
    }
    // Reserve decimal growth of omitted counters and array separators once.
    used += 64;
    // Under budget pressure select distinct branch guards first, then call
    // witnesses carrying root-input provenance, then raw CFG blocks. Exact
    // duplicate observations add no evidence: they coalesce silently without
    // consuming budget or counting as omitted records. The upstream helper's
    // omitted_records total is preserved verbatim; only distinct records this
    // attachment excludes are added to it.
    let mut seen = BTreeSet::new();
    for branch in all.branches.iter().filter(|b| b.root == id) {
        let bytes = encoded(branch)?;
        let cost = escaped_len(&bytes) + 24;
        if !seen.insert(bytes) {
            continue;
        }
        if retained.contains(&branch.caller) && used + cost <= budget {
            used += cost;
            plan.guards.push(evidence.branches.len());
            evidence.branches.push(branch.clone());
        } else {
            evidence.omitted_records = evidence.omitted_records.saturating_add(1);
        }
    }
    for call in all.calls.iter().filter(|c| c.root == id) {
        let bytes = encoded(call)?;
        let mut cost = escaped_len(&bytes) + 4;
        if !seen.insert(bytes) {
            continue;
        }
        let (inputs, producers) = argument_plan(call, evidence.calls.len());
        cost += size(&inputs)? + size(&producers)?;
        let references = std::iter::once(&call.caller)
            .chain(call.callee.iter())
            .chain(call.path.iter())
            .chain(
                call.arguments
                    .iter()
                    .filter_map(|a| a.producer.as_ref().map(|p| &p.function)),
            );
        if references.clone().all(|f| retained.contains(f)) && used + cost <= budget {
            used += cost;
            evidence.calls.push(call.clone());
            plan.inputs.extend(inputs);
            plan.producer_uses.extend(producers);
        } else {
            evidence.omitted_records = evidence.omitted_records.saturating_add(1);
        }
    }
    for cfg in all.cfgs.iter().filter(|c| c.function == id) {
        let bytes = encoded(cfg)?;
        let cost = escaped_len(&bytes) + 1;
        if !seen.insert(bytes) {
            continue;
        }
        if used + cost <= budget {
            used += cost;
            evidence.cfgs.push(cfg.clone());
        } else {
            evidence.omitted_records = evidence.omitted_records.saturating_add(1);
        }
    }
    context.plan = Some(plan);
    context.exploration = Some(evidence);
    Ok(())
}
