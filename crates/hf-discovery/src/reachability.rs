//! Call-graph reachability analysis over discovered functions.
//!
//! From the syntactic call edges the scanner extracts (`fn -> direct callees`),
//! this computes, per candidate, the set of *project* functions it transitively
//! reaches and the accumulated cyclomatic complexity of that set -- how much
//! code fuzzing the target actually exercises. It is an approximation (no
//! function pointers / virtual dispatch), used as a ranking + prompting signal.

use std::collections::{HashMap, HashSet, VecDeque};

use hf_core::target::TargetCandidate;

/// Max reachable functions stored per candidate (to bound prompt/serialized
/// size); complexity is accumulated over the *full* reachable set regardless.
const MAX_REACHABLE_STORED: usize = 64;

/// Annotate each candidate with its reachable project functions and the
/// accumulated complexity of that set.
///
/// `calls` maps a function name to the names it directly calls; `complexity`
/// maps a project function name to its complexity (membership identifies which
/// callees are project-defined -- only those are followed).
pub fn analyze(
    candidates: &mut [TargetCandidate],
    calls: &HashMap<String, Vec<String>>,
    complexity: &HashMap<String, u32>,
) {
    for candidate in candidates.iter_mut() {
        let reachable = reachable_from(&candidate.symbol, calls, complexity);
        let accumulated = candidate.complexity
            + reachable
                .iter()
                .map(|f| complexity.get(f).copied().unwrap_or(0))
                .sum::<u32>();
        let mut list: Vec<String> = reachable.into_iter().collect();
        list.sort();
        list.truncate(MAX_REACHABLE_STORED);
        candidate.reachable_functions = list;
        candidate.accumulated_complexity = accumulated;

        // Reachability bonus: a target that unlocks more reachable complexity
        // exercises more code, so rank it up (a high-leverage "blocker"). Bounded
        // so it refines rather than dominates the existing heuristic score.
        let unlocked = f64::from(accumulated.saturating_sub(candidate.complexity));
        let bonus = (unlocked / 200.0).min(0.15);
        candidate.fit_score = (candidate.fit_score + bonus).clamp(0.0, 1.0);
    }
}

/// BFS over the call graph from `start`, returning the project functions
/// reachable from it (excluding `start`). Only callees defined in the project
/// (present in `complexity`) are followed; library calls are leaves. The visited
/// set makes it cycle-safe.
fn reachable_from(
    start: &str,
    calls: &HashMap<String, Vec<String>>,
    complexity: &HashMap<String, u32>,
) -> HashSet<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(start.to_owned());
    while let Some(name) = queue.pop_front() {
        let Some(callees) = calls.get(&name) else {
            continue;
        };
        for callee in callees {
            if callee != start && complexity.contains_key(callee) && visited.insert(callee.clone())
            {
                queue.push_back(callee.clone());
            }
        }
    }
    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, SourceLocation, TargetKind, TargetLanguage};
    use std::path::PathBuf;

    fn candidate(symbol: &str, complexity: u32) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::new(),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::new(),
                line: 1,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity,
            fit_score: 0.0,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        }
    }

    #[test]
    fn transitive_reachability_and_accumulated_complexity() {
        // entry -> mid -> leaf ; entry also calls libc (not in project).
        let calls = HashMap::from([
            (
                "entry".to_owned(),
                vec!["mid".to_owned(), "memcpy".to_owned()],
            ),
            ("mid".to_owned(), vec!["leaf".to_owned()]),
            ("leaf".to_owned(), vec![]),
        ]);
        let complexity = HashMap::from([
            ("entry".to_owned(), 3),
            ("mid".to_owned(), 5),
            ("leaf".to_owned(), 7),
        ]);
        let mut cands = vec![candidate("entry", 3), candidate("leaf", 7)];
        analyze(&mut cands, &calls, &complexity);

        // entry reaches mid + leaf (memcpy is a library leaf, skipped).
        assert_eq!(cands[0].reachable_functions, vec!["leaf", "mid"]);
        assert_eq!(cands[0].accumulated_complexity, 3 + 5 + 7);

        // leaf reaches nothing.
        assert!(cands[1].reachable_functions.is_empty());
        assert_eq!(cands[1].accumulated_complexity, 7);
    }

    #[test]
    fn cycles_are_handled() {
        let calls = HashMap::from([
            ("a".to_owned(), vec!["b".to_owned()]),
            ("b".to_owned(), vec!["a".to_owned()]),
        ]);
        let complexity = HashMap::from([("a".to_owned(), 1), ("b".to_owned(), 1)]);
        let mut cands = vec![candidate("a", 1)];
        analyze(&mut cands, &calls, &complexity);
        assert_eq!(cands[0].reachable_functions, vec!["b"]);
        assert_eq!(cands[0].accumulated_complexity, 2);
    }
}
