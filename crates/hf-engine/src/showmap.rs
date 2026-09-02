//! Per-input coverage via `afl-showmap`.
//!
//! `afl-showmap` runs an AFL-instrumented binary on a single input and prints
//! the set of edges it exercised (one `edge_id:hit_count` line per edge). The
//! set of edge ids is a fingerprint of what that input covers, so hashing it
//! gives a per-input coverage key: two inputs with the same key are redundant
//! and corpus minimization can drop one. This is what turns `corpus prune` from
//! content-dedup into true coverage-based distillation.

/// Build the `afl-showmap` command that captures one input's edge coverage on
/// stdout. `binary` and `input` are container-internal paths.
#[must_use]
pub fn build_showmap_args(binary: &str, input: &str) -> Vec<String> {
    let mut args = vec![
        "afl-showmap".to_owned(),
        "-o".to_owned(),
        "-".to_owned(),  // write the map to stdout
        "-q".to_owned(), // quiet: only the map
        "--".to_owned(),
    ];
    args.extend(crate::afl::build_reproduction_args(binary, input));
    args
}

/// The parsed, sorted, de-duplicated `(edge_id, hit-count bucket)` tuples of
/// one input's `afl-showmap` output. Empty when the binary ran no edge at all.
#[must_use]
pub fn coverage_tuples(showmap_stdout: &str) -> Vec<(u64, u8)> {
    let mut tuples: Vec<(u64, u8)> = showmap_stdout.lines().filter_map(parse_edge).collect();
    tuples.sort_unstable();
    tuples.dedup();
    tuples
}

/// Compute a coverage fingerprint from `afl-showmap` output: the deterministic
/// hash of the sorted, de-duplicated set of `(edge_id, hit-count bucket)` tuples.
/// Returns `None` when the output contains no edges (e.g. the binary failed to
/// run), so the caller can fall back to content hashing rather than collapsing
/// distinct inputs under an empty-coverage key.
///
/// The hit count is folded in via AFL's own bucketing (`classify_count`) rather
/// than dropped: AFL treats `(edge, bucket)` as the coverage tuple, so two inputs
/// exercising the same edges a different number of times are genuinely distinct.
/// Keying only on the edge set would let `corpus prune` collapse them and drop an
/// input AFL considers uniquely covering.
#[must_use]
pub fn coverage_hash(showmap_stdout: &str) -> Option<String> {
    let tuples = coverage_tuples(showmap_stdout);
    if tuples.is_empty() {
        return None;
    }
    // FNV-1a over the sorted (edge, bucket) tuples: deterministic and
    // dependency-free (the key only needs to be equal for equal coverage, not
    // cryptographic).
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut fold = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for (edge, bucket) in tuples {
        for byte in edge.to_le_bytes() {
            fold(byte);
        }
        fold(bucket);
    }
    Some(format!("cov:{hash:016x}"))
}

/// Whether one seed input gets past a harness's entry validation, judged by
/// comparing its coverage tuples against the empty input's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedSurvival {
    /// The seed covered at least one tuple the empty input did not: the
    /// harness let it deeper than the entry path.
    Survives,
    /// The seed covered only tuples the empty input already covers: it died
    /// at entry validation, the most common reason a seed corpus finds
    /// nothing.
    DiesAtEntry,
    /// The seed produced no coverage map at all (crash or measurement
    /// failure); distinct from dying at entry, and never silently treated as
    /// either verdict.
    NotMeasured,
}

/// Classify one seed's survival against the empty input's coverage map.
///
/// Survival is a proxy, stated honestly: a seed that walks a few validation
/// edges the empty input misses and then still rejects has technically new
/// tuples. The verdict is advisory -- it tells an operator which seeds are
/// worth keeping and which to regenerate -- not a gate.
#[must_use]
pub fn classify_seed_survival(seed_map: &str, empty_input_map: &str) -> SeedSurvival {
    let seed = coverage_tuples(seed_map);
    if seed.is_empty() {
        return SeedSurvival::NotMeasured;
    }
    let baseline = coverage_tuples(empty_input_map);
    // Both tuples are sorted, so membership is a binary search; an edge set is
    // small enough that this never matters, but the sorted invariant is free.
    let reaches_further = seed
        .iter()
        .any(|tuple| baseline.binary_search(tuple).is_err());
    if reaches_further {
        SeedSurvival::Survives
    } else {
        SeedSurvival::DiesAtEntry
    }
}

/// Parse `(edge_id, hit-count bucket)` from an `afl-showmap` line of the form
/// `edge_id:hit_count`. A missing/unparsable count is treated as a single hit.
fn parse_edge(line: &str) -> Option<(u64, u8)> {
    let mut parts = line.splitn(2, ':');
    let edge = parts.next()?.trim();
    if edge.is_empty() {
        return None;
    }
    let edge = edge.parse::<u64>().ok()?;
    let count = parts
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(1);
    Some((edge, classify_count(count)))
}

/// Map a raw hit count to AFL++'s coverage bucket. Mirrors AFL's
/// `count_class_lookup`: a monotonic set of power-of-two buckets so small
/// differences in how often an edge is hit do not explode the tuple space, while
/// meaningful jumps (1 vs 2 vs many) stay distinct.
#[must_use]
fn classify_count(count: u64) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn showmap_args_target_stdout_and_input() {
        let args = build_showmap_args("/work/fuzz", "/work/corpus/a");
        assert_eq!(args[0], "afl-showmap");
        assert!(args.windows(2).any(|w| w == ["-o", "-"]));
        let dd = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dd + 1], "/work/fuzz");
        assert_eq!(args[dd + 2], "/work/corpus/a");
    }

    #[test]
    fn identical_tuples_hash_equally_regardless_of_order() {
        let a = "000001:1\n000002:2\n000003:1\n";
        // Same (edge, count) tuples, different line order.
        let b = "000003:1\n000001:1\n000002:2\n";
        assert_eq!(coverage_hash(a), coverage_hash(b));
    }

    #[test]
    fn counts_in_the_same_afl_bucket_hash_equally() {
        // Counts 4 and 7 both fall in AFL bucket 8, so they are equivalent.
        assert_eq!(coverage_hash("1:4\n"), coverage_hash("1:7\n"));
    }

    #[test]
    fn same_edges_different_buckets_hash_differently() {
        // Same edge, hit once vs twice -> different AFL tuples, so distinct keys.
        assert_ne!(coverage_hash("1:1\n"), coverage_hash("1:2\n"));
    }

    #[test]
    fn different_edge_sets_hash_differently() {
        let a = "1:1\n2:1\n";
        let b = "1:1\n2:1\n3:1\n";
        assert_ne!(coverage_hash(a), coverage_hash(b));
    }

    #[test]
    fn empty_output_has_no_hash() {
        assert!(coverage_hash("").is_none());
        assert!(coverage_hash("\n  \n").is_none());
    }

    #[test]
    fn coverage_tuples_parses_sorts_and_dedupes() {
        // Counts 4 and 7 share AFL bucket 8; a missing count is a single hit.
        let tuples = coverage_tuples("3:1\n1:4\n1:7\n2:\n");
        assert_eq!(tuples, vec![(1, 8), (2, 1), (3, 1)]);
    }

    #[test]
    fn a_seed_covering_a_new_tuple_survives() {
        let baseline = "1:1\n2:1\n";
        let deep_seed = "1:1\n2:1\n3:1\n";
        assert_eq!(
            classify_seed_survival(deep_seed, baseline),
            SeedSurvival::Survives
        );
    }

    #[test]
    fn a_seed_covering_only_baseline_tuples_dies_at_entry() {
        let baseline = "1:1\n2:1\n";
        assert_eq!(
            classify_seed_survival(baseline, baseline),
            SeedSurvival::DiesAtEntry
        );
        // A subset (a different early return) is still only baseline coverage.
        assert_eq!(
            classify_seed_survival("1:1\n", baseline),
            SeedSurvival::DiesAtEntry
        );
    }

    #[test]
    fn a_seed_with_no_measured_coverage_is_not_measured() {
        // No tuples means the binary produced no map on this input -- crash or
        // infrastructure -- which is not the same verdict as dying at entry.
        assert_eq!(
            classify_seed_survival("", "1:1\n"),
            SeedSurvival::NotMeasured
        );
    }

    #[test]
    fn a_seed_covering_a_new_bucket_of_a_known_edge_survives() {
        // Same edge id, different AFL bucket: a distinct coverage tuple.
        assert_eq!(
            classify_seed_survival("1:2\n", "1:1\n"),
            SeedSurvival::Survives
        );
    }

    #[test]
    fn against_an_empty_baseline_any_covering_seed_survives() {
        // The empty input itself produced no tuples; covering anything at all
        // got further than it did.
        assert_eq!(classify_seed_survival("1:1\n", ""), SeedSurvival::Survives);
    }
}
