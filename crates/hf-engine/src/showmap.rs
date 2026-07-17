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
    let mut tuples: Vec<(u64, u8)> = showmap_stdout.lines().filter_map(parse_edge).collect();
    if tuples.is_empty() {
        return None;
    }
    tuples.sort_unstable();
    tuples.dedup();
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
}
