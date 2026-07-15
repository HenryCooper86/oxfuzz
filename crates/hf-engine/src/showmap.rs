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
/// hash of the sorted, de-duplicated set of edge ids. Returns `None` when the
/// output contains no edges (e.g. the binary failed to run), so the caller can
/// fall back to content hashing rather than collapsing distinct inputs under an
/// empty-coverage key.
#[must_use]
pub fn coverage_hash(showmap_stdout: &str) -> Option<String> {
    let mut edges: Vec<u64> = showmap_stdout.lines().filter_map(parse_edge_id).collect();
    if edges.is_empty() {
        return None;
    }
    edges.sort_unstable();
    edges.dedup();
    // FNV-1a over the sorted edge ids: deterministic and dependency-free (the
    // key only needs to be equal for equal coverage sets, not cryptographic).
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for edge in edges {
        for byte in edge.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    Some(format!("cov:{hash:016x}"))
}

/// Parse the edge id from an `afl-showmap` line of the form `edge_id:hit_count`.
fn parse_edge_id(line: &str) -> Option<u64> {
    let key = line.split(':').next()?.trim();
    if key.is_empty() {
        return None;
    }
    key.parse::<u64>().ok()
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
    fn identical_edge_sets_hash_equally_regardless_of_order_or_counts() {
        let a = "000001:1\n000002:3\n000003:1\n";
        // Same edges, different order and hit counts.
        let b = "000003:9\n000001:2\n000002:1\n";
        assert_eq!(coverage_hash(a), coverage_hash(b));
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
