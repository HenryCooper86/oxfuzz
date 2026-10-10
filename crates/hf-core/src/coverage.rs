//! Coverage model.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A coverage report for a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub run_id: Uuid,
    pub edges: u64,
    pub blocks: u64,
    pub delta_edges: i64,
    pub stagnation_secs: u64,
    pub new_edges_files: Vec<PathBuf>,
}

/// Bytes in one retained edge-set bitmap. Bit `i` marks AFL coverage-map
/// offset `i` as covered by the run the set belongs to.
pub const EDGE_SET_BYTES: usize = 64 * 1024;

/// Coverage-map offsets one edge set addresses (one bit each). Harnesses
/// oxfuzz builds use AFL's default 65536-entry map, well under this ceiling;
/// a larger `AFL_MAP_SIZE` build overflows here and fails capture rather than
/// silently dropping edges.
pub const EDGE_SET_CAPACITY: u64 = (EDGE_SET_BYTES * 8) as u64;

/// One run's covered edge set: the AFL coverage-map offsets its retained
/// corpus exercises, as a fixed-size bitmap.
///
/// Presence semantics only: the hit-count bucket an input reached is folded
/// away, so the set answers "which edges did this run cover" and nothing
/// about how often. The identity is the map offset the engine optimizes, so
/// two runs are directly comparable only when they measured the same binary
/// (AFL assigns edge ids per build).
#[derive(Clone, PartialEq, Eq)]
pub struct EdgeSet {
    bits: Box<[u8; EDGE_SET_BYTES]>,
}

impl std::fmt::Debug for EdgeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeSet")
            .field("edges", &self.count())
            .finish()
    }
}

impl Default for EdgeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: Box::new([0; EDGE_SET_BYTES]),
        }
    }

    /// Mark one coverage-map offset covered.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when `edge` is beyond
    /// [`EDGE_SET_CAPACITY`]: storing it would silently drop coverage.
    pub fn set(&mut self, edge: u64) -> Result<(), crate::error::ClassifiedError> {
        if edge >= EDGE_SET_CAPACITY {
            return Err(crate::error::ClassifiedError::Validation(format!(
                "edge id {edge} exceeds the edge-set capacity of {EDGE_SET_CAPACITY} offsets"
            )));
        }
        let index = usize::try_from(edge).map_err(|_| {
            crate::error::ClassifiedError::Validation(format!(
                "edge id {edge} exceeds the edge-set capacity of {EDGE_SET_CAPACITY} offsets"
            ))
        })?;
        self.bits[index / 8] |= 1 << (index % 8);
        Ok(())
    }

    /// Whether the offset is covered. Out-of-capacity offsets are never
    /// covered (they were rejected at record time).
    #[must_use]
    pub fn contains(&self, edge: u64) -> bool {
        usize::try_from(edge).is_ok_and(|index| {
            index < EDGE_SET_BYTES * 8 && self.bits[index / 8] & (1 << (index % 8)) != 0
        })
    }

    /// How many offsets are covered.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.bits
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum()
    }

    /// The raw bitmap, exactly [`EDGE_SET_BYTES`] long.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; EDGE_SET_BYTES] {
        &self.bits
    }

    /// Restore a set from its raw bitmap.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when `bytes` is not exactly
    /// [`EDGE_SET_BYTES`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ClassifiedError> {
        let bits = <[u8; EDGE_SET_BYTES]>::try_from(bytes).map_err(|_| {
            crate::error::ClassifiedError::Validation(format!(
                "edge-set map must be exactly {EDGE_SET_BYTES} bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self {
            bits: Box::new(bits),
        })
    }

    /// Set-compare `self` (baseline a) against `other` (b): exact counts for
    /// each side, the intersection, and the union, plus the lowest
    /// `sample_cap` ids exclusive to each side.
    #[must_use]
    pub fn diff(&self, other: &EdgeSet, sample_cap: usize) -> EdgeSetDiff {
        let mut diff = EdgeSetDiff::default();
        for byte_index in 0..EDGE_SET_BYTES {
            let a = self.bits[byte_index];
            let b = other.bits[byte_index];
            diff.only_a += u64::from((a & !b).count_ones());
            diff.only_b += u64::from((b & !a).count_ones());
            diff.common += u64::from((a & b).count_ones());
            diff.union += u64::from((a | b).count_ones());
            let collect = |mask: u8, sample: &mut Vec<u64>| {
                if sample.len() >= sample_cap {
                    return;
                }
                let mut mask = mask;
                while mask != 0 && sample.len() < sample_cap {
                    let bit = mask.trailing_zeros();
                    sample.push(byte_index as u64 * 8 + u64::from(bit));
                    mask &= mask - 1;
                }
            };
            collect(a & !b, &mut diff.only_a_sample);
            collect(b & !a, &mut diff.only_b_sample);
        }
        diff
    }
}

/// Exact set arithmetic between two edge sets, with bounded samples of the
/// exclusive sides. Counts are exact regardless of the sample cap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EdgeSetDiff {
    /// Edges only the baseline covered (lost by the other run).
    pub only_a: u64,
    /// Edges only the other run covered (gained over the baseline).
    pub only_b: u64,
    /// Edges both runs covered.
    pub common: u64,
    /// Edges either run covered.
    pub union: u64,
    /// Lowest ids exclusive to the baseline, capped at the requested sample.
    pub only_a_sample: Vec<u64>,
    /// Lowest ids exclusive to the other run, capped at the requested sample.
    pub only_b_sample: Vec<u64>,
}

#[cfg(test)]
mod edge_set_tests {
    use super::{EdgeSet, EDGE_SET_CAPACITY};

    fn set_with(edges: &[u64]) -> EdgeSet {
        let mut set = EdgeSet::new();
        for edge in edges {
            set.set(*edge).unwrap();
        }
        set
    }

    #[test]
    fn a_set_marks_exactly_the_edges_it_recorded() {
        let mut set = EdgeSet::new();
        assert_eq!(set.count(), 0);
        assert!(!set.contains(7));

        set.set(7).unwrap();
        set.set(65_535).unwrap();
        set.set(7).unwrap();

        assert!(set.contains(7));
        assert!(set.contains(65_535));
        assert!(!set.contains(8));
        assert_eq!(set.count(), 2, "recording an edge twice is idempotent");
    }

    #[test]
    fn an_edge_beyond_the_map_capacity_is_rejected() {
        let mut set = EdgeSet::new();
        let error = set.set(EDGE_SET_CAPACITY).unwrap_err();
        assert!(
            error.to_string().contains("exceeds the edge-set capacity"),
            "{error}"
        );
        assert!(set.set(EDGE_SET_CAPACITY - 1).is_ok());
        assert!(!set.contains(EDGE_SET_CAPACITY));
    }

    #[test]
    fn bytes_round_trip_and_reject_a_wrong_length() {
        let set = set_with(&[0, 1, 524_287]);
        let bytes = set.as_bytes();
        assert_eq!(bytes.len(), super::EDGE_SET_BYTES);
        assert_eq!(EdgeSet::from_bytes(bytes).unwrap(), set);

        let error = EdgeSet::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(error.to_string().contains("edge-set map"), "{error}");
    }

    #[test]
    fn diff_reports_exact_set_arithmetic() {
        let a = set_with(&[1, 2, 3, 4]);
        let b = set_with(&[3, 4, 5]);

        let diff = a.diff(&b, 64);

        assert_eq!(diff.only_a, 2);
        assert_eq!(diff.only_b, 1);
        assert_eq!(diff.common, 2);
        assert_eq!(diff.union, 5);
        assert_eq!(diff.only_a_sample, vec![1, 2]);
        assert_eq!(diff.only_b_sample, vec![5]);
    }

    #[test]
    fn diff_samples_are_capped_and_ascending_but_counts_stay_exact() {
        let a = set_with(&(0..200).collect::<Vec<u64>>());
        let b = set_with(&[0]);

        let diff = a.diff(&b, 8);

        assert_eq!(diff.only_a, 199);
        assert_eq!(diff.only_a_sample.len(), 8);
        assert_eq!(diff.only_a_sample, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(diff.only_b, 0);
        assert!(diff.only_b_sample.is_empty());
        assert_eq!(diff.common, 1);
        assert_eq!(diff.union, 200);
    }

    #[test]
    fn identical_sets_diff_to_zero_and_empty_sets_diff_to_empty() {
        let a = set_with(&[9, 10]);
        assert_eq!(a.diff(&a, 64).union, 2);
        let diff = a.diff(&a, 64);
        assert_eq!((diff.only_a, diff.only_b, diff.common), (0, 0, 2));

        let empty = EdgeSet::new().diff(&EdgeSet::new(), 64);
        assert_eq!(
            (empty.only_a, empty.only_b, empty.common, empty.union),
            (0, 0, 0, 0)
        );
    }
}
