//! Pure-Rust offline analysis over normalized capture frames.
//!
//! Provides the reverse-engineering primitives that `SavvyCAN` surfaces as its
//! "sniffer", bus statistics, and file-comparison tools, computed
//! deterministically over [`crate::capture::FrameRecord`] lists:
//!
//! - [`bus_stats`] -- frame totals, per-id counts, duration, and frame rate.
//! - [`change_maps`] -- per-id, per-byte change detection (the sniffer signal
//!   that highlights which payload bytes vary).
//! - [`diff`] -- compare two captures by the set of payloads seen per id.
//!
//! Nothing here opens an interface or spawns a process.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capture::FrameRecord;

/// Per-arbitration-id traffic statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdStats {
    /// Whether the id is a 29-bit extended id.
    pub extended: bool,
    /// Number of frames observed for this id.
    pub count: usize,
    /// Mean inter-frame period in microseconds, when at least two frames were
    /// seen and timestamps are monotonic.
    pub avg_period_micros: Option<u64>,
}

/// Aggregate statistics over a capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusStats {
    /// Total frames.
    pub frame_count: usize,
    /// Number of distinct arbitration ids.
    pub unique_ids: usize,
    /// Earliest timestamp (microseconds).
    pub first_micros: u64,
    /// Latest timestamp (microseconds).
    pub last_micros: u64,
    /// Span between first and last frame (microseconds).
    pub duration_micros: u64,
    /// Frames per second across the span (0 when the span is zero).
    pub frames_per_second: f64,
    /// Per-id breakdown keyed by arbitration id.
    pub per_id: BTreeMap<u32, IdStats>,
}

/// Per-byte change detection for one arbitration id (the sniffer view).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeMap {
    /// Whether the id is a 29-bit extended id.
    pub extended: bool,
    /// Number of frames observed for this id.
    pub observations: usize,
    /// For each byte position, whether its value ever changed.
    pub byte_changed: Vec<bool>,
    /// For each byte position, how many distinct values were observed.
    pub distinct_values: Vec<usize>,
}

/// The result of comparing two captures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDiff {
    /// Ids present only in the first capture.
    pub only_in_first: Vec<u32>,
    /// Ids present only in the second capture.
    pub only_in_second: Vec<u32>,
    /// Ids in both captures whose set of payloads differs.
    pub changed: Vec<u32>,
}

/// Compute aggregate bus statistics for a capture.
#[must_use]
pub fn bus_stats(frames: &[FrameRecord]) -> BusStats {
    if frames.is_empty() {
        return BusStats {
            frame_count: 0,
            unique_ids: 0,
            first_micros: 0,
            last_micros: 0,
            duration_micros: 0,
            frames_per_second: 0.0,
            per_id: BTreeMap::new(),
        };
    }

    let mut first = u64::MAX;
    let mut last = 0_u64;
    let mut timestamps: BTreeMap<u32, (bool, Vec<u64>)> = BTreeMap::new();
    for frame in frames {
        first = first.min(frame.timestamp_micros);
        last = last.max(frame.timestamp_micros);
        let entry = timestamps
            .entry(frame.id)
            .or_insert_with(|| (frame.extended, Vec::new()));
        entry.1.push(frame.timestamp_micros);
    }

    let duration = last.saturating_sub(first);
    let frames_per_second = if duration == 0 {
        0.0
    } else {
        frames.len() as f64 / (duration as f64 / 1_000_000.0)
    };

    let per_id = timestamps
        .into_iter()
        .map(|(id, (extended, mut stamps))| {
            stamps.sort_unstable();
            let avg_period_micros = average_period(&stamps);
            (
                id,
                IdStats {
                    extended,
                    count: stamps.len(),
                    avg_period_micros,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    BusStats {
        frame_count: frames.len(),
        unique_ids: per_id.len(),
        first_micros: first,
        last_micros: last,
        duration_micros: duration,
        frames_per_second,
        per_id,
    }
}

/// Mean inter-frame period from sorted timestamps, or `None` for fewer than two.
fn average_period(sorted: &[u64]) -> Option<u64> {
    if sorted.len() < 2 {
        return None;
    }
    let span = sorted.last()? - sorted.first()?;
    Some(span / (sorted.len() as u64 - 1))
}

/// Compute per-id, per-byte change maps (the sniffer view).
#[must_use]
pub fn change_maps(frames: &[FrameRecord]) -> BTreeMap<u32, ChangeMap> {
    let mut payloads: BTreeMap<u32, (bool, Vec<Vec<u8>>)> = BTreeMap::new();
    for frame in frames {
        let entry = payloads
            .entry(frame.id)
            .or_insert_with(|| (frame.extended, Vec::new()));
        entry.1.push(frame.data.clone());
    }

    payloads
        .into_iter()
        .map(|(id, (extended, observations))| {
            let width = observations.iter().map(Vec::len).max().unwrap_or(0);
            let mut byte_changed = vec![false; width];
            let mut distinct_values = vec![0_usize; width];
            for position in 0..width {
                let mut seen = BTreeSet::new();
                for payload in &observations {
                    if let Some(&byte) = payload.get(position) {
                        seen.insert(byte);
                    }
                }
                distinct_values[position] = seen.len();
                byte_changed[position] = seen.len() > 1;
            }
            (
                id,
                ChangeMap {
                    extended,
                    observations: observations.len(),
                    byte_changed,
                    distinct_values,
                },
            )
        })
        .collect()
}

/// Compare two captures by the set of payloads seen per arbitration id.
#[must_use]
pub fn diff(first: &[FrameRecord], second: &[FrameRecord]) -> CaptureDiff {
    let group = |frames: &[FrameRecord]| -> BTreeMap<u32, BTreeSet<Vec<u8>>> {
        let mut map: BTreeMap<u32, BTreeSet<Vec<u8>>> = BTreeMap::new();
        for frame in frames {
            map.entry(frame.id).or_default().insert(frame.data.clone());
        }
        map
    };
    let a = group(first);
    let b = group(second);

    let mut only_in_first = Vec::new();
    let mut only_in_second = Vec::new();
    let mut changed = Vec::new();
    for (id, payloads) in &a {
        match b.get(id) {
            None => only_in_first.push(*id),
            Some(other) if other != payloads => changed.push(*id),
            Some(_) => {}
        }
    }
    for id in b.keys() {
        if !a.contains_key(id) {
            only_in_second.push(*id);
        }
    }
    CaptureDiff {
        only_in_first,
        only_in_second,
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{parse, Format};

    fn frames(candump: &str) -> Vec<FrameRecord> {
        parse(Format::Candump, candump).expect("valid candump")
    }

    #[test]
    fn bus_stats_counts_ids_and_rate() {
        let text = "\
(1.000000) can0 100#00
(1.100000) can0 100#01
(1.200000) can0 200#AA
";
        let stats = bus_stats(&frames(text));
        assert_eq!(stats.frame_count, 3);
        assert_eq!(stats.unique_ids, 2);
        assert_eq!(stats.duration_micros, 200_000);
        assert_eq!(stats.per_id[&0x100].count, 2);
        assert_eq!(stats.per_id[&0x100].avg_period_micros, Some(100_000));
        assert!((stats.frames_per_second - 15.0).abs() < 1e-6);
    }

    #[test]
    fn change_map_flags_only_varying_bytes() {
        let text = "\
(1.0) can0 123#AA0011
(1.1) can0 123#AA0022
(1.2) can0 123#AA0033
";
        let maps = change_maps(&frames(text));
        let map = &maps[&0x123];
        assert_eq!(map.observations, 3);
        assert_eq!(map.byte_changed, vec![false, false, true]);
        assert_eq!(map.distinct_values, vec![1, 1, 3]);
    }

    #[test]
    fn diff_reports_added_removed_and_changed_ids() {
        let a = frames("(1.0) can0 100#00\n(1.0) can0 200#AA\n");
        let b = frames("(1.0) can0 100#01\n(1.0) can0 300#BB\n");
        let d = diff(&a, &b);
        assert_eq!(d.only_in_first, vec![0x200]);
        assert_eq!(d.only_in_second, vec![0x300]);
        assert_eq!(d.changed, vec![0x100]);
    }

    #[test]
    fn empty_capture_has_zeroed_stats() {
        let stats = bus_stats(&[]);
        assert_eq!(stats.frame_count, 0);
        assert!((stats.frames_per_second - 0.0).abs() < f64::EPSILON);
    }
}
