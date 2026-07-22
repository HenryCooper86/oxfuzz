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

use crate::capture::{Direction, FrameKind, FrameRecord};
use crate::isotp::{Addressing, Reassembler};

/// Collision-safe identity of a CAN arbitration id.
///
/// Standard and extended frames occupy separate namespaces even when their
/// numeric ids are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FrameIdentity {
    /// Arbitration id with any format flag stripped.
    pub id: u32,
    /// Whether this is a 29-bit extended-id frame.
    pub extended: bool,
}

impl FrameIdentity {
    /// Construct an identity from a normalized arbitration id and format flag.
    #[must_use]
    pub const fn new(id: u32, extended: bool) -> Self {
        Self { id, extended }
    }
}

impl From<&FrameRecord> for FrameIdentity {
    fn from(frame: &FrameRecord) -> Self {
        Self::new(frame.id, frame.extended)
    }
}

/// Per-arbitration-id traffic statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdStats {
    /// Collision-safe arbitration identity.
    pub identity: FrameIdentity,
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
    /// Per-id breakdown in stable identity order.
    pub per_id: Vec<IdStats>,
}

/// Per-byte change detection for one arbitration id (the sniffer view).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeMap {
    /// Collision-safe arbitration identity.
    pub identity: FrameIdentity,
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
    pub only_in_first: Vec<FrameIdentity>,
    /// Ids present only in the second capture.
    pub only_in_second: Vec<FrameIdentity>,
    /// Ids in both captures whose set of payloads differs.
    pub changed: Vec<FrameIdentity>,
}

/// One directional ISO-TP stream within a capture.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UdsStream {
    /// Capture channel or interface.
    pub channel: String,
    /// Collision-safe CAN id.
    pub identity: FrameIdentity,
    /// Captured direction, when supplied by the input format.
    pub direction: Option<Direction>,
}

/// Deterministic UDS state decoded from one complete ISO-TP payload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UdsState {
    /// Diagnostic request service and optional subfunction.
    Request {
        /// UDS service identifier.
        service: u8,
        /// First parameter, normally the subfunction.
        subfunction: Option<u8>,
    },
    /// Positive response, normalized back to the request service id.
    PositiveResponse {
        /// Request service identifier (`response_sid - 0x40`).
        service: u8,
        /// First response parameter, normally the echoed subfunction.
        subfunction: Option<u8>,
    },
    /// Negative response with the rejected service and response code.
    NegativeResponse {
        /// Rejected request service.
        service: u8,
        /// UDS negative-response code.
        code: u8,
    },
    /// A complete payload outside the recognized UDS request/response shapes.
    Other {
        /// First payload byte.
        service: u8,
    },
}

/// One unique state observed on one stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdsStateObservation {
    /// Stream that produced the state.
    pub stream: UdsStream,
    /// Decoded state.
    pub state: UdsState,
}

/// One unique state transition and its occurrence count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdsStateTransition {
    /// Stream that produced the transition.
    pub stream: UdsStream,
    /// Previous decoded state.
    pub from: UdsState,
    /// Next decoded state.
    pub to: UdsState,
    /// Number of occurrences in the capture.
    pub count: usize,
}

/// Bounded protocol-state summary derived from ISO-TP/UDS traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdsStateAnalysis {
    /// Complete ISO-TP payloads decoded.
    pub completed_pdus: usize,
    /// Structurally invalid ISO-TP frames rejected by reassembly.
    pub malformed_frames: usize,
    /// Unique stream-scoped UDS states in stable order.
    pub unique_states: Vec<UdsStateObservation>,
    /// Unique stream-scoped transitions in stable order.
    pub transitions: Vec<UdsStateTransition>,
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
            per_id: Vec::new(),
        };
    }

    let mut first = u64::MAX;
    let mut last = 0_u64;
    let mut timestamps: BTreeMap<FrameIdentity, Vec<u64>> = BTreeMap::new();
    for frame in frames {
        first = first.min(frame.timestamp_micros);
        last = last.max(frame.timestamp_micros);
        timestamps
            .entry(FrameIdentity::from(frame))
            .or_default()
            .push(frame.timestamp_micros);
    }

    let duration = last.saturating_sub(first);
    let frames_per_second = if duration == 0 {
        0.0
    } else {
        frames.len() as f64 / (duration as f64 / 1_000_000.0)
    };

    let per_id = timestamps
        .into_iter()
        .map(|(identity, mut stamps)| {
            stamps.sort_unstable();
            let avg_period_micros = average_period(&stamps);
            IdStats {
                identity,
                count: stamps.len(),
                avg_period_micros,
            }
        })
        .collect::<Vec<_>>();

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
pub fn change_maps(frames: &[FrameRecord]) -> Vec<ChangeMap> {
    let mut payloads: BTreeMap<FrameIdentity, Vec<Vec<u8>>> = BTreeMap::new();
    for frame in frames {
        payloads
            .entry(FrameIdentity::from(frame))
            .or_default()
            .push(frame.data.clone());
    }

    payloads
        .into_iter()
        .map(|(identity, observations)| {
            let width = observations.iter().map(Vec::len).max().unwrap_or(0);
            let mut byte_changed = vec![false; width];
            let mut distinct_values = vec![0_usize; width];
            for position in 0..width {
                let mut seen = BTreeSet::new();
                let mut present = 0_usize;
                for payload in &observations {
                    if let Some(&byte) = payload.get(position) {
                        seen.insert(byte);
                        present += 1;
                    }
                }
                distinct_values[position] = seen.len();
                byte_changed[position] = seen.len() > 1 || present != observations.len();
            }
            ChangeMap {
                identity,
                observations: observations.len(),
                byte_changed,
                distinct_values,
            }
        })
        .collect()
}

/// Compare two captures by the set of payloads seen per arbitration id.
#[must_use]
pub fn diff(first: &[FrameRecord], second: &[FrameRecord]) -> CaptureDiff {
    let group = |frames: &[FrameRecord]| -> BTreeMap<FrameIdentity, BTreeSet<Vec<u8>>> {
        let mut map: BTreeMap<FrameIdentity, BTreeSet<Vec<u8>>> = BTreeMap::new();
        for frame in frames {
            map.entry(FrameIdentity::from(frame))
                .or_default()
                .insert(frame.data.clone());
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

fn classify_uds_state(payload: &[u8]) -> Option<UdsState> {
    let (&service, rest) = payload.split_first()?;
    if service == 0x7f {
        return match rest {
            [rejected, code, ..] => Some(UdsState::NegativeResponse {
                service: *rejected,
                code: *code,
            }),
            _ => Some(UdsState::Other { service }),
        };
    }
    if (0x40..0x7f).contains(&service) {
        return Some(UdsState::PositiveResponse {
            service: service - 0x40,
            subfunction: rest.first().copied(),
        });
    }
    if service < 0x40 {
        return Some(UdsState::Request {
            service,
            subfunction: rest.first().copied(),
        });
    }
    Some(UdsState::Other { service })
}

/// Reassemble normal-addressing ISO-TP streams and summarize UDS state novelty.
///
/// Frames are partitioned by channel, collision-safe id, and direction. Invalid
/// ISO-TP input increments `malformed_frames` and resets only its own stream.
#[must_use]
pub fn uds_state_analysis(frames: &[FrameRecord]) -> UdsStateAnalysis {
    let mut receivers: BTreeMap<UdsStream, Reassembler> = BTreeMap::new();
    let mut previous: BTreeMap<UdsStream, UdsState> = BTreeMap::new();
    let mut states: BTreeSet<(UdsStream, UdsState)> = BTreeSet::new();
    let mut transitions: BTreeMap<(UdsStream, UdsState, UdsState), usize> = BTreeMap::new();
    let mut completed_pdus = 0_usize;
    let mut malformed_frames = 0_usize;

    for frame in frames {
        if frame.kind != FrameKind::Data || frame.data.is_empty() {
            continue;
        }
        let stream = UdsStream {
            channel: frame.channel.clone(),
            identity: FrameIdentity::from(frame),
            direction: frame.direction,
        };
        let receiver = receivers
            .entry(stream.clone())
            .or_insert_with(|| Reassembler::new(Addressing::Normal));
        match receiver.push(&frame.data) {
            Ok(Some(pdu)) => {
                completed_pdus += 1;
                let Some(state) = classify_uds_state(&pdu.data) else {
                    continue;
                };
                states.insert((stream.clone(), state.clone()));
                if let Some(from) = previous.insert(stream.clone(), state.clone()) {
                    *transitions.entry((stream, from, state)).or_default() += 1;
                }
            }
            Ok(None) => {}
            Err(_) => malformed_frames += 1,
        }
    }

    UdsStateAnalysis {
        completed_pdus,
        malformed_frames,
        unique_states: states
            .into_iter()
            .map(|(stream, state)| UdsStateObservation { stream, state })
            .collect(),
        transitions: transitions
            .into_iter()
            .map(|((stream, from, to), count)| UdsStateTransition {
                stream,
                from,
                to,
                count,
            })
            .collect(),
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
        let id_100 = stats
            .per_id
            .iter()
            .find(|stat| stat.identity == FrameIdentity::new(0x100, false))
            .expect("standard id 0x100");
        assert_eq!(id_100.count, 2);
        assert_eq!(id_100.avg_period_micros, Some(100_000));
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
        let map = maps
            .iter()
            .find(|map| map.identity == FrameIdentity::new(0x123, false))
            .expect("standard id 0x123");
        assert_eq!(map.observations, 3);
        assert_eq!(map.byte_changed, vec![false, false, true]);
        assert_eq!(map.distinct_values, vec![1, 1, 3]);
    }

    #[test]
    fn change_map_treats_payload_length_changes_as_byte_changes() {
        let text = "(1.0) can0 123#AA\n(1.1) can0 123#AABB\n";
        let maps = change_maps(&frames(text));
        let map = maps
            .iter()
            .find(|map| map.identity == FrameIdentity::new(0x123, false))
            .expect("standard id 0x123");
        assert_eq!(map.byte_changed, vec![false, true]);
        assert_eq!(map.distinct_values, vec![1, 1]);
    }

    #[test]
    fn diff_reports_added_removed_and_changed_ids() {
        let a = frames("(1.0) can0 100#00\n(1.0) can0 200#AA\n");
        let b = frames("(1.0) can0 100#01\n(1.0) can0 300#BB\n");
        let d = diff(&a, &b);
        assert_eq!(d.only_in_first, vec![FrameIdentity::new(0x200, false)]);
        assert_eq!(d.only_in_second, vec![FrameIdentity::new(0x300, false)]);
        assert_eq!(d.changed, vec![FrameIdentity::new(0x100, false)]);
    }

    #[test]
    fn empty_capture_has_zeroed_stats() {
        let stats = bus_stats(&[]);
        assert_eq!(stats.frame_count, 0);
        assert!((stats.frames_per_second - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn standard_and_extended_ids_do_not_collide() {
        let traffic = frames("(1.0) can0 123#00\n(1.1) can0 00000123#11\n");
        let standard = FrameIdentity::new(0x123, false);
        let extended = FrameIdentity::new(0x123, true);

        let stats = bus_stats(&traffic);
        assert_eq!(stats.unique_ids, 2);
        assert_eq!(
            stats
                .per_id
                .iter()
                .find(|stat| stat.identity == standard)
                .expect("standard identity")
                .count,
            1
        );
        assert_eq!(
            stats
                .per_id
                .iter()
                .find(|stat| stat.identity == extended)
                .expect("extended identity")
                .count,
            1
        );

        let maps = change_maps(&traffic);
        assert_eq!(maps.len(), 2);
        assert_eq!(
            maps.iter()
                .find(|map| map.identity == standard)
                .expect("standard identity")
                .observations,
            1
        );
        assert_eq!(
            maps.iter()
                .find(|map| map.identity == extended)
                .expect("extended identity")
                .observations,
            1
        );

        let captures = diff(&traffic[..1], &traffic[1..]);
        assert_eq!(captures.only_in_first, vec![standard]);
        assert_eq!(captures.only_in_second, vec![extended]);
    }

    #[test]
    fn uds_state_analysis_counts_novel_transitions_once() {
        let traffic = frames(
            "(1.0) can0 7E0#021001\n\
             (1.1) can0 7E0#025001\n\
             (1.2) can0 7E0#021001\n\
             (1.3) can0 7E0#025001\n",
        );

        let analysis = uds_state_analysis(&traffic);
        assert_eq!(analysis.completed_pdus, 4);
        assert_eq!(analysis.malformed_frames, 0);
        assert_eq!(analysis.unique_states.len(), 2);
        assert_eq!(analysis.transitions.len(), 2);
        let repeated = analysis
            .transitions
            .iter()
            .find(|transition| transition.count == 2)
            .expect("request-to-response transition is counted twice");
        assert_eq!(
            repeated.from,
            UdsState::Request {
                service: 0x10,
                subfunction: Some(0x01),
            }
        );
        assert_eq!(
            repeated.to,
            UdsState::PositiveResponse {
                service: 0x10,
                subfunction: Some(0x01),
            }
        );
    }

    #[test]
    fn malformed_isotp_does_not_fabricate_a_uds_state() {
        let traffic = frames("(1.0) can0 7E0#1008\n");
        let analysis = uds_state_analysis(&traffic);
        assert_eq!(analysis.completed_pdus, 0);
        assert_eq!(analysis.malformed_frames, 1);
        assert!(analysis.unique_states.is_empty());
        assert!(analysis.transitions.is_empty());
    }
}
