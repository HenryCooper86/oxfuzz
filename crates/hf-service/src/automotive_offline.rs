//! Service-owned offline CAN analysis: capture import, DBC decode, bus
//! statistics, sniffer change maps, and capture diff.
//!
//! These operations are pure and deterministic. Unlike the sidecar-backed
//! automotive operations they never open an interface or spawn a process: they
//! read an operator-selected capture file (bounded by the automotive input
//! limit), parse it with the `hf-automotive` importers, and analyze it in
//! process. They are the `SavvyCAN`-style reverse-engineering tools brought into
//! the offline workflow.

use std::fmt::Write as _;
use std::path::Path;

use hf_automotive::{analysis, capture, dbc};
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

use crate::ServiceContainer;

/// Maximum number of frames returned in the frame grid; statistics and change
/// maps are always computed over the whole capture.
const FRAME_VIEW_CAP: usize = 5_000;

/// One decoded signal in a [`FrameView`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedSignalView {
    /// Signal name.
    pub name: String,
    /// Physical value.
    pub value: f64,
    /// Physical unit (may be empty).
    pub unit: String,
    /// Value-table label, when defined.
    pub label: Option<String>,
}

/// One frame prepared for presentation, with optional DBC decode attached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameView {
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
    /// Interface/bus/channel identifier.
    pub channel: String,
    /// Arbitration id (extended flag stripped).
    pub id: u32,
    /// Whether the id is a 29-bit extended id.
    pub extended: bool,
    /// Whether the frame is CAN-FD.
    pub fd: bool,
    /// Frame kind: `data`, `remote`, or `error`.
    pub kind: String,
    /// Uppercase hex payload.
    pub data_hex: String,
    /// Direction (`rx`/`tx`) when the source records it.
    pub direction: Option<String>,
    /// DBC message name when the frame decoded.
    pub message: Option<String>,
    /// Decoded signals (empty when no DBC matched).
    pub signals: Vec<DecodedSignalView>,
}

/// Per-id traffic statistics for presentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdStatView {
    /// Arbitration id.
    pub id: u32,
    /// Whether the id is extended.
    pub extended: bool,
    /// Frames observed.
    pub count: usize,
    /// Mean inter-frame period in microseconds, when known.
    pub avg_period_micros: Option<u64>,
}

/// Per-id, per-byte change map for the sniffer view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeMapView {
    /// Arbitration id.
    pub id: u32,
    /// Whether the id is extended.
    pub extended: bool,
    /// Frames observed for this id.
    pub observations: usize,
    /// Per byte position, whether the value ever changed.
    pub byte_changed: Vec<bool>,
    /// Per byte position, how many distinct values were observed.
    pub distinct_values: Vec<usize>,
}

/// The result of importing and analyzing one capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureImport {
    /// Capture format identifier.
    pub format: String,
    /// Total frames in the capture.
    pub frame_count: usize,
    /// Whether `frames` was truncated to the presentation cap.
    pub truncated: bool,
    /// Number of DBC messages loaded (0 when no DBC supplied).
    pub dbc_message_count: usize,
    /// Distinct arbitration ids.
    pub unique_ids: usize,
    /// Capture span in microseconds.
    pub duration_micros: u64,
    /// Frames per second across the span.
    pub frames_per_second: f64,
    /// Bounded frame grid (first `FRAME_VIEW_CAP` frames; see `truncated`).
    pub frames: Vec<FrameView>,
    /// Per-id statistics.
    pub per_id: Vec<IdStatView>,
    /// Per-id change maps (the sniffer).
    pub change_maps: Vec<ChangeMapView>,
}

/// The result of comparing two captures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDiffView {
    /// Ids only in the first capture.
    pub only_in_first: Vec<u32>,
    /// Ids only in the second capture.
    pub only_in_second: Vec<u32>,
    /// Ids in both whose payload set differs.
    pub changed: Vec<u32>,
}

impl ServiceContainer {
    /// Import and analyze an operator-selected capture file, optionally decoding
    /// signals with a supplied DBC database.
    ///
    /// # Errors
    /// Returns a validation error for an unknown format, an oversized or
    /// unreadable file, non-UTF-8 content, or malformed capture/DBC text.
    pub fn automotive_import_capture(
        &self,
        path: &Path,
        format: &str,
        dbc_path: Option<&Path>,
    ) -> Result<CaptureImport, ClassifiedError> {
        let text = read_text_input(path)?;
        let dbc_text = match dbc_path {
            Some(dbc) => Some(read_text_input(dbc)?),
            None => None,
        };
        analyze_capture_text(format, &text, dbc_text.as_deref())
    }

    /// Compare two operator-selected captures of the same format.
    ///
    /// # Errors
    /// Returns a validation error for an unknown format or an unreadable file.
    pub fn automotive_diff_captures(
        &self,
        first: &Path,
        second: &Path,
        format: &str,
    ) -> Result<CaptureDiffView, ClassifiedError> {
        let first_text = read_text_input(first)?;
        let second_text = read_text_input(second)?;
        diff_capture_texts(format, &first_text, &second_text)
    }
}

/// Read an operator-selected text input (capture or DBC), bounded by the
/// automotive input limit.
fn read_text_input(path: &Path) -> Result<String, ClassifiedError> {
    let maximum = crate::config::effective_automotive_settings()
        .map_err(ClassifiedError::Validation)?
        .limits
        .max_input_bytes;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!("inspect input {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(ClassifiedError::Validation(format!(
            "input must be a regular file no larger than {maximum} bytes"
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        ClassifiedError::Validation(format!("read input {}: {error}", path.display()))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(ClassifiedError::Validation(
            "input changed while it was read".to_owned(),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| ClassifiedError::Validation("input is not valid UTF-8 text".to_owned()))
}

fn parse_format(name: &str) -> Result<capture::Format, ClassifiedError> {
    match name {
        "candump" => Ok(capture::Format::Candump),
        "vector_asc" => Ok(capture::Format::VectorAsc),
        "crtd" => Ok(capture::Format::Crtd),
        "gvret_csv" => Ok(capture::Format::GvretCsv),
        other => Err(ClassifiedError::Validation(format!(
            "unknown capture format '{other}'"
        ))),
    }
}

/// Analyze already-read capture text (the testable core of import).
fn analyze_capture_text(
    format: &str,
    text: &str,
    dbc_text: Option<&str>,
) -> Result<CaptureImport, ClassifiedError> {
    let fmt = parse_format(format)?;
    let frames = capture::parse(fmt, text)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

    let database = match dbc_text {
        Some(text) if !text.trim().is_empty() => Some(
            dbc::Database::parse(text)
                .map_err(|error| ClassifiedError::Validation(error.to_string()))?,
        ),
        _ => None,
    };
    let dbc_message_count = database.as_ref().map_or(0, dbc::Database::len);

    let stats = analysis::bus_stats(&frames);
    let change_maps = analysis::change_maps(&frames);

    let frame_count = frames.len();
    let truncated = frame_count > FRAME_VIEW_CAP;
    let frames_view = frames
        .iter()
        .take(FRAME_VIEW_CAP)
        .map(|frame| frame_view(frame, database.as_ref()))
        .collect();

    Ok(CaptureImport {
        format: format.to_owned(),
        frame_count,
        truncated,
        dbc_message_count,
        unique_ids: stats.unique_ids,
        duration_micros: stats.duration_micros,
        frames_per_second: stats.frames_per_second,
        frames: frames_view,
        per_id: stats
            .per_id
            .into_iter()
            .map(|(id, stat)| IdStatView {
                id,
                extended: stat.extended,
                count: stat.count,
                avg_period_micros: stat.avg_period_micros,
            })
            .collect(),
        change_maps: change_maps
            .into_iter()
            .map(|(id, map)| ChangeMapView {
                id,
                extended: map.extended,
                observations: map.observations,
                byte_changed: map.byte_changed,
                distinct_values: map.distinct_values,
            })
            .collect(),
    })
}

fn diff_capture_texts(
    format: &str,
    first: &str,
    second: &str,
) -> Result<CaptureDiffView, ClassifiedError> {
    let fmt = parse_format(format)?;
    let a = capture::parse(fmt, first)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    let b = capture::parse(fmt, second)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    let diff = analysis::diff(&a, &b);
    Ok(CaptureDiffView {
        only_in_first: diff.only_in_first,
        only_in_second: diff.only_in_second,
        changed: diff.changed,
    })
}

fn frame_view(frame: &capture::FrameRecord, database: Option<&dbc::Database>) -> FrameView {
    let decoded = database
        .filter(|_| frame.kind == capture::FrameKind::Data && !frame.data.is_empty())
        .and_then(|database| database.decode(frame.id, frame.extended, &frame.data));
    let (message, signals) = decoded.map_or((None, Vec::new()), |decoded| {
        let signals = decoded
            .signals
            .into_iter()
            .map(|signal| DecodedSignalView {
                name: signal.name,
                value: signal.value,
                unit: signal.unit,
                label: signal.label,
            })
            .collect();
        (Some(decoded.message), signals)
    });
    FrameView {
        timestamp_micros: frame.timestamp_micros,
        channel: frame.channel.clone(),
        id: frame.id,
        extended: frame.extended,
        fd: frame.fd,
        kind: kind_str(frame.kind).to_owned(),
        data_hex: hex_encode(&frame.data),
        direction: frame.direction.map(|dir| direction_str(dir).to_owned()),
        message,
        signals,
    }
}

fn kind_str(kind: capture::FrameKind) -> &'static str {
    match kind {
        capture::FrameKind::Data => "data",
        capture::FrameKind::Remote => "remote",
        capture::FrameKind::Error => "error",
    }
}

fn direction_str(direction: capture::Direction) -> &'static str {
    match direction {
        capture::Direction::Rx => "rx",
        capture::Direction::Tx => "tx",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDUMP: &str = "\
(1.000000) can0 100#0010
(1.100000) can0 100#0020
(1.200000) can0 200#AABB
";

    const DBC: &str = "\
BO_ 256 EngineData: 8 ECU
 SG_ Level : 8|8@1+ (2,0) [0|510] \"pct\" ECU
";

    #[test]
    fn analyzes_capture_with_stats_and_sniffer() {
        let import = analyze_capture_text("candump", CANDUMP, None).expect("analysis");
        assert_eq!(import.frame_count, 3);
        assert_eq!(import.unique_ids, 2);
        assert!(!import.truncated);
        // Id 0x100 second byte varies (0x10 vs 0x20); first byte constant.
        let map = import.change_maps.iter().find(|m| m.id == 0x100).unwrap();
        assert_eq!(map.byte_changed, vec![false, true]);
        assert_eq!(import.frames[0].data_hex, "0010");
    }

    #[test]
    fn decodes_signals_when_dbc_supplied() {
        let import = analyze_capture_text("candump", CANDUMP, Some(DBC)).expect("analysis");
        assert_eq!(import.dbc_message_count, 1);
        // Message 0x100 = 256, Level at byte 1 -> 0x10 * 2 = 32.0 for the first frame.
        let first = &import.frames[0];
        assert_eq!(first.message.as_deref(), Some("EngineData"));
        let level = first.signals.iter().find(|s| s.name == "Level").unwrap();
        assert!((level.value - 32.0).abs() < 1e-9);
        assert_eq!(level.unit, "pct");
    }

    #[test]
    fn diff_identifies_changed_and_unique_ids() {
        let a = "(1.0) can0 100#00\n(1.0) can0 200#AA\n";
        let b = "(1.0) can0 100#01\n(1.0) can0 300#BB\n";
        let diff = diff_capture_texts("candump", a, b).expect("diff");
        assert_eq!(diff.changed, vec![0x100]);
        assert_eq!(diff.only_in_first, vec![0x200]);
        assert_eq!(diff.only_in_second, vec![0x300]);
    }

    #[test]
    fn unknown_format_is_rejected() {
        assert!(analyze_capture_text("blf", CANDUMP, None).is_err());
    }
}
