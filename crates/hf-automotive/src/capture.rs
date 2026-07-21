//! Pure-Rust importers for common CAN capture/log formats.
//!
//! Each importer parses file *content* (a string the caller has already read)
//! into a normalized [`FrameRecord`] list; it never opens a file or an
//! interface. The normalized frames feed offline analysis, DBC decoding, and
//! corpus seeding, complementing the PCAP path that goes through the sidecar.
//!
//! Phase-1 formats: `SocketCAN` `candump -l`, Vector ASCII (`.asc`, classic
//! frames), CRTD (OVMS), and GVRET native CSV. CAN-FD lines in Vector ASC and
//! the binary BLF format are deferred (see the design doc); the importer surface
//! is shaped so they drop in without disturbing the others.
//!
//! Clean-room from each format's public documentation; no GPL parser source is
//! used. Parsers fail closed on a malformed data line and skip known non-frame
//! lines (headers, comments, blanks, error/statistic markers).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Direction of a captured frame, when the source records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Received frame.
    Rx,
    /// Transmitted frame.
    Tx,
}

/// Kind of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    /// A normal data frame.
    Data,
    /// A remote-transmission-request frame (no data payload).
    Remote,
    /// An error frame.
    Error,
}

/// One normalized captured CAN frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameRecord {
    /// Timestamp in microseconds. Absolute epoch or relative depending on the
    /// source; importers do not reinterpret the source's time base beyond unit
    /// normalization.
    pub timestamp_micros: u64,
    /// Interface/bus/channel identifier, or empty when the source omits it.
    pub channel: String,
    /// Arbitration id with the 29-bit extended flag stripped.
    pub id: u32,
    /// Whether the frame is a 29-bit extended-id frame.
    pub extended: bool,
    /// Whether the frame is CAN-FD.
    pub fd: bool,
    /// Frame kind (data, remote, or error).
    pub kind: FrameKind,
    /// Data payload (empty for remote frames).
    pub data: Vec<u8>,
    /// Direction, when the source records it.
    pub direction: Option<Direction>,
}

/// Supported capture formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// `SocketCAN` `candump -l` log.
    Candump,
    /// Vector ASCII trace (`.asc`), classic frames.
    VectorAsc,
    /// CRTD (OVMS) log.
    Crtd,
    /// GVRET native CSV export.
    GvretCsv,
}

/// A capture-import error naming the offending line.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("malformed {format} capture on line {line}: {reason}")]
pub struct ImportError {
    /// Format being parsed.
    pub format: &'static str,
    /// 1-based source line number.
    pub line: usize,
    /// Human-readable reason.
    pub reason: String,
}

/// Parse capture text of the given format into normalized frames.
///
/// # Errors
/// Returns [`ImportError`] on the first malformed data line.
pub fn parse(format: Format, text: &str) -> Result<Vec<FrameRecord>, ImportError> {
    match format {
        Format::Candump => parse_candump(text),
        Format::VectorAsc => parse_asc(text),
        Format::Crtd => parse_crtd(text),
        Format::GvretCsv => parse_gvret_csv(text),
    }
}

fn err(format: &'static str, line: usize, reason: &str) -> ImportError {
    ImportError {
        format,
        line,
        reason: reason.to_owned(),
    }
}

/// Parse a contiguous hex string (even length) into bytes.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Convert `<secs>.<frac>` seconds text into microseconds.
fn seconds_to_micros(text: &str) -> Option<u64> {
    let (secs, frac) = text.split_once('.').unwrap_or((text, ""));
    let secs: u64 = secs.parse().ok()?;
    // Normalize the fractional part to exactly six digits (microseconds).
    let mut micros_digits = frac.chars().take(6).collect::<String>();
    while micros_digits.len() < 6 {
        micros_digits.push('0');
    }
    let micros: u64 = if micros_digits.is_empty() {
        0
    } else {
        micros_digits.parse().ok()?
    };
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

/// Split a candump `id#data` frame body.
fn parse_candump_frame(frame: &str) -> Option<(u32, bool, bool, FrameKind, Vec<u8>)> {
    let (id_str, rest) = frame.split_once('#')?;
    if id_str.is_empty() || id_str.len() > 8 {
        return None;
    }
    let raw_id = u32::from_str_radix(id_str, 16).ok()?;
    let extended = id_str.len() == 8;
    let id = raw_id & 0x1FFF_FFFF;

    if let Some(fd_rest) = rest.strip_prefix('#') {
        // CAN-FD: one flags nibble then the payload.
        let payload = fd_rest.get(1..)?;
        let data = hex_bytes(payload)?;
        return Some((id, extended, true, FrameKind::Data, data));
    }
    if let Some(remote) = rest.strip_prefix('R') {
        // Optional single DLC digit; no data bytes.
        if !remote.is_empty() && remote.parse::<u8>().is_err() {
            return None;
        }
        return Some((id, extended, false, FrameKind::Remote, Vec::new()));
    }
    let kind = if extended && raw_id & 0x2000_0000 != 0 {
        FrameKind::Error
    } else {
        FrameKind::Data
    };
    let data = hex_bytes(rest)?;
    Some((id, extended, false, kind, data))
}

fn parse_candump(text: &str) -> Result<Vec<FrameRecord>, ImportError> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = index + 1;
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            return Err(err("candump", line_no, "expected `(ts) iface id#data`"));
        }
        let ts = tokens[0]
            .strip_prefix('(')
            .and_then(|t| t.strip_suffix(')'))
            .and_then(seconds_to_micros)
            .ok_or_else(|| err("candump", line_no, "invalid timestamp"))?;
        let (id, extended, fd, kind, data) = parse_candump_frame(tokens[2])
            .ok_or_else(|| err("candump", line_no, "invalid frame body"))?;
        out.push(FrameRecord {
            timestamp_micros: ts,
            channel: tokens[1].to_owned(),
            id,
            extended,
            fd,
            kind,
            data,
            direction: None,
        });
    }
    Ok(out)
}

fn parse_asc(text: &str) -> Result<Vec<FrameRecord>, ImportError> {
    let mut radix = 16_u32;
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let line_no = index + 1;
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("base") {
            if lower.contains("dec") {
                radix = 10;
            }
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Data line: `<ts> <chan> <id[x]> <Rx|Tx> <d|r> <dlc> <data...>`.
        if tokens.len() < 6 {
            continue; // header / non-frame line
        }
        if tokens[0].parse::<f64>().is_err() {
            continue; // "date ...", "Begin ..." etc.
        }
        // Skip CAN-FD (deferred), ErrorFrame, and statistics events.
        if tokens[1].eq_ignore_ascii_case("canfd") || tokens[2].eq_ignore_ascii_case("errorframe") {
            continue;
        }
        let direction = match tokens[3] {
            "Rx" => Some(Direction::Rx),
            "Tx" => Some(Direction::Tx),
            _ => continue, // not a classic data/remote frame line
        };
        let ts = seconds_to_micros(tokens[0])
            .ok_or_else(|| err("vector-asc", line_no, "invalid timestamp"))?;
        let (id_text, extended) = strip_extended_suffix(tokens[2]);
        let id = u32::from_str_radix(id_text, radix)
            .map_err(|_| err("vector-asc", line_no, "invalid id"))?
            & 0x1FFF_FFFF;
        let is_remote = tokens[4].eq_ignore_ascii_case("r");
        let dlc: usize = tokens[5]
            .parse()
            .map_err(|_| err("vector-asc", line_no, "invalid dlc"))?;
        let (kind, data) = if is_remote {
            (FrameKind::Remote, Vec::new())
        } else {
            let mut bytes = Vec::with_capacity(dlc);
            for token in tokens.iter().skip(6).take(dlc) {
                bytes.push(
                    u8::from_str_radix(token, radix)
                        .map_err(|_| err("vector-asc", line_no, "invalid data byte"))?,
                );
            }
            (FrameKind::Data, bytes)
        };
        out.push(FrameRecord {
            timestamp_micros: ts,
            channel: tokens[1].to_owned(),
            id,
            extended,
            fd: false,
            kind,
            data,
            direction,
        });
    }
    Ok(out)
}

/// Strip a trailing `x`/`X` extended-id marker from a Vector ASC id token.
fn strip_extended_suffix(token: &str) -> (&str, bool) {
    token
        .strip_suffix(['x', 'X'])
        .map_or((token, false), |base| (base, true))
}

fn parse_crtd(text: &str) -> Result<Vec<FrameRecord>, ImportError> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let line_no = index + 1;
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let ts = seconds_to_micros(tokens[0])
            .ok_or_else(|| err("crtd", line_no, "invalid timestamp"))?;
        // Type token: optional leading bus digits, then R/T, then 11/29.
        let type_token = tokens[1];
        let type_body = type_token.trim_start_matches(|c: char| c.is_ascii_digit());
        let bus = &type_token[..type_token.len() - type_body.len()];
        let direction = match type_body.chars().next() {
            Some('R') => Direction::Rx,
            Some('T') => Direction::Tx,
            _ => continue, // comment/command record (CXX, CER, ...) or unknown
        };
        let extended = type_body.ends_with("29");
        if !type_body.ends_with("11") && !extended {
            continue;
        }
        if tokens.len() < 3 {
            return Err(err("crtd", line_no, "missing arbitration id"));
        }
        let id = u32::from_str_radix(tokens[2], 16)
            .map_err(|_| err("crtd", line_no, "invalid id"))?
            & 0x1FFF_FFFF;
        let mut data = Vec::with_capacity(tokens.len().saturating_sub(3));
        for token in tokens.iter().skip(3) {
            data.push(
                u8::from_str_radix(token, 16)
                    .map_err(|_| err("crtd", line_no, "invalid data byte"))?,
            );
        }
        out.push(FrameRecord {
            timestamp_micros: ts,
            channel: if bus.is_empty() {
                "1".to_owned()
            } else {
                bus.to_owned()
            },
            id,
            extended,
            fd: false,
            kind: FrameKind::Data,
            data,
            direction: Some(direction),
        });
    }
    Ok(out)
}

fn parse_gvret_csv(text: &str) -> Result<Vec<FrameRecord>, ImportError> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let line_no = index + 1;
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Time Stamp") {
            continue; // header row
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 5 {
            return Err(err("gvret-csv", line_no, "expected at least 5 columns"));
        }
        // Timestamp: integer microseconds by default, or seconds if it has a dot.
        let ts = if fields[0].contains('.') {
            seconds_to_micros(fields[0])
        } else {
            fields[0].parse::<u64>().ok()
        }
        .ok_or_else(|| err("gvret-csv", line_no, "invalid timestamp"))?;
        let id = u32::from_str_radix(fields[1], 16)
            .map_err(|_| err("gvret-csv", line_no, "invalid id"))?
            & 0x1FFF_FFFF;
        let extended = matches!(fields[2].to_ascii_lowercase().as_str(), "true" | "1");
        let channel = fields[3].to_owned();
        let len: usize = fields[4]
            .parse()
            .map_err(|_| err("gvret-csv", line_no, "invalid length"))?;
        let mut data = Vec::with_capacity(len);
        for field in fields.iter().skip(5).take(len) {
            if field.is_empty() {
                return Err(err("gvret-csv", line_no, "missing data byte"));
            }
            data.push(
                u8::from_str_radix(field, 16)
                    .map_err(|_| err("gvret-csv", line_no, "invalid data byte"))?,
            );
        }
        out.push(FrameRecord {
            timestamp_micros: ts,
            channel,
            id,
            extended,
            fd: false,
            kind: FrameKind::Data,
            data,
            direction: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_candump_standard_extended_remote_and_fd() {
        let text = "\
(1633072800.123456) can0 123#DEADBEEF
(1633072800.234567) can0 18FEF100#0102030405060708
(1633072800.345678) can1 200#R8
(1633072800.567890) can0 123##11122334455667788\n";
        let frames = parse(Format::Candump, text).expect("valid candump");
        assert_eq!(frames.len(), 4);

        assert_eq!(frames[0].id, 0x123);
        assert!(!frames[0].extended);
        assert_eq!(frames[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(frames[0].timestamp_micros, 1_633_072_800_123_456);

        assert_eq!(frames[1].id, 0x18FE_F100 & 0x1FFF_FFFF);
        assert!(frames[1].extended);

        assert_eq!(frames[2].kind, FrameKind::Remote);
        assert!(frames[2].data.is_empty());
        assert_eq!(frames[2].channel, "can1");

        assert!(frames[3].fd);
        assert_eq!(
            frames[3].data,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
    }

    #[test]
    fn candump_rejects_malformed_frame() {
        let text = "(1.0) can0 123#ZZ\n";
        assert!(parse(Format::Candump, text).is_err());
    }

    #[test]
    fn imports_vector_asc_classic() {
        let text = "\
date Wed Sep 27 10:00:00.000 2017
base hex  timestamps absolute
Begin Triggerblock
0.123456 1 7DF Rx d 3 12 34 56
0.234000 1 18DB33F1x Tx d 2 02 10
0.240000 1 300 Rx r 8
0.250000 1 400 Rx ErrorFrame
End TriggerBlock\n";
        let frames = parse(Format::VectorAsc, text).expect("valid asc");
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].id, 0x7DF);
        assert_eq!(frames[0].data, vec![0x12, 0x34, 0x56]);
        assert_eq!(frames[0].direction, Some(Direction::Rx));
        assert!(frames[1].extended);
        assert_eq!(frames[1].direction, Some(Direction::Tx));
        assert_eq!(frames[2].kind, FrameKind::Remote);
    }

    #[test]
    fn imports_crtd() {
        let text = "\
1542473901.020305 1R11 213 00 11 22 33
1542473901.030 2T29 18FEF100 AA BB
1542473901.040 CXX vehicle started\n";
        let frames = parse(Format::Crtd, text).expect("valid crtd");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].id, 0x213);
        assert_eq!(frames[0].channel, "1");
        assert_eq!(frames[0].direction, Some(Direction::Rx));
        assert_eq!(frames[0].data, vec![0x00, 0x11, 0x22, 0x33]);
        assert!(frames[1].extended);
        assert_eq!(frames[1].channel, "2");
        assert_eq!(frames[1].direction, Some(Direction::Tx));
    }

    #[test]
    fn imports_gvret_csv() {
        let text = "\
Time Stamp,ID,Extended,Bus,LEN,D1,D2,D3,D4,D5,D6,D7,D8
166064000,0000021A,false,0,8,FE,36,12,FE,69,05,07,AD,
166064000,0000027A,false,0,7,30,30,0D,8C,09,15,00,00,\n";
        let frames = parse(Format::GvretCsv, text).expect("valid gvret csv");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].id, 0x21A);
        assert!(!frames[0].extended);
        assert_eq!(frames[0].channel, "0");
        assert_eq!(
            frames[0].data,
            vec![0xFE, 0x36, 0x12, 0xFE, 0x69, 0x05, 0x07, 0xAD]
        );
        assert_eq!(frames[1].data.len(), 7);
    }

    #[test]
    fn seconds_to_micros_normalizes_fraction_width() {
        assert_eq!(seconds_to_micros("5.5"), Some(5_500_000));
        assert_eq!(seconds_to_micros("5.000123"), Some(5_000_123));
        assert_eq!(seconds_to_micros("5"), Some(5_000_000));
    }
}
