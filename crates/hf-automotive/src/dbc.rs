//! Pure-Rust DBC (CAN database) parsing and deterministic signal decoding.
//!
//! This module loads the common subset of the DBC interchange format -- messages
//! (`BO_`), signals (`SG_`), and value tables (`VAL_`), including simple
//! multiplexing (`M` / `m<N>`) -- and decodes raw CAN frame payloads into named,
//! scaled signal values. It never opens an interface, spawns a process, or reads
//! a file path: callers pass DBC text and frame bytes. Decoding is total and
//! deterministic; malformed databases fail closed and out-of-range signals are
//! skipped rather than reading past the payload, which matters because a fuzzer
//! will feed malformed databases and short frames.
//!
//! Clean-room from the public DBC format definition (see
//! `docs/design/savvycan-inspired-automotive-tooling.md`); no GPL source is used.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bit ordering of a signal within the frame payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    /// `@1` little-endian (Intel): `start_bit` is the signal LSB.
    Little,
    /// `@0` big-endian (Motorola): `start_bit` is the signal MSB.
    Big,
}

/// Whether a signal's raw value is interpreted as two's-complement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// `+` unsigned.
    Unsigned,
    /// `-` signed (two's complement).
    Signed,
}

/// Multiplexing role of a signal within its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Multiplex {
    /// Always present.
    Plain,
    /// The multiplexor switch signal (`M`).
    Multiplexor,
    /// Present only when the switch equals this value (`m<N>`).
    Multiplexed(u64),
}

/// One signal definition inside a [`Message`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// Signal name, unique within its message.
    pub name: String,
    /// Bit position of the LSB (little) or MSB (big), LSB-first within each byte.
    pub start_bit: u16,
    /// Signal width in bits (1..=64).
    pub length: u16,
    /// Bit ordering.
    pub byte_order: ByteOrder,
    /// Signed/unsigned interpretation.
    pub value_type: ValueType,
    /// Linear scaling factor.
    pub factor: f64,
    /// Linear scaling offset.
    pub offset: f64,
    /// Minimum physical value (metadata; `[0|0]` means unspecified).
    pub min: f64,
    /// Maximum physical value.
    pub max: f64,
    /// Physical unit string (may be empty).
    pub unit: String,
    /// Multiplexing role.
    pub multiplex: Multiplex,
    /// Optional raw-value to label map from a `VAL_` table.
    pub value_table: BTreeMap<i64, String>,
}

/// One CAN message definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Arbitration id with the 29-bit extended flag stripped.
    pub id: u32,
    /// Whether the message is a 29-bit extended-id frame.
    pub extended: bool,
    /// Message name.
    pub name: String,
    /// Declared data length in bytes.
    pub dlc: u8,
    /// Ordered signal definitions.
    pub signals: Vec<Signal>,
}

/// A parsed DBC database keyed by `(id, extended)`.
///
/// Not serializable on purpose: the tuple map key is not a valid JSON object
/// key. Serialize the decoded output ([`DecodedFrame`]) or individual
/// [`Message`]s instead.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Database {
    messages: BTreeMap<(u32, bool), Message>,
}

/// A `VAL_` value-table definition resolved against its message after parsing.
struct ValueTableDef {
    id: u32,
    extended: bool,
    signal: String,
    table: BTreeMap<i64, String>,
}

/// One decoded signal value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedSignal {
    /// Signal name.
    pub name: String,
    /// Raw integer value (sign-extended for signed signals).
    pub raw: i64,
    /// Physical value after `raw * factor + offset`.
    pub value: f64,
    /// Physical unit (may be empty).
    pub unit: String,
    /// Value-table label for `raw`, when one is defined.
    pub label: Option<String>,
}

/// The result of decoding one frame against the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedFrame {
    /// Matched message name.
    pub message: String,
    /// Decoded signals in definition order (multiplexed signals filtered).
    pub signals: Vec<DecodedSignal>,
}

/// A DBC parsing error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DbcError {
    /// A `BO_`, `SG_`, or `VAL_` line did not match the expected grammar.
    #[error("malformed {kind} on line {line}: {reason}")]
    Malformed {
        /// Line kind (`BO_`, `SG_`, `VAL_`).
        kind: &'static str,
        /// 1-based source line number.
        line: usize,
        /// Human-readable reason.
        reason: String,
    },
    /// A `SG_` line appeared before any `BO_` message.
    #[error("signal on line {line} has no preceding message")]
    OrphanSignal {
        /// 1-based source line number.
        line: usize,
    },
}

impl Database {
    /// Parse a DBC document into a database.
    ///
    /// Unknown line kinds (comments, attributes, node lists) are skipped; only
    /// `BO_`, `SG_`, and `VAL_` are interpreted. Malformed lines of those kinds
    /// fail closed.
    pub fn parse(text: &str) -> Result<Self, DbcError> {
        let mut messages: Vec<Message> = Vec::new();
        let mut value_tables: Vec<ValueTableDef> = Vec::new();

        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            let line_no = index + 1;
            let mut tokens = line.split_whitespace();
            match tokens.next() {
                Some("BO_") => {
                    let message = parse_message(line, line_no)?;
                    if messages.iter().any(|existing| {
                        existing.id == message.id && existing.extended == message.extended
                    }) {
                        return Err(DbcError::Malformed {
                            kind: "BO_",
                            line: line_no,
                            reason: "duplicate message id".to_owned(),
                        });
                    }
                    messages.push(message);
                }
                Some("SG_") => {
                    let message = messages
                        .last_mut()
                        .ok_or(DbcError::OrphanSignal { line: line_no })?;
                    let signal = parse_signal(line, line_no)?;
                    if message
                        .signals
                        .iter()
                        .any(|existing| existing.name == signal.name)
                    {
                        return Err(DbcError::Malformed {
                            kind: "SG_",
                            line: line_no,
                            reason: "duplicate signal name".to_owned(),
                        });
                    }
                    message.signals.push(signal);
                }
                Some("VAL_") => value_tables.push(parse_value_table(line, line_no)?),
                _ => {}
            }
        }

        let mut database = Self {
            messages: BTreeMap::new(),
        };
        for message in messages {
            database
                .messages
                .insert((message.id, message.extended), message);
        }
        for def in value_tables {
            if let Some(message) = database.messages.get_mut(&(def.id, def.extended)) {
                if let Some(signal) = message.signals.iter_mut().find(|s| s.name == def.signal) {
                    signal.value_table = def.table;
                }
            }
        }
        Ok(database)
    }

    /// Look up a message by arbitration id and extended flag.
    #[must_use]
    pub fn message(&self, id: u32, extended: bool) -> Option<&Message> {
        self.messages.get(&(id, extended))
    }

    /// Number of messages in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the database has no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Decode a frame payload into named signals.
    ///
    /// Returns `None` when no message matches `(id, extended)`. Signals whose bits
    /// fall outside `data` are skipped; multiplexed signals are included only when
    /// the message's multiplexor switch selects them.
    #[must_use]
    pub fn decode(&self, id: u32, extended: bool, data: &[u8]) -> Option<DecodedFrame> {
        let message = self.messages.get(&(id, extended))?;
        let switch = message
            .signals
            .iter()
            .find(|s| s.multiplex == Multiplex::Multiplexor)
            .and_then(|s| extract_raw(data, s.start_bit, s.length, s.byte_order));

        let mut signals = Vec::new();
        for signal in &message.signals {
            if let Multiplex::Multiplexed(selector) = signal.multiplex {
                if switch != Some(selector) {
                    continue;
                }
            }
            let Some(raw_bits) =
                extract_raw(data, signal.start_bit, signal.length, signal.byte_order)
            else {
                continue;
            };
            let raw = signed_value(raw_bits, signal.length, signal.value_type);
            let base = match signal.value_type {
                ValueType::Unsigned => raw_bits as f64,
                ValueType::Signed => raw as f64,
            };
            let label = signal.value_table.get(&raw).cloned();
            signals.push(DecodedSignal {
                name: signal.name.clone(),
                raw,
                value: base.mul_add(signal.factor, signal.offset),
                unit: signal.unit.clone(),
                label,
            });
        }
        Some(DecodedFrame {
            message: message.name.clone(),
            signals,
        })
    }
}

/// Read the bit at absolute position `pos` (LSB-first within each byte).
fn bit_at(data: &[u8], pos: usize) -> Option<u8> {
    let byte = pos / 8;
    let bit = pos % 8;
    data.get(byte).map(|value| (value >> bit) & 1)
}

/// Extract the raw unsigned bit field for a signal, or `None` if it runs past
/// the payload. Handles both bit orderings for signal widths up to 64 bits.
fn extract_raw(data: &[u8], start_bit: u16, length: u16, order: ByteOrder) -> Option<u64> {
    let length = length as usize;
    if length == 0 || length > 64 {
        return None;
    }
    let start = start_bit as usize;
    let mut raw: u64 = 0;
    match order {
        ByteOrder::Little => {
            for offset in 0..length {
                let bit = bit_at(data, start + offset)?;
                raw |= u64::from(bit) << offset;
            }
        }
        ByteOrder::Big => {
            // Motorola: MSB first, walking down within a byte, then jumping to the
            // top of the next-higher byte. On a byte boundary (pos % 8 == 0) the
            // next-less-significant bit is `pos + 15`; otherwise `pos - 1`.
            let mut pos = start;
            for _ in 0..length {
                let bit = bit_at(data, pos)?;
                raw = (raw << 1) | u64::from(bit);
                if pos.is_multiple_of(8) {
                    pos += 15;
                } else {
                    pos -= 1;
                }
            }
        }
    }
    Some(raw)
}

/// Interpret `raw` as a `length`-bit value under `value_type`, sign-extending
/// signed values into an `i64`.
fn signed_value(raw: u64, length: u16, value_type: ValueType) -> i64 {
    let length = u32::from(length);
    if value_type == ValueType::Signed && length < 64 && (raw >> (length - 1)) & 1 == 1 {
        raw.cast_signed().wrapping_sub(1_i64 << length)
    } else {
        raw.cast_signed()
    }
}

/// Parse a `BO_ <id> <name>: <dlc> <transmitter>` line.
fn parse_message(line: &str, line_no: usize) -> Result<Message, DbcError> {
    let malformed = |reason: &str| DbcError::Malformed {
        kind: "BO_",
        line: line_no,
        reason: reason.to_owned(),
    };
    let (head, tail) = line
        .split_once(':')
        .ok_or_else(|| malformed("missing ':' separator"))?;
    let head_tokens: Vec<&str> = head.split_whitespace().collect();
    // head_tokens = ["BO_", "<id>", "<name>"]
    if head_tokens.len() != 3 {
        return Err(malformed("expected `BO_ <id> <name>:`"));
    }
    let raw_id: u32 = head_tokens[1]
        .parse()
        .map_err(|_| malformed("id is not an unsigned integer"))?;
    let name = head_tokens[2].to_owned();
    if name.is_empty() {
        return Err(malformed("empty message name"));
    }
    let dlc: u8 = tail
        .split_whitespace()
        .next()
        .ok_or_else(|| malformed("missing DLC"))?
        .parse()
        .map_err(|_| malformed("DLC is not a byte"))?;
    if dlc > 64 {
        return Err(malformed("DLC exceeds the CAN FD payload limit"));
    }
    Ok(Message {
        id: raw_id & 0x1FFF_FFFF,
        extended: raw_id & 0x8000_0000 != 0,
        name,
        dlc,
        signals: Vec::new(),
    })
}

/// Parse a `SG_ <name> [mux] : <start>|<len>@<order><type> (<f>,<o>) [<min>|<max>] "<unit>" <rx>` line.
fn parse_signal(line: &str, line_no: usize) -> Result<Signal, DbcError> {
    let malformed = |reason: &str| DbcError::Malformed {
        kind: "SG_",
        line: line_no,
        reason: reason.to_owned(),
    };
    let (head, tail) = line
        .split_once(':')
        .ok_or_else(|| malformed("missing ':' separator"))?;
    let head_tokens: Vec<&str> = head.split_whitespace().collect();
    // head_tokens = ["SG_", "<name>", optional "<mux>"]
    if head_tokens.len() < 2 {
        return Err(malformed("missing signal name"));
    }
    let name = head_tokens[1].to_owned();
    let multiplex = match head_tokens.get(2) {
        None => Multiplex::Plain,
        Some(&"M") => Multiplex::Multiplexor,
        Some(token) if token.starts_with('m') => {
            let value = token[1..]
                .parse::<u64>()
                .map_err(|_| malformed("invalid multiplex selector"))?;
            Multiplex::Multiplexed(value)
        }
        Some(_) => return Err(malformed("unrecognized multiplex indicator")),
    };

    let tail = tail.trim();
    let bitspec_token = tail
        .split_whitespace()
        .next()
        .ok_or_else(|| malformed("missing bit layout"))?;
    // "<start>|<len>@<order><type>"
    let (start_str, rest) = bitspec_token
        .split_once('|')
        .ok_or_else(|| malformed("missing '|' in bit layout"))?;
    let (len_str, order_type) = rest
        .split_once('@')
        .ok_or_else(|| malformed("missing '@' in bit layout"))?;
    let start_bit: u16 = start_str
        .parse()
        .map_err(|_| malformed("invalid start bit"))?;
    let length: u16 = len_str.parse().map_err(|_| malformed("invalid length"))?;
    if !(1..=64).contains(&length) {
        return Err(malformed("signal length must be between 1 and 64 bits"));
    }
    let mut order_chars = order_type.chars();
    let byte_order = match order_chars.next() {
        Some('1') => ByteOrder::Little,
        Some('0') => ByteOrder::Big,
        _ => return Err(malformed("byte order must be 0 or 1")),
    };
    let value_type = match order_chars.next() {
        Some('+') => ValueType::Unsigned,
        Some('-') => ValueType::Signed,
        _ => return Err(malformed("value type must be + or -")),
    };
    if order_chars.next().is_some() {
        return Err(malformed("unexpected text after the bit layout"));
    }

    let (factor, offset) =
        parse_factor_offset(tail).ok_or_else(|| malformed("invalid (factor,offset)"))?;
    if !factor.is_finite() || !offset.is_finite() {
        return Err(malformed("factor and offset must be finite"));
    }
    let (min, max) = parse_min_max(tail).ok_or_else(|| malformed("invalid [min|max]"))?;
    if !min.is_finite() || !max.is_finite() {
        return Err(malformed("minimum and maximum must be finite"));
    }
    let unit = parse_quoted(tail).unwrap_or_default();

    Ok(Signal {
        name,
        start_bit,
        length,
        byte_order,
        value_type,
        factor,
        offset,
        min,
        max,
        unit,
        multiplex,
        value_table: BTreeMap::new(),
    })
}

/// Extract `(factor, offset)` from the `(f,o)` group in a signal tail.
fn parse_factor_offset(tail: &str) -> Option<(f64, f64)> {
    let start = tail.find('(')?;
    let end = tail[start..].find(')')? + start;
    let inner = &tail[start + 1..end];
    let (factor, offset) = inner.split_once(',')?;
    Some((factor.trim().parse().ok()?, offset.trim().parse().ok()?))
}

/// Extract `(min, max)` from the `[min|max]` group in a signal tail.
fn parse_min_max(tail: &str) -> Option<(f64, f64)> {
    let start = tail.find('[')?;
    let end = tail[start..].find(']')? + start;
    let inner = &tail[start + 1..end];
    let (min, max) = inner.split_once('|')?;
    Some((min.trim().parse().ok()?, max.trim().parse().ok()?))
}

/// Extract the first `"..."` quoted substring (the unit) from a signal tail.
fn parse_quoted(tail: &str) -> Option<String> {
    let start = tail.find('"')?;
    let end = tail[start + 1..].find('"')? + start + 1;
    Some(tail[start + 1..end].to_owned())
}

/// Parse a `VAL_ <id> <signal> <value> "label" ... ;` line.
fn parse_value_table(line: &str, line_no: usize) -> Result<ValueTableDef, DbcError> {
    let malformed = |reason: &str| DbcError::Malformed {
        kind: "VAL_",
        line: line_no,
        reason: reason.to_owned(),
    };
    let body = line.trim_start_matches("VAL_").trim().trim_end_matches(';');
    let tokens: Vec<&str> = body.split_whitespace().collect();
    if tokens.len() < 2 {
        return Err(malformed("expected `VAL_ <id> <signal> ...`"));
    }
    let raw_id: u32 = tokens[0]
        .parse()
        .map_err(|_| malformed("id is not an unsigned integer"))?;
    let signal_name = tokens[1].to_owned();

    // The remainder is a sequence of `<value> "label"` pairs. Rejoin and scan for
    // quoted labels so labels may contain spaces.
    let remainder = body
        .split_once(signal_name.as_str())
        .map_or("", |(_, rest)| rest)
        .trim();
    let mut table = BTreeMap::new();
    let mut cursor = remainder;
    while let Some(quote_start) = cursor.find('"') {
        let value_part = cursor[..quote_start].trim();
        let value: i64 = value_part
            .split_whitespace()
            .next_back()
            .ok_or_else(|| malformed("missing value before label"))?
            .parse()
            .map_err(|_| malformed("value is not an integer"))?;
        let after = &cursor[quote_start + 1..];
        let quote_end = after
            .find('"')
            .ok_or_else(|| malformed("unterminated label"))?;
        table.insert(value, after[..quote_end].to_owned());
        cursor = &after[quote_end + 1..];
    }
    Ok(ValueTableDef {
        id: raw_id & 0x1FFF_FFFF,
        extended: raw_id & 0x8000_0000 != 0,
        signal: signal_name,
        table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    const SAMPLE: &str = r#"
BO_ 100 EngineData: 8 ECU
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
 SG_ Temperature : 7|16@0- (1,-40) [-40|215] "degC" Vector__XXX

BO_ 200 Multiplexed: 8 ECU
 SG_ Mode M : 0|8@1+ (1,0) [0|255] "" ECU
 SG_ VoltageA m0 : 8|16@1+ (0.01,0) [0|655] "V" ECU
 SG_ CurrentB m1 : 8|16@1+ (0.1,0) [0|6553] "A" ECU

VAL_ 200 Mode 0 "voltage" 1 "current" ;
"#;

    #[test]
    fn parses_messages_and_signals() {
        let db = Database::parse(SAMPLE).expect("valid dbc");
        assert_eq!(db.len(), 2);
        let engine = db.message(100, false).expect("engine message");
        assert_eq!(engine.name, "EngineData");
        assert_eq!(engine.dlc, 8);
        assert_eq!(engine.signals.len(), 2);
        let speed = &engine.signals[0];
        assert_eq!(speed.start_bit, 24);
        assert_eq!(speed.length, 16);
        assert_eq!(speed.byte_order, ByteOrder::Little);
        assert_eq!(speed.value_type, ValueType::Unsigned);
        assert!(approx(speed.factor, 0.125));
    }

    #[test]
    fn decodes_intel_unsigned_signal() {
        let db = Database::parse(SAMPLE).unwrap();
        // EngineSpeed at bit 24, 16 bits little-endian: bytes 3 (low) and 4 (high).
        let data = [0, 0, 0, 0x00, 0x10, 0, 0, 0];
        let frame = db.decode(100, false, &data).unwrap();
        let speed = frame
            .signals
            .iter()
            .find(|s| s.name == "EngineSpeed")
            .unwrap();
        assert_eq!(speed.raw, 0x1000);
        assert!(approx(speed.value, 512.0)); // 4096 * 0.125
        assert_eq!(speed.unit, "rpm");
    }

    #[test]
    fn decodes_motorola_signed_signal() {
        let db = Database::parse(SAMPLE).unwrap();
        // Temperature at bit 7 MSB, 16 bits big-endian => bytes 0 (high) and 1 (low).
        // 0x8000 as signed 16-bit = -32768, factor 1, offset -40 => -32808.
        let data = [0x80, 0x00, 0, 0, 0, 0, 0, 0];
        let frame = db.decode(100, false, &data).unwrap();
        let temp = frame
            .signals
            .iter()
            .find(|s| s.name == "Temperature")
            .unwrap();
        assert_eq!(temp.raw, -32768);
        assert!(approx(temp.value, -32808.0));
    }

    #[test]
    fn out_of_range_signal_is_skipped_not_panicking() {
        // A 4-byte frame cannot satisfy a signal that needs bytes 3 and 4.
        let db = Database::parse(SAMPLE).unwrap();
        let data = [0, 0, 0, 0];
        let frame = db.decode(100, false, &data).unwrap();
        assert!(frame.signals.iter().all(|s| s.name != "EngineSpeed"));
    }

    #[test]
    fn multiplexing_selects_by_switch_value() {
        let db = Database::parse(SAMPLE).unwrap();
        // Mode byte 0 = 0 selects VoltageA (m0); CurrentB (m1) must be absent.
        let data = [0x00, 0xE8, 0x03, 0, 0, 0, 0, 0]; // VoltageA raw 0x03E8 = 1000 -> 10.0 V
        let frame = db.decode(200, false, &data).unwrap();
        assert!(frame.signals.iter().any(|s| s.name == "VoltageA"));
        assert!(frame.signals.iter().all(|s| s.name != "CurrentB"));
        let mode = frame.signals.iter().find(|s| s.name == "Mode").unwrap();
        assert_eq!(mode.label.as_deref(), Some("voltage"));
        let volt = frame.signals.iter().find(|s| s.name == "VoltageA").unwrap();
        assert!(approx(volt.value, 10.0));
    }

    #[test]
    fn unknown_message_decodes_to_none() {
        let db = Database::parse(SAMPLE).unwrap();
        assert!(db.decode(0x7FF, false, &[0; 8]).is_none());
    }

    #[test]
    fn malformed_signal_fails_closed() {
        let bad = "BO_ 1 X: 8 ECU\n SG_ Broken : notbits@1+ (1,0) \"\" ECU\n";
        assert!(matches!(
            Database::parse(bad),
            Err(DbcError::Malformed { kind: "SG_", .. })
        ));
    }

    #[test]
    fn rejects_signal_lengths_outside_the_public_contract() {
        for length in [0, 65] {
            let bad = format!("BO_ 1 X: 8 ECU\n SG_ Broken : 0|{length}@1+ (1,0) [0|1] \"\" ECU\n");
            assert!(matches!(
                Database::parse(&bad),
                Err(DbcError::Malformed { kind: "SG_", .. })
            ));
        }
    }

    #[test]
    fn rejects_non_finite_scaling_and_malformed_bounds() {
        let non_finite = "BO_ 1 X: 8 ECU\n SG_ Broken : 0|8@1+ (NaN,0) [0|1] \"\" ECU\n";
        assert!(matches!(
            Database::parse(non_finite),
            Err(DbcError::Malformed { kind: "SG_", .. })
        ));

        let malformed_bounds = "BO_ 1 X: 8 ECU\n SG_ Broken : 0|8@1+ (1,0) [not-bounds] \"\" ECU\n";
        assert!(matches!(
            Database::parse(malformed_bounds),
            Err(DbcError::Malformed { kind: "SG_", .. })
        ));
    }

    #[test]
    fn rejects_duplicate_messages_and_signal_names() {
        let duplicate_message = "BO_ 1 First: 8 ECU\nBO_ 1 Second: 8 ECU\n";
        assert!(matches!(
            Database::parse(duplicate_message),
            Err(DbcError::Malformed { kind: "BO_", .. })
        ));

        let duplicate_signal = "\
BO_ 1 Message: 8 ECU
 SG_ Value : 0|8@1+ (1,0) [0|255] \"\" ECU
 SG_ Value : 8|8@1+ (1,0) [0|255] \"\" ECU
";
        assert!(matches!(
            Database::parse(duplicate_signal),
            Err(DbcError::Malformed { kind: "SG_", .. })
        ));
    }

    #[test]
    fn rejects_invalid_message_dlc_and_trailing_bit_layout_text() {
        let invalid_dlc = "BO_ 1 Message: 65 ECU\n";
        assert!(matches!(
            Database::parse(invalid_dlc),
            Err(DbcError::Malformed { kind: "BO_", .. })
        ));

        let invalid_layout = "BO_ 1 X: 8 ECU\n SG_ Broken : 0|8@1+garbage (1,0) [0|1] \"\" ECU\n";
        assert!(matches!(
            Database::parse(invalid_layout),
            Err(DbcError::Malformed { kind: "SG_", .. })
        ));
    }

    #[test]
    fn orphan_signal_is_rejected() {
        let bad = " SG_ Lonely : 0|8@1+ (1,0) \"\" ECU\n";
        assert!(matches!(
            Database::parse(bad),
            Err(DbcError::OrphanSignal { .. })
        ));
    }
}
