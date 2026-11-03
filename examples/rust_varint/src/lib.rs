//! Unsigned LEB128 varint decoding, as used by protobuf, WebAssembly and
//! DWARF.
//!
//! Each byte carries 7 value bits, least-significant group first. A set high
//! bit (0x80) means another byte follows.
//!
//! This is an oxfuzz example target with one deliberately planted bug; see
//! README.md in this directory.

use std::fmt;

/// Why a varint could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended while the continuation bit was still set.
    Truncated,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("varint truncated"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decodes one unsigned LEB128 varint from the start of `data`.
///
/// Returns the decoded value and the number of bytes consumed.
///
/// # Errors
///
/// Returns [`DecodeError::Truncated`] if `data` ends before a byte with a
/// clear continuation bit.
pub fn decode(data: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        // BUG: no upper bound on `shift`. A u64 holds at most 10 groups
        // (shift 0..=63). On the 11th byte `shift` is 70, and `<<` panics
        // with "attempt to shift left with overflow" when overflow checks are
        // on, or silently wraps the shift amount when they are off. A correct
        // decoder rejects the input once `shift >= 64` (and checks that the
        // 10th byte contributes only one bit).
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(DecodeError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_and_multi_byte_values() {
        assert_eq!(decode(&[0x00]), Ok((0, 1)));
        assert_eq!(decode(&[0x7f]), Ok((127, 1)));
        assert_eq!(decode(&[0xe5, 0x8e, 0x26]), Ok((624_485, 3)));
        assert_eq!(decode(&[0x96, 0x01, 0xff]), Ok((150, 2)));
    }

    #[test]
    fn decodes_u64_max_in_ten_bytes() {
        let mut bytes = [0xff_u8; 10];
        bytes[9] = 0x01;
        assert_eq!(decode(&bytes), Ok((u64::MAX, 10)));
    }

    #[test]
    fn reports_truncation() {
        assert_eq!(decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(decode(&[0x80, 0x80]), Err(DecodeError::Truncated));
    }
}
