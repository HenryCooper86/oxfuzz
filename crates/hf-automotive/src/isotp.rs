//! Pure-Rust ISO-TP (ISO 15765-2) receiver reassembly.
//!
//! Turns a sequence of raw CAN frames belonging to one ISO-TP connection into
//! reassembled protocol data units (PDUs), so multi-frame UDS/GMLAN/OBD payloads
//! decode correctly. This is offline analysis: it parses Single, First, and
//! Consecutive frames and concatenates them; Flow-Control frames (which a live
//! receiver would send) are recognized and ignored for reassembly. It never
//! opens an interface.
//!
//! Normal and extended addressing are supported (extended addressing consumes
//! the first data byte as the address extension). Clean-room from ISO 15765-2;
//! no GPL source is used.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ISO-TP addressing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Addressing {
    /// The CAN id alone identifies the connection; PCI starts at byte 0.
    Normal,
    /// The first data byte is the address extension; PCI starts at byte 1.
    Extended,
}

/// A fully reassembled ISO-TP PDU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pdu {
    /// Reassembled payload, trimmed to the declared length.
    pub data: Vec<u8>,
}

/// An ISO-TP reassembly error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IsoTpError {
    /// A frame was shorter than its PCI required.
    #[error("truncated ISO-TP frame")]
    Truncated,
    /// A consecutive frame arrived with an unexpected sequence number.
    #[error("ISO-TP sequence error: expected {expected}, got {got}")]
    SequenceError {
        /// Sequence number the reassembler expected next.
        expected: u8,
        /// Sequence number that actually arrived.
        got: u8,
    },
}

/// Streaming ISO-TP receiver reassembler for one connection.
#[derive(Debug, Clone)]
pub struct Reassembler {
    addressing: Addressing,
    buffer: Vec<u8>,
    expected_len: usize,
    next_sn: u8,
    active: bool,
}

impl Reassembler {
    /// Create a reassembler for the given addressing mode.
    #[must_use]
    pub fn new(addressing: Addressing) -> Self {
        Self {
            addressing,
            buffer: Vec::new(),
            expected_len: 0,
            next_sn: 0,
            active: false,
        }
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.expected_len = 0;
        self.next_sn = 0;
        self.active = false;
    }

    fn finish(&mut self) -> Pdu {
        self.buffer.truncate(self.expected_len);
        let data = std::mem::take(&mut self.buffer);
        self.reset();
        Pdu { data }
    }

    /// Feed one CAN frame's data bytes. Returns a completed [`Pdu`] when this
    /// frame finishes a message, or `None` while more frames are needed.
    ///
    /// # Errors
    /// Returns [`IsoTpError`] on a truncated frame or an out-of-order
    /// consecutive frame.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Pdu>, IsoTpError> {
        let offset = match self.addressing {
            Addressing::Normal => 0,
            Addressing::Extended => 1,
        };
        let pci = frame.get(offset..).unwrap_or(&[]);
        let Some(&first) = pci.first() else {
            self.reset();
            return Err(IsoTpError::Truncated);
        };
        match first >> 4 {
            0x0 => self.single_frame(pci),
            0x1 => self.first_frame(pci),
            0x2 => self.consecutive_frame(pci),
            // Flow control (0x3) and reserved types are not part of receiver
            // reassembly; ignore them.
            _ => Ok(None),
        }
    }

    fn single_frame(&mut self, pci: &[u8]) -> Result<Option<Pdu>, IsoTpError> {
        self.reset();
        let low = pci[0] & 0x0F;
        let (len, start) = if low != 0 {
            (low as usize, 1)
        } else {
            // CAN-FD escape: SF_DL == 0 means the real length is in the next byte.
            (*pci.get(1).ok_or(IsoTpError::Truncated)? as usize, 2)
        };
        if len == 0 {
            return Err(IsoTpError::Truncated);
        }
        let data = pci
            .get(start..start + len)
            .ok_or(IsoTpError::Truncated)?
            .to_vec();
        Ok(Some(Pdu { data }))
    }

    fn first_frame(&mut self, pci: &[u8]) -> Result<Option<Pdu>, IsoTpError> {
        self.reset();
        let high = usize::from(pci[0] & 0x0F);
        let low = usize::from(*pci.get(1).ok_or(IsoTpError::Truncated)?);
        let (len, payload_start) = if high == 0 && low == 0 {
            // 32-bit escape for lengths > 4095.
            let bytes: [u8; 4] = pci
                .get(2..6)
                .ok_or(IsoTpError::Truncated)?
                .try_into()
                .map_err(|_| IsoTpError::Truncated)?;
            (u32::from_be_bytes(bytes) as usize, 6)
        } else {
            ((high << 8) | low, 2)
        };
        if len == 0 {
            return Err(IsoTpError::Truncated);
        }
        let payload = pci.get(payload_start..).ok_or(IsoTpError::Truncated)?;
        if payload.is_empty() || len <= payload.len() {
            return Err(IsoTpError::Truncated);
        }
        self.buffer.extend_from_slice(payload);
        self.expected_len = len;
        self.next_sn = 1;
        self.active = true;
        if self.buffer.len() >= self.expected_len {
            return Ok(Some(self.finish()));
        }
        Ok(None)
    }

    fn consecutive_frame(&mut self, pci: &[u8]) -> Result<Option<Pdu>, IsoTpError> {
        if !self.active {
            return Ok(None); // stray consecutive frame
        }
        let sn = pci[0] & 0x0F;
        if sn != self.next_sn {
            let expected = self.next_sn;
            self.reset();
            return Err(IsoTpError::SequenceError { expected, got: sn });
        }
        if pci.len() == 1 {
            self.reset();
            return Err(IsoTpError::Truncated);
        }
        let remaining = self.expected_len - self.buffer.len();
        let payload = pci.get(1..).unwrap_or(&[]);
        let take = remaining.min(payload.len());
        self.buffer.extend_from_slice(&payload[..take]);
        self.next_sn = (self.next_sn + 1) & 0x0F;
        if self.buffer.len() >= self.expected_len {
            return Ok(Some(self.finish()));
        }
        Ok(None)
    }
}

/// Reassemble every complete PDU from a sequence of one connection's frames.
///
/// Best-effort for offline analysis: an out-of-order or truncated frame resets
/// the current partial message and reassembly continues with the next frame.
pub fn reassemble_all<'a, I>(frames: I, addressing: Addressing) -> Vec<Pdu>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut reassembler = Reassembler::new(addressing);
    let mut pdus = Vec::new();
    for frame in frames {
        match reassembler.push(frame) {
            Ok(Some(pdu)) => pdus.push(pdu),
            Ok(None) => {}
            Err(_) => reassembler.reset(),
        }
    }
    pdus
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Segment a payload into ISO-TP frames (normal addressing) for round-trip
    /// tests, exercising the FF/CF split and sequence-number wraparound.
    fn segment(payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.len() <= 7 {
            let mut sf = vec![payload.len() as u8];
            sf.extend_from_slice(payload);
            return vec![sf];
        }
        let mut frames = Vec::new();
        let len = payload.len();
        let mut ff = vec![0x10 | ((len >> 8) as u8 & 0x0F), (len & 0xFF) as u8];
        ff.extend_from_slice(&payload[..6]);
        frames.push(ff);
        let mut sent = 6;
        let mut sn = 1_u8;
        while sent < len {
            let take = (len - sent).min(7);
            let mut cf = vec![0x20 | (sn & 0x0F)];
            cf.extend_from_slice(&payload[sent..sent + take]);
            frames.push(cf);
            sent += take;
            sn = (sn + 1) & 0x0F;
        }
        frames
    }

    #[test]
    fn single_frame_delivers_immediately() {
        let mut r = Reassembler::new(Addressing::Normal);
        // SF, length 3, data AA BB CC.
        let pdu = r.push(&[0x03, 0xAA, 0xBB, 0xCC, 0x00]).unwrap().unwrap();
        assert_eq!(pdu.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn single_frame_fd_escape() {
        let mut r = Reassembler::new(Addressing::Normal);
        // SF_DL nibble 0 -> length in next byte (9), then 9 data bytes.
        let frame = [0x00, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pdu = r.push(&frame).unwrap().unwrap();
        assert_eq!(pdu.data, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn first_and_consecutive_frames_reassemble() {
        let mut r = Reassembler::new(Addressing::Normal);
        // 17-byte message split FF(6) + CF1(7) + CF2(4).
        assert!(r.push(&[0x10, 0x11, 0, 1, 2, 3, 4, 5]).unwrap().is_none());
        assert!(r.push(&[0x21, 6, 7, 8, 9, 10, 11, 12]).unwrap().is_none());
        let pdu = r
            .push(&[0x22, 13, 14, 15, 16, 0xAA, 0xAA, 0xAA])
            .unwrap()
            .unwrap();
        assert_eq!(pdu.data, (0..=16).collect::<Vec<u8>>());
    }

    #[test]
    fn round_trip_with_sequence_wraparound() {
        // 200 bytes forces well past SN 15, exercising the 15 -> 0 wrap.
        let payload: Vec<u8> = (0..200).map(|i| (i * 7 % 251) as u8).collect();
        let frames = segment(&payload);
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let pdus = reassemble_all(refs, Addressing::Normal);
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0].data, payload);
    }

    #[test]
    fn extended_addressing_skips_address_byte() {
        let mut r = Reassembler::new(Addressing::Extended);
        // Byte 0 is the address extension; PCI/data follow.
        let pdu = r.push(&[0xF1, 0x02, 0xDE, 0xAD]).unwrap().unwrap();
        assert_eq!(pdu.data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn missing_pci_is_reported_as_truncated() {
        let mut normal = Reassembler::new(Addressing::Normal);
        assert_eq!(normal.push(&[]), Err(IsoTpError::Truncated));

        let mut extended = Reassembler::new(Addressing::Extended);
        assert_eq!(extended.push(&[0xF1]), Err(IsoTpError::Truncated));
    }

    #[test]
    fn zero_length_first_frame_is_rejected() {
        let mut r = Reassembler::new(Addressing::Normal);
        assert_eq!(
            r.push(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(IsoTpError::Truncated)
        );
    }

    #[test]
    fn first_frame_requires_payload_and_a_multiframe_length() {
        let mut no_payload = Reassembler::new(Addressing::Normal);
        assert_eq!(no_payload.push(&[0x10, 0x10]), Err(IsoTpError::Truncated));

        let mut already_complete = Reassembler::new(Addressing::Normal);
        assert_eq!(
            already_complete.push(&[0x10, 0x03, 0xAA, 0xBB, 0xCC]),
            Err(IsoTpError::Truncated)
        );
    }

    #[test]
    fn consecutive_frame_requires_payload() {
        let mut r = Reassembler::new(Addressing::Normal);
        r.push(&[0x10, 0x10, 0, 1, 2, 3, 4, 5]).unwrap();
        assert_eq!(r.push(&[0x21]), Err(IsoTpError::Truncated));
    }

    #[test]
    fn out_of_order_consecutive_frame_errors() {
        let mut r = Reassembler::new(Addressing::Normal);
        r.push(&[0x10, 0x14, 0, 1, 2, 3, 4, 5]).unwrap();
        // Expected SN 1, send SN 2.
        assert!(matches!(
            r.push(&[0x22, 6, 7, 8, 9, 10, 11, 12]),
            Err(IsoTpError::SequenceError {
                expected: 1,
                got: 2
            })
        ));
    }

    #[test]
    fn flow_control_frame_is_ignored() {
        let mut r = Reassembler::new(Addressing::Normal);
        assert!(r.push(&[0x30, 0x00, 0x00]).unwrap().is_none());
    }

    #[test]
    fn stray_consecutive_frame_is_ignored() {
        let mut r = Reassembler::new(Addressing::Normal);
        assert!(r.push(&[0x21, 1, 2, 3]).unwrap().is_none());
    }
}
