//! Shared SSE (Server-Sent Events) stream parsing infrastructure.
//!
//! Provides a reusable byte-stream-to-text decoder and SSE event extractor
//! used by all streaming LLM provider implementations. This module
//! eliminates ~150 lines of duplicated UTF-8 decoding and event boundary
//! detection logic that was previously copied across 5 provider files.

use std::pin::Pin;

use bytes::Bytes;
use futures::Stream;

use hf_core::provider::ProviderError;

// ---------------------------------------------------------------------------
// Byte stream type alias
// ---------------------------------------------------------------------------

/// A pinned, boxed byte stream from an HTTP response.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

// ---------------------------------------------------------------------------
// SSE stream state
// ---------------------------------------------------------------------------

/// Framing used by a successful provider response.
#[derive(Clone, Copy)]
pub enum StreamFraming {
    /// Events terminated by LF/LF or CRLF/CRLF.
    Sse,
    /// JSON objects terminated by one newline.
    Ndjson,
}

/// Incremental bounded UTF-8 receiver. Consumers drain a complete frame before
/// calling `read_next` again. Provider-specific accumulation stays in adapters.
pub struct SseStreamState {
    byte_stream: Option<ByteStream>,
    pending: Bytes,
    limits: hf_core::provider::ResponseStreamLimits,
    framing: StreamFraming,
    wire_bytes: usize,
    decoded_bytes: usize,
    /// Decoded bytes of at most one protocol frame.
    pub buffer: String,
    bytes_remainder: Vec<u8>,
    /// Whether the stream has ended or failed.
    pub done: bool,
}

impl SseStreamState {
    /// Construct a receiver from explicitly resolved budgets and framing.
    pub fn new(
        byte_stream: ByteStream,
        limits: hf_core::provider::ResponseStreamLimits,
        framing: StreamFraming,
    ) -> Self {
        Self {
            byte_stream: Some(byte_stream),
            pending: Bytes::new(),
            limits,
            framing,
            wire_bytes: 0,
            decoded_bytes: 0,
            buffer: String::new(),
            bytes_remainder: Vec::new(),
            done: false,
        }
    }

    /// Receive and decode at most one complete frame. A transport chunk may
    /// contain several frames; its unread bytes remain a shared Bytes slice.
    ///
    /// # Errors
    /// Returns one terminal network or resource error. Subsequent calls return
    /// `Ok(false)`; resource failures immediately drop all receive state.
    pub async fn read_next(&mut self) -> Result<bool, ProviderError> {
        if self.done {
            return Ok(false);
        }
        let result = self.receive_next().await;
        if result.is_err() {
            self.done = true;
            self.byte_stream = None;
            self.pending = Bytes::new();
            self.buffer = String::new();
            self.bytes_remainder = Vec::new();
        }
        result
    }

    async fn receive_next(&mut self) -> Result<bool, ProviderError> {
        use futures::StreamExt as _;
        use hf_core::provider::ResponseStreamBudget;
        if self.pending.is_empty() {
            let stream = self
                .byte_stream
                .as_mut()
                .expect("active receiver owns its stream");
            match stream.next().await {
                Some(Ok(bytes)) => {
                    if bytes.len() > self.limits.wire_bytes() - self.wire_bytes {
                        return Err(self.limit_error(ResponseStreamBudget::Wire));
                    }
                    self.wire_bytes += bytes.len();
                    self.pending = bytes;
                }
                Some(Err(error)) => {
                    return Err(ProviderError::NetworkError {
                        message: format!("stream read error: {error}"),
                    })
                }
                None => {
                    self.byte_stream = None;
                    if !self.bytes_remainder.is_empty() {
                        self.bytes_remainder.clear();
                        self.append_text("\u{FFFD}")?;
                    }
                    self.done = true;
                    return Ok(false);
                }
            }
        }
        while !self.pending.is_empty() {
            // Limit the temporary UTF-8 combination too, before copying. An
            // unterminated transport chunk cannot allocate a second huge buffer.
            let capacity =
                (self.limits.frame_bytes() - self.buffer.len() - self.bytes_remainder.len())
                    .min(self.limits.decoded_bytes() - self.decoded_bytes)
                    + 1;
            let window = self.pending.len().min(capacity);
            let count = self.pending[..window]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(window, |i| i + 1);
            let bytes = self.pending.split_to(count);
            self.decode_bytes(&bytes)?;
            let complete = match self.framing {
                StreamFraming::Sse => {
                    self.buffer.ends_with("\n\n") || self.buffer.ends_with("\r\n\r\n")
                }
                StreamFraming::Ndjson => self.buffer.ends_with('\n'),
            };
            if complete {
                break;
            }
        }
        Ok(true)
    }

    fn limit_error(&self, budget: hf_core::provider::ResponseStreamBudget) -> ProviderError {
        use hf_core::provider::ResponseStreamBudget;
        ProviderError::ResponseStreamLimitExceeded {
            budget,
            limit_bytes: match budget {
                ResponseStreamBudget::Wire => self.limits.wire_bytes(),
                ResponseStreamBudget::Decoded => self.limits.decoded_bytes(),
                ResponseStreamBudget::Frame => self.limits.frame_bytes(),
            },
        }
    }

    fn append_text(&mut self, text: &str) -> Result<(), ProviderError> {
        use hf_core::provider::ResponseStreamBudget;
        if text.len() > self.limits.decoded_bytes() - self.decoded_bytes {
            return Err(self.limit_error(ResponseStreamBudget::Decoded));
        }
        if text.len() > self.limits.frame_bytes() - self.buffer.len() {
            return Err(self.limit_error(ResponseStreamBudget::Frame));
        }
        self.decoded_bytes += text.len();
        self.buffer.push_str(text);
        Ok(())
    }

    fn decode_bytes(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        let mut combined = std::mem::take(&mut self.bytes_remainder);
        combined.extend_from_slice(bytes);
        let mut remaining = combined.as_slice();
        loop {
            match std::str::from_utf8(remaining) {
                Ok(text) => return self.append_text(text),
                Err(error) => {
                    let valid = error.valid_up_to();
                    self.append_text(
                        std::str::from_utf8(&remaining[..valid])
                            .expect("valid_up_to guarantees UTF-8"),
                    )?;
                    match error.error_len() {
                        None => {
                            let tail = &remaining[valid..];
                            if tail.len() > self.limits.frame_bytes() - self.buffer.len() {
                                return Err(self
                                    .limit_error(hf_core::provider::ResponseStreamBudget::Frame));
                            }
                            self.bytes_remainder.extend_from_slice(tail);
                            return Ok(());
                        }
                        Some(invalid) => {
                            self.append_text("\u{FFFD}")?;
                            remaining = &remaining[valid + invalid..];
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn resolve_default_limits() -> hf_core::provider::ResponseStreamLimits {
    hf_core::provider::ResponseStreamLimitsConfig::default()
        .resolve()
        .expect("default stream budgets are valid")
}

// ---------------------------------------------------------------------------
// SSE event extraction
// ---------------------------------------------------------------------------

/// Extract one SSE event `data:` payload from the buffer.
///
/// SSE events are separated by double newlines (`\n\n` or `\r\n\r\n`).
/// Each event may contain multiple `data:` lines which are joined with `\n`.
/// Non-data fields (`event:`, `id:`, `retry:`) are ignored.
///
/// Returns `None` if no complete event is available yet.
/// Returns `Some("")` for events with no `data:` lines (e.g. comments).
///
/// Used by `OpenAI`, Azure, Gemini, and compatible providers.
pub fn extract_sse_data(buffer: &mut String) -> Option<String> {
    let lf = buffer.find("\n\n");
    let crlf = buffer.find("\r\n\r\n");
    let boundary = match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }?;

    let raw_event: String = buffer.drain(..boundary).collect();
    let skip = buffer
        .bytes()
        .take_while(|&b| b == b'\n' || b == b'\r')
        .count();
    if skip > 0 {
        buffer.drain(..skip);
    }

    let mut data_parts = Vec::new();
    for line in raw_event.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data:") {
            data_parts.push(data.trim().to_string());
        }
    }

    if data_parts.is_empty() {
        return Some(String::new());
    }

    Some(data_parts.join("\n"))
}

/// Extract one newline-delimited JSON line from the buffer.
///
/// Used by Ollama which sends one JSON object per line (NDJSON format).
pub fn extract_json_line(buffer: &mut String) -> Option<String> {
    let newline_pos = buffer.find('\n')?;
    let line: String = buffer.drain(..=newline_pos).collect();
    Some(line)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sse_data_simple() {
        let mut buf = "data: {\"hello\":\"world\"}\n\n".to_string();
        let event = extract_sse_data(&mut buf).unwrap();
        assert_eq!(event, "{\"hello\":\"world\"}");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_sse_data_done_signal() {
        let mut buf = "data: [DONE]\n\n".to_string();
        let event = extract_sse_data(&mut buf).unwrap();
        assert_eq!(event, "[DONE]");
    }

    #[test]
    fn extract_sse_data_incomplete() {
        let mut buf = "data: {\"partial\":".to_string();
        assert!(extract_sse_data(&mut buf).is_none());
        assert_eq!(buf, "data: {\"partial\":");
    }

    #[test]
    fn extract_sse_data_multiple_events() {
        let mut buf = "data: first\n\ndata: second\n\n".to_string();
        let e1 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e1, "first");
        let e2 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e2, "second");
    }

    #[test]
    fn extract_sse_data_with_event_type() {
        let mut buf = "event: content_block_delta\ndata: {\"type\":\"delta\"}\n\n".to_string();
        let event = extract_sse_data(&mut buf).unwrap();
        assert_eq!(event, "{\"type\":\"delta\"}");
    }

    #[test]
    fn extract_sse_data_no_data_lines() {
        let mut buf = "event: ping\n\n".to_string();
        let event = extract_sse_data(&mut buf).unwrap();
        assert_eq!(event, "");
    }

    #[test]
    fn extract_sse_data_crlf_boundary() {
        let mut buf = "data: {\"ok\":true}\r\n\r\n".to_string();
        let event = extract_sse_data(&mut buf).unwrap();
        assert_eq!(event, "{\"ok\":true}");
    }

    /// Mixed line-ending streams: an LF-terminated event followed by a CRLF-terminated
    /// one must extract the first event without fusing it into the second.
    #[test]
    fn extract_sse_data_lf_then_crlf() {
        let mut buf = "data: first\n\ndata: second\r\n\r\n".to_string();
        let e1 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e1, "first");
        let e2 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e2, "second");
    }

    /// And the reverse order — CRLF first, LF second.
    #[test]
    fn extract_sse_data_crlf_then_lf() {
        let mut buf = "data: first\r\n\r\ndata: second\n\n".to_string();
        let e1 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e1, "first");
        let e2 = extract_sse_data(&mut buf).unwrap();
        assert_eq!(e2, "second");
    }

    #[test]
    fn extract_json_line_simple() {
        let mut buf = "{\"done\":false,\"message\":\"hi\"}\n".to_string();
        let line = extract_json_line(&mut buf).unwrap();
        assert!(line.contains("\"done\":false"));
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_json_line_incomplete() {
        let mut buf = "{\"partial\":true".to_string();
        assert!(extract_json_line(&mut buf).is_none());
    }

    #[test]
    fn decode_bytes_handles_split_utf8() {
        let mut state = SseStreamState::new(
            Box::pin(futures::stream::empty()),
            resolve_default_limits(),
            StreamFraming::Sse,
        );

        // "e" with acute accent = 0xC3 0xA9 in UTF-8
        // Simulate splitting the multi-byte sequence across chunks
        state.decode_bytes(&[b'h', b'i', 0xC3]).unwrap();
        assert_eq!(state.buffer, "hi");
        assert_eq!(state.bytes_remainder, vec![0xC3]);

        state.decode_bytes(&[0xA9, b'!']).unwrap();
        assert_eq!(state.buffer, "hi\u{00e9}!");
        assert!(state.bytes_remainder.is_empty());
    }

    #[test]
    fn decode_bytes_recovers_from_invalid_byte_without_stalling() {
        let mut state = SseStreamState::new(
            Box::pin(futures::stream::empty()),
            resolve_default_limits(),
            StreamFraming::Sse,
        );

        // 0xFF is never valid UTF-8. The decoder must emit the surrounding text
        // plus a replacement char and keep going -- the old code stashed the bad
        // byte in `bytes_remainder`, where it re-failed forever and the stream
        // silently stopped decoding.
        state.decode_bytes(&[b'a', 0xFF, b'b']).unwrap();
        assert_eq!(state.buffer, "a\u{FFFD}b");
        assert!(
            state.bytes_remainder.is_empty(),
            "invalid byte left in remainder would stall the stream"
        );

        // A subsequent valid chunk still decodes -- no permanent stall.
        state.decode_bytes(b"c").unwrap();
        assert_eq!(state.buffer, "a\u{FFFD}bc");
    }
    fn limited_state(
        chunks: Vec<Vec<u8>>,
        wire: usize,
        decoded: usize,
        frame: usize,
        framing: StreamFraming,
    ) -> SseStreamState {
        let limits = hf_core::provider::ResponseStreamLimitsConfig {
            wire_bytes: wire,
            decoded_bytes: decoded,
            frame_bytes: frame,
        }
        .resolve()
        .unwrap();
        let stream = futures::stream::iter(chunks.into_iter().map(|bytes| Ok(Bytes::from(bytes))));
        SseStreamState::new(Box::pin(stream), limits, framing)
    }

    #[tokio::test]
    async fn unterminated_frames_stop_at_budget_and_drop_receive_state() {
        for framing in [StreamFraming::Sse, StreamFraming::Ndjson] {
            let mut state = limited_state(vec![b"xxxxxxxxx".to_vec()], 100, 100, 8, framing);
            let error = state.read_next().await.unwrap_err();
            assert!(error.to_string().contains("frame_bytes"));
            assert!(state.done);
            assert!(state.buffer.is_empty());
            assert!(state.bytes_remainder.is_empty());
            assert!(!state.read_next().await.unwrap());
        }
    }

    #[tokio::test]
    async fn decoded_budget_counts_invalid_replacement_and_split_utf8() {
        let mut state = limited_state(
            vec![vec![0xe4], vec![0xbd], vec![0xa0, b'\n']],
            4,
            4,
            4,
            StreamFraming::Ndjson,
        );
        while state.read_next().await.unwrap() {}
        assert_eq!(state.buffer, "你\n");
        let mut state = limited_state(
            vec![vec![0xff], vec![b'\n']],
            2,
            3,
            4,
            StreamFraming::Ndjson,
        );
        assert!(state.read_next().await.unwrap());
        assert_eq!(state.buffer, "�");
        assert!(state
            .read_next()
            .await
            .unwrap_err()
            .to_string()
            .contains("decoded_bytes"));
        assert!(!state.read_next().await.unwrap());
        let mut state = limited_state(vec![vec![0xff, b'\n']], 2, 4, 4, StreamFraming::Ndjson);
        assert!(state.read_next().await.unwrap());
        assert_eq!(state.buffer, "�\n");
    }

    #[tokio::test]
    async fn eof_incomplete_utf8_obeys_decoded_budget() {
        let mut state = limited_state(vec![vec![0xe4]], 1, 2, 4, StreamFraming::Ndjson);
        assert!(state.read_next().await.unwrap());
        assert!(state
            .read_next()
            .await
            .unwrap_err()
            .to_string()
            .contains("decoded_bytes"));
        assert!(!state.read_next().await.unwrap());
    }

    #[tokio::test]
    async fn coalesced_crlf_and_lf_events_are_decoded_one_frame_at_a_time() {
        let mut state = limited_state(
            vec![b"data: a\r\n\r\ndata: b\n\n".to_vec()],
            22,
            22,
            11,
            StreamFraming::Sse,
        );
        assert!(state.read_next().await.unwrap());
        assert_eq!(extract_sse_data(&mut state.buffer).as_deref(), Some("a"));
        assert!(state.read_next().await.unwrap());
        assert_eq!(extract_sse_data(&mut state.buffer).as_deref(), Some("b"));
        assert!(!state.read_next().await.unwrap());
    }

    #[tokio::test]
    async fn dropping_partial_frame_releases_underlying_stream() {
        struct Dropped(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Dropped(std::sync::Arc::clone(&flag));
        let stream = futures::stream::unfold((guard, false), |(guard, sent)| async move {
            if sent {
                std::future::pending().await
            } else {
                Some((Ok(Bytes::from_static(b"data: partial")), (guard, true)))
            }
        });
        let limits = hf_core::provider::ResponseStreamLimitsConfig::default()
            .resolve()
            .unwrap();
        let mut state = SseStreamState::new(Box::pin(stream), limits, StreamFraming::Sse);
        assert!(state.read_next().await.unwrap());
        drop(state);
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[tokio::test]
    async fn wire_budget_is_cumulative_across_transport_chunks_and_drained_frames() {
        let mut state = limited_state(
            vec![b"x\n".to_vec(), b"y\n".to_vec(), b"z\n".to_vec()],
            5,
            100,
            2,
            StreamFraming::Ndjson,
        );
        assert!(state.read_next().await.unwrap());
        assert_eq!(extract_json_line(&mut state.buffer).as_deref(), Some("x\n"));
        assert!(state.read_next().await.unwrap());
        assert_eq!(extract_json_line(&mut state.buffer).as_deref(), Some("y\n"));
        assert!(state
            .read_next()
            .await
            .unwrap_err()
            .to_string()
            .contains("wire_bytes"));
        assert!(!state.read_next().await.unwrap());
    }

    #[tokio::test]
    async fn incomplete_utf8_counts_toward_unfinished_frame_budget() {
        let mut state = limited_state(
            vec![b"xx".to_vec(), vec![0xe4], vec![0xbd]],
            100,
            100,
            3,
            StreamFraming::Sse,
        );
        assert!(state.read_next().await.unwrap());
        assert!(state.read_next().await.unwrap());
        assert!(state
            .read_next()
            .await
            .unwrap_err()
            .to_string()
            .contains("frame_bytes"));
        assert!(!state.read_next().await.unwrap());
    }

    #[tokio::test]
    async fn resource_failure_drops_transport_before_receiver_is_dropped() {
        struct Dropped(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Dropped(std::sync::Arc::clone(&flag));
        let stream = futures::stream::unfold(guard, |guard| async move {
            Some((Ok(Bytes::from_static(b"xxxxxxxxx")), guard))
        });
        let limits = hf_core::provider::ResponseStreamLimitsConfig {
            wire_bytes: 100,
            decoded_bytes: 100,
            frame_bytes: 8,
        }
        .resolve()
        .unwrap();
        let mut state = SseStreamState::new(Box::pin(stream), limits, StreamFraming::Sse);
        assert!(state.read_next().await.is_err());
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!state.read_next().await.unwrap());
    }
}
