# Provider response resources

Status: active. Owner: hf-provider and hf-core; embedding configuration is owned
by hf-service and hf-knowledge.

## HTTP bodies

All concrete provider adapters collect successful chat/image JSON and failed HTTP
responses through a shared bounded byte receiver. Embeddings use the same receiver.
Streaming handshake failures are HTTP bodies and use the error budget. A response
that exceeds its budget fails; no truncated successful JSON is returned.

`providers.toml` exposes a pool-wide `[response_body_limits]` table. Knowledge
embedding settings expose `[knowledge.embedding_response_body_limits]` in
`oxfuzz.toml`. Both use `success_bytes` (default 16777216, maximum 268435456)
and `error_bytes` (default 65536, maximum 1048576). Values must be positive;
unknown fields and invalid values fail configuration parsing. Provider edits
replace the provider array structurally, preserving pool settings and comments
regardless of TOML table order. Constructors
resolve an immutable specification once. Direct adapter callers can pass that
validated specification explicitly; receive operations never select defaults.

The 16 MiB success default permits ordinary text, embedding batches and common
base64 image payloads; larger deployments must configure a larger finite budget.
The 64 KiB error default accommodates diagnostic JSON without retaining unlimited
error text. Independent budgets avoid reserving the image allowance for errors.

Count received bytes before appending each transport chunk. A missing or
inaccurate Content-Length cannot authorize extra bytes. Text decoding preserves declared charset, BOM removal and
UTF-8 replacement behavior; replacement characters can expand text to at most
three times the wire budget. Transport buffers and parsed JSON have additional
finite allocations; these settings are not an RSS ceiling.

A resource violation produces a bounded typed error containing only the limit,
with no response text. It is not retried within the same pool call and does not
freeze the provider: an operator can adjust the budget or reduce response size.
Adapters that discard a status-only rate-limit/overload response keep doing so,
without collecting its body. Normal HTTP/network classification and concurrency cleanup remain effective.

## Successful streams

Every successful SSE/NDJSON adapter uses a shared incremental receiver with a
resolved `[response_stream_limits]` specification. Embeddings expose only body
limits. The independent positive budgets are `wire_bytes` (default 67108864,
maximum 268435456), `decoded_bytes` (default 67108864, maximum 805306368), and
`frame_bytes` (default 16777216, maximum 268435456). Unknown fields and invalid
values fail configuration. Direct adapters resolve defaults at construction or
accept a validated specification explicitly; receive operations never default.

The cumulative 64 MiB allowance accommodates repeated text, reasoning and tool
argument deltas. A 16 MiB frame allowance permits common base64 image frames;
larger deployments can raise finite budgets. Frame bytes include delimiters and
incomplete UTF-8 bytes. Decoded bytes count UTF-8 output before extraction,
including replacement characters; invalid bytes can consume this allowance
faster than the wire allowance. Cumulative accounting limits retained tool
arguments and thinking even when each frame is small.

Check every transport chunk against cumulative wire bytes before decoding. Keep
its unread portion as a Bytes slice, feed at most one complete protocol frame,
and let the concrete parser consume it before decoding the next. Coalesced
small frames never count as one large frame. UTF-8 split sequences are retained
in at most three bytes; decoded text is checked before appending. No missing
terminator can grow the unfinished frame beyond its budget.

A limit violation drops receive buffers and the HTTP stream, emits one typed
error naming only the budget and limit, and then ends. It cannot flush pending
tool calls or turn into clean completion. Previously emitted deltas are
provisional; this receiver does not collect an entire response atomically.
The pool records one failed request, no successful completion, no retry/freeze,
and releases its concurrency permits when the stream ends or drops. Transport,
allocator, parsed JSON and event/container overhead are additional finite
allocations; these byte budgets are not an RSS ceiling.

## Verification

Loopback HTTP fixtures exercise real pool-built adapters and embedding clients:
exact/one-byte-over limits, chunked responses without Content-Length, split UTF-8,
invalid-byte replacement, success/error/image JSON, all concrete backends,
streaming handshake errors, no repeated limit failure and released permits.
No live provider, generated harness or target is required.

Successful stream fixtures additionally exercise independent wire/decoded/frame
limits through every pool-built parser, coalesced LF/CRLF frames, unfinished
frames, split UTF-8 and replacement expansion, repeated arguments/thinking,
Gemini images, transport release on violation/drop, and pool permit release at
EOF even when a completed stream object is retained. Provider edits preserve
stream settings alongside HTTP budgets.
