# Provider response resources

Status: active. Owner: hf-provider and hf-core; embedding configuration is owned
by hf-service and hf-knowledge.

## HTTP bodies

Configured proxies are required transport settings. Invalid enabled proxy URLs
fail pool validation, and the shared HTTP client constructor repeats validation
for directly constructed adapters. Concrete adapter constructors return errors
for invalid transport configuration or client construction; they never replace
a failed configured client with a default direct client. Proxy construction
errors contain no URL or embedded credentials. Disabled proxy entries retain
their existing cascade semantics.

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

OpenAI-compatible streamed tool calls use an explicit `index` when present.
Without one, a repeated call ID selects the existing call, an anonymous argument
fragment continues the latest call, and a new identity starts a separate call.
Fragments for parallel calls with the same tool name remain separate by call ID.

Anthropic content deltas require valid JSON and the string field declared by
their delta type. Malformed required events fail the stream rather than silently
discarding model text, reasoning, signatures, or tool arguments. Unknown delta
types remain ignorable for protocol extension.

A limit violation drops receive buffers and the HTTP stream, emits one typed
error naming only the budget and limit, and then ends. It cannot flush pending
tool calls or turn into clean completion. Previously emitted deltas are
provisional; this receiver does not collect an entire response atomically.
The pool records one failed request, no successful completion, no retry/freeze,
and releases its concurrency permits when the stream ends or drops. Transport,
allocator, parsed JSON and event/container overhead are additional finite
allocations; these byte budgets are not an RSS ceiling.

## Gemini native continuation

Native function-call responses retain their complete ordered assistant parts,
including opaque `thoughtSignature` values and signed text siblings. The first
`ToolCallRequest` carries a Gemini continuation record in its optional
`provider_metadata`; the remaining calls do not duplicate that record. The
version-1 record is namespaced under `gemini` and contains the original parts
and the corresponding generated call IDs. Gemini's original wire call IDs,
when present, are retained and echoed in the matching function response.
It survives the ordinary serialized `Message.tool_calls` representation and is
independent of skipped, diagnostic-only `raw_response` fields.

Request reconstruction checks the retained IDs, call order, function names,
arguments and assistant text against the message before replaying the original
parts. Malformed or mismatched Gemini continuation records fail before HTTP
dispatch, including duplicate or misplaced continuation records. Unsigned
manually constructed calls remain supported. Tool responses
use the matching function name and original call order, including repeated
function names. No signature is synthesized and no signature-validator bypass
is emitted.

Gemini streaming accumulates bounded original parts until the model's finish
successful `STOP` event, then publishes complete native calls through the existing tool-call
stream adapter. Text/image deltas remain incremental. A transport error,
resource violation, unsuccessful finish reason or premature EOF cannot flush
unfinished native calls. Protocol parse errors end the stream immediately;
later valid frames cannot revive pending calls.
Each retained part keeps its own signature and extension fields; signed parts
are never concatenated with neighboring parts.

Signed-text-only continuations are outside this repair: their replay is
recommended by Google but not required by API validation. The native-call
record still retains text siblings whenever function calls are present.

References: [Google function calling](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/tools/function-calling),
[Google thought signatures](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thinking/thought-signatures).

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
