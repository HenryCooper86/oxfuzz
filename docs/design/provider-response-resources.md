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

## Streaming follow-up

Successful SSE/NDJSON currently requires a separate incremental receive package:
stream-wide wire bytes, unfinished-frame storage, and repeated decoded deltas.
HTTP body limits do not claim to address that receive path. The resource finding
remains open until those operations are bounded and verified.

## Verification

Loopback HTTP fixtures exercise real pool-built adapters and embedding clients:
exact/one-byte-over limits, chunked responses without Content-Length, split UTF-8,
invalid-byte replacement, success/error/image JSON, all concrete backends,
streaming handshake errors, no repeated limit failure and released permits.
No live provider, generated harness or target is required.
